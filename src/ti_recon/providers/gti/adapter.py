"""The GTI provider adapter (Task 7).

Implements the Task 5 :class:`ProviderAdapter` contract over GTI / VirusTotal
API v3. It normalizes and classifies; it does not decide anything about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

Client lifetime
---------------

A client is created per call from the supplied credential and closed when the
call ends. That costs a TLS handshake per uncached lookup, and the trade is
deliberate: nothing shared means no session can outlive the credential that
opened it and no credential can be reused for another analyst. Within one
lookup the same client serves the primary object and every relationship, so
pooling still applies where a lookup actually makes several calls, and Task 6's
cache means repeat lookups make none. Per-credential connection reuse is a later
optimization, not a correctness requirement.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import TracebackType

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderErrorCategory
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.limits import QuotaStore
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.providers.adapter import (
    CapabilityDiscovery,
    CredentialValidation,
    ProviderAdapter,
    ProviderHealthReport,
)
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import (
    ProviderError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.gti.client import GTIClient, GTIClientFactory, VtPyGTIClientFactory
from ti_recon.providers.gti.config import GTIConfig
from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID, build_gti_descriptor
from ti_recon.providers.gti.policy import GTILookupPolicy
from ti_recon.providers.gti.quota import GTIQuotaReading, parse_overall_quotas
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope

__all__ = ["GTIAdapter"]

_logger = logging.getLogger(__name__)

#: Categories that prove the credential itself is the problem. Everything else
#: leaves the credential's recorded status alone — see ``validate_credentials``.
_INVALIDATING_CATEGORIES = frozenset({ProviderErrorCategory.AUTHENTICATION_ERROR})


class GTIAdapter(ProviderAdapter):
    """Passive GTI enrichment for IPs, domains, URLs and file hashes."""

    def __init__(
        self,
        *,
        client_factory: GTIClientFactory | None = None,
        config: GTIConfig | None = None,
        lookup_policy: GTILookupPolicy | None = None,
        quota_store: QuotaStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = GTIConfig() if config is None else config
        self._client_factory = (
            VtPyGTIClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = GTILookupPolicy() if lookup_policy is None else lookup_policy
        # Task 6's own quota store, injected rather than duplicated. Sharing it
        # means the executor's pre-check and this adapter's refresh agree on both
        # the key and the freshness window.
        self._quota_store = quota_store
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_gti_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> GTIConfig:
        return self._config

    @property
    def lookup_policy(self) -> GTILookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credential validation
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a key by asking GTI for its own quota.

        The cheapest authenticated call available: it touches no IOC, consumes
        no lookup allowance, and proves the key resolves to an active account.

        The mapping is deliberately conservative about what counts as a bad
        credential:

        * an authentication failure is the *only* thing that marks it invalid;
        * ``ForbiddenError`` does not — a 403 usually means this key may not do
          this one thing, and disabling a working Enterprise key over one
          restricted endpoint would be worse than the restriction;
        * quota exhaustion reports the key as valid, because an allowance
          belongs to an account and could not have been spent by an
          unrecognized key;
        * anything transient reports ``UNKNOWN`` rather than guessing, so a
          provider outage never invalidates a good key.
        """
        if credential is None:
            return self._validation(CredentialStatus.INVALID, "no credential supplied")

        try:
            async with self._client_for(credential) as client:
                await client.get_quota()
        except ProviderError as error:
            return self._validation(
                self._status_for_error(error),
                f"quota lookup returned {error.category.value}",
            )
        return self._validation(CredentialStatus.ACTIVE, "quota lookup succeeded")

    @staticmethod
    def _status_for_error(error: ProviderError) -> CredentialStatus:
        if error.category in _INVALIDATING_CATEGORIES:
            return CredentialStatus.INVALID
        if error.category is ProviderErrorCategory.QUOTA_EXCEEDED:
            # An exhausted allowance is proof the account was identified.
            return CredentialStatus.ACTIVE
        return CredentialStatus.UNKNOWN

    def _validation(self, status: CredentialStatus, detail: str) -> CredentialValidation:
        return CredentialValidation(provider_id=GTI_PROVIDER_ID, status=status, detail=detail)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account.

        Deliberately free of API calls. Probing each capability would cost a
        request per capability and still be a guess, because entitlement can
        differ per object type and per relationship. What a specific key is
        allowed to do is discovered where it matters: at request time, where a
        refusal becomes ``PLAN_LIMITED`` for that operation and leaves the rest
        of the provider usable.
        """
        return CapabilityDiscovery(
            provider_id=GTI_PROVIDER_ID,
            capabilities=self._descriptor.capabilities,
            plan_hint="entitlement is determined per request",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(provider_id=GTI_PROVIDER_ID, health=ProviderHealth.UNKNOWN)
        try:
            async with self._client_for(credential) as client:
                await client.get_quota()
        except ProviderError as error:
            health = (
                ProviderHealth.UNAVAILABLE
                if error.category
                in {
                    ProviderErrorCategory.PROVIDER_UNAVAILABLE,
                    ProviderErrorCategory.TRANSIENT_ERROR,
                }
                else ProviderHealth.DEGRADED
            )
            return ProviderHealthReport(
                provider_id=GTI_PROVIDER_ID,
                health=health,
                detail=f"quota lookup returned {error.category.value}",
            )
        return ProviderHealthReport(provider_id=GTI_PROVIDER_ID, health=ProviderHealth.AVAILABLE)

    # ------------------------------------------------------------------ #
    # Quota
    # ------------------------------------------------------------------ #

    async def fetch_quota(self, credential: CredentialMaterial) -> GTIQuotaReading:
        """Read this credential's allowances.

        Raises a normalized :class:`ProviderError` on failure. The failure is
        never described in terms of the endpoint, because that endpoint's path
        contains the API key.
        """
        async with self._client_for(credential) as client:
            payload = await client.get_quota()
        return self._reading_from(payload, credential)

    def _reading_from(
        self, payload: Mapping[str, object], credential: CredentialMaterial
    ) -> GTIQuotaReading:
        return parse_overall_quotas(
            payload,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
            retrieved_at=self._clock.now(),
        )

    async def _refresh_quota_if_stale(
        self, client: GTIClient, credential: CredentialMaterial
    ) -> ProviderQuotaSnapshot | None:
        """Read quota only when Task 6's store has nothing fresh.

        Returning ``None`` means "no refresh needed", which keeps normal
        enrichment at one API call per uncached lookup. A failure here is
        swallowed on purpose: quota is useful context, and losing it must not
        turn a successful IOC lookup into a failed one.
        """
        if not self._lookup_policy.quota_refresh_enabled:
            return None
        if self._quota_store is not None:
            existing = await self._quota_store.get(self._scope_identity(credential))
            if existing is not None:
                return None
        try:
            payload = await client.get_quota()
        except ProviderError as error:
            # Logged without the endpoint: the path contains the API key.
            _logger.info(
                "GTI quota lookup failed",
                extra={
                    "provider": GTI_PROVIDER_ID,
                    "error_category": error.category.value,
                    "provider_error_code": error.provider_error_code,
                },
            )
            return None
        reading = self._reading_from(payload, credential)
        if self._quota_store is not None:
            await self._quota_store.put(self._scope_identity(credential), reading.snapshot)
        return reading.snapshot

    @staticmethod
    def _scope_identity(credential: CredentialMaterial) -> str:
        """The Task 6 scope key for this credential.

        Rebuilt from ids only, and identical to what the executor derives, so
        both sides address the same quota entry.
        """
        return ExecutionScope.for_user(
            provider_id=GTI_PROVIDER_ID,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
        ).identity

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one observable. Implemented in the next commit."""
        raise UnsupportedProviderOperation(GTI_PROVIDER_ID, operation="lookup")

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        """Turn a GTI payload into Task 3 models. Implemented in a later commit."""
        return NormalizedPayload()

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Normalize an exception the client did not already translate.

        The client raises normalized errors, so this is the safety net for
        anything unexpected escaping it rather than the main mapping path.
        """
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        if isinstance(error, ValueError):
            # A payload we could not read is a schema problem, and retrying an
            # unreadable response cannot help.
            return ProviderErrorCategory.SCHEMA_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    # ------------------------------------------------------------------ #
    # Client plumbing
    # ------------------------------------------------------------------ #

    def _client_for(self, credential: CredentialMaterial) -> _ClientScope:
        """A client bound to this credential, closed when the block ends."""
        return _ClientScope(self._client_factory.create(credential.secret))

    def __repr__(self) -> str:
        return (
            f"<GTIAdapter host={self._config.host} "
            f"adapter_version={self._descriptor.adapter_version}>"
        )


class _ClientScope:
    """Async context manager that always closes the client it was given.

    A thin wrapper rather than relying on the client's own ``__aenter__``,
    because :class:`GTIClient` is a protocol and an implementation is not
    required to be a context manager.
    """

    def __init__(self, client: GTIClient) -> None:
        self._client = client

    async def __aenter__(self) -> GTIClient:
        return self._client

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.close()
