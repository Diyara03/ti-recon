"""The URLhaus provider adapter (Task 10).

Implements the Task 5 :class:`ProviderAdapter` contract over URLhaus's URL, host
and payload lookups. It normalizes and classifies; it decides nothing about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

One request, and which one matters
----------------------------------

An observable selects exactly one endpoint:

* a URL  → ``/v1/url/``     — the exact artifact, ``EXACT_OBSERVABLE``
* a host → ``/v1/host/``    — an association, ``SAME_HOST``
* a file → ``/v1/payload/`` — provenance, and context only

Those are three genuinely different claims and the adapter never substitutes one
for another. In particular an exact URL that URLhaus does not know is **not**
retried as a host lookup: "URLhaus has not tracked this URL" and "URLhaus has
tracked other malware on this host" are different answers, and quietly widening
the question would report the second as though it answered the first.

Never the URL itself
--------------------

The URL under investigation is sent *to URLhaus* and never fetched. That is the
whole point of asking a URL-tracking provider rather than looking.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Protocol

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.abusech.client import AbuseChJsonResult
from ti_recon.providers.abusech.errors import (
    credential_validation_for,
    query_status_of,
    translate_query_status,
)
from ti_recon.providers.abusech.evidence import (
    AbuseChNormalization,
    NormalizationContext,
)
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
    ProviderInvalidRequestError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope
from ti_recon.providers.transport import ProviderTransportError
from ti_recon.providers.urlhaus.client import (
    URLHAUS_HASH_LENGTHS,
    UrlhausClient,
    UrlhausConfig,
    UrlhausHttpClient,
)
from ti_recon.providers.urlhaus.descriptor import (
    URLHAUS_PROVIDER_ID,
    build_urlhaus_descriptor,
)
from ti_recon.providers.urlhaus.normalizer import (
    normalize_blocklists,
    normalize_host_association,
    normalize_not_tracked,
    normalize_payload_record,
    normalize_relayed_virustotal,
    normalize_url_record,
)
from ti_recon.providers.urlhaus.policy import UrlhausLookupPolicy

__all__ = [
    "UNSUPPORTED_REASONS",
    "URLHAUS_NOT_SUPPORTED",
    "UrlhausAdapter",
    "UrlhausClientFactory",
    "UrlhausLookupKind",
]

#: Reported when the observable is not something URLhaus can be asked about —
#: an IPv6 address, or a file identified only by SHA-1. A coverage gap, never an
#: absence of findings.
URLHAUS_NOT_SUPPORTED: Final[str] = "URLHAUS_OBSERVABLE_NOT_SUPPORTED"

#: Human-readable reason, carried on the envelope so the execution layer's
#: outcome explains itself without anyone having to look the code up.
UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    URLHAUS_NOT_SUPPORTED: (
        "URLhaus looks up an exact URL, an IPv4 or hostname as a host, or an "
        "MD5/SHA-256 payload; this observable has no URLhaus lookup"
    )
}

#: A reserved documentation host (RFC 5737) used only to prove a key works.
_CREDENTIAL_PROBE_HOST: Final[str] = "192.0.2.1"


class UrlhausLookupKind:
    """Which URLhaus question an observable asks."""

    URL: Final[str] = "url"
    HOST: Final[str] = "host"
    PAYLOAD: Final[str] = "payload"


class UrlhausClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> UrlhausClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to URLhaus."""

    def __init__(self, config: UrlhausConfig) -> None:
        self._config = config

    def __call__(self) -> UrlhausClient:
        return UrlhausHttpClient(self._config)


class UrlhausAdapter(ProviderAdapter):
    """Passive URLhaus malware-distribution enrichment."""

    def __init__(
        self,
        *,
        client_factory: UrlhausClientFactory | None = None,
        config: UrlhausConfig | None = None,
        lookup_policy: UrlhausLookupPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = UrlhausConfig() if config is None else config
        self._client_factory: UrlhausClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = UrlhausLookupPolicy() if lookup_policy is None else lookup_policy
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_urlhaus_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> UrlhausConfig:
        return self._config

    @property
    def lookup_policy(self) -> UrlhausLookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check an Auth-Key with one host lookup for a reserved address.

        URLhaus has no zero-cost status endpoint, so validation asks about RFC
        5737 documentation space, which is never anybody's observable. A "no
        results" is success: the key was accepted and URLhaus looked.

        Only a rejected key is reported invalid — one Auth-Key serves all three
        abuse.ch providers, so a URLhaus refusal must not disable the others.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=URLHAUS_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        return credential_validation_for(URLHAUS_PROVIDER_ID, await self._probe(credential))

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account."""
        return CapabilityDiscovery(
            provider_id=URLHAUS_PROVIDER_ID,
            capabilities=frozenset(self._descriptor.capabilities),
            plan_hint="community API; lookups only",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(
                provider_id=URLHAUS_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        error = await self._probe(credential)
        if error is None:
            return ProviderHealthReport(
                provider_id=URLHAUS_PROVIDER_ID, health=ProviderHealth.AVAILABLE
            )
        unavailable = error.category in {
            ProviderErrorCategory.PROVIDER_UNAVAILABLE,
            ProviderErrorCategory.TRANSIENT_ERROR,
        }
        return ProviderHealthReport(
            provider_id=URLHAUS_PROVIDER_ID,
            health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
            detail=f"probe returned {error.category.value}",
        )

    async def _probe(self, credential: CredentialMaterial) -> ProviderError | None:
        """One host lookup for a reserved address. ``None`` means the key works."""
        client = self._client_factory()
        try:
            result = await client.lookup_host(host=_CREDENTIAL_PROBE_HOST, credential=credential)
        except ProviderError as transport_error:
            return transport_error
        finally:
            await client.aclose()

        reported = translate_query_status(
            result.query_status, provider_id=URLHAUS_PROVIDER_ID, operation="urlhaus.probe"
        )
        if reported is not None and reported.category is ProviderErrorCategory.NOT_FOUND:
            return None
        return reported

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one observable from URLhaus's own records."""
        if credential is None:
            raise ProviderInvalidRequestError(
                URLHAUS_PROVIDER_ID,
                message="urlhaus requires a credential",
                operation="lookup",
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refusing here as well as in ``active_action`` means a caller
            # bypassing the executor still cannot turn a passive integration
            # into an active one. URLhaus accepts URL submissions and serves
            # payload downloads; this adapter can do neither.
            raise UnsupportedProviderOperation(URLHAUS_PROVIDER_ID, operation="active_action")

        plan = self._plan(request.intel_object)
        if plan is None:
            return self._unsupported_envelope(request)

        kind, value = plan
        client = self._client_factory()
        try:
            if kind == UrlhausLookupKind.URL:
                result = await client.lookup_url(url=value, credential=credential)
            elif kind == UrlhausLookupKind.HOST:
                result = await client.lookup_host(host=value, credential=credential)
            else:
                result = await client.lookup_payload(file_hash=value, credential=credential)
        finally:
            await client.aclose()

        return self._normalize_result(request, result, kind=kind)

    def _plan(self, intel_object: IntelObject) -> tuple[str, str] | None:
        """The one endpoint and value for this observable, or ``None``.

        For a file this picks the strongest digest URLhaus indexes, once:
        SHA-256 if present, otherwise MD5. A SHA-1-only file yields ``None`` —
        URLhaus indexes payloads by MD5 and SHA-256, and asking under either key
        with a SHA-1 would produce a "no results" that means nothing.
        """
        match intel_object.object_type:
            case IntelObjectType.URL:
                return UrlhausLookupKind.URL, intel_object.canonical_value
            case IntelObjectType.DOMAIN_NAME | IntelObjectType.IPV4_ADDR:
                return UrlhausLookupKind.HOST, intel_object.canonical_value
            case IntelObjectType.FILE:
                hashes = intel_object.hashes
                for algorithm in ("SHA-256", "MD5"):
                    digest = hashes.get(algorithm)
                    if digest and len(digest) in URLHAUS_HASH_LENGTHS:
                        return UrlhausLookupKind.PAYLOAD, digest
                return None
            case _:
                return None

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def _normalize_result(
        self,
        request: ProviderRequest,
        result: AbuseChJsonResult,
        *,
        kind: str,
        raw_reference: RawEvidenceReference | None = None,
    ) -> ProviderResultEnvelope:
        """Turn one response into an envelope, honouring the body's own verdict.

        The body status is checked before the payload: ``no_results``,
        ``invalid_url`` and a missing key all arrive as HTTP 200, and reading the
        document instead of the status is how a rejected credential becomes
        "this URL was never seen distributing malware".
        """
        error = translate_query_status(
            result.query_status, provider_id=URLHAUS_PROVIDER_ID, operation=f"urlhaus.{kind}"
        )
        if error is not None and error.category is not ProviderErrorCategory.NOT_FOUND:
            raise error

        context = self._context(request, raw_reference=raw_reference)
        if error is not None:
            return self._envelope(
                request,
                normalize_not_tracked(context, lookup=kind),
                status=ProviderRunStatus.NO_DATA,
            )

        bounds = self._lookup_policy.bounds(request.depth)
        payload = result.payload
        if kind == UrlhausLookupKind.URL:
            normalization = normalize_url_record(context, payload, max_related=bounds.max_related)
        elif kind == UrlhausLookupKind.HOST:
            normalization = normalize_host_association(
                context, payload, max_related=bounds.max_related
            )
        else:
            normalization = normalize_payload_record(
                context, payload, max_related=bounds.max_related
            )

        if not normalization.evidence:
            # A 200 with nothing readable in it. Reported as an absence rather
            # than as a success carrying no evidence.
            return self._envelope(
                request,
                normalize_not_tracked(context, lookup=kind),
                status=ProviderRunStatus.NO_DATA,
            )

        if bounds.include_nested_detail:
            # Relayed findings, attributed to whoever produced them. Read only at
            # the depths that keep nested detail: they are context, and a QUICK
            # answer does not need somebody else's opinion in it.
            normalization = normalization.merge(normalize_relayed_virustotal(context, payload))
            normalization = normalization.merge(normalize_blocklists(context, payload))

        status = ProviderRunStatus.PARTIAL if normalization.degraded else ProviderRunStatus.SUCCESS
        return self._envelope(request, normalization, status=status)

    def _context(
        self,
        request: ProviderRequest,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizationContext:
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
            raw_reference_id=raw_reference.id if raw_reference else None,
        )

    # ------------------------------------------------------------------ #
    # Contract helpers
    # ------------------------------------------------------------------ #

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        """Turn one URLhaus response into Task 3 models. Pure, no I/O."""
        plan = self._plan(request.intel_object)
        if plan is None:
            return NormalizedPayload(warnings=(URLHAUS_NOT_SUPPORTED,))
        envelope = self._normalize_result(
            request,
            AbuseChJsonResult(payload=dict(payload), query_status=query_status_of(dict(payload))),
            kind=plan[0],
            raw_reference=raw_reference,
        )
        return NormalizedPayload(
            evidence=envelope.evidence,
            objects=envelope.objects,
            relationships=envelope.relationships,
            warnings=envelope.warnings,
        )

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category."""
        if isinstance(error, ProviderTransportError):
            return ProviderErrorCategory.INVALID_REQUEST
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    def _unsupported_envelope(self, request: ProviderRequest) -> ProviderResultEnvelope:
        """A run that was never attempted, said plainly."""
        return ProviderResultEnvelope(
            provider=URLHAUS_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(URLHAUS_NOT_SUPPORTED,),
            error_message=UNSUPPORTED_REASONS[URLHAUS_NOT_SUPPORTED],
        )

    def _envelope(
        self,
        request: ProviderRequest,
        normalization: AbuseChNormalization,
        *,
        status: ProviderRunStatus,
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=URLHAUS_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=NormalizedPayload(
                evidence=normalization.evidence,
                objects=normalization.objects,
                relationships=normalization.relationships,
                warnings=normalization.warnings,
            ),
        )
