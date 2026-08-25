"""The GreyNoise provider adapter (Task 9).

Implements the Task 5 :class:`ProviderAdapter` contract over GreyNoise's v3 IP
and Community endpoints. It normalizes and classifies; it decides nothing about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

One request per lookup
----------------------

A GreyNoise lookup is a single GET. There is no search to page through and no
history to walk, so depth does not buy more requests — it selects the endpoint
variant and how much of the returned document is normalized. See
:mod:`ti_recon.providers.greynoise.policy`.

The only case where a lookup makes two requests is the access probe: an ``AUTO``
lookup whose full-context request came back ``403`` may try Community exactly
once, and the outcome is remembered per credential so the next lookup goes
straight to the door that works. A ``401`` never triggers that probe — see
:mod:`ti_recon.providers.greynoise.access`.

What absence means
------------------

GreyNoise not having a record is reported as ``NO_DATA`` and carries context
evidence saying so. It is never reported as benign, and nothing here turns
``noise: false``, ``riot: false`` or a 404 into a direction.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceClass,
    EvidenceEffect,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import Clock, SystemClock
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
    ProviderInvalidRequestError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.greynoise.access import (
    AccessLevelStore,
    GreyNoiseAccessLevel,
    GreyNoiseAccessMode,
    InMemoryAccessLevelStore,
)
from ti_recon.providers.greynoise.client import (
    GreyNoiseClient,
    GreyNoiseHttpClient,
    GreyNoiseJsonResult,
    GreyNoiseOperation,
)
from ti_recon.providers.greynoise.config import GreyNoiseConfig
from ti_recon.providers.greynoise.descriptor import (
    GREYNOISE_PROVIDER_ID,
    build_greynoise_descriptor,
)
from ti_recon.providers.greynoise.errors import credential_validation_for
from ti_recon.providers.greynoise.metering import parse_rate_limit_headers
from ti_recon.providers.greynoise.normalizer import (
    GreyNoiseDocument,
    GreyNoiseNormalization,
    NormalizationContext,
    build_evidence,
    enrich_primary_object,
    normalize_business_service,
    normalize_classification,
    normalize_cve_activity,
    normalize_network_context,
    normalize_not_observed,
    normalize_scanner_observation,
    normalize_tags,
)
from ti_recon.providers.greynoise.policy import (
    GreyNoiseDetail,
    GreyNoiseLookupPolicy,
    detail_for_depth,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import (
    NormalizedPayload,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)
from ti_recon.providers.transport import ProviderTransportError

__all__ = [
    "GREYNOISE_COMMUNITY_ACCESS_ONLY",
    "GREYNOISE_DOCUMENT_UNREADABLE",
    "GREYNOISE_NOT_SUPPORTED",
    "GREYNOISE_PARTIAL_CONTEXT",
    "UNSUPPORTED_REASONS",
    "GreyNoiseAdapter",
    "GreyNoiseClientFactory",
]

_logger = logging.getLogger(__name__)

#: Reported when the observable is not something GreyNoise can answer for — a
#: domain, a URL, a hash, or an IPv6 address. A coverage gap, never an absence
#: of findings.
GREYNOISE_NOT_SUPPORTED: Final[str] = "GREYNOISE_OBSERVABLE_NOT_SUPPORTED"

#: Reported when the full context was refused and the Community answer was used
#: instead. Real evidence, narrower coverage: an analyst should be able to see
#: that the tags, CVE associations and sensor metadata were never available
#: rather than absent.
GREYNOISE_COMMUNITY_ACCESS_ONLY: Final[str] = "GREYNOISE_COMMUNITY_ACCESS_ONLY"

#: Reported when GreyNoise answered ``206`` — a document it trimmed for this
#: account. The evidence that parsed is kept; the run is partial.
GREYNOISE_PARTIAL_CONTEXT: Final[str] = "GREYNOISE_PARTIAL_CONTEXT"

#: Reported when a response carried no field this adapter recognizes.
GREYNOISE_DOCUMENT_UNREADABLE: Final[str] = "GREYNOISE_DOCUMENT_UNREADABLE"

#: Human-readable reason per warning, carried on the envelope so the execution
#: layer's outcome explains itself without anyone having to look the code up.
UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    GREYNOISE_NOT_SUPPORTED: (
        "GreyNoise is queried by IPv4 address; this observable type has no GreyNoise lookup"
    )
}

#: Capabilities a Community-only credential genuinely cannot serve.
#:
#: The Community document has no sensor metadata, so there is no ASN,
#: organization or reverse-DNS name in it — and therefore no network ownership
#: to report and no pivots to build. Reported as a capability gap rather than
#: silently producing less, so a coverage report can say what was missing.
_FULL_ONLY_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {ProviderCapability.NETWORK_OWNERSHIP, ProviderCapability.RELATIONSHIPS}
)


class GreyNoiseClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> GreyNoiseClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to GreyNoise."""

    def __init__(self, config: GreyNoiseConfig) -> None:
        self._config = config

    def __call__(self) -> GreyNoiseClient:
        return GreyNoiseHttpClient(self._config)


@dataclass(frozen=True, slots=True)
class _Answer:
    """One resolved GreyNoise answer, and how it was obtained.

    ``result is None`` means GreyNoise answered and had no record — a finding,
    not a failure. ``downgraded`` means the full context was refused and the
    Community answer stood in for it, which is a coverage fact worth carrying
    all the way to the envelope.
    """

    level: GreyNoiseAccessLevel
    result: GreyNoiseJsonResult | None
    downgraded: bool = False

    @property
    def found(self) -> bool:
        return self.result is not None

    @property
    def is_partial(self) -> bool:
        return self.result is not None and self.result.is_partial


class GreyNoiseAdapter(ProviderAdapter):
    """Passive GreyNoise enrichment for IPv4 addresses."""

    def __init__(
        self,
        *,
        client_factory: GreyNoiseClientFactory | None = None,
        config: GreyNoiseConfig | None = None,
        lookup_policy: GreyNoiseLookupPolicy | None = None,
        access_store: AccessLevelStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = GreyNoiseConfig() if config is None else config
        self._client_factory: GreyNoiseClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = GreyNoiseLookupPolicy() if lookup_policy is None else lookup_policy
        self._clock = SystemClock() if clock is None else clock
        # Injected so a deployment can share one store across adapter instances,
        # and so a test can inspect what was remembered. The default is scoped
        # to this adapter, which is the right default for a single process.
        self._access_store: AccessLevelStore = (
            InMemoryAccessLevelStore(
                clock=self._clock,
                ttl_seconds=self._lookup_policy.access_ttl_seconds,
            )
            if access_store is None
            else access_store
        )
        self._descriptor = build_greynoise_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> GreyNoiseConfig:
        return self._config

    @property
    def lookup_policy(self) -> GreyNoiseLookupPolicy:
        return self._lookup_policy

    @property
    def access_store(self) -> AccessLevelStore:
        return self._access_store

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a key against GreyNoise's own ``/ping`` status endpoint.

        ``/ping`` takes no observable and consumes no intelligence lookup, which
        is what a credential check should cost. Validating by looking an address
        up would spend part of the analyst's allowance to be told their key
        works — and on the plans where that allowance is smallest, checking a key
        is exactly when spending it hurts most.

        What this proves is **reachability and authentication**, and nothing
        else. Whether the key may read the full IP context is a separate
        question, discovered from a real lookup; see
        :mod:`ti_recon.providers.greynoise.access`.

        Only a rejected key is reported invalid; see
        :func:`~ti_recon.providers.greynoise.errors.credential_status_for`.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=GREYNOISE_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        error = await self._probe(credential)
        if error is None:
            return credential_validation_for(GREYNOISE_PROVIDER_ID)
        return credential_validation_for(GREYNOISE_PROVIDER_ID, error)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what this credential's access level actually allows.

        Deliberately free of API calls: it reads the access level already
        observed for this credential and reports accordingly. Discovering an
        entitlement by spending a request is what the lookup path does, once,
        and repeating it here would double the cost of every capability query.

        An unknown level reports the full capability set. Claiming less than we
        might be able to do would make the planner skip a provider that works.
        """
        capabilities = set(self._descriptor.capabilities)
        level = await self._known_level(credential)
        if level is GreyNoiseAccessLevel.COMMUNITY:
            capabilities -= _FULL_ONLY_CAPABILITIES
        return CapabilityDiscovery(
            provider_id=GREYNOISE_PROVIDER_ID,
            capabilities=frozenset(capabilities),
            plan_hint=level.value if level is not None else "access level not yet observed",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available.

        Also ``/ping``: establishing that a provider is up should never cost an
        intelligence lookup.
        """
        if credential is None:
            return ProviderHealthReport(
                provider_id=GREYNOISE_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        error = await self._probe(credential)
        if error is None:
            return ProviderHealthReport(
                provider_id=GREYNOISE_PROVIDER_ID, health=ProviderHealth.AVAILABLE
            )
        unavailable = error.category in {
            ProviderErrorCategory.PROVIDER_UNAVAILABLE,
            ProviderErrorCategory.TRANSIENT_ERROR,
        }
        return ProviderHealthReport(
            provider_id=GREYNOISE_PROVIDER_ID,
            health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
            detail=f"ping returned {error.category.value}",
        )

    async def _probe(self, credential: CredentialMaterial) -> ProviderError | None:
        """One ``/ping``. ``None`` means the key was accepted and the service is up.

        No observable is named and no intelligence lookup is consumed, so this
        can be called as often as an operator likes. Any failure is returned
        rather than interpreted: whether it says something about the credential
        is :func:`~ti_recon.providers.greynoise.errors.credential_status_for`'s
        decision, and nothing here writes an access level — a ping proves
        nothing about entitlement.
        """
        client = self._client_factory()
        try:
            await client.ping(credential=credential)
        except ProviderError as error:
            return error
        finally:
            await client.aclose()
        return None

    # ------------------------------------------------------------------ #
    # Access level
    # ------------------------------------------------------------------ #

    @staticmethod
    def _scope_identity(credential: CredentialMaterial) -> str:
        """The Task 6 scope key for this credential, rebuilt from ids only."""
        return ExecutionScope.for_user(
            provider_id=GREYNOISE_PROVIDER_ID,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
        ).identity

    async def _known_level(
        self, credential: CredentialMaterial | None
    ) -> GreyNoiseAccessLevel | None:
        """The access level in force for this credential, without any I/O.

        A pinned mode wins outright — an operator who said ``COMMUNITY`` meant
        it. ``AUTO`` consults what was observed for this specific credential,
        and answers ``None`` when nothing has been observed yet.
        """
        mode = self._lookup_policy.access_mode
        if mode is GreyNoiseAccessMode.FULL:
            return GreyNoiseAccessLevel.FULL
        if mode is GreyNoiseAccessMode.COMMUNITY:
            return GreyNoiseAccessLevel.COMMUNITY
        if credential is None:
            return None
        return await self._access_store.get(self._scope_identity(credential))

    async def _remember(self, credential: CredentialMaterial, level: GreyNoiseAccessLevel) -> None:
        """Record an observed access level, if remembering is switched on.

        Only ever called after a real response. A status code alone never
        reaches this method.
        """
        if not self._lookup_policy.access_caching_enabled:
            return
        await self._access_store.put(self._scope_identity(credential), level)

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one IPv4 address from GreyNoise.

        One GET, or two in the single case where an ``AUTO`` lookup has to find
        out which door this credential may use. Nothing is submitted, nothing is
        hunted, and no deprecated v2 endpoint is touched.
        """
        if credential is None:
            raise ProviderInvalidRequestError(
                GREYNOISE_PROVIDER_ID,
                message="greynoise requires a credential",
                operation="lookup",
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refusing here as well as in ``active_action`` means a caller
            # bypassing the executor still cannot turn a passive integration
            # into an active one.
            raise UnsupportedProviderOperation(GREYNOISE_PROVIDER_ID, operation="active_action")

        if request.intel_object.object_type not in self._descriptor.supported_object_types:
            # No request is made, so this is not "we looked and found nothing".
            return self._unsupported_envelope(request, GREYNOISE_NOT_SUPPORTED)

        detail = detail_for_depth(request.depth, self._lookup_policy)
        client = self._client_factory()
        try:
            answer = await self._resolve_answer(client, request, credential, detail)
        finally:
            await client.aclose()

        rate_limit = (
            parse_rate_limit_headers(
                answer.result.metering_headers,
                operation=self._operation_name(answer.level, detail),
                now=self._clock.now(),
            )
            if answer.result is not None
            else None
        )

        normalization = self._coverage(request, answer, detail)
        if answer.result is None:
            normalization = normalization.merge(
                normalize_not_observed(self._context(request), GreyNoiseDocument({}))
            )
            return self._envelope(
                request, normalization, status=ProviderRunStatus.NO_DATA, rate_limit=rate_limit
            )

        document = GreyNoiseDocument(answer.result.payload, partial=answer.result.is_partial)
        normalization = normalization.merge(self._normalize_document(request, document, detail))

        warnings: list[str] = []
        if answer.downgraded:
            warnings.append(GREYNOISE_COMMUNITY_ACCESS_ONLY)
        if answer.is_partial:
            warnings.append(GREYNOISE_PARTIAL_CONTEXT)
        if warnings:
            normalization = normalization.merge(GreyNoiseNormalization(warnings=tuple(warnings)))

        # A Community answer is complete for what Community is, so it stays a
        # success with a recorded coverage gap. Only a document GreyNoise itself
        # trimmed, or a block that would not parse, makes the run partial —
        # otherwise every free-tier lookup would be uncacheable and every
        # free-tier analyst would pay for the same answer twice.
        status = (
            ProviderRunStatus.PARTIAL
            if answer.is_partial or normalization.degraded
            else ProviderRunStatus.SUCCESS
        )
        return self._envelope(request, normalization, status=status, rate_limit=rate_limit)

    async def _resolve_answer(
        self,
        client: GreyNoiseClient,
        request: ProviderRequest,
        credential: CredentialMaterial,
        detail: GreyNoiseDetail,
    ) -> _Answer:
        """Fetch through whichever door this credential may use.

        The ordering is the whole point of the access mechanism:

        * a pinned mode is obeyed without probing anything;
        * an ``AUTO`` lookup with a remembered level goes straight there;
        * an ``AUTO`` lookup with no memory tries the full context first,
          because that is the answer worth having;
        * ``401`` propagates untouched — a rejected key is never reinterpreted
          as a subscription limit;
        * ``403`` earns exactly one Community attempt, and only if the operator
          left that enabled.
        """
        address = request.intel_object.canonical_value
        level = await self._known_level(credential)
        if level is GreyNoiseAccessLevel.COMMUNITY:
            # Downgraded only when nobody chose this: a pinned COMMUNITY mode is
            # the configured answer, not a coverage gap. A remembered level under
            # AUTO *is* a gap, because the full context was refused earlier.
            return await self._community_answer(
                client,
                credential,
                address,
                downgraded=self._lookup_policy.access_mode is GreyNoiseAccessMode.AUTO,
            )

        try:
            result = await client.get_ip_context(
                ip=address, quick=detail.quick, credential=credential
            )
        except ProviderError as error:
            return await self._after_full_failure(client, credential, address, error)

        await self._remember(credential, GreyNoiseAccessLevel.FULL)
        return _Answer(level=GreyNoiseAccessLevel.FULL, result=result)

    async def _after_full_failure(
        self,
        client: GreyNoiseClient,
        credential: CredentialMaterial,
        address: str,
        error: ProviderError,
    ) -> _Answer:
        """Decide what a failed full-context request means.

        Three outcomes, and the difference between them is the reason this
        module exists:

        * ``NOT_FOUND`` — the endpoint answered. Full access is confirmed and
          the absence of a record is the finding.
        * ``PERMISSION_ERROR`` / ``PLAN_LIMITED`` under ``AUTO`` — the key is
          accepted but not for this endpoint, so try Community once.
        * anything else, ``AUTHENTICATION_ERROR`` very much included — raise.
        """
        if error.category is ProviderErrorCategory.NOT_FOUND:
            await self._remember(credential, GreyNoiseAccessLevel.FULL)
            return _Answer(level=GreyNoiseAccessLevel.FULL, result=None)

        may_probe = (
            self._lookup_policy.access_mode is GreyNoiseAccessMode.AUTO
            and self._lookup_policy.allow_community_probe
            and error.category
            in {ProviderErrorCategory.PERMISSION_ERROR, ProviderErrorCategory.PLAN_LIMITED}
        )
        if not may_probe:
            raise error

        _logger.info(
            "greynoise full context refused; probing community once",
            extra={
                "provider": GREYNOISE_PROVIDER_ID,
                "error_category": error.category.value,
                "provider_error_code": error.provider_error_code,
            },
        )
        try:
            return await self._community_answer(client, credential, address, downgraded=True)
        except ProviderError as probe_error:
            if probe_error.category is ProviderErrorCategory.AUTHENTICATION_ERROR:
                # The key really is bad. Report that, not the earlier 403 — an
                # analyst needs to be told to replace it.
                raise
            # Community failed for some unrelated reason. The first failure is
            # the more informative one, and reporting the probe's would hide
            # what actually blocked the lookup.
            raise error from probe_error

    async def _community_answer(
        self,
        client: GreyNoiseClient,
        credential: CredentialMaterial,
        address: str,
        *,
        downgraded: bool,
    ) -> _Answer:
        """Read the Community view, treating a 404 as the finding it is."""
        try:
            result = await client.get_community(ip=address, credential=credential)
        except ProviderError as error:
            if error.category is not ProviderErrorCategory.NOT_FOUND:
                raise
            # A legitimate 404 still proves Community access works.
            await self._remember(credential, GreyNoiseAccessLevel.COMMUNITY)
            return _Answer(level=GreyNoiseAccessLevel.COMMUNITY, result=None, downgraded=downgraded)
        await self._remember(credential, GreyNoiseAccessLevel.COMMUNITY)
        return _Answer(level=GreyNoiseAccessLevel.COMMUNITY, result=result, downgraded=downgraded)

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def _normalize_document(
        self,
        request: ProviderRequest,
        document: GreyNoiseDocument,
        detail: GreyNoiseDetail,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> GreyNoiseNormalization:
        """Every normalization pass over one GreyNoise document.

        Each pass is independent, so one missing or unreadable block still
        leaves the others. None of them produces a verdict.
        """
        context = self._context(request, raw_reference=raw_reference)
        if document.is_empty:
            return GreyNoiseNormalization(warnings=(GREYNOISE_DOCUMENT_UNREADABLE,), degraded=True)

        result = GreyNoiseNormalization(
            objects=(enrich_primary_object(request.intel_object, document),)
        )
        result = result.merge(normalize_classification(context, document))
        result = result.merge(normalize_business_service(context, document))
        result = result.merge(
            normalize_scanner_observation(
                context, document, include_sensor_detail=detail.include_sensor_detail
            )
        )
        if detail.include_tags:
            result = result.merge(normalize_tags(context, document))
        if detail.include_cves:
            result = result.merge(normalize_cve_activity(context, document))
        if detail.include_network_context:
            result = result.merge(normalize_network_context(context, document))
        if document.scanner_found is False:
            # GreyNoise answered with a document and said it has no scanner
            # record. That is the same coverage fact a 404 carries, and it must
            # be written down rather than left as an empty space.
            result = result.merge(normalize_not_observed(context, document))
        return result

    def _coverage(
        self, request: ProviderRequest, answer: _Answer, detail: GreyNoiseDetail
    ) -> GreyNoiseNormalization:
        """Record which door answered, and how much of it was read.

        "GreyNoise found nothing" means one thing through the full context and
        another through Community, and only this says which happened. Context
        evidence, because how a lookup was performed says nothing about the
        address — it says what the answer is worth.
        """
        attributes: dict[str, Any] = {
            "depth": request.depth.value,
            "access_level": answer.level.value,
            "access_mode": self._lookup_policy.access_mode.value,
            "endpoint": self._operation_name(answer.level, detail),
            "sensor_detail_included": detail.include_sensor_detail,
            "provider_reduced_response": answer.is_partial,
        }
        if answer.downgraded:
            attributes["full_context_unavailable"] = True
        evidence = build_evidence(
            self._context(request),
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="greynoise_coverage",
            effect=EvidenceEffect.CONTEXT_ONLY,
            attributes=attributes,
        )
        return GreyNoiseNormalization(evidence=(evidence,))

    def _context(
        self,
        request: ProviderRequest,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizationContext:
        """The normalization context for this request.

        The match scope is always ``EXACT_OBSERVABLE``: GreyNoise is asked about
        one address and answers about that address. Nothing here is inferred
        from a neighbouring host or a shared network.
        """
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
            raw_reference_id=raw_reference.id if raw_reference else None,
        )

    @staticmethod
    def _operation_name(level: GreyNoiseAccessLevel, detail: GreyNoiseDetail) -> str:
        if level is GreyNoiseAccessLevel.COMMUNITY:
            return GreyNoiseOperation.COMMUNITY
        return (
            GreyNoiseOperation.IP_CONTEXT_QUICK if detail.quick else GreyNoiseOperation.IP_CONTEXT
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
        """Turn one GreyNoise document into Task 3 models. Pure, no I/O."""
        normalization = self._normalize_document(
            request,
            GreyNoiseDocument(payload),
            detail_for_depth(request.depth, self._lookup_policy),
            raw_reference=raw_reference,
        )
        return _payload_of(normalization)

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category.

        Transport security failures are reported as invalid requests rather than
        as provider problems: refusing to leave GreyNoise's host is our
        decision, not GreyNoise misbehaving.
        """
        if isinstance(error, ProviderTransportError):
            return ProviderErrorCategory.INVALID_REQUEST
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    def parse_rate_limits(self, headers: Mapping[str, str]) -> RateLimitSnapshot | None:
        return parse_rate_limit_headers(headers, now=self._clock.now())

    def _unsupported_envelope(
        self, request: ProviderRequest, reason: str
    ) -> ProviderResultEnvelope:
        """A run that was never attempted, said plainly.

        ``NOT_SUPPORTED`` rather than ``NO_DATA``, and it carries a reason a
        coverage report can quote: a future coverage layer reads this as
        ``NOT_APPLICABLE`` for the capability, not as a covered lookup that
        found nothing. GreyNoise having no answer for a domain is not the same
        statement as GreyNoise never having seen an address, and collapsing the
        two would let a blind spot read as a clean result.
        """
        return ProviderResultEnvelope(
            provider=GREYNOISE_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(reason,),
            error_message=UNSUPPORTED_REASONS.get(reason),
        )

    def _envelope(
        self,
        request: ProviderRequest,
        normalization: GreyNoiseNormalization,
        *,
        status: ProviderRunStatus,
        rate_limit: RateLimitSnapshot | None = None,
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=GREYNOISE_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=_payload_of(normalization),
            rate_limit=rate_limit,
        )


def _payload_of(normalization: GreyNoiseNormalization) -> NormalizedPayload:
    return NormalizedPayload(
        evidence=normalization.evidence,
        objects=normalization.objects,
        relationships=normalization.relationships,
        warnings=normalization.warnings,
    )
