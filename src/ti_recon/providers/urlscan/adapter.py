"""The urlscan provider adapter (Task 8).

Implements the Task 5 :class:`ProviderAdapter` contract over urlscan's Search
and Result APIs. It normalizes and classifies; it decides nothing about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

Two modes, and only one of them can happen by accident
------------------------------------------------------

**Enrichment** runs on every lookup: a bounded historical search, a bounded
number of stored scan results, and normalization of what those contain. It never
retrieves a DOM, a screenshot or a response body, so a routine SOC lookup stays
cheap.

**Web forensics** runs only when the caller explicitly asked — DEEP depth *and*
``WEB_FORENSICS`` in the requested capabilities, both checked in
:func:`~ti_recon.providers.urlscan.policy.forensics_requested`. It retrieves
stored artifacts into the bounded artifact store, and it remains passive:
everything it reads is content urlscan already holds, and nothing causes a new
visit to anybody's site.

Client lifetime
---------------

One client per lookup, closed when the lookup ends. The credential is applied
per request by the transport rather than held by the client, so a lookup's
several calls share one connection pool without any credential outliving the
call that supplied it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from ti_recon.artifacts.models import ArtifactKind, ArtifactScope, StoredArtifact
from ti_recon.artifacts.store import ArtifactStore, ArtifactStoreError
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
from ti_recon.execution.limits import QuotaStore
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.evidence import Evidence, RawEvidenceReference
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
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import (
    NormalizedPayload,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)
from ti_recon.providers.transport import ProviderTransportError
from ti_recon.providers.urlscan.client import (
    UrlscanArtifact,
    UrlscanClient,
    UrlscanHttpClient,
)
from ti_recon.providers.urlscan.config import UrlscanConfig
from ti_recon.providers.urlscan.descriptor import (
    URLSCAN_PROVIDER_ID,
    build_urlscan_descriptor,
)
from ti_recon.providers.urlscan.errors import credential_validation_for
from ti_recon.providers.urlscan.forensics import (
    analyze_dom,
    analyze_script,
    forensic_evidence,
    select_response_bodies,
)
from ti_recon.providers.urlscan.normalizer import (
    NormalizationContext,
    ScanDocument,
    UrlscanNormalization,
    build_evidence,
    enrich_primary_object,
    match_scope_for_scan,
    normalize_page_context,
    normalize_scan_observation,
    normalize_verdicts,
)
from ti_recon.providers.urlscan.observations import (
    normalize_contacted_infrastructure,
    normalize_redirect_chain,
    normalize_served_bodies,
    normalize_traffic_summary,
)
from ti_recon.providers.urlscan.policy import (
    UrlscanLookupPolicy,
    forensics_requested,
    search_limits_for,
)
from ti_recon.providers.urlscan.quota import (
    UrlscanQuotaReading,
    parse_rate_limit_headers,
    parse_user_quotas,
)
from ti_recon.providers.urlscan.search import (
    ScanCandidate,
    parse_hits,
    plan_search,
    select_candidates,
)

__all__ = [
    "URLSCAN_ARTIFACTS_UNAVAILABLE",
    "URLSCAN_FORENSICS_NOT_REQUESTED",
    "URLSCAN_NOT_SEARCHABLE",
    "URLSCAN_SCAN_UNRETRIEVABLE",
    "UrlscanAdapter",
    "UrlscanClientFactory",
]

_logger = logging.getLogger(__name__)

#: Reported when urlscan indexes nothing that could answer for an observable —
#: an MD5, say, where only SHA-256 response bodies are indexed. A coverage gap,
#: never an absence of findings.
URLSCAN_NOT_SEARCHABLE: Final[str] = "URLSCAN_OBSERVABLE_NOT_SEARCHABLE"

#: Reported when a selected scan could not be retrieved. The other scans still
#: produced evidence, so the run is partial rather than failed.
URLSCAN_SCAN_UNRETRIEVABLE: Final[str] = "URLSCAN_SCAN_UNRETRIEVABLE"

#: Reported when forensics ran but urlscan served no usable artifact.
URLSCAN_ARTIFACTS_UNAVAILABLE: Final[str] = "URLSCAN_ARTIFACTS_UNAVAILABLE"

#: Reported when WEB_FORENSICS was requested but the gate refused it — the
#: depth was not DEEP, or the deployment has forensics switched off. Recorded
#: so a caller sees why an artifact-backed answer did not arrive.
URLSCAN_FORENSICS_NOT_REQUESTED: Final[str] = "URLSCAN_WEB_FORENSICS_NOT_PERFORMED"


@dataclass(frozen=True, slots=True)
class _ForensicCapture:
    """What one forensic stage produced, and how much of it it actually kept.

    The count is separate from the evidence because a stage can produce
    observations without capturing anything, and "we retrieved nothing" is what
    the caller has to report.
    """

    normalization: UrlscanNormalization
    captured: int


class UrlscanClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> UrlscanClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to urlscan."""

    def __init__(self, config: UrlscanConfig) -> None:
        self._config = config

    def __call__(self) -> UrlscanClient:
        return UrlscanHttpClient(self._config)


class UrlscanAdapter(ProviderAdapter):
    """Passive urlscan enrichment, with explicitly-requested web forensics."""

    def __init__(
        self,
        *,
        client_factory: UrlscanClientFactory | None = None,
        config: UrlscanConfig | None = None,
        lookup_policy: UrlscanLookupPolicy | None = None,
        artifact_store: ArtifactStore | None = None,
        quota_store: QuotaStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = UrlscanConfig() if config is None else config
        self._client_factory: UrlscanClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = UrlscanLookupPolicy() if lookup_policy is None else lookup_policy
        # Injected rather than created: artifacts belong to the investigation,
        # not to one adapter instance, and a deployment that declines to store
        # page content simply passes nothing.
        self._artifact_store = artifact_store
        # Task 6's own quota store, shared so the executor's pre-check and this
        # adapter's refresh agree on both the key and the freshness window.
        self._quota_store = quota_store
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_urlscan_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> UrlscanConfig:
        return self._config

    @property
    def lookup_policy(self) -> UrlscanLookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a key by asking urlscan for its own quota.

        The cheapest authenticated call available: it touches no observable,
        spends no search allowance, and proves the key resolves to an account.
        Only a rejected key is reported invalid — see
        :func:`~ti_recon.providers.urlscan.errors.credential_status_for`.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=URLSCAN_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        try:
            client = self._client_factory()
            try:
                await client.get_quotas(credential=credential)
            finally:
                await client.aclose()
        except ProviderError as error:
            return credential_validation_for(URLSCAN_PROVIDER_ID, error)
        return credential_validation_for(URLSCAN_PROVIDER_ID)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account.

        Deliberately free of API calls. What a specific key may see is
        discovered where it matters — at request time, where a refusal becomes
        ``PERMISSION_ERROR`` for that scan and leaves the rest usable.
        """
        capabilities = set(self._descriptor.capabilities)
        if not self._lookup_policy.allow_web_forensics:
            # An operator switching forensics off is a real capability change,
            # and reporting it here is what turns it into an honest coverage
            # gap rather than a silently missing answer.
            capabilities.discard(ProviderCapability.WEB_FORENSICS)
        return CapabilityDiscovery(
            provider_id=URLSCAN_PROVIDER_ID,
            capabilities=frozenset(capabilities),
            plan_hint="visibility is determined per scan",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(
                provider_id=URLSCAN_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        try:
            client = self._client_factory()
            try:
                await client.get_quotas(credential=credential)
            finally:
                await client.aclose()
        except ProviderError as error:
            unavailable = error.category in {
                ProviderErrorCategory.PROVIDER_UNAVAILABLE,
                ProviderErrorCategory.TRANSIENT_ERROR,
            }
            return ProviderHealthReport(
                provider_id=URLSCAN_PROVIDER_ID,
                health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
                detail=f"quota lookup returned {error.category.value}",
            )
        return ProviderHealthReport(
            provider_id=URLSCAN_PROVIDER_ID, health=ProviderHealth.AVAILABLE
        )

    # ------------------------------------------------------------------ #
    # Quota
    # ------------------------------------------------------------------ #

    async def fetch_quota(self, credential: CredentialMaterial) -> UrlscanQuotaReading:
        """Read this credential's allowances."""
        client = self._client_factory()
        try:
            result = await client.get_quotas(credential=credential)
        finally:
            await client.aclose()
        return self._reading_from(result.payload, credential)

    def _reading_from(
        self, payload: Mapping[str, Any], credential: CredentialMaterial
    ) -> UrlscanQuotaReading:
        return parse_user_quotas(
            payload,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
            retrieved_at=self._clock.now(),
        )

    async def _refresh_quota_if_stale(
        self, client: UrlscanClient, credential: CredentialMaterial
    ) -> ProviderQuotaSnapshot | None:
        """Read quota only when Task 6's store has nothing fresh.

        A failure here is swallowed on purpose: quota is useful context, and
        losing it must not turn a successful lookup into a failed one.
        """
        if not self._lookup_policy.quota_refresh_enabled:
            return None
        if self._quota_store is not None:
            existing = await self._quota_store.get(self._scope_identity(credential))
            if existing is not None:
                return None
        try:
            result = await client.get_quotas(credential=credential)
        except ProviderError as error:
            _logger.info(
                "urlscan quota lookup failed",
                extra={
                    "provider": URLSCAN_PROVIDER_ID,
                    "error_category": error.category.value,
                    "provider_error_code": error.provider_error_code,
                },
            )
            return None
        reading = self._reading_from(result.payload, credential)
        if self._quota_store is not None:
            await self._quota_store.put(self._scope_identity(credential), reading.snapshot)
        return reading.snapshot

    @staticmethod
    def _scope_identity(credential: CredentialMaterial) -> str:
        """The Task 6 scope key for this credential, rebuilt from ids only."""
        return ExecutionScope.for_user(
            provider_id=URLSCAN_PROVIDER_ID,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
        ).identity

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one observable from urlscan's history.

        One search, then up to a depth-bounded number of stored scan results.
        Nothing is submitted, rescanned or downloaded, and no artifact is
        retrieved unless forensics was explicitly requested.
        """
        if credential is None:
            raise ProviderInvalidRequestError(
                URLSCAN_PROVIDER_ID, message="urlscan requires a credential", operation="lookup"
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refusing here as well as in ``active_action`` means a caller
            # bypassing the executor still cannot turn a passive integration
            # into an active one.
            raise UnsupportedProviderOperation(URLSCAN_PROVIDER_ID, operation="active_action")

        limits = search_limits_for(request.depth, self._lookup_policy)
        plan = plan_search(request.intel_object, depth=request.depth, limits=limits)
        if plan is None:
            return self._envelope(
                request,
                UrlscanNormalization(warnings=(URLSCAN_NOT_SEARCHABLE,)),
                status=ProviderRunStatus.NO_DATA,
            )

        warnings: list[str] = []
        client = self._client_factory()
        try:
            search = await client.search(
                query=plan.query, size=plan.page_size, credential=credential
            )
            candidates = select_candidates(parse_hits(search.payload), limits)
            rate_limit = parse_rate_limit_headers(
                search.rate_limit_headers, operation="urlscan.search", now=self._clock.now()
            )
            if not candidates:
                quota = await self._refresh_quota_if_stale(client, credential)
                return self._envelope(
                    request,
                    UrlscanNormalization(),
                    status=ProviderRunStatus.NO_DATA,
                    quota=quota,
                    rate_limit=rate_limit,
                )

            normalization = UrlscanNormalization()
            documents: dict[str, ScanDocument] = {}
            for candidate in candidates:
                result, document, candidate_warning = await self._normalize_candidate(
                    client, request, candidate, credential
                )
                normalization = normalization.merge(result)
                if document is not None:
                    documents[candidate.scan_id] = document
                if candidate_warning is not None:
                    warnings.append(candidate_warning)

            normalization = normalization.merge(
                await self._web_forensics(client, request, candidates, documents, credential)
            )
            quota = await self._refresh_quota_if_stale(client, credential)
        finally:
            await client.aclose()

        if warnings:
            normalization = normalization.merge(UrlscanNormalization(warnings=tuple(warnings)))
        status = (
            ProviderRunStatus.PARTIAL
            if normalization.degraded or warnings
            else ProviderRunStatus.SUCCESS
        )
        return self._envelope(
            request, normalization, status=status, quota=quota, rate_limit=rate_limit
        )

    async def _normalize_candidate(
        self,
        client: UrlscanClient,
        request: ProviderRequest,
        candidate: ScanCandidate,
        credential: CredentialMaterial,
    ) -> tuple[UrlscanNormalization, ScanDocument | None, str | None]:
        """Fetch and normalize one stored scan.

        A scan that cannot be retrieved — deleted, or private to another team —
        degrades this lookup to partial rather than failing it: the other scans
        still produced evidence, and losing all of it over one missing document
        would be the wrong trade.
        """
        try:
            result = await client.get_result(scan_id=candidate.scan_id, credential=credential)
        except ProviderError as error:
            _logger.info(
                "urlscan scan result unavailable",
                extra={
                    "provider": URLSCAN_PROVIDER_ID,
                    "error_category": error.category.value,
                    "operation": "urlscan.result",
                },
            )
            return UrlscanNormalization(), None, URLSCAN_SCAN_UNRETRIEVABLE
        document = ScanDocument(result.payload)
        return self._normalize_document(request, document), document, None

    def _normalize_document(
        self,
        request: ProviderRequest,
        document: ScanDocument,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> UrlscanNormalization:
        """Every normalization pass over one scan document.

        Each pass is independent, so one missing or unreadable block still
        leaves the others. None of them produces a verdict.
        """
        context = NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
            match_scope=match_scope_for_scan(request.intel_object, document),
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        result = UrlscanNormalization(
            objects=(enrich_primary_object(request.intel_object, document),)
        )
        for normalize in (
            normalize_verdicts,
            normalize_scan_observation,
            normalize_page_context,
            normalize_redirect_chain,
            normalize_contacted_infrastructure,
            normalize_served_bodies,
            normalize_traffic_summary,
        ):
            result = result.merge(normalize(context, document))
        return result

    # ------------------------------------------------------------------ #
    # Web forensics
    # ------------------------------------------------------------------ #

    async def _web_forensics(
        self,
        client: UrlscanClient,
        request: ProviderRequest,
        candidates: tuple[ScanCandidate, ...],
        documents: Mapping[str, ScanDocument],
        credential: CredentialMaterial,
    ) -> UrlscanNormalization:
        """Retrieve stored artifacts, but only when explicitly asked to.

        The gate is checked here and nowhere else, so there is exactly one place
        where "may we pull page content" is decided. When it refuses, that is
        recorded as a warning rather than passed over in silence: an analyst who
        asked for forensics and got none should be able to see why.

        Only the newest selected scan is captured. Artifacts are large, and the
        current state of a page is what a forensic question is almost always
        about; capturing every candidate would multiply the cost for very little
        extra signal.
        """
        if not forensics_requested(request, self._lookup_policy):
            if ProviderCapability.WEB_FORENSICS in request.requested_capabilities:
                return UrlscanNormalization(warnings=(URLSCAN_FORENSICS_NOT_REQUESTED,))
            return UrlscanNormalization()
        if self._artifact_store is None:
            # Nowhere to put page content is a reason not to fetch it.
            return UrlscanNormalization(warnings=(URLSCAN_ARTIFACTS_UNAVAILABLE,))

        candidate = candidates[0]
        scope = ArtifactScope(user_id=credential.user_id, investigation_id=request.investigation_id)
        result = UrlscanNormalization()
        captured = 0

        if self._lookup_policy.allows(ArtifactKind.SCREENSHOT):
            screenshot = await self._fetch_artifact(
                client.get_screenshot(scan_id=candidate.scan_id, credential=credential)
            )
            stored = self._keep(scope, ArtifactKind.SCREENSHOT, screenshot, candidate)
            if stored is not None:
                # A screenshot is for a human to look at. There is nothing this
                # module would trust itself to extract from pixels.
                captured += 1
                result = result.merge(self._captured_evidence(request, candidate, stored))

        if self._lookup_policy.allows(ArtifactKind.DOM):
            dom = await self._fetch_artifact(
                client.get_dom(scan_id=candidate.scan_id, credential=credential)
            )
            stored = self._keep(scope, ArtifactKind.DOM, dom, candidate)
            if stored is not None and dom is not None:
                captured += 1
                result = result.merge(self._captured_evidence(request, candidate, stored))
                result = result.merge(
                    forensic_evidence(
                        self._forensic_context(request),
                        analyze_dom(dom.content, page_url=candidate.final_url),
                        artifact_id=stored.id,
                    )
                )

        bodies = await self._response_body_forensics(
            client, request, candidate, documents.get(candidate.scan_id), scope, credential
        )
        captured += bodies.captured
        result = result.merge(bodies.normalization)

        if not captured:
            return UrlscanNormalization(warnings=(URLSCAN_ARTIFACTS_UNAVAILABLE,))
        return result

    async def _response_body_forensics(
        self,
        client: UrlscanClient,
        request: ProviderRequest,
        candidate: ScanCandidate,
        document: ScanDocument | None,
        scope: ArtifactScope,
        credential: CredentialMaterial,
    ) -> _ForensicCapture:
        """Retrieve and statically analyse a few stored response bodies.

        Only textual ones, only up to the policy's budget, and only bodies
        urlscan already holds. Nothing is fetched from the original site, and
        nothing retrieved is ever executed — see
        :mod:`ti_recon.providers.urlscan.forensics`.
        """
        if document is None or not self._lookup_policy.allows(ArtifactKind.RESPONSE_BODY):
            return _ForensicCapture(UrlscanNormalization(), 0)
        digests = select_response_bodies(document, self._lookup_policy.max_response_bodies)

        result = UrlscanNormalization()
        captured = 0
        for digest in digests:
            body = await self._fetch_artifact(
                client.get_response_body(body_sha256=digest, credential=credential)
            )
            stored = self._keep(scope, ArtifactKind.RESPONSE_BODY, body, candidate)
            if stored is None or body is None:
                continue
            captured += 1
            result = result.merge(self._captured_evidence(request, candidate, stored))
            result = result.merge(
                forensic_evidence(
                    self._forensic_context(request),
                    analyze_script(body.content),
                    artifact_id=stored.id,
                    claim_type="urlscan_response_forensics",
                )
            )
        return _ForensicCapture(result, captured)

    def _keep(
        self,
        scope: ArtifactScope,
        kind: ArtifactKind,
        artifact: UrlscanArtifact | None,
        candidate: ScanCandidate,
    ) -> StoredArtifact | None:
        """Store one fetched artifact, if there was one and it fits."""
        if artifact is None or self._artifact_store is None:
            return None
        return self._store_artifact(self._artifact_store, scope, kind, artifact, candidate)

    def _captured_evidence(
        self, request: ProviderRequest, candidate: ScanCandidate, artifact: StoredArtifact
    ) -> UrlscanNormalization:
        return UrlscanNormalization(
            evidence=(self._artifact_evidence(request, candidate, artifact),)
        )

    def _forensic_context(self, request: ProviderRequest) -> NormalizationContext:
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
        )

    @staticmethod
    async def _fetch_artifact(awaitable: Awaitable[UrlscanArtifact]) -> UrlscanArtifact | None:
        """Await one artifact fetch, treating an absent artifact as absent.

        Not every scan has a screenshot or a stored DOM, and a missing one is
        an ordinary fact rather than a failure of the lookup.
        """
        try:
            artifact = await awaitable
        except ProviderError as error:
            _logger.info(
                "urlscan artifact unavailable",
                extra={
                    "provider": URLSCAN_PROVIDER_ID,
                    "error_category": error.category.value,
                },
            )
            return None
        return artifact if artifact.content else None

    @staticmethod
    def _store_artifact(
        store: ArtifactStore,
        scope: ArtifactScope,
        kind: ArtifactKind,
        artifact: UrlscanArtifact,
        candidate: ScanCandidate,
    ) -> StoredArtifact | None:
        """Put one artifact in the store, or give up quietly if it will not fit.

        A budget refusal is not an error for the lookup: the enrichment evidence
        is already gathered, and failing the whole run because a screenshot did
        not fit would trade real findings for a picture.
        """
        try:
            return store.put(
                scope,
                provider_id=URLSCAN_PROVIDER_ID,
                kind=kind,
                content=artifact.content,
                content_type=artifact.content_type,
                provider_reference=candidate.scan_id,
                truncated=artifact.truncated,
            )
        except ArtifactStoreError as error:
            _logger.info(
                "urlscan artifact not stored",
                extra={
                    "provider": URLSCAN_PROVIDER_ID,
                    "artifact_kind": kind.value,
                    "reason": type(error).__name__,
                },
            )
            return None

    def _artifact_evidence(
        self, request: ProviderRequest, candidate: ScanCandidate, artifact: StoredArtifact
    ) -> Evidence:
        """Record that an artifact was captured — never its content.

        Context only. Holding a page's DOM says nothing about the page; what it
        gives an analyst is something to point at when a later finding needs
        explaining.
        """
        context = NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
        )
        return build_evidence(
            context,
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="urlscan_stored_artifact",
            effect=EvidenceEffect.CONTEXT_ONLY,
            attributes={
                "artifact_id": artifact.id,
                "kind": artifact.kind.value,
                "content_type": artifact.content_type,
                "sha256": artifact.content_sha256,
                "size_bytes": artifact.size_bytes,
                "truncated": artifact.truncated,
                "scan_id": candidate.scan_id,
            },
            observed_at=candidate.scanned_at,
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
        """Turn one stored scan document into Task 3 models. Pure, no I/O."""
        normalization = self._normalize_document(
            request, ScanDocument(payload), raw_reference=raw_reference
        )
        return _payload_of(normalization)

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category.

        Transport security failures are reported as invalid requests rather than
        as provider problems: refusing to leave urlscan's host is our decision,
        not urlscan misbehaving.
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

    def _envelope(
        self,
        request: ProviderRequest,
        normalization: UrlscanNormalization,
        *,
        status: ProviderRunStatus,
        quota: ProviderQuotaSnapshot | None = None,
        rate_limit: RateLimitSnapshot | None = None,
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=URLSCAN_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=_payload_of(normalization),
            quota=quota,
            rate_limit=rate_limit,
        )


def _payload_of(normalization: UrlscanNormalization) -> NormalizedPayload:
    return NormalizedPayload(
        evidence=normalization.evidence,
        objects=normalization.objects,
        relationships=normalization.relationships,
        warnings=normalization.warnings,
    )
