"""The Hybrid Analysis provider adapter (Task 12).

Implements the Task 5 :class:`ProviderAdapter` contract over Falcon Sandbox's
passive read paths. It normalizes and classifies; it decides nothing about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

The question this adapter answers
---------------------------------

*What happened when this sample was previously analysed in a sandbox, in which
environment, and how informative was that run?*

Not: *the sandbox saw nothing, so the file is fine.* There is no path through
this adapter that produces benign evidence — not from an absence, not from a
failed detonation, not from a clean run.

Request budget
--------------

One hash search, plus at most two report summaries, so a lookup costs 1, 2 or 3
physical requests at QUICK, STANDARD and DEEP. A restricted key allows roughly
five requests a minute, so a naive "summarize every report" would exhaust an
analyst's allowance on a single well-studied hash. Which reports get read, and
why, is :mod:`ti_recon.sandbox.selection`.

Nothing is submitted and nothing is downloaded
----------------------------------------------

There is no submission or download path to disable — the client cannot express
one. Active sandboxing is deferred deliberately: the public service is a
community platform whose terms allow retention and redistribution of what it
receives, so detonating a customer's file needs explicit approval and a privacy
warning rather than a code path that already exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Protocol

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    InvestigationDepth,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
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
from ti_recon.providers.hybrid_analysis.client import (
    HASH_LENGTHS,
    ContainerReport,
    HybridAnalysisClient,
    HybridAnalysisHttpClient,
)
from ti_recon.providers.hybrid_analysis.config import HybridAnalysisConfig
from ti_recon.providers.hybrid_analysis.descriptor import (
    HYBRID_ANALYSIS_PROVIDER_ID,
    build_hybrid_analysis_descriptor,
)
from ti_recon.providers.hybrid_analysis.errors import credential_validation_for
from ti_recon.providers.hybrid_analysis.models import (
    read_key_info,
    read_report_summary,
    read_search_result,
)
from ti_recon.providers.hybrid_analysis.normalizer import (
    NormalizationContext,
    ObjectRegistry,
    SandboxNormalization,
    normalize_behaviour,
    normalize_coverage,
    normalize_no_report,
    normalize_sample_assessment,
)
from ti_recon.providers.hybrid_analysis.policy import HybridAnalysisLookupPolicy
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import (
    NormalizedPayload,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)
from ti_recon.providers.transport import ProviderTransportError
from ti_recon.sandbox.models import SandboxReportSummary, SandboxSampleView
from ti_recon.sandbox.selection import ReportSelection, select_reports

__all__ = [
    "HYBRID_ANALYSIS_NOT_SUPPORTED",
    "UNSUPPORTED_REASONS",
    "HybridAnalysisAdapter",
    "HybridAnalysisClientFactory",
]

#: Reported when the observable is not a file, or is a file with no digest this
#: API accepts. A coverage gap, never an absence of findings.
HYBRID_ANALYSIS_NOT_SUPPORTED: Final[str] = "HYBRID_ANALYSIS_OBSERVABLE_NOT_SUPPORTED"

UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    HYBRID_ANALYSIS_NOT_SUPPORTED: (
        "Hybrid Analysis is searched by file hash for existing sandbox reports; "
        "this observable has no such lookup"
    )
}

#: Digest preference. One request, strongest first — the API resolves any of the
#: three to the same sample, so asking three times would spend three of a
#: five-per-minute allowance to receive the same answer.
_HASH_PREFERENCE: Final[tuple[str, ...]] = ("SHA-256", "SHA-1", "MD5")


class HybridAnalysisClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> HybridAnalysisClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to Hybrid Analysis."""

    def __init__(self, config: HybridAnalysisConfig) -> None:
        self._config = config

    def __call__(self) -> HybridAnalysisClient:
        return HybridAnalysisHttpClient(self._config)


class HybridAnalysisAdapter(ProviderAdapter):
    """Passive historical sandbox intelligence."""

    def __init__(
        self,
        *,
        client_factory: HybridAnalysisClientFactory | None = None,
        config: HybridAnalysisConfig | None = None,
        lookup_policy: HybridAnalysisLookupPolicy | None = None,
    ) -> None:
        self._config = HybridAnalysisConfig() if config is None else config
        self._client_factory: HybridAnalysisClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = (
            HybridAnalysisLookupPolicy() if lookup_policy is None else lookup_policy
        )
        self._descriptor = build_hybrid_analysis_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> HybridAnalysisConfig:
        return self._config

    @property
    def lookup_policy(self) -> HybridAnalysisLookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a key against ``/key/current``.

        The one place that endpoint is used. It is never called before a lookup:
        a successful hash search already proves the key can do the work, and
        asking permission first would halve an allowance measured in single
        digits per minute.

        Only a rejected key is reported invalid. A permission failure means the
        key works but is below the authorization level for something — which is
        the expected state of a restricted key, not a reason to replace it.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        client = self._client_factory()
        try:
            response = await client.key_current(credential=credential)
        except ProviderError as error:
            return credential_validation_for(HYBRID_ANALYSIS_PROVIDER_ID, error)
        finally:
            await client.aclose()
        info = read_key_info(response.payload)
        return CredentialValidation(
            provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
            status=CredentialStatus.ACTIVE,
            detail=info.get("auth_level_name"),
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account."""
        return CapabilityDiscovery(
            provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
            capabilities=frozenset(self._descriptor.capabilities),
            plan_hint="passive historical sandbox reports; no submission, no downloads",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(
                provider_id=HYBRID_ANALYSIS_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        client = self._client_factory()
        try:
            await client.key_current(credential=credential)
        except ProviderError as error:
            unavailable = error.category in {
                ProviderErrorCategory.PROVIDER_UNAVAILABLE,
                ProviderErrorCategory.TRANSIENT_ERROR,
            }
            return ProviderHealthReport(
                provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
                health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
                detail=f"probe returned {error.category.value}",
            )
        finally:
            await client.aclose()
        return ProviderHealthReport(
            provider_id=HYBRID_ANALYSIS_PROVIDER_ID, health=ProviderHealth.AVAILABLE
        )

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Find and normalize existing sandbox reports for one sample."""
        if credential is None:
            raise ProviderInvalidRequestError(
                HYBRID_ANALYSIS_PROVIDER_ID,
                message="hybrid analysis requires a credential",
                operation="lookup",
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refused here as well as in ``active_action``: a caller bypassing the
            # executor still cannot turn a passive integration into one that
            # submits a customer's file to a community sandbox.
            raise UnsupportedProviderOperation(
                HYBRID_ANALYSIS_PROVIDER_ID, operation="active_action"
            )

        planned = self._plan(request.intel_object)
        if planned is None:
            return self._unsupported_envelope(request)
        algorithm, digest = planned

        client = self._client_factory()
        requests_made = 0
        rate_limit: RateLimitSnapshot | None = None
        containers: list[str] = []
        unavailable: list[str] = []
        summaries: list[SandboxReportSummary] = []
        try:
            search = await client.search_hash(file_hash=digest, credential=credential)
            requests_made += 1
            rate_limit = search.rate_limit or rate_limit
            sha256, refs = read_search_result(search.payload)

            selection = select_reports(refs, request.depth)
            bounds = self._lookup_policy.bounds(request.depth)
            for ref in selection.selected:
                try:
                    detail = await client.report_summary(
                        report_id=ref.report_id, credential=credential
                    )
                except ContainerReport as container:
                    # A real answer about a real report. Children are named and
                    # deliberately not followed.
                    requests_made += 1
                    containers.append(container.report_id)
                    continue
                except ProviderError as error:
                    if error.category is ProviderErrorCategory.NOT_FOUND:
                        # The index described this report moments ago, so it has
                        # gone rather than never existed. One report lost, not the
                        # lookup.
                        requests_made += 1
                        unavailable.append(ref.report_id)
                        continue
                    raise
                requests_made += 1
                rate_limit = detail.rate_limit or rate_limit
                summary = read_report_summary(
                    detail.payload, report_id=ref.report_id, bounds=bounds
                )
                if summary is None:
                    unavailable.append(ref.report_id)
                    continue
                summaries.append(summary)
        finally:
            await client.aclose()

        view = SandboxSampleView(canonical_sha256=sha256, reports=refs, summaries=tuple(summaries))
        return self._envelope(
            request,
            view=view,
            selection=selection,
            algorithm=algorithm,
            requests_made=requests_made,
            rate_limit=rate_limit,
            containers=tuple(containers),
            unavailable=tuple(unavailable),
        )

    def _plan(self, intel_object: IntelObject) -> tuple[str, str] | None:
        """``(algorithm, digest)`` for the one search, or ``None``.

        Strongest available digest, once. The API resolves MD5, SHA-1 and SHA-256
        to the same sample, so asking under each would spend three requests of a
        five-per-minute allowance for one answer.
        """
        if intel_object.object_type is not IntelObjectType.FILE:
            return None
        hashes = intel_object.hashes
        for algorithm in _HASH_PREFERENCE:
            digest = hashes.get(algorithm)
            if digest and len(digest) in HASH_LENGTHS:
                return algorithm, digest
        return None

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def _envelope(
        self,
        request: ProviderRequest,
        *,
        view: SandboxSampleView,
        selection: ReportSelection,
        algorithm: str,
        requests_made: int,
        rate_limit: RateLimitSnapshot | None,
        containers: tuple[str, ...],
        unavailable: tuple[str, ...],
    ) -> ProviderResultEnvelope:
        """Assemble the result, and decide what status honestly describes it."""
        context = NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            sample_sha256=view.canonical_sha256,
        )
        normalization = SandboxNormalization()

        if view.reports:
            normalization = normalization.merge(normalize_sample_assessment(context, view))
            # One registry for the whole lookup: two reports observing the same C2
            # contribute two relationships to one object, not two objects.
            registry = ObjectRegistry()
            for summary in view.summaries:
                normalization = normalization.merge(normalize_behaviour(context, summary, registry))
        else:
            normalization = normalization.merge(normalize_no_report(context))

        partial_reason = self._partial_reason(
            view=view, selection=selection, containers=containers, unavailable=unavailable
        )
        normalization = normalization.merge(
            normalize_coverage(
                context,
                view=view,
                selection=selection,
                depth=request.depth.value,
                queried_hash_algorithm=algorithm,
                requests_made=requests_made,
                partial_reason=partial_reason,
                container_reports=containers,
                unavailable_reports=unavailable,
            )
        )

        if not view.reports:
            status = ProviderRunStatus.NO_DATA
        elif partial_reason is not None:
            status = ProviderRunStatus.PARTIAL
        else:
            status = ProviderRunStatus.SUCCESS

        return ProviderResultEnvelope.from_payload(
            provider=HYBRID_ANALYSIS_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=NormalizedPayload(
                evidence=normalization.evidence,
                objects=normalization.objects,
                relationships=normalization.relationships,
            ),
            rate_limit=rate_limit,
        )

    def _partial_reason(
        self,
        *,
        view: SandboxSampleView,
        selection: ReportSelection,
        containers: tuple[str, ...],
        unavailable: tuple[str, ...],
    ) -> str | None:
        """Why this lookup is incomplete, or ``None``.

        Deliberately narrow. Not summarizing thirty-eight of forty reports is the
        *designed* behaviour, not a degradation — reporting PARTIAL for it would
        make the status meaningless at every depth. What counts is a summary that
        was asked for and could not be read.
        """
        if containers and unavailable:
            return (
                f"{len(containers)} selected reports are containers, "
                f"{len(unavailable)} could not be retrieved"
            )
        if containers:
            return f"{len(containers)} selected reports are containers"
        if unavailable:
            return f"{len(unavailable)} selected reports could not be retrieved"
        if selection.selected and not view.summaries:
            return "no selected report summary could be read"
        return None

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
        """Normalize a hash-search document without performing any I/O.

        Index only: the report summaries are separate documents this method was
        not given, so it yields the sample-level assessment and coverage and no
        behaviour.
        """
        planned = self._plan(request.intel_object)
        if planned is None:
            return NormalizedPayload(warnings=(HYBRID_ANALYSIS_NOT_SUPPORTED,))
        algorithm, _ = planned
        sha256, refs = read_search_result(dict(payload))
        view = SandboxSampleView(canonical_sha256=sha256, reports=refs)
        selection = select_reports(refs, InvestigationDepth.QUICK)
        envelope = self._envelope(
            request,
            view=view,
            selection=selection,
            algorithm=algorithm,
            requests_made=0,
            rate_limit=None,
            containers=(),
            unavailable=(),
        )
        return NormalizedPayload(
            evidence=envelope.evidence,
            objects=envelope.objects,
            relationships=envelope.relationships,
            warnings=envelope.warnings,
        )

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category."""
        if isinstance(error, ContainerReport):
            # A container is a semantic answer, not a failure. Reported as a
            # partial-result category rather than anything that looks like an
            # outage.
            return ProviderErrorCategory.PARTIAL_RESULT
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
            provider=HYBRID_ANALYSIS_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(HYBRID_ANALYSIS_NOT_SUPPORTED,),
            error_message=UNSUPPORTED_REASONS[HYBRID_ANALYSIS_NOT_SUPPORTED],
        )

    def __repr__(self) -> str:
        return f"<HybridAnalysisAdapter provider={HYBRID_ANALYSIS_PROVIDER_ID}>"
