"""Provider-neutral inputs for readiness tests.

Task 18 consumes four finished artifacts. Building them by hand keeps each test
about one readiness rule rather than about how a provider happens to answer, and
lets a scenario state exactly which capability was checked, blocked or never
attempted -- which is the distinction the whole layer turns on.

The Task 17 assessment is produced by the **real fusion engine** over real
claims, so readiness is always reasoning about an assessment fusion actually
reached rather than one a test asserted into existence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fixtures.fusion import envelope, evidence, fuse_with_semantics
from fixtures.fusion import file_object as fusion_file_object
from fixtures.fusion import observable as fusion_observable
from fixtures.fusion import scenario as fusion_scenario
from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.models.coverage import CoverageItem
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning.models import (
    AdaptiveEnrichmentResult,
    CallCostClass,
    EnrichmentBudget,
    NoveltyClass,
    PlannedProviderCall,
    PlanningDecision,
    ProviderAttempt,
    ProviderLocality,
    SelectionReason,
    SkippedCandidate,
    SkipReason,
    StopReason,
)
from ti_recon.reasoning.false_positive.models import (
    DoesNotEstablish,
    FindingLimitation,
    FindingLink,
    LinkRelation,
    LinkTarget,
    ReasonCode,
    ReasoningDimension,
    ReasoningFinding,
    ReasoningRole,
    finding_id_for,
)
from ti_recon.reasoning.false_positive.policy import (
    FALSE_POSITIVE_REASONING_POLICY_VERSION,
    RULE_IDS,
)
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    SignalOrigin,
    observable_subject,
)
from ti_recon.reasoning.readiness import AssessmentReadinessEngine, ReadinessPurpose
from ti_recon.reasoning.results import TemporalContextResult
from ti_recon.versions import ENGINE_VERSION

#: One fixed instant. Readiness reads no clock, so every run shares this.
AS_OF = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

observable = fusion_observable
file_object = fusion_file_object


def attempt(
    capability: ProviderCapability,
    *,
    provider: str = "alpha",
    source_family: str | None = None,
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
    called_provider: bool = True,
    cache_hit: bool = False,
    locality: ProviderLocality = ProviderLocality.REMOTE,
    produced_evidence: bool = True,
    sequence: int = 1,
) -> ProviderAttempt:
    """One recorded execution, described in generic terms."""
    return ProviderAttempt(
        sequence=sequence,
        provider_id=provider,
        capability=capability,
        source_family=source_family or provider,
        locality=locality,
        cost_class=CallCostClass.LOW,
        reason=SelectionReason.MISSING_CAPABILITY,
        novelty=NoveltyClass.NEW_CAPABILITY,
        status=status,
        called_provider=called_provider,
        cache_hit=cache_hit,
        attempts=1,
        duration_ms=1.0,
        coverage_gained=status is ProviderRunStatus.SUCCESS,
        # A partial result usually carries reduced evidence; Task 6 documents
        # that an adapter may instead raise with nothing to show, which a test
        # asks for by passing produced_evidence=False.
        produced_evidence=produced_evidence
        and status in {ProviderRunStatus.SUCCESS, ProviderRunStatus.PARTIAL},
        recorded_at=AS_OF,
    )


def bundled_call(
    primary: ProviderCapability,
    answered: frozenset[ProviderCapability],
    *,
    provider: str = "alpha",
    source_family: str | None = None,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> PlannedProviderCall:
    """One request the planner bundled to answer several goals at once.

    The shape Task 13 produces when a provider declares that one read returns
    its whole document: ``capability`` is the goal that won the decision and
    ``answered_capabilities`` is everything the response covers.
    """
    return PlannedProviderCall(
        provider_id=provider,
        capability=primary,
        capabilities=frozenset({primary}) | answered,
        answered_capabilities=frozenset({primary}) | answered,
        source_family=source_family or provider,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        depth=depth,
        reason=SelectionReason.MISSING_CAPABILITY,
        novelty=NoveltyClass.NEW_CAPABILITY,
    )


def skipped(
    capability: ProviderCapability,
    reason: SkipReason,
    *,
    provider: str = "beta",
) -> SkippedCandidate:
    """One candidate the planner declined, with the reason it recorded."""
    return SkippedCandidate(provider_id=provider, capability=capability, reason=reason)


def coverage_item(
    capability: ProviderCapability,
    *,
    status: CoverageStatus = CoverageStatus.COVERED,
    relevance: CoverageRelevance = CoverageRelevance.RELEVANT,
    providers_considered: tuple[str, ...] = ("alpha",),
    reason: str | None = None,
) -> CoverageItem:
    """The planner's own coverage statement for one capability."""
    if status in {CoverageStatus.NOT_COVERED, CoverageStatus.PARTIAL} and reason is None:
        reason = "test fixture"
    return CoverageItem(
        capability=capability,
        relevance=relevance,
        status=status,
        providers_considered=providers_considered,
        reason=reason,
    )


def signal(signal_type: ContextSignalType, subject: IntelObject) -> ContextSignal:
    """One Task 15 context signal about the subject."""
    return ContextSignal(
        signal_type=signal_type,
        subject=observable_subject(subject.canonical_key),
        origin=SignalOrigin.ENGINE_POLICY,
        source_key="fixture",
    )


def finding_stale(subject: IntelObject, evidence_id: str) -> ReasoningFinding:
    """A Task 16 finding whose supporting context came from a stale dataset."""
    subject_ref = observable_subject(subject.canonical_key)
    links = (
        FindingLink(relation=LinkRelation.QUALIFIES, target=LinkTarget.EVIDENCE, ref=evidence_id),
    )
    return ReasoningFinding(
        finding_id=finding_id_for(
            policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
            rule_id=RULE_IDS["shared_infrastructure"],
            subject=subject_ref,
            match_scope=subject_ref
            and __import__("ti_recon.enums", fromlist=["MatchScope"]).MatchScope.EXACT_OBSERVABLE,
            link_refs=tuple(item.ref for item in links),
        ),
        rule_id=RULE_IDS["shared_infrastructure"],
        policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
        role=ReasoningRole.ATTRIBUTION_CAUTION,
        dimension=ReasoningDimension.ATTRIBUTION,
        reason_code=ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION,
        subject=subject_ref,
        match_scope=__import__(
            "ti_recon.enums", fromlist=["MatchScope"]
        ).MatchScope.EXACT_OBSERVABLE,
        links=links,
        does_not_establish=(DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,),
        limitations=(FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE,),
    )


@dataclass
class ReadinessScenario:
    """One finished investigation, ready to be evaluated for readiness."""

    root: IntelObject
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    requested_capabilities: frozenset[ProviderCapability] = frozenset()
    attempts: list[ProviderAttempt] = field(default_factory=list)
    skips: list[SkippedCandidate] = field(default_factory=list)
    coverage: list[CoverageItem] = field(default_factory=list)
    calls: list[PlannedProviderCall] = field(default_factory=list)
    signals: list[ContextSignal] = field(default_factory=list)
    findings: list[ReasoningFinding] = field(default_factory=list)
    stop_reason: StopReason = StopReason.GOALS_SATISFIED
    budget: EnrichmentBudget = field(
        default_factory=lambda: EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=1)
    )
    _claims: dict[str, str] = field(default_factory=dict)
    _envelopes: list[Any] = field(default_factory=list)

    def with_attempt(self, item: ProviderAttempt) -> ReadinessScenario:
        self.attempts.append(item)
        return self

    def with_call(self, item: PlannedProviderCall) -> ReadinessScenario:
        """Record a bundled call the way the planner would."""
        self.calls.append(item)
        return self

    def with_skip(self, item: SkippedCandidate) -> ReadinessScenario:
        self.skips.append(item)
        return self

    def with_coverage(self, item: CoverageItem) -> ReadinessScenario:
        self.coverage.append(item)
        return self

    def with_signal(self, item: ContextSignal) -> ReadinessScenario:
        self.signals.append(item)
        return self

    def with_finding(self, item: ReasoningFinding) -> ReadinessScenario:
        self.findings.append(item)
        return self

    def with_stop(self, reason: StopReason) -> ReadinessScenario:
        self.stop_reason = reason
        return self

    def with_claim(
        self,
        semantic: str,
        *,
        provider: str = "alpha",
        source_family: str | None = None,
        subject: IntelObject | None = None,
        **kwargs: Any,
    ) -> ReadinessScenario:
        """One directional claim, fused by the real Task 17 engine."""
        target = self.root if subject is None else subject
        record = evidence(
            target, provider=provider, source_family=source_family or provider, **kwargs
        )
        self._envelopes.append(envelope(record, provider=provider, objects=(target,)))
        self._claims[record.id] = semantic
        return self

    def planning(self) -> AdaptiveEnrichmentResult:
        # One decision per bundled call, then a terminating decision carrying
        # the candidates the planner declined when the run stopped.
        decisions = (
            *(
                PlanningDecision(sequence=index + 1, call=call)
                for index, call in enumerate(self.calls)
            ),
            PlanningDecision(
                sequence=len(self.calls) + 1,
                stop=self.stop_reason,
                skipped=tuple(self.skips),
            ),
        )
        return AdaptiveEnrichmentResult(
            target=self.root,
            depth=self.depth,
            requested_capabilities=self.requested_capabilities,
            attempts=tuple(self.attempts),
            decisions=decisions,
            coverage=tuple(self.coverage),
            budget=self.budget,
            stop_reason=self.stop_reason,
        )

    def fusion(self) -> Any:
        scene = fusion_scenario(self.root)
        for item in self._envelopes:
            scene = scene.with_envelope(item)
        return fuse_with_semantics(scene, dict(self._claims))

    def qualification(self) -> TemporalContextResult:
        return TemporalContextResult(
            evaluated_at=AS_OF,
            engine_version=ENGINE_VERSION,
            context_policy_version="1.0.0",
            warninglist_map_version="1.0.0",
            context_signals=tuple(self.signals),
        )

    def reasoning(self) -> FalsePositiveReasoningResult:
        return FalsePositiveReasoningResult(
            policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
            qualification_policy_version="1.0.0",
            engine_version=ENGINE_VERSION,
            as_of=AS_OF,
            findings=tuple(self.findings),
        )


def scenario(root: IntelObject, **kwargs: Any) -> ReadinessScenario:
    return ReadinessScenario(root=root, **kwargs)


def assess(
    scene: ReadinessScenario,
    *,
    purpose: ReadinessPurpose = ReadinessPurpose.ANALYST_TRIAGE,
    engine: AssessmentReadinessEngine | None = None,
) -> Any:
    """Run Task 17 then Task 18 over one scenario."""
    fusion = scene.fusion()
    runner = AssessmentReadinessEngine() if engine is None else engine
    return runner.evaluate(
        fusion=fusion,
        planning=scene.planning(),
        qualification=scene.qualification(),
        reasoning=scene.reasoning(),
        purpose=purpose,
    )
