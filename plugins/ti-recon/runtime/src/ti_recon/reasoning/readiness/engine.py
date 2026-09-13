"""Assessment readiness and coverage adequacy (Task 18).

Consumes what Tasks 13-17 already produced and answers one question: **was the
collection behind this assessment adequate for analyst triage, and if not, what
is missing?**

It performs no enrichment. No HTTP, no DNS, no provider call, no planner run, no
clock read. Every input is a finished artifact, so a stored investigation can be
re-evaluated years later with the network unplugged and give the same answer.

The two things it must never do
-------------------------------

**It never touches the assessment.** Verdict, confidence, rules, claims,
contributions and conflicts are read-only. MALICIOUS at HIGH with no sandbox
coverage stays MALICIOUS at HIGH; the missing sandbox becomes a limitation
recorded beside it. Coverage incompleteness is not doubt about correctness, and
folding one into the other is precisely the mistake Task 17 had to fix twice.

**It never recommends an action.** It does not know asset criticality, business
impact, user context, compensating controls or incident policy, so it cannot say
whether to block, quarantine, escalate or close. It can say whether the external
sources worth asking have been asked.

Input consistency is checked, not assumed
-----------------------------------------

Fusing a planning run for one observable with an assessment of another would
produce a confident answer about nothing in particular. The target keys must
agree and the depths must match before anything is evaluated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from ti_recon.enums import (
    CoverageRelevance,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.planning.models import AdaptiveEnrichmentResult
from ti_recon.planning.policy import EnrichmentPolicy
from ti_recon.reasoning.false_positive.models import FindingLimitation
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.fusion.independence import independence_groups
from ti_recon.reasoning.fusion.models import FusionIssueType
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.coverage import (
    capability_checks,
    capability_coverage_items,
    completion_for,
    directional_capabilities_by_provider,
    directional_provider_ids,
)
from ti_recon.reasoning.readiness.gaps import (
    gaps_from_evaluations,
    information_needs_from_gaps,
    outlook_for,
)
from ti_recon.reasoning.readiness.metrics import (
    NoOpReadinessMetricsSink,
    ReadinessMetric,
    ReadinessMetricsSink,
)
from ti_recon.reasoning.readiness.models import (
    CheckCompletion,
    CoverageRequirement,
    GapType,
    InformationYield,
    ReadinessCoverageSummary,
    ReadinessGap,
    ReadinessPurpose,
    RequirementActivation,
    RequirementEvaluation,
    RequirementStatus,
    gap_id_for,
    readiness_id_for,
    requirement_id_for,
)
from ti_recon.reasoning.readiness.policy import (
    BASIS_RATIONALE,
    DIRECTIONAL_SEARCH_CAPABILITIES,
    READINESS_POLICY_VERSION,
    SUPPORTED_PURPOSES,
    adequacy_for,
    continuation_for,
    requires_independent_challenge,
    status_for,
)
from ti_recon.reasoning.readiness.requirements import (
    EvaluationInputs,
    evaluate_requirement,
    requirements_from_goals,
)
from ti_recon.reasoning.readiness.results import (
    AssessmentReadinessResult,
    ReadinessPolicyVersions,
)
from ti_recon.reasoning.results import TemporalContextResult

__all__ = ["AssessmentReadinessEngine", "ReadinessInputMismatch"]


class ReadinessInputMismatch(ValueError):
    """Inputs describe different investigations, so nothing may be concluded."""


#: Integrity is a property of the run rather than of the observable, so the
#: requirement id behind an unresolved-input gap must not vary by object type.
_INTEGRITY_OBJECT_TYPE: Final[IntelObjectType] = IntelObjectType.FILE


@dataclass
class AssessmentReadinessEngine:
    """Evaluate one finished investigation against one readiness profile.

    Stateless between runs: everything it needs arrives as arguments, so two
    evaluations cannot influence each other.
    """

    policy: EnrichmentPolicy = field(default_factory=EnrichmentPolicy)
    metrics: ReadinessMetricsSink = field(default_factory=NoOpReadinessMetricsSink)

    def evaluate(
        self,
        *,
        fusion: FusionResult,
        planning: AdaptiveEnrichmentResult,
        qualification: TemporalContextResult,
        reasoning: FalsePositiveReasoningResult,
        purpose: ReadinessPurpose = ReadinessPurpose.ANALYST_TRIAGE,
    ) -> AssessmentReadinessResult:
        """Assess coverage adequacy for one purpose."""
        self._check_inputs(fusion=fusion, planning=planning, purpose=purpose)

        assessment = fusion.assessment
        depth = planning.depth
        object_type = planning.target.object_type

        goals = self.policy.goals_for(object_type, depth, requested=planning.requested_capabilities)
        skipped = tuple(
            candidate for decision in planning.decisions for candidate in decision.skipped
        )
        attempted = frozenset(
            carried for attempt in planning.attempts for carried in attempt.capabilities
        )

        requirements = requirements_from_goals(
            goals,
            object_type=object_type,
            depth=depth,
            policy_version=READINESS_POLICY_VERSION,
            skipped=skipped,
            attempted=attempted,
        )

        checks_by_capability = capability_checks(
            planning.attempts,
            directional_providers=directional_provider_ids(fusion.normalized_claims),
            attributed_capabilities=directional_capabilities_by_provider(fusion.normalized_claims),
        )
        inputs = EvaluationInputs(
            checks_by_capability=checks_by_capability,
            coverage_by_capability=capability_coverage_items(planning.coverage),
            skipped=skipped,
            signals=qualification.context_signals,
            stale_capabilities=self._stale_capabilities(reasoning),
            verdict=assessment.verdict,
            verdict_rule_id=assessment.verdict_rule_id,
        )

        evaluations = tuple(
            evaluate_requirement(requirement, inputs) for requirement in requirements
        )
        evaluations = evaluations + self._benign_challenge(
            fusion=fusion,
            planning=planning,
            inputs=inputs,
            object_type=object_type,
            depth=depth,
        )
        evaluations = tuple(sorted(evaluations, key=lambda item: item.requirement.capability.value))

        gaps = gaps_from_evaluations(evaluations, policy_version=READINESS_POLICY_VERSION)
        gaps = gaps + self._integrity_gaps(fusion)
        gaps = tuple(sorted(gaps, key=lambda item: (item.gap_type.value, item.requirement_id)))

        limitations = tuple(
            limitation for evaluation in evaluations for limitation in evaluation.limitations
        )
        unresolved_inputs = sum(1 for gap in gaps if gap.gap_type is GapType.UNRESOLVED_INPUT)

        adequacy = adequacy_for(
            verdict=assessment.verdict,
            material_gaps=len(gaps) - unresolved_inputs,
            limitations=len(limitations),
            unresolved_inputs=unresolved_inputs,
        )
        continuation = continuation_for(material_gap_types=frozenset(gap.gap_type for gap in gaps))
        status = status_for(
            adequacy=adequacy, continuation=continuation, limitations=len(limitations)
        )
        summary = self._summary(evaluations, gaps)

        result = AssessmentReadinessResult(
            result_id=readiness_id_for(
                policy_version=READINESS_POLICY_VERSION,
                purpose=purpose,
                target_key=fusion.target_key,
                depth=depth,
                assessment_id=assessment.assessment_id,
                requirement_refs=tuple(item.requirement.requirement_id for item in evaluations),
                gap_ids=tuple(gap.gap_id for gap in gaps),
            ),
            purpose=purpose,
            target_key=fusion.target_key,
            requested_depth=depth,
            readiness_status=status,
            coverage_adequacy=adequacy,
            continuation_state=continuation,
            requirement_evaluations=evaluations,
            gaps=gaps,
            information_needs=information_needs_from_gaps(gaps),
            limitations=limitations,
            assessment_id=assessment.assessment_id,
            verdict=assessment.verdict,
            confidence=assessment.confidence,
            verdict_rule_id=assessment.verdict_rule_id,
            coverage_summary=summary,
            policy_versions=ReadinessPolicyVersions(
                readiness_policy_version=READINESS_POLICY_VERSION,
                fusion_policy_version=assessment.fusion_policy_version,
                claim_semantics_policy_version=assessment.claim_semantics_policy_version,
                false_positive_policy_version=assessment.false_positive_policy_version,
                qualification_policy_version=assessment.qualification_policy_version,
            ),
            evaluated_at=qualification.evaluated_at,
        )
        self._record(result)
        return result

    # ------------------------------------------------------------------ #
    # Input integrity
    # ------------------------------------------------------------------ #

    def _check_inputs(
        self,
        *,
        fusion: FusionResult,
        planning: AdaptiveEnrichmentResult,
        purpose: ReadinessPurpose,
    ) -> None:
        """Refuse to evaluate artifacts from different investigations.

        Silently proceeding would produce a readiness answer about a mixture of
        two observables, which is worse than no answer because it looks like
        one.
        """
        if purpose not in SUPPORTED_PURPOSES:
            msg = f"unsupported readiness purpose: {purpose.value}"
            raise ReadinessInputMismatch(msg)
        if fusion.target_key != planning.target.canonical_key:
            msg = (
                "assessment and planning describe different observables: "
                f"{fusion.target_key!r} vs {planning.target.canonical_key!r}"
            )
            raise ReadinessInputMismatch(msg)

    def _stale_capabilities(
        self, reasoning: FalsePositiveReasoningResult
    ) -> frozenset[ProviderCapability]:
        """Capabilities whose supporting data Task 16 marked stale.

        Scoped, not global. Task 16 records staleness on the finding whose
        context used the dataset, and only false-positive context is sourced
        that way today -- so an out-of-date local dataset limits the
        false-positive requirement and leaves an exact malware identification
        entirely alone. A run-wide stale flag is the bug that layer already
        fixed once.
        """
        stale = any(
            FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE in finding.limitations
            for finding in reasoning.findings
        )
        return frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}) if stale else frozenset()

    def _integrity_gaps(self, fusion: FusionResult) -> tuple[ReadinessGap, ...]:
        """Fusion issues that stop a clean full-readiness answer.

        A directional claim whose subject could not be resolved is not cosmetic:
        evidence exists that nobody can attribute to the target or away from it.
        Returning fully READY over that would be asserting a completeness the
        inputs do not support.
        """
        unresolved = [
            issue
            for issue in fusion.issues
            if issue.issue_type is FusionIssueType.UNRESOLVED_CLAIM_SUBJECT
        ]
        if not unresolved:
            return ()
        requirement_id = requirement_id_for(
            policy_version=READINESS_POLICY_VERSION,
            capability=ProviderCapability.RELATIONSHIPS,
            object_type=_INTEGRITY_OBJECT_TYPE,
        )
        return (
            ReadinessGap(
                gap_id=gap_id_for(
                    policy_version=READINESS_POLICY_VERSION,
                    requirement_id=requirement_id,
                    gap_type=GapType.UNRESOLVED_INPUT,
                ),
                requirement_id=requirement_id,
                gap_type=GapType.UNRESOLVED_INPUT,
                capability=None,
                criticality=CoverageRelevance.REQUIRED,
                outlook=outlook_for(GapType.UNRESOLVED_INPUT),
                detail=(
                    "a directional claim could not be attributed to a known object, "
                    "so its relevance to the target is undetermined"
                ),
            ),
        )

    # ------------------------------------------------------------------ #
    # The benign asymmetry
    # ------------------------------------------------------------------ #

    def _benign_challenge(
        self,
        *,
        fusion: FusionResult,
        planning: AdaptiveEnrichmentResult,
        inputs: EvaluationInputs,
        object_type: IntelObjectType,
        depth: InvestigationDepth,
    ) -> tuple[RequirementEvaluation, ...]:
        """Require that somebody independent has looked, for single-source benign.

        A malicious finding is self-limiting -- something was found, and looking
        further would not unfind it. A benign finding is an absence, and an
        absence is only as good as the search behind it. So a LIKELY_BENIGN that
        rests on one provider's unopposed assertion is not fully ready until an
        *independent* origin has run an adverse search.

        Independence follows Task 17's provenance grouping: the challenge must
        come from outside the benign claim's own source family, so three datasets
        run by one organisation cannot challenge themselves. The challenge may
        return nothing at all -- that satisfies "somebody looked" and contributes
        no benign evidence whatsoever.
        """
        assessment = fusion.assessment
        if not requires_independent_challenge(assessment.verdict, assessment.verdict_rule_id):
            return ()

        dependent_families = self._benign_origin_families(fusion)
        challenged = False
        limited = False
        # What the challenging search returned, where that is knowable. An
        # attempt keyed to the capability carries its own yield; a bundled
        # secondary does not, and says so rather than reporting an absence.
        challenge_yield = InformationYield.NONE
        for capability in DIRECTIONAL_SEARCH_CAPABILITIES:
            for check in inputs.checks_by_capability.get(capability, ()):
                if check.source_family in dependent_families:
                    continue
                if check.completion is CheckCompletion.COMPLETE:
                    challenged = True
                    challenge_yield = check.information_yield
                elif check.completion is CheckCompletion.PARTIAL:
                    limited = True

        # An adverse search can also arrive as the *secondary* half of a bundled
        # call, where Task 13 records one attempt under the call's primary
        # capability. Reading attempts alone would miss it and report a benign
        # assessment as unchallenged when an independent search had in fact run
        # -- sending a later orchestration to buy a lookup that already happened.
        for completion, family in self._bundled_adverse_searches(planning):
            if family in dependent_families:
                continue
            if completion is CheckCompletion.COMPLETE:
                if not challenged:
                    # Answered, and the record does not retain what it returned.
                    challenge_yield = InformationYield.UNATTRIBUTED
                challenged = True
            elif completion is CheckCompletion.PARTIAL:
                limited = True

        requirement = CoverageRequirement(
            requirement_id=requirement_id_for(
                policy_version=READINESS_POLICY_VERSION,
                capability=ProviderCapability.THREAT_ASSOCIATIONS,
                object_type=object_type,
            ),
            capability=ProviderCapability.THREAT_ASSOCIATIONS,
            criticality=CoverageRelevance.REQUIRED,
            activation=RequirementActivation.ACTIVE,
            object_type=object_type,
            requested_depth=depth,
            rationale=BASIS_RATIONALE["benign_challenge"],
        )
        if challenged:
            status, completion, gap_type, material = (
                RequirementStatus.SATISFIED,
                CheckCompletion.COMPLETE,
                None,
                False,
            )
        elif limited:
            status, completion, gap_type, material = (
                RequirementStatus.LIMITED,
                CheckCompletion.PARTIAL,
                GapType.PARTIAL_COVERAGE,
                False,
            )
        else:
            status, completion, gap_type, material = (
                RequirementStatus.UNSATISFIED,
                CheckCompletion.NOT_ATTEMPTED,
                GapType.INDEPENDENT_CHALLENGE_MISSING,
                True,
            )

        return (
            RequirementEvaluation(
                requirement=requirement,
                status=status,
                completion=completion,
                information_yield=challenge_yield if challenged else InformationYield.NONE,
                gap_type=gap_type,
                material=material,
            ),
        )

    def _bundled_adverse_searches(
        self, planning: AdaptiveEnrichmentResult
    ) -> tuple[tuple[CheckCompletion, str], ...]:
        """Adverse searches answered as the secondary half of a bundled call.

        Task 13 records one :class:`ProviderAttempt` per call, carrying the
        call's *primary* capability; everything else the response answered is
        named on the :class:`PlannedProviderCall` itself. So a bundle whose
        primary was, say, an infrastructure lookup and whose secondary was a
        threat search leaves no attempt keyed to the search — and the challenge
        rule, which reads attempts, would not see it.

        The planner's own record supplies both halves of what the challenge
        needs: ``answered_capabilities`` says the search was answered, and
        ``source_family`` says by whom, which is what independence is judged on.
        The call carries no outcome, so completion comes from the attempt for its
        primary capability — the same execution, so the same result.

        Nothing here reads evidence, a claim type or a provider name. A coverage
        item alone would not do: it records *candidacy* rather than who answered,
        so crediting a challenge from it could credit the benign basis's own
        family with challenging itself.
        """
        by_primary = {(item.provider_id, item.capability): item for item in planning.attempts}
        found: list[tuple[CheckCompletion, str]] = []
        for decision in planning.decisions:
            call = decision.call
            if call is None:
                continue
            secondary = (
                frozenset(call.answered_capabilities) & DIRECTIONAL_SEARCH_CAPABILITIES
            ) - {call.capability}
            if not secondary:
                continue
            attempt = by_primary.get((call.provider_id, call.capability))
            if attempt is None:
                continue
            found.append((completion_for(attempt), call.source_family))
        return tuple(found)

    def _benign_origin_families(self, fusion: FusionResult) -> frozenset[str]:
        """Every source family dependent on the benign claim's information origin.

        **Task 17's connected components, not a family comparison.** Reading the
        benign claims' own ``source_family`` and calling anything else
        independent is precisely the approximation Task 17 had to abandon: a
        relayed finding carries a different transport family while naming the
        same origin, so a family-only test reads one source reporting twice as
        two, and a benign assessment ends up "challenged" by itself.

        So the benign claims' component is resolved through
        :func:`independence_groups`, which unions over source family, origin
        provider and lineage group, and every family inside that component is
        treated as dependent.

        **The honest limit.** A check that returned ``NO_DATA`` has no claim and
        therefore no origin or lineage to group on — the only provenance an
        attempt records is its provider id and source family. So for those,
        family separation is the strongest defensible test available, and it is
        weaker than Task 17's claim-level precision. Two sources that silently
        share an upstream feed would be indistinguishable here. That is a
        limitation of what the execution record contains, not a policy choice,
        and it is not papered over by inventing an origin the data never had.
        """
        benign_claims = [
            claim for claim in fusion.normalized_claims if not claim.is_malicious_direction
        ]
        if not benign_claims:
            return frozenset()
        benign_ids = {claim.claim_id for claim in benign_claims}
        return frozenset(
            family
            for group in independence_groups(fusion.normalized_claims)
            if benign_ids & set(group.claim_ids)
            for family in {
                claim.source_family
                for claim in fusion.normalized_claims
                if claim.claim_id in set(group.claim_ids)
            }
        )

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #

    def _summary(
        self,
        evaluations: tuple[RequirementEvaluation, ...],
        gaps: tuple[ReadinessGap, ...],
    ) -> ReadinessCoverageSummary:
        """Counts, never a ratio -- see the model docstring."""
        checks = [check for evaluation in evaluations for check in evaluation.checks]
        return ReadinessCoverageSummary(
            requirements_total=len(evaluations),
            requirements_satisfied=sum(
                1 for item in evaluations if item.status is RequirementStatus.SATISFIED
            ),
            requirements_limited=sum(
                1 for item in evaluations if item.status is RequirementStatus.LIMITED
            ),
            requirements_unsatisfied=sum(
                1 for item in evaluations if item.status is RequirementStatus.UNSATISFIED
            ),
            requirements_not_applicable=sum(
                1 for item in evaluations if item.status is RequirementStatus.NOT_APPLICABLE
            ),
            requirements_yield_unattributed=sum(
                1 for item in evaluations if item.information_yield is InformationYield.UNATTRIBUTED
            ),
            checks_complete=sum(
                1 for item in checks if item.completion is CheckCompletion.COMPLETE
            ),
            checks_partial=sum(1 for item in checks if item.completion is CheckCompletion.PARTIAL),
            checks_no_data=sum(
                1 for item in checks if item.information_yield is InformationYield.NO_DATA
            ),
            checks_blocked=sum(1 for item in checks if item.completion is CheckCompletion.BLOCKED),
            checks_not_attempted=sum(
                1 for item in checks if item.completion is CheckCompletion.NOT_ATTEMPTED
            ),
            material_gaps=len(gaps),
            optional_gaps=sum(
                1 for item in evaluations if item.gap_type is not None and not item.material
            ),
        )

    def _record(self, result: AssessmentReadinessResult) -> None:
        self.metrics.record(
            ReadinessMetric(
                readiness_status=result.readiness_status.value,
                coverage_adequacy=result.coverage_adequacy.value,
                continuation_state=result.continuation_state.value,
                purpose=result.purpose.value,
                requested_depth=result.requested_depth.value,
                verdict=result.verdict.value,
                requirements_total=result.coverage_summary.requirements_total,
                requirements_satisfied=result.coverage_summary.requirements_satisfied,
                material_gaps=result.coverage_summary.material_gaps,
            )
        )
