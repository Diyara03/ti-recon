"""What this investigation needed, and how well it got it (Task 18).

Requirements are **not invented here**. Task 13 already models what an observable
of a given type needs at a given depth, which goals exist only below a depth
threshold, and which wait for a trigger. Reconstructing that would produce a
second opinion about applicability that could drift from the one the planner
actually used, and readiness would start reporting gaps for work nobody ever
intended to do.

So the derivation is thin: ask :meth:`EnrichmentPolicy.goals_for` for the goals,
carry each one's capability and relevance across, and read activation from what
the planner *recorded* rather than re-deriving it.

Three ways a requirement can be out of play
-------------------------------------------

* **Out of depth** -- the goal does not exist below the requested depth, so
  ``goals_for`` never returns it and it is never a gap. A QUICK run is not
  incomplete for having skipped DEEP work nobody asked for.
* **Not activated** -- the goal exists but its trigger never fired. The planner
  recorded that decision with information this layer does not have; overriding it
  would make "everything the system could theoretically do" mandatory.
* **Not applicable** -- wrong observable type. Handled entirely by ``goals_for``.

Limitations attach to the requirement they actually bear on
-----------------------------------------------------------

A stale context dataset limits the requirement that *used* it, not the whole run.
This is Task 16's scoping lesson carried forward: a stale warninglist says nothing
about an exact malware-sample identification, and letting it downgrade one would
be the run-wide read that layer already had to fix twice.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    Verdict,
)
from ti_recon.models.coverage import CoverageItem
from ti_recon.planning.goals import CapabilityGoal
from ti_recon.planning.models import SkippedCandidate, SkipReason
from ti_recon.reasoning.models import ContextSignal, ContextSignalType
from ti_recon.reasoning.readiness.coverage import (
    best_yield,
    coverage_completion,
    has_no_eligible_source,
    independent_families,
    worst_completion,
)
from ti_recon.reasoning.readiness.models import (
    CheckCompletion,
    CoverageRequirement,
    GapType,
    InformationYield,
    ReadinessLimitation,
    RequirementActivation,
    RequirementEvaluation,
    RequirementStatus,
    SourceCheck,
    requirement_id_for,
)
from ti_recon.reasoning.readiness.policy import BASIS_RATIONALE, is_material

#: Worst to best, so combining the two records is a maximum rather than a nest
#: of conditionals. Mirrors the ordering in :mod:`.coverage`.
_COMPLETION_RANK: dict[CheckCompletion, int] = {
    CheckCompletion.NOT_ATTEMPTED: 0,
    CheckCompletion.OUT_OF_SCOPE: 1,
    CheckCompletion.BLOCKED: 2,
    CheckCompletion.PARTIAL: 3,
    CheckCompletion.COMPLETE: 4,
}

__all__ = [
    "EvaluationInputs",
    "activation_for",
    "evaluate_requirement",
    "requirements_from_goals",
]

#: Skip reasons meaning "the planner decided this goal was not in play", as
#: opposed to "it was in play and something stopped it".
_INACTIVE_SKIPS: frozenset[SkipReason] = frozenset(
    {SkipReason.GOAL_NOT_ACTIVE, SkipReason.DEPTH_TOO_SHALLOW}
)

#: Skip reasons meaning the run ran out of allowance with candidates still
#: standing. Distinct from a blocked source: another run with a larger budget
#: could ask.
_BUDGET_SKIPS: frozenset[SkipReason] = frozenset(
    {SkipReason.BUDGET_EXHAUSTED, SkipReason.HIGH_COST_BUDGET_EXHAUSTED}
)

#: Provider statuses, as recorded on a check, that mean a source exists but
#: cannot currently be used. Mapped to the gap category that names the cause.
_BLOCKED_STATUS_GAPS: dict[str, GapType] = {
    "not_configured": GapType.NOT_CONFIGURED,
    "plan_limited": GapType.PLAN_LIMITED,
    "quota_exceeded": GapType.QUOTA_EXCEEDED,
    "temporarily_unavailable": GapType.TEMPORARILY_UNAVAILABLE,
    "error": GapType.TEMPORARILY_UNAVAILABLE,
    # A partial result that carried no evidence: the adapter could not retrieve
    # enough to build an envelope, so nothing about this capability was learned.
    "partial": GapType.PARTIAL_COVERAGE,
}

#: Context signals saying a behavioural check ran but watched nothing happen.
#: Task 12 established that a sandbox which observed no execution has not
#: produced behavioural coverage; Task 18 records that as a limitation on the
#: coverage, and never as evidence in either direction.
_LOW_EXECUTION_SIGNALS: frozenset[ContextSignalType] = frozenset(
    {ContextSignalType.SANDBOX_LOW_EXECUTION}
)


@dataclass(frozen=True)
class EvaluationInputs:
    """Everything a requirement evaluation may read, and nothing else."""

    checks_by_capability: dict[ProviderCapability, tuple[SourceCheck, ...]]
    coverage_by_capability: dict[ProviderCapability, CoverageItem]
    skipped: tuple[SkippedCandidate, ...]
    signals: tuple[ContextSignal, ...]
    #: Requirements whose supporting data Task 16 marked stale, by capability.
    stale_capabilities: frozenset[ProviderCapability]
    verdict: Verdict
    verdict_rule_id: str


def requirements_from_goals(
    goals: Sequence[CapabilityGoal],
    *,
    object_type: IntelObjectType,
    depth: InvestigationDepth,
    policy_version: str,
    skipped: Sequence[SkippedCandidate] = (),
    attempted: frozenset[ProviderCapability] = frozenset(),
    answered: frozenset[ProviderCapability] = frozenset(),
) -> tuple[CoverageRequirement, ...]:
    """One requirement per Task 13 goal, in deterministic capability order."""
    found = [
        CoverageRequirement(
            requirement_id=requirement_id_for(
                policy_version=policy_version,
                capability=goal.capability,
                object_type=object_type,
            ),
            capability=goal.capability,
            criticality=goal.relevance,
            activation=activation_for(
                goal, skipped=skipped, attempted=attempted, answered=answered
            ),
            object_type=object_type,
            requested_depth=depth,
            rationale=BASIS_RATIONALE["planner_goal"],
        )
        for goal in goals
    ]
    return tuple(sorted(found, key=lambda item: item.capability.value))


def activation_for(
    goal: CapabilityGoal,
    *,
    skipped: Sequence[SkippedCandidate],
    attempted: frozenset[ProviderCapability],
    answered: frozenset[ProviderCapability] = frozenset(),
) -> RequirementActivation:
    """Whether this goal was ever in play, from the planner's own record.

    An attempt settles it: something ran, so the goal was active. So does
    Task 13's own coverage statement: ``answered`` holds every capability
    whose coverage item reports at least one family answering (``COVERED`` or
    ``PARTIAL``), and a capability a family answered was in play whatever an
    earlier round said about it. That matters for a follow-up goal that
    activates after the baseline and is satisfied the moment it does -- by a
    whole-document answer credited before it activated, say. Such a goal
    generates neither a candidate nor a skip once active, so the only skips on
    record are the early "not yet eligible" ones, and reading those alone
    reported a covered capability as never applicable (Task 24
    capability-accounting validation, CS-01). Coverage truth outranks stale activation history.

    Otherwise the recorded skip reason speaks -- and only the reasons that
    mean "not in play" count. A goal skipped for budget was very much in play
    and simply did not get its turn. A goal with no attempt, no answered
    family and an inactive skip stays NOT_APPLICABLE: nothing here activates a
    conditional goal whose trigger never fired.
    """
    if goal.capability in attempted or goal.capability in answered:
        return RequirementActivation.ACTIVE
    reasons = {item.reason for item in skipped if item.capability is goal.capability}
    if SkipReason.DEPTH_TOO_SHALLOW in reasons:
        return RequirementActivation.OUT_OF_DEPTH
    if reasons & _INACTIVE_SKIPS:
        return RequirementActivation.NOT_ACTIVATED
    return RequirementActivation.ACTIVE


def _limitations(
    requirement: CoverageRequirement,
    checks: Sequence[SourceCheck],
    inputs: EvaluationInputs,
) -> tuple[ReadinessLimitation, ...]:
    """Caveats on a check that otherwise completed."""
    found: list[ReadinessLimitation] = []
    capability = requirement.capability

    item = inputs.coverage_by_capability.get(capability)
    if item is not None and item.status is CoverageStatus.PARTIAL:
        # The planner's own statement that the capability was only partly
        # covered. Capability-specific by construction, which is what keeps a
        # partial envelope from making every capability partial.
        found.append(
            ReadinessLimitation(
                requirement_id=requirement.requirement_id,
                gap_type=GapType.LIMITED_SOURCE_HORIZON,
                capability=capability,
                detail="source coverage for this capability was reported partial",
            )
        )
    elif any(check.completion is CheckCompletion.PARTIAL for check in checks):
        found.append(
            ReadinessLimitation(
                requirement_id=requirement.requirement_id,
                gap_type=GapType.PARTIAL_COVERAGE,
                capability=capability,
                detail="a source answered this capability incompletely",
            )
        )

    if capability is ProviderCapability.FILE_BEHAVIOR and any(
        signal.signal_type in _LOW_EXECUTION_SIGNALS for signal in inputs.signals
    ):
        found.append(
            ReadinessLimitation(
                requirement_id=requirement.requirement_id,
                gap_type=GapType.LOW_INFORMATION_YIELD,
                capability=capability,
                detail="behavioural analysis completed without observing execution",
            )
        )

    if capability in inputs.stale_capabilities:
        found.append(
            ReadinessLimitation(
                requirement_id=requirement.requirement_id,
                gap_type=GapType.STALE_CONTEXT_DATA,
                capability=capability,
                detail="supporting context for this capability came from a stale dataset",
            )
        )
    return tuple(found)


def _gap_type(
    requirement: CoverageRequirement,
    checks: Sequence[SourceCheck],
    inputs: EvaluationInputs,
) -> GapType:
    """Why an unmet requirement went unmet, in generic terms."""
    capability = requirement.capability

    # Execution history outranks catalogue inference. A recorded budget skip is
    # direct evidence that a candidate existed and was declined for allowance,
    # whereas an empty `providers_considered` is an *inference* that nothing
    # could have served the capability. When the two disagree the observed fact
    # wins: reporting a budget stop as "no source exists" would tell an operator
    # the question is unanswerable when a larger budget would answer it.
    budget_skipped = any(
        item.capability is capability and item.reason in _BUDGET_SKIPS for item in inputs.skipped
    )
    if budget_skipped:
        return GapType.BUDGET_LIMITED

    if has_no_eligible_source(inputs.coverage_by_capability.get(capability)):
        return GapType.CAPABILITY_UNAVAILABLE

    blocked = [check for check in checks if check.completion is CheckCompletion.BLOCKED]
    if blocked:
        # Deterministic and cause-preserving: the specific reason each source
        # could not be used is still in the trace, and the gap names the one
        # that came first in a stable order rather than an arbitrary sample.
        for status in sorted({check.raw_status for check in blocked}):
            mapped = _BLOCKED_STATUS_GAPS.get(status)
            if mapped is not None:
                return mapped
        return GapType.TEMPORARILY_UNAVAILABLE

    if checks and all(check.completion is CheckCompletion.OUT_OF_SCOPE for check in checks):
        # Every source that could have been asked says it cannot answer this
        # question about this observable. That is a catalogue limit, not a run
        # that went wrong.
        return GapType.CAPABILITY_UNAVAILABLE
    return GapType.NOT_ATTEMPTED


def evaluate_requirement(
    requirement: CoverageRequirement, inputs: EvaluationInputs
) -> RequirementEvaluation:
    """How one requirement fared, with the trace that explains it."""
    if requirement.activation is not RequirementActivation.ACTIVE:
        return RequirementEvaluation(
            requirement=requirement,
            status=RequirementStatus.NOT_APPLICABLE,
            completion=CheckCompletion.OUT_OF_SCOPE,
            information_yield=InformationYield.NONE,
        )

    checks = inputs.checks_by_capability.get(requirement.capability, ())
    item = inputs.coverage_by_capability.get(requirement.capability)

    # Two records of the same run, describing different things. The attempts say
    # what was executed and why anything failed; Task 13's coverage item says
    # which capabilities were actually *answered*, which is more than was
    # executed whenever a bundled request answered several goals at once.
    #
    # Taking the better of the two is what keeps readiness from demanding a
    # second call for a capability the planner deliberately covered with one --
    # while leaving the attempts free to report a partial or blocked execution
    # that the coverage summary alone would not show.
    observed = worst_completion(checks)
    recorded = coverage_completion(item)
    completion = max((observed, recorded), key=lambda value: _COMPLETION_RANK[value])

    # Where the coverage record proves a capability was answered but no attempt
    # observed it, the answer came from a bundled call and its content is not
    # retained per capability. Saying NONE there would assert that nothing came
    # back, which the record cannot support; saying NO_DATA would invent an
    # answer. The gap in the record gets named instead.
    if _COMPLETION_RANK[recorded] > _COMPLETION_RANK[observed]:
        yielded = InformationYield.UNATTRIBUTED
    else:
        yielded = best_yield(checks)
    limitations = _limitations(requirement, checks, inputs)

    if completion is CheckCompletion.COMPLETE:
        status = RequirementStatus.LIMITED if limitations else RequirementStatus.SATISFIED
        gap_type = limitations[0].gap_type if limitations else None
    elif completion is CheckCompletion.PARTIAL:
        status = RequirementStatus.LIMITED
        gap_type = GapType.PARTIAL_COVERAGE
    else:
        status = RequirementStatus.UNSATISFIED
        gap_type = _gap_type(requirement, checks, inputs)

    material = status is not RequirementStatus.SATISFIED and is_material(
        criticality=requirement.criticality,
        verdict=inputs.verdict,
        verdict_rule_id=inputs.verdict_rule_id,
    )
    # A limitation on an otherwise complete check is a caveat, never a gap that
    # blocks: the information arrived, with a stated qualification on it.
    if status is RequirementStatus.LIMITED and completion is CheckCompletion.COMPLETE:
        material = False

    return RequirementEvaluation(
        requirement=requirement,
        status=status,
        completion=completion,
        information_yield=yielded,
        checks=checks,
        independent_families=independent_families(checks),
        limitations=limitations,
        gap_type=gap_type,
        material=material,
    )


def requirement_criticality(requirement: CoverageRequirement) -> CoverageRelevance:
    """Exposed so callers do not reach into the model to compare criticality."""
    return requirement.criticality
