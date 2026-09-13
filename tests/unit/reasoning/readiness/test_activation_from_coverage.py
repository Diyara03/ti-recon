"""Coverage truth outranks stale activation history (Task 24, CS-01).

Live shape: a relevant follow-up goal activates after the baseline and is
satisfied the moment it does, by a whole-document answer a capability-invariant
provider was credited with before the goal was eligible. From then on the goal
generates neither a candidate nor a skip, so the only trace left is the early
``goal_not_active`` skips -- and readiness read those as "never activated" while
Task 13's own coverage item said ``COVERED``. Two layers, one capability, two
contradictory answers.

The rule now: a capability whose Task 13 coverage reports an answered family
(``COVERED`` or ``PARTIAL``) was in play, whatever an earlier round said. A goal
with no attempt, no answered family and only inactive skips stays
``NOT_APPLICABLE``; a depth-excluded goal stays out of depth.
"""

from __future__ import annotations

from fixtures.readiness import assess, attempt, coverage_item, scenario, skipped
from ti_recon.enums import CoverageStatus, InvestigationDepth, ProviderCapability, ProviderRunStatus
from ti_recon.normalization import normalize_observable
from ti_recon.planning.goals import CapabilityGoal, GoalActivation
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    InformationYield,
    RequirementActivation,
    RequirementStatus,
)
from ti_recon.reasoning.readiness.requirements import activation_for

REPUTATION = ProviderCapability.REPUTATION
SCANNER = ProviderCapability.SCANNER_CONTEXT
OWNERSHIP = ProviderCapability.NETWORK_OWNERSHIP
INFRASTRUCTURE = ProviderCapability.CURRENT_INFRASTRUCTURE


def _evaluation(result, capability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


def _goal(capability: ProviderCapability, **kwargs) -> CapabilityGoal:
    return CapabilityGoal(capability=capability, activation=GoalActivation.AFTER_BASELINE, **kwargs)


def _address_scene(depth: InvestigationDepth = InvestigationDepth.DEEP):
    """The live shape: one scanner call answering reputation and scanner context
    with nothing, one reputation answer from another family."""
    root = normalize_observable("203.0.113.9").intel_object
    return (
        scenario(root, depth=depth)
        .with_claim("aggregated_reputation", provider="rep", source_family="fam_rep")
        .with_attempt(
            attempt(
                REPUTATION,
                provider="scanner",
                source_family="fam_scanner",
                status=ProviderRunStatus.NO_DATA,
                capabilities=frozenset({REPUTATION, SCANNER}),
                sequence=1,
            )
        )
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep", sequence=2))
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(SCANNER, status=CoverageStatus.COVERED))
    )


# --------------------------------------------------------------------------- #
# The pure rule
# --------------------------------------------------------------------------- #


def test_a_an_early_inactive_skip_is_outranked_by_an_answered_family() -> None:
    goal = _goal(OWNERSHIP)
    early = (skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"),)
    assert (
        activation_for(goal, skipped=early, attempted=frozenset(), answered=frozenset({OWNERSHIP}))
        is RequirementActivation.ACTIVE
    )


def test_b_a_goal_that_never_activated_and_was_never_answered_stays_not_activated() -> None:
    goal = _goal(OWNERSHIP)
    early = (skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"),)
    assert (
        activation_for(goal, skipped=early, attempted=frozenset(), answered=frozenset())
        is RequirementActivation.NOT_ACTIVATED
    )


def test_c_a_partial_answer_proves_activation_too() -> None:
    """``answered`` is built from COVERED *and* PARTIAL: a family that answered
    in part still answered."""
    goal = _goal(OWNERSHIP)
    early = (skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"),)
    assert (
        activation_for(goal, skipped=early, attempted=frozenset(), answered=frozenset({OWNERSHIP}))
        is RequirementActivation.ACTIVE
    )


def test_d_a_depth_excluded_goal_with_no_coverage_stays_out_of_depth() -> None:
    goal = _goal(INFRASTRUCTURE, minimum_depth=InvestigationDepth.DEEP)
    shallow = (skipped(INFRASTRUCTURE, SkipReason.DEPTH_TOO_SHALLOW, provider="beta"),)
    assert (
        activation_for(goal, skipped=shallow, attempted=frozenset(), answered=frozenset())
        is RequirementActivation.OUT_OF_DEPTH
    )


def test_an_answered_family_for_another_capability_activates_nothing_here() -> None:
    goal = _goal(OWNERSHIP)
    early = (skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"),)
    assert (
        activation_for(goal, skipped=early, attempted=frozenset(), answered=frozenset({SCANNER}))
        is RequirementActivation.NOT_ACTIVATED
    )


def test_the_default_keeps_the_previous_reading() -> None:
    goal = _goal(OWNERSHIP)
    early = (skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"),)
    assert (
        activation_for(goal, skipped=early, attempted=frozenset())
        is RequirementActivation.NOT_ACTIVATED
    )


# --------------------------------------------------------------------------- #
# Through the engine, on the live shape
# --------------------------------------------------------------------------- #


def test_a_the_live_shape_reads_satisfied_complete_no_data() -> None:
    """Task 13 said COVERED for network ownership (the scanner family's empty
    whole-document answer); readiness must agree it was in play and report the
    empty answer as exactly that."""
    scene = (
        _address_scene()
        .with_skip(skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"))
        .with_skip(skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"))
        .with_coverage(coverage_item(OWNERSHIP, status=CoverageStatus.COVERED))
    )
    evaluation = _evaluation(assess(scene), OWNERSHIP)
    assert evaluation.requirement.activation is RequirementActivation.ACTIVE
    assert evaluation.status is RequirementStatus.SATISFIED
    assert evaluation.completion is CheckCompletion.COMPLETE
    # No attempt is keyed to the capability, so the ledger's yield is the
    # retention limit, never a manufactured answer.
    assert evaluation.information_yield in {
        InformationYield.UNATTRIBUTED,
        InformationYield.NO_DATA,
    }
    assert evaluation.information_yield is not InformationYield.DIRECTIONAL


def test_b_the_engine_keeps_a_never_activated_goal_not_applicable() -> None:
    scene = (
        _address_scene()
        .with_skip(skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"))
        .with_coverage(
            coverage_item(OWNERSHIP, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )
    evaluation = _evaluation(assess(scene), OWNERSHIP)
    assert evaluation.requirement.activation is RequirementActivation.NOT_ACTIVATED
    assert evaluation.status is RequirementStatus.NOT_APPLICABLE
    assert evaluation.completion is CheckCompletion.OUT_OF_SCOPE
    assert not [gap for gap in assess(scene).gaps if gap.capability is OWNERSHIP]


def test_c_the_engine_treats_partial_coverage_as_in_play() -> None:
    scene = (
        _address_scene()
        .with_skip(skipped(OWNERSHIP, SkipReason.GOAL_NOT_ACTIVE, provider="-"))
        .with_coverage(coverage_item(OWNERSHIP, status=CoverageStatus.PARTIAL))
    )
    evaluation = _evaluation(assess(scene), OWNERSHIP)
    assert evaluation.requirement.activation is RequirementActivation.ACTIVE
    assert evaluation.status is not RequirementStatus.NOT_APPLICABLE
    assert evaluation.completion is not CheckCompletion.OUT_OF_SCOPE


def test_d_the_engine_keeps_a_deeper_goal_out_of_depth_at_standard() -> None:
    """At STANDARD the DEEP-only infrastructure goal does not exist for an
    address, so the engine derives no requirement for it at all -- nothing
    here can make a coverage item invent one."""
    scene = _address_scene(depth=InvestigationDepth.STANDARD).with_coverage(
        coverage_item(INFRASTRUCTURE, status=CoverageStatus.COVERED)
    )
    result = assess(scene)
    assert not [
        item
        for item in result.requirement_evaluations
        if item.requirement.capability is INFRASTRUCTURE
    ]
