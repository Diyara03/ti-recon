"""An empty answer from one dataset does not close its family (Task 24 Phase 2).

A family target counts a family once it has answered. ``NO_DATA`` from one
dataset answers for that dataset; while a sibling dataset in the same family
that serves the capability is still eligible and unattempted, the family stays
open and the goal stays unsatisfied. A dataset that answered with data closes
the family exactly as before, a whole-document response counts for every
capability it answered, and an ineligible sibling -- blocked, unaffordable,
unsupported -- cannot hold a family open.
"""

from __future__ import annotations

from fixtures.planning import (
    FAMILY_A,
    FAMILY_B,
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
)
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderRunStatus,
)
from ti_recon.planning import (
    AdaptiveEnrichmentPlanner,
    EnrichmentPlanningRequest,
    NoveltyClass,
    StopReason,
)
from ti_recon.planning.models import CallCostClass

REPUTATION = ProviderCapability.REPUTATION
THREAT = ProviderCapability.THREAT_ASSOCIATIONS


def _specs(*, invariant: bool = False, second_cost: CallCostClass = CallCostClass.LOW):
    return (
        FakeProviderSpec(
            provider_id="a_first",
            source_family=FAMILY_A,
            capabilities=frozenset({REPUTATION, THREAT}),
            priority=60,
            capability_invariant_response=invariant,
        ),
        FakeProviderSpec(
            provider_id="a_second",
            source_family=FAMILY_A,
            capabilities=frozenset({REPUTATION}),
            priority=50,
            cost_class=second_cost,
        ),
        FakeProviderSpec(
            provider_id="b_only",
            source_family=FAMILY_B,
            capabilities=frozenset({REPUTATION}),
            priority=70,
        ),
    )


def _planner(specs=None) -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(specs or _specs())
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def _request(**overrides):
    return EnrichmentPlanningRequest(
        intel_object=file_object(), depth=InvestigationDepth.STANDARD, **overrides
    )


def _drive(plan, request, statuses: dict[str, ProviderRunStatus], *, limit: int = 10):
    state = plan.initial_state(request)
    chosen = []
    stop = None
    for _ in range(limit):
        decision = plan.next(request, state)
        if decision.stop is not None:
            stop = decision.stop
            break
        call = decision.call
        assert call is not None
        chosen.append((call.provider_id, call.novelty))
        status = statuses.get(call.provider_id, ProviderRunStatus.SUCCESS)
        state.observe(
            call,
            fake_outcome(
                call.provider_id,
                status=status,
                source_family=call.source_family,
                effect=None,
                error_category=(
                    ProviderErrorCategory.PROVIDER_UNAVAILABLE
                    if status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
                    else None
                ),
            ),
        )
    return chosen, stop, state


def test_a_no_data_dataset_keeps_its_family_open_for_an_eligible_sibling() -> None:
    plan = _planner()
    chosen, stop, state = _drive(
        plan,
        _request(),
        {"b_only": ProviderRunStatus.SUCCESS, "a_first": ProviderRunStatus.NO_DATA},
    )
    ids = [item[0] for item in chosen]
    assert ids == ["b_only", "a_first", "a_second"]
    assert chosen[2][1] is NoveltyClass.NEW_DATASET_SAME_FAMILY
    assert stop is StopReason.GOALS_SATISFIED
    # Family A answered with data in the end, so it is covered rather than empty.
    assert state.covered_families[REPUTATION] == {FAMILY_A, FAMILY_B}


def test_a_dataset_that_answered_with_data_closes_its_family() -> None:
    plan = _planner()
    chosen, stop, _ = _drive(plan, _request(), {})
    assert [item[0] for item in chosen] == ["b_only", "a_first"]
    assert stop is StopReason.GOALS_SATISFIED


def test_two_empty_datasets_answer_for_their_family_and_the_goal_closes() -> None:
    plan = _planner()
    chosen, stop, state = _drive(
        plan,
        _request(),
        {
            "b_only": ProviderRunStatus.SUCCESS,
            "a_first": ProviderRunStatus.NO_DATA,
            "a_second": ProviderRunStatus.NO_DATA,
        },
    )
    assert [item[0] for item in chosen] == ["b_only", "a_first", "a_second"]
    assert stop is StopReason.GOALS_SATISFIED
    assert state.no_data_families[REPUTATION] == {FAMILY_A}
    assert state.answered_families(REPUTATION) == {FAMILY_A, FAMILY_B}
    assert len(chosen) == len({item[0] for item in chosen})


def test_a_whole_document_response_answers_every_capability_it_covered() -> None:
    """An invariant provider's NO_DATA counts for every capability it answered,
    so it is never the sibling that reopens its own family."""
    plan = _planner(_specs(invariant=True))
    request = _request(requested_capabilities=frozenset({THREAT}))
    chosen, _, state = _drive(
        plan, request, {"a_first": ProviderRunStatus.NO_DATA, "a_second": ProviderRunStatus.NO_DATA}
    )
    assert ("a_first", THREAT) in state.answered
    assert ("a_first", REPUTATION) in state.answered
    assert [item[0] for item in chosen].count("a_first") == 1


def test_a_blocked_sibling_cannot_hold_a_family_open() -> None:
    plan = _planner()
    request = _request()
    state = plan.initial_state(request)
    state.block("a_second")
    decisions = []
    for _ in range(6):
        decision = plan.next(request, state)
        if decision.stop is not None:
            decisions.append(decision.stop)
            break
        call = decision.call
        assert call is not None
        decisions.append(call.provider_id)
        state.observe(
            call,
            fake_outcome(
                call.provider_id,
                status=(
                    ProviderRunStatus.NO_DATA
                    if call.provider_id == "a_first"
                    else ProviderRunStatus.SUCCESS
                ),
                source_family=call.source_family,
                effect=None,
            ),
        )
    assert decisions == ["b_only", "a_first", StopReason.GOALS_SATISFIED]


def test_an_unaffordable_sibling_cannot_hold_a_family_open() -> None:
    plan = _planner(_specs(second_cost=CallCostClass.HIGH))
    request = _request(
        constraints={"max_remote_provider_runs": 2},  # type: ignore[arg-type]
    )
    chosen, stop, _ = _drive(
        plan, request, {"b_only": ProviderRunStatus.SUCCESS, "a_first": ProviderRunStatus.NO_DATA}
    )
    assert [item[0] for item in chosen] == ["b_only", "a_first"]
    assert stop in {StopReason.GOALS_SATISFIED, StopReason.REMOTE_BUDGET_EXHAUSTED}


def test_an_open_family_survives_a_continuation_round() -> None:
    plan = _planner()
    request = _request()
    state = plan.initial_state(request)
    first = plan.next(request, state).call
    assert first is not None
    state.observe(
        first, fake_outcome(first.provider_id, source_family=first.source_family, effect=None)
    )
    second = plan.next(request, state).call
    assert second is not None and second.provider_id == "a_first"
    state.observe(
        second,
        fake_outcome(
            second.provider_id,
            status=ProviderRunStatus.NO_DATA,
            source_family=second.source_family,
            effect=None,
        ),
    )
    carried = plan.initial_state(request, carry_over=state)
    assert carried.no_data_families[REPUTATION] == {FAMILY_A}
    assert carried.answered == state.answered
    third = plan.next(request, carried).call
    assert third is not None and third.provider_id == "a_second"
