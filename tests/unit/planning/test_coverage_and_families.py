"""Adaptive coverage, source families and what counts as an answer (Task 13).

The rules under test are the ones that decide whether *another* query is worth
making. All of them are about coverage of questions and independence of sources;
none of them is about how strong an answer was, which belongs to the fusion layer
that does not exist yet.
"""

from __future__ import annotations

import pytest

from fixtures.planning import (
    EXPENSIVE_BEHAVIOR,
    FAMILY_A,
    FAMILY_B,
    LOCAL_CONTEXT,
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
)
from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderRunStatus,
)
from ti_recon.planning import (
    AdaptiveEnrichmentPlanner,
    EnrichmentPlanningRequest,
    NoveltyClass,
    PlanningConstraints,
    SelectionReason,
    SkipReason,
    StopReason,
)
from ti_recon.planning.state import BLOCKING_ERROR_CATEGORIES


def planner(specs: tuple[FakeProviderSpec, ...] | None = None) -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(specs)
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def request_for(**overrides: object) -> EnrichmentPlanningRequest:
    return EnrichmentPlanningRequest(intel_object=file_object(), **overrides)  # type: ignore[arg-type]


def run(
    plan: AdaptiveEnrichmentPlanner,
    request: EnrichmentPlanningRequest,
    *,
    outcome_for: object = None,
    limit: int = 30,
) -> tuple[list[str], StopReason, object]:
    """Drive a plan, letting the caller decide each outcome from the call."""
    state = plan.initial_state(request)
    chosen: list[str] = []
    stop = StopReason.NO_ELIGIBLE_PROVIDER
    for _ in range(limit):
        decision = plan.next(request, state)
        if decision.stop is not None:
            stop = decision.stop
            break
        call = decision.call
        assert call is not None
        chosen.append(f"{call.provider_id}:{call.capability.value}")
        outcome = (
            fake_outcome(
                call.provider_id,
                source_family=call.source_family,
                effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            )
            if outcome_for is None
            else outcome_for(call)  # type: ignore[operator]
        )
        state.observe(call, outcome)
    return chosen, stop, state


# --------------------------------------------------------------------------- #
# Independence of sources
# --------------------------------------------------------------------------- #


def test_a_new_source_family_is_preferred_over_another_dataset_in_a_covered_family() -> None:
    """Two datasets from one house are not two opinions.

    ``reputation_a`` and ``reputation_a_second`` share a family; ``reputation_b``
    is independent. Once the family has answered, the independent source is what
    a second reputation query is for.
    """
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    state = plan.initial_state(request)

    first = plan.next(request, state).call
    assert first is not None and first.provider_id == "local_context"
    state.observe(first, fake_outcome(first.provider_id, source_family=first.source_family))

    second = plan.next(request, state).call
    assert second is not None and second.source_family == FAMILY_A
    assert second.novelty is NoveltyClass.NEW_CAPABILITY
    state.observe(
        second,
        fake_outcome(
            second.provider_id,
            source_family=second.source_family,
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        ),
    )

    third = plan.next(request, state).call
    assert third is not None
    assert third.capability is ProviderCapability.REPUTATION
    assert third.source_family == FAMILY_B
    assert third.novelty is NoveltyClass.NEW_SOURCE_FAMILY
    assert third.reason is SelectionReason.NEW_SOURCE_FAMILY


def test_a_provider_in_a_covered_family_is_still_valuable_for_a_new_capability() -> None:
    """Family independence bounds corroboration, not usefulness.

    ``reputation_a_second`` shares FAMILY_A, and is still the only source of
    malware intelligence — a different question, not a second opinion.
    """
    chosen, _, state = run(planner(), request_for(depth=InvestigationDepth.STANDARD))
    assert "reputation_a_second:malware_intelligence" in chosen
    assert state.covered_families[ProviderCapability.MALWARE_INTELLIGENCE] == {FAMILY_A}  # type: ignore[attr-defined]


def test_several_evidence_records_from_one_provider_are_one_family() -> None:
    """A sandbox's many reports, or a provider's many claims, are one source."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    state = plan.initial_state(request)
    call = plan.next(request, state).call
    assert call is not None
    while call.capability is not ProviderCapability.REPUTATION:
        state.observe(call, fake_outcome(call.provider_id, source_family=call.source_family))
        call = plan.next(request, state).call
        assert call is not None
    state.observe(
        call,
        fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            evidence_count=25,
        ),
    )
    assert state.malicious_families == {FAMILY_A}
    assert state.covered_families[ProviderCapability.REPUTATION] == {FAMILY_A}
    # And a second independent family is still wanted.
    assert not state.satisfied(
        next(goal for goal in state.goals if goal.capability is ProviderCapability.REPUTATION),
        2,
    )


def test_two_datasets_in_one_family_never_satisfy_a_two_family_target() -> None:
    same_house = (
        FakeProviderSpec(
            provider_id="house_one",
            source_family="one_house",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        FakeProviderSpec(
            provider_id="house_two",
            source_family="one_house",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
    )
    plan = planner(same_house)
    request = request_for(depth=InvestigationDepth.STANDARD)
    chosen, _, state = run(plan, request)
    assert len(chosen) == 2
    goal = next(goal for goal in state.goals if goal.capability is ProviderCapability.REPUTATION)  # type: ignore[attr-defined]
    assert not state.satisfied(goal, 2)  # type: ignore[attr-defined]
    items = {
        item.capability: item
        for item in state.coverage_items(  # type: ignore[attr-defined]
            plan.depth_targets(request, state),  # type: ignore[arg-type]
            plan.providers_considered(request),
        )
    }
    reputation = items[ProviderCapability.REPUTATION]
    assert reputation.status is CoverageStatus.PARTIAL
    assert reputation.reason is not None
    assert "1 of 2 independent source families" in reputation.reason


# --------------------------------------------------------------------------- #
# What counts as an answer
# --------------------------------------------------------------------------- #


def test_no_data_is_coverage_of_a_source_and_never_evidence_of_safety() -> None:
    """The rule that stops a planner exonerating exactly the samples nobody has
    seen yet."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    chosen, _, state = run(
        plan,
        request,
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.NO_DATA,
            source_family=call.source_family,
            effect=None,
        ),
    )
    assert state.benign_families == set()  # type: ignore[attr-defined]
    assert not state.has_directional_evidence  # type: ignore[attr-defined]
    # Coverage was still gained, so the same source is not asked again...
    assert len(chosen) == len(set(chosen))
    # NO_DATA is an answer from each dataset: recorded as answered-but-empty,
    # never as data, and both families count once no sibling remains.
    assert state.answered_families(ProviderCapability.REPUTATION) == {FAMILY_A, FAMILY_B}  # type: ignore[attr-defined]
    assert ProviderCapability.REPUTATION not in state.covered_families  # type: ignore[attr-defined]
    # ...and a second family was consulted rather than the first repeated.
    assert all(attempt.coverage_gained for attempt in state.attempts)  # type: ignore[attr-defined]


def test_a_partial_answer_is_recorded_but_does_not_satisfy_a_family_target() -> None:
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    _, _, state = run(
        plan,
        request,
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.PARTIAL,
            source_family=call.source_family,
            effect=None,
        ),
    )
    assert state.partial_families[ProviderCapability.REPUTATION] == {FAMILY_A, FAMILY_B}  # type: ignore[attr-defined]
    assert ProviderCapability.REPUTATION not in state.covered_families  # type: ignore[attr-defined]
    goal = next(goal for goal in state.goals if goal.capability is ProviderCapability.REPUTATION)  # type: ignore[attr-defined]
    assert not state.satisfied(goal, 1)  # type: ignore[attr-defined]


def test_a_context_only_match_does_not_terminate_enrichment() -> None:
    """A warninglist hit explains evidence; it does not replace it.

    The local provider answers first and for free, and the run continues to the
    threat-intelligence sources exactly as if it had not.
    """
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    chosen, stop, state = run(
        plan,
        request,
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.CONTEXT_ONLY,
        ),
    )
    assert chosen[0] == "local_context:false_positive_context"
    assert state.false_positive_context_families == {LOCAL_CONTEXT}  # type: ignore[attr-defined]
    assert state.context_families  # type: ignore[attr-defined]
    assert not state.has_directional_evidence  # type: ignore[attr-defined]
    assert len([name for name in chosen if "reputation" in name]) >= 2
    assert stop is not StopReason.NO_ELIGIBLE_PROVIDER


def test_a_false_positive_capability_is_recorded_from_the_request_not_a_claim_name() -> None:
    """Reading a claim name would put provider vocabulary in the planner."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.QUICK)
    state = plan.initial_state(request)
    call = plan.next(request, state).call
    assert call is not None and call.capability is ProviderCapability.FALSE_POSITIVE_CONTEXT
    state.observe(
        call,
        fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.CONTEXT_ONLY,
        ),
    )
    assert state.false_positive_context_families == {LOCAL_CONTEXT}


# --------------------------------------------------------------------------- #
# Blocked providers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("category", sorted(BLOCKING_ERROR_CATEGORIES))
def test_a_blocking_error_takes_a_provider_out_of_this_run(
    category: ProviderErrorCategory,
) -> None:
    """Not a retry policy: Task 6 already retried whatever is retryable.

    This only stops the planner re-picking a source that just refused, which
    would waste the decision and, for a throttled provider, make it worse. The
    block is per *provider*, not per question: ``reputation_a`` also offers threat
    associations, and a refused credential does not become valid for those.
    """
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)

    # Advance to the provider with two capabilities, so a whole-provider block is
    # observable on the capability it was never asked about.
    call = plan.next(request, state).call
    assert call is not None
    while call.provider_id != "reputation_a":
        state.observe(call, fake_outcome(call.provider_id, source_family=call.source_family))
        call = plan.next(request, state).call
        assert call is not None

    state.observe(
        call,
        fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.ERROR,
            error_category=category,
            effect=None,
        ),
    )
    assert state.blocked == {"reputation_a"}

    seen_blocked = False
    for _ in range(8):
        later = plan.next(request, state)
        seen_blocked = seen_blocked or any(
            item.provider_id == "reputation_a" and item.reason is SkipReason.BLOCKED
            for item in later.skipped
        )
        if later.stop is not None:
            break
        assert later.call is not None
        assert later.call.provider_id != "reputation_a"
        state.observe(
            later.call,
            fake_outcome(later.call.provider_id, source_family=later.call.source_family),
        )
    assert seen_blocked


def test_an_unconfigured_provider_is_blocked_without_being_called() -> None:
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    call = plan.next(request, state).call
    assert call is not None
    state.observe(
        call,
        fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.NOT_CONFIGURED,
            called_provider=False,
            effect=None,
        ),
    )
    assert state.blocked == {call.provider_id}
    assert state.budget.remote_runs_used == 0


def test_a_not_supported_answer_does_not_block_the_whole_provider() -> None:
    """One capability being unavailable says nothing about the others."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    call = plan.next(request, state).call
    assert call is not None
    state.observe(
        call,
        fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.NOT_SUPPORTED,
            called_provider=False,
            effect=None,
        ),
    )
    assert state.blocked == set()
    assert (call.provider_id, call.capability) in state.attempted


def test_every_source_blocked_stops_with_no_eligible_provider() -> None:
    _, stop, state = run(
        planner(),
        request_for(depth=InvestigationDepth.DEEP),
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.ERROR,
            error_category=ProviderErrorCategory.AUTHENTICATION_ERROR,
            effect=None,
        ),
    )
    assert stop is StopReason.ALL_REMAINING_BLOCKED
    assert state.budget.remote_runs_used <= state.budget.max_remote_provider_runs  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Activation of specialized goals
# --------------------------------------------------------------------------- #


def test_behaviour_analysis_waits_for_the_baseline() -> None:
    """The expensive question is never the first one asked."""
    chosen, _, _ = run(
        planner(),
        request_for(
            depth=InvestigationDepth.STANDARD,
        ),
    )
    behaviour = [index for index, name in enumerate(chosen) if name.startswith("expensive")]
    reputation = [index for index, name in enumerate(chosen) if "reputation" in name]
    assert behaviour, chosen
    assert min(behaviour) > max(reputation)


def test_a_conditional_follow_up_is_not_bought_without_a_reason() -> None:
    """At STANDARD, behaviour analysis is conditional. A covered baseline that
    found nothing directional is not a reason to detonate-shop."""
    chosen, stop, state = run(
        planner(),
        request_for(depth=InvestigationDepth.STANDARD),
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.CONTEXT_ONLY,
        ),
    )
    assert not any(name.startswith("expensive") for name in chosen)
    assert stop is StopReason.GOALS_SATISFIED
    assert state.budget.high_cost_runs_used == 0  # type: ignore[attr-defined]


def test_directional_evidence_activates_the_conditional_follow_up() -> None:
    chosen, _, _ = run(
        planner(),
        request_for(depth=InvestigationDepth.STANDARD),
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        ),
    )
    assert "expensive_behavior:file_behavior" in chosen


def test_an_uncovered_baseline_also_activates_the_conditional_follow_up() -> None:
    """Nobody has ever seen this file is a reason to ask what it does."""

    def outcome(call: object) -> object:
        capability = call.capability  # type: ignore[attr-defined]
        if capability is ProviderCapability.REPUTATION:
            return fake_outcome(
                call.provider_id,  # type: ignore[attr-defined]
                status=ProviderRunStatus.PARTIAL,
                effect=None,
            )
        return fake_outcome(
            call.provider_id,  # type: ignore[attr-defined]
            source_family=call.source_family,  # type: ignore[attr-defined]
            effect=EvidenceEffect.CONTEXT_ONLY,
        )

    # Allowlisted down to one reputation source, so the budget is still intact
    # when the follow-up becomes eligible — this is a test of activation, not of
    # what happens to be affordable afterwards.
    chosen, _, _ = run(
        planner(),
        request_for(
            depth=InvestigationDepth.STANDARD,
            constraints=PlanningConstraints(
                provider_allowlist=frozenset(
                    {"local_context", "reputation_a", "expensive_behavior"}
                )
            ),
        ),
        outcome_for=outcome,
    )
    assert "expensive_behavior:file_behavior" in chosen


def test_at_deep_the_follow_up_needs_no_trigger() -> None:
    """A deep file investigation is what behaviour analysis is for."""
    chosen, _, _ = run(
        planner(),
        request_for(depth=InvestigationDepth.DEEP),
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            source_family=call.source_family,
            effect=EvidenceEffect.CONTEXT_ONLY,
        ),
    )
    assert "expensive_behavior:file_behavior" in chosen


def test_an_explicit_capability_outranks_the_baseline_it_would_have_waited_for() -> None:
    """A caller who named the capability already made the judgement the
    activation rule exists to make for them."""
    plan = planner()
    request = request_for(
        depth=InvestigationDepth.STANDARD,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    decision = plan.next(request, plan.initial_state(request))
    assert decision.call is not None
    assert decision.call.provider_id == "expensive_behavior"
    assert decision.call.reason is SelectionReason.EXPLICIT_CAPABILITY
    assert decision.call.source_family == EXPENSIVE_BEHAVIOR


def test_an_unserved_requested_capability_is_reported_as_uncovered() -> None:
    """Asking for something nobody offers must not look like coverage."""
    only_local = (
        FakeProviderSpec(
            provider_id="local_context",
            source_family=LOCAL_CONTEXT,
            capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            object_types=frozenset({IntelObjectType.FILE}),
        ),
    )
    plan = planner(only_local)
    request = request_for(
        depth=InvestigationDepth.DEEP,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    state = plan.initial_state(request)
    assert all(goal.capability is not ProviderCapability.FILE_BEHAVIOR for goal in state.goals)
    considered = plan.providers_considered(request)
    assert ProviderCapability.FILE_BEHAVIOR not in considered


def test_coverage_reports_a_required_goal_nobody_answered() -> None:
    plan = planner()
    request = request_for(depth=InvestigationDepth.STANDARD)
    _, _, state = run(
        plan,
        request,
        outcome_for=lambda call: fake_outcome(
            call.provider_id,
            status=ProviderRunStatus.ERROR,
            error_category=ProviderErrorCategory.AUTHENTICATION_ERROR,
            effect=None,
        ),
    )
    items = {
        item.capability: item
        for item in state.coverage_items(  # type: ignore[attr-defined]
            plan.depth_targets(request, state),  # type: ignore[arg-type]
            plan.providers_considered(request),
        )
    }
    reputation = items[ProviderCapability.REPUTATION]
    assert reputation.status is CoverageStatus.NOT_COVERED
    assert reputation.relevance is CoverageRelevance.REQUIRED
    assert reputation.providers_considered
    assert reputation.reason == "no eligible provider produced coverage"
