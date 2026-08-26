"""Planning vocabulary, registry and result shapes (Task 13).

The small pieces the planner is assembled from, checked directly: what a model
refuses to represent, what the registry refuses to accept, and what a finished
run reports.
"""

from __future__ import annotations

import pytest

from fixtures.planning import (
    FAMILY_A,
    FAMILY_B,
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
)
from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.planning import (
    COST_ORDER,
    NOVELTY_ORDER,
    AdaptiveEnrichmentPlanner,
    AdaptiveEnrichmentResult,
    CallCostClass,
    CapabilityGoal,
    EnrichmentBudget,
    EnrichmentPlanningRequest,
    EnrichmentPolicy,
    GoalActivation,
    NoveltyClass,
    PlannedProviderCall,
    PlanningDecision,
    PlanningState,
    ProviderAttempt,
    ProviderLocality,
    ProviderPlanningProfile,
    ProviderPlanningRegistry,
    SelectionReason,
    SkippedCandidate,
    SkipReason,
    StopReason,
    UnknownProviderError,
    depth_at_least,
)
from ti_recon.planning.state import BLOCKING_ERROR_CATEGORIES, COVERING_STATUSES


def call(
    provider_id: str = "reputation_a",
    capability: ProviderCapability = ProviderCapability.REPUTATION,
    *,
    source_family: str = FAMILY_A,
    locality: ProviderLocality = ProviderLocality.REMOTE,
    cost_class: CallCostClass = CallCostClass.LOW,
) -> PlannedProviderCall:
    return PlannedProviderCall(
        provider_id=provider_id,
        capability=capability,
        source_family=source_family,
        locality=locality,
        cost_class=cost_class,
        depth=InvestigationDepth.STANDARD,
        reason=SelectionReason.MISSING_CAPABILITY,
        novelty=NoveltyClass.NEW_CAPABILITY,
    )


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #


def test_a_decision_is_a_call_or_a_stop_and_never_both() -> None:
    """An ambiguous decision would let a caller act and stop on the same round."""
    with pytest.raises(ValueError, match="either a call or a stop"):
        PlanningDecision(sequence=0, call=call(), stop=StopReason.GOALS_SATISFIED)
    with pytest.raises(ValueError, match="either a call or a stop"):
        PlanningDecision(sequence=0)
    assert PlanningDecision(sequence=0, stop=StopReason.GOALS_SATISFIED).is_stop
    assert not PlanningDecision(sequence=0, call=call()).is_stop


def test_the_orderings_cover_every_member() -> None:
    assert set(COST_ORDER) == set(CallCostClass)
    assert set(NOVELTY_ORDER) == set(NoveltyClass)
    assert COST_ORDER[CallCostClass.ZERO] < COST_ORDER[CallCostClass.HIGH]
    assert NOVELTY_ORDER[NoveltyClass.NEW_CAPABILITY] < NOVELTY_ORDER[NoveltyClass.REDUNDANT]


def test_no_stop_or_skip_reason_asserts_knowledge() -> None:
    """The rule that keeps a scheduler from implying a verdict."""
    forbidden = ("confidence", "verdict", "malicious", "benign", "certain", "enough")
    for reason in (*StopReason, *SkipReason, *SelectionReason):
        assert not [word for word in forbidden if word in reason.value], reason


def test_depth_ordering_is_total() -> None:
    assert depth_at_least(InvestigationDepth.DEEP, InvestigationDepth.QUICK)
    assert not depth_at_least(InvestigationDepth.QUICK, InvestigationDepth.DEEP)
    assert depth_at_least(InvestigationDepth.STANDARD, InvestigationDepth.STANDARD)


def test_a_quick_goal_never_asks_for_more_than_one_family() -> None:
    goal = CapabilityGoal(
        capability=ProviderCapability.REPUTATION,
        relevance=CoverageRelevance.REQUIRED,
        minimum_source_families=2,
    )
    assert goal.families_for_depth(InvestigationDepth.QUICK) == 1
    assert goal.families_for_depth(InvestigationDepth.DEEP) == 2
    assert goal.is_required
    assert goal.exists_at(InvestigationDepth.QUICK)


def test_a_goal_can_be_withheld_until_it_is_asked_for() -> None:
    goal = CapabilityGoal(
        capability=ProviderCapability.WEB_FORENSICS,
        activation=GoalActivation.EXPLICIT_ONLY,
        minimum_depth=InvestigationDepth.DEEP,
    )
    assert not goal.exists_at(InvestigationDepth.QUICK)
    assert not goal.is_required


# --------------------------------------------------------------------------- #
# Budget arithmetic
# --------------------------------------------------------------------------- #


def test_a_local_call_is_always_affordable() -> None:
    spent = EnrichmentBudget(max_remote_provider_runs=1, max_high_cost_runs=0, remote_runs_used=1)
    assert spent.can_afford(locality=ProviderLocality.LOCAL, cost=CallCostClass.HIGH)
    assert not spent.can_afford(locality=ProviderLocality.REMOTE, cost=CallCostClass.LOW)


def test_a_high_cost_call_needs_both_allowances() -> None:
    budget = EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=0)
    assert budget.can_afford(locality=ProviderLocality.REMOTE, cost=CallCostClass.MEDIUM)
    assert not budget.can_afford(locality=ProviderLocality.REMOTE, cost=CallCostClass.HIGH)


def test_charging_returns_a_new_budget_and_leaves_the_old_one_alone() -> None:
    budget = EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=2)
    charged = budget.charge(
        locality=ProviderLocality.REMOTE, cost=CallCostClass.HIGH, called_provider=True
    )
    assert (charged.remote_runs_used, charged.high_cost_runs_used) == (1, 1)
    assert (budget.remote_runs_used, budget.high_cost_runs_used) == (0, 0)
    assert charged.remote_remaining == 3
    assert charged.high_cost_remaining == 1


def test_a_high_cost_provider_charges_both_counters_once() -> None:
    budget = EnrichmentBudget(max_remote_provider_runs=2, max_high_cost_runs=1).charge(
        locality=ProviderLocality.REMOTE, cost=CallCostClass.HIGH, called_provider=True
    )
    assert budget.remote_runs_used == 1
    assert budget.high_cost_runs_used == 1


# --------------------------------------------------------------------------- #
# Profiles and the registry
# --------------------------------------------------------------------------- #


def profile(provider_id: str = "one") -> ProviderPlanningProfile:
    return ProviderPlanningProfile(
        provider_id=provider_id,
        source_family=provider_id,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        planning_capabilities=frozenset({ProviderCapability.REPUTATION}),
    )


def test_a_duplicate_profile_is_refused() -> None:
    """Two profiles for one provider would make selection depend on order."""
    registry = ProviderPlanningRegistry((profile(),))
    with pytest.raises(ValueError, match="duplicate planning profile"):
        registry.register(profile())


def test_requiring_an_unregistered_provider_fails_loudly() -> None:
    registry = ProviderPlanningRegistry((profile(),))
    assert registry.get("missing") is None
    with pytest.raises(UnknownProviderError, match="no planning profile"):
        registry.require("missing")
    with pytest.raises(UnknownProviderError, match="unknown provider ids"):
        registry.validate_names(frozenset({"missing"}))
    registry.validate_names(frozenset({"one"}))


def test_the_registry_reports_itself_deterministically() -> None:
    registry = ProviderPlanningRegistry((profile("b"), profile("a")))
    assert [item.provider_id for item in registry.all()] == ["a", "b"]
    assert registry.provider_ids == frozenset({"a", "b"})
    assert len(registry) == 2
    assert "profiles=2" in repr(registry)


def test_a_profile_may_withhold_a_capability_it_really_has() -> None:
    """ "Integrated" and "chosen on an analyst's behalf" are separate decisions."""
    withheld = ProviderPlanningProfile(
        provider_id="one",
        source_family="one",
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        planning_capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    assert withheld.serves(ProviderCapability.REPUTATION)
    assert not withheld.serves(ProviderCapability.FILE_BEHAVIOR)
    assert not withheld.is_local


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


def test_goals_exist_only_at_the_depth_they_were_declared_for() -> None:
    policy = EnrichmentPolicy()
    quick = policy.goals_for(
        file_object().object_type, InvestigationDepth.QUICK, requested=frozenset()
    )
    deep = policy.goals_for(
        file_object().object_type, InvestigationDepth.DEEP, requested=frozenset()
    )
    assert {goal.capability for goal in quick} < {goal.capability for goal in deep}


def test_a_requested_capability_becomes_a_goal_even_when_no_template_has_it() -> None:
    policy = EnrichmentPolicy()
    goals = policy.goals_for(
        file_object().object_type,
        InvestigationDepth.QUICK,
        requested=frozenset({ProviderCapability.CERTIFICATE_CONTEXT}),
    )
    assert ProviderCapability.CERTIFICATE_CONTEXT in {goal.capability for goal in goals}


# --------------------------------------------------------------------------- #
# State and result reporting
# --------------------------------------------------------------------------- #


def test_a_benign_claim_is_recorded_by_family_and_satisfies_nothing() -> None:
    """No provider in the catalogue emits one today; the state still records the
    direction rather than dropping it, and it never becomes satisfaction."""
    state = PlanningState(budget=EnrichmentBudget(max_remote_provider_runs=2, max_high_cost_runs=0))
    state.observe(
        call(),
        fake_outcome("reputation_a", source_family=FAMILY_A, effect=EvidenceEffect.SUPPORTS_BENIGN),
    )
    assert state.benign_families == {FAMILY_A}
    assert state.has_directional_evidence
    assert state.covered_families[ProviderCapability.REPUTATION] == {FAMILY_A}


def test_blocking_a_provider_by_hand_is_possible_for_the_orchestrator() -> None:
    """Used when the registry and profiles disagree — a provider with a profile
    and no adapter must not be chosen forever."""
    state = PlanningState(budget=EnrichmentBudget(max_remote_provider_runs=2, max_high_cost_runs=0))
    state.block("ghost")
    assert state.blocked == {"ghost"}


def test_every_covering_status_and_blocking_category_is_a_real_member() -> None:
    assert COVERING_STATUSES <= set(ProviderRunStatus)
    assert ProviderRunStatus.NO_DATA in COVERING_STATUSES
    assert ProviderRunStatus.NOT_CONFIGURED not in COVERING_STATUSES
    assert BLOCKING_ERROR_CATEGORIES


def test_a_result_reports_contacts_families_and_cache_hits_separately() -> None:
    """Selected, contacted and covering are three different sets."""
    attempts = (
        ProviderAttempt(
            sequence=0,
            provider_id="cached",
            capability=ProviderCapability.REPUTATION,
            source_family=FAMILY_A,
            locality=ProviderLocality.REMOTE,
            cost_class=CallCostClass.LOW,
            reason=SelectionReason.MISSING_CAPABILITY,
            novelty=NoveltyClass.NEW_CAPABILITY,
            status=ProviderRunStatus.SUCCESS,
            called_provider=False,
            cache_hit=True,
            coverage_gained=True,
        ),
        ProviderAttempt(
            sequence=1,
            provider_id="called",
            capability=ProviderCapability.REPUTATION,
            source_family=FAMILY_B,
            locality=ProviderLocality.REMOTE,
            cost_class=CallCostClass.LOW,
            reason=SelectionReason.NEW_SOURCE_FAMILY,
            novelty=NoveltyClass.NEW_SOURCE_FAMILY,
            status=ProviderRunStatus.ERROR,
            called_provider=True,
            cache_hit=False,
            coverage_gained=False,
        ),
    )
    result = AdaptiveEnrichmentResult(
        target=file_object(),
        depth=InvestigationDepth.STANDARD,
        attempts=attempts,
        decisions=(PlanningDecision(sequence=0, stop=StopReason.GOALS_SATISFIED),),
        coverage=(),
        budget=EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=1),
        stop_reason=StopReason.GOALS_SATISFIED,
    )
    assert result.providers_called == ("called",)
    assert result.cache_hits == 1
    assert result.source_families_consulted == frozenset({FAMILY_A})


def test_a_run_can_stop_tidily_with_a_required_capability_uncovered() -> None:
    """The one field worth alerting on."""
    from ti_recon.models.coverage import CoverageItem

    result = AdaptiveEnrichmentResult(
        target=file_object(),
        depth=InvestigationDepth.STANDARD,
        attempts=(),
        decisions=(PlanningDecision(sequence=0, stop=StopReason.ALL_REMAINING_BLOCKED),),
        coverage=(
            CoverageItem(
                capability=ProviderCapability.REPUTATION,
                relevance=CoverageRelevance.REQUIRED,
                status=CoverageStatus.NOT_COVERED,
                reason="every remaining source was blocked",
            ),
        ),
        budget=EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=1),
        stop_reason=StopReason.ALL_REMAINING_BLOCKED,
    )
    assert result.has_uncovered_required_capability


def test_a_skipped_candidate_needs_no_capability() -> None:
    assert SkippedCandidate(provider_id="-", reason=SkipReason.GOAL_NOT_ACTIVE).capability is None


# --------------------------------------------------------------------------- #
# Stop reasons that need a specific shape of catalogue
# --------------------------------------------------------------------------- #


def test_only_expensive_candidates_left_stops_on_the_high_cost_budget() -> None:
    """One high-cost slot at STANDARD, two capabilities that only expensive
    providers serve: the second is reported as unaffordable rather than as
    nobody being able to answer it."""
    specs = (
        FakeProviderSpec(
            provider_id="cheap",
            source_family="cheap_family",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        FakeProviderSpec(
            provider_id="dear_one",
            source_family="dear_one_family",
            capabilities=frozenset({ProviderCapability.MALWARE_INTELLIGENCE}),
            cost_class=CallCostClass.HIGH,
        ),
        FakeProviderSpec(
            provider_id="dear_two",
            source_family="dear_two_family",
            capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            cost_class=CallCostClass.HIGH,
        ),
    )
    registry, profiles = build_registry(specs)
    plan = AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)
    request = EnrichmentPlanningRequest(
        intel_object=file_object(), depth=InvestigationDepth.STANDARD
    )
    state = plan.initial_state(request)
    stop = None
    for _ in range(8):
        decision = plan.next(request, state)
        if decision.stop is not None:
            stop = decision.stop
            break
        assert decision.call is not None
        state.observe(
            decision.call,
            fake_outcome(
                decision.call.provider_id,
                source_family=decision.call.source_family,
                effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            ),
        )
    assert stop is StopReason.HIGH_COST_BUDGET_EXHAUSTED
    assert state.budget.high_cost_runs_used == 1


def test_the_planner_exposes_its_policy_and_profiles() -> None:
    registry, profiles = build_registry()
    plan = AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)
    assert isinstance(plan.policy, EnrichmentPolicy)
    assert plan.profiles is profiles
