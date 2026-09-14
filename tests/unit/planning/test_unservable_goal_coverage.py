"""A template goal nobody can serve is recorded, never planned (Task 24, US-06).

Live shape: a domain's ``CURRENT_INFRASTRUCTURE`` goal, once the last provider
that falsely declared it for domains stopped doing so. The planner dropped the
goal -- correctly, because a candidate search over it finds nobody every round
-- and with it every trace that the template had asked. Readiness rebuilt the
requirement from the template, found no attempt and no coverage record, and
reported "nobody was asked" with a path remaining; the workflow then asked for
a continuation that named nothing it could request.

The fact "zero providers can serve this capability for this observable" is the
planner's to state, because the planner is the one layer that walks the
catalogue. It states it as a ``NOT_COVERED`` coverage item with an empty
``providers_considered`` -- the structural shape readiness already reads as
``CAPABILITY_UNAVAILABLE`` -- and plans exactly as before.
"""

from __future__ import annotations

from fixtures.planning import (
    FAMILY_A,
    FAMILY_B,
    LOCAL_CONTEXT,
    FakePlanningAdapter,
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    profile_for,
)
from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.planning import (
    CAPABILITY_UNAVAILABLE_REASON,
    AdaptiveEnrichmentPlanner,
    EnrichmentPlanningRequest,
    SkipReason,
    StopReason,
)
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.catalog import build_default_adapters

INFRA = ProviderCapability.CURRENT_INFRASTRUCTURE
REPUTATION = ProviderCapability.REPUTATION
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT
DOMAIN: IntelObject = normalize_observable("example.com").intel_object
ADDRESS: IntelObject = normalize_observable("203.0.113.9").intel_object
DOMAIN_TYPES = frozenset({IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR})


def _local() -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id="local_context",
        source_family=LOCAL_CONTEXT,
        capabilities=frozenset({CONTEXT}),
        object_types=DOMAIN_TYPES,
        priority=90,
    )


def _reputation() -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id="reputation_a",
        source_family=FAMILY_A,
        capabilities=frozenset({REPUTATION}),
        object_types=DOMAIN_TYPES,
        priority=50,
    )


def _reputation_b() -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id="reputation_b",
        source_family=FAMILY_B,
        capabilities=frozenset({REPUTATION}),
        object_types=DOMAIN_TYPES,
        priority=40,
    )


def _infra(object_types: frozenset[IntelObjectType] = DOMAIN_TYPES) -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id="infra",
        source_family="infra_family",
        capabilities=frozenset({INFRA}),
        object_types=object_types,
        priority=10,
    )


def _planner(*specs: FakeProviderSpec) -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(specs)
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def _request(root: IntelObject = DOMAIN, **overrides: object) -> EnrichmentPlanningRequest:
    return EnrichmentPlanningRequest(intel_object=root, **overrides)  # type: ignore[arg-type]


def _run(plan: AdaptiveEnrichmentPlanner, request: EnrichmentPlanningRequest, *, outcome_for=None):
    state = plan.initial_state(request)
    skips = []
    stop = StopReason.NO_ELIGIBLE_PROVIDER
    for _ in range(20):
        decision = plan.next(request, state)
        skips.extend(decision.skipped)
        if decision.stop is not None:
            stop = decision.stop
            break
        call = decision.call
        assert call is not None
        outcome = (
            fake_outcome(
                call.provider_id,
                source_family=call.source_family,
                effect=EvidenceEffect.CONTEXT_ONLY,
            )
            if outcome_for is None
            else outcome_for(call)
        )
        state.observe(call, outcome)
    coverage = {
        item.capability: item
        for item in state.coverage_items(
            plan.depth_targets(request, state), plan.providers_considered(request)
        )
    }
    return stop, skips, state, coverage


# --------------------------------------------------------------------------- #
# A -- the template asks, the catalogue cannot answer
# --------------------------------------------------------------------------- #


def test_a_goal_nobody_serves_is_kept_as_unservable_and_never_planned() -> None:
    plan = _planner(_local(), _reputation(), _reputation_b())
    request = _request(depth=InvestigationDepth.STANDARD)
    state = plan.initial_state(request)

    assert all(goal.capability is not INFRA for goal in state.goals)
    assert [goal.capability for goal in state.unservable_goals] == [INFRA]
    # The template's own relevance travels with it: this is a relevant goal the
    # catalogue cannot serve, not an optional one.
    assert state.unservable_goals[0].relevance is CoverageRelevance.RELEVANT


def test_a_the_blind_spot_is_a_coverage_item_with_nobody_considered() -> None:
    plan = _planner(_local(), _reputation(), _reputation_b())
    _, _, _, coverage = _run(plan, _request(depth=InvestigationDepth.STANDARD))

    item = coverage[INFRA]
    assert item.status is CoverageStatus.NOT_COVERED
    assert item.providers_considered == ()
    assert item.reason == CAPABILITY_UNAVAILABLE_REASON
    assert item.relevance is CoverageRelevance.RELEVANT
    assert item.catalogue_unavailable
    # Every served goal reads exactly as it would have without the record.
    assert coverage[REPUTATION].status is CoverageStatus.COVERED
    assert not coverage[REPUTATION].catalogue_unavailable


def test_a_planning_itself_is_unchanged_by_the_record() -> None:
    """No candidate, no skip, no attempt and no stop reason ever mentions the
    unservable goal: the planner does not go looking for a provider it has
    already established does not exist."""
    plan = _planner(_local(), _reputation(), _reputation_b())
    stop, skips, state, _ = _run(plan, _request(depth=InvestigationDepth.STANDARD))

    assert stop is StopReason.GOALS_SATISFIED
    assert all(item.capability is not INFRA for item in skips)
    assert all(attempt.capability is not INFRA for attempt in state.attempts)


def test_a_an_unserved_explicit_request_is_reported_as_required_and_unavailable() -> None:
    plan = _planner(_local(), _reputation(), _reputation_b())
    request = _request(depth=InvestigationDepth.STANDARD, requested_capabilities=frozenset({INFRA}))
    _, _, _, coverage = _run(plan, request)
    item = coverage[INFRA]
    assert item.relevance is CoverageRelevance.REQUIRED
    assert item.catalogue_unavailable


# --------------------------------------------------------------------------- #
# B / C -- a compatible provider exists: never unavailable
# --------------------------------------------------------------------------- #


def test_b_a_served_goal_lists_its_candidates_even_when_nobody_answered() -> None:
    plan = _planner(_local(), _reputation(), _reputation_b(), _infra())
    request = _request(
        depth=InvestigationDepth.STANDARD,
        constraints={"max_remote_provider_runs": 1},  # type: ignore[arg-type]
    )
    _, skips, _, coverage = _run(plan, request)

    item = coverage[INFRA]
    assert item.status is CoverageStatus.NOT_COVERED
    assert item.providers_considered == ("infra",)
    assert not item.catalogue_unavailable
    assert any(s.capability is INFRA and s.reason is SkipReason.BUDGET_EXHAUSTED for s in skips)


def test_c_an_unconfigured_provider_makes_a_served_goal_uncovered_not_unavailable() -> None:
    def outcome_for(call):
        if call.provider_id == "infra":
            return fake_outcome(
                "infra",
                source_family="infra_family",
                status=ProviderRunStatus.NOT_CONFIGURED,
                called_provider=False,
            )
        return fake_outcome(
            call.provider_id, source_family=call.source_family, effect=EvidenceEffect.CONTEXT_ONLY
        )

    plan = _planner(_local(), _reputation(), _reputation_b(), _infra())
    _, _, state, coverage = _run(
        plan, _request(depth=InvestigationDepth.STANDARD), outcome_for=outcome_for
    )

    assert any(
        a.provider_id == "infra" and a.status is ProviderRunStatus.NOT_CONFIGURED
        for a in state.attempts
    )
    item = coverage[INFRA]
    assert item.status is CoverageStatus.NOT_COVERED
    assert item.providers_considered == ("infra",)
    assert not item.catalogue_unavailable
    assert item.reason != CAPABILITY_UNAVAILABLE_REASON


# --------------------------------------------------------------------------- #
# D -- served only at a deeper investigation: the depth rule speaks
# --------------------------------------------------------------------------- #


def test_d_a_depth_gated_provider_keeps_the_goal_servable() -> None:
    """Servability is descriptor compatibility for the observable type. A
    provider that serves the capability only at DEEP still makes the goal
    servable at STANDARD; the depth rule records ``DEPTH_TOO_SHALLOW`` and
    readiness reads that as out of depth, never as a catalogue blind spot."""
    specs = (_local(), _reputation(), _reputation_b(), _infra())
    adapters = [FakePlanningAdapter(item) for item in specs]
    profiles = ProviderPlanningRegistry(
        tuple(
            profile_for(item).model_copy(
                update={"capability_minimum_depth": {INFRA: InvestigationDepth.DEEP}}
            )
            if item.provider_id == "infra"
            else profile_for(item)
            for item in specs
        )
    )
    plan = AdaptiveEnrichmentPlanner(registry=ProviderRegistry(adapters), profiles=profiles)
    request = _request(depth=InvestigationDepth.STANDARD)
    state = plan.initial_state(request)
    assert any(goal.capability is INFRA for goal in state.goals)
    assert state.unservable_goals == ()

    _, skips, _, coverage = _run(plan, request)
    assert any(s.capability is INFRA and s.reason is SkipReason.DEPTH_TOO_SHALLOW for s in skips)
    assert coverage[INFRA].providers_considered == ("infra",)
    assert not coverage[INFRA].catalogue_unavailable


# --------------------------------------------------------------------------- #
# E -- compatibility is capability *and* observable type
# --------------------------------------------------------------------------- #


def test_e_a_provider_serving_the_capability_for_addresses_only_leaves_domains_unserved() -> None:
    plan = _planner(
        _local(),
        _reputation(),
        _reputation_b(),
        _infra(object_types=frozenset({IntelObjectType.IPV4_ADDR})),
    )
    requested = frozenset({INFRA})

    _, _, _, for_domain = _run(
        plan, _request(DOMAIN, depth=InvestigationDepth.STANDARD, requested_capabilities=requested)
    )
    _, _, _, for_address = _run(
        plan,
        _request(ADDRESS, depth=InvestigationDepth.STANDARD, requested_capabilities=requested),
    )

    assert for_domain[INFRA].catalogue_unavailable
    assert for_address[INFRA].providers_considered == ("infra",)
    assert not for_address[INFRA].catalogue_unavailable


# --------------------------------------------------------------------------- #
# Rounds
# --------------------------------------------------------------------------- #


def test_unservable_goals_carry_into_a_later_round() -> None:
    plan = _planner(_local(), _reputation(), _reputation_b())
    request = _request(depth=InvestigationDepth.STANDARD)
    first = plan.initial_state(request)

    carried = first.continuation()
    assert carried.unservable_goals == first.unservable_goals

    recomputed = plan.initial_state(request, carry_over=first)
    assert [goal.capability for goal in recomputed.unservable_goals] == [INFRA]
    assert all(goal.capability is not INFRA for goal in recomputed.goals)


def test_the_record_is_deterministic_across_registration_order() -> None:
    forward = _planner(_local(), _reputation(), _reputation_b())
    backward = _planner(_reputation_b(), _reputation(), _local())
    request = _request(depth=InvestigationDepth.STANDARD)
    left = _run(forward, request)[3]
    right = _run(backward, request)[3]
    assert [(k.value, v.status, v.providers_considered) for k, v in left.items()] == [
        (k.value, v.status, v.providers_considered) for k, v in right.items()
    ]


# --------------------------------------------------------------------------- #
# The shipped catalogue
# --------------------------------------------------------------------------- #


def _shipped() -> AdaptiveEnrichmentPlanner:
    return AdaptiveEnrichmentPlanner(
        registry=ProviderRegistry(build_default_adapters()),
        profiles=build_default_planning_registry(),
    )


def test_the_shipped_catalogue_records_the_domain_blind_spot() -> None:
    """The live shape, offline: no shipped provider observes a domain's current
    infrastructure, so the STANDARD template's goal is recorded as unavailable
    -- and it is the only one."""
    plan = _shipped()
    for depth in (InvestigationDepth.STANDARD, InvestigationDepth.DEEP):
        request = _request(DOMAIN, depth=depth)
        state = plan.initial_state(request)
        items = state.coverage_items(
            plan.depth_targets(request, state), plan.providers_considered(request)
        )
        unavailable = [item.capability for item in items if item.catalogue_unavailable]
        assert unavailable == [INFRA], depth


def test_the_shipped_catalogue_still_serves_current_infrastructure_for_addresses_and_urls() -> None:
    plan = _shipped()
    for value in ("203.0.113.9", "2001:db8::1", "https://example.com/x"):
        root = normalize_observable(value).intel_object
        request = _request(
            root, depth=InvestigationDepth.DEEP, requested_capabilities=frozenset({INFRA})
        )
        state = plan.initial_state(request)
        assert state.unservable_goals == (), value
        assert plan.providers_considered(request)[INFRA], value
