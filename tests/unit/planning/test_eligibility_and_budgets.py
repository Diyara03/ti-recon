"""What the planner may choose, and what it may spend (Task 13).

Deliberately against fake providers. A planner tested only on today's catalogue
would be a test of today's catalogue; these prove the rules are generic, and a
separate suite checks the real providers.
"""

from __future__ import annotations

import pytest

from fixtures.planning import (
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
)
from ti_recon.enums import (
    ActivityMode,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.planning import (
    RANKING_FACTORS,
    AdaptiveEnrichmentPlanner,
    CallCostClass,
    EnrichmentPlanningRequest,
    EnrichmentPolicy,
    PlanningConstraints,
    ProviderLocality,
    SkipReason,
    StopReason,
    UnknownProviderError,
)


def planner(specs: tuple[FakeProviderSpec, ...] | None = None) -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(specs)
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def request_for(
    subject: IntelObject | str | None = None, **overrides: object
) -> EnrichmentPlanningRequest:
    if subject is None:
        target = file_object()
    elif isinstance(subject, str):
        target = normalize_observable(subject).intel_object
    else:
        target = subject
    return EnrichmentPlanningRequest(intel_object=target, **overrides)  # type: ignore[arg-type]


def drive(
    plan: AdaptiveEnrichmentPlanner,
    request: EnrichmentPlanningRequest,
    *,
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
    effect: EvidenceEffect | None = EvidenceEffect.SUPPORTS_MALICIOUS,
    called: bool = True,
    cache_hit: bool = False,
    limit: int = 30,
) -> tuple[list[str], StopReason, object]:
    """Run a whole plan against uniform fake outcomes."""
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
        state.observe(
            call,
            fake_outcome(
                call.provider_id,
                status=status,
                source_family=call.source_family,
                effect=effect,
                called_provider=called,
                cache_hit=cache_hit,
            ),
        )
    return chosen, stop, state


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #


def test_a_provider_that_does_not_support_the_observable_is_never_chosen() -> None:
    """The expensive behaviour provider is file-only.

    No provider-specific condition anywhere: an unsupported observable simply
    produces no candidate.
    """
    chosen, _, _ = drive(planner(), request_for("8.8.8.8", depth=InvestigationDepth.DEEP))
    assert not any(name.startswith("expensive_behavior") for name in chosen)


def test_ipv6_naturally_selects_only_compatible_providers() -> None:
    ipv4_only = FakeProviderSpec(
        provider_id="ipv4_only",
        source_family="ipv4_only_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        object_types=frozenset({IntelObjectType.IPV4_ADDR}),
    )
    ipv6_capable = FakeProviderSpec(
        provider_id="both",
        source_family="both_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        object_types=frozenset({IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}),
    )
    chosen, _, _ = drive(planner((ipv4_only, ipv6_capable)), request_for("2001:db8::1"))
    assert chosen == ["both:reputation"]


def test_a_capability_no_provider_offers_produces_no_goal() -> None:
    """A goal nothing can satisfy would be a permanent, misleading gap."""
    only_reputation = FakeProviderSpec(
        provider_id="only_reputation",
        source_family="solo",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    plan = planner((only_reputation,))
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    assert {goal.capability for goal in state.goals} == {ProviderCapability.REPUTATION}


def test_a_provider_with_no_planning_profile_is_never_chosen() -> None:
    """Registered as an adapter is not the same as plannable."""
    from fixtures.planning.fakes import FakePlanningAdapter, profile_for
    from ti_recon.planning.policy import ProviderPlanningRegistry
    from ti_recon.providers.registry import ProviderRegistry

    known = FakeProviderSpec(
        provider_id="known",
        source_family="known_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    unplanned = FakeProviderSpec(
        provider_id="unplanned",
        source_family="other_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    plan = AdaptiveEnrichmentPlanner(
        registry=ProviderRegistry([FakePlanningAdapter(known), FakePlanningAdapter(unplanned)]),
        profiles=ProviderPlanningRegistry((profile_for(known),)),
    )
    chosen, _, _ = drive(plan, request_for(depth=InvestigationDepth.DEEP))
    assert all(not name.startswith("unplanned") for name in chosen)


def test_auto_enrichment_can_be_withheld_for_a_provider() -> None:
    withheld = FakeProviderSpec(
        provider_id="withheld",
        source_family="withheld_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        auto_enrichment_allowed=False,
    )
    allowed = FakeProviderSpec(
        provider_id="allowed",
        source_family="allowed_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    chosen, _, _ = drive(planner((withheld, allowed)), request_for())
    assert chosen == ["allowed:reputation"]


def test_a_provider_below_its_minimum_depth_is_skipped_with_a_reason() -> None:
    """A shallow investigation is not told a source does not exist.

    The skip is reported with its reason, so an analyst who wants that source can
    see that raising the depth is what unlocks it.
    """
    deeper = FakeProviderSpec(
        provider_id="deeper",
        source_family="deeper_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        minimum_depth=InvestigationDepth.STANDARD,
    )
    plan = planner((deeper,))
    request = request_for(depth=InvestigationDepth.QUICK)
    decision = plan.next(request, plan.initial_state(request))
    assert decision.call is None
    skipped = {item.provider_id: item for item in decision.skipped}
    assert skipped["deeper"].reason is SkipReason.DEPTH_TOO_SHALLOW
    assert skipped["deeper"].detail == "needs standard"
    # And the same provider becomes eligible one depth up.
    chosen, _, _ = drive(plan, request_for(depth=InvestigationDepth.STANDARD))
    assert chosen == ["deeper:reputation"]


def test_the_same_provider_and_capability_is_never_asked_twice() -> None:
    chosen, _, _ = drive(planner(), request_for(depth=InvestigationDepth.DEEP))
    assert len(chosen) == len(set(chosen))


def test_a_blocked_provider_is_not_selected_again() -> None:
    """Not a retry policy: Task 6 owns retry. This stops wasting decisions."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    first = plan.next(request, state)
    assert first.call is not None
    state.observe(
        first.call,
        fake_outcome(
            first.call.provider_id,
            status=ProviderRunStatus.ERROR,
            error_category=ProviderErrorCategory.RATE_LIMITED,
            source_family=first.call.source_family,
            effect=None,
        ),
    )
    assert first.call.provider_id in state.blocked
    for _ in range(10):
        decision = plan.next(request, state)
        if decision.stop is not None:
            break
        assert decision.call is not None
        assert decision.call.provider_id != first.call.provider_id
        state.observe(
            decision.call,
            fake_outcome(decision.call.provider_id, source_family=decision.call.source_family),
        )


# --------------------------------------------------------------------------- #
# Passive only
# --------------------------------------------------------------------------- #


def test_an_active_request_cannot_be_constructed() -> None:
    """Refused at the model, so no plan can exist that submits anything."""
    with pytest.raises(ValueError, match="passive only"):
        EnrichmentPlanningRequest(intel_object=file_object(), activity_mode=ActivityMode.ACTIVE)


def test_a_non_lookup_operation_cannot_be_constructed() -> None:
    with pytest.raises(ValueError, match="lookups only"):
        EnrichmentPlanningRequest(
            intel_object=file_object(), operation=ProviderOperation.ACTIVE_ACTION
        )


def test_every_planned_call_is_a_passive_lookup() -> None:
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    for _ in range(12):
        decision = plan.next(request, state)
        if decision.stop is not None:
            break
        call = decision.call
        assert call is not None
        assert request.operation is ProviderOperation.LOOKUP
        assert request.activity_mode is ActivityMode.PASSIVE
        state.observe(call, fake_outcome(call.provider_id, source_family=call.source_family))


def test_an_active_only_provider_is_never_planned() -> None:
    """Even if a future descriptor advertises an active capability."""
    from fixtures.planning.fakes import FakePlanningAdapter, profile_for
    from ti_recon.planning.policy import ProviderPlanningRegistry
    from ti_recon.providers.descriptor import ProviderDescriptor
    from ti_recon.providers.registry import ProviderRegistry

    spec = FakeProviderSpec(
        provider_id="active_scanner",
        source_family="active_family",
        capabilities=frozenset({ProviderCapability.REPUTATION, ProviderCapability.ACTIVE_SCAN}),
        supports_active=True,
    )
    adapter = FakePlanningAdapter(spec)
    # Force the descriptor to be active-only, which the registry filter respects.
    object.__setattr__(
        adapter,
        "_descriptor",
        ProviderDescriptor(
            provider_id=spec.provider_id,
            display_name=spec.provider_id,
            adapter_version="1.0.0",
            api_version="v1",
            source_family=spec.source_family,
            supported_object_types=spec.object_types,
            capabilities=spec.capabilities,
            supports_passive=False,
            supports_active=True,
        ),
    )
    plan = AdaptiveEnrichmentPlanner(
        registry=ProviderRegistry([adapter]),
        profiles=ProviderPlanningRegistry((profile_for(spec),)),
    )
    chosen, _, _ = drive(plan, request_for())
    assert chosen == []


# --------------------------------------------------------------------------- #
# Allow / deny / remote disclosure
# --------------------------------------------------------------------------- #


def test_a_denylist_excludes_a_provider() -> None:
    chosen, _, _ = drive(
        planner(),
        request_for(
            depth=InvestigationDepth.DEEP,
            constraints=PlanningConstraints(provider_denylist=frozenset({"reputation_b"})),
        ),
    )
    assert all(not name.startswith("reputation_b") for name in chosen)


def test_an_allowlist_restricts_to_named_providers() -> None:
    chosen, _, _ = drive(
        planner(),
        request_for(
            depth=InvestigationDepth.DEEP,
            constraints=PlanningConstraints(
                provider_allowlist=frozenset({"local_context", "reputation_b"})
            ),
        ),
    )
    assert {name.split(":")[0] for name in chosen} <= {"local_context", "reputation_b"}


def test_a_provider_cannot_be_both_allowed_and_denied() -> None:
    """Reported rather than silently resolved: the caller meant something."""
    with pytest.raises(ValueError, match="both allowed and denied"):
        PlanningConstraints(
            provider_allowlist=frozenset({"reputation_a"}),
            provider_denylist=frozenset({"reputation_a"}),
        )


def test_an_unknown_provider_name_fails_loudly() -> None:
    """A misspelled denylist entry otherwise permits what it meant to exclude."""
    plan = planner()
    with pytest.raises(UnknownProviderError, match="unknown provider"):
        plan.initial_state(
            request_for(constraints=PlanningConstraints(provider_denylist=frozenset({"typo"})))
        )


def test_disabling_remote_lookups_leaves_only_local_providers() -> None:
    """A passive API call still discloses the observable to a third party."""
    chosen, stop, state = drive(
        planner(),
        request_for(
            depth=InvestigationDepth.DEEP,
            constraints=PlanningConstraints(allow_remote_lookup=False),
        ),
    )
    assert chosen == ["local_context:false_positive_context"]
    assert stop is StopReason.REMOTE_LOOKUPS_DISABLED
    assert state.budget.remote_runs_used == 0  # type: ignore[attr-defined]


def test_locality_is_not_inferred_from_credentials() -> None:
    """A credential-free HTTP provider still discloses the observable."""
    credential_free_remote = FakeProviderSpec(
        provider_id="free_but_remote",
        source_family="remote_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.ZERO,
    )
    chosen, _, _ = drive(
        planner((credential_free_remote,)),
        request_for(constraints=PlanningConstraints(allow_remote_lookup=False)),
    )
    assert chosen == []


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("depth", "remote", "high"),
    [
        (InvestigationDepth.QUICK, 2, 0),
        (InvestigationDepth.STANDARD, 4, 1),
        (InvestigationDepth.DEEP, 6, 2),
    ],
)
def test_default_budgets_per_depth(depth: InvestigationDepth, remote: int, high: int) -> None:
    budget = EnrichmentPolicy().budget_for(depth)
    assert budget.max_remote_provider_runs == remote
    assert budget.max_high_cost_runs == high


@pytest.mark.parametrize("depth", list(InvestigationDepth))
def test_no_depth_ever_exceeds_its_remote_budget(depth: InvestigationDepth) -> None:
    """The property that keeps enrichment cost a function of depth."""
    many = tuple(
        FakeProviderSpec(
            provider_id=f"provider_{index:02d}",
            source_family=f"family_{index:02d}",
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
            ),
        )
        for index in range(20)
    )
    _, stop, state = drive(planner(many), request_for(depth=depth))
    budget = state.budget  # type: ignore[attr-defined]
    assert budget.remote_runs_used <= budget.max_remote_provider_runs
    assert stop in set(StopReason)


def test_a_high_cost_provider_cannot_exceed_the_high_cost_budget() -> None:
    expensive = tuple(
        FakeProviderSpec(
            provider_id=f"expensive_{index}",
            source_family=f"expensive_family_{index}",
            capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            cost_class=CallCostClass.HIGH,
            object_types=frozenset({IntelObjectType.FILE}),
        )
        for index in range(5)
    )
    _, _, state = drive(
        planner(expensive),
        request_for(
            depth=InvestigationDepth.STANDARD,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        ),
    )
    budget = state.budget  # type: ignore[attr-defined]
    assert budget.high_cost_runs_used <= budget.max_high_cost_runs == 1


def test_quick_cannot_afford_any_high_cost_provider() -> None:
    """QUICK allows zero high-cost runs, so an expensive specialist is unreachable
    even when explicitly requested — depth is the caller's own statement about how
    much work this investigation warrants."""
    chosen, _, _ = drive(
        planner(),
        request_for(
            depth=InvestigationDepth.QUICK,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        ),
    )
    assert all(not name.startswith("expensive_behavior") for name in chosen)


def test_a_local_provider_never_consumes_remote_budget() -> None:
    locals_only = tuple(
        FakeProviderSpec(
            provider_id=f"local_{index}",
            source_family=f"local_family_{index}",
            capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            locality=ProviderLocality.LOCAL,
            cost_class=CallCostClass.ZERO,
        )
        for index in range(4)
    )
    _, _, state = drive(planner(locals_only), request_for(depth=InvestigationDepth.QUICK))
    assert state.budget.remote_runs_used == 0  # type: ignore[attr-defined]


def test_a_cache_hit_does_not_consume_remote_budget() -> None:
    """Which is what makes cache-first ranking safe: the planner may pick the
    best source and let the execution layer answer for free."""
    _, _, state = drive(
        planner(), request_for(depth=InvestigationDepth.DEEP), called=False, cache_hit=True
    )
    assert state.budget.remote_runs_used == 0  # type: ignore[attr-defined]
    assert any(item.cache_hit for item in state.attempts)  # type: ignore[attr-defined]


def test_an_executor_short_circuit_does_not_consume_remote_budget() -> None:
    """NOT_CONFIGURED, cooldown and quota pre-checks never contacted anyone."""
    plan = planner()
    request = request_for(depth=InvestigationDepth.DEEP)
    state = plan.initial_state(request)
    for _ in range(8):
        decision = plan.next(request, state)
        if decision.stop is not None:
            break
        call = decision.call
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
    assert state.budget.remote_runs_used == 0


def test_a_real_provider_call_does_consume_remote_budget() -> None:
    _, _, state = drive(planner(), request_for(depth=InvestigationDepth.STANDARD))
    assert state.budget.remote_runs_used > 0  # type: ignore[attr-defined]


def test_a_caller_may_lower_the_budget_but_not_raise_it() -> None:
    policy = EnrichmentPolicy()
    assert (
        policy.budget_for(InvestigationDepth.DEEP, override_remote=1).max_remote_provider_runs == 1
    )
    assert (
        policy.budget_for(InvestigationDepth.QUICK, override_remote=99).max_remote_provider_runs
        == 2
    )


def test_an_exhausted_budget_stops_with_the_budget_reason() -> None:
    many = tuple(
        FakeProviderSpec(
            provider_id=f"provider_{index:02d}",
            source_family=f"family_{index:02d}",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        )
        for index in range(10)
    )
    _, stop, _ = drive(
        planner(many),
        request_for(
            depth=InvestigationDepth.DEEP,
            # Force a shortfall: three families wanted, one run allowed.
            constraints=PlanningConstraints(max_remote_provider_runs=1),
        ),
    )
    assert stop is StopReason.REMOTE_BUDGET_EXHAUSTED


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_the_same_inputs_produce_the_same_plan() -> None:
    request = request_for(depth=InvestigationDepth.DEEP)
    first, _, _ = drive(planner(), request)
    second, _, _ = drive(planner(), request)
    assert first == second


def test_registration_order_does_not_change_the_plan() -> None:
    """Candidate generation iterates sorted collections for exactly this reason."""
    from fixtures.planning.fakes import specs_for

    specs = specs_for()
    forward, _, _ = drive(planner(specs), request_for(depth=InvestigationDepth.DEEP))
    reverse, _, _ = drive(
        planner(tuple(reversed(specs))), request_for(depth=InvestigationDepth.DEEP)
    )
    assert forward == reverse


def test_the_ranking_order_is_documented_as_data() -> None:
    """So the documentation and the implementation cannot drift apart."""
    assert RANKING_FACTORS == (
        "explicit_capability",
        "local_before_remote",
        "required_unsatisfied_goal",
        "baseline_before_specialized",
        "novelty",
        "cost_class",
        "profile_priority",
        "provider_id",
        "capability",
    )
