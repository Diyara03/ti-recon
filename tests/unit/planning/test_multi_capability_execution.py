"""One provider, several capabilities, how many physical executions (Task 13).

A provider that answers four active goals with one read must be asked once. The
opposite — one request per capability — costs a budget unit and a real API call
per goal and returns the same document each time, which is what these tests exist
to prevent.

Every count here is measured through a real `ProviderExecutor` against a counting
adapter, not asserted from planner intent: the cache key includes
`requested_capabilities`, so two capability sets are two physical calls and no
amount of planner tidiness would hide a duplicate.
"""

from __future__ import annotations

from functools import lru_cache

import pytest

from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from fixtures.planning import (
    FakeProviderSpec,
    fake_outcome,
    file_object,
)
from fixtures.planning.fakes import FakePlanningAdapter, profile_for
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryExecutionMetricsSink,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ManualClock,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RecordingSleeper,
)
from ti_recon.planning import (
    AdaptiveEnrichmentOrchestrator,
    AdaptiveEnrichmentPlanner,
    CallCostClass,
    EnrichmentPlanningRequest,
    NoveltyClass,
    PlannedProviderCall,
    PlanningConstraints,
    ProviderLocality,
    SelectionReason,
)
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers.gti import GTI_PROVIDER_ID, GTIAdapter
from ti_recon.providers.hybrid_analysis import (
    HYBRID_ANALYSIS_PROVIDER_ID,
    HybridAnalysisAdapter,
    build_hybrid_analysis_execution_policy,
)
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter
from ti_recon.providers.misp_warninglists import (
    MispWarningListsAdapter,
    build_misp_warninglists_execution_policy,
)
from ti_recon.providers.registry import ProviderRegistry

FILE_CAPABILITIES = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
    }
)


def local_multi(
    *, invariant: bool, capabilities: frozenset[ProviderCapability] = FILE_CAPABILITIES
) -> FakeProviderSpec:
    """A credential-free provider serving several capabilities.

    Local so the executor reaches `lookup` with no credential to configure — the
    point here is how many times it is reached, not how it is authenticated.
    """
    return FakeProviderSpec(
        provider_id="multi",
        source_family="multi_family",
        capabilities=capabilities,
        locality=ProviderLocality.LOCAL,
        cost_class=CallCostClass.ZERO,
        object_types=frozenset({IntelObjectType.FILE}),
        capability_invariant_response=invariant,
    )


class Harness:
    """Planner and orchestrator over counting fake adapters."""

    def __init__(self, specs: tuple[FakeProviderSpec, ...]) -> None:
        self.specs = specs
        self.adapters = [FakePlanningAdapter(spec) for spec in specs]
        self.registry = ProviderRegistry(self.adapters)
        clock = ManualClock()
        self.metrics = InMemoryExecutionMetricsSink()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.orchestrator = AdaptiveEnrichmentOrchestrator(
            planner=AdaptiveEnrichmentPlanner(
                registry=self.registry,
                profiles=ProviderPlanningRegistry(tuple(profile_for(spec) for spec in specs)),
            ),
            executor=ProviderExecutor(
                credential_resolver=CredentialResolver(self.secrets, self.connections),
                cache=InMemoryProviderCache(clock=clock),
                quota_store=InMemoryQuotaStore(clock=clock),
                cooldown_store=InMemoryCooldownStore(clock=clock),
                limiter=ConcurrencyLimiter(max_concurrency=4),
                policies=ProviderPolicyRegistry(policies=[]),
                metrics=self.metrics,
                clock=clock,
                sleeper=RecordingSleeper(clock),
                jitter=FixedJitter(0.0),
            ),
            registry=self.registry,
        )

    def adapter(self, provider_id: str) -> FakePlanningAdapter:
        return next(item for item in self.adapters if item.descriptor.provider_id == provider_id)

    def capability_sets(self, provider_id: str) -> list[frozenset[ProviderCapability]]:
        """The capability set of each physical lookup, in order."""
        return [caps for _, caps in self.adapter(provider_id).calls]

    async def add_credentials(self) -> None:
        """A key per remote fake, so the executor reaches the adapter."""
        for spec in self.specs:
            if spec.locality is ProviderLocality.REMOTE:
                await self.manager.create_connection(
                    user_id="analyst-a",
                    provider_id=spec.provider_id,
                    secret=f"{spec.provider_id}-key-SHOULD-NOT-LEAK",
                    auth_type=AuthType.API_KEY,
                    status=CredentialStatus.ACTIVE,
                )

    async def run(self, **overrides: object) -> object:
        await self.add_credentials()
        request = EnrichmentPlanningRequest(
            intel_object=file_object(),
            **{"depth": InvestigationDepth.STANDARD, **overrides},  # type: ignore[arg-type]
        )
        return await self.orchestrator.run(
            request,
            ExecutionContext(authenticated_user_id="analyst-a", request_id="req-1"),
            investigation_id="inv-1",
        )


# --------------------------------------------------------------------------- #
# A. Two active goals, one provider
# --------------------------------------------------------------------------- #


async def test_two_active_goals_one_provider_serves_are_one_physical_execution() -> None:
    """The regression this review found: one request per capability.

    Reputation and malware intelligence are both active from the first round at
    STANDARD depth, and one provider serves both, so it is asked once for both.
    """
    harness = Harness((local_multi(invariant=True),))
    await harness.run()
    assert len(harness.capability_sets("multi")) == 1
    assert harness.capability_sets("multi")[0] == frozenset(
        {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
    )


async def test_the_bundled_call_is_one_logical_run_in_the_trace() -> None:
    """One decision, one attempt, one budget unit — with the primary capability
    still naming the decision so the explanation stays readable."""
    harness = Harness(
        (
            FakeProviderSpec(
                provider_id="multi",
                source_family="multi_family",
                capabilities=FILE_CAPABILITIES,
                object_types=frozenset({IntelObjectType.FILE}),
                capability_invariant_response=True,
            ),
        )
    )
    result = await harness.run()
    attempts = result.attempts  # type: ignore[attr-defined]
    assert len(attempts) == 1
    assert attempts[0].capability is ProviderCapability.REPUTATION
    assert result.budget.remote_runs_used == 1  # type: ignore[attr-defined]


async def test_coverage_is_credited_for_every_capability_the_one_response_answers() -> None:
    harness = Harness((local_multi(invariant=True),))
    result = await harness.run()
    covered = {item.capability for item in result.coverage}  # type: ignore[attr-defined]
    assert ProviderCapability.MALWARE_INTELLIGENCE in covered


# --------------------------------------------------------------------------- #
# B. An inactive capability is not activated by bundling
# --------------------------------------------------------------------------- #


async def test_bundling_never_activates_a_capability_the_depth_does_not_want() -> None:
    """QUICK has no behaviour goal, so a provider that supports behaviour is not
    asked for it merely because it is being asked something else."""
    harness = Harness(
        (
            local_multi(
                invariant=True,
                capabilities=FILE_CAPABILITIES | {ProviderCapability.FILE_BEHAVIOR},
            ),
        )
    )
    await harness.run(depth=InvestigationDepth.QUICK)
    sets = harness.capability_sets("multi")
    assert len(sets) == 1
    assert ProviderCapability.FILE_BEHAVIOR not in sets[0]


async def test_bundling_never_includes_a_goal_still_waiting_for_its_trigger() -> None:
    """Threat associations exist only at DEEP and only after the baseline, so the
    first request cannot carry them."""
    harness = Harness((local_multi(invariant=False),))
    await harness.run(depth=InvestigationDepth.DEEP)
    first = harness.capability_sets("multi")[0]
    assert ProviderCapability.THREAT_ASSOCIATIONS not in first


async def test_an_expensive_capability_is_never_bundled_in_silently() -> None:
    """An elevated-cost capability has to win a decision of its own.

    Otherwise a bundle becomes a way to spend the high-cost budget nobody
    decided to spend — and, for retrieved page content, a way around the rule
    that forensics needs an explicit request.
    """
    spec = FakeProviderSpec(
        provider_id="multi",
        source_family="multi_family",
        capabilities=FILE_CAPABILITIES | {ProviderCapability.FILE_BEHAVIOR},
        object_types=frozenset({IntelObjectType.FILE}),
        elevated=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        capability_invariant_response=True,
    )
    harness = Harness((spec,))
    result = await harness.run(
        depth=InvestigationDepth.DEEP,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    # Behaviour was explicitly requested, so it is the *primary* of its own call.
    sets = harness.capability_sets("multi")
    behaviour_calls = [item for item in sets if ProviderCapability.FILE_BEHAVIOR in item]
    assert len(behaviour_calls) == 1
    assert result.budget.high_cost_runs_used == 1  # type: ignore[attr-defined]
    # And no other call smuggled it in.
    assert all(
        ProviderCapability.FILE_BEHAVIOR not in item
        for item in sets
        if item is not behaviour_calls[0]
    )


# --------------------------------------------------------------------------- #
# C. A capability that becomes active later
# --------------------------------------------------------------------------- #


async def test_a_capability_invariant_provider_is_not_asked_twice() -> None:
    """Its own declaration is what makes the second call unnecessary.

    One read returned the whole document, so the later-activating goal is already
    covered and no duplicate request is made.
    """
    harness = Harness((local_multi(invariant=True),))
    result = await harness.run(depth=InvestigationDepth.DEEP)
    assert len(harness.capability_sets("multi")) == 1
    covered = {
        item.capability
        for item in result.coverage  # type: ignore[attr-defined]
        if item.status.value == "covered"
    }
    assert ProviderCapability.THREAT_ASSOCIATIONS in covered


async def test_a_request_shaped_provider_is_asked_again_deliberately() -> None:
    """When the response is shaped by the request, a capability nobody asked for
    was not answered, and the second call is real incremental coverage."""
    harness = Harness((local_multi(invariant=False),))
    await harness.run(depth=InvestigationDepth.DEEP)
    sets = harness.capability_sets("multi")
    assert len(sets) == 2
    assert sets[0] == frozenset(
        {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
    )
    assert sets[1] == frozenset({ProviderCapability.THREAT_ASSOCIATIONS})


async def test_the_two_calls_are_two_logical_runs_and_two_budget_units() -> None:
    """Honest accounting: incremental work is charged, not hidden."""
    harness = Harness(
        (
            FakeProviderSpec(
                provider_id="multi",
                source_family="multi_family",
                capabilities=FILE_CAPABILITIES,
                object_types=frozenset({IntelObjectType.FILE}),
                capability_invariant_response=False,
            ),
        )
    )
    result = await harness.run(depth=InvestigationDepth.DEEP)
    assert result.budget.remote_runs_used == 2  # type: ignore[attr-defined]
    assert len(harness.metrics.executions) == 2


# --------------------------------------------------------------------------- #
# D. The GTI DEEP file case, counted
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def real_registry() -> ProviderRegistry:
    """Cached: constructing the local-dataset adapter reads the shipped snapshot,
    and these tests only read descriptors from it."""
    return ProviderRegistry(
        [
            GTIAdapter(),
            MalwareBazaarAdapter(),
            MispWarningListsAdapter(),
            HybridAnalysisAdapter(),
        ]
    )


def real_planner() -> AdaptiveEnrichmentPlanner:
    return AdaptiveEnrichmentPlanner(
        registry=real_registry(), profiles=build_default_planning_registry()
    )


def plan_calls(
    depth: InvestigationDepth,
    *,
    effect: EvidenceEffect | None = None,
    requested: frozenset[ProviderCapability] = frozenset(),
) -> list[tuple[str, frozenset[ProviderCapability]]]:
    """Provider and capability set of every call a plan would make."""
    plan = real_planner()
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=depth,
        requested_capabilities=requested,
    )
    state = plan.initial_state(request)
    calls: list[tuple[str, frozenset[ProviderCapability]]] = []
    for _ in range(15):
        decision = plan.next(request, state)
        if decision.stop is not None:
            break
        call = decision.call
        assert call is not None
        calls.append((call.provider_id, call.capabilities))
        state.observe(
            call,
            fake_outcome(call.provider_id, source_family=call.source_family, effect=effect),
        )
    return calls


@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        # QUICK: GTI is not needed — one family satisfies the reputation goal and a
        # cheaper provider ranks first.
        (InvestigationDepth.QUICK, 0),
        # STANDARD: one call. Reputation, as the second independent family.
        (InvestigationDepth.STANDARD, 1),
        # DEEP: two calls, and the second is not a duplicate. GTI's response is
        # shaped by the request — the behaviour summary is a separate endpoint,
        # fetched only when FILE_BEHAVIOR is asked for — and that goal only
        # activates once the baseline exists.
        (InvestigationDepth.DEEP, 2),
    ],
)
def test_the_documented_number_of_gti_executions_per_depth(
    depth: InvestigationDepth, expected: int
) -> None:
    calls = [item for item in plan_calls(depth) if item[0] == GTI_PROVIDER_ID]
    assert len(calls) == expected, calls


def test_the_second_gti_call_carries_only_the_incremental_capability() -> None:
    """Not a repeat of the first: reputation is already covered, so it is not
    asked again."""
    calls = [item for item in plan_calls(InvestigationDepth.DEEP) if item[0] == GTI_PROVIDER_ID]
    assert calls[1][1] == frozenset({ProviderCapability.FILE_BEHAVIOR})
    assert ProviderCapability.REPUTATION not in calls[1][1]


def test_the_abusech_platform_answers_two_goals_in_one_call() -> None:
    """MalwareBazaar declares its response capability-invariant, so reputation and
    malware intelligence arrive together — before this review it was called once
    per capability."""
    calls = [item for item in plan_calls(InvestigationDepth.DEEP) if item[0] == "malwarebazaar"]
    assert len(calls) == 1
    assert {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE} <= calls[0][1]


def test_quick_never_asks_for_behaviour_even_though_gti_supports_it() -> None:
    for depth, allowed in (
        (InvestigationDepth.QUICK, False),
        (InvestigationDepth.DEEP, True),
    ):
        behaviour = [
            item for item in plan_calls(depth) if ProviderCapability.FILE_BEHAVIOR in item[1]
        ]
        assert bool(behaviour) is allowed, (depth, behaviour)


# --------------------------------------------------------------------------- #
# E. The dedicated sandbox stays reachable
# --------------------------------------------------------------------------- #


def test_the_sandbox_remains_eligible_when_behaviour_coverage_is_wanted() -> None:
    """Bundling must not quietly answer FILE_BEHAVIOR from a provider that only
    declares it as a side capability.

    GTI outranks the dedicated sandbox on priority, so it is asked first; when it
    cannot serve, the sandbox is still there.
    """
    calls = plan_calls(
        InvestigationDepth.DEEP,
        requested=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    behaviour = [item for item in calls if ProviderCapability.FILE_BEHAVIOR in item[1]]
    assert behaviour
    assert behaviour[0][0] == GTI_PROVIDER_ID

    plan = AdaptiveEnrichmentPlanner(
        registry=ProviderRegistry([MispWarningListsAdapter(), HybridAnalysisAdapter()]),
        profiles=build_default_planning_registry(),
    )
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=InvestigationDepth.DEEP,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    decision = plan.next(request, plan.initial_state(request))
    assert decision.call is not None
    assert decision.call.provider_id == HYBRID_ANALYSIS_PROVIDER_ID
    assert decision.call.capabilities == frozenset({ProviderCapability.FILE_BEHAVIOR})
    assert decision.call.reason is SelectionReason.EXPLICIT_CAPABILITY


async def test_the_sandbox_executes_with_exactly_the_bundled_capability_set() -> None:
    """End to end through Task 6, with a fake sandbox client: one request, and its
    capability set is what the planner decided."""
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)
    await manager.create_connection(
        user_id="analyst-a",
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        secret="ha-key-SHOULD-NOT-LEAK",
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
    )
    client = FakeHybridAnalysisClient()
    registry = ProviderRegistry(
        [
            MispWarningListsAdapter(),
            HybridAnalysisAdapter(client_factory=ClientFactory(client)),  # type: ignore[arg-type]
        ]
    )
    clock = ManualClock()
    orchestrator = AdaptiveEnrichmentOrchestrator(
        planner=AdaptiveEnrichmentPlanner(
            registry=registry, profiles=build_default_planning_registry()
        ),
        executor=ProviderExecutor(
            credential_resolver=CredentialResolver(secrets, connections),
            cache=InMemoryProviderCache(clock=clock),
            quota_store=InMemoryQuotaStore(clock=clock),
            cooldown_store=InMemoryCooldownStore(clock=clock),
            limiter=ConcurrencyLimiter(max_concurrency=2),
            policies=ProviderPolicyRegistry(
                policies=[
                    build_misp_warninglists_execution_policy(),
                    build_hybrid_analysis_execution_policy(),
                ]
            ),
            metrics=InMemoryExecutionMetricsSink(),
            clock=clock,
            sleeper=RecordingSleeper(clock),
            jitter=FixedJitter(0.0),
        ),
        registry=registry,
    )
    result = await orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=file_object(),
            depth=InvestigationDepth.DEEP,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            constraints=PlanningConstraints(
                provider_allowlist=frozenset({"misp_warninglists", HYBRID_ANALYSIS_PROVIDER_ID})
            ),
        ),
        ExecutionContext(authenticated_user_id="analyst-a", request_id="req-1"),
        investigation_id="inv-1",
    )
    sandbox = [
        attempt for attempt in result.attempts if attempt.provider_id == HYBRID_ANALYSIS_PROVIDER_ID
    ]
    assert len(sandbox) == 1
    assert sandbox[0].status is ProviderRunStatus.SUCCESS
    assert client.call_count("search_hash") == 1
    assert result.budget.high_cost_runs_used == 1


# --------------------------------------------------------------------------- #
# Why this is the planner's problem and not the cache's
# --------------------------------------------------------------------------- #


def test_two_capability_sets_are_two_different_cache_keys() -> None:
    """`requested_capabilities` is part of the Task 6 cache key, and rightly so:
    for a provider whose response is shaped by the request, two sets are two
    different questions. Which is exactly why asking once per capability cannot be
    deduplicated below the planner — the duplicate has to be *not made*.
    """
    from ti_recon.execution.cache import build_cache_key
    from ti_recon.execution.models import ExecutionScope
    from ti_recon.providers import ProviderRequest
    from ti_recon.providers.malwarebazaar import build_malwarebazaar_descriptor

    descriptor = build_malwarebazaar_descriptor()
    scope = ExecutionScope(provider_id=descriptor.provider_id, user_id="analyst-a")

    def key(capabilities: frozenset[ProviderCapability]) -> str:
        return build_cache_key(
            scope=scope,
            descriptor=descriptor,
            request=ProviderRequest(
                investigation_id="inv-1",
                intel_object=file_object(),
                requested_capabilities=capabilities,
            ),
        ).digest

    one = key(frozenset({ProviderCapability.REPUTATION}))
    another = key(frozenset({ProviderCapability.MALWARE_INTELLIGENCE}))
    both = key(frozenset({ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}))
    assert len({one, another, both}) == 3
    # A bundle is stable regardless of how the set was built.
    assert both == key(
        frozenset({ProviderCapability.MALWARE_INTELLIGENCE, ProviderCapability.REPUTATION})
    )


# --------------------------------------------------------------------------- #
# The model refuses an incoherent call
# --------------------------------------------------------------------------- #


def test_a_call_must_carry_the_capability_it_was_selected_for() -> None:
    with pytest.raises(ValueError, match="must be part of the request"):
        PlannedProviderCall(
            provider_id="one",
            capability=ProviderCapability.REPUTATION,
            capabilities=frozenset({ProviderCapability.MALWARE_INTELLIGENCE}),
            source_family="one",
            locality=ProviderLocality.REMOTE,
            cost_class=CallCostClass.LOW,
            depth=InvestigationDepth.QUICK,
            reason=SelectionReason.MISSING_CAPABILITY,
            novelty=NoveltyClass.NEW_CAPABILITY,
        )


def test_answered_capabilities_cannot_be_narrower_than_the_request() -> None:
    """Coverage would then be credited for less than was actually asked."""
    with pytest.raises(ValueError, match="must include everything requested"):
        PlannedProviderCall(
            provider_id="one",
            capability=ProviderCapability.REPUTATION,
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
            ),
            answered_capabilities=frozenset({ProviderCapability.REPUTATION}),
            source_family="one",
            locality=ProviderLocality.REMOTE,
            cost_class=CallCostClass.LOW,
            depth=InvestigationDepth.QUICK,
            reason=SelectionReason.MISSING_CAPABILITY,
            novelty=NoveltyClass.NEW_CAPABILITY,
        )


def test_a_hand_built_call_defaults_to_its_single_capability() -> None:
    call = PlannedProviderCall(
        provider_id="one",
        capability=ProviderCapability.REPUTATION,
        source_family="one",
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        depth=InvestigationDepth.QUICK,
        reason=SelectionReason.MISSING_CAPABILITY,
        novelty=NoveltyClass.NEW_CAPABILITY,
    )
    assert call.capabilities == frozenset({ProviderCapability.REPUTATION})
    assert call.answered_capabilities == call.capabilities


def test_bundling_is_deterministic() -> None:
    """Same inputs, same bundle — including which capability is primary."""
    first = plan_calls(InvestigationDepth.DEEP)
    second = plan_calls(InvestigationDepth.DEEP)
    assert first == second


async def test_registration_order_does_not_change_a_bundle() -> None:
    """Two providers, both orders, same bundles."""
    other = FakeProviderSpec(
        provider_id="other",
        source_family="other_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        object_types=frozenset({IntelObjectType.FILE}),
        capability_invariant_response=True,
    )
    forward = Harness((local_multi(invariant=True), other))
    reverse = Harness((other, local_multi(invariant=True)))
    await forward.run()
    await reverse.run()
    assert forward.capability_sets("multi") == reverse.capability_sets("multi")
    assert forward.capability_sets("other") == reverse.capability_sets("other")


async def test_the_bundled_attempt_records_every_capability_it_carried() -> None:
    """One attempt, naming the primary and carrying the bundle (Task 24 Phase 3)."""
    harness = Harness(
        (
            FakeProviderSpec(
                provider_id="multi",
                source_family="multi_family",
                capabilities=FILE_CAPABILITIES,
                object_types=frozenset({IntelObjectType.FILE}),
                capability_invariant_response=True,
            ),
        )
    )
    result = await harness.run()
    (attempt,) = result.attempts  # type: ignore[attr-defined]
    assert attempt.capability is ProviderCapability.REPUTATION
    assert attempt.capability in attempt.capabilities
    assert ProviderCapability.MALWARE_INTELLIGENCE in attempt.capabilities
