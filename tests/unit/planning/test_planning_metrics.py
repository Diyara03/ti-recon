"""Planning metrics: what is emitted, and what can never be (Task 13)."""

from __future__ import annotations

import pytest

from fixtures.planning import build_registry, file_object
from ti_recon.credentials import (
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ManualClock,
    NoOpExecutionMetricsSink,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RecordingSleeper,
)
from ti_recon.planning import (
    AdaptiveEnrichmentOrchestrator,
    AdaptiveEnrichmentPlanner,
    EnrichmentPlanningRequest,
    InMemoryPlanningMetricsSink,
    NoOpPlanningMetricsSink,
    PlanningConstraints,
    PlanningMetricsSink,
    PlanningRunMetric,
    ProviderSelectionMetric,
    ProviderSkipMetric,
    SkipReason,
    StopReason,
)

SECRET = "planning-metrics-key-SHOULD-NOT-LEAK"


def orchestrator(
    metrics: PlanningMetricsSink | None = None,
) -> AdaptiveEnrichmentOrchestrator:
    registry, profiles = build_registry()
    clock = ManualClock()
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    executor = ProviderExecutor(
        credential_resolver=CredentialResolver(secrets, connections),
        cache=InMemoryProviderCache(clock=clock),
        quota_store=InMemoryQuotaStore(clock=clock),
        cooldown_store=InMemoryCooldownStore(clock=clock),
        limiter=ConcurrencyLimiter(max_concurrency=4),
        policies=ProviderPolicyRegistry(policies=[]),
        metrics=NoOpExecutionMetricsSink(),
        clock=clock,
        sleeper=RecordingSleeper(clock),
        jitter=FixedJitter(0.0),
    )
    return AdaptiveEnrichmentOrchestrator(
        planner=AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles),
        executor=executor,
        registry=registry,
        metrics=metrics,
    )


async def run_once(metrics: PlanningMetricsSink | None = None, **overrides: object) -> None:
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        **{"depth": InvestigationDepth.STANDARD, **overrides},  # type: ignore[arg-type]
    )
    await orchestrator(metrics).run(
        request,
        ExecutionContext(authenticated_user_id="analyst-a", request_id="req-1"),
        investigation_id="inv-1",
    )


async def test_a_run_emits_one_run_metric_with_its_stop_reason() -> None:
    sink = InMemoryPlanningMetricsSink()
    await run_once(sink)
    assert len(sink.runs) == 1
    run = sink.runs[0]
    assert run.object_type is IntelObjectType.FILE
    assert run.depth is InvestigationDepth.STANDARD
    assert run.stop_reason in set(StopReason)
    assert run.rounds >= 1
    assert run.remote_budget == 4
    assert run.remote_runs_used <= run.remote_budget


async def test_selections_and_skips_are_both_recorded() -> None:
    """A skip is the more useful aggregate: it is invisible in the calls that
    did happen."""
    sink = InMemoryPlanningMetricsSink()
    await run_once(sink)
    assert sink.selections
    assert sink.skips
    assert set(sink.selections_by_provider()) <= {
        "local_context",
        "reputation_a",
        "reputation_a_second",
        "reputation_b",
        "expensive_behavior",
    }
    assert set(sink.skips_by_reason()) <= set(SkipReason)


async def test_a_blocked_provider_is_visible_as_a_skip_reason() -> None:
    """No credential is configured for any of these fakes, so every remote
    provider reports itself unconfigured through Task 6.

    Run at DEEP, where a later-activating goal (threat associations) gives a
    blocked provider a second chance to be considered — at STANDARD the capability
    would have been bundled into the first request and the skip would read
    ``ALREADY_ATTEMPTED`` instead, which is also true and less interesting.
    """
    sink = InMemoryPlanningMetricsSink()
    await run_once(sink, depth=InvestigationDepth.DEEP)
    assert sink.skips_by_reason()[SkipReason.BLOCKED] >= 1


async def test_stop_reasons_aggregate() -> None:
    sink = InMemoryPlanningMetricsSink()
    await run_once(sink)
    await run_once(sink)
    assert sum(sink.stops_by_reason().values()) == 2


async def test_a_denied_provider_appears_as_a_skip_not_a_selection() -> None:
    sink = InMemoryPlanningMetricsSink()
    await run_once(
        sink, constraints=PlanningConstraints(provider_denylist=frozenset({"reputation_b"}))
    )
    assert "reputation_b" not in sink.selections_by_provider()
    assert sink.skips_by_reason()[SkipReason.DENIED] >= 1


async def test_the_default_sink_discards_and_nothing_depends_on_metrics() -> None:
    await run_once(None)
    await run_once(NoOpPlanningMetricsSink())


def test_no_metric_can_hold_an_observable_value_or_free_text() -> None:
    """Structural, not a spot check: a metric labelled with the IOC would turn a
    metrics pipeline into a log of everything every analyst investigated.

    Provider ids are bounded and enumerable; everything else must be an enum, a
    bounded int, a bool or a timestamp.
    """
    bounded_strings = {"provider_id"}
    for model in (ProviderSelectionMetric, ProviderSkipMetric, PlanningRunMetric):
        for name, field in model.model_fields.items():
            annotation = repr(field.annotation)
            if "str" in annotation:
                assert name in bounded_strings, f"{model.__name__}.{name}"


def test_the_in_memory_sink_is_bounded_and_marked_unfit_for_production() -> None:
    sink = InMemoryPlanningMetricsSink(max_records=2)
    for index in range(5):
        sink.record_run(
            PlanningRunMetric(
                object_type=IntelObjectType.FILE,
                depth=InvestigationDepth.QUICK,
                stop_reason=StopReason.GOALS_SATISFIED,
                rounds=index,
                providers_called=0,
                remote_runs_used=0,
                high_cost_runs_used=0,
                remote_budget=2,
                cache_hits=0,
            )
        )
    assert len(sink.runs) == 2
    assert sink.is_production_ready is False
    sink.clear()
    assert not sink.runs
    with pytest.raises(ValueError, match="max_records"):
        InMemoryPlanningMetricsSink(max_records=0)


def test_a_skip_that_is_not_about_a_provider_needs_no_capability() -> None:
    metric = ProviderSkipMetric(
        provider_id="-",
        object_type=IntelObjectType.FILE,
        depth=InvestigationDepth.QUICK,
        reason=SkipReason.GOAL_NOT_ACTIVE,
    )
    assert metric.capability is None


def test_the_sink_protocol_is_satisfied_by_both_implementations() -> None:
    assert isinstance(NoOpPlanningMetricsSink(), PlanningMetricsSink)
    assert isinstance(InMemoryPlanningMetricsSink(), PlanningMetricsSink)


def test_a_selection_metric_records_why_not_just_what() -> None:
    """The reason code is what makes an aggregate explainable rather than a
    count of calls."""
    assert "reason" in ProviderSelectionMetric.model_fields
    assert "novelty" in ProviderSelectionMetric.model_fields
    assert "capability" in ProviderSelectionMetric.model_fields
    assert ProviderCapability in {
        field.annotation for field in ProviderSelectionMetric.model_fields.values()
    }
