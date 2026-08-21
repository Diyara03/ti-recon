"""Execution metrics (Task 6, step 6)."""

from __future__ import annotations

import json

import pytest

from fixtures.execution import make_object, make_request
from fixtures.execution_adapters import ScriptedAdapter, ScriptedStep
from ti_recon.enums import (
    IntelObjectType,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    ExecutionMetric,
    ExecutionMetricsSink,
    InMemoryExecutionMetricsSink,
    NoOpExecutionMetricsSink,
    ProviderAttemptMetric,
    ProviderExecutor,
    scope_digest,
)
from ti_recon.providers.errors import provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN
from unit.execution.test_executor import KEY_A, USER_A, Harness


def make_metric(**overrides: object) -> ExecutionMetric:
    kwargs: dict[str, object] = {
        "provider_id": "fake_aggregator",
        "operation": ProviderOperation.LOOKUP,
        "status": ProviderRunStatus.SUCCESS,
        "object_type": IntelObjectType.DOMAIN_NAME,
        "duration_ms": 12.5,
        "attempts": 1,
    }
    kwargs.update(overrides)
    return ExecutionMetric(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Sinks
# --------------------------------------------------------------------------- #


def test_the_noop_sink_discards_everything() -> None:
    sink = NoOpExecutionMetricsSink()
    sink.record_execution(make_metric())
    sink.record_attempt(
        ProviderAttemptMetric(
            provider_id="fake_aggregator",
            operation=ProviderOperation.LOOKUP,
            attempt=1,
            duration_ms=1.0,
        )
    )
    assert isinstance(sink, ExecutionMetricsSink)


def test_the_in_memory_sink_keeps_what_it_is_given() -> None:
    sink = InMemoryExecutionMetricsSink()
    sink.record_execution(make_metric())
    sink.record_execution(make_metric(status=ProviderRunStatus.NO_DATA))
    assert len(sink) == 2
    assert sink.count_by_status(ProviderRunStatus.SUCCESS) == 1
    assert sink.count_by_status(ProviderRunStatus.NO_DATA) == 1
    assert isinstance(sink, ExecutionMetricsSink)


def test_the_in_memory_sink_is_bounded() -> None:
    sink = InMemoryExecutionMetricsSink(max_records=3)
    for _ in range(10):
        sink.record_execution(make_metric())
    assert len(sink) == 3


def test_the_in_memory_sink_rejects_an_invalid_bound() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryExecutionMetricsSink(max_records=0)


def test_the_in_memory_sink_can_be_cleared() -> None:
    sink = InMemoryExecutionMetricsSink()
    sink.record_execution(make_metric())
    sink.record_attempt(
        ProviderAttemptMetric(
            provider_id="fake_aggregator",
            operation=ProviderOperation.LOOKUP,
            attempt=1,
            duration_ms=1.0,
        )
    )
    sink.clear()
    assert len(sink) == 0
    assert not sink.attempts


def test_the_in_memory_sink_is_labelled_not_production_ready() -> None:
    assert InMemoryExecutionMetricsSink.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemoryExecutionMetricsSink.__doc__ or "")


def test_sink_aggregates() -> None:
    sink = InMemoryExecutionMetricsSink()
    sink.record_execution(make_metric(attempts=3))
    sink.record_execution(make_metric(attempts=0, cache_hit=True))
    sink.record_execution(make_metric(attempts=1, coalesced=True))
    sink.record_execution(make_metric(attempts=1, cooldown_applied=True))

    assert sink.total_attempts == 5
    assert sink.total_retries == 2
    assert sink.cache_hits == 1
    assert sink.coalesced == 1
    assert sink.cooldowns_applied == 1


def test_sink_repr_reports_counts_only() -> None:
    sink = InMemoryExecutionMetricsSink()
    sink.record_execution(make_metric())
    assert repr(sink) == "<InMemoryExecutionMetricsSink executions=1 attempts=0>"


# --------------------------------------------------------------------------- #
# Metric shape
# --------------------------------------------------------------------------- #


def test_logical_and_attempt_metrics_are_separate_concepts() -> None:
    """Three attempts must not look like three requests."""
    metric = make_metric(attempts=3)
    assert metric.attempts == 3
    assert metric.retry_count == 2
    assert metric.called_provider is True


def test_a_cache_hit_reports_no_provider_call() -> None:
    metric = make_metric(attempts=0, cache_hit=True)
    assert metric.called_provider is False
    assert metric.retry_count == 0


def test_an_attempt_metric_reports_success_or_category() -> None:
    ok = ProviderAttemptMetric(
        provider_id="fake_aggregator",
        operation=ProviderOperation.LOOKUP,
        attempt=1,
        duration_ms=5.0,
    )
    failed = ProviderAttemptMetric(
        provider_id="fake_aggregator",
        operation=ProviderOperation.LOOKUP,
        attempt=2,
        duration_ms=5.0,
        error_category=ProviderErrorCategory.TRANSIENT_ERROR,
        retried=True,
    )
    assert ok.succeeded is True
    assert failed.succeeded is False
    assert failed.retried is True


def test_attempt_numbers_are_one_based() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProviderAttemptMetric(
            provider_id="fake_aggregator",
            operation=ProviderOperation.LOOKUP,
            attempt=0,
            duration_ms=1.0,
        )


def test_metrics_have_no_field_that_could_hold_an_observable_value() -> None:
    """Structural, not a filter: there is nowhere to put an IOC."""
    for model in (ExecutionMetric, ProviderAttemptMetric):
        fields = set(model.model_fields)
        assert fields.isdisjoint(
            {
                "observable",
                "canonical_value",
                "intel_object",
                "value",
                "url",
                "indicator",
                "query",
            }
        )


def test_metrics_have_no_credential_shaped_field() -> None:
    for model in (ExecutionMetric, ProviderAttemptMetric):
        for name in model.model_fields:
            assert SENSITIVE_KEY_PATTERN.search(name) is None, name


def test_scope_digest_is_opaque_stable_and_short() -> None:
    first = scope_digest("user|analyst-a|fake_aggregator|conn-a")
    second = scope_digest("user|analyst-a|fake_aggregator|conn-a")
    other = scope_digest("user|analyst-b|fake_aggregator|conn-b")
    assert first == second
    assert first != other
    assert len(first) == 16
    assert "analyst-a" not in first


# --------------------------------------------------------------------------- #
# Emission from the executor
# --------------------------------------------------------------------------- #


async def executed_harness(
    *, sink: InMemoryExecutionMetricsSink, **executor_kwargs: object
) -> Harness:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    harness.executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        quota_store=harness.quota,
        cooldown_store=harness.cooldowns,
        policies=harness.policies,
        metrics=sink,
        clock=harness.clock,
        sleeper=harness.sleeper,
        **executor_kwargs,  # type: ignore[arg-type]
    )
    return harness


async def test_a_successful_execution_emits_one_metric() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(adapter, make_request(), harness.context())

    assert len(sink.executions) == 1
    metric = sink.executions[0]
    assert metric.provider_id == "fake_aggregator"
    assert metric.status is ProviderRunStatus.SUCCESS
    assert metric.object_type is IntelObjectType.DOMAIN_NAME
    assert metric.attempts == 1
    assert metric.cache_hit is False
    assert metric.duration_ms >= 0.0
    assert len(sink.attempts) == 1


async def test_a_retry_emits_one_execution_and_several_attempts() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        ),
        ScriptedStep(),
    )

    await harness.executor.execute(adapter, make_request(), harness.context())

    assert len(sink.executions) == 1
    assert sink.executions[0].attempts == 2
    assert sink.executions[0].retry_count == 1
    assert len(sink.attempts) == 2
    assert sink.attempts[0].error_category is ProviderErrorCategory.TRANSIENT_ERROR
    assert sink.attempts[0].retried is True
    assert sink.attempts[1].succeeded is True
    assert sink.total_retries == 1


async def test_a_cache_hit_emits_a_metric_with_no_attempts() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()

    await harness.executor.execute(adapter, request, harness.context())
    await harness.executor.execute(adapter, request, harness.context())

    assert len(sink.executions) == 2
    assert sink.cache_hits == 1
    assert sink.executions[1].attempts == 0
    # No second physical call, so no second attempt metric.
    assert len(sink.attempts) == 1


async def test_a_cooldown_short_circuit_emits_a_metric() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "fake_aggregator")
        )
    )
    await harness.executor.execute(adapter, make_request(), harness.context())
    await harness.executor.execute(
        adapter,
        make_request(intel_object=make_object(value="other.example")),
        harness.context(),
    )

    assert len(sink.executions) == 2
    assert sink.cooldowns_applied == 2
    assert sink.executions[1].attempts == 0
    assert sink.executions[1].status is ProviderRunStatus.QUOTA_EXCEEDED


async def test_a_not_configured_execution_still_emits_a_metric() -> None:
    """A coverage gap is exactly the thing worth being able to count."""
    sink = InMemoryExecutionMetricsSink()
    harness = Harness()
    harness.executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        metrics=sink,
        clock=harness.clock,
        sleeper=harness.sleeper,
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(adapter, make_request(), harness.context())

    assert len(sink.executions) == 1
    assert sink.executions[0].status is ProviderRunStatus.NOT_CONFIGURED
    assert sink.executions[0].attempts == 0
    assert not sink.attempts


async def test_the_scope_digest_is_not_emitted_by_default() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(adapter, make_request(), harness.context())

    assert sink.executions[0].scope_digest is None


async def test_the_scope_digest_is_emitted_when_explicitly_enabled() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink, emit_scope_digest=True)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(adapter, make_request(), harness.context())

    digest = sink.executions[0].scope_digest
    assert digest is not None
    assert len(digest) == 16
    assert USER_A not in digest


async def test_emitted_metrics_contain_no_observable_value_or_secret() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = await executed_harness(sink=sink, emit_scope_digest=True)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(
        adapter,
        make_request(intel_object=make_object(value="very-distinctive-host.example")),
        harness.context(),
    )

    payload = json.dumps(
        [metric.model_dump(mode="json") for metric in sink.executions]
        + [metric.model_dump(mode="json") for metric in sink.attempts]
    )
    assert "very-distinctive-host.example" not in payload
    assert KEY_A not in payload
    assert USER_A not in payload
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_metrics_are_never_load_bearing() -> None:
    """An executor built without a sink still executes normally."""
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    executor = ProviderExecutor(credential_resolver=harness.resolver, clock=harness.clock)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await executor.execute(adapter, make_request(), harness.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
