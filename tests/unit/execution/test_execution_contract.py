"""Task 6 contract validation: the execution layer as a whole system.

Three families of test:

* **End-to-end** — one path through every layer that exists, asserting the
  layers actually hand off to each other rather than each working alone.
* **Provider scenarios** — deterministic fakes shaped after categories of real
  provider behaviour (a quota-metered aggregator, a provider with per-action
  limits, a provider returning subscription-limited partial data).
* **Security** — the isolation and non-leakage properties, gathered in one place
  so the guarantees are readable as a list.

No live provider, no network, no wall clock, no sleeping.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from fixtures.execution import make_object, make_request
from fixtures.execution_adapters import (
    GreyNoiseLikeAdapter,
    ScriptedAdapter,
    ScriptedStep,
    UrlscanLikeAdapter,
    credential_free_descriptor,
    gti_like_descriptor,
)
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    CachePolicy,
    ConcurrencyLimiter,
    CooldownReason,
    ExecutionScope,
    FixedJitter,
    InMemoryExecutionMetricsSink,
    ProviderExecutionOutcome,
    ProviderExecutionPolicy,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RetryPolicy,
    SingleFlight,
)
from ti_recon.providers import (
    ProviderQuotaSnapshot,
    QuotaBucket,
    QuotaPeriod,
    RateLimitSnapshot,
    RateLimitWindow,
)
from ti_recon.providers.errors import provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN
from unit.execution.test_executor import KEY_A, KEY_B, USER_A, USER_B, Harness

TIMEOUT = 3.0


# --------------------------------------------------------------------------- #
# End-to-end
# --------------------------------------------------------------------------- #


async def test_one_request_traverses_every_layer() -> None:
    """user -> credentials -> policy -> cooldown -> cache -> concurrency ->
    single-flight -> adapter -> retry -> limits -> metrics -> outcome."""
    sink = InMemoryExecutionMetricsSink()
    harness = Harness()
    connection_id = await harness.add_credential(USER_A, KEY_A)
    limiter = ConcurrencyLimiter(max_concurrency=2)
    flight = SingleFlight()
    executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        quota_store=harness.quota,
        cooldown_store=harness.cooldowns,
        limiter=limiter,
        single_flight=flight,
        policies=harness.policies,
        metrics=sink,
        clock=harness.clock,
        sleeper=harness.sleeper,
        jitter=FixedJitter(0.0),
    )

    quota = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(QuotaBucket(name="hourly", period=QuotaPeriod.HOUR, allowed=1000, used=1),),
    )
    adapter = ScriptedAdapter.with_steps(
        # One transient failure, then a success carrying limits and quota.
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        ),
        ScriptedStep(
            rate_limit=RateLimitSnapshot(
                operation=ProviderOperation.LOOKUP.value,
                windows=(RateLimitWindow(window_name="minute", limit=60, remaining=58),),
            ),
            quota=quota,
        ),
    )

    outcome = await executor.execute(adapter, make_request(), harness.context())

    # Credential layer: the right user's key reached the adapter.
    assert adapter.seen_credentials == [KEY_A, KEY_A]
    # Retry layer.
    assert outcome.attempts == 2
    assert outcome.retry_count == 1
    assert harness.sleeper.slept == [0.5]
    # Adapter result, preserved.
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.result is not None
    assert len(outcome.result.evidence) == 1
    # Limits layer.
    assert outcome.rate_limit_snapshot is not None
    assert outcome.quota_snapshot is not None
    assert await harness.quota.get(outcome.scope_identity) is not None
    # No cooldown, because nothing was exhausted.
    assert outcome.cooldown_applied is False
    # Scope layer: keyed on this user and this connection.
    assert outcome.scope_identity == harness.scope(connection_id)
    # Metrics layer.
    assert len(sink.executions) == 1
    assert len(sink.attempts) == 2
    assert sink.total_retries == 1
    # Coordination state released.
    assert limiter.tracked_scopes == 0
    assert flight.in_flight == 0
    # And the whole thing records as a Task 3 provider run.
    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )
    assert run.provider == "fake_aggregator"
    assert run.status is ProviderRunStatus.SUCCESS


async def test_a_second_identical_request_traverses_only_the_cache() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        quota_store=harness.quota,
        cooldown_store=harness.cooldowns,
        policies=harness.policies,
        metrics=sink,
        clock=harness.clock,
        sleeper=harness.sleeper,
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()

    await executor.execute(adapter, request, harness.context())
    second = await executor.execute(adapter, request, harness.context())

    assert adapter.calls == 1
    assert second.cache_hit is True
    assert second.attempts == 0
    assert len(sink.executions) == 2
    assert sink.cache_hits == 1
    # The cached path resolved no secret: still one credentialed call.
    assert adapter.seen_credentials == [KEY_A]


async def test_a_queued_duplicate_finds_the_leaders_cached_result() -> None:
    """With coalescing off, the post-slot cache re-check still saves the call."""
    harness = Harness(policy=ProviderExecutionPolicy(coalesce_requests=False, max_concurrency=1))
    await harness.add_credential(USER_A, KEY_A)
    executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        cooldown_store=harness.cooldowns,
        limiter=ConcurrencyLimiter(max_concurrency=1),
        policies=harness.policies,
        clock=harness.clock,
        sleeper=harness.sleeper,
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()
    request = make_request()

    async def call() -> ProviderExecutionOutcome:
        return await executor.execute(adapter, request, harness.context())

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call()) for _ in range(4)]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    assert adapter.calls == 1
    assert sum(1 for outcome in outcomes if outcome.cache_hit) == 3
    assert all(not outcome.coalesced for outcome in outcomes)


# --------------------------------------------------------------------------- #
# Scenario: a quota-metered aggregator
# --------------------------------------------------------------------------- #


async def test_quota_metadata_across_several_periods_is_recorded() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    quota = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(
            QuotaBucket(name="hourly", period=QuotaPeriod.HOUR, allowed=1000, used=250),
            QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=20_000, used=9_000),
            QuotaBucket(name="monthly", period=QuotaPeriod.MONTH, allowed=500_000, used=12_000),
        ),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(quota=quota))

    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.quota_snapshot is not None
    assert len(outcome.quota_snapshot.buckets) == 3
    assert outcome.quota_snapshot.is_exhausted is False
    assert outcome.cooldown_applied is False
    stored = await harness.quota.get(outcome.scope_identity)
    assert stored is not None
    hourly = stored.bucket("hourly")
    assert hourly is not None
    assert hourly.remaining == 750


async def test_known_exhausted_quota_prevents_the_call_with_no_cooldown() -> None:
    """A pre-known exhausted allowance is not worth a request to reconfirm."""
    harness = Harness()
    connection_id = await harness.add_credential(USER_A, KEY_A)
    scope = ExecutionScope.for_user(
        provider_id="fake_aggregator", user_id=USER_A, provider_connection_id=connection_id
    )
    await harness.quota.put(
        scope.identity,
        ProviderQuotaSnapshot(
            provider_id="fake_aggregator",
            user_id=USER_A,
            retrieved_at=harness.clock.now(),
            buckets=(
                QuotaBucket(
                    name="daily",
                    period=QuotaPeriod.DAY,
                    allowed=100,
                    used=100,
                    reset_at=harness.clock.now() + timedelta(hours=5),
                ),
            ),
        ),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 0
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.attempts == 0
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.QUOTA_EXHAUSTED
    assert outcome.quota_snapshot is not None


async def test_the_quota_precheck_can_be_disabled_by_policy() -> None:
    harness = Harness(policy=ProviderExecutionPolicy(quota_precheck=False))
    connection_id = await harness.add_credential(USER_A, KEY_A)
    scope = ExecutionScope.for_user(
        provider_id="fake_aggregator", user_id=USER_A, provider_connection_id=connection_id
    )
    await harness.quota.put(
        scope.identity,
        ProviderQuotaSnapshot(
            provider_id="fake_aggregator",
            user_id=USER_A,
            retrieved_at=harness.clock.now(),
            buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=1, used=1),),
        ),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert adapter.calls == 1
    assert outcome.status is ProviderRunStatus.SUCCESS


async def test_a_transient_aggregator_failure_recovers_within_the_budget() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        ),
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        ),
        ScriptedStep(),
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 3
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert harness.sleeper.slept == [0.5, 1.0]


# --------------------------------------------------------------------------- #
# Scenario: per-action rate limits
# --------------------------------------------------------------------------- #


async def test_an_action_specific_limit_does_not_block_other_actions() -> None:
    """The whole reason cooldowns are per operation rather than per provider."""
    harness = Harness()
    await harness.add_credential(USER_A, "web-key", provider_id="fake_websurface")
    adapter = UrlscanLikeAdapter(exhausted_reset_at=harness.clock.now() + timedelta(minutes=10))
    url_object = make_object(IntelObjectType.URL, "https://evil.example/a")

    pivot = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            intel_object=url_object,
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert pivot.status is ProviderRunStatus.SUCCESS
    assert pivot.cooldown_applied is True
    assert pivot.rate_limit_snapshot is not None
    exhausted = pivot.rate_limit_snapshot.exhausted_windows
    assert [window.window_name for window in exhausted] == ["minute"]

    scope_identity = pivot.scope_identity
    entries = await harness.cooldowns.entries(scope_identity=scope_identity)
    assert [entry.operation for entry in entries] == ["pivot"]

    # The limited action is blocked...
    blocked = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            intel_object=make_object(IntelObjectType.URL, "https://other.example/b"),
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert blocked.attempts == 0
    assert blocked.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE

    # ...and the unrelated action still works.
    lookup = await harness.executor.execute(
        adapter,
        make_request(
            intel_object=url_object,
            requested_capabilities=frozenset({ProviderCapability.WEB_BEHAVIOR}),
        ),
        harness.context(),
    )
    assert lookup.status is ProviderRunStatus.SUCCESS
    assert lookup.attempts == 1
    assert lookup.cooldown_applied is False


async def test_a_429_with_reset_metadata_never_sleeps_for_long() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                retry_after_seconds=1800.0,
                provider_error_code="RATE_LIMIT_EXCEEDED",
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert harness.sleeper.total_slept == 0.0
    assert outcome.cooldown_reason is CooldownReason.RATE_LIMIT
    assert outcome.cooldown_until == harness.clock.now() + timedelta(seconds=1800)
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE


async def test_an_action_cooldown_lifts_and_the_action_resumes() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                retry_after_seconds=300.0,
            )
        ),
        ScriptedStep(),
    )
    await harness.executor.execute(adapter, make_request(), harness.context())
    harness.clock.advance(301)
    resumed = await harness.executor.execute(adapter, make_request(), harness.context())
    assert resumed.status is ProviderRunStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Scenario: subscription-limited partial results
# --------------------------------------------------------------------------- #


async def test_partial_evidence_survives_and_is_never_retried() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "noise-key", provider_id="fake_scannoise")
    adapter = GreyNoiseLikeAdapter()

    outcome = await harness.executor.execute(
        adapter,
        make_request(
            intel_object=make_object(IntelObjectType.IPV4_ADDR, "198.51.100.7"),
            requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
        ),
        harness.context(),
    )

    assert outcome.status is ProviderRunStatus.PARTIAL
    assert adapter.calls == 1
    assert outcome.attempts == 1
    assert harness.sleeper.slept == []
    assert outcome.result is not None
    evidence = outcome.result.evidence
    assert len(evidence) == 1
    assert evidence[0].attributes["fields_withheld"] is True
    assert outcome.result.warnings == ("subscription returns a subset of fields",)
    # And it records as a partial provider run rather than a failure.
    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.SCANNER_CONTEXT
    )
    assert run.status is ProviderRunStatus.PARTIAL
    assert run.error_code is None


async def test_a_partial_result_error_is_also_not_retried() -> None:
    """Whether reported as an envelope or raised, PARTIAL is not a retry signal."""
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.PARTIAL_RESULT, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert adapter.calls == 1
    assert outcome.status is ProviderRunStatus.PARTIAL
    assert harness.sleeper.slept == []


# --------------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------------- #


async def test_user_a_cache_is_not_readable_by_user_b() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()

    await harness.executor.execute(adapter, request, harness.context(USER_A))
    outcome_b = await harness.executor.execute(adapter, request, harness.context(USER_B))

    assert outcome_b.cache_hit is False
    assert adapter.calls == 2


async def test_user_a_quota_state_does_not_affect_user_b() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    await harness.add_credential(USER_B, KEY_B)
    exhausted = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=1, used=1),),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(quota=exhausted))

    await harness.executor.execute(adapter, make_request(), harness.context(USER_A))
    outcome_b = await harness.executor.execute(adapter, make_request(), harness.context(USER_B))
    assert outcome_b.status is ProviderRunStatus.SUCCESS
    assert outcome_b.attempts == 1


async def test_user_a_cooldown_does_not_affect_user_b() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "fake_aggregator")
        ),
        ScriptedStep(),
    )
    blocked_user = await harness.executor.execute(adapter, make_request(), harness.context(USER_A))
    assert blocked_user.cooldown_applied is True

    other_user = await harness.executor.execute(adapter, make_request(), harness.context(USER_B))
    assert other_user.attempts == 1
    assert other_user.status is ProviderRunStatus.SUCCESS


async def test_user_a_single_flight_does_not_merge_with_user_b() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()
    request = make_request()

    async def call(user_id: str) -> ProviderExecutionOutcome:
        return await harness.executor.execute(adapter, request, harness.context(user_id))

    async with asyncio.timeout(TIMEOUT):
        tasks = [
            asyncio.create_task(call(USER_A)),
            asyncio.create_task(call(USER_A)),
            asyncio.create_task(call(USER_B)),
            asyncio.create_task(call(USER_B)),
        ]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    # One call per user, not one call in total.
    assert adapter.calls == 2
    assert sorted(set(adapter.seen_credentials)) == sorted([KEY_A, KEY_B])
    assert sum(1 for outcome in outcomes if outcome.coalesced) == 2


async def test_no_secret_reaches_the_cache_key() -> None:
    harness = Harness()
    connection_id = await harness.add_credential(USER_A, KEY_A)
    from ti_recon.execution import build_cache_key

    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id="fake_aggregator",
            user_id=USER_A,
            provider_connection_id=connection_id,
        ),
        descriptor=gti_like_descriptor(),
        request=make_request(),
    )
    assert KEY_A not in key.storage_key
    assert KEY_A not in str(key)
    assert SENSITIVE_KEY_PATTERN.search(key.storage_key) is None


async def test_no_secret_reaches_the_outcome_the_metrics_or_the_cooldowns() -> None:
    sink = InMemoryExecutionMetricsSink()
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        quota_store=harness.quota,
        cooldown_store=harness.cooldowns,
        policies=harness.policies,
        metrics=sink,
        clock=harness.clock,
        sleeper=harness.sleeper,
        emit_scope_digest=True,
    )
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                message=f"throttled for apikey={KEY_A}",
                retry_after_seconds=3600.0,
            )
        )
    )
    outcome = await executor.execute(adapter, make_request(), harness.context())

    everything = json.dumps(
        {
            "outcome": outcome.model_dump(mode="json"),
            "metrics": [metric.model_dump(mode="json") for metric in sink.executions],
            "attempts": [metric.model_dump(mode="json") for metric in sink.attempts],
            "cooldowns": [
                entry.model_dump(mode="json")
                for entry in await harness.cooldowns.entries(scope_identity=outcome.scope_identity)
            ],
        }
    )
    assert KEY_A not in everything
    lowered = everything.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_no_secret_survives_exception_rendering() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.AUTHENTICATION_ERROR,
                "fake_aggregator",
                message=f"Authorization: Bearer {KEY_A} rejected",
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert outcome.error_message is not None
    assert KEY_A not in outcome.error_message


async def test_the_execution_layer_adds_no_arbitrary_url_fetching() -> None:
    """The SSRF boundary from Task 5 must not be widened by this layer."""
    import ti_recon.execution as execution_package

    forbidden = ("fetch", "fetch_url", "fetch_arbitrary_url", "open_url", "browse", "get_url")
    for name in execution_package.__all__:
        assert name not in forbidden

    for module_name in (
        "cache",
        "clock",
        "coordination",
        "executor",
        "limits",
        "metrics",
        "models",
        "policy",
        "retry",
    ):
        module = __import__(f"ti_recon.execution.{module_name}", fromlist=["x"])
        source = inspect.getsource(module)
        # No HTTP client is constructed or imported anywhere in this layer.
        assert "httpx" not in source
        assert "AsyncClient" not in source
        for token in forbidden:
            assert f"def {token}" not in source


async def test_the_execution_layer_names_no_real_provider() -> None:
    """Task 6 must stay provider-neutral."""
    for module_name in (
        "cache",
        "clock",
        "coordination",
        "executor",
        "limits",
        "metrics",
        "models",
        "policy",
        "retry",
    ):
        module = __import__(f"ti_recon.execution.{module_name}", fromlist=["x"])
        source = inspect.getsource(module).lower()
        for vendor in (
            "virustotal",
            "gti",
            "urlscan",
            "greynoise",
            "censys",
            "threatfox",
            "urlhaus",
            "malwarebazaar",
            "shodan",
            "abuseipdb",
            "securitytrails",
            "ipinfo",
        ):
            assert vendor not in source, f"{module_name} mentions {vendor}"


async def test_the_execution_layer_reacts_to_categories_not_status_codes() -> None:
    """Provider HTTP interpretation belongs to adapters."""
    for module_name in ("executor", "retry", "limits"):
        module = __import__(f"ti_recon.execution.{module_name}", fromlist=["x"])
        source = inspect.getsource(module)
        for code in ("== 403", "== 429", "== 404", "== 401", "status_code =="):
            assert code not in source


async def test_the_execution_layer_computes_no_verdict() -> None:
    fields = set(ProviderExecutionOutcome.model_fields)
    assert fields.isdisjoint(
        {"verdict", "risk_score", "confidence", "score", "malicious", "assessment"}
    )
    for name, _ in inspect.getmembers(ProviderExecutor, inspect.isfunction):
        assert name not in {"assess", "verdict", "score", "decide_verdict", "risk"}


async def test_an_active_operation_is_neither_cached_nor_retried_nor_coalesced() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "active-key", provider_id="fake_active")
    descriptor = gti_like_descriptor("fake_active").model_copy(
        update={
            "capabilities": frozenset({ProviderCapability.ACTIVE_SCAN}),
            "supports_active": True,
        }
    )
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_active")
        ),
        ScriptedStep(),
        descriptor=descriptor,
    )
    request = make_request(
        operation=ProviderOperation.ACTIVE_ACTION,
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )

    first = await harness.executor.execute(adapter, request, harness.context())
    assert first.attempts == 1  # not retried
    assert harness.sleeper.slept == []

    second = await harness.executor.execute(adapter, request, harness.context())
    assert second.cache_hit is False  # not cached
    assert adapter.calls == 2


# --------------------------------------------------------------------------- #
# Outcome and policy contracts
# --------------------------------------------------------------------------- #


def outcome_kwargs(**overrides: object) -> dict[str, object]:
    from ti_recon.models.base import utc_now

    now = utc_now()
    kwargs: dict[str, object] = {
        "provider_id": "fake_aggregator",
        "operation": ProviderOperation.LOOKUP,
        "status": ProviderRunStatus.NO_DATA,
        "request_id": "req-1",
        "scope_identity": "user|analyst-a|fake_aggregator|conn-a",
        "started_at": now,
        "completed_at": now,
        "duration_ms": 1.0,
    }
    kwargs.update(overrides)
    return kwargs


def test_an_outcome_rejects_an_inverted_timeline() -> None:
    from ti_recon.models.base import utc_now

    now = utc_now()
    with pytest.raises(ValidationError, match="must not precede started_at"):
        ProviderExecutionOutcome(
            **outcome_kwargs(started_at=now, completed_at=now - timedelta(seconds=1))
        )


def test_success_requires_a_result() -> None:
    with pytest.raises(ValidationError, match="must carry a provider result"):
        ProviderExecutionOutcome(**outcome_kwargs(status=ProviderRunStatus.SUCCESS))


def test_partial_may_arrive_without_a_result() -> None:
    """An adapter may raise PARTIAL_RESULT rather than build a reduced envelope."""
    outcome = ProviderExecutionOutcome(
        **outcome_kwargs(
            status=ProviderRunStatus.PARTIAL,
            error_category=ProviderErrorCategory.PARTIAL_RESULT,
        )
    )
    assert outcome.result is None
    assert outcome.has_data is False


def test_no_data_needs_no_result() -> None:
    """A normalized 'not found' is a legitimate answer with no envelope."""
    outcome = ProviderExecutionOutcome(**outcome_kwargs(status=ProviderRunStatus.NO_DATA))
    assert outcome.result is None
    assert outcome.has_data is False


def test_an_outcome_status_must_match_the_result_it_carries() -> None:
    from fixtures.execution import make_envelope

    with pytest.raises(ValidationError, match="must match the provider result"):
        ProviderExecutionOutcome(
            **outcome_kwargs(
                status=ProviderRunStatus.PARTIAL,
                result=make_envelope(status=ProviderRunStatus.SUCCESS),
            )
        )


def test_a_failed_outcome_must_carry_a_category() -> None:
    with pytest.raises(ValidationError, match="normalized error category"):
        ProviderExecutionOutcome(**outcome_kwargs(status=ProviderRunStatus.ERROR))


def test_an_applied_cooldown_must_say_when_and_why() -> None:
    from ti_recon.models.base import utc_now

    with pytest.raises(ValidationError, match="when it lifts"):
        ProviderExecutionOutcome(**outcome_kwargs(cooldown_applied=True))
    with pytest.raises(ValidationError, match="must record why"):
        ProviderExecutionOutcome(
            **outcome_kwargs(cooldown_applied=True, cooldown_until=utc_now() + timedelta(minutes=5))
        )


def test_a_cache_hit_must_not_report_provider_attempts() -> None:
    with pytest.raises(ValidationError, match="must not report provider attempts"):
        ProviderExecutionOutcome(**outcome_kwargs(cache_hit=True, attempts=1))


def test_an_outcome_error_message_may_not_mention_credential_material() -> None:
    with pytest.raises(ValidationError, match="must not mention credential material"):
        ProviderExecutionOutcome(
            **outcome_kwargs(
                status=ProviderRunStatus.ERROR,
                error_category=ProviderErrorCategory.AUTHENTICATION_ERROR,
                error_message="rejected api_key=abc",
            )
        )


def test_the_policy_registry_falls_back_to_its_default() -> None:
    default = ProviderExecutionPolicy(retry=RetryPolicy(max_attempts=1))
    registry = ProviderPolicyRegistry(default=default)
    assert registry.get("anything") is default
    assert registry.default is default
    assert len(registry) == 0
    assert "anything" not in registry


def test_the_policy_registry_accepts_policies_at_construction() -> None:
    specific = ProviderExecutionPolicy(
        provider_id="fake_aggregator", cache=CachePolicy(success_ttl_seconds=60)
    )
    registry = ProviderPolicyRegistry(policies=[specific])
    assert registry.get("fake_aggregator") is specific
    assert registry.get("other") is not specific
    assert "fake_aggregator" in registry
    assert len(registry) == 1
    assert "fake_aggregator" in repr(registry)


def test_a_registered_policy_must_name_its_provider() -> None:
    with pytest.raises(ValueError, match="must name the provider"):
        ProviderPolicyRegistry().register(ProviderExecutionPolicy())


def test_a_cache_key_renders_as_its_storage_key() -> None:
    from ti_recon.execution import build_cache_key

    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id="fake_aggregator", user_id=USER_A, provider_connection_id="conn-a"
        ),
        descriptor=gti_like_descriptor(),
        request=make_request(),
    )
    assert str(key) == key.storage_key
    assert key.storage_key.startswith("v1|user|")


async def test_a_passive_request_to_an_active_only_provider_is_refused() -> None:
    """The provider offers the capability, but only actively."""
    harness = Harness()
    descriptor = credential_free_descriptor().model_copy(
        update={
            "capabilities": frozenset(
                {
                    ProviderCapability.ACTIVE_SCAN,
                    ProviderCapability.FALSE_POSITIVE_CONTEXT,
                }
            ),
            "supports_active": True,
            "supports_passive": False,
        }
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=descriptor)
    outcome = await harness.executor.execute(
        adapter,
        make_request(requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT})),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.error_message == "provider does not support passive operations"
    assert adapter.calls == 0


async def test_an_active_request_to_a_passive_only_provider_is_refused() -> None:
    """The provider offers the capability, but only passively."""
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.ACTIVE_ACTION,
            activity_mode=ActivityMode.ACTIVE,
            requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.error_message == "provider does not support active operations"
    assert adapter.calls == 0


def test_an_outcome_reports_whether_it_cost_a_provider_request() -> None:
    assert ProviderExecutionOutcome(**outcome_kwargs(attempts=2)).called_provider is True
    hit = ProviderExecutionOutcome(**outcome_kwargs(attempts=0, cache_hit=True))
    assert hit.called_provider is False
