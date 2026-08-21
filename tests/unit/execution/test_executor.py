"""Bounded provider executor (Task 6, step 5).

Uses scripted fake adapters throughout. No network, no wall clock, no sleeping.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import timedelta

import pytest

from fixtures.execution import deterministic_time, make_object, make_request
from fixtures.execution_adapters import (
    GreyNoiseLikeAdapter,
    ScriptedAdapter,
    ScriptedStep,
    UrlscanLikeAdapter,
    credential_free_descriptor,
    gti_like_descriptor,
)
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
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
    CacheScope,
    ConcurrencyLimiter,
    CooldownReason,
    ExecutionConfigurationError,
    ExecutionContext,
    ExecutionScope,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ProviderExecutionOutcome,
    ProviderExecutionPolicy,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RetryPolicy,
    make_cooldown,
)
from ti_recon.providers import (
    ProviderQuotaSnapshot,
    QuotaBucket,
    QuotaPeriod,
    RateLimitSnapshot,
    RateLimitWindow,
)
from ti_recon.providers.errors import provider_error_for

USER_A = "analyst-a"
USER_B = "analyst-b"
KEY_A = "aggregator-key-AAAA1111"
KEY_B = "aggregator-key-BBBB2222"
TIMEOUT = 3.0


class Harness:
    """The whole execution stack wired to deterministic, in-memory pieces."""

    def __init__(self, *, policy: ProviderExecutionPolicy | None = None) -> None:
        self.clock, self.sleeper = deterministic_time()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.cache = InMemoryProviderCache(clock=self.clock)
        self.quota = InMemoryQuotaStore(clock=self.clock)
        self.cooldowns = InMemoryCooldownStore(clock=self.clock)
        self.policies = ProviderPolicyRegistry(default=policy or ProviderExecutionPolicy())
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=self.quota,
            cooldown_store=self.cooldowns,
            policies=self.policies,
            clock=self.clock,
            sleeper=self.sleeper,
            jitter=FixedJitter(0.0),
        )

    async def add_credential(
        self, user_id: str, secret: str, provider_id: str = "fake_aggregator"
    ) -> str:
        connection = await self.manager.create_connection(
            user_id=user_id,
            provider_id=provider_id,
            secret=secret,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")

    def scope(self, connection_id: str, provider_id: str = "fake_aggregator") -> str:
        return ExecutionScope.for_user(
            provider_id=provider_id, user_id=USER_A, provider_connection_id=connection_id
        ).identity


@pytest.fixture
async def harness() -> Harness:
    stack = Harness()
    await stack.add_credential(USER_A, KEY_A)
    return stack


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #


async def test_a_successful_lookup_calls_the_provider_once(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 1
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.attempts == 1
    assert outcome.cache_hit is False
    assert outcome.result is not None
    assert len(outcome.result.evidence) == 1
    assert outcome.has_data is True
    assert outcome.duration_ms >= 0.0
    assert outcome.request_id == f"req-{USER_A}"


async def test_the_result_is_cached_and_the_second_call_is_free(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()

    first = await harness.executor.execute(adapter, request, harness.context())
    second = await harness.executor.execute(adapter, request, harness.context())

    assert adapter.calls == 1
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert second.attempts == 0
    assert second.status is ProviderRunStatus.SUCCESS
    assert second.result is not None


async def test_a_cache_hit_serves_a_different_investigation(harness: Harness) -> None:
    """The same question from a new investigation is still the same question."""
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    await harness.executor.execute(
        adapter, make_request(investigation_id="inv-1"), harness.context()
    )
    second = await harness.executor.execute(
        adapter, make_request(investigation_id="inv-2"), harness.context()
    )
    assert adapter.calls == 1
    assert second.cache_hit is True


async def test_a_cache_hit_preserves_the_provider_retrieval_time(
    harness: Harness,
) -> None:
    """Execution timings change on a hit; the provider's fact does not."""
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()
    first = await harness.executor.execute(adapter, request, harness.context())
    assert first.result is not None
    original = first.result.retrieved_at

    harness.clock.advance(120)
    second = await harness.executor.execute(adapter, request, harness.context())

    assert second.result is not None
    assert second.result.retrieved_at == original
    assert second.started_at > first.started_at


async def test_an_expired_cache_entry_causes_a_fresh_call(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()
    await harness.executor.execute(adapter, request, harness.context())

    harness.clock.advance(harness.policies.default.cache.success_ttl_seconds + 1)
    await harness.executor.execute(adapter, request, harness.context())

    assert adapter.calls == 2


async def test_a_cache_hit_never_reads_the_secret(harness: Harness) -> None:
    """Cache scope comes from connection metadata, so no secret is needed."""
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()
    await harness.executor.execute(adapter, request, harness.context())
    assert adapter.seen_credentials == [KEY_A]

    await harness.executor.execute(adapter, request, harness.context())
    # Still just the one credentialed call; the hit resolved no secret.
    assert adapter.seen_credentials == [KEY_A]


async def test_no_data_is_cached_with_the_shorter_negative_ttl(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(status=ProviderRunStatus.NO_DATA, with_evidence=False)
    )
    request = make_request()
    first = await harness.executor.execute(adapter, request, harness.context())
    assert first.status is ProviderRunStatus.NO_DATA
    assert first.has_data is False

    second = await harness.executor.execute(adapter, request, harness.context())
    assert second.cache_hit is True
    assert adapter.calls == 1

    harness.clock.advance(harness.policies.default.cache.no_data_ttl_seconds + 1)
    await harness.executor.execute(adapter, request, harness.context())
    assert adapter.calls == 2


async def test_no_data_is_not_a_benign_verdict(harness: Harness) -> None:
    """The execution layer has no notion of benign, and must not imply one."""
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(status=ProviderRunStatus.NO_DATA, with_evidence=False)
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert outcome.status is ProviderRunStatus.NO_DATA
    dumped = outcome.model_dump()
    assert {"verdict", "risk_score", "confidence", "benign"}.isdisjoint(dumped)


# --------------------------------------------------------------------------- #
# Isolation
# --------------------------------------------------------------------------- #


async def test_user_a_result_is_never_served_to_user_b(harness: Harness) -> None:
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()

    await harness.executor.execute(adapter, request, harness.context(USER_A))
    second = await harness.executor.execute(adapter, request, harness.context(USER_B))

    assert adapter.calls == 2
    assert second.cache_hit is False
    assert adapter.seen_credentials == [KEY_A, KEY_B]


async def test_each_user_gets_their_own_credential(harness: Harness) -> None:
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    await harness.executor.execute(adapter, make_request(), harness.context(USER_B))
    assert adapter.seen_credentials == [KEY_B]


async def test_scope_identity_distinguishes_users(harness: Harness) -> None:
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    first = await harness.executor.execute(adapter, make_request(), harness.context(USER_A))
    second = await harness.executor.execute(adapter, make_request(), harness.context(USER_B))
    assert first.scope_identity != second.scope_identity
    assert USER_A in first.scope_identity
    assert USER_B in second.scope_identity


# --------------------------------------------------------------------------- #
# Missing credential
# --------------------------------------------------------------------------- #


async def test_a_missing_credential_reports_not_configured_without_calling() -> None:
    harness = Harness()
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0
    assert outcome.result is None
    assert adapter.calls == 0


async def test_a_disabled_credential_reports_not_configured() -> None:
    harness = Harness()
    connection_id = await harness.add_credential(USER_A, KEY_A)
    await harness.manager.disable_connection(user_id=USER_A, connection_id=connection_id)

    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert adapter.calls == 0


async def test_a_credential_free_provider_needs_no_connection() -> None:
    harness = Harness()
    adapter = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=credential_free_descriptor())
    outcome = await harness.executor.execute(
        adapter,
        make_request(requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT})),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert adapter.seen_credentials == [None]


# --------------------------------------------------------------------------- #
# Unsupported requests
# --------------------------------------------------------------------------- #


async def test_an_unsupported_object_type_is_reported_not_called(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=credential_free_descriptor())
    outcome = await harness.executor.execute(
        adapter,
        make_request(
            intel_object=make_object(IntelObjectType.URL, "https://evil.example/a"),
            requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        ),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert adapter.calls == 0
    assert outcome.error_message is not None
    assert "url" in outcome.error_message


async def test_an_unsupported_capability_is_reported_not_called(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(
        adapter,
        make_request(requested_capabilities=frozenset({ProviderCapability.CERTIFICATE_CONTEXT})),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert adapter.calls == 0


async def test_an_active_request_to_a_passive_provider_is_refused(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.ACTIVE_ACTION,
            activity_mode=ActivityMode.ACTIVE,
            requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
        ),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert adapter.calls == 0


async def test_batch_operations_are_not_executed_by_this_layer(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(
        adapter, make_request(operation=ProviderOperation.BATCH_LOOKUP), harness.context()
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert adapter.calls == 0


async def test_a_pivot_is_dispatched_to_the_pivot_method(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert adapter.seen_operations == [ProviderOperation.PIVOT]


# --------------------------------------------------------------------------- #
# Retry
# --------------------------------------------------------------------------- #


async def test_a_transient_failure_is_retried_then_succeeds(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        ),
        ScriptedStep(),
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 2
    assert outcome.attempts == 2
    assert outcome.retry_count == 1
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert harness.sleeper.slept == [0.5]


async def test_an_authentication_error_is_not_retried(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 1
    assert outcome.attempts == 1
    assert outcome.status is ProviderRunStatus.ERROR
    assert outcome.error_category is ProviderErrorCategory.AUTHENTICATION_ERROR
    assert harness.sleeper.slept == []


async def test_a_plan_limitation_is_not_retried(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.PLAN_LIMITED, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 1
    assert outcome.status is ProviderRunStatus.PLAN_LIMITED
    assert harness.sleeper.slept == []


async def test_a_plan_limited_outcome_is_not_cached(harness: Harness) -> None:
    adapter = ScriptedAdapter(
        script=deque(
            [
                ScriptedStep(
                    error=provider_error_for(ProviderErrorCategory.PLAN_LIMITED, "fake_aggregator")
                ),
                ScriptedStep(),
            ]
        )
    )
    request = make_request()
    await harness.executor.execute(adapter, request, harness.context())
    second = await harness.executor.execute(adapter, request, harness.context())

    assert second.status is ProviderRunStatus.SUCCESS
    assert second.cache_hit is False
    assert adapter.calls == 2


async def test_retries_stop_at_the_policy_ceiling(harness: Harness) -> None:
    always_down = ScriptedStep(
        error=provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "fake_aggregator")
    )
    adapter = ScriptedAdapter.with_steps(always_down)
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 3
    assert outcome.attempts == 3
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert harness.sleeper.slept == [0.5, 1.0]


async def test_exhausted_retries_apply_a_short_cooldown(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.PROVIDER_UNAVAILABLE
    assert outcome.cooldown_until is not None

    # The next request short-circuits instead of paying the retry budget again.
    calls_before = adapter.calls
    again = await harness.executor.execute(adapter, make_request(), harness.context())
    assert adapter.calls == calls_before
    assert again.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert again.attempts == 0


async def test_a_non_provider_exception_is_normalized_by_the_adapter() -> None:
    """classify_error exists so the executor never reads a vendor exception."""
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)

    class Exploding(ScriptedAdapter):
        async def lookup(self, request, credential):  # type: ignore[no-untyped-def]
            self.calls += 1
            msg = "malformed payload"
            raise ValueError(msg)

    adapter = Exploding(_descriptor=gti_like_descriptor())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.error_category is ProviderErrorCategory.SCHEMA_ERROR
    assert outcome.status is ProviderRunStatus.ERROR
    assert adapter.calls == 1  # schema errors are never retried


async def test_an_adapter_attributing_a_result_elsewhere_is_a_schema_error() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)

    class Misattributing(ScriptedAdapter):
        async def lookup(self, request, credential):  # type: ignore[no-untyped-def]
            envelope = await super().lookup(request, credential)
            return envelope.model_copy(update={"provider": "someone_else"})

    adapter = Misattributing(_descriptor=gti_like_descriptor())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert outcome.error_category is ProviderErrorCategory.SCHEMA_ERROR


# --------------------------------------------------------------------------- #
# Rate limits and quota
# --------------------------------------------------------------------------- #


async def test_a_short_rate_limit_is_waited_out_inline(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                retry_after_seconds=2.0,
            )
        ),
        ScriptedStep(),
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 2
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert harness.sleeper.slept == [2.0]


async def test_a_long_rate_limit_becomes_a_cooldown_without_waiting(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                reset_at=harness.clock.now() + timedelta(hours=1),
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 1
    assert harness.sleeper.slept == []
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.RATE_LIMIT
    assert outcome.cooldown_until == harness.clock.now() + timedelta(hours=1)


async def test_a_rate_limit_cooldown_is_scoped_to_the_operation(
    harness: Harness,
) -> None:
    """A throttled action must not silence the rest of the integration."""
    adapter = UrlscanLikeAdapter()
    await harness.add_credential(USER_A, "web-key", provider_id="fake_websurface")

    pivot = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            intel_object=make_object(IntelObjectType.URL, "https://evil.example/a"),
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert pivot.cooldown_applied is True
    assert pivot.cooldown_reason is CooldownReason.RATE_LIMIT

    # The pivot action is now blocked...
    blocked = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            intel_object=make_object(IntelObjectType.URL, "https://other.example/a"),
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert blocked.attempts == 0
    assert blocked.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE

    # ...while the lookup action still runs.
    lookup = await harness.executor.execute(
        adapter,
        make_request(
            intel_object=make_object(IntelObjectType.URL, "https://evil.example/a"),
            requested_capabilities=frozenset({ProviderCapability.WEB_BEHAVIOR}),
        ),
        harness.context(),
    )
    assert lookup.status is ProviderRunStatus.SUCCESS
    assert lookup.attempts == 1


async def test_an_exhausted_rate_limit_window_on_a_success_sets_a_cooldown(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            rate_limit=RateLimitSnapshot(
                operation=ProviderOperation.LOOKUP.value,
                windows=(
                    RateLimitWindow(
                        window_name="minute", limit=4, remaining=0, reset_after_seconds=45.0
                    ),
                ),
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.cooldown_applied is True
    assert outcome.rate_limit_snapshot is not None
    assert outcome.rate_limit_snapshot.is_throttled is True


async def test_quota_exhaustion_is_not_retried_and_blocks_the_provider(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.QUOTA_EXCEEDED,
                "fake_aggregator",
                reset_at=harness.clock.now() + timedelta(hours=4),
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert adapter.calls == 1
    assert harness.sleeper.slept == []
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.cooldown_reason is CooldownReason.QUOTA_EXHAUSTED

    # Provider-wide: even a different operation is blocked.
    blocked = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.PIVOT,
            requested_capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        harness.context(),
    )
    assert blocked.attempts == 0
    assert blocked.status is ProviderRunStatus.QUOTA_EXCEEDED


async def test_reported_quota_is_stored_and_prevents_the_next_call(
    harness: Harness,
) -> None:
    exhausted = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(
            QuotaBucket(name="api_requests_daily", period=QuotaPeriod.DAY, allowed=10, used=10),
        ),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(quota=exhausted))
    first = await harness.executor.execute(adapter, make_request(), harness.context())

    assert first.status is ProviderRunStatus.SUCCESS
    assert first.quota_snapshot is not None
    assert first.quota_snapshot.is_exhausted is True

    calls_before = adapter.calls
    second = await harness.executor.execute(
        adapter,
        make_request(intel_object=make_object(value="other.example")),
        harness.context(),
    )
    assert adapter.calls == calls_before
    assert second.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert second.attempts == 0


async def test_a_healthy_quota_report_does_not_block(harness: Harness) -> None:
    healthy = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=1000, used=3),),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(quota=healthy))
    await harness.executor.execute(adapter, make_request(), harness.context())
    second = await harness.executor.execute(
        adapter,
        make_request(intel_object=make_object(value="other.example")),
        harness.context(),
    )
    assert second.status is ProviderRunStatus.SUCCESS


async def test_quota_state_does_not_leak_between_users(harness: Harness) -> None:
    await harness.add_credential(USER_B, KEY_B)
    exhausted = ProviderQuotaSnapshot(
        provider_id="fake_aggregator",
        user_id=USER_A,
        retrieved_at=harness.clock.now(),
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=1, used=1),),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(quota=exhausted))
    await harness.executor.execute(adapter, make_request(), harness.context(USER_A))

    outcome = await harness.executor.execute(adapter, make_request(), harness.context(USER_B))
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.attempts == 1


async def test_a_cooldown_does_not_leak_between_users(harness: Harness) -> None:
    await harness.add_credential(USER_B, KEY_B)
    connection_a = await harness.manager.find_connection_for_provider(
        user_id=USER_A, provider_id="fake_aggregator"
    )
    assert connection_a is not None
    await harness.cooldowns.set(
        make_cooldown(
            scope=ExecutionScope.for_user(
                provider_id="fake_aggregator",
                user_id=USER_A,
                provider_connection_id=connection_a.id,
            ),
            reason=CooldownReason.QUOTA_EXHAUSTED,
            seconds=3600,
            now=harness.clock.now(),
        )
    )

    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    blocked = await harness.executor.execute(adapter, make_request(), harness.context(USER_A))
    allowed = await harness.executor.execute(adapter, make_request(), harness.context(USER_B))

    assert blocked.attempts == 0
    assert allowed.attempts == 1


async def test_a_cooldown_lifts_on_the_clock(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.RATE_LIMITED,
                "fake_aggregator",
                retry_after_seconds=600.0,
            )
        ),
        ScriptedStep(),
    )
    first = await harness.executor.execute(adapter, make_request(), harness.context())
    assert first.cooldown_applied is True

    harness.clock.advance(601)
    second = await harness.executor.execute(adapter, make_request(), harness.context())
    assert second.status is ProviderRunStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Partial results
# --------------------------------------------------------------------------- #


async def test_a_partial_result_survives_and_is_not_retried() -> None:
    """Partial data often reflects a subscription's entitlements, not a failure."""
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
    assert outcome.attempts == 1
    assert adapter.calls == 1
    assert outcome.result is not None
    assert len(outcome.result.evidence) == 1
    assert outcome.result.evidence[0].claim_type == "scanner.classification"
    assert outcome.has_data is True


async def test_a_partial_result_is_not_cached_by_default() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "noise-key", provider_id="fake_scannoise")
    adapter = GreyNoiseLikeAdapter()
    request = make_request(
        intel_object=make_object(IntelObjectType.IPV4_ADDR, "198.51.100.7"),
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
    )

    await harness.executor.execute(adapter, request, harness.context())
    second = await harness.executor.execute(adapter, request, harness.context())

    assert adapter.calls == 2
    assert second.cache_hit is False


async def test_a_partial_result_can_be_cached_by_explicit_policy() -> None:
    harness = Harness(policy=ProviderExecutionPolicy(cache=CachePolicy(partial_ttl_seconds=60)))
    await harness.add_credential(USER_A, "noise-key", provider_id="fake_scannoise")
    adapter = GreyNoiseLikeAdapter()
    request = make_request(
        intel_object=make_object(IntelObjectType.IPV4_ADDR, "198.51.100.7"),
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
    )

    await harness.executor.execute(adapter, request, harness.context())
    second = await harness.executor.execute(adapter, request, harness.context())

    assert adapter.calls == 1
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.PARTIAL


# --------------------------------------------------------------------------- #
# Concurrency and coalescing
# --------------------------------------------------------------------------- #


async def test_identical_concurrent_requests_make_one_provider_call(
    harness: Harness,
) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()
    request = make_request()

    async def call() -> ProviderExecutionOutcome:
        return await harness.executor.execute(adapter, request, harness.context())

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call()) for _ in range(10)]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    assert adapter.calls == 1
    coalesced = [outcome.coalesced for outcome in outcomes]
    assert coalesced.count(True) == 9
    assert all(outcome.status is ProviderRunStatus.SUCCESS for outcome in outcomes)


async def test_different_observables_do_not_coalesce(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()

    async def call(value: str) -> ProviderExecutionOutcome:
        return await harness.executor.execute(
            adapter, make_request(intel_object=make_object(value=value)), harness.context()
        )

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call(f"host{index}.example")) for index in range(4)]
        await asyncio.sleep(0)
        adapter.release.set()
        await asyncio.gather(*tasks)

    assert adapter.calls == 4


async def test_different_request_options_do_not_coalesce(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()

    async def call(max_results: int) -> ProviderExecutionOutcome:
        return await harness.executor.execute(
            adapter, make_request(max_results=max_results), harness.context()
        )

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call(size)) for size in (10, 20, 30)]
        await asyncio.sleep(0)
        adapter.release.set()
        await asyncio.gather(*tasks)

    assert adapter.calls == 3


async def test_different_users_never_coalesce(harness: Harness) -> None:
    """Sharing one analyst's credentialed call with another is not an optimization."""
    await harness.add_credential(USER_B, KEY_B)
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))
    adapter.release = asyncio.Event()
    request = make_request()

    async def call(user_id: str) -> ProviderExecutionOutcome:
        return await harness.executor.execute(adapter, request, harness.context(user_id))

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call(USER_A)), asyncio.create_task(call(USER_B))]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    assert adapter.calls == 2
    assert all(not outcome.coalesced for outcome in outcomes)
    assert sorted(adapter.seen_credentials) == sorted([KEY_A, KEY_B])


async def test_concurrency_is_bounded_per_scope(harness: Harness) -> None:
    harness.policies.register(
        ProviderExecutionPolicy(provider_id="fake_aggregator", max_concurrency=2)
    )
    executor = ProviderExecutor(
        credential_resolver=harness.resolver,
        cache=harness.cache,
        cooldown_store=harness.cooldowns,
        limiter=ConcurrencyLimiter(max_concurrency=2),
        policies=harness.policies,
        clock=harness.clock,
        sleeper=harness.sleeper,
        jitter=FixedJitter(0.0),
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True))

    async def call(value: str) -> ProviderExecutionOutcome:
        return await executor.execute(
            adapter, make_request(intel_object=make_object(value=value)), harness.context()
        )

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(*(call(f"host{index}.example") for index in range(8)))

    assert adapter.calls == 8
    assert adapter.peak_concurrency <= 2


async def test_a_failing_leader_fails_every_coalesced_caller(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "fake_aggregator"),
            hold=True,
        )
    )
    adapter.release = asyncio.Event()
    request = make_request()

    async def call() -> ProviderExecutionOutcome:
        return await harness.executor.execute(adapter, request, harness.context())

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call()) for _ in range(5)]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    assert adapter.calls == 1
    assert all(
        outcome.error_category is ProviderErrorCategory.AUTHENTICATION_ERROR for outcome in outcomes
    )


async def test_active_requests_are_not_coalesced() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "active-key", provider_id="fake_active")
    active_descriptor = gti_like_descriptor("fake_active").model_copy(
        update={
            "capabilities": frozenset({ProviderCapability.ACTIVE_SCAN}),
            "supports_active": True,
        }
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(hold=True), descriptor=active_descriptor)
    adapter.release = asyncio.Event()
    request = make_request(
        operation=ProviderOperation.ACTIVE_ACTION,
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )

    async def call() -> ProviderExecutionOutcome:
        return await harness.executor.execute(adapter, request, harness.context())

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call()) for _ in range(3)]
        await asyncio.sleep(0)
        adapter.release.set()
        outcomes = await asyncio.gather(*tasks)

    # Three callers asking for a submission each want one to happen.
    assert adapter.calls == 3
    assert all(not outcome.coalesced for outcome in outcomes)


async def test_active_requests_are_not_cached() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "active-key", provider_id="fake_active")
    active_descriptor = gti_like_descriptor("fake_active").model_copy(
        update={
            "capabilities": frozenset({ProviderCapability.ACTIVE_SCAN}),
            "supports_active": True,
        }
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=active_descriptor)
    request = make_request(
        operation=ProviderOperation.ACTIVE_ACTION,
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )

    await harness.executor.execute(adapter, request, harness.context())
    second = await harness.executor.execute(adapter, request, harness.context())

    assert adapter.calls == 2
    assert second.cache_hit is False


async def test_an_active_request_is_never_retried() -> None:
    harness = Harness()
    await harness.add_credential(USER_A, "active-key", provider_id="fake_active")
    active_descriptor = gti_like_descriptor("fake_active").model_copy(
        update={
            "capabilities": frozenset({ProviderCapability.ACTIVE_SCAN}),
            "supports_active": True,
        }
    )
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_active")
        ),
        descriptor=active_descriptor,
    )
    outcome = await harness.executor.execute(
        adapter,
        make_request(
            operation=ProviderOperation.ACTIVE_ACTION,
            activity_mode=ActivityMode.ACTIVE,
            requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
        ),
        harness.context(),
    )
    assert adapter.calls == 1
    assert outcome.attempts == 1
    assert harness.sleeper.slept == []


# --------------------------------------------------------------------------- #
# Configuration safety
# --------------------------------------------------------------------------- #


async def test_a_global_cache_scope_is_refused_for_a_credentialed_provider(
    harness: Harness,
) -> None:
    """Sharing one analyst's credentialed results with everybody is a mistake."""
    harness.policies.register(
        ProviderExecutionPolicy(
            provider_id="fake_aggregator",
            cache=CachePolicy(scope=CacheScope.GLOBAL),
        )
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    with pytest.raises(ExecutionConfigurationError, match="global scope"):
        await harness.executor.execute(adapter, make_request(), harness.context())
    assert adapter.calls == 0


async def test_a_global_cache_scope_is_allowed_for_a_credential_free_provider() -> None:
    harness = Harness()
    harness.policies.register(
        ProviderExecutionPolicy(
            provider_id="fake_localwarninglist",
            cache=CachePolicy(scope=CacheScope.GLOBAL),
        )
    )
    adapter = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=credential_free_descriptor())
    request = make_request(
        requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT})
    )

    first = await harness.executor.execute(adapter, request, harness.context(USER_A))
    second = await harness.executor.execute(adapter, request, harness.context(USER_B))

    assert adapter.calls == 1
    assert second.cache_hit is True
    assert first.scope_identity.startswith("global|")


async def test_the_executor_works_without_optional_collaborators() -> None:
    """Cache, quota and cooldown stores are all optional."""
    harness = Harness()
    await harness.add_credential(USER_A, KEY_A)
    executor = ProviderExecutor(credential_resolver=harness.resolver, clock=harness.clock)
    adapter = ScriptedAdapter.with_steps(ScriptedStep())

    outcome = await executor.execute(adapter, make_request(), harness.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.cache_hit is False


async def test_policies_are_per_provider(harness: Harness) -> None:
    harness.policies.register(
        ProviderExecutionPolicy(provider_id="fake_aggregator", retry=RetryPolicy(max_attempts=1))
    )
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert adapter.calls == 1
    assert outcome.attempts == 1


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


async def test_the_serialized_outcome_carries_no_secret(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    payload = json.dumps(outcome.model_dump(mode="json"))
    assert KEY_A not in payload
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_an_error_outcome_carries_no_secret(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.AUTHENTICATION_ERROR,
                "fake_aggregator",
                message=f"rejected apikey={KEY_A}",
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    assert outcome.error_message is not None
    assert KEY_A not in outcome.error_message
    assert KEY_A not in json.dumps(outcome.model_dump(mode="json"))


async def test_a_message_that_cannot_be_made_safe_is_withheld(
    harness: Harness,
) -> None:
    """The redactor is best-effort; withholding is the guarantee behind it."""
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(
                ProviderErrorCategory.AUTHENTICATION_ERROR,
                "fake_aggregator",
                message="X-Api-Key aaaabbbbccccdddd was rejected",
            )
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    assert outcome.error_message == "provider detail withheld as unsafe to record"


async def test_the_cached_envelope_carries_no_secret(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()
    await harness.executor.execute(adapter, request, harness.context())
    outcome = await harness.executor.execute(adapter, request, harness.context())

    assert outcome.cache_hit is True
    assert outcome.result is not None
    assert KEY_A not in json.dumps(outcome.result.model_dump(mode="json"))


async def test_the_outcome_has_no_credential_field() -> None:
    from ti_recon.execution import ProviderExecutionOutcome
    from ti_recon.security import SENSITIVE_KEY_PATTERN

    for name in ProviderExecutionOutcome.model_fields:
        assert SENSITIVE_KEY_PATTERN.search(name) is None, name


# --------------------------------------------------------------------------- #
# Bridging back to Task 3
# --------------------------------------------------------------------------- #


async def test_an_outcome_records_as_a_provider_run(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())

    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )
    assert run.provider == "fake_aggregator"
    assert run.status is ProviderRunStatus.SUCCESS
    assert run.cache_hit is False
    assert run.adapter_version == "0.3.0"
    assert run.api_version == "v3"
    assert run.error_code is None
    assert run.raw_reference_id is not None


async def test_a_cache_hit_records_as_a_cached_provider_run(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(ScriptedStep())
    request = make_request()
    await harness.executor.execute(adapter, request, harness.context())
    outcome = await harness.executor.execute(adapter, request, harness.context())

    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )
    assert run.cache_hit is True


async def test_a_failed_outcome_records_its_error_category(harness: Harness) -> None:
    adapter = ScriptedAdapter.with_steps(
        ScriptedStep(
            error=provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "fake_aggregator")
        )
    )
    outcome = await harness.executor.execute(adapter, make_request(), harness.context())
    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )
    assert run.status is ProviderRunStatus.ERROR
    assert run.error_code is ProviderErrorCategory.AUTHENTICATION_ERROR
