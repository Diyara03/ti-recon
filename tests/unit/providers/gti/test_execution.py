"""GTI running under the Task 6 ProviderExecutor (Task 7).

The point of these tests is that GTI is not special. It goes through the same
cache, retry, cooldown, quota and concurrency machinery every future provider
will, with no GTI-shaped branch anywhere in the execution layer — and the
executor's guarantees (negative caching, secret redaction, per-user isolation)
hold for a real integration exactly as they did for the fakes.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    CooldownReason,
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
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.gti import GTIAdapter, build_gti_execution_policy

KEY_A = "vt-key-SHOULD-NOT-LEAK-12345"
KEY_B = "vt-key-BELONGS-TO-ANALYST-B-67890"
USER_A = "analyst-a"
USER_B = "analyst-b"
SHA256 = payloads.EMPTY_FILE_SHA256
TIMEOUT = 3.0


class Stack:
    """The whole platform, wired deterministically around a fake GTI client."""

    def __init__(self, client: FakeGTIClient | None = None) -> None:
        self.clock = ManualClock()
        self.sleeper = RecordingSleeper(self.clock)
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.cache = InMemoryProviderCache(clock=self.clock)
        self.quota = InMemoryQuotaStore(clock=self.clock)
        self.cooldowns = InMemoryCooldownStore(clock=self.clock)
        self.metrics = InMemoryExecutionMetricsSink()
        self.policies = ProviderPolicyRegistry(policies=[build_gti_execution_policy()])
        self.client = client if client is not None else loaded_client()
        self.factory = FakeGTIClientFactory(client=self.client)
        self.adapter = GTIAdapter(
            client_factory=self.factory, quota_store=self.quota, clock=self.clock
        )
        self.registry = ProviderRegistry([self.adapter])
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=self.quota,
            cooldown_store=self.cooldowns,
            limiter=ConcurrencyLimiter(max_concurrency=4),
            policies=self.policies,
            metrics=self.metrics,
            clock=self.clock,
            sleeper=self.sleeper,
            jitter=FixedJitter(0.0),
        )

    async def add_credential(self, user_id: str, secret: str) -> str:
        connection = await self.manager.create_connection(
            user_id=user_id,
            provider_id="gti",
            secret=secret,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def loaded_client() -> FakeGTIClient:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake.register_primary("files", payloads.file_object())
    fake.register_primary("domains", payloads.domain_object())
    return fake


def file_subject() -> IntelObject:
    return normalize_observable(SHA256).intel_object


def request_for(intel_object: IntelObject | None = None, **overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": intel_object if intel_object is not None else file_subject(),
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


@pytest.fixture
async def stack() -> Stack:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    return stack


# --------------------------------------------------------------------------- #
# Registry and capability discovery
# --------------------------------------------------------------------------- #


def test_gti_is_discoverable_by_capability_with_no_vendor_branch(stack: Stack) -> None:
    from ti_recon.enums import IntelObjectType

    matches = stack.registry.find_compatible(IntelObjectType.FILE, ProviderCapability.REPUTATION)
    assert [adapter.descriptor.provider_id for adapter in matches] == ["gti"]


# --------------------------------------------------------------------------- #
# Success and caching
# --------------------------------------------------------------------------- #


async def test_a_successful_lookup_flows_through_the_executor(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.provider_id == "gti"
    assert outcome.attempts == 1
    assert outcome.result is not None
    assert [e.claim_type for e in outcome.result.evidence if e.claim_type == "gti_assessment"]
    assert stack.client.call_count >= 1
    assert stack.factory.created_for == [KEY_A]


async def test_a_repeat_lookup_is_served_from_cache(stack: Stack) -> None:
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())
    calls_after_first = len(stack.client.operations("primary"))

    second = await stack.executor.execute(stack.adapter, request, stack.context())

    assert second.cache_hit is True
    assert second.attempts == 0
    assert len(stack.client.operations("primary")) == calls_after_first
    assert second.result is not None


async def test_a_cache_hit_reads_no_secret(stack: Stack) -> None:
    """Connection metadata is enough to scope a cache lookup."""
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())
    assert stack.factory.created_for == [KEY_A]

    await stack.executor.execute(stack.adapter, request, stack.context())
    assert stack.factory.created_for == [KEY_A]


async def test_a_cached_gti_result_expires_on_the_executor_ttl(stack: Stack) -> None:
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())
    policy = stack.policies.get("gti")

    stack.clock.advance(policy.cache.success_ttl_seconds + 1)
    third = await stack.executor.execute(stack.adapter, request, stack.context())

    assert third.cache_hit is False
    assert len(stack.client.operations("primary")) == 2


# --------------------------------------------------------------------------- #
# NO_DATA and negative caching
# --------------------------------------------------------------------------- #


async def test_an_unknown_hash_is_no_data_and_negatively_cached(stack: Stack) -> None:
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    request = request_for()

    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())

    assert first.status is ProviderRunStatus.NO_DATA
    assert second.cache_hit is True
    assert len(stack.client.operations("primary")) == 1


async def test_a_negative_result_expires_sooner_than_a_positive_one(
    stack: Stack,
) -> None:
    """What GTI has never seen is what changes when a sample first appears."""
    policy = stack.policies.get("gti")
    assert policy.cache.no_data_ttl_seconds < policy.cache.success_ttl_seconds

    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())

    stack.clock.advance(policy.cache.no_data_ttl_seconds + 1)
    again = await stack.executor.execute(stack.adapter, request, stack.context())
    assert again.cache_hit is False


async def test_no_data_never_becomes_benign(stack: Stack) -> None:
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NO_DATA
    assert "verdict" not in outcome.model_dump()
    assert outcome.has_data is False


# --------------------------------------------------------------------------- #
# Retry, rate limits and cooldowns — all owned by Task 6
# --------------------------------------------------------------------------- #


async def test_a_transient_gti_failure_is_retried_by_the_executor() -> None:
    class FlakyClient(FakeGTIClient):
        attempts: int = 0

        async def get_primary_object(self, **kwargs: Any) -> Any:  # type: ignore[override]
            self.attempts += 1
            if self.attempts == 1:
                raise provider_error_for(
                    ProviderErrorCategory.TRANSIENT_ERROR,
                    "gti",
                    operation="primary_lookup",
                )
            return await super().get_primary_object(**kwargs)

    client = FlakyClient(quota_payload=payloads.overall_quotas_payload())
    client.register_primary("files", payloads.file_object())
    stack = Stack(client)
    await stack.add_credential(USER_A, KEY_A)

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.attempts == 2
    assert stack.sleeper.slept == [0.5]


async def test_an_authentication_failure_is_not_retried(stack: Stack) -> None:
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.AUTHENTICATION_ERROR, "gti", operation="primary_lookup"
    )

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.status is ProviderRunStatus.ERROR
    assert outcome.attempts == 1
    assert stack.sleeper.slept == []


async def test_a_long_gti_rate_limit_becomes_a_cooldown_not_a_wait(
    stack: Stack,
) -> None:
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.RATE_LIMITED,
        "gti",
        operation="primary_lookup",
        retry_after_seconds=1800.0,
    )

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert stack.sleeper.total_slept == 0.0
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.RATE_LIMIT
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE


async def test_gti_quota_exhaustion_blocks_the_next_call(stack: Stack) -> None:
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.QUOTA_EXCEEDED, "gti", operation="primary_lookup"
    )

    first = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    calls = len(stack.client.operations("primary"))
    second = await stack.executor.execute(
        stack.adapter,
        request_for(normalize_observable("evil.example").intel_object),
        stack.context(),
    )

    assert first.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert second.attempts == 0
    assert len(stack.client.operations("primary")) == calls


async def test_a_reported_exhausted_quota_pre_empts_the_next_lookup() -> None:
    exhausted = payloads.overall_quotas_payload(daily_used=20_000, daily_allowed=20_000)
    client = FakeGTIClient(quota_payload=exhausted)
    client.register_primary("files", payloads.file_object())
    client.register_primary("domains", payloads.domain_object())
    stack = Stack(client)
    await stack.add_credential(USER_A, KEY_A)

    first = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert first.status is ProviderRunStatus.SUCCESS
    assert first.result is not None
    assert first.result.quota is not None

    second = await stack.executor.execute(
        stack.adapter,
        request_for(normalize_observable("evil.example").intel_object),
        stack.context(),
    )
    assert second.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert second.attempts == 0


async def test_the_adapter_makes_exactly_one_attempt_per_executor_attempt(
    stack: Stack,
) -> None:
    """No second retry subsystem inside the adapter."""
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.PROVIDER_UNAVAILABLE, "gti", operation="primary_lookup"
    )

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert len(stack.client.operations("primary")) == outcome.attempts


# --------------------------------------------------------------------------- #
# PARTIAL
# --------------------------------------------------------------------------- #


async def test_a_partial_gti_result_keeps_its_evidence_and_is_not_cached() -> None:
    payload = payloads.file_object()
    payload["attributes"]["gti_assessment"] = {"verdict": {"value": ["unreadable"]}}
    client = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    client.register_primary("files", payload)
    stack = Stack(client)
    await stack.add_credential(USER_A, KEY_A)
    request = request_for()

    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())

    assert first.status is ProviderRunStatus.PARTIAL
    assert first.result is not None
    # The reputation aggregate still parsed and survived.
    assert [e for e in first.result.evidence if e.claim_type == "gti_analysis_stats"]
    assert "GTI_ASSESSMENT_UNREADABLE" in first.result.warnings
    # A truncated answer must not later look like a complete one.
    assert second.cache_hit is False


async def test_a_missing_assessment_is_still_a_success() -> None:
    client = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    client.register_primary("files", payloads.file_object(with_assessment=False))
    stack = Stack(client)
    await stack.add_credential(USER_A, KEY_A)

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.result is not None
    assert "GTI_ASSESSMENT_UNAVAILABLE" in outcome.result.warnings
    assert [e for e in outcome.result.evidence if e.claim_type == "gti_analysis_stats"]


# --------------------------------------------------------------------------- #
# Per-user isolation, end to end
# --------------------------------------------------------------------------- #


async def test_one_analysts_gti_result_is_never_served_to_another(
    stack: Stack,
) -> None:
    await stack.add_credential(USER_B, KEY_B)
    request = request_for()

    await stack.executor.execute(stack.adapter, request, stack.context(USER_A))
    second = await stack.executor.execute(stack.adapter, request, stack.context(USER_B))

    assert second.cache_hit is False
    assert stack.factory.created_for == [KEY_A, KEY_B]


async def test_one_analysts_gti_cooldown_does_not_affect_another(
    stack: Stack,
) -> None:
    await stack.add_credential(USER_B, KEY_B)
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.QUOTA_EXCEEDED, "gti", operation="primary_lookup"
    )

    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.cooldown_applied is True

    stack.client.primary_errors.clear()
    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.attempts == 1
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_an_analyst_without_a_credential_gets_not_configured() -> None:
    stack = Stack()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0
    assert stack.client.calls == []
    assert stack.factory.created_for == []


# --------------------------------------------------------------------------- #
# Coalescing and concurrency
# --------------------------------------------------------------------------- #


async def test_identical_concurrent_gti_lookups_make_one_api_call(
    stack: Stack,
) -> None:
    """Eight callers, one request to Google — by coalescing, caching or both."""
    request = request_for()

    async def call() -> Any:
        return await stack.executor.execute(stack.adapter, request, stack.context())

    async with asyncio.timeout(TIMEOUT):
        outcomes = await asyncio.gather(*(call() for _ in range(8)))

    assert len(stack.client.operations("primary")) == 1
    spared = sum(1 for outcome in outcomes if outcome.coalesced or outcome.cache_hit)
    assert spared == 7
    assert all(o.status is ProviderRunStatus.SUCCESS for o in outcomes)


async def test_concurrent_lookups_that_genuinely_overlap_are_coalesced() -> None:
    """With a slow provider the followers ride along rather than re-asking."""

    class SlowClient(FakeGTIClient):
        release: asyncio.Event | None = None

        async def get_primary_object(self, **kwargs: Any) -> Any:  # type: ignore[override]
            if self.release is not None:
                await self.release.wait()
            return await super().get_primary_object(**kwargs)

    client = SlowClient(quota_payload=payloads.overall_quotas_payload())
    client.register_primary("files", payloads.file_object())
    client.release = asyncio.Event()
    stack = Stack(client)
    await stack.add_credential(USER_A, KEY_A)
    request = request_for()

    async def call() -> Any:
        return await stack.executor.execute(stack.adapter, request, stack.context())

    async with asyncio.timeout(TIMEOUT):
        tasks = [asyncio.create_task(call()) for _ in range(6)]
        await asyncio.sleep(0)
        client.release.set()
        outcomes = await asyncio.gather(*tasks)

    assert len(client.operations("primary")) == 1
    assert sum(1 for outcome in outcomes if outcome.coalesced) == 5


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


async def test_metrics_record_the_execution_without_the_ioc_or_the_key(
    stack: Stack,
) -> None:
    await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert len(stack.metrics.executions) == 1
    metric = stack.metrics.executions[0]
    assert metric.provider_id == "gti"
    assert metric.status is ProviderRunStatus.SUCCESS
    assert metric.attempts == 1

    payload = json.dumps(
        [m.model_dump(mode="json") for m in stack.metrics.executions]
        + [m.model_dump(mode="json") for m in stack.metrics.attempts]
    )
    assert KEY_A not in payload
    assert SHA256 not in payload
    assert "overall_quotas" not in payload


async def test_a_cache_hit_is_visible_in_metrics(stack: Stack) -> None:
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())
    await stack.executor.execute(stack.adapter, request, stack.context())
    assert stack.metrics.cache_hits == 1


# --------------------------------------------------------------------------- #
# Nothing leaks through the whole pipeline
# --------------------------------------------------------------------------- #


async def test_no_secret_survives_the_whole_execution_trail(stack: Stack) -> None:
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(depth=InvestigationDepth.DEEP),
        stack.context(),
    )
    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )

    trail = json.dumps(
        {
            "outcome": outcome.model_dump(mode="json"),
            "run": run.model_dump(mode="json"),
            "metrics": [m.model_dump(mode="json") for m in stack.metrics.executions],
        }
    )
    assert KEY_A not in trail
    lowered = trail.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_an_unsafe_provider_message_is_withheld_by_the_executor(
    stack: Stack,
) -> None:
    """Belt and braces: the executor sanitizes whatever reaches it."""
    stack.client.primary_errors[("files", SHA256)] = provider_error_for(
        ProviderErrorCategory.AUTHENTICATION_ERROR,
        "gti",
        operation="primary_lookup",
        message=f"apikey={KEY_A} rejected",
    )

    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())

    assert outcome.error_message is not None
    assert KEY_A not in outcome.error_message


async def test_the_outcome_records_as_a_task_3_provider_run(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    run = outcome.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.REPUTATION
    )
    assert run.provider == "gti"
    assert run.api_version == "v3"
    assert run.status is ProviderRunStatus.SUCCESS
    assert run.error_code is None
