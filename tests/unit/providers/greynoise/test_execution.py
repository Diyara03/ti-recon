"""GreyNoise running under the Task 6 ProviderExecutor (Task 9).

The point of these tests is that GreyNoise is not special. It goes through the
same cache, cooldown, quota and concurrency machinery every other provider does,
with no GreyNoise-shaped branch anywhere in the execution layer.

The GreyNoise-specific guarantee proved here is the important one: two accounts
do not see the same document for the same address, so nothing one analyst's key
fetched may ever be served to another.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.greynoise import payloads
from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
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
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.greynoise import (
    GreyNoiseAdapter,
    build_greynoise_execution_policy,
)

KEY_A = "greynoise-key-SHOULD-NOT-LEAK-12345"
KEY_B = "greynoise-key-BELONGS-TO-ANALYST-B-67890"
USER_A = "analyst-a"
USER_B = "analyst-b"
FULL = FakeGreyNoiseClient.FULL
COMMUNITY = FakeGreyNoiseClient.COMMUNITY


class Stack:
    """The whole platform, wired deterministically around a fake client."""

    def __init__(self, client: FakeGreyNoiseClient | None = None) -> None:
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
        self.policies = ProviderPolicyRegistry(policies=[build_greynoise_execution_policy()])
        self.client = client if client is not None else FakeGreyNoiseClient()
        self.factory = FakeGreyNoiseClientFactory(self.client)
        self.adapter = GreyNoiseAdapter(
            client_factory=self.factory,  # type: ignore[arg-type]
            clock=self.clock,
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
            provider_id="greynoise",
            secret=secret,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(payloads.SCANNER_IP).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.SCANNER_CONTEXT}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


@pytest.fixture
async def stack() -> Stack:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    return stack


# --------------------------------------------------------------------------- #
# The provider is chosen by capability, never by name
# --------------------------------------------------------------------------- #


def test_greynoise_is_discoverable_by_capability_with_no_vendor_branch(stack: Stack) -> None:
    matches = stack.registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["greynoise"]


# --------------------------------------------------------------------------- #
# Ordinary execution
# --------------------------------------------------------------------------- #


async def test_a_lookup_flows_through_the_executor(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.provider_id == "greynoise"
    assert outcome.attempts == 1
    assert outcome.cache_hit is False
    assert outcome.result is not None
    assert outcome.result.evidence


async def test_a_repeat_lookup_is_served_from_cache(stack: Stack) -> None:
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (first.attempts, first.cache_hit, first.called_provider) == (1, False, True)

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (second.attempts, second.cache_hit, second.called_provider) == (0, True, False)
    assert stack.client.call_count(FULL) == 1


async def test_an_unknown_address_is_cached_as_a_negative_answer(stack: Stack) -> None:
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NO_DATA

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.NO_DATA


async def test_a_trimmed_document_is_not_cached(stack: Stack) -> None:
    """A partial answer must never later be mistaken for a complete one."""
    stack.client.full_status = 206
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.PARTIAL

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is False


async def test_a_downgraded_community_answer_is_still_cacheable(stack: Stack) -> None:
    """Otherwise every free-tier analyst pays twice for the same answer."""
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.SUCCESS

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is True
    assert stack.client.call_count(COMMUNITY) == 1


async def test_different_depths_do_not_share_a_cache_entry(stack: Stack) -> None:
    """A QUICK answer is a smaller document; serving it for STANDARD would lie."""
    await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.QUICK), stack.context()
    )
    outcome = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.STANDARD), stack.context()
    )
    assert outcome.cache_hit is False


async def test_a_rate_limit_puts_this_analyst_on_cooldown(stack: Stack) -> None:
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "greynoise"))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.cooldown_applied is True


async def test_an_analyst_without_a_credential_gets_not_configured() -> None:
    stack = Stack()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0
    assert stack.client.calls == []


async def test_a_transient_failure_is_retried_then_reported(stack: Stack) -> None:
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "greynoise"))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.attempts > 1


# --------------------------------------------------------------------------- #
# Per-user isolation, end to end
# --------------------------------------------------------------------------- #


async def test_one_analysts_result_is_never_served_to_another(stack: Stack) -> None:
    """Two GreyNoise plans do not produce the same document for one address."""
    await stack.add_credential(USER_B, KEY_B)
    request = request_for()

    await stack.executor.execute(stack.adapter, request, stack.context(USER_A))
    second = await stack.executor.execute(stack.adapter, request, stack.context(USER_B))

    assert second.cache_hit is False
    assert stack.client.call_count(FULL) == 2


async def test_one_analysts_cooldown_does_not_affect_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, KEY_B)
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "greynoise"))
    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.cooldown_applied is True

    stack.client.errors.clear()
    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_one_analysts_access_level_is_never_applied_to_another(stack: Stack) -> None:
    """A free-tier analyst must not push a paid-tier colleague onto Community."""
    await stack.add_credential(USER_B, KEY_B)
    stack.client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert stack.client.call_count(FULL) == 1

    stack.client.errors.clear()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert stack.client.call_count(FULL) == 2
    assert outcome.status is ProviderRunStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Unsupported is not the same as empty
# --------------------------------------------------------------------------- #


async def test_an_ipv6_address_reaches_the_executor_as_not_supported(stack: Stack) -> None:
    """A blind spot must not arrive at the engine looking like a clean result."""
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(intel_object=normalize_observable("2001:db8::1").intel_object),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.status is not ProviderRunStatus.NO_DATA
    assert stack.client.calls == []


async def test_a_domain_reaches_the_executor_as_not_supported(stack: Stack) -> None:
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(intel_object=normalize_observable("example.com").intel_object),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.error_message is not None


async def test_an_unsupported_observable_is_not_cached_as_an_answer(stack: Stack) -> None:
    """Nothing was asked of GreyNoise, so there is no answer to keep."""
    request = request_for(intel_object=normalize_observable("example.com").intel_object)
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NOT_SUPPORTED
    assert second.cache_hit is False


# --------------------------------------------------------------------------- #
# Nothing carries a secret
# --------------------------------------------------------------------------- #


async def test_no_key_reaches_metrics_or_the_serialized_result(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None

    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    assert KEY_A not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized

    recorded = json.dumps(
        [metric.model_dump(mode="json") for metric in stack.metrics.executions]
        + [metric.model_dump(mode="json") for metric in stack.metrics.attempts],
        default=str,
    )
    assert KEY_A not in recorded
    assert "SHOULD-NOT-LEAK" not in recorded


def test_the_execution_policy_never_shares_results_between_analysts() -> None:
    assert build_greynoise_execution_policy().cache.scope.value == "user"
