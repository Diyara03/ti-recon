"""Censys running under the Task 6 ProviderExecutor (Task 9).

The point of these tests is that Censys is not special. It goes through the same
cache, cooldown, quota and concurrency machinery every other provider does, with
no Censys-shaped branch anywhere in the execution layer.

Two Censys-specific guarantees are proved here. Every asset read costs a credit,
so the cache is not a convenience — a repeat lookup that hits it is the
difference between one credit and two. And a spent balance stops the provider
being called at all, because no amount of waiting refills a wallet.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.censys import payloads
from fixtures.censys.fake_client import FakeCensysClient, FakeCensysClientFactory
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
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.providers.censys import (
    ORGANIZATION_METADATA_KEY,
    CensysAdapter,
    ConnectionOrganizationDirectory,
    build_censys_execution_policy,
)
from ti_recon.providers.errors import provider_error_for

TOKEN_A = "censys-pat-SHOULD-NOT-LEAK-12345"
TOKEN_B = "censys-pat-BELONGS-TO-ANALYST-B-67890"
USER_A = "analyst-a"
USER_B = "analyst-b"
HOST = FakeCensysClient.HOST
USER_CREDITS = FakeCensysClient.USER_CREDITS
ORGANIZATION_CREDITS = FakeCensysClient.ORGANIZATION_CREDITS


class Stack:
    """The whole platform, wired deterministically around a fake client."""

    def __init__(self, client: FakeCensysClient | None = None) -> None:
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
        self.policies = ProviderPolicyRegistry(policies=[build_censys_execution_policy()])
        self.client = client if client is not None else FakeCensysClient()
        self.factory = FakeCensysClientFactory(self.client)
        self.adapter = CensysAdapter(
            client_factory=self.factory,  # type: ignore[arg-type]
            organizations=ConnectionOrganizationDirectory(self.connections),
            quota_store=self.quota,
            clock=self.clock,
        )
        self.registry = ProviderRegistry([self.adapter])
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=self.quota,
            cooldown_store=self.cooldowns,
            limiter=ConcurrencyLimiter(max_concurrency=1),
            policies=self.policies,
            metrics=self.metrics,
            clock=self.clock,
            sleeper=self.sleeper,
            jitter=FixedJitter(0.0),
        )

    async def add_credential(
        self, user_id: str, secret: str, *, organization_id: str | None = None
    ) -> str:
        metadata = (
            {ORGANIZATION_METADATA_KEY: organization_id} if organization_id is not None else {}
        )
        connection = await self.manager.create_connection(
            user_id=user_id,
            provider_id="censys",
            secret=secret,
            auth_type=AuthType.BEARER_TOKEN,
            metadata=metadata,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(payloads.HOST_IP).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.CURRENT_INFRASTRUCTURE}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


@pytest.fixture
async def stack() -> Stack:
    stack = Stack()
    await stack.add_credential(USER_A, TOKEN_A)
    return stack


# --------------------------------------------------------------------------- #
# The provider is chosen by capability, never by name
# --------------------------------------------------------------------------- #


def test_censys_is_discoverable_by_capability_with_no_vendor_branch(stack: Stack) -> None:
    matches = stack.registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.CURRENT_INFRASTRUCTURE
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["censys"]


def test_censys_is_never_selected_for_a_reputation_question(stack: Stack) -> None:
    assert (
        stack.registry.find_compatible(IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION)
        == ()
    )


# --------------------------------------------------------------------------- #
# Ordinary execution
# --------------------------------------------------------------------------- #


async def test_a_lookup_flows_through_the_executor(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.provider_id == "censys"
    assert outcome.attempts == 1
    assert outcome.cache_hit is False
    assert outcome.result is not None
    assert outcome.result.evidence


async def test_a_repeat_lookup_costs_no_second_credit(stack: Stack) -> None:
    """The cache is not a convenience here; it is one credit rather than two."""
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (first.attempts, first.cache_hit, first.called_provider) == (1, False, True)

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (second.attempts, second.cache_hit, second.called_provider) == (0, True, False)
    assert stack.client.call_count(HOST) == 1


async def test_an_unscanned_asset_is_cached_as_a_negative_answer() -> None:
    stack = Stack(FakeCensysClient(hosts={}))
    await stack.add_credential(USER_A, TOKEN_A)
    request = request_for()

    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NO_DATA

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.NO_DATA


async def test_a_partial_document_is_not_cached() -> None:
    stack = Stack(FakeCensysClient(hosts={payloads.HOST_IP: {"unexpected": "shape"}}))
    await stack.add_credential(USER_A, TOKEN_A)
    request = request_for()

    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.PARTIAL

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is False


async def test_different_depths_do_not_share_a_cache_entry(stack: Stack) -> None:
    """A QUICK answer keeps less of the document; serving it for DEEP would lie."""
    await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.QUICK), stack.context()
    )
    outcome = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.DEEP), stack.context()
    )
    assert outcome.cache_hit is False


async def test_an_analyst_without_a_credential_gets_not_configured() -> None:
    stack = Stack()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0
    assert stack.client.calls == []


async def test_a_transient_failure_is_retried_then_reported(stack: Stack) -> None:
    stack.client.fail(HOST, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "censys"))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.attempts > 1


# --------------------------------------------------------------------------- #
# Credits and rate limits are different resources
# --------------------------------------------------------------------------- #


async def test_a_throttled_minute_is_a_cooldown_that_lifts(stack: Stack) -> None:
    """Reported as temporary, with a rate-limit cooldown rather than a quota one."""
    stack.client.fail(HOST, provider_error_for(ProviderErrorCategory.RATE_LIMITED, "censys"))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.RATE_LIMIT
    assert outcome.cooldown_reason is not CooldownReason.QUOTA_EXHAUSTED


async def test_a_throttled_minute_censys_dated_is_waited_out_inline(stack: Stack) -> None:
    """When Censys says how long, the executor waits rather than giving up."""
    stack.client.fail(
        HOST,
        provider_error_for(ProviderErrorCategory.RATE_LIMITED, "censys", retry_after_seconds=1.0),
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.attempts > 1
    assert stack.sleeper.total_slept > 0


async def test_a_spent_balance_stops_the_provider_being_called_at_all() -> None:
    """Retrying against an empty wallet is a wasted request, every time."""
    stack = Stack(FakeCensysClient(user_credits=payloads.user_credits_payload(remaining=0)))
    await stack.add_credential(USER_A, TOKEN_A)

    first = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert first.status is ProviderRunStatus.SUCCESS
    assert stack.client.call_count(HOST) == 1

    second = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.DEEP), stack.context()
    )
    assert second.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert second.attempts == 0
    assert stack.client.call_count(HOST) == 1


async def test_a_spent_balance_is_reported_as_quota_rather_than_a_rate_limit(
    stack: Stack,
) -> None:
    """Never retried: every retry against an empty wallet is a wasted request."""
    stack.client.fail(HOST, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "censys"))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.attempts == 1
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.QUOTA_EXHAUSTED


# --------------------------------------------------------------------------- #
# Per-user and per-organization isolation, end to end
# --------------------------------------------------------------------------- #


async def test_one_analysts_result_is_never_served_to_another(stack: Stack) -> None:
    """A lookup is charged to whichever account's token paid for it."""
    await stack.add_credential(USER_B, TOKEN_B)
    request = request_for()

    await stack.executor.execute(stack.adapter, request, stack.context(USER_A))
    second = await stack.executor.execute(stack.adapter, request, stack.context(USER_B))

    assert second.cache_hit is False
    assert stack.client.call_count(HOST) == 2


async def test_one_analysts_spent_wallet_does_not_block_another() -> None:
    stack = Stack(FakeCensysClient(user_credits=payloads.user_credits_payload(remaining=0)))
    await stack.add_credential(USER_A, TOKEN_A)
    await stack.add_credential(USER_B, TOKEN_B)

    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.status is ProviderRunStatus.QUOTA_EXCEEDED

    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_each_analysts_balance_is_read_against_their_own_account(stack: Stack) -> None:
    """One analyst in an organization, one not: two different endpoints."""
    await stack.add_credential(USER_B, TOKEN_B, organization_id="org-b")

    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))

    assert stack.client.details(USER_CREDITS) == [USER_A]
    assert stack.client.details(ORGANIZATION_CREDITS) == ["org-b"]


async def test_an_organization_balance_is_never_read_for_another_analyst() -> None:
    stack = Stack()
    await stack.add_credential(USER_A, TOKEN_A, organization_id="org-a")
    await stack.add_credential(USER_B, TOKEN_B)

    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert not stack.client.called(ORGANIZATION_CREDITS)
    assert stack.client.details(USER_CREDITS) == [USER_B]


async def test_one_analysts_cooldown_does_not_affect_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, TOKEN_B)
    stack.client.fail(HOST, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "censys"))
    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.cooldown_applied is True

    stack.client.errors.clear()
    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Unsupported is not the same as empty
# --------------------------------------------------------------------------- #


async def test_a_domain_reaches_the_executor_as_not_supported(stack: Stack) -> None:
    """A blind spot must not arrive at the engine looking like a clean result."""
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(intel_object=normalize_observable("example.com").intel_object),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.status is not ProviderRunStatus.NO_DATA
    assert stack.client.calls == []
    assert outcome.error_message is not None


async def test_an_unsupported_observable_is_not_cached_as_an_answer(stack: Stack) -> None:
    """Nothing was asked of Censys, so there is no answer to keep."""
    request = request_for(intel_object=normalize_observable("example.com").intel_object)
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NOT_SUPPORTED
    assert second.cache_hit is False


async def test_a_url_reaches_the_executor_as_a_web_property_lookup(stack: Stack) -> None:
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(
            intel_object=normalize_observable(
                f"https://{payloads.WEB_PROPERTY_HOST}/login"
            ).intel_object
        ),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert stack.client.details(FakeCensysClient.WEB_PROPERTY) == [
        f"{payloads.WEB_PROPERTY_HOST}:443"
    ]


# --------------------------------------------------------------------------- #
# Nothing carries a secret
# --------------------------------------------------------------------------- #


async def test_no_token_reaches_metrics_or_the_serialized_result(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None

    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    assert TOKEN_A not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized

    recorded = json.dumps(
        [metric.model_dump(mode="json") for metric in stack.metrics.executions]
        + [metric.model_dump(mode="json") for metric in stack.metrics.attempts],
        default=str,
    )
    assert TOKEN_A not in recorded
    assert "SHOULD-NOT-LEAK" not in recorded


async def test_no_banner_or_body_reaches_the_cached_result(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    assert "ATTACKER-CONTROLLED-TEXT" not in serialized
    assert "banner" not in serialized


def test_the_execution_policy_never_shares_results_between_analysts() -> None:
    assert build_censys_execution_policy().cache.scope.value == "user"
