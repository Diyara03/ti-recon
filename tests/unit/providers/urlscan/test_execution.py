"""urlscan running under the Task 6 ProviderExecutor (Task 8).

The point of these tests is that urlscan is not special. It goes through the
same cache, cooldown, quota and concurrency machinery every other provider does,
with no urlscan-shaped branch anywhere in the execution layer — and the
executor's guarantees hold for it exactly as they did for the fakes.

The one urlscan-specific guarantee proved here is the important one: an
authenticated urlscan search can return scans visible only to one analyst's key,
so nothing it produces may ever be served to another analyst.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.urlscan.fake_client import FakeUrlscanClient, FakeUrlscanClientFactory
from ti_recon.artifacts import ArtifactScope, InMemoryArtifactStore
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
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.urlscan import UrlscanAdapter, build_urlscan_execution_policy
from ti_recon.providers.urlscan.client import UrlscanArtifact

KEY_A = "urlscan-key-SHOULD-NOT-LEAK-12345"
KEY_B = "urlscan-key-BELONGS-TO-ANALYST-B-67890"
USER_A = "analyst-a"
USER_B = "analyst-b"
DOMAIN = "login.evil.example"

DOM = UrlscanArtifact(
    content=b'<html><form action="https://collector.evil.example/x"></form></html>',
    content_type="text/html",
    truncated=False,
)


class Stack:
    """The whole platform, wired deterministically around a fake urlscan client."""

    def __init__(self, client: FakeUrlscanClient | None = None) -> None:
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
        self.artifacts = InMemoryArtifactStore()
        self.policies = ProviderPolicyRegistry(policies=[build_urlscan_execution_policy()])
        self.client = client if client is not None else FakeUrlscanClient(dom=DOM)
        self.factory = FakeUrlscanClientFactory(self.client)
        self.adapter = UrlscanAdapter(
            client_factory=self.factory,  # type: ignore[arg-type]
            artifact_store=self.artifacts,
            quota_store=self.quota,
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
            provider_id="urlscan",
            secret=secret,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def subject() -> IntelObject:
    return normalize_observable(DOMAIN).intel_object


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": subject(),
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def forensic_request() -> ProviderRequest:
    return request_for(
        depth=InvestigationDepth.DEEP,
        requested_capabilities=frozenset(
            {ProviderCapability.REPUTATION, ProviderCapability.WEB_FORENSICS}
        ),
    )


@pytest.fixture
async def stack() -> Stack:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    return stack


# --------------------------------------------------------------------------- #
# The provider is chosen by capability, never by name
# --------------------------------------------------------------------------- #


def test_urlscan_is_discoverable_by_capability_with_no_vendor_branch(stack: Stack) -> None:
    matches = stack.registry.find_compatible(
        IntelObjectType.DOMAIN_NAME, ProviderCapability.WEB_FORENSICS
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["urlscan"]


# --------------------------------------------------------------------------- #
# Ordinary execution
# --------------------------------------------------------------------------- #


async def test_a_lookup_flows_through_the_executor(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.provider_id == "urlscan"
    assert outcome.attempts == 1
    assert outcome.result is not None
    assert outcome.result.evidence


async def test_a_repeat_lookup_is_served_from_cache(stack: Stack) -> None:
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context())
    searches = stack.client.call_count("search")

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is True
    assert stack.client.call_count("search") == searches


async def test_no_scans_is_cached_as_a_negative_answer(stack: Stack) -> None:
    stack.client.search_payload = {"results": []}
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NO_DATA

    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.NO_DATA


async def test_a_rate_limit_puts_this_analyst_on_cooldown(stack: Stack) -> None:
    stack.client.fail(
        "search",
        provider_error_for(
            ProviderErrorCategory.QUOTA_EXCEEDED, "urlscan", operation="urlscan.search"
        ),
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.cooldown_applied is True


async def test_an_analyst_without_a_credential_gets_not_configured() -> None:
    stack = Stack()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0


# --------------------------------------------------------------------------- #
# Per-user isolation, end to end
# --------------------------------------------------------------------------- #


async def test_one_analysts_urlscan_result_is_never_served_to_another(stack: Stack) -> None:
    """An authenticated search can return scans only one analyst's key may see."""
    await stack.add_credential(USER_B, KEY_B)
    request = request_for()

    await stack.executor.execute(stack.adapter, request, stack.context(USER_A))
    second = await stack.executor.execute(stack.adapter, request, stack.context(USER_B))

    assert second.cache_hit is False


async def test_one_analysts_cooldown_does_not_affect_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, KEY_B)
    stack.client.fail(
        "search",
        provider_error_for(
            ProviderErrorCategory.QUOTA_EXCEEDED, "urlscan", operation="urlscan.search"
        ),
    )
    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.cooldown_applied is True

    stack.client.errors.clear()
    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_captured_page_content_belongs_to_the_analyst_who_captured_it(
    stack: Stack,
) -> None:
    await stack.add_credential(USER_B, KEY_B)
    await stack.executor.execute(stack.adapter, forensic_request(), stack.context(USER_A))

    mine = ArtifactScope(user_id=USER_A, investigation_id="inv-1")
    theirs = ArtifactScope(user_id=USER_B, investigation_id="inv-1")
    assert stack.artifacts.list(mine)
    assert stack.artifacts.list(theirs) == ()


async def test_forensics_runs_through_the_executor_when_requested(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, forensic_request(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert stack.client.called("dom")
    claims = {item.claim_type for item in (outcome.result.evidence if outcome.result else ())}
    assert "urlscan_page_forensics" in claims


async def test_an_ordinary_lookup_through_the_executor_captures_nothing(
    stack: Stack,
) -> None:
    await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert not stack.client.called("dom")
    assert not stack.client.called("screenshot")
    assert stack.artifacts.list(ArtifactScope(user_id=USER_A, investigation_id="inv-1")) == ()


# --------------------------------------------------------------------------- #
# Nothing carries a secret
# --------------------------------------------------------------------------- #


async def test_no_key_reaches_metrics_or_the_serialized_result(stack: Stack) -> None:
    await stack.executor.execute(stack.adapter, forensic_request(), stack.context())
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


async def test_captured_page_content_never_reaches_the_envelope(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, forensic_request(), stack.context())
    assert outcome.result is not None
    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    assert "<html>" not in serialized
    assert "<form" not in serialized


def test_the_execution_policy_never_shares_results_between_analysts() -> None:
    policy = build_urlscan_execution_policy()
    assert policy.cache.scope.value == "user"
