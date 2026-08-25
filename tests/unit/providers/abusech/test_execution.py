"""The three abuse.ch providers under the Task 6 ProviderExecutor (Task 10).

Nothing here is abuse.ch-specific machinery: the same cache, cooldown, quota and
concurrency layer that runs GTI, urlscan, GreyNoise and Censys runs these three,
with no provider-name branch anywhere in it.

What *is* specific is the credential. One Auth-Key serves all three platforms, so
these tests prove the two things that follow from that: one stored connection is
enough for every abuse.ch lookup, and sharing a key between providers never makes
them share a cache entry, a cooldown or another analyst's answer.
"""

from __future__ import annotations

from typing import Any

import pytest

from fixtures.abusech import payloads
from fixtures.abusech.fake_clients import (
    ClientFactory,
    FakeMalwareBazaarClient,
    FakeThreatFoxClient,
    FakeUrlhausClient,
)
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.credentials.groups import ABUSE_CH_GROUP
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
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
from ti_recon.providers.abusech import ABUSE_CH_MAX_CONCURRENCY
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.malwarebazaar import (
    MalwareBazaarAdapter,
    build_malwarebazaar_execution_policy,
)
from ti_recon.providers.threatfox import ThreatFoxAdapter, build_threatfox_execution_policy
from ti_recon.providers.urlhaus import UrlhausAdapter, build_urlhaus_execution_policy

KEY_A = "abusech-key-SHOULD-NOT-LEAK-12345"
KEY_B = "abusech-key-BELONGS-TO-ANALYST-B-67890"
USER_A = "analyst-a"
USER_B = "analyst-b"

SEARCH_IOC = FakeThreatFoxClient.SEARCH_IOC
LOOKUP_URL = FakeUrlhausClient.LOOKUP_URL
GET_INFO = FakeMalwareBazaarClient.GET_INFO


def file_object() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.SAMPLE_SHA256,
        display_value=payloads.SAMPLE_SHA256,
        properties={"hashes": {"SHA-256": payloads.SAMPLE_SHA256}},
    )


class Stack:
    """The whole platform, wired deterministically around three fake clients."""

    def __init__(self) -> None:
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
        self.policies = ProviderPolicyRegistry(
            policies=[
                build_threatfox_execution_policy(),
                build_urlhaus_execution_policy(),
                build_malwarebazaar_execution_policy(),
            ]
        )
        self.threatfox_client = FakeThreatFoxClient()
        self.urlhaus_client = FakeUrlhausClient()
        self.malwarebazaar_client = FakeMalwareBazaarClient()
        self.threatfox = ThreatFoxAdapter(
            client_factory=ClientFactory(self.threatfox_client),  # type: ignore[arg-type]
            clock=self.clock,
        )
        self.urlhaus = UrlhausAdapter(
            client_factory=ClientFactory(self.urlhaus_client),  # type: ignore[arg-type]
            clock=self.clock,
        )
        self.malwarebazaar = MalwareBazaarAdapter(
            client_factory=ClientFactory(self.malwarebazaar_client),  # type: ignore[arg-type]
            clock=self.clock,
        )
        self.registry = ProviderRegistry([self.threatfox, self.urlhaus, self.malwarebazaar])
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
        """Store one abuse.ch key, the way an analyst would: once."""
        connection = await self.manager.create_connection(
            user_id=user_id,
            provider_id="threatfox",
            secret=secret,
            auth_type=AuthType.AUTH_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def request_for(
    subject: str | IntelObject = payloads.SCANNER_IP, **overrides: Any
) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": target,
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
# One stored key, three providers
# --------------------------------------------------------------------------- #


async def test_one_stored_connection_serves_all_three_providers(stack: Stack) -> None:
    """The analyst stored a key for one platform and got the ecosystem."""
    connections = await stack.connections.list_for_user(USER_A)
    assert [connection.credential_group for connection in connections] == [ABUSE_CH_GROUP]

    outcomes = [
        await stack.executor.execute(stack.threatfox, request_for(), stack.context()),
        await stack.executor.execute(
            stack.urlhaus, request_for(payloads.MALICIOUS_URL), stack.context()
        ),
        await stack.executor.execute(
            stack.malwarebazaar, request_for(file_object()), stack.context()
        ),
    ]
    for outcome in outcomes:
        assert outcome.status is ProviderRunStatus.SUCCESS
        assert outcome.called_provider is True
        assert outcome.result is not None
        assert outcome.result.evidence


async def test_an_analyst_without_the_shared_key_gets_not_configured() -> None:
    stack = Stack()
    answerable = (
        (stack.threatfox, request_for()),
        (stack.urlhaus, request_for(payloads.MALICIOUS_URL)),
        (stack.malwarebazaar, request_for(file_object())),
    )
    for adapter, request in answerable:
        outcome = await stack.executor.execute(adapter, request, stack.context())
        assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
        assert outcome.attempts == 0
    assert stack.threatfox_client.calls == []
    assert stack.urlhaus_client.calls == []
    assert stack.malwarebazaar_client.calls == []


async def test_the_shared_key_is_resolved_per_user_and_never_borrowed(stack: Stack) -> None:
    material_a = await stack.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="malwarebazaar"
    )
    assert material_a.secret.get_secret_value() == KEY_A
    assert material_a.credential_group == ABUSE_CH_GROUP

    await stack.add_credential(USER_B, KEY_B)
    material_b = await stack.resolver.resolve(authenticated_user_id=USER_B, provider_id="urlhaus")
    assert material_b.secret.get_secret_value() == KEY_B
    assert material_b.connection_id != material_a.connection_id


# --------------------------------------------------------------------------- #
# Caching
# --------------------------------------------------------------------------- #


async def test_a_repeat_lookup_is_served_from_cache(stack: Stack) -> None:
    request = request_for()
    first = await stack.executor.execute(stack.threatfox, request, stack.context())
    assert (first.attempts, first.cache_hit, first.called_provider) == (1, False, True)

    second = await stack.executor.execute(stack.threatfox, request, stack.context())
    assert (second.attempts, second.cache_hit, second.called_provider) == (0, True, False)
    assert stack.threatfox_client.call_count(SEARCH_IOC) == 1


async def test_sharing_a_key_never_means_sharing_a_cache_entry(stack: Stack) -> None:
    """Three platforms, three answers. One key does not merge them."""
    subject = request_for(file_object())
    await stack.executor.execute(stack.malwarebazaar, subject, stack.context())
    outcome = await stack.executor.execute(stack.urlhaus, subject, stack.context())
    assert outcome.cache_hit is False
    assert stack.urlhaus_client.called(FakeUrlhausClient.LOOKUP_PAYLOAD)


async def test_different_depths_do_not_share_a_cache_entry(stack: Stack) -> None:
    """A QUICK answer normalizes less of the same document; serving it would lie."""
    await stack.executor.execute(
        stack.malwarebazaar,
        request_for(file_object(), depth=InvestigationDepth.QUICK),
        stack.context(),
    )
    outcome = await stack.executor.execute(
        stack.malwarebazaar,
        request_for(file_object(), depth=InvestigationDepth.DEEP),
        stack.context(),
    )
    assert outcome.cache_hit is False


async def test_an_absence_is_cached_as_an_absence(stack: Stack) -> None:
    stack.malwarebazaar_client.info_payload = payloads.malwarebazaar_not_found()
    request = request_for(file_object())
    first = await stack.executor.execute(stack.malwarebazaar, request, stack.context())
    assert first.status is ProviderRunStatus.NO_DATA

    second = await stack.executor.execute(stack.malwarebazaar, request, stack.context())
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.NO_DATA
    assert stack.malwarebazaar_client.call_count(GET_INFO) == 1


async def test_an_unsupported_observable_never_reaches_a_client(stack: Stack) -> None:
    """A blind spot must not arrive at the engine looking like a clean result."""
    outcome = await stack.executor.execute(
        stack.malwarebazaar, request_for(payloads.MALICIOUS_DOMAIN), stack.context()
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.status is not ProviderRunStatus.NO_DATA
    assert stack.malwarebazaar_client.calls == []


# --------------------------------------------------------------------------- #
# Per-user isolation
# --------------------------------------------------------------------------- #


async def test_one_analysts_answer_is_never_served_to_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, KEY_B)
    request = request_for()

    await stack.executor.execute(stack.threatfox, request, stack.context(USER_A))
    second = await stack.executor.execute(stack.threatfox, request, stack.context(USER_B))

    assert second.cache_hit is False
    assert stack.threatfox_client.call_count(SEARCH_IOC) == 2


async def test_one_analysts_cooldown_does_not_affect_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, KEY_B)
    stack.threatfox_client.fail(
        SEARCH_IOC, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "threatfox")
    )
    blocked = await stack.executor.execute(stack.threatfox, request_for(), stack.context(USER_A))
    assert blocked.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert blocked.cooldown_applied is True

    stack.threatfox_client.errors.clear()
    allowed = await stack.executor.execute(stack.threatfox, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_one_providers_cooldown_does_not_disable_its_siblings(stack: Stack) -> None:
    """A ThreatFox throttle is not a reason to stop asking URLhaus."""
    stack.threatfox_client.fail(
        SEARCH_IOC, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "threatfox")
    )
    blocked = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert blocked.cooldown_applied is True

    outcome = await stack.executor.execute(
        stack.urlhaus, request_for(payloads.MALICIOUS_URL), stack.context()
    )
    assert outcome.status is ProviderRunStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Failure handling belongs to Task 6, not to the adapters
# --------------------------------------------------------------------------- #


async def test_a_transient_failure_is_retried_then_reported(stack: Stack) -> None:
    stack.urlhaus_client.fail(
        LOOKUP_URL, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "urlhaus")
    )
    outcome = await stack.executor.execute(
        stack.urlhaus, request_for(payloads.MALICIOUS_URL), stack.context()
    )
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.attempts > 1


async def test_a_rejected_shared_key_is_not_retried(stack: Stack) -> None:
    """Retrying a bad key spends fair-use allowance to be told the same thing."""
    stack.malwarebazaar_client.info_payload = {"query_status": "no_api_key"}
    outcome = await stack.executor.execute(
        stack.malwarebazaar, request_for(file_object()), stack.context()
    )
    assert outcome.status is ProviderRunStatus.ERROR
    assert outcome.attempts == 1


async def test_a_fair_use_block_is_reported_without_invalidating_the_key(stack: Stack) -> None:
    """abuse.ch blocks a noisy account for up to 72 hours; the key is intact."""
    stack.threatfox_client.ioc_payload = {"query_status": "user_blacklisted"}
    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.ERROR
    assert outcome.error_category is ProviderErrorCategory.PERMISSION_ERROR
    connection = await stack.connections.find_by_group(USER_A, ABUSE_CH_GROUP)
    assert connection is not None
    assert connection.status is CredentialStatus.ACTIVE


# --------------------------------------------------------------------------- #
# Politeness towards a free service
# --------------------------------------------------------------------------- #


def test_every_provider_stays_at_one_request_at_a_time(stack: Stack) -> None:
    """abuse.ch is free and fair-use metered; parallelism is not ours to take."""
    assert ABUSE_CH_MAX_CONCURRENCY == 1
    for policy in (
        build_threatfox_execution_policy(),
        build_urlhaus_execution_policy(),
        build_malwarebazaar_execution_policy(),
    ):
        assert policy.max_concurrency == ABUSE_CH_MAX_CONCURRENCY


def test_no_provider_caches_globally() -> None:
    """An authenticated answer belongs to the analyst who paid attention for it."""
    for policy in (
        build_threatfox_execution_policy(),
        build_urlhaus_execution_policy(),
        build_malwarebazaar_execution_policy(),
    ):
        assert policy.cache.scope.value == "user"


def test_identical_concurrent_lookups_are_coalesced() -> None:
    for policy in (
        build_threatfox_execution_policy(),
        build_urlhaus_execution_policy(),
        build_malwarebazaar_execution_policy(),
    ):
        assert policy.coalesce_requests is True


def test_the_execution_layer_names_no_abusech_provider() -> None:
    """Task 6 decides how, never what. A vendor name there would be a bug."""
    import ast
    import inspect
    from pathlib import Path

    from ti_recon import execution

    package = Path(inspect.getfile(execution)).parent
    for module_path in sorted(package.glob("*.py")):
        source = module_path.read_text(encoding="utf-8")
        ast.parse(source)
        lowered = source.lower()
        for provider_id in ("threatfox", "urlhaus", "malwarebazaar", "abuse_ch", "abuse.ch"):
            assert provider_id not in lowered, f"{module_path.name} mentions {provider_id}"
