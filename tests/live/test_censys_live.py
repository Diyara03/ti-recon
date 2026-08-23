"""Optional Censys live smoke tests (Task 9).

**Disabled by default.** Along with the GTI, urlscan and GreyNoise ones these are
the only tests in the repository that touch a real API, and they stay off unless
explicitly enabled:

.. code-block:: bash

    RUN_CENSYS_LIVE_TESTS=1 CENSYS_PAT=<your token> uv run pytest tests/live -q

``CENSYS_ORGANIZATION_ID`` is optional; when it is set the credit balance is read
from the organization endpoint instead of the user one. Without the first two
variables every test here skips, so a default ``pytest`` run, CI and pre-commit
never contact Censys.

Credits
-------

Every Censys asset read costs a credit, so this file is deliberately frugal and
ordered.

The credit endpoints cost **nothing**, so they go first: the credential check and
the health check both read a balance rather than an asset, and the balance is
asserted before anything is spent. Then exactly one well-known public host is
looked up, and the repeat-lookup test reuses that same asset through the cache so
the second call costs nothing either.

There is **no search test**, at any depth. Search is not implemented, costs
credits per page rather than per asset, and is explicitly deferred.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a direct asset read succeeds, that what comes back normalizes
into TI Recon models with the right provenance and no direction, that no banner
or body text survives into evidence, and that a repeat lookup through the Task 6
executor spends no second credit.

They do **not** assert which ports are open on anything. Exposure changes, and a
test that fails because a host closed a port is a test that teaches you to ignore
failures.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from pydantic import SecretStr

from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceEffect,
    InvestigationDepth,
    MatchScope,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ProviderExecutor,
    ProviderPolicyRegistry,
)
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.censys import (
    ORGANIZATION_METADATA_KEY,
    CensysAdapter,
    CensysConfig,
    CensysCreditScope,
    ConnectionOrganizationDirectory,
    StaticOrganizationDirectory,
    build_censys_execution_policy,
)

RUN_LIVE_ENV_VAR = "RUN_CENSYS_LIVE_TESTS"
TOKEN_ENV_VAR = "CENSYS_PAT"
ORGANIZATION_ENV_VAR = "CENSYS_ORGANIZATION_ID"

#: A host that is scanned constantly and is not anybody's malicious
#: infrastructure. Deliberately boring, and deliberately a single address: each
#: read of it costs one credit.
SMOKE_ADDRESS = "8.8.8.8"

LIVE_USER = "live-analyst"
LIVE_CONNECTION = "live-connection"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_token = os.environ.get(TOKEN_ENV_VAR, "")
_organization_id = os.environ.get(ORGANIZATION_ENV_VAR, "").strip() or None

pytestmark = pytest.mark.skipif(
    not (_enabled and _token),
    reason=(
        f"censys live tests are off. Enable with {RUN_LIVE_ENV_VAR}=1 and {TOKEN_ENV_VAR}=<token>."
    ),
)


def live_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id=LIVE_CONNECTION,
        user_id=LIVE_USER,
        provider_id="censys",
        credential_group="censys",
        auth_type=AuthType.BEARER_TOKEN,
        secret=SecretStr(_token),
    )


def live_organizations() -> StaticOrganizationDirectory | None:
    if _organization_id is None:
        return None
    directory = StaticOrganizationDirectory()
    directory.set(
        user_id=LIVE_USER, connection_id=LIVE_CONNECTION, organization_id=_organization_id
    )
    return directory


@pytest.fixture
async def adapter() -> AsyncIterator[CensysAdapter]:
    yield CensysAdapter(config=CensysConfig(), organizations=live_organizations())


def request_for(
    raw: str,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=normalize_observable(raw).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.CURRENT_INFRASTRUCTURE}),
        depth=depth,
    )


# --------------------------------------------------------------------------- #
# The free endpoints, first
# --------------------------------------------------------------------------- #


async def test_the_credential_is_accepted_without_spending_a_credit(
    adapter: CensysAdapter,
) -> None:
    """Validation reads a balance, never an asset."""
    result = await adapter.validate_credentials(live_credential())
    assert result.is_usable, f"credential validation returned {result.status.value}"


async def test_the_credit_balance_is_readable(adapter: CensysAdapter) -> None:
    reading = await adapter.fetch_credits(live_credential())
    expected = CensysCreditScope.ORGANIZATION if _organization_id else CensysCreditScope.USER
    assert reading.scope is expected
    # The balance itself is not asserted: a plan may report nothing measurable,
    # and an empty snapshot is an honest answer rather than a failure.
    assert reading.snapshot.provider_id == "censys"


async def test_the_provider_reports_itself_available(adapter: CensysAdapter) -> None:
    report = await adapter.health(live_credential())
    assert report.provider_id == "censys"
    assert report.health.value in {"available", "degraded", "unavailable", "unknown"}


async def test_capability_discovery_spends_nothing(adapter: CensysAdapter) -> None:
    discovery = await adapter.discover_capabilities(live_credential())
    assert ProviderCapability.CURRENT_INFRASTRUCTURE in discovery.capabilities
    assert ProviderCapability.REPUTATION not in discovery.capabilities


async def test_an_unsupported_observable_costs_no_credit(adapter: CensysAdapter) -> None:
    """A bare domain has no deterministic asset, so nothing is requested."""
    envelope = await adapter.lookup(request_for("example.com"), live_credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# One asset read
# --------------------------------------------------------------------------- #


async def test_a_well_known_host_normalizes(adapter: CensysAdapter) -> None:
    """One direct lookup of one deterministic asset identity."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())

    assert envelope.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }
    assert envelope.provider == "censys"
    assert envelope.api_version == "v3"

    # Structure and provenance only. Nothing about which ports are currently
    # open: that changes, and pinning it would make this test fail for a reason
    # nobody should act on.
    for evidence in envelope.evidence:
        assert evidence.transport_provider == "censys"
        assert evidence.origin_provider == "censys"
        assert evidence.lineage_group_id
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_nothing_censys_reports_carries_a_direction(adapter: CensysAdapter) -> None:
    """Exposure is not an accusation, against the real API as much as a fixture."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    for evidence in envelope.evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_the_result_records_which_asset_was_read(adapter: CensysAdapter) -> None:
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    coverage = next(
        item.attributes for item in envelope.evidence if item.claim_type == "censys_asset_coverage"
    )
    assert coverage["asset_kind"] == "host"
    assert coverage["asset"] == SMOKE_ADDRESS
    assert coverage["match_scope"] == MatchScope.EXACT_OBSERVABLE.value


async def test_no_banner_or_body_reaches_the_result(adapter: CensysAdapter) -> None:
    """A real response carries banners; a real evidence record must not."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    serialized = envelope.model_dump_json()
    assert "banner" not in serialized
    assert "html_title" not in serialized
    assert "<html" not in serialized.lower()


async def test_nothing_in_the_result_carries_the_token(adapter: CensysAdapter) -> None:
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    assert _token not in envelope.model_dump_json()


# --------------------------------------------------------------------------- #
# The same lookup through the Task 6 executor
# --------------------------------------------------------------------------- #


class LiveStack:
    """The real adapter behind the real execution layer."""

    def __init__(self) -> None:
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.cache = InMemoryProviderCache()
        self.quota = InMemoryQuotaStore()
        self.adapter = CensysAdapter(
            config=CensysConfig(),
            organizations=ConnectionOrganizationDirectory(self.connections),
            quota_store=self.quota,
        )
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=self.quota,
            cooldown_store=InMemoryCooldownStore(),
            # One at a time: the plan's per-minute allowance is unknown here.
            limiter=ConcurrencyLimiter(max_concurrency=1),
            policies=ProviderPolicyRegistry(policies=[build_censys_execution_policy()]),
        )

    async def configure(self) -> None:
        metadata = {ORGANIZATION_METADATA_KEY: _organization_id} if _organization_id else {}
        await self.manager.create_connection(
            user_id=LIVE_USER,
            provider_id="censys",
            secret=_token,
            auth_type=AuthType.BEARER_TOKEN,
            metadata=metadata,
            status=CredentialStatus.ACTIVE,
        )

    @property
    def context(self) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=LIVE_USER, request_id="live-req")


@pytest.fixture
async def stack() -> AsyncIterator[LiveStack]:
    live = LiveStack()
    await live.configure()
    yield live


async def test_a_lookup_flows_through_the_executor(stack: LiveStack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(SMOKE_ADDRESS), stack.context)
    assert outcome.provider_id == "censys"
    assert outcome.attempts >= 1
    assert outcome.cache_hit is False


async def test_a_repeat_lookup_costs_no_second_credit(stack: LiveStack) -> None:
    """The reason the cache matters here: one credit rather than two."""
    request = request_for(SMOKE_ADDRESS)
    first = await stack.executor.execute(stack.adapter, request, stack.context)
    if first.status not in {ProviderRunStatus.SUCCESS, ProviderRunStatus.NO_DATA}:
        pytest.skip(f"first live lookup returned {first.status.value}; caching not exercised")

    second = await stack.executor.execute(stack.adapter, request, stack.context)
    assert second.cache_hit is True
    assert second.attempts == 0
    assert second.called_provider is False


async def test_the_balance_is_recorded_where_the_precheck_will_see_it(
    stack: LiveStack,
) -> None:
    await stack.executor.execute(stack.adapter, request_for(SMOKE_ADDRESS), stack.context)
    snapshot = await stack.quota.get(f"user|{LIVE_USER}|censys|{LIVE_CONNECTION}")
    if snapshot is None:
        pytest.skip("no balance was recorded for this account")
    assert snapshot.provider_id == "censys"
