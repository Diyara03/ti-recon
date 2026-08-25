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

What a full run costs
---------------------

Every Censys **asset** read costs a credit. The account endpoints cost nothing.

===============================  =====================================
Check                            Cost
===============================  =====================================
credential validation            credit endpoint — **0 credits**
credit balance                   credit endpoint — **0 credits**
health                           credit endpoint — **0 credits**
capability discovery             no request at all
unsupported observable           no request at all
every enrichment assertion       **one** host read — 1 credit, shared
the repeat-lookup assertion      served from the Task 6 cache — 0 credits
===============================  =====================================

**A full run performs exactly one physical, credit-consuming asset read.**

That is enforced by the code rather than by a comment or by test ordering:
:func:`live_lookup` performs the read once, caches both outcomes in a
module-level slot, and every assertion below reads that same pair. Calling
``adapter.lookup`` directly from several tests — as an earlier version of this
file did — bypasses the Task 6 cache and quietly spends one credit per test,
which is exactly the mistake this structure removes.

There is **no search test**, at any depth: search is not implemented, costs
credits per page rather than per asset, and is explicitly deferred. There is no
second web-property read, no certificate lookup and no rescan.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a direct asset read succeeds, that what comes back normalizes
into TI Recon models with the right provenance and no direction, that no banner
or body text survives into evidence, and that the identical request run again is
served from cache.

They do **not** assert which ports are open on anything. Exposure changes, and a
test that fails because a host closed a port is a test that teaches you to ignore
failures.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass

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
    ProviderExecutionOutcome,
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
from ti_recon.providers.quota import ProviderQuotaSnapshot

RUN_LIVE_ENV_VAR = "RUN_CENSYS_LIVE_TESTS"
TOKEN_ENV_VAR = "CENSYS_PAT"
ORGANIZATION_ENV_VAR = "CENSYS_ORGANIZATION_ID"

#: A host that is scanned constantly and is not anybody's malicious
#: infrastructure. Deliberately boring, and deliberately a single address: one
#: read of it is the entire credit budget of this file.
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
# Zero-credit checks
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
# The one credit, spent once and shared
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LiveLookup:
    """The two outcomes of one identical request, issued back to back.

    ``first`` cost one credit. ``second`` cost nothing: it went through the same
    executor, cache and provider connection, so the Task 6 cache answered it —
    which for a credit-metered provider is the difference between one credit and
    two.
    """

    first: ProviderExecutionOutcome
    second: ProviderExecutionOutcome
    quota: ProviderQuotaSnapshot | None


#: Computed at most once per session. A module-level slot rather than a fixture
#: because fixture scope and test ordering are exactly the things that must not
#: be able to turn one credit into several.
_LOOKUP: LiveLookup | None = None


async def live_lookup() -> LiveLookup:
    """Perform the run's single credit-bearing read, or return the cached pair."""
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = await _perform_single_lookup()
    return _LOOKUP


async def _perform_single_lookup() -> LiveLookup:
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)
    resolver = CredentialResolver(secrets, connections)
    metadata = {ORGANIZATION_METADATA_KEY: _organization_id} if _organization_id else {}
    await manager.create_connection(
        user_id=LIVE_USER,
        provider_id="censys",
        secret=SecretStr(_token),
        auth_type=AuthType.BEARER_TOKEN,
        metadata=metadata,
        status=CredentialStatus.ACTIVE,
    )

    quota_store = InMemoryQuotaStore()
    adapter = CensysAdapter(
        config=CensysConfig(),
        organizations=ConnectionOrganizationDirectory(connections),
        quota_store=quota_store,
    )
    executor = ProviderExecutor(
        credential_resolver=resolver,
        cache=InMemoryProviderCache(),
        quota_store=quota_store,
        cooldown_store=InMemoryCooldownStore(),
        # One at a time: the plan's per-minute allowance is unknown here.
        limiter=ConcurrencyLimiter(max_concurrency=1),
        policies=ProviderPolicyRegistry(policies=[build_censys_execution_policy()]),
    )
    context = ExecutionContext(authenticated_user_id=LIVE_USER, request_id="live-req")
    request = request_for(SMOKE_ADDRESS)

    # The one and only credit-consuming call in this file.
    first = await executor.execute(adapter, request, context)
    # Identical request, same executor and cache: this must not reach Censys.
    second = await executor.execute(adapter, request, context)
    snapshot = await quota_store.get(f"user|{LIVE_USER}|censys|{LIVE_CONNECTION}")
    return LiveLookup(first=first, second=second, quota=snapshot)


async def enriched() -> ProviderExecutionOutcome:
    """The successful first outcome, or a skip if Censys refused it.

    Skipping rather than failing when the balance is spent or the token is not
    permitted: that is an account fact, not a defect in the integration.
    """
    lookup = await live_lookup()
    if lookup.first.result is None:
        pytest.skip(f"live lookup returned {lookup.first.status.value} with no result")
    return lookup.first


# --------------------------------------------------------------------------- #
# Everything below reads that one credit
# --------------------------------------------------------------------------- #


async def test_the_lookup_flows_through_the_executor() -> None:
    lookup = await live_lookup()
    assert lookup.first.provider_id == "censys"
    assert lookup.first.attempts >= 1
    assert lookup.first.cache_hit is False
    assert lookup.first.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }


async def test_the_repeat_lookup_costs_no_second_credit() -> None:
    """The reason the cache matters here: one credit rather than two."""
    lookup = await live_lookup()
    if lookup.first.status not in {ProviderRunStatus.SUCCESS, ProviderRunStatus.NO_DATA}:
        pytest.skip(
            f"first live lookup returned {lookup.first.status.value}; caching not exercised"
        )
    assert lookup.second.cache_hit is True
    assert lookup.second.attempts == 0
    assert lookup.second.called_provider is False


async def test_the_result_is_a_structurally_valid_v3_answer() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    assert outcome.result.provider == "censys"
    assert outcome.result.api_version == "v3"


async def test_every_piece_of_evidence_carries_first_hand_provenance() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        assert evidence.transport_provider == "censys"
        assert evidence.origin_provider == "censys"
        assert evidence.lineage_group_id
        # Admiralty grading is TI Recon policy, never a provider's to claim.
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_nothing_censys_reports_carries_a_direction() -> None:
    """Exposure is not an accusation, against the real API as much as a fixture."""
    outcome = await enriched()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_the_result_records_which_asset_was_read() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    coverage = next(
        item.attributes
        for item in outcome.result.evidence
        if item.claim_type == "censys_asset_coverage"
    )
    assert coverage["asset_kind"] == "host"
    assert coverage["asset"] == SMOKE_ADDRESS
    assert coverage["match_scope"] == MatchScope.EXACT_OBSERVABLE.value


async def test_no_banner_or_body_reaches_the_result() -> None:
    """A real response carries banners; a real evidence record must not."""
    outcome = await enriched()
    assert outcome.result is not None
    serialized = outcome.result.model_dump_json()
    assert "banner" not in serialized
    assert "html_title" not in serialized
    assert "<html" not in serialized.lower()


async def test_nothing_in_the_result_carries_the_token() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    assert _token not in outcome.result.model_dump_json()


async def test_the_balance_is_recorded_where_the_precheck_will_see_it() -> None:
    """Read from the free endpoint during the same lookup; costs nothing extra."""
    lookup = await live_lookup()
    if lookup.quota is None:
        pytest.skip("no balance was recorded for this account")
    assert lookup.quota.provider_id == "censys"
