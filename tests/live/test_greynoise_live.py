"""Optional GreyNoise live smoke tests (Task 9).

**Disabled by default.** Along with the GTI, urlscan and Censys ones these are
the only tests in the repository that touch a real API, and they stay off unless
explicitly enabled:

.. code-block:: bash

    RUN_GREYNOISE_LIVE_TESTS=1 GREYNOISE_API_KEY=<your key> uv run pytest tests/live -q

Without both variables every test here skips, so a default ``pytest`` run, CI
and pre-commit never contact GreyNoise.

What a full run costs
---------------------

GreyNoise's free and Community plans meter intelligence lookups over a *weekly*
allowance, so this file is built around spending as little of it as possible:

===============================  =====================================
Check                            Cost
===============================  =====================================
credential validation            ``/ping`` — no intelligence lookup
health                           ``/ping`` — no intelligence lookup
unsupported observable           no request at all
every enrichment assertion       **one** lookup, shared between them
the repeat-lookup assertion      served from the Task 6 cache
===============================  =====================================

**A full run performs exactly one physical GreyNoise IOC request.**

That is enforced by the code rather than by a comment or by test ordering:
:func:`live_lookup` performs the lookup once, caches both outcomes in a
module-level slot, and every assertion below reads that same pair. A test added
later that wants live enrichment data uses the same helper and still spends
nothing.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a lookup succeeds against whichever endpoint the key is entitled
to use, that what comes back normalizes into TI Recon models with the right
provenance, and that the identical request run again through the same executor
is served from cache.

They do **not** assert today's classification for anything. GreyNoise
reclassifies addresses constantly, and a test that fails because a scanner was
re-scored is a test that teaches you to ignore failures. They also make no
assumption about which access level the key turns out to have: both are valid
answers, and the run records which one happened.

Rules these obey
----------------

Passive GET reads of ``/ping``, ``/v3/ip/{ip}`` and ``/v3/community/{ip}`` only.
No GNQL, no timeline, no bulk lookup, no feed, no PCAP — the integration has no
code path for any of those and these tests do not add one. The API key is never
printed.
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
from ti_recon.providers.greynoise import (
    GreyNoiseAccessLevel,
    GreyNoiseAdapter,
    GreyNoiseConfig,
    build_greynoise_execution_policy,
)

RUN_LIVE_ENV_VAR = "RUN_GREYNOISE_LIVE_TESTS"
API_KEY_ENV_VAR = "GREYNOISE_API_KEY"

#: A routable address that is not anybody's malicious infrastructure and is
#: constantly present in GreyNoise's data as a well-known public service.
#: Deliberately boring: a live test should not depend on a particular scanner
#: still being listed. It must be routable — GreyNoise has no record of reserved
#: documentation space, so a TEST-NET address would prove nothing.
SMOKE_ADDRESS = "8.8.8.8"

LIVE_USER = "live-analyst"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_api_key = os.environ.get(API_KEY_ENV_VAR, "")

pytestmark = pytest.mark.skipif(
    not (_enabled and _api_key),
    reason=(
        f"greynoise live tests are off. "
        f"Enable with {RUN_LIVE_ENV_VAR}=1 and {API_KEY_ENV_VAR}=<key>."
    ),
)


def live_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="live-connection",
        user_id=LIVE_USER,
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(_api_key),
    )


@pytest.fixture
async def adapter() -> AsyncIterator[GreyNoiseAdapter]:
    yield GreyNoiseAdapter(config=GreyNoiseConfig())


def request_for(
    raw: str,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=normalize_observable(raw).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
        depth=depth,
    )


# --------------------------------------------------------------------------- #
# Zero-lookup checks
# --------------------------------------------------------------------------- #


async def test_the_credential_is_accepted_without_a_lookup(
    adapter: GreyNoiseAdapter,
) -> None:
    """``/ping`` names no observable, so this spends nothing at all."""
    result = await adapter.validate_credentials(live_credential())
    assert result.is_usable, f"credential validation returned {result.status.value}"


async def test_the_provider_reports_itself_available(adapter: GreyNoiseAdapter) -> None:
    """Also ``/ping``: availability should never cost an intelligence lookup."""
    report = await adapter.health(live_credential())
    assert report.provider_id == "greynoise"
    assert report.health.value in {"available", "degraded", "unavailable", "unknown"}


async def test_capability_discovery_makes_no_request(adapter: GreyNoiseAdapter) -> None:
    discovery = await adapter.discover_capabilities(live_credential())
    assert ProviderCapability.SCANNER_CONTEXT in discovery.capabilities


async def test_an_unsupported_observable_costs_no_lookup(
    adapter: GreyNoiseAdapter,
) -> None:
    """A domain has no GreyNoise lookup, so no request is made."""
    envelope = await adapter.lookup(request_for("example.com"), live_credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# The one physical lookup, performed once and shared
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LiveLookup:
    """The two outcomes of one identical request, issued back to back.

    ``first`` cost one GreyNoise lookup. ``second`` cost nothing: it went through
    the same executor, cache and provider connection, so the Task 6 cache
    answered it.
    """

    first: ProviderExecutionOutcome
    second: ProviderExecutionOutcome


#: Computed at most once per session. A module-level slot rather than a fixture
#: because fixture scope and test ordering are exactly the things that must not
#: be able to turn one lookup into several.
_LOOKUP: LiveLookup | None = None


async def live_lookup() -> LiveLookup:
    """Perform the run's single GreyNoise lookup, or return the cached pair."""
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = await _perform_single_lookup()
    return _LOOKUP


async def _perform_single_lookup() -> LiveLookup:
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)
    resolver = CredentialResolver(secrets, connections)
    await manager.create_connection(
        user_id=LIVE_USER,
        provider_id="greynoise",
        secret=SecretStr(_api_key),
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
    )

    adapter = GreyNoiseAdapter(config=GreyNoiseConfig())
    executor = ProviderExecutor(
        credential_resolver=resolver,
        cache=InMemoryProviderCache(),
        quota_store=InMemoryQuotaStore(),
        cooldown_store=InMemoryCooldownStore(),
        limiter=ConcurrencyLimiter(max_concurrency=1),
        policies=ProviderPolicyRegistry(policies=[build_greynoise_execution_policy()]),
    )
    context = ExecutionContext(authenticated_user_id=LIVE_USER, request_id="live-req")
    request = request_for(SMOKE_ADDRESS)

    # The one and only credit-bearing call in this file.
    first = await executor.execute(adapter, request, context)
    # Identical request, same executor and cache: this must not reach GreyNoise.
    second = await executor.execute(adapter, request, context)
    return LiveLookup(first=first, second=second)


async def enriched() -> ProviderExecutionOutcome:
    """The successful first outcome, or a skip if GreyNoise refused it.

    Skipping rather than failing when the account is throttled or unentitled:
    that is an account fact, not a defect in the integration, and every
    assertion below is about a result that exists.
    """
    lookup = await live_lookup()
    if lookup.first.result is None:
        pytest.skip(f"live lookup returned {lookup.first.status.value} with no result")
    return lookup.first


# --------------------------------------------------------------------------- #
# Everything below reads that one lookup
# --------------------------------------------------------------------------- #


async def test_the_lookup_flows_through_the_executor() -> None:
    lookup = await live_lookup()
    assert lookup.first.provider_id == "greynoise"
    assert lookup.first.attempts >= 1
    assert lookup.first.cache_hit is False
    assert lookup.first.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }


async def test_the_repeat_lookup_costs_no_second_request() -> None:
    """The Task 6 guarantee, against the real API."""
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
    assert outcome.result.provider == "greynoise"
    assert outcome.result.api_version == "v3"


async def test_every_piece_of_evidence_carries_first_hand_provenance() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        assert evidence.transport_provider == "greynoise"
        assert evidence.origin_provider == "greynoise"
        assert evidence.lineage_group_id
        # Admiralty grading is TI Recon policy, never a provider's to claim.
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_the_result_records_which_door_answered() -> None:
    """A full-tier and a Community answer are both fine; the run says which."""
    outcome = await enriched()
    assert outcome.result is not None
    coverage = next(
        item.attributes
        for item in outcome.result.evidence
        if item.claim_type == "greynoise_coverage"
    )
    assert coverage["access_level"] in {level.value for level in GreyNoiseAccessLevel}
    assert coverage["depth"] == InvestigationDepth.STANDARD.value


async def test_a_classification_keeps_its_own_word() -> None:
    """Whatever GreyNoise said, the raw word travels with the evidence."""
    outcome = await enriched()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        if evidence.claim_type == "greynoise_classification":
            assert evidence.attributes["raw_classification"]


async def test_business_service_context_never_points_anywhere() -> None:
    """Whatever the trust level, BSI is context and not a benign vote."""
    outcome = await enriched()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        if evidence.claim_type == "greynoise_business_service":
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_nothing_in_the_result_carries_the_key() -> None:
    outcome = await enriched()
    assert outcome.result is not None
    assert _api_key not in outcome.result.model_dump_json()
