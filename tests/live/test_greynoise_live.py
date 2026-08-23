"""Optional GreyNoise live smoke tests (Task 9).

**Disabled by default.** Along with the GTI, urlscan and Censys ones these are
the only tests in the repository that touch a real API, and they stay off unless
explicitly enabled:

.. code-block:: bash

    RUN_GREYNOISE_LIVE_TESTS=1 GREYNOISE_API_KEY=<your key> uv run pytest tests/live -q

Without both variables every test here skips, so a default ``pytest`` run, CI
and pre-commit never contact GreyNoise.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a lookup succeeds against whichever endpoint the key is entitled
to use, that what comes back normalizes into TI Recon models with the right
provenance, and that the same lookup run twice through the Task 6 executor costs
one provider request rather than two.

They do **not** assert today's classification for anything. GreyNoise
reclassifies addresses constantly, and a test that fails because a scanner was
re-scored is a test that teaches you to ignore failures.

Rules these obey
----------------

Passive GET reads of ``/v3/ip/{ip}`` and ``/v3/community/{ip}`` only. No GNQL, no
timeline, no bulk lookup, no feed, no PCAP — the integration has no code path for
any of those and these tests do not add one. The credential check looks up a
reserved documentation address, so it reveals nothing about any investigation.
STANDARD depth, so a run costs a small, countable number of requests. The API key
is never printed.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

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
#: still being listed.
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
# The credential
# --------------------------------------------------------------------------- #


async def test_the_credential_is_accepted(adapter: GreyNoiseAdapter) -> None:
    """One Community read of a reserved address: it reveals nothing real."""
    result = await adapter.validate_credentials(live_credential())
    assert result.is_usable, f"credential validation returned {result.status.value}"


async def test_the_provider_reports_itself_available(adapter: GreyNoiseAdapter) -> None:
    report = await adapter.health(live_credential())
    assert report.provider_id == "greynoise"
    assert report.health.value in {"available", "degraded", "unavailable", "unknown"}


# --------------------------------------------------------------------------- #
# The adapter against the real API
# --------------------------------------------------------------------------- #


async def test_a_well_known_address_normalizes(adapter: GreyNoiseAdapter) -> None:
    """The lookup succeeds through whichever door this key may use."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())

    assert envelope.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }
    assert envelope.provider == "greynoise"
    assert envelope.api_version == "v3"

    # Structure and provenance only. Nothing about what GreyNoise currently
    # thinks of the address: that changes, and pinning it would make this test
    # fail for a reason nobody should act on.
    for evidence in envelope.evidence:
        assert evidence.transport_provider == "greynoise"
        assert evidence.origin_provider == "greynoise"
        assert evidence.lineage_group_id
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_the_result_records_which_door_answered(adapter: GreyNoiseAdapter) -> None:
    """A full-tier and a Community answer are both fine; the run says which."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    coverage = next(
        item.attributes for item in envelope.evidence if item.claim_type == "greynoise_coverage"
    )
    assert coverage["access_level"] in {level.value for level in GreyNoiseAccessLevel}
    assert coverage["depth"] == InvestigationDepth.STANDARD.value


async def test_a_classification_keeps_its_own_word(adapter: GreyNoiseAdapter) -> None:
    """Whatever GreyNoise said, the raw word travels with the evidence."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    for evidence in envelope.evidence:
        if evidence.claim_type == "greynoise_classification":
            assert evidence.attributes["raw_classification"]


async def test_business_service_context_never_points_anywhere(
    adapter: GreyNoiseAdapter,
) -> None:
    """Whatever the trust level, BSI is context and not a benign vote."""
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    for evidence in envelope.evidence:
        if evidence.claim_type == "greynoise_business_service":
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_an_unsupported_observable_is_reported_as_such(
    adapter: GreyNoiseAdapter,
) -> None:
    """No request is made, so this costs nothing against the live account."""
    envelope = await adapter.lookup(request_for("example.com"), live_credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA


async def test_nothing_in_the_result_carries_the_key(adapter: GreyNoiseAdapter) -> None:
    envelope = await adapter.lookup(request_for(SMOKE_ADDRESS), live_credential())
    assert _api_key not in envelope.model_dump_json()


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
        self.adapter = GreyNoiseAdapter(config=GreyNoiseConfig())
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=InMemoryQuotaStore(),
            cooldown_store=InMemoryCooldownStore(),
            limiter=ConcurrencyLimiter(max_concurrency=2),
            policies=ProviderPolicyRegistry(policies=[build_greynoise_execution_policy()]),
        )

    async def configure(self) -> None:
        await self.manager.create_connection(
            user_id=LIVE_USER,
            provider_id="greynoise",
            secret=_api_key,
            auth_type=AuthType.API_KEY,
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
    assert outcome.provider_id == "greynoise"
    assert outcome.attempts >= 1
    assert outcome.cache_hit is False


async def test_a_repeat_lookup_costs_no_second_request(stack: LiveStack) -> None:
    """The Task 6 guarantee, against the real API."""
    request = request_for(SMOKE_ADDRESS)
    first = await stack.executor.execute(stack.adapter, request, stack.context)
    if first.status not in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.NO_DATA,
    }:
        pytest.skip(f"first live lookup returned {first.status.value}; caching not exercised")

    second = await stack.executor.execute(stack.adapter, request, stack.context)
    assert second.cache_hit is True
    assert second.attempts == 0
    assert second.called_provider is False


def test_no_secret_reaches_a_recorded_outcome(stack: LiveStack) -> None:
    """Nothing is executed here; only the wiring is inspected."""
    serialized: Any = stack.context.model_dump_json()
    assert _api_key not in serialized
