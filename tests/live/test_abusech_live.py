"""Optional abuse.ch live smoke tests (Task 10).

**Disabled by default.** Along with the GTI, urlscan, GreyNoise and Censys ones
these are the only tests in the repository that touch a real API, and they stay
off unless explicitly enabled:

.. code-block:: bash

    RUN_ABUSECH_LIVE_TESTS=1 ABUSECH_AUTH_KEY=<your key> uv run pytest tests/live -q

One key covers all three platforms, which is the arrangement being exercised.
Without both variables every test here skips, so a default ``pytest`` run, CI and
pre-commit never contact abuse.ch.

What a full run costs
---------------------

abuse.ch charges nothing and meters nothing per query — but it *is* a free
service with published fair-use limits, and an account that trips them is
blocked for up to 72 hours. A test suite that hammers it is both rude and
self-defeating, so this file is built to make the smallest number of requests
that can prove anything:

===============================  =====================================
Check                            Cost
===============================  =====================================
capability discovery             no request at all
unsupported observable           no request at all
credential acceptance            proved by the shared lookups — 0 extra
every ThreatFox assertion        **one** ``search_ioc``, shared
every URLhaus assertion          **one** ``url`` read, shared
every MalwareBazaar assertion    **one** ``get_info``, shared
each repeat-lookup assertion     served from the Task 6 cache
===============================  =====================================

**A full run performs exactly one physical request per platform — three in
total.**

That is enforced by the code rather than by a comment or by test ordering:
:func:`live_lookup` performs the three lookups once, caches every outcome in a
module-level slot, and every assertion below reads that same set. A test added
later that wants live data uses the same helper and adds nothing to the bill.

Credential validation is deliberately *not* given its own test here. Unlike
GreyNoise's ``/ping`` or Censys's credit endpoint, none of these three APIs has a
zero-cost status endpoint — validating each one separately would double the
suite's request count to prove what a successful lookup already proves.

What these check, and what they deliberately do not
---------------------------------------------------

They check that each platform answers, that what comes back normalizes into TI
Recon models with the right provenance and lineage, that relayed third-party
findings keep somebody else's origin, that nothing excluded by policy reaches an
evidence record, and that an identical request is served from the Task 6 cache.

They do **not** assert that any particular indicator is currently listed.
ThreatFox expires IOCs after about six months, URLhaus URLs go offline and get
de-listed, and MalwareBazaar's holdings change hourly; a test that fails because
an indicator aged out is a test that teaches you to ignore failures. Each
platform's answer is accepted as ``SUCCESS`` or ``NO_DATA``, and the assertions
are about *shape and provenance*, not about today's verdict.

Rules these obey
----------------

Read-only queries only: ``search_ioc``, ``url`` and ``get_info``. No indicator
submission, no URL submission or rescan, no sample upload or download, no
comment, no feed and no bulk or hunting query — the integrations have no code
path for any of those and these tests do not add one. Nothing here contacts a
malicious URL returned by a provider: those values are data. The Auth-Key is
never printed.
"""

from __future__ import annotations

import os
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
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
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
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.abusech import ABUSE_CH_SOURCE_FAMILY, lineage_group_for
from ti_recon.providers.malwarebazaar import (
    MalwareBazaarAdapter,
    build_malwarebazaar_execution_policy,
)
from ti_recon.providers.threatfox import ThreatFoxAdapter, build_threatfox_execution_policy
from ti_recon.providers.urlhaus import UrlhausAdapter, build_urlhaus_execution_policy

RUN_LIVE_ENV_VAR = "RUN_ABUSECH_LIVE_TESTS"
AUTH_KEY_ENV_VAR = "ABUSECH_AUTH_KEY"

#: A routable address that is not anybody's malicious infrastructure and is
#: constantly present in public datasets as a well-known service. Deliberately
#: boring: whether ThreatFox currently lists it is irrelevant, because a miss is
#: an accepted answer.
SMOKE_ADDRESS = "8.8.8.8"

#: A URL on a domain reserved for documentation (RFC 2606). URLhaus will almost
#: certainly not know it, which is fine — ``NO_DATA`` exercises the absence path,
#: and nothing here ever contacts the URL.
SMOKE_URL = "http://example.com/"

#: The SHA-256 of the empty file. A real, stable, universally known digest that
#: is nobody's malware and nobody's investigation, so asking about it discloses
#: nothing.
SMOKE_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

LIVE_USER = "live-analyst"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_auth_key = os.environ.get(AUTH_KEY_ENV_VAR, "")

pytestmark = pytest.mark.skipif(
    not (_enabled and _auth_key),
    reason=(
        f"abuse.ch live tests are off. "
        f"Enable with {RUN_LIVE_ENV_VAR}=1 and {AUTH_KEY_ENV_VAR}=<key>."
    ),
)


def smoke_file() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=SMOKE_HASH,
        display_value=SMOKE_HASH,
        properties={"hashes": {"SHA-256": SMOKE_HASH}},
    )


def request_for(
    subject: str | IntelObject,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=target,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        depth=depth,
    )


# --------------------------------------------------------------------------- #
# Zero-request checks
# --------------------------------------------------------------------------- #


async def test_capability_discovery_makes_no_request() -> None:
    for adapter, capability in (
        (ThreatFoxAdapter(), ProviderCapability.REPUTATION),
        (UrlhausAdapter(), ProviderCapability.REPUTATION),
        (MalwareBazaarAdapter(), ProviderCapability.MALWARE_INTELLIGENCE),
    ):
        discovery = await adapter.discover_capabilities(None)
        assert capability in discovery.capabilities


async def test_an_unsupported_observable_costs_no_request() -> None:
    """MalwareBazaar is a sample repository; a domain has no lookup there."""
    envelope = await MalwareBazaarAdapter().lookup(
        request_for("example.com"), _live_credential("malwarebazaar")
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# The three physical lookups, performed once and shared
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PlatformLookup:
    """The two outcomes of one identical request against one platform.

    ``first`` cost one abuse.ch request. ``second`` cost nothing: it went through
    the same executor, cache and provider connection, so the Task 6 cache
    answered it.
    """

    provider_id: str
    first: ProviderExecutionOutcome
    second: ProviderExecutionOutcome


@dataclass(frozen=True, slots=True)
class LiveLookup:
    """One :class:`PlatformLookup` per platform. Three paid requests in total."""

    threatfox: PlatformLookup
    urlhaus: PlatformLookup
    malwarebazaar: PlatformLookup

    def all(self) -> tuple[PlatformLookup, ...]:
        return (self.threatfox, self.urlhaus, self.malwarebazaar)


#: Computed at most once per session. A module-level slot rather than a fixture
#: because fixture scope and test ordering are exactly the things that must not
#: be able to turn three requests into thirty.
_LOOKUP: LiveLookup | None = None


async def live_lookup() -> LiveLookup:
    """Perform the run's three abuse.ch lookups, or return the cached set."""
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = await _perform_single_lookup()
    return _LOOKUP


def _live_credential(provider_id: str) -> CredentialMaterial:
    """The shared Auth-Key as Task 4 credential material."""
    return CredentialMaterial(
        connection_id="live-connection",
        user_id=LIVE_USER,
        provider_id=provider_id,
        credential_group="abuse_ch",
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(_auth_key),
    )


async def _perform_single_lookup() -> LiveLookup:
    """Every request this file makes, in one place.

    One stored connection, one executor, three providers, and per provider
    exactly one paying execution followed by one that the cache must answer.
    """
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)
    resolver = CredentialResolver(secrets, connections)
    # One key, stored once, for the whole family. Task 4 resolves it by group.
    await manager.create_connection(
        user_id=LIVE_USER,
        provider_id="threatfox",
        secret=SecretStr(_auth_key),
        auth_type=AuthType.AUTH_KEY,
        status=CredentialStatus.ACTIVE,
    )

    executor = ProviderExecutor(
        credential_resolver=resolver,
        cache=InMemoryProviderCache(),
        quota_store=InMemoryQuotaStore(),
        cooldown_store=InMemoryCooldownStore(),
        limiter=ConcurrencyLimiter(max_concurrency=1),
        policies=ProviderPolicyRegistry(
            policies=[
                build_threatfox_execution_policy(),
                build_urlhaus_execution_policy(),
                build_malwarebazaar_execution_policy(),
            ]
        ),
    )
    context = ExecutionContext(authenticated_user_id=LIVE_USER, request_id="live-req")

    plan = (
        ("threatfox", ThreatFoxAdapter(), request_for(SMOKE_ADDRESS)),
        ("urlhaus", UrlhausAdapter(), request_for(SMOKE_URL)),
        ("malwarebazaar", MalwareBazaarAdapter(), request_for(smoke_file())),
    )
    results: dict[str, PlatformLookup] = {}
    for provider_id, adapter, request in plan:
        # The one and only request this file makes to this platform.
        first = await executor.execute(adapter, request, context)
        # Identical request, same executor and cache: this must not reach out.
        second = await executor.execute(adapter, request, context)
        results[provider_id] = PlatformLookup(provider_id=provider_id, first=first, second=second)

    return LiveLookup(
        threatfox=results["threatfox"],
        urlhaus=results["urlhaus"],
        malwarebazaar=results["malwarebazaar"],
    )


async def answered(provider_id: str) -> PlatformLookup:
    """One platform's shared outcome, or a skip if it refused to answer.

    Skipping rather than failing when the account is throttled or blocked: that
    is an account fact, not a defect in the integration.
    """
    lookup = await live_lookup()
    platform = next(item for item in lookup.all() if item.provider_id == provider_id)
    if platform.first.status not in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }:
        pytest.skip(f"{provider_id} returned {platform.first.status.value}")
    return platform


# --------------------------------------------------------------------------- #
# Everything below reads those three lookups
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_the_shared_key_reaches_every_platform(provider_id: str) -> None:
    """One stored Auth-Key, three platforms, no per-provider configuration."""
    platform = await answered(provider_id)
    assert platform.first.provider_id == provider_id
    assert platform.first.status is not ProviderRunStatus.NOT_CONFIGURED
    assert platform.first.attempts >= 1
    assert platform.first.cache_hit is False


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_the_repeat_lookup_costs_no_second_request(provider_id: str) -> None:
    """The Task 6 guarantee, against the real APIs."""
    platform = await answered(provider_id)
    assert platform.second.cache_hit is True
    assert platform.second.attempts == 0
    assert platform.second.called_provider is False


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_an_answer_is_never_ambiguous_about_coverage(provider_id: str) -> None:
    """A miss is ``NO_DATA``: an absence, and never a statement of safety."""
    platform = await answered(provider_id)
    assert platform.first.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }
    if platform.first.status is ProviderRunStatus.NO_DATA:
        assert platform.first.result is not None
        directional = [
            item
            for item in platform.first.result.evidence
            if item.effect is not EvidenceEffect.CONTEXT_ONLY
        ]
        assert directional == []


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_first_hand_evidence_carries_the_shared_family(provider_id: str) -> None:
    platform = await answered(provider_id)
    assert platform.first.result is not None
    for evidence in platform.first.result.evidence:
        assert evidence.transport_provider == provider_id
        if not evidence.is_relayed:
            assert evidence.origin_provider == provider_id
            assert evidence.source_family == ABUSE_CH_SOURCE_FAMILY
            assert evidence.lineage_group_id == lineage_group_for(provider_id)


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_relayed_evidence_keeps_somebody_elses_provenance(provider_id: str) -> None:
    """Whatever a live response relayed, it is not an abuse.ch corroboration."""
    platform = await answered(provider_id)
    assert platform.first.result is not None
    for evidence in platform.first.result.evidence:
        if evidence.is_relayed:
            assert evidence.origin_provider != provider_id
            assert evidence.source_family != ABUSE_CH_SOURCE_FAMILY
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_no_provider_grades_its_own_reliability(provider_id: str) -> None:
    platform = await answered(provider_id)
    assert platform.first.result is not None
    for evidence in platform.first.result.evidence:
        # Admiralty grading is TI Recon policy, never a provider's to claim.
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


@pytest.mark.parametrize("provider_id", ["threatfox", "urlhaus", "malwarebazaar"])
async def test_nothing_in_the_result_carries_the_shared_key(provider_id: str) -> None:
    platform = await answered(provider_id)
    assert platform.first.result is not None
    assert _auth_key not in platform.first.result.model_dump_json()


async def test_no_live_response_smuggles_excluded_content_into_evidence() -> None:
    """The policy exclusions, against whatever the live APIs actually returned."""
    platform = await answered("malwarebazaar")
    assert platform.first.result is not None
    serialized = platform.first.result.model_dump_json()
    for excluded in ("archive_pw", "comment_author", "origin_country", "reporter"):
        assert excluded not in serialized
