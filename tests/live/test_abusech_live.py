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

Community API calls have no per-query monetary charge, but they are
*authenticated* and subject to abuse.ch's fair-use controls — an account that
trips them is blocked until abuse.ch lifts it. A test suite that hammers a free
service is both rude and self-defeating, so this file is built to make the
smallest number of requests that can prove anything:

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

**The targets are deliberately records that exist.** An earlier version asked
about ``8.8.8.8``, ``example.com`` and the empty file — all three of which every
API can legitimately answer with "no record", which meant a green run proved
authentication, caching and the absence path while never once exercising
positive-response normalization. So each platform is now asked about a known
public record instead, and the suite validates real response schemas.

What that must **not** turn into is a suite that fails when a dataset moves.
ThreatFox expires IOCs after about six months, URLhaus URLs go offline, and
MalwareBazaar's holdings change hourly. So the split is:

* every platform's answer is accepted as ``SUCCESS``, ``PARTIAL`` **or**
  ``NO_DATA``, and the provenance, lineage, isolation and caching assertions run
  against whichever of those came back;
* the assertions that need a *record* — a current IOC, a tracked URL, a sample
  — run only when one was returned, and skip themselves otherwise.

A future run against an aged-out IOC therefore reports skips, not failures, and
the value is trivial to refresh: see each ``SMOKE_*`` constant.

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
from typing import Any
from urllib.parse import urlsplit

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
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
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
    MALWAREBAZAAR_PROPERTY_NAMESPACE,
    MalwareBazaarAdapter,
    build_malwarebazaar_execution_policy,
)
from ti_recon.providers.threatfox import ThreatFoxAdapter, build_threatfox_execution_policy
from ti_recon.providers.urlhaus import UrlhausAdapter, build_urlhaus_execution_policy

RUN_LIVE_ENV_VAR = "RUN_ABUSECH_LIVE_TESTS"
AUTH_KEY_ENV_VAR = "ABUSECH_AUTH_KEY"

#: A ThreatFox-listed domain, chosen so a live run exercises positive-response
#: normalization rather than only the absence path.
#:
#: Selected 2026-08-25 from ThreatFox's public recent-IOC export: a
#: ``js.clearfake`` domain at confidence 100. A domain rather than an address on
#: purpose — ThreatFox stores addresses as ``ip:port``, and the loose search that
#: forces is a normalization path with its own unit tests; a live run is a poorer
#: place to exercise it than to exercise a plain exact match.
#:
#: **This value will stop being listed.** ThreatFox drops IOCs from its API after
#: about six months, so expect ``NO_DATA`` from roughly 2027-02 onwards. That is
#: not a failure and the suite does not treat it as one: the positive assertions
#: skip themselves. To refresh it, take any current domain-type IOC from
#: ThreatFox's browse page or public export.
#:
#: It is malicious infrastructure, and it is sent to the ThreatFox API as a
#: *search term* and nowhere else. Nothing here resolves it or contacts it.
SMOKE_IOC = "en-us-en-eloncode.com"

#: The URL from URLhaus's own API documentation for the ``/v1/url/`` endpoint.
#:
#: Their published example, which makes it the value most likely to keep
#: returning a record: URLhaus keeps historical entries after a URL goes offline
#: rather than de-listing it.
#:
#: This is a real malware-distribution URL. It travels to the URLhaus API as
#: lookup data and nothing else — **TI Recon never contacts a URL a provider
#: reports, including this one.** There is no code path that could: the transport
#: is pinned to ``urlhaus-api.abuse.ch``.
SMOKE_URL = (
    "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"
)

#: A SHA-256 with a MalwareBazaar record, so a live run normalizes a real sample.
#:
#: Selected 2026-08-25 from MalwareBazaar's public recent-samples export: a
#: signature-attributed PE. MalwareBazaar keeps what it accepts, so unlike the
#: ThreatFox IOC this is not expected to age out.
#:
#: Only ``get_info`` is ever called with it. The sample itself is never
#: requested — there is no client method that could request it — and nothing
#: here writes a byte of it anywhere.
SMOKE_HASH = "a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684"

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
        ("threatfox", ThreatFoxAdapter(), request_for(SMOKE_IOC)),
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


# --------------------------------------------------------------------------- #
# Positive records: real response schemas
# --------------------------------------------------------------------------- #
#
# These read the same three shared outcomes — they add no request. They are the
# half of the suite that only runs when a record actually came back, so a dataset
# that has moved on produces skips rather than failures.


async def with_a_record(provider_id: str) -> Any:
    """One platform's outcome, or a skip if it had nothing to normalize.

    ``NO_DATA`` is a legitimate answer from every one of these APIs — see the
    module docstring — so it skips here rather than failing. What must not happen
    is a green run that silently never exercised a positive response, which is
    why these assertions exist at all.
    """
    platform = await answered(provider_id)
    if platform.first.status is ProviderRunStatus.NO_DATA:
        pytest.skip(
            f"{provider_id} has no current record for the smoke target; "
            f"positive-response assertions skipped"
        )
    assert platform.first.result is not None
    return platform.first.result


def claim(result: Any, claim_type: str) -> Any:
    return next((item for item in result.evidence if item.claim_type == claim_type), None)


def claims_of(result: Any) -> set[str]:
    """Every claim type in a result, so a missing one fails informatively."""
    return {item.claim_type for item in result.evidence}


# --- ThreatFox ------------------------------------------------------------- #


async def test_a_listed_ioc_produces_a_current_ioc_assertion() -> None:
    result = await with_a_record("threatfox")
    ioc = claim(result, "threatfox_ioc")
    assert ioc is not None, f"listed IOC produced no assertion: {sorted(claims_of(result))}"
    assert ioc.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert ioc.effect is EvidenceEffect.SUPPORTS_MALICIOUS


async def test_a_listed_domain_matches_the_observable_exactly() -> None:
    """A domain is stored as itself, so the match needs no re-validation."""
    ioc = claim(await with_a_record("threatfox"), "threatfox_ioc")
    assert ioc is not None
    assert ioc.match_scope is MatchScope.EXACT_OBSERVABLE


async def test_a_positive_ioc_carries_threatfox_provenance() -> None:
    ioc = claim(await with_a_record("threatfox"), "threatfox_ioc")
    assert ioc is not None
    assert ioc.transport_provider == "threatfox"
    assert ioc.origin_provider == "threatfox"
    assert ioc.source_family == ABUSE_CH_SOURCE_FAMILY
    assert ioc.lineage_group_id == lineage_group_for("threatfox")
    assert ioc.is_relayed is False


async def test_the_six_month_horizon_is_recorded_on_a_hit_too() -> None:
    """An analyst reading a ThreatFox answer needs its blind spot either way."""
    coverage = claim(await with_a_record("threatfox"), "threatfox_coverage")
    assert coverage is not None
    assert coverage.attributes["current_api_only"] is True
    assert coverage.attributes["expiration_horizon_months"] == 6
    assert coverage.attributes["matched_records"] >= 1
    assert coverage.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_listed_ioc_is_one_assertion_however_many_records_matched() -> None:
    """Several reporters inside one platform are not several providers."""
    result = await with_a_record("threatfox")
    directional = [
        item for item in result.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]
    assert len(directional) == 1


# --- URLhaus --------------------------------------------------------------- #


async def test_a_tracked_url_produces_an_exact_url_assertion() -> None:
    result = await with_a_record("urlhaus")
    record = claim(result, "urlhaus_malware_url")
    assert record is not None, f"tracked URL produced no assertion: {sorted(claims_of(result))}"
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    # The strongest thing URLhaus says: this artifact, not its host.
    assert record.match_scope is MatchScope.EXACT_OBSERVABLE


async def test_an_offline_url_is_still_malicious_evidence() -> None:
    """This URL is years old and long dead. History, not absolution."""
    record = claim(await with_a_record("urlhaus"), "urlhaus_malware_url")
    assert record is not None
    status = record.attributes.get("url_status")
    if status is None:
        pytest.skip("URLhaus returned no url_status for the smoke target")
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.effect is not EvidenceEffect.SUPPORTS_BENIGN


async def test_a_tracked_url_is_reported_as_data_and_never_fetched() -> None:
    """Provider content is data. The record describes the URL; nothing dials it.

    The structural guarantee is the transport's, not this test's — the client is
    pinned to ``urlhaus-api.abuse.ch`` and a path leaving it raises. What this
    adds is that a *live* response, whose fields and related URLs are entirely
    provider-controlled, did not change that: the host is parsed locally from the
    observable we submitted, and nothing in the result carries retrieved content.

    Note what is deliberately absent from the attributes: the URL itself. It is
    the observable under investigation, already the subject the evidence attaches
    to, and copying it into the claim would only invite something downstream to
    treat a stored string as a place to go.
    """
    result = await with_a_record("urlhaus")
    record = claim(result, "urlhaus_malware_url")
    assert record is not None
    assert result.provider == "urlhaus"

    host = record.attributes.get("host")
    if host is not None:
        assert host == urlsplit(SMOKE_URL).hostname

    # Nothing was retrieved to store: no raw reference on the envelope, none on
    # any piece of evidence, and no embedded bytes anywhere in it. urlscan is the
    # only integration that stores artifacts, and only on an explicit request;
    # URLhaus has no such path and this proves a live response did not open one.
    assert result.raw_reference is None
    assert all(evidence.raw_reference_id is None for evidence in result.evidence)
    assert "base64," not in result.model_dump_json()


async def test_a_relayed_finding_in_a_live_response_keeps_its_own_origin() -> None:
    """A real record often carries VirusTotal and blocklist data. None is ours."""
    result = await with_a_record("urlhaus")
    relayed = [item for item in result.evidence if item.is_relayed]
    if not relayed:
        pytest.skip("URLhaus returned no relayed third-party context")
    for evidence in relayed:
        assert evidence.transport_provider == "urlhaus"
        assert evidence.origin_provider != "urlhaus"
        assert evidence.source_family != ABUSE_CH_SOURCE_FAMILY
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


# --- MalwareBazaar --------------------------------------------------------- #


async def test_a_known_sample_produces_a_sample_record() -> None:
    result = await with_a_record("malwarebazaar")
    record = claim(result, "malwarebazaar_sample_record")
    assert record is not None, f"known sample produced no record: {sorted(claims_of(result))}"
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.match_scope is MatchScope.EXACT_OBSERVABLE


async def test_the_live_hash_metadata_normalizes() -> None:
    """The digest we asked with comes back as a digest, not as provider text."""
    record = claim(await with_a_record("malwarebazaar"), "malwarebazaar_sample_record")
    assert record is not None
    assert record.attributes["sha256_hash"] == SMOKE_HASH
    for field in ("sha1_hash", "md5_hash"):
        digest = record.attributes.get(field)
        if digest is not None:
            assert digest == digest.lower()
            assert len(digest) in {32, 40}


async def test_the_live_sample_lands_on_one_file_object() -> None:
    """Three digests identify one file; three objects would fracture it."""
    result = await with_a_record("malwarebazaar")
    files = [item for item in result.objects if item.object_type is IntelObjectType.FILE]
    assert len(files) == 1
    namespace = files[0].properties[MALWAREBAZAAR_PROPERTY_NAMESPACE]
    assert namespace["sha256_hash"] == SMOKE_HASH


async def test_a_live_sample_record_is_still_one_assertion() -> None:
    """Whatever YARA, signing and vendor detail arrived, it is one finding."""
    result = await with_a_record("malwarebazaar")
    directional = [
        item for item in result.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]
    assert len(directional) == 1
    assert directional[0].claim_type == "malwarebazaar_sample_record"


async def test_live_vendor_intel_is_named_and_never_counted() -> None:
    """A real record usually relays several sandboxes. They stay one context row."""
    result = await with_a_record("malwarebazaar")
    summary = claim(result, "malwarebazaar_vendor_intel_summary")
    if summary is None:
        pytest.skip("MalwareBazaar returned no vendor_intel for the smoke target")
    assert summary.effect is EvidenceEffect.CONTEXT_ONLY
    assert summary.origin_provider != "malwarebazaar"
    assert summary.attributes["sources"]


async def test_no_sample_bytes_are_ever_retrieved() -> None:
    """``get_info`` is metadata. The sample is never asked for or written.

    Three ways: the read-only client protocol has no method that could fetch
    one, the permitted query set holds exactly the one that cannot, and the
    normalized result of a real lookup carries no file content.
    """
    from ti_recon.providers.malwarebazaar import ALLOWED_QUERIES
    from ti_recon.providers.malwarebazaar.client import MalwareBazaarHttpClient

    assert ALLOWED_QUERIES == {"get_info"}
    surface = {name for name in dir(MalwareBazaarHttpClient) if not name.startswith("_")}
    for forbidden in ("get_file", "download", "upload", "submit"):
        assert forbidden not in surface

    result = await with_a_record("malwarebazaar")
    serialized = result.model_dump_json()
    for byte_bearing in ("file_content", "base64", "data:application", "MZ\\u0090"):
        assert byte_bearing not in serialized
