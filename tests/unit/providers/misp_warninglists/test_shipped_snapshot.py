"""The snapshot the repository actually ships (Task 11).

The other suites pin *semantics* against synthetic fixtures on purpose: a matcher
test should fail because the matcher is wrong, not because upstream re-ranked a
domain. This one is the counterweight — it checks the shipped dataset is real,
loadable, and still contains the values those fixtures model, so the fixtures
cannot drift into fiction unnoticed.

Deliberately tolerant about *content*. Upstream moves daily and this snapshot
will be refreshed; a test asserting an exact list count would fail every refresh
and teach everyone to ignore it. What is asserted is structure, provenance, and a
handful of anchors that have been stable for years — RFC1918, RFC6761, the
empty-file hashes.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.misp_warninglists import (
    COVERAGE_CLAIM_TYPE,
    DEFAULT_SNAPSHOT_ROOT,
    MATCHER_SUPPORT,
    MATCHES_CLAIM_TYPE,
    MispWarningListsAdapter,
    load_snapshot,
)

pytestmark = pytest.mark.skipif(
    not (DEFAULT_SNAPSHOT_ROOT / "manifest.json").is_file(),
    reason="no shipped warninglist snapshot in this checkout",
)

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture(scope="module")
def adapter() -> MispWarningListsAdapter:
    """One adapter for the whole module: the dataset loads once."""
    return MispWarningListsAdapter()


def request_for(subject: str | IntelObject) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=target,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
    )


def matched_lists(envelope: object) -> list[str]:
    record = next(
        (
            item
            for item in envelope.evidence  # type: ignore[attr-defined]
            if item.claim_type == MATCHES_CLAIM_TYPE
        ),
        None,
    )
    return [] if record is None else list(record.attributes["matched_lists"])


# --------------------------------------------------------------------------- #
# It is a real, verified snapshot
# --------------------------------------------------------------------------- #


def test_the_shipped_snapshot_records_its_upstream_provenance() -> None:
    manifest = load_snapshot(DEFAULT_SNAPSHOT_ROOT).manifest
    assert manifest.upstream_repository == "https://github.com/MISP/misp-warninglists"
    assert len(manifest.upstream_commit) == 40
    assert manifest.upstream_commit != "0" * 40
    assert manifest.generator.startswith("tools/update_misp_warninglists.py")
    assert manifest.license == "CC0-1.0"


def test_every_shipped_list_verifies_against_its_checksum() -> None:
    """Reads the whole dataset. Slow-ish, and the point of shipping checksums."""
    snapshot = load_snapshot(DEFAULT_SNAPSHOT_ROOT)
    for record in snapshot.manifest.lists:
        raw = snapshot.read_list(record)
        assert raw.type in MATCHER_SUPPORT
        assert len(raw.list) == record.entry_count


def test_the_shipped_snapshot_loads_without_a_single_unusable_list(
    adapter: MispWarningListsAdapter,
) -> None:
    assert adapter.index is not None
    assert adapter.index.unusable == ()
    assert adapter.index.diagnostics.malformed_list_count == 0
    assert adapter.index.diagnostics.invalid_cidr_count == 0


def test_the_default_profile_bounds_the_shipped_snapshot(
    adapter: MispWarningListsAdapter,
) -> None:
    """Measured, and reported rather than implied."""
    assert adapter.index is not None
    assert adapter.snapshot is not None
    loaded = len(adapter.index.lists)
    assert loaded > 50
    assert loaded < adapter.snapshot.manifest.list_count
    assert adapter.index.profile_excluded
    # The build itself omitted the million-entry rankings; both are recorded.
    assert adapter.index.snapshot_omitted


def test_the_omitted_lists_are_the_oversized_ones(
    adapter: MispWarningListsAdapter,
) -> None:
    assert adapter.index is not None
    for omission in adapter.index.snapshot_omitted:
        assert omission.entry_count > 100_000
        assert omission.reason == "oversized_at_build"


# --------------------------------------------------------------------------- #
# The anchors the synthetic fixtures model
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("observable", "expected_list"),
    [
        ("8.8.8.8", "public-dns-v4"),
        ("10.0.0.1", "rfc1918"),
        ("192.168.1.5", "rfc1918"),
        ("162.142.125.5", "censys-scanning"),
        ("2001:4860:4860::8888", "public-dns-v6"),
        ("example.com", "rfc6761"),
        ("foo.dynv6.net", "dynamic-dns"),
    ],
)
async def test_a_stable_upstream_anchor_still_matches(
    adapter: MispWarningListsAdapter, observable: str, expected_list: str
) -> None:
    """If one of these stops matching, the fixtures need re-checking, not the code."""
    envelope = await adapter.lookup(request_for(observable), None)
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert expected_list in matched_lists(envelope)


async def test_the_empty_file_hashes_match_through_all_three_algorithms(
    adapter: MispWarningListsAdapter,
) -> None:
    for algorithm, digest in (
        ("MD5", EMPTY_MD5),
        ("SHA-1", EMPTY_SHA1),
        ("SHA-256", EMPTY_SHA256),
    ):
        subject = IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.FILE,
            canonical_value=digest,
            display_value=digest,
            properties={"hashes": {algorithm: digest}},
        )
        envelope = await adapter.lookup(request_for(subject), None)
        assert envelope.status is ProviderRunStatus.SUCCESS, algorithm
        assert "empty-hashes" in matched_lists(envelope), algorithm


async def test_a_boundary_miss_is_still_a_miss_against_real_data(
    adapter: MispWarningListsAdapter,
) -> None:
    envelope = await adapter.lookup(request_for("evil-example.com"), None)
    assert envelope.status is ProviderRunStatus.NO_DATA


async def test_a_url_on_a_common_host_reports_host_scope_against_real_data(
    adapter: MispWarningListsAdapter,
) -> None:
    """The living-off-trusted-sites case, against the shipped lists."""
    envelope = await adapter.lookup(request_for("https://github.com/attacker/payload.exe"), None)
    assert envelope.status is ProviderRunStatus.SUCCESS
    record = next(item for item in envelope.evidence if item.claim_type == MATCHES_CLAIM_TYPE)
    assert record.match_scope is MatchScope.SAME_HOST
    assert record.attributes["host_component_only"] is True
    assert record.effect is EvidenceEffect.CONTEXT_ONLY
    # `lots-project` is upstream's living-off-trusted-sites list.
    assert "lots-project" in matched_lists(envelope)


# --------------------------------------------------------------------------- #
# Regex, against the real dataset
# --------------------------------------------------------------------------- #


def test_the_shipped_regex_lists_target_attributes_we_cannot_produce(
    adapter: MispWarningListsAdapter,
) -> None:
    """The measurement behind not implementing a regex engine.

    Both regex lists in the pinned snapshot are about email and phone
    attributes. If a future refresh adds one about domains, this test fails and
    the decision gets revisited — which is exactly when it should be.
    """
    assert adapter.index is not None
    regex_lists = [item for item in adapter.index.lists if item.matcher == "regex"]
    assert regex_lists, "expected the pinned snapshot to contain regex lists"
    ours = frozenset(
        {"ip-src", "ip-dst", "domain", "hostname", "url", "uri", "md5", "sha1", "sha256"}
    )
    for item in regex_lists:
        assert item.attribute_types is not None
        assert not (item.attribute_types & ours), item.slug


@pytest.mark.parametrize("observable", ["8.8.8.8", "example.com", "https://example.com/a"])
async def test_a_lookup_is_fully_covered_despite_the_regex_lists(
    adapter: MispWarningListsAdapter, observable: str
) -> None:
    """No applicable regex list means no partiality and no execution."""
    envelope = await adapter.lookup(request_for(observable), None)
    assert envelope.status is not ProviderRunStatus.PARTIAL
    coverage = next(item for item in envelope.evidence if item.claim_type == COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["unsupported_applicable_lists"] == 0
    assert "regex" not in coverage.attributes["matcher_types_available"]
    assert "partial_reason" not in coverage.attributes


async def test_coverage_never_claims_it_checked_everything(
    adapter: MispWarningListsAdapter,
) -> None:
    """Both the profile and the build leave lists out, so this must be false."""
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    coverage = next(item for item in envelope.evidence if item.claim_type == COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["all_lists_checked"] is False
    assert coverage.attributes["profile_excluded_lists"] > 0
    assert coverage.attributes["snapshot_omitted_lists"] > 0
