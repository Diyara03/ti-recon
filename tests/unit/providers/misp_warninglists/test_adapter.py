"""The warninglist adapter's semantics (Task 11).

The invariant every test here defends: a warninglist match is **context**, and a
clean lookup means only that nothing in the configured lists matched. Neither is
a statement about whether an observable is safe.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from fixtures.warninglists import build_snapshot
from ti_recon.enums import (
    ActivityMode,
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
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.misp_warninglists import (
    COVERAGE_CLAIM_TYPE,
    MATCHES_CLAIM_TYPE,
    MISP_WARNINGLISTS_NOT_SUPPORTED,
    MISP_WARNINGLISTS_PROVIDER_ID,
    MISP_WARNINGLISTS_SOURCE_FAMILY,
    NO_MATCH_CLAIM_TYPE,
    SNAPSHOT_UNAVAILABLE,
    MispWarningListsAdapter,
    MispWarningListsConfig,
    WarningListProfile,
    core_profile,
    lineage_group_for_dataset,
)

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture
def adapter(tmp_path: Path) -> MispWarningListsAdapter:
    """An adapter over a small snapshot of real values, no profile bounds."""
    build_snapshot(tmp_path / "snapshot")
    return MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=tmp_path / "snapshot"),
        profile=WarningListProfile(profile_id="test", max_list_entries=None),
    )


def file_object(hashes: dict[str, str], **properties: object) -> IntelObject:
    strongest = hashes.get("SHA-256") or hashes.get("SHA-1") or next(iter(hashes.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": hashes, **properties},
    )


def request_for(subject: str | IntelObject, **overrides: Any) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": target,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def evidence_of(envelope: Any, claim_type: str) -> Any:
    return next((item for item in envelope.evidence if item.claim_type == claim_type), None)


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


# --------------------------------------------------------------------------- #
# Descriptor and registration
# --------------------------------------------------------------------------- #


def test_the_provider_needs_no_credential(adapter: MispWarningListsAdapter) -> None:
    """The whole point: available offline, during triage, with no key."""
    assert adapter.descriptor.requires_credentials is False


def test_the_provider_serves_false_positive_context_and_not_reputation(
    adapter: MispWarningListsAdapter,
) -> None:
    """A planner asking for reputation wants an opinion this provider lacks."""
    capabilities = adapter.descriptor.capabilities
    assert capabilities == frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT})
    assert ProviderCapability.REPUTATION not in capabilities


def test_nothing_active_is_declared(adapter: MispWarningListsAdapter) -> None:
    assert adapter.descriptor.supports_active is False
    assert adapter.descriptor.supports_batch is False
    assert adapter.descriptor.supports_passive is True


def test_the_dataset_version_carries_the_snapshot_and_profile(
    adapter: MispWarningListsAdapter,
) -> None:
    """Both halves, so neither a refresh nor a profile change can serve stale answers."""
    version = adapter.descriptor.dataset_version
    assert adapter.index is not None
    assert adapter.snapshot is not None
    assert version == adapter.index.profile_identity
    assert version is not None
    profile_part, snapshot_part = version.split(":")
    assert adapter.profile.fingerprint().startswith(profile_part)
    assert adapter.snapshot.manifest.dataset_fingerprint.startswith(snapshot_part)


def test_the_provider_is_discoverable_by_capability(adapter: MispWarningListsAdapter) -> None:
    registry = ProviderRegistry([adapter])
    for object_type in (
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    ):
        matches = registry.find_compatible(object_type, ProviderCapability.FALSE_POSITIVE_CONTEXT)
        assert [item.descriptor.provider_id for item in matches] == [MISP_WARNINGLISTS_PROVIDER_ID]


# --------------------------------------------------------------------------- #
# Every hit is context
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
async def test_a_known_value_produces_context_and_only_context(
    adapter: MispWarningListsAdapter, observable: str, expected_list: str
) -> None:
    envelope = await adapter.lookup(request_for(observable), None)
    assert envelope.status is ProviderRunStatus.SUCCESS
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    assert expected_list in matches.attributes["matched_lists"]
    assert matches.evidence_class is EvidenceClass.CONTEXT
    assert matches.effect is EvidenceEffect.CONTEXT_ONLY


async def test_no_warninglist_finding_ever_points_anywhere(
    adapter: MispWarningListsAdapter,
) -> None:
    """Not benign, not malicious. Every record, every observable."""
    subjects = [
        request_for("8.8.8.8"),
        request_for("10.0.0.1"),
        request_for("example.com"),
        request_for("https://github.com/a/b"),
        request_for(file_object({"MD5": EMPTY_MD5})),
        request_for("no-warninglist-knows-this.example"),
    ]
    for request in subjects:
        envelope = await adapter.lookup(request, None)
        assert envelope.evidence
        for item in envelope.evidence:
            assert item.evidence_class is EvidenceClass.CONTEXT
            assert item.effect is EvidenceEffect.CONTEXT_ONLY
            assert item.effect is not EvidenceEffect.SUPPORTS_BENIGN
            assert item.effect is not EvidenceEffect.SUPPORTS_MALICIOUS


async def test_an_eicar_hash_is_a_test_artifact_not_a_benign_file(
    adapter: MispWarningListsAdapter,
) -> None:
    envelope = await adapter.lookup(request_for(file_object({"MD5": EICAR_MD5})), None)
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    assert "eicar.com" in matches.attributes["matched_lists"]
    assert matches.effect is EvidenceEffect.CONTEXT_ONLY


async def test_the_provider_never_grades_its_own_reliability(
    adapter: MispWarningListsAdapter,
) -> None:
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    for item in envelope.evidence:
        assert item.source_reliability is None
        assert item.information_credibility is None
        assert item.provider_confidence is None


# --------------------------------------------------------------------------- #
# One finding, one lineage
# --------------------------------------------------------------------------- #


async def test_several_matching_lists_produce_one_finding(
    adapter: MispWarningListsAdapter,
) -> None:
    """`example.com` matches two lists here. That is one contextual fact."""
    envelope = await adapter.lookup(request_for("example.com"), None)
    assert [item.claim_type for item in envelope.evidence].count(MATCHES_CLAIM_TYPE) == 1
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    assert set(matches.attributes["matched_lists"]) >= {"rfc6761", "cloudflare-top10k"}
    assert matches.attributes["total_matches"] >= 2


async def test_every_record_shares_one_dataset_lineage_group(
    adapter: MispWarningListsAdapter,
) -> None:
    """rfc1918 and public-dns-v4 are not two providers agreeing."""
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    assert adapter.snapshot is not None
    expected = lineage_group_for_dataset(adapter.snapshot.manifest.dataset_fingerprint)
    for item in envelope.evidence:
        assert item.lineage_group_id == expected
        assert item.transport_provider == MISP_WARNINGLISTS_PROVIDER_ID
        assert item.origin_provider == MISP_WARNINGLISTS_PROVIDER_ID
        assert item.source_family == MISP_WARNINGLISTS_SOURCE_FAMILY


async def test_a_list_matched_through_two_candidates_is_reported_once(
    adapter: MispWarningListsAdapter,
) -> None:
    """A domain is offered as both `domain` and `hostname`; that is one artifact."""
    envelope = await adapter.lookup(request_for("example.com"), None)
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    slugs = [record["list"] for record in matches.attributes["matches"]]
    assert len(slugs) == len(set(slugs))


async def test_a_file_matched_through_three_hashes_is_reported_once_per_list(
    adapter: MispWarningListsAdapter,
) -> None:
    envelope = await adapter.lookup(
        request_for(file_object({"MD5": EMPTY_MD5, "SHA-1": EMPTY_SHA1, "SHA-256": EMPTY_SHA256})),
        None,
    )
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    slugs = [record["list"] for record in matches.attributes["matches"]]
    assert slugs.count("empty-hashes") == 1
    assert "matched_by_hash" in matches.attributes["matches"][0]


# --------------------------------------------------------------------------- #
# The URL host distinction
# --------------------------------------------------------------------------- #


async def test_a_url_host_match_is_never_a_statement_about_the_url(
    adapter: MispWarningListsAdapter,
) -> None:
    """The living-off-trusted-sites case, which this provider must not blur.

    A malicious payload hosted on github.com matches a popular-domain list
    *through its host*. Reporting that at exact-artifact scope would say the
    payload is common software.
    """
    envelope = await adapter.lookup(request_for("https://github.com/attacker/payload.exe"), None)
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    assert matches.match_scope is MatchScope.SAME_HOST
    assert matches.match_scope is not MatchScope.EXACT_OBSERVABLE
    assert matches.attributes["host_component_only"] is True
    assert matches.effect is EvidenceEffect.CONTEXT_ONLY
    for record in matches.attributes["matches"]:
        assert record["candidate_component"] == "url_host"
        assert record["match_scope"] == MatchScope.SAME_HOST.value


async def test_a_url_path_or_query_never_becomes_a_hostname_match(
    adapter: MispWarningListsAdapter,
) -> None:
    """`?ref=github.com` is not hosted on GitHub."""
    envelope = await adapter.lookup(
        request_for("http://not-in-any-list.example/?ref=github.com"), None
    )
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert MATCHES_CLAIM_TYPE not in claims(envelope)


async def test_an_exact_url_match_keeps_exact_scope(
    tmp_path: Path,
) -> None:
    """When a list really is about the whole URL, the scope says so."""
    from fixtures.warninglists import SnapshotBuilder

    root = tmp_path / "snapshot"
    SnapshotBuilder(root=root).add(
        "exact-urls",
        matcher="string",
        entries=["https://example.com/a"],
        matching_attributes=["url"],
    ).write()
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=root),
        profile=WarningListProfile(profile_id="test", max_list_entries=None),
    )
    envelope = await adapter.lookup(request_for("https://example.com/a"), None)
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    assert matches.match_scope is MatchScope.EXACT_OBSERVABLE
    assert matches.attributes["host_component_only"] is False


# --------------------------------------------------------------------------- #
# No match is not benign
# --------------------------------------------------------------------------- #


async def test_no_match_is_no_data_and_says_it_is_not_benign(
    adapter: MispWarningListsAdapter,
) -> None:
    """Most values an analyst submits are in no warninglist at all."""
    envelope = await adapter.lookup(request_for("nothing-knows-this-host.example"), None)
    assert envelope.status is ProviderRunStatus.NO_DATA
    record = evidence_of(envelope, NO_MATCH_CLAIM_TYPE)
    assert record is not None
    assert record.attributes["matched"] is False
    assert record.attributes["means_benign"] is False
    assert record.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_clean_lookup_still_reports_what_it_covered(
    adapter: MispWarningListsAdapter,
) -> None:
    """Otherwise 'nothing matched' and 'nothing was checked' look identical."""
    envelope = await adapter.lookup(request_for("nothing-knows-this-host.example"), None)
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["applicable_lists"] > 0
    assert coverage.attributes["checked_lists"] > 0
    assert coverage.attributes["total_matches"] == 0


async def test_a_boundary_miss_is_a_miss(adapter: MispWarningListsAdapter) -> None:
    """`evil-example.com` is not `example.com`, end to end."""
    envelope = await adapter.lookup(request_for("evil-example.com"), None)
    assert envelope.status is ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# Depth changes presentation, never coverage
# --------------------------------------------------------------------------- #


async def test_every_depth_checks_the_same_lists(
    adapter: MispWarningListsAdapter,
) -> None:
    """A QUICK lookup consulting fewer lists would answer a different question.

    Asserted as equality across depths rather than against a fixed number: the
    property under test is that coverage does not vary, and a hardcoded count
    would only be testing the fixture.
    """
    seen: set[tuple[int, int, int]] = set()
    for depth in InvestigationDepth:
        envelope = await adapter.lookup(request_for("example.com", depth=depth), None)
        coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
        matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
        assert coverage is not None
        assert matches is not None
        seen.add(
            (
                coverage.attributes["applicable_lists"],
                coverage.attributes["checked_lists"],
                matches.attributes["total_matches"],
            )
        )
    assert len(seen) == 1
    applicable, checked, _ = seen.pop()
    assert applicable == checked > 0


async def test_depth_bounds_rendered_records_and_records_the_truncation(
    tmp_path: Path,
) -> None:
    from fixtures.warninglists import SnapshotBuilder

    root = tmp_path / "snapshot"
    builder = SnapshotBuilder(root=root)
    for index in range(30):
        builder.add(
            f"list-{index:02d}",
            matcher="string",
            entries=["crowded.example"],
            matching_attributes=["domain"],
        )
    builder.write()
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=root),
        profile=WarningListProfile(profile_id="test", max_list_entries=None),
    )
    for depth, expected in (
        (InvestigationDepth.QUICK, 10),
        (InvestigationDepth.STANDARD, 25),
        (InvestigationDepth.DEEP, 30),
    ):
        envelope = await adapter.lookup(request_for("crowded.example", depth=depth), None)
        matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
        assert matches is not None
        assert matches.attributes["total_matches"] == 30
        assert len(matches.attributes["matches"]) == expected
        assert matches.attributes["truncated"] is (expected < 30)
        # The full set of matched lists survives truncation.
        assert len(matches.attributes["matched_lists"]) == 30


# --------------------------------------------------------------------------- #
# Refusals and hygiene
# --------------------------------------------------------------------------- #


async def test_an_unsupported_observable_is_reported_not_guessed_at(
    adapter: MispWarningListsAdapter,
) -> None:
    certificate = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.X509_CERTIFICATE,
        canonical_value="a" * 40,
        display_value="a" * 40,
    )
    envelope = await adapter.lookup(request_for(certificate), None)
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert MISP_WARNINGLISTS_NOT_SUPPORTED in envelope.warnings
    assert envelope.evidence == ()


async def test_an_active_request_is_refused(adapter: MispWarningListsAdapter) -> None:
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request_for("8.8.8.8", activity_mode=ActivityMode.ACTIVE), None)


async def test_an_active_action_is_refused(adapter: MispWarningListsAdapter) -> None:
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(request_for("8.8.8.8"), None)


async def test_normalize_is_refused_because_there_is_no_provider_payload(
    adapter: MispWarningListsAdapter,
) -> None:
    """This adapter *is* the source; an empty payload would look like a document."""
    with pytest.raises(UnsupportedProviderOperation):
        adapter.normalize(request_for("8.8.8.8"), {})


async def test_a_lookup_works_with_no_credential_at_all(
    adapter: MispWarningListsAdapter,
) -> None:
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    assert envelope.status is ProviderRunStatus.SUCCESS


async def test_credential_validation_reports_that_none_is_needed(
    adapter: MispWarningListsAdapter,
) -> None:
    """ "Needs no key" and "key is missing" must not look the same."""
    validation = await adapter.validate_credentials(None)
    assert validation.is_usable is True


async def test_health_reflects_the_dataset(adapter: MispWarningListsAdapter) -> None:
    report = await adapter.health(None)
    assert report.health.value == "available"


async def test_no_snapshot_is_an_error_and_never_an_empty_result(tmp_path: Path) -> None:
    """A provider that could not read its data has not answered the question."""
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=tmp_path / "absent")
    )
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    assert envelope.status is ProviderRunStatus.ERROR
    assert envelope.status is not ProviderRunStatus.NO_DATA
    assert SNAPSHOT_UNAVAILABLE in envelope.warnings
    report = await adapter.health(None)
    assert report.health.value == "unavailable"


async def test_a_stale_snapshot_still_answers_and_says_it_is_old(tmp_path: Path) -> None:
    """Failing would be useless; refreshing silently would be dishonest."""
    build_snapshot(tmp_path / "snapshot", age=timedelta(days=120))
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(
            snapshot_root=tmp_path / "snapshot", stale_after=timedelta(days=30)
        ),
        profile=WarningListProfile(profile_id="test", max_list_entries=None),
    )
    envelope = await adapter.lookup(request_for("8.8.8.8"), None)
    assert envelope.status is ProviderRunStatus.SUCCESS
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["snapshot_stale"] is True
    assert coverage.attributes["snapshot_age_days"] > 100
    report = await adapter.health(None)
    assert report.health.value == "degraded"


async def test_the_result_never_contains_a_whole_warninglist(
    adapter: MispWarningListsAdapter,
) -> None:
    """A match record is evidence, not a copy of the dataset."""
    envelope = await adapter.lookup(request_for("10.0.0.1"), None)
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert len(serialized) < 20_000
    matches = evidence_of(envelope, MATCHES_CLAIM_TYPE)
    assert matches is not None
    for record in matches.attributes["matches"]:
        assert isinstance(record["matched_entry"], str)
    # rfc1918 has three entries; only the one that matched is present.
    assert "172.16.0.0/12" not in serialized


def test_the_default_profile_is_the_core_profile(tmp_path: Path) -> None:
    build_snapshot(tmp_path / "snapshot")
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=tmp_path / "snapshot")
    )
    assert adapter.profile.profile_id == core_profile().profile_id
