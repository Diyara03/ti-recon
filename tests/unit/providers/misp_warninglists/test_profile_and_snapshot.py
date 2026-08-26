"""Profiles, snapshot provenance and data quality (Task 11).

Three things are being defended here.

**No result may imply it checked lists it never had.** Exclusions and omissions
are different situations needing different fixes, and both have to survive into
coverage.

**The dataset is only as trustworthy as its provenance.** A snapshot with no
recorded commit is a pile of JSON somebody has to take on faith, and one whose
files no longer match its checksums is worse than absent.

**Upstream data is imperfect, and the response is to record the loss.** Not to
repair it, not to hide it, and not to lose 122 working lists because the 123rd is
malformed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fixtures.warninglists import SnapshotBuilder, build_snapshot
from ti_recon.providers.misp_warninglists import (
    DEFAULT_MAX_LIST_ENTRIES,
    MANIFEST_FILENAME,
    REDUNDANT_POPULARITY_TIERS,
    RETAINED_POPULARITY_TIERS,
    MispWarningListsAdapter,
    MispWarningListsConfig,
    SnapshotError,
    WarningListProfile,
    build_index,
    core_profile,
    full_profile,
    load_snapshot,
    slug_is_safe,
)


def snapshot_at(path: Path):
    build_snapshot(path)
    return load_snapshot(path)


def unbounded(profile_id: str = "test") -> WarningListProfile:
    return WarningListProfile(profile_id=profile_id, max_list_entries=None)


# --------------------------------------------------------------------------- #
# Manifest and provenance
# --------------------------------------------------------------------------- #


def test_a_snapshot_records_where_it_came_from(tmp_path: Path) -> None:
    manifest = snapshot_at(tmp_path).manifest
    assert manifest.upstream_repository.endswith("misp-warninglists")
    assert len(manifest.upstream_commit) == 40
    assert manifest.dataset_fingerprint
    assert manifest.schema_fingerprint
    assert manifest.license == "CC0-1.0"
    assert manifest.list_count == len(manifest.lists)
    assert manifest.entry_count == sum(item.entry_count for item in manifest.lists)


def test_the_dataset_fingerprint_is_deterministic(tmp_path: Path) -> None:
    """Two builds of the same data must agree, or a rebuild looks like new data."""
    first = snapshot_at(tmp_path / "a").manifest.dataset_fingerprint
    second = snapshot_at(tmp_path / "b").manifest.dataset_fingerprint
    assert first == second


def test_the_dataset_fingerprint_changes_when_a_list_changes(tmp_path: Path) -> None:
    before = snapshot_at(tmp_path / "a").manifest.dataset_fingerprint
    root = tmp_path / "b"
    SnapshotBuilder(root=root).add(
        "rfc1918", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"]
    ).write()
    assert load_snapshot(root).manifest.dataset_fingerprint != before


def test_a_missing_snapshot_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError, match="not found"):
        load_snapshot(tmp_path / "absent")


def test_a_snapshot_without_a_manifest_is_refused(tmp_path: Path) -> None:
    (tmp_path / "lists").mkdir(parents=True)
    with pytest.raises(SnapshotError, match=MANIFEST_FILENAME):
        load_snapshot(tmp_path)


def test_a_malformed_manifest_is_refused(tmp_path: Path) -> None:
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / MANIFEST_FILENAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(tmp_path)


def test_a_manifest_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    (tmp_path / MANIFEST_FILENAME).write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(SnapshotError, match="not a JSON object"):
        load_snapshot(tmp_path)


def test_a_manifest_failing_validation_reports_a_stable_message(tmp_path: Path) -> None:
    """Deliberately not echoing the validation detail: it can quote content."""
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps({"snapshot_format": 1}), "utf-8")
    with pytest.raises(SnapshotError, match="failed validation"):
        load_snapshot(tmp_path)


def test_an_unknown_snapshot_format_is_refused(tmp_path: Path) -> None:
    build_snapshot(tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["snapshot_format"] = 99
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SnapshotError, match="unsupported"):
        load_snapshot(tmp_path)


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "slug",
    ["../escape", "a/b", "a\\b", "..", ".hidden", "", "x" * 200, "with space"],
)
def test_an_unsafe_slug_is_refused(slug: str) -> None:
    assert slug_is_safe(slug) is False


@pytest.mark.parametrize("slug", ["rfc1918", "cisco_top10k", "eicar.com", "public-dns-v4"])
def test_real_upstream_slugs_are_accepted(slug: str) -> None:
    assert slug_is_safe(slug) is True


def test_a_list_path_cannot_escape_the_snapshot_root(tmp_path: Path) -> None:
    snapshot = snapshot_at(tmp_path)
    with pytest.raises(SnapshotError, match="unsafe"):
        snapshot.list_path("../../etc/passwd")


def test_a_list_path_stays_inside_the_lists_directory(tmp_path: Path) -> None:
    snapshot = snapshot_at(tmp_path)
    resolved = snapshot.list_path("rfc1918")
    assert resolved.is_relative_to((tmp_path / "lists").resolve())


# --------------------------------------------------------------------------- #
# Checksums and data quality
# --------------------------------------------------------------------------- #


def test_a_checksum_mismatch_makes_one_list_unusable_not_the_dataset(
    tmp_path: Path,
) -> None:
    """122 working lists must survive the 123rd being wrong."""
    root = tmp_path / "snapshot"
    from fixtures.warninglists import realistic_lists

    builder = SnapshotBuilder(root=root)
    realistic_lists(builder)
    builder.write(corrupt_checksum="rfc1918")

    snapshot = load_snapshot(root)
    index = build_index(snapshot, unbounded().select(snapshot.manifest))
    assert "rfc1918" not in {item.slug for item in index.lists}
    assert [item.slug for item in index.unusable] == ["rfc1918"]
    assert index.diagnostics.malformed_list_count == 1
    # Everything else still loaded.
    assert "public-dns-v4" in {item.slug for item in index.lists}


def test_a_read_of_a_corrupted_list_reports_the_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    build_snapshot(root)
    target = root / "lists" / "rfc1918.json"
    target.write_bytes(target.read_bytes().replace(b"10.0.0.0", b"11.0.0.0"))
    snapshot = load_snapshot(root)
    record = snapshot.manifest.record("rfc1918")
    assert record is not None
    with pytest.raises(SnapshotError, match="checksum mismatch"):
        snapshot.read_list(record)


@pytest.mark.parametrize(
    ("body", "label"),
    [
        (b"{not json", "malformed JSON"),
        (b"[1,2,3]", "not an object"),
        (b'{"name":"x","version":1,"description":"x","type":"string"}', "missing list"),
        (
            b'{"name":"x","version":1,"description":"x","type":"nope","list":["a"]}',
            "unknown matcher",
        ),
        (
            b'{"name":"x","version":1,"description":"x","type":"string","list":["a"],"extra":1}',
            "extra field",
        ),
    ],
)
def test_a_structurally_invalid_list_is_isolated(tmp_path: Path, body: bytes, label: str) -> None:
    """One bad file, one unusable list, and the rest of the dataset works."""
    root = tmp_path / "snapshot"
    builder = SnapshotBuilder(root=root)
    builder.add("good", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"])
    builder.add_raw("bad", body)
    builder.write()

    snapshot = load_snapshot(root)
    index = build_index(snapshot, unbounded().select(snapshot.manifest))
    assert {item.slug for item in index.lists} == {"good"}, label
    assert [item.slug for item in index.unusable] == ["bad"]
    assert index.diagnostics.malformed_list_count == 1


def test_diagnostics_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    SnapshotBuilder(root=root).add(
        "messy",
        matcher="cidr",
        entries=["10.0.0.0/8", "nonsense", "", "999.1.1.1/24"],
        matching_attributes=["ip-src"],
    ).write()
    snapshot = load_snapshot(root)
    first = build_index(snapshot, unbounded().select(snapshot.manifest)).diagnostics
    second = build_index(snapshot, unbounded().select(snapshot.manifest)).diagnostics
    assert first == second
    assert first.invalid_cidr_count == 3


def test_a_bad_irrelevant_list_does_not_degrade_an_unrelated_lookup(
    tmp_path: Path,
) -> None:
    """The point of applicability-aware partiality.

    A broken phone-number list is nothing to do with an IPv4 address, and a
    lookup that reported PARTIAL because of it would be crying wolf on every
    observable forever.
    """
    root = tmp_path / "snapshot"
    builder = SnapshotBuilder(root=root)
    builder.add("rfc1918", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"])
    builder.add_raw("phone_numbers", b"{broken", matcher="regex")
    builder.write()
    # The manifest says the broken list is about phone numbers only.
    manifest = json.loads((root / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    for record in manifest["lists"]:
        if record["slug"] == "phone_numbers":
            record["matching_attributes"] = ["phone-number"]
    (root / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")

    snapshot = load_snapshot(root)
    index = build_index(snapshot, unbounded().select(snapshot.manifest))
    assert len(index.unusable) == 1
    assert index.unusable_for(frozenset({"ip-src", "ip-dst"})) == ()
    assert len(index.unusable_for(frozenset({"phone-number"}))) == 1


async def test_an_unusable_applicable_list_makes_the_lookup_partial(
    tmp_path: Path,
) -> None:
    root = tmp_path / "snapshot"
    builder = SnapshotBuilder(root=root)
    builder.add("rfc1918", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"])
    builder.add_raw("broken-cidr", b"{broken", matcher="cidr")
    builder.write()
    manifest = json.loads((root / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    for record in manifest["lists"]:
        if record["slug"] == "broken-cidr":
            record["matching_attributes"] = ["ip-src", "ip-dst"]
    (root / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")

    from ti_recon.enums import ProviderCapability, ProviderOperation, ProviderRunStatus
    from ti_recon.normalization import normalize_observable
    from ti_recon.providers import ProviderRequest
    from ti_recon.providers.misp_warninglists import COVERAGE_CLAIM_TYPE

    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=root), profile=unbounded()
    )
    envelope = await adapter.lookup(
        ProviderRequest(
            investigation_id="inv",
            intel_object=normalize_observable("10.0.0.1").intel_object,
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        ),
        None,
    )
    assert envelope.status is ProviderRunStatus.PARTIAL
    coverage = next(item for item in envelope.evidence if item.claim_type == COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["unusable_applicable_lists"] == 1
    assert "partial_reason" in coverage.attributes
    assert coverage.attributes["all_lists_checked"] is False


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #


def test_the_core_profile_bounds_by_size_and_drops_duplicated_tiers() -> None:
    profile = core_profile()
    assert profile.max_list_entries == DEFAULT_MAX_LIST_ENTRIES
    # Two independent 10k rankings are kept; the nested tiers are not.
    assert profile.drop_redundant_tiers == REDUNDANT_POPULARITY_TIERS - RETAINED_POPULARITY_TIERS
    for retained in RETAINED_POPULARITY_TIERS:
        assert retained not in profile.drop_redundant_tiers


def test_an_oversized_list_is_excluded_with_a_reason(tmp_path: Path) -> None:
    root = tmp_path / "snapshot"
    SnapshotBuilder(root=root).add(
        "huge",
        matcher="string",
        entries=[f"host-{index}.example" for index in range(50)],
        matching_attributes=["domain"],
    ).add("small", matcher="string", entries=["a.example"], matching_attributes=["domain"]).write()
    snapshot = load_snapshot(root)
    selection = WarningListProfile(profile_id="tiny", max_list_entries=10).select(snapshot.manifest)
    assert selection.selected == ("small",)
    assert [(item.slug, item.reason) for item in selection.excluded] == [("huge", "oversized")]


def test_include_is_an_allow_list(tmp_path: Path) -> None:
    snapshot = snapshot_at(tmp_path)
    selection = WarningListProfile(
        profile_id="one", include=frozenset({"rfc1918"}), max_list_entries=None
    ).select(snapshot.manifest)
    assert selection.selected == ("rfc1918",)
    assert all(item.reason == "not_in_include_list" for item in selection.excluded)


def test_exclude_removes_one_list(tmp_path: Path) -> None:
    snapshot = snapshot_at(tmp_path)
    selection = WarningListProfile(
        profile_id="minus", exclude=frozenset({"rfc1918"}), max_list_entries=None
    ).select(snapshot.manifest)
    assert "rfc1918" not in selection.selected
    assert [(item.slug, item.reason) for item in selection.excluded] == [
        ("rfc1918", "explicitly_excluded")
    ]


async def test_an_excluded_list_cannot_produce_a_match(tmp_path: Path) -> None:
    from ti_recon.enums import ProviderCapability, ProviderOperation, ProviderRunStatus
    from ti_recon.normalization import normalize_observable
    from ti_recon.providers import ProviderRequest

    build_snapshot(tmp_path / "snapshot")
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=tmp_path / "snapshot"),
        profile=WarningListProfile(
            profile_id="no-private",
            exclude=frozenset({"rfc1918", "rfc5735"}),
            max_list_entries=None,
        ),
    )
    envelope = await adapter.lookup(
        ProviderRequest(
            investigation_id="inv",
            intel_object=normalize_observable("10.0.0.1").intel_object,
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        ),
        None,
    )
    assert envelope.status is ProviderRunStatus.NO_DATA


def test_a_list_cannot_be_both_included_and_excluded() -> None:
    with pytest.raises(ValueError, match="both included and excluded"):
        WarningListProfile(
            profile_id="conflicting",
            include=frozenset({"rfc1918"}),
            exclude=frozenset({"rfc1918"}),
        )


def test_an_unknown_slug_is_reported_rather_than_silently_ignored(tmp_path: Path) -> None:
    """A misspelled include otherwise produces a silently empty profile."""
    snapshot = snapshot_at(tmp_path)
    selection = WarningListProfile(
        profile_id="typo", include=frozenset({"rfc1918", "rcf1918"}), max_list_entries=None
    ).select(snapshot.manifest)
    assert selection.unknown_slugs == ("rcf1918",)


def test_a_profile_fingerprint_is_stable() -> None:
    assert core_profile().fingerprint() == core_profile().fingerprint()


@pytest.mark.parametrize(
    "other",
    [
        WarningListProfile(profile_id="core", max_list_entries=50_000),
        WarningListProfile(profile_id="core", exclude=frozenset({"rfc1918"})),
        WarningListProfile(profile_id="core", include=frozenset({"rfc1918"})),
        WarningListProfile(profile_id="different"),
        WarningListProfile(profile_id="core", drop_redundant_tiers=frozenset({"alexa"})),
    ],
)
def test_a_profile_fingerprint_changes_when_selection_changes(
    other: WarningListProfile,
) -> None:
    """Two profiles selecting different lists must not share a cache entry."""
    baseline = WarningListProfile(profile_id="core")
    assert other.fingerprint() != baseline.fingerprint()


def test_the_selection_identity_pairs_the_profile_with_the_dataset(tmp_path: Path) -> None:
    """Either half alone would serve a wrong answer."""
    snapshot = snapshot_at(tmp_path)
    identity = unbounded().select(snapshot.manifest).identity()
    profile_part, snapshot_part = identity.split(":")
    assert unbounded().fingerprint().startswith(profile_part)
    assert snapshot.manifest.dataset_fingerprint.startswith(snapshot_part)


def test_profile_and_snapshot_exclusions_are_reported_separately(tmp_path: Path) -> None:
    """Different situations needing different fixes."""
    root = tmp_path / "snapshot"
    builder = SnapshotBuilder(root=root)
    builder.add("rfc1918", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"])
    builder.add(
        "cloudflare-top10k",
        matcher="string",
        entries=["example.com"],
        matching_attributes=["domain"],
    )
    builder.omit("cloudflare-top1m", reason="oversized_at_build", entry_count=1_000_125)
    builder.write()

    snapshot = load_snapshot(root)
    selection = WarningListProfile(
        profile_id="p", exclude=frozenset({"cloudflare-top10k"}), max_list_entries=None
    ).select(snapshot.manifest)
    index = build_index(snapshot, selection)
    assert [item.slug for item in index.profile_excluded] == ["cloudflare-top10k"]
    assert [item.slug for item in index.snapshot_omitted] == ["cloudflare-top1m"]


def test_the_full_profile_has_no_ceiling() -> None:
    assert full_profile().max_list_entries is None
    assert full_profile().drop_redundant_tiers == frozenset()


# --------------------------------------------------------------------------- #
# Staleness
# --------------------------------------------------------------------------- #


def test_a_fresh_snapshot_is_not_stale(tmp_path: Path) -> None:
    snapshot = snapshot_at(tmp_path)
    assert snapshot.is_stale(timedelta(days=30)) is False


def test_an_old_snapshot_is_stale_but_still_readable(tmp_path: Path) -> None:
    build_snapshot(tmp_path, age=timedelta(days=200))
    snapshot = load_snapshot(tmp_path)
    assert snapshot.is_stale(timedelta(days=30)) is True
    assert snapshot.age() > timedelta(days=199)
    record = snapshot.manifest.record("rfc1918")
    assert record is not None
    assert snapshot.read_list(record).type == "cidr"


def test_the_stale_threshold_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        MispWarningListsConfig(stale_after=timedelta(0))


def test_a_snapshot_generated_in_the_future_is_not_stale(tmp_path: Path) -> None:
    build_snapshot(tmp_path, generated_at=datetime.now(UTC) + timedelta(days=1))
    assert load_snapshot(tmp_path).is_stale(timedelta(days=30)) is False
