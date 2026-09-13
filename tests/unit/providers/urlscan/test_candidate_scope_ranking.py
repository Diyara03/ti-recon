"""Primary-page scans are retrieved before incidental contacts (Task 24, US-04).

The retrieval budget is one, three or eight scans. A search for an address
matches every page that loaded a resource from it, and selection was recency
only, so the budget could go entirely to pages that merely contacted the
observable while the one scan hosted on it waited. Selection now reads the
same identity rule the normalizer applies -- from the fields a search hit
already carries -- and puts scans whose page *is* the observable, or its
neighbourhood, before scans that merely contacted it. Within a class the
order is what it always was: newest first, the per-domain cap, unspent budget
filled, undated scans last, ties broken by scan id.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ti_recon.enums import MatchScope
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.urlscan.search import ScanCandidate, SearchLimits, select_candidates

HOSTED_IP = "198.51.100.7"
OTHER_IP = "203.0.113.9"
ROOT: IntelObject = normalize_observable(HOSTED_IP).intel_object


def uuid_at(index: int) -> str:
    return f"0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c{index:02d}"


def hosted(index: int, *, day: int, domain: str = "hosted.example") -> ScanCandidate:
    """A scan whose page was served from the queried address."""
    return ScanCandidate(
        scan_id=uuid_at(index),
        page_domain=domain,
        page_ip=HOSTED_IP,
        scanned_at=datetime(2026, 8, day, tzinfo=UTC),
    )


def contacted(index: int, *, day: int, domain: str = "other.example") -> ScanCandidate:
    """A scan whose page merely loaded something from the queried address."""
    return ScanCandidate(
        scan_id=uuid_at(index),
        page_domain=domain,
        page_ip=OTHER_IP,
        scanned_at=datetime(2026, 8, day, tzinfo=UTC),
    )


def limits(max_candidates: int, max_per_group: int = 9) -> SearchLimits:
    return SearchLimits(
        page_size=10, max_candidates=max_candidates, max_per_group=max_per_group, lookback_days=365
    )


def test_the_hit_reads_scope_the_same_way_the_normalizer_will() -> None:
    assert hosted(1, day=1).match_scope_for(ROOT) is MatchScope.SAME_IP
    assert contacted(2, day=2).match_scope_for(ROOT) is MatchScope.CLUSTER


def test_a_an_older_hosting_scan_beats_a_newer_incidental_contact_for_a_budget_of_one() -> None:
    chosen = select_candidates([contacted(2, day=20), hosted(1, day=2)], limits(1), subject=ROOT)
    assert [c.scan_id for c in chosen] == [uuid_at(1)]


def test_b_several_hosting_scans_keep_the_recency_order() -> None:
    chosen = select_candidates(
        [hosted(1, day=1), hosted(5, day=5), hosted(3, day=3)], limits(2), subject=ROOT
    )
    assert [c.scan_id for c in chosen] == [uuid_at(5), uuid_at(3)]


def test_c_with_no_hosting_scan_incidental_contacts_are_still_selected() -> None:
    chosen = select_candidates([contacted(1, day=1), contacted(2, day=2)], limits(1), subject=ROOT)
    assert [c.scan_id for c in chosen] == [uuid_at(2)]


def test_d_the_bound_is_unchanged_and_contacts_fill_behind_the_primaries() -> None:
    chosen = select_candidates(
        [contacted(9, day=9), hosted(1, day=1), contacted(8, day=8), hosted(2, day=2)],
        limits(3),
        subject=ROOT,
    )
    assert len(chosen) == 3
    assert [c.scan_id for c in chosen] == [uuid_at(2), uuid_at(1), uuid_at(9)]


def test_e_the_order_is_deterministic_across_input_orders() -> None:
    pool = [contacted(9, day=9), hosted(1, day=1), contacted(8, day=8), hosted(2, day=2)]
    first = select_candidates(pool, limits(4), subject=ROOT)
    second = select_candidates(list(reversed(pool)), limits(4), subject=ROOT)
    assert [c.scan_id for c in first] == [c.scan_id for c in second]


def test_the_per_domain_cap_still_applies_within_the_primary_class() -> None:
    chosen = select_candidates(
        [
            hosted(1, day=1, domain="busy.example"),
            hosted(2, day=2, domain="busy.example"),
            hosted(3, day=3, domain="quiet.example"),
        ],
        limits(2, max_per_group=1),
        subject=ROOT,
    )
    assert {c.page_domain for c in chosen} == {"busy.example", "quiet.example"}


def test_without_a_subject_the_previous_recency_order_is_kept() -> None:
    chosen = select_candidates([contacted(2, day=20), hosted(1, day=2)], limits(1))
    assert [c.scan_id for c in chosen] == [uuid_at(2)]


def test_an_undated_hosting_scan_still_ranks_before_a_dated_contact() -> None:
    undated = ScanCandidate(scan_id=uuid_at(7), page_domain="hosted.example", page_ip=HOSTED_IP)
    chosen = select_candidates([contacted(2, day=20), undated], limits(1), subject=ROOT)
    assert [c.scan_id for c in chosen] == [uuid_at(7)]
