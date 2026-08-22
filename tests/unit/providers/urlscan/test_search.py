"""Safe historical scan discovery (Task 8).

urlscan's Search API speaks ElasticSearch query-string syntax, so the tests that
matter most are the ones proving a value can never become syntax.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from ti_recon.enums import IntelObjectType, InvestigationDepth, ObjectClass
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.urlscan import (
    DEPTH_SEARCH_LIMITS,
    ScanCandidate,
    SearchLimits,
    SearchTerm,
    UrlscanSearchField,
    build_query,
    cursor_for_hit,
    parse_hits,
    plan_search,
    select_candidates,
)

SHA256 = "b" * 64


def observable(
    object_type: IntelObjectType, value: str, properties: dict[str, Any] | None = None
) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
        properties=properties or {},
    )


# --------------------------------------------------------------------------- #
# A value can never become syntax
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        'example.com" OR page.domain:"victim.com',
        "example.com OR ip:*",
        "example.com AND date:>now-10y",
        "*.com",
        "/ev.l.*/",
        "example.com)",
        "example.com~2",
        "example.com^5",
        "a\\b.com",
        "page.domain:example.com",
        "[a TO z]",
        "exam ple.com",
    ],
)
def test_a_value_carrying_query_syntax_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value=value)


def test_a_control_character_is_refused() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="exa\nmple.com")


def test_only_allowlisted_fields_exist() -> None:
    """A field that is not in the enum cannot be expressed at all."""
    with pytest.raises(ValidationError):
        SearchTerm(field_name="page.internalNotes", value="x")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        (UrlscanSearchField.IP, "not-an-ip"),
        (UrlscanSearchField.PAGE_IP, "999.1.1.1"),
        (UrlscanSearchField.ASN, "12345"),
        (UrlscanSearchField.PAGE_ASN, "ASX"),
        (UrlscanSearchField.HASH, "a" * 63),
        (UrlscanSearchField.HASH, "A" * 64),
        (UrlscanSearchField.PAGE_DOMAIN, "localhost"),
        (UrlscanSearchField.PAGE_DOMAIN, "-bad.example.com"),
        (UrlscanSearchField.URL, "ftp://example.com"),
        (UrlscanSearchField.PAGE_URL, "javascript:alert(1)"),
        (UrlscanSearchField.TASK_URL, "example.com"),
    ],
)
def test_a_value_of_the_wrong_shape_for_its_field_is_refused(
    field_name: UrlscanSearchField, value: str
) -> None:
    with pytest.raises(ValidationError):
        SearchTerm(field_name=field_name, value=value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        (UrlscanSearchField.IP, "198.51.100.7"),
        (UrlscanSearchField.PAGE_IP, "2001:db8::1"),
        (UrlscanSearchField.ASN, "AS64500"),
        (UrlscanSearchField.HASH, SHA256),
        (UrlscanSearchField.PAGE_DOMAIN, "sub.example.co.uk"),
        (UrlscanSearchField.PAGE_DOMAIN, "xn--80ak6aa92e.com"),
        (UrlscanSearchField.PAGE_URL, "https://example.com/a/b?c=d&e=f"),
    ],
)
def test_a_well_shaped_value_is_accepted(field_name: UrlscanSearchField, value: str) -> None:
    term = SearchTerm(field_name=field_name, value=value)
    assert term.render() == f'{field_name.value}:"{value}"'


def test_a_url_value_is_quoted_so_its_punctuation_stays_literal() -> None:
    term = SearchTerm(
        field_name=UrlscanSearchField.PAGE_URL, value="https://example.com/?q=a+b&r=*"
    )
    assert term.render() == 'page.url:"https://example.com/?q=a+b&r=*"'


def test_a_quote_inside_a_url_value_is_escaped() -> None:
    """URL fields accept punctuation, so escaping — not rejection — protects them."""
    term = SearchTerm(
        field_name=UrlscanSearchField.PAGE_URL, value='https://example.com/"%20OR%20x'
    )
    assert term.render() == 'page.url:"https://example.com/\\"%20OR%20x"'


# --------------------------------------------------------------------------- #
# Query composition is ours, never the caller's
# --------------------------------------------------------------------------- #


def test_a_single_term_query() -> None:
    term = SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="example.com")
    assert build_query([term]) == 'page.domain:"example.com"'


def test_several_terms_are_grouped_before_being_bounded() -> None:
    terms = [
        SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="example.com"),
        SearchTerm(field_name=UrlscanSearchField.DOMAIN, value="example.com"),
    ]
    assert build_query(terms, since="now-1y") == (
        '(page.domain:"example.com" OR domain:"example.com") AND date:>now-1y'
    )


def test_an_empty_search_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one term"):
        build_query([])


def test_a_time_bound_must_be_a_known_expression() -> None:
    with pytest.raises(ValidationError):
        SearchLimits(page_size=10, max_candidates=1, max_per_group=1, since="now OR x")


# --------------------------------------------------------------------------- #
# Planning per observable
# --------------------------------------------------------------------------- #


def test_a_domain_is_searched_as_the_page_and_as_a_contacted_domain() -> None:
    plan = plan_search(observable(IntelObjectType.DOMAIN_NAME, "example.com"))
    assert plan is not None
    assert plan.query == ('(page.domain:"example.com" OR domain:"example.com") AND date:>now-1y')


def test_an_ip_is_searched_as_the_page_ip_and_as_a_contacted_ip() -> None:
    plan = plan_search(observable(IntelObjectType.IPV4_ADDR, "198.51.100.7"))
    assert plan is not None
    assert 'page.ip:"198.51.100.7"' in plan.query
    assert 'ip:"198.51.100.7"' in plan.query


def test_a_url_is_searched_as_the_final_and_the_submitted_url() -> None:
    plan = plan_search(observable(IntelObjectType.URL, "https://example.com/login"))
    assert plan is not None
    assert 'page.url:"https://example.com/login"' in plan.query
    assert 'task.url:"https://example.com/login"' in plan.query


def test_a_file_is_searched_by_the_sha256_of_a_served_body() -> None:
    plan = plan_search(observable(IntelObjectType.FILE, SHA256, {"hashes": {"SHA-256": SHA256}}))
    assert plan is not None
    assert plan.query.startswith(f'hash:"{SHA256}"')


def test_a_hash_urlscan_does_not_index_is_a_gap_not_an_empty_result() -> None:
    """Reporting "no results" for an unsearchable hash would be a false absence."""
    md5 = "c" * 32
    plan = plan_search(observable(IntelObjectType.FILE, md5, {"hashes": {"MD5": md5}}))
    assert plan is None


def test_an_object_type_urlscan_does_not_answer_for_produces_no_plan() -> None:
    asn = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value="AS64500",
        display_value="AS64500",
    )
    assert plan_search(asn) is None


# --------------------------------------------------------------------------- #
# Depth decides the bound
# --------------------------------------------------------------------------- #


def test_depth_bounds_grow_with_cost() -> None:
    quick = DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK]
    standard = DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD]
    deep = DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP]
    assert quick.max_candidates < standard.max_candidates < deep.max_candidates
    assert quick.page_size < standard.page_size < deep.page_size


def test_only_a_deep_lookup_sees_the_whole_history() -> None:
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK].since == "now-90d"
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD].since == "now-1y"
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP].since is None


def test_a_quick_plan_is_time_bounded_and_cheap() -> None:
    plan = plan_search(
        observable(IntelObjectType.DOMAIN_NAME, "example.com"),
        depth=InvestigationDepth.QUICK,
    )
    assert plan is not None
    assert plan.query.endswith("AND date:>now-90d")
    assert plan.page_size == 10


def test_a_deep_plan_drops_the_time_bound() -> None:
    plan = plan_search(
        observable(IntelObjectType.DOMAIN_NAME, "example.com"),
        depth=InvestigationDepth.DEEP,
    )
    assert plan is not None
    assert "date:>" not in plan.query


def test_explicit_limits_override_the_depth_default() -> None:
    limits = SearchLimits(page_size=5, max_candidates=2, max_per_group=1, since=None)
    plan = plan_search(observable(IntelObjectType.DOMAIN_NAME, "example.com"), limits=limits)
    assert plan is not None
    assert plan.limits == limits


# --------------------------------------------------------------------------- #
# Reading hits
# --------------------------------------------------------------------------- #


def hit(scan_id: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "_id": scan_id,
        "task": {
            "url": "https://example.com/login",
            "time": "2026-08-20T10:00:00.000Z",
            "visibility": "public",
        },
        "page": {
            "url": "https://example.com/login",
            "domain": "example.com",
            "ip": "198.51.100.7",
            "asn": "AS64500",
        },
        "sort": [1755680400000, scan_id],
    }
    base.update(overrides)
    return base


def uuid_at(index: int) -> str:
    return f"0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c{index:02d}"


def test_hits_become_candidates() -> None:
    candidates = parse_hits({"results": [hit(uuid_at(1))]})
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.scan_id == uuid_at(1)
    assert candidate.page_domain == "example.com"
    assert candidate.page_ip == "198.51.100.7"
    assert candidate.submitted_url == "https://example.com/login"
    assert candidate.scanned_at == datetime(2026, 8, 20, 10, 0, tzinfo=UTC)
    assert candidate.visibility == "public"
    assert candidate.cursor == f"1755680400000,{uuid_at(1)}"


@pytest.mark.parametrize(
    "payload",
    [{}, {"results": None}, {"results": []}, {"results": ["not-a-hit"]}],
)
def test_an_unusable_response_yields_nothing(payload: dict[str, Any]) -> None:
    assert parse_hits(payload) == ()


def test_a_hit_without_a_valid_scan_id_is_dropped() -> None:
    """An id that is not a UUID must never reach a URL path."""
    payload = {
        "results": [
            hit(uuid_at(1)),
            {"_id": "../../etc/passwd", "task": {}, "page": {}},
            {"_id": None},
            {"task": {}},
        ]
    }
    assert [candidate.scan_id for candidate in parse_hits(payload)] == [uuid_at(1)]


def test_duplicate_hits_are_collapsed() -> None:
    payload = {"results": [hit(uuid_at(1)), hit(uuid_at(1))]}
    assert len(parse_hits(payload)) == 1


def test_a_hit_with_odd_nested_blocks_still_parses() -> None:
    payload = {"results": [{"_id": uuid_at(1), "task": "nope", "page": 42}]}
    candidates = parse_hits(payload)
    assert len(candidates) == 1
    assert candidates[0].page_domain is None


def test_provider_text_is_stripped_of_control_characters_and_bounded() -> None:
    payload = {
        "results": [
            hit(uuid_at(1), page={"domain": "exa\x00mple.com", "url": "https://x/" + "a" * 5000})
        ]
    }
    candidate = parse_hits(payload)[0]
    assert candidate.page_domain == "example.com"
    assert candidate.final_url is not None
    assert len(candidate.final_url) == 2048


@pytest.mark.parametrize(
    "sort",
    [None, [], "1,2", [{"nested": 1}]],
)
def test_an_unusable_sort_value_yields_no_cursor(sort: Any) -> None:
    assert cursor_for_hit({"sort": sort}) is None


# --------------------------------------------------------------------------- #
# Spending the retrieval budget
# --------------------------------------------------------------------------- #


def candidate(
    index: int, *, domain: str = "example.com", scanned_at: datetime | None = None
) -> ScanCandidate:
    return ScanCandidate(
        scan_id=uuid_at(index),
        page_domain=domain,
        scanned_at=scanned_at or datetime(2026, 8, index + 1, tzinfo=UTC),
    )


def test_the_newest_scans_are_preferred() -> None:
    limits = SearchLimits(page_size=10, max_candidates=2, max_per_group=9, since=None)
    chosen = select_candidates([candidate(1), candidate(5), candidate(3)], limits)
    assert [c.scan_id for c in chosen] == [uuid_at(5), uuid_at(3)]


def test_one_busy_site_cannot_consume_the_whole_budget() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, since=None)
    chosen = select_candidates(
        [
            candidate(1, domain="busy.example"),
            candidate(2, domain="busy.example"),
            candidate(3, domain="busy.example"),
            candidate(4, domain="other.example"),
            candidate(5, domain="third.example"),
        ],
        limits,
    )
    assert {c.page_domain for c in chosen} == {"busy.example", "other.example", "third.example"}


def test_unspent_budget_is_filled_rather_than_wasted() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, since=None)
    chosen = select_candidates([candidate(1), candidate(2), candidate(3), candidate(4)], limits)
    assert len(chosen) == 3
    # The per-group cap admitted one, and the rest of the budget went to the
    # next-newest scans of the same site rather than going unused.
    assert [c.scan_id for c in chosen] == [uuid_at(4), uuid_at(3), uuid_at(2)]


def test_selection_never_exceeds_the_budget() -> None:
    limits = SearchLimits(page_size=10, max_candidates=2, max_per_group=5, since=None)
    chosen = select_candidates([candidate(index) for index in range(1, 20)], limits)
    assert len(chosen) == 2


def test_scans_without_a_timestamp_go_last_deterministically() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=9, since=None)
    undated_b = ScanCandidate(scan_id=uuid_at(9), page_domain="b.example")
    undated_a = ScanCandidate(scan_id=uuid_at(8), page_domain="a.example")
    chosen = select_candidates([undated_b, undated_a, candidate(1)], limits)
    assert [c.scan_id for c in chosen] == [uuid_at(1), uuid_at(8), uuid_at(9)]


def test_selecting_from_nothing_is_empty_rather_than_an_error() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, since=None)
    assert select_candidates([], limits) == ()


def test_a_candidate_without_a_domain_groups_by_ip_then_by_itself() -> None:
    by_ip = ScanCandidate(scan_id=uuid_at(1), page_ip="198.51.100.7")
    alone = ScanCandidate(scan_id=uuid_at(2))
    assert by_ip.group_key == "198.51.100.7"
    assert alone.group_key == uuid_at(2)
