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
    DEEP_FALLBACK_LOOKBACK_DAYS,
    DEPTH_SEARCH_LIMITS,
    MAX_LOOKBACK_DAYS,
    MAX_LOOKBACK_MONTHS,
    ScanCandidate,
    SearchLimits,
    SearchTerm,
    UrlscanSearchField,
    build_query,
    cursor_for_hit,
    lookback_days_for_months,
    parse_hits,
    plan_search,
    select_candidates,
    subtract_months,
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


def test_a_single_term_query_is_still_date_bounded() -> None:
    term = SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="example.com")
    assert build_query([term], since="now-30d") == 'page.domain:"example.com" AND date:>now-30d'


def test_several_terms_are_grouped_before_being_bounded() -> None:
    terms = [
        SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="example.com"),
        SearchTerm(field_name=UrlscanSearchField.DOMAIN, value="example.com"),
    ]
    assert build_query(terms, since="now-180d") == (
        '(page.domain:"example.com" OR domain:"example.com") AND date:>now-180d'
    )


def test_an_empty_search_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one term"):
        build_query([], since="now-30d")


@pytest.mark.parametrize(
    "since",
    ["", "now", "now-1y", "now-30d OR x", "*", "now-30d AND date:>now-10y", "now--1d"],
)
def test_a_date_bound_that_is_not_a_plain_lookback_is_refused(since: str) -> None:
    """The bound is composed by TI Recon; anything else cannot reach the query."""
    term = SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value="example.com")
    with pytest.raises(ValueError, match="now-<days>d"):
        build_query([term], since=since)


def test_a_lookback_is_always_present_and_bounded() -> None:
    """There is no value of ``SearchLimits`` that produces an unbounded query."""
    assert "lookback_days" in SearchLimits.model_fields
    assert "since" not in SearchLimits.model_fields
    with pytest.raises(ValidationError):
        SearchLimits(page_size=10, max_candidates=1, max_per_group=1, lookback_days=0)
    with pytest.raises(ValidationError):
        SearchLimits(page_size=10, max_candidates=1, max_per_group=1, lookback_days=10_000)


# --------------------------------------------------------------------------- #
# Planning per observable
# --------------------------------------------------------------------------- #


def test_a_domain_is_searched_as_the_page_and_as_a_contacted_domain() -> None:
    plan = plan_search(observable(IntelObjectType.DOMAIN_NAME, "example.com"))
    assert plan is not None
    assert plan.query == ('(page.domain:"example.com" OR domain:"example.com") AND date:>now-180d')


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


def test_every_depth_is_bounded_including_deep() -> None:
    """An unbounded query is not "more thorough"; it is a scan of the index."""
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK].lookback_days == 30
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD].lookback_days == 180
    for limits in DEPTH_SEARCH_LIMITS.values():
        assert limits.lookback_days >= 1
        assert limits.since.startswith("now-")


def test_only_deep_reaches_for_the_accounts_own_maximum() -> None:
    """ "As far back as this analyst may look" is what DEEP means."""
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP].use_account_maximum is True
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK].use_account_maximum is False
    assert DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD].use_account_maximum is False


def test_the_deep_number_is_a_fallback_not_the_policy() -> None:
    deep = DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP]
    assert deep.lookback_days == DEEP_FALLBACK_LOOKBACK_DAYS == 365


def test_a_quick_plan_is_time_bounded_and_cheap() -> None:
    plan = plan_search(
        observable(IntelObjectType.DOMAIN_NAME, "example.com"),
        depth=InvestigationDepth.QUICK,
    )
    assert plan is not None
    assert plan.query.endswith("AND date:>now-30d")
    assert plan.page_size == 10


@pytest.mark.parametrize("depth", list(InvestigationDepth))
def test_no_depth_ever_produces_an_unbounded_query(depth: InvestigationDepth) -> None:
    plan = plan_search(observable(IntelObjectType.DOMAIN_NAME, "example.com"), depth=depth)
    assert plan is not None
    assert " AND date:>now-" in plan.query


def test_a_deep_plan_without_account_metadata_falls_back_to_a_year() -> None:
    """``plan_search`` is given whatever window was resolved for it."""
    plan = plan_search(
        observable(IntelObjectType.DOMAIN_NAME, "example.com"),
        depth=InvestigationDepth.DEEP,
    )
    assert plan is not None
    assert plan.query.endswith("AND date:>now-365d")


def test_explicit_limits_override_the_depth_default() -> None:
    limits = SearchLimits(page_size=5, max_candidates=2, max_per_group=1, lookback_days=7)
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
    limits = SearchLimits(page_size=10, max_candidates=2, max_per_group=9, lookback_days=365)
    chosen = select_candidates([candidate(1), candidate(5), candidate(3)], limits)
    assert [c.scan_id for c in chosen] == [uuid_at(5), uuid_at(3)]


def test_one_busy_site_cannot_consume_the_whole_budget() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, lookback_days=365)
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
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, lookback_days=365)
    chosen = select_candidates([candidate(1), candidate(2), candidate(3), candidate(4)], limits)
    assert len(chosen) == 3
    # The per-group cap admitted one, and the rest of the budget went to the
    # next-newest scans of the same site rather than going unused.
    assert [c.scan_id for c in chosen] == [uuid_at(4), uuid_at(3), uuid_at(2)]


def test_selection_never_exceeds_the_budget() -> None:
    limits = SearchLimits(page_size=10, max_candidates=2, max_per_group=5, lookback_days=365)
    chosen = select_candidates([candidate(index) for index in range(1, 20)], limits)
    assert len(chosen) == 2


def test_scans_without_a_timestamp_go_last_deterministically() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=9, lookback_days=365)
    undated_b = ScanCandidate(scan_id=uuid_at(9), page_domain="b.example")
    undated_a = ScanCandidate(scan_id=uuid_at(8), page_domain="a.example")
    chosen = select_candidates([undated_b, undated_a, candidate(1)], limits)
    assert [c.scan_id for c in chosen] == [uuid_at(1), uuid_at(8), uuid_at(9)]


def test_selecting_from_nothing_is_empty_rather_than_an_error() -> None:
    limits = SearchLimits(page_size=10, max_candidates=3, max_per_group=1, lookback_days=365)
    assert select_candidates([], limits) == ()


def test_a_candidate_without_a_domain_groups_by_ip_then_by_itself() -> None:
    by_ip = ScanCandidate(scan_id=uuid_at(1), page_ip="198.51.100.7")
    alone = ScanCandidate(scan_id=uuid_at(2))
    assert by_ip.group_key == "198.51.100.7"
    assert alone.group_key == uuid_at(2)


# --------------------------------------------------------------------------- #
# The account's maximum searchable range
# --------------------------------------------------------------------------- #


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def test_a_window_change_never_changes_the_result_budget() -> None:
    """Historical breadth and result volume are separate controls."""
    limits = DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP]
    widened = limits.with_lookback_days(3653)
    assert widened.lookback_days == 3653
    assert widened.page_size == limits.page_size
    assert widened.max_candidates == limits.max_candidates
    assert widened.max_per_group == limits.max_per_group


def test_a_window_is_clamped_to_the_models_own_ceiling() -> None:
    limits = DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP]
    assert limits.with_lookback_days(1_000_000).lookback_days == MAX_LOOKBACK_DAYS
    assert limits.with_lookback_days(0).lookback_days == 1


# --------------------------------------------------------------------------- #
# Calendar-month arithmetic
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("moment", "months", "expected"),
    [
        (datetime(2026, 8, 22, tzinfo=UTC), 48, datetime(2022, 8, 22, tzinfo=UTC)),
        (datetime(2026, 8, 22, tzinfo=UTC), 120, datetime(2016, 8, 22, tzinfo=UTC)),
        (datetime(2026, 1, 15, tzinfo=UTC), 1, datetime(2025, 12, 15, tzinfo=UTC)),
        (datetime(2026, 3, 31, tzinfo=UTC), 1, datetime(2026, 2, 28, tzinfo=UTC)),
        (datetime(2024, 2, 29, tzinfo=UTC), 12, datetime(2023, 2, 28, tzinfo=UTC)),
        (datetime(2026, 8, 22, tzinfo=UTC), 0, datetime(2026, 8, 22, tzinfo=UTC)),
    ],
)
def test_months_are_counted_on_the_calendar(
    moment: datetime, months: int, expected: datetime
) -> None:
    """A 30-day month drifts by nearly two months over a decade."""
    assert subtract_months(moment, months) == expected


def test_a_month_count_beyond_the_ceiling_is_bounded() -> None:
    moment = datetime(2026, 8, 22, tzinfo=UTC)
    assert subtract_months(moment, 10_000) == subtract_months(moment, MAX_LOOKBACK_MONTHS)


@pytest.mark.parametrize(
    ("months", "expected_days"),
    [(1, 31), (6, 181), (12, 365), (48, 1461), (120, 3652)],
)
def test_a_month_range_becomes_the_exact_day_offset(months: int, expected_days: int) -> None:
    assert lookback_days_for_months(months, now=NOW) == expected_days


def test_a_day_offset_is_never_zero_or_unbounded() -> None:
    assert lookback_days_for_months(0, now=NOW) == 1
    assert lookback_days_for_months(100_000, now=NOW) <= MAX_LOOKBACK_DAYS


# --------------------------------------------------------------------------- #
# The date bound cannot be removed through a value
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        'example.com" OR page.domain:"victim.com',
        "example.com) OR (date:>now-10y",
        "example.com AND date:>now-10y",
        "example.com*",
    ],
)
def test_an_ioc_cannot_smuggle_its_way_past_the_date_bound(value: str) -> None:
    """The value never becomes syntax, so it can never reach the bound."""
    with pytest.raises(ValidationError):
        SearchTerm(field_name=UrlscanSearchField.PAGE_DOMAIN, value=value)


def test_a_url_value_containing_query_syntax_stays_inside_its_own_term() -> None:
    """URL values accept punctuation, so escaping is what protects the bound.

    A URL with whitespace in it is refused outright by the field's shape check,
    so the only injection worth testing here is one that keeps the URL shape.
    """
    term = SearchTerm(
        field_name=UrlscanSearchField.PAGE_URL,
        value='https://evil.example/?x="OR+date:>now-10y+OR+"',
    )
    query = build_query([term], since="now-30d")
    assert query.endswith(" AND date:>now-30d")
    # The injected text survives as literal characters inside the quoted phrase
    # — its quotes are escaped, so it never becomes a second condition.
    assert query.count(" AND date:>") == 1
    assert '\\"' in query


def test_the_bound_survives_a_multi_term_query() -> None:
    plan = plan_search(observable(IntelObjectType.URL, "https://example.com/a?b=c"))
    assert plan is not None
    assert plan.query.endswith(" AND date:>now-180d")
    assert plan.query.count("date:>") == 1
