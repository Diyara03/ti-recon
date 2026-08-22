"""Safe historical scan discovery (Task 8).

urlscan's Search API takes an ElasticSearch query-string expression. That
language has field selectors, wildcards, regular expressions, ranges and boolean
operators, which makes "pass the analyst's input through" a query-injection
vulnerability rather than a convenience: a submitted value containing a quote
could close the term and append conditions of its own, widening the search to
somebody else's scans or turning one lookup into an unbounded scan of the index.

So no query ever reaches this module as text. A query is *composed* here from an
allowlisted field and a value validated against the shape that field can hold —
an IP that parses, a domain of label characters, a SHA-256 of 64 hex digits.
Boolean structure is ours, never the caller's.

The second job here is bounding. A domain can have tens of thousands of scans,
and each full result is a large document. Discovery therefore returns a *plan* —
how many hits to ask for, how many of them to actually retrieve — derived from
the investigation's depth, and selection spends that budget on distinct
infrastructure rather than on fifty scans of the same page.
"""

from __future__ import annotations

import ipaddress
import re
from calendar import monthrange
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import Field, field_validator

from ti_recon.enums import IntelObjectType, InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.urlscan.errors import parse_utc_timestamp

__all__ = [
    "DEEP_FALLBACK_LOOKBACK_DAYS",
    "DEPTH_SEARCH_LIMITS",
    "MAX_LOOKBACK_DAYS",
    "MAX_LOOKBACK_MONTHS",
    "ScanCandidate",
    "SearchLimits",
    "SearchTerm",
    "UrlscanSearchField",
    "UrlscanSearchPlan",
    "build_query",
    "cursor_for_hit",
    "lookback_days_for_months",
    "parse_hits",
    "plan_search",
    "select_candidates",
    "subtract_months",
]


class UrlscanSearchField(StrEnum):
    """The only fields TI Recon will ever search on.

    An allowlist rather than a validator: a field name that is not one of these
    cannot be expressed, so no caller can reach an unindexed, expensive or
    privacy-sensitive field by naming it.
    """

    #: The page the browser ended on after redirects.
    PAGE_DOMAIN = "page.domain"
    PAGE_IP = "page.ip"
    PAGE_ASN = "page.asn"
    PAGE_URL = "page.url"
    #: What was submitted, before redirects.
    TASK_DOMAIN = "task.domain"
    TASK_URL = "task.url"
    #: Every domain, IP, ASN or URL the page contacted, not just the final one.
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    #: SHA-256 of a response body the page served.
    HASH = "hash"


#: The longest lookback any depth may configure. Two years is far beyond what
#: current-infrastructure questions need and still finite.
MAX_LOOKBACK_DAYS: Final[int] = 7305

#: TI Recon's own ceiling on an account's reported search range, in months.
#:
#: A generous urlscan plan can report a range longer than anyone investigates
#: over; twenty years is already far past the point where an old scan is a
#: pivot rather than history, and a finite ceiling keeps the derived day count
#: inside :data:`MAX_LOOKBACK_DAYS`.
MAX_LOOKBACK_MONTHS: Final[int] = 240

#: What DEEP falls back to when the account's maximum cannot be determined.
#: A safety net, not the policy — see :data:`DEPTH_SEARCH_LIMITS`.
DEEP_FALLBACK_LOOKBACK_DAYS: Final[int] = 365

#: The only shape a date bound may take, checked where the query is composed.
_LOOKBACK_EXPRESSION: Final[re.Pattern[str]] = re.compile(r"^now-[0-9]{1,4}d$")

#: How a value must look, per field. Each is deliberately strict: these are
#: normalized observables, not free text, so anything that fails to match is a
#: bug or an attack rather than an unusual input.
_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_ASN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^AS[1-9][0-9]{0,9}$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^https?://[!-~]{1,2000}$")
_SCAN_UUID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Fields whose values are URLs, where the syntax check is applied to a
#: percent-encoded form instead: a URL legitimately contains ``/``, ``?`` and
#: ``&``, so it is escaped rather than rejected.
_URL_FIELDS: Final[frozenset[UrlscanSearchField]] = frozenset(
    {UrlscanSearchField.PAGE_URL, UrlscanSearchField.TASK_URL, UrlscanSearchField.URL}
)


class SearchTerm(FrozenTiReconModel):
    """One ``field:"value"`` condition, validated on construction."""

    field_name: UrlscanSearchField
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def _reject_control_characters(cls, value: str) -> str:
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            msg = "search value must not contain control characters"
            raise ValueError(msg)
        return value

    def model_post_init(self, context: Any, /) -> None:
        _validate_value_for_field(self.field_name, self.value)

    def render(self) -> str:
        """The query fragment for this term.

        Always quoted, so the value is one phrase rather than a sequence of
        tokens the parser could interpret.
        """
        return f'{self.field_name.value}:"{_escape(self.value)}"'


class SearchLimits(FrozenTiReconModel):
    """How much of urlscan's history one lookup may spend."""

    #: Hits requested from the Search API in one page.
    page_size: int = Field(ge=1, le=1000)
    #: Full scan results actually retrieved. Each is a large document, so this
    #: is the number that decides what a lookup costs.
    max_candidates: int = Field(ge=1, le=50)
    #: Candidates allowed from one page domain, so a single busy site cannot
    #: consume the whole budget and hide the rest of the infrastructure.
    max_per_group: int = Field(ge=1, le=50)
    #: How far back to look, in days. There is deliberately no "unbounded"
    #: value: an open-ended query over urlscan's whole index is expensive for
    #: urlscan, slow for the analyst, and — on an account whose plan limits the
    #: searchable range — rejected outright rather than silently narrowed.
    #:
    #: When :attr:`use_account_maximum` is set this is the *fallback* window,
    #: used only when the account's own maximum is unknown.
    lookback_days: int = Field(ge=1, le=MAX_LOOKBACK_DAYS)

    #: Whether this depth should reach as far back as the credential allows.
    #:
    #: Set for DEEP and for nothing else. A phishing kit first scanned in 2022
    #: is still the pivot that identifies the 2026 deployment, so a deep
    #: investigation asks for everything the analyst's account is entitled to
    #: search — while retrieving the same small number of scans as always.
    use_account_maximum: bool = False

    @property
    def since(self) -> str:
        """The date bound as the query language's own expression."""
        return f"now-{self.lookback_days}d"

    def with_lookback_days(self, days: int) -> SearchLimits:
        """The same budget over a different window.

        Only the window changes. Page size, candidate count and the per-domain
        cap are untouched, because how far back a search reaches and how many
        scans it retrieves are separate controls: a decade of history still
        returns a handful of representative scans.
        """
        return self.model_copy(update={"lookback_days": min(max(1, days), MAX_LOOKBACK_DAYS)})


#: Depth is the analyst's cost signal, so it decides the window.
#:
#: QUICK asks "what has urlscan seen recently?" — a month. STANDARD asks for
#: broader recent context — half a year. DEEP asks "search as far back as this
#: analyst's access permits", which is why its window comes from the account
#: rather than from a number here; the 365 days below is only the fallback for
#: when the account's maximum cannot be determined.
#:
#: Every depth is bounded. An unbounded query is not "more thorough": it asks
#: urlscan to scan its whole index, and an account whose plan caps the
#: searchable range would have the query refused rather than quietly narrowed.
#:
#: The candidate counts are unrelated to the window and do not grow with it —
#: see :meth:`SearchLimits.with_lookback_days`.
DEPTH_SEARCH_LIMITS: Final[dict[InvestigationDepth, SearchLimits]] = {
    InvestigationDepth.QUICK: SearchLimits(
        page_size=10, max_candidates=1, max_per_group=1, lookback_days=30
    ),
    InvestigationDepth.STANDARD: SearchLimits(
        page_size=50, max_candidates=3, max_per_group=2, lookback_days=180
    ),
    InvestigationDepth.DEEP: SearchLimits(
        page_size=100,
        max_candidates=8,
        max_per_group=3,
        lookback_days=DEEP_FALLBACK_LOOKBACK_DAYS,
        use_account_maximum=True,
    ),
}


class UrlscanSearchPlan(FrozenTiReconModel):
    """What to ask urlscan, and how much of the answer to use."""

    query: str = Field(min_length=1, max_length=1024)
    limits: SearchLimits
    terms: tuple[SearchTerm, ...] = ()

    @property
    def page_size(self) -> int:
        return self.limits.page_size


class ScanCandidate(FrozenTiReconModel):
    """One search hit, reduced to what selection and retrieval need.

    Nothing here is fetched. The URLs are recorded as strings for provenance and
    are never visited: a suspicious URL is investigated *through* urlscan, never
    by TI Recon following it.
    """

    scan_id: str = Field(min_length=36, max_length=36)
    submitted_url: str | None = Field(default=None, max_length=2048)
    final_url: str | None = Field(default=None, max_length=2048)
    page_domain: str | None = Field(default=None, max_length=253)
    page_ip: str | None = Field(default=None, max_length=45)
    page_asn: str | None = Field(default=None, max_length=16)
    scanned_at: datetime | None = None
    visibility: str | None = Field(default=None, max_length=32)
    cursor: str | None = Field(default=None, max_length=200)

    @property
    def group_key(self) -> str:
        """What counts as "the same infrastructure" when spending the budget."""
        return self.page_domain or self.page_ip or self.scan_id


def _escape(value: str) -> str:
    """Escape what the query language would otherwise read as syntax."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_value_for_field(field_name: UrlscanSearchField, value: str) -> None:
    """Refuse a value that does not have the shape its field can hold.

    This is the defense against query injection, and it works by exclusion
    rather than by blocklisting syntax: an IP must parse, a domain must be
    label characters, a hash must be 64 hex digits. None of those shapes can
    express a quote, a wildcard, a boolean or a second field, so there is no
    list of dangerous characters to keep up to date. URLs are the exception —
    they legitimately contain the punctuation — and are escaped and quoted.
    """
    if field_name in _URL_FIELDS:
        if not _URL_PATTERN.match(value):
            msg = "URL search values must be absolute http(s) URLs"
            raise ValueError(msg)
        # A URL legitimately contains most of the query language's punctuation,
        # so it is escaped and quoted rather than character-checked.
        return

    if field_name in {UrlscanSearchField.IP, UrlscanSearchField.PAGE_IP}:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            msg = "IP search values must be an IP address"
            raise ValueError(msg) from exc
    elif field_name in {UrlscanSearchField.ASN, UrlscanSearchField.PAGE_ASN}:
        if not _ASN_PATTERN.match(value):
            msg = "ASN search values must look like AS12345"
            raise ValueError(msg)
    elif field_name is UrlscanSearchField.HASH:
        if not _SHA256_PATTERN.match(value):
            msg = "hash search values must be a lowercase SHA-256 digest"
            raise ValueError(msg)
    elif not _DOMAIN_PATTERN.match(value):
        msg = "domain search values must be a hostname"
        raise ValueError(msg)


def subtract_months(moment: datetime, months: int) -> datetime:
    """``moment`` moved back by whole calendar months.

    Calendar arithmetic rather than a fixed month length, because
    ``maxSearchRangeMonths`` is expressed in months and a 30-day approximation
    drifts by nearly two months over a decade — enough to miss the scan a
    historical pivot depends on. A day that does not exist in the target month
    lands on that month's last day, so 31 March minus one month is 28 February.

    No dependency is added for this: the whole calculation is two lines of
    integer arithmetic plus :func:`calendar.monthrange`.
    """
    bounded = max(0, min(months, MAX_LOOKBACK_MONTHS))
    total = moment.year * 12 + (moment.month - 1) - bounded
    year, month_index = divmod(total, 12)
    month = month_index + 1
    day = min(moment.day, monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def lookback_days_for_months(months: int, *, now: datetime) -> int:
    """How many days back ``months`` calendar months reaches from ``now``.

    The query language takes a day offset, so the calendar boundary is turned
    into one here rather than being approximated. ``now`` is supplied by the
    caller's injected clock, which keeps this deterministic under test.
    """
    delta = now - subtract_months(now, months)
    return max(1, min(delta.days, MAX_LOOKBACK_DAYS))


def build_query(terms: Sequence[SearchTerm], *, since: str) -> str:
    """Compose an ``OR`` of terms, bounded in time.

    The boolean structure is fixed here and never comes from a caller. Several
    terms describe the same observable seen in different roles — the page's own
    domain, and any domain the page contacted — so ``OR`` is the only join that
    makes sense, and a caller cannot ask for another.

    ``since`` is required and its shape is checked, which is what makes "every
    normal search is date bounded" structural: there is no argument that
    produces an unbounded query, and a value that is not a plain ``now-<n>d``
    expression is rejected rather than concatenated into the query. The bound is
    appended with ``AND`` after the terms are grouped, so no value inside a term
    can escape its own parentheses and disable it.
    """
    if not terms:
        msg = "a search needs at least one term"
        raise ValueError(msg)
    if not _LOOKBACK_EXPRESSION.match(since):
        msg = "a search bound must be a now-<days>d expression"
        raise ValueError(msg)
    rendered = " OR ".join(term.render() for term in terms)
    if len(terms) > 1:
        rendered = f"({rendered})"
    return f"{rendered} AND date:>{since}"


def plan_search(
    intel_object: IntelObject,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
    limits: SearchLimits | None = None,
) -> UrlscanSearchPlan | None:
    """Build the search for an observable, or ``None`` if urlscan indexes none.

    ``None`` is a real answer — an MD5 or SHA-1 cannot be searched, because
    urlscan indexes response bodies by SHA-256 only. Reporting that as "no
    results" would turn a coverage gap into a false absence of evidence.
    """
    effective = limits or DEPTH_SEARCH_LIMITS[depth]
    terms = _terms_for(intel_object)
    if not terms:
        return None
    return UrlscanSearchPlan(
        query=build_query(terms, since=effective.since),
        limits=effective,
        terms=terms,
    )


def _terms_for(intel_object: IntelObject) -> tuple[SearchTerm, ...]:
    """Which fields answer for an observable, most specific first."""
    value = intel_object.canonical_value
    match intel_object.object_type:
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            fields = (UrlscanSearchField.PAGE_IP, UrlscanSearchField.IP)
        case IntelObjectType.DOMAIN_NAME:
            fields = (UrlscanSearchField.PAGE_DOMAIN, UrlscanSearchField.DOMAIN)
        case IntelObjectType.URL:
            fields = (UrlscanSearchField.PAGE_URL, UrlscanSearchField.TASK_URL)
        case IntelObjectType.FILE:
            digest = intel_object.hashes.get("SHA-256")
            if not digest:
                # urlscan indexes response bodies by SHA-256 only.
                return ()
            return (SearchTerm(field_name=UrlscanSearchField.HASH, value=digest),)
        case _:
            return ()
    return tuple(SearchTerm(field_name=field_name, value=value) for field_name in fields)


def parse_hits(payload: Mapping[str, Any]) -> tuple[ScanCandidate, ...]:
    """Reduce a search response to candidates, skipping anything unusable.

    Every field is provider-controlled, so each is read defensively: a hit
    without a usable scan id is dropped rather than allowed to reach a URL path,
    and a malformed hit does not fail the whole page.
    """
    results = payload.get("results")
    if not isinstance(results, list):
        return ()
    candidates: list[ScanCandidate] = []
    seen: set[str] = set()
    for hit in results:
        candidate = _candidate_from_hit(hit)
        if candidate is None or candidate.scan_id in seen:
            continue
        seen.add(candidate.scan_id)
        candidates.append(candidate)
    return tuple(candidates)


def _candidate_from_hit(hit: Any) -> ScanCandidate | None:
    if not isinstance(hit, Mapping):
        return None
    scan_id = _text(hit.get("_id"), 36)
    if scan_id is None or not _SCAN_UUID_PATTERN.match(scan_id):
        return None
    task = _block(hit.get("task"))
    page = _block(hit.get("page"))
    return ScanCandidate(
        scan_id=scan_id.lower(),
        submitted_url=_text(task.get("url"), 2048),
        final_url=_text(page.get("url"), 2048),
        page_domain=_text(page.get("domain"), 253),
        page_ip=_text(page.get("ip"), 45),
        page_asn=_text(page.get("asn"), 16),
        scanned_at=parse_utc_timestamp(_text(task.get("time"), 64)),
        visibility=_text(task.get("visibility"), 32),
        cursor=cursor_for_hit(hit),
    )


def _block(value: Any) -> Mapping[str, Any]:
    """A nested object, or an empty one when urlscan sent something else."""
    return value if isinstance(value, Mapping) else {}


def cursor_for_hit(hit: Mapping[str, Any]) -> str | None:
    """The ``search_after`` cursor that continues paging past this hit."""
    sort = hit.get("sort")
    if not isinstance(sort, list) or not sort:
        return None
    parts = [str(item) for item in sort if isinstance(item, str | int | float)]
    if len(parts) != len(sort):
        return None
    cursor = ",".join(parts)
    return cursor[:200] or None


def select_candidates(
    candidates: Iterable[ScanCandidate], limits: SearchLimits
) -> tuple[ScanCandidate, ...]:
    """Spend the retrieval budget on distinct infrastructure, newest first.

    Two rules, in order. Recency first, because a page's current behaviour
    matters more than what it did last year. Then a per-domain cap, because
    fifty scans of one popular site would otherwise crowd out the one scan that
    shows the observable somewhere else — which is exactly the pivot an analyst
    is looking for. If the cap leaves budget unspent, it is filled from the
    remaining hits rather than wasted.
    """
    ordered = sorted(candidates, key=_recency_key)
    selected: list[ScanCandidate] = []
    deferred: list[ScanCandidate] = []
    per_group: dict[str, int] = {}

    for candidate in ordered:
        if len(selected) >= limits.max_candidates:
            break
        group = candidate.group_key
        if per_group.get(group, 0) >= limits.max_per_group:
            deferred.append(candidate)
            continue
        per_group[group] = per_group.get(group, 0) + 1
        selected.append(candidate)

    for candidate in deferred:
        if len(selected) >= limits.max_candidates:
            break
        selected.append(candidate)
    return tuple(selected)


def _recency_key(candidate: ScanCandidate) -> tuple[int, float, str]:
    """Newest first; scans with no usable timestamp go last, deterministically."""
    if candidate.scanned_at is None:
        return (1, 0.0, candidate.scan_id)
    return (0, -candidate.scanned_at.timestamp(), candidate.scan_id)


def _text(value: Any, max_length: int) -> str | None:
    """A bounded, control-character-free string, or ``None``."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character
        for character in value.strip()
        if ord(character) >= 0x20 and ord(character) != 0x7F
    )[:max_length]
    return cleaned or None
