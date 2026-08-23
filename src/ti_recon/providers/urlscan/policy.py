"""urlscan execution and lookup policy (Task 8).

Two kinds of policy live here.

:class:`UrlscanLookupPolicy` is provider-specific: how much history a lookup
reads, whether it may retrieve stored page artifacts, and which artifacts those
may be.

:func:`build_urlscan_execution_policy` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy` — cache TTLs, retry
budget, concurrency. It is a *default*, not a claim about urlscan's documented
limits; an operator tunes it, and Task 6 remains the only thing that acts on it.

The forensics gate
------------------

Retrieving a stored DOM or screenshot is an order of magnitude more expensive
than reading a scan summary, and it pulls page content — chosen by whoever is
being investigated — into TI Recon's memory. It must therefore never happen
because a lookup happened to run at a higher depth, or because a capability was
requested loosely.

So the gate is a conjunction, and both halves are the caller's explicit act:

* the request's depth must be ``DEEP`` — the analyst accepted the cost, and
* ``WEB_FORENSICS`` must be in ``requested_capabilities`` — the analyst asked
  for *this*, not merely for "everything urlscan has".

Neither alone is enough. A deep lookup that asked for reputation gets a deep
search and nothing else.

Forensics stays passive throughout. Everything it reads is content urlscan
already stored; no part of it causes a new visit to anybody's site.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import Field

from ti_recon.artifacts.models import ArtifactKind
from ti_recon.enums import ActivityMode, InvestigationDepth, ProviderCapability
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID
from ti_recon.providers.urlscan.search import (
    DEPTH_SEARCH_LIMITS,
    MAX_LOOKBACK_MONTHS,
    SearchLimits,
    lookback_days_for_months,
)

__all__ = [
    "DEFAULT_FORENSIC_ARTIFACTS",
    "FORENSICS_DEPTH",
    "HistoricalRangeSource",
    "SearchWindow",
    "UrlscanLookupPolicy",
    "build_urlscan_execution_policy",
    "forensics_requested",
    "resolve_search_window",
]

#: The only depth at which stored artifacts may be retrieved.
FORENSICS_DEPTH: Final[InvestigationDepth] = InvestigationDepth.DEEP

#: What a forensic run may retrieve by default.
#:
#: The screenshot is included because it is what an analyst actually looks at,
#: and the DOM because it is what the extraction reads. Response bodies are
#: included but separately budgeted: a page can serve hundreds of them.
DEFAULT_FORENSIC_ARTIFACTS: Final[frozenset[ArtifactKind]] = frozenset(
    {ArtifactKind.SCREENSHOT, ArtifactKind.DOM, ArtifactKind.RESPONSE_BODY}
)


class UrlscanLookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a urlscan lookup is performed."""

    #: Whether this deployment permits web forensics at all. Off switches the
    #: capability off everywhere, regardless of what a request asks for — an
    #: operator's decision outranks a caller's.
    allow_web_forensics: bool = True

    #: Which artifact kinds a forensic run may retrieve.
    forensic_artifacts: frozenset[ArtifactKind] = DEFAULT_FORENSIC_ARTIFACTS

    #: How many stored response bodies one forensic run may retrieve. Small on
    #: purpose: the interesting bodies are the page's own scripts, and a page
    #: can serve hundreds of images nobody needs.
    max_response_bodies: int = Field(default=5, ge=0, le=50)

    #: How long a quota reading stays useful. Short, because an allowance moves
    #: with every request; long enough that enrichment does not spend a call on
    #: quota before each lookup.
    quota_ttl_seconds: int = Field(default=300, ge=0, le=86_400)

    #: Whether a lookup may refresh quota at all.
    refresh_quota_on_lookup: bool = True

    #: Search bounds per depth. Overridable so an operator can trade cost for
    #: history without touching code.
    search_limits: dict[InvestigationDepth, SearchLimits] = Field(
        default_factory=lambda: dict(DEPTH_SEARCH_LIMITS)
    )

    @property
    def quota_refresh_enabled(self) -> bool:
        return self.refresh_quota_on_lookup and self.quota_ttl_seconds > 0

    def allows(self, kind: ArtifactKind) -> bool:
        return self.allow_web_forensics and kind in self.forensic_artifacts


class HistoricalRangeSource(StrEnum):
    """Where a search's historical window came from.

    Recorded on the result so an analyst can tell "DEEP searched ten years"
    from "DEEP searched one year because we could not find out what this
    account is allowed to search". Both are legitimate answers; only one of
    them is the answer the analyst asked for.
    """

    #: The window is the account's own maximum searchable range.
    PROVIDER_LIMIT = "provider_limit"
    #: The configured depth window applied as-is.
    CONFIGURED = "configured"
    #: DEEP wanted the account maximum and it was unknown, so the safe finite
    #: fallback applied.
    FALLBACK = "fallback"


class SearchWindow(FrozenTiReconModel):
    """The resolved bounds for one search, and where they came from."""

    limits: SearchLimits
    source: HistoricalRangeSource
    #: The account's reported maximum, when it decided the window.
    account_months: int | None = Field(default=None, ge=1)

    @property
    def lookback_days(self) -> int:
        return self.limits.lookback_days

    @property
    def is_fallback(self) -> bool:
        return self.source is HistoricalRangeSource.FALLBACK


def resolve_search_window(
    depth: InvestigationDepth,
    policy: UrlscanLookupPolicy | None = None,
    *,
    max_search_range_months: int | None = None,
    now: datetime,
) -> SearchWindow:
    """The window one search may cover, and the reason it is that wide.

    Three rules, and each depth uses exactly one of them:

    * QUICK and STANDARD keep their configured windows — a recent question and
      a broader-recent one — narrowed if the account may not search that far
      back. A generous account never widens them: nobody asked for more.
    * DEEP takes the account's maximum. A phishing kit first scanned in 2022 is
      still what identifies its 2026 redeployment, so "deep" means "as far back
      as this credential is entitled to look".
    * DEEP without that metadata takes the configured fallback, which is finite.
      A missing plan limit must never become an unbounded query, and it must
      never fail an otherwise useful investigation either.

    Months become days by calendar arithmetic against ``now``, which the caller
    supplies from its injected clock.

    What does *not* change with the window is how much comes back: page size,
    candidate count and the per-domain cap are the same at ten years as at
    thirty days. Historical breadth and result volume are separate controls.
    """
    limits = policy.search_limits if policy is not None else DEPTH_SEARCH_LIMITS
    configured = limits.get(depth, DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD])
    account_months = _usable_months(max_search_range_months)

    if account_months is None:
        # Unknown: the configured window stands, already finite. Only DEEP
        # calls that a fallback, because only DEEP asked for something else.
        source = (
            HistoricalRangeSource.FALLBACK
            if configured.use_account_maximum
            else HistoricalRangeSource.CONFIGURED
        )
        return SearchWindow(limits=configured, source=source)

    account_days = lookback_days_for_months(account_months, now=now)
    if configured.use_account_maximum:
        return SearchWindow(
            limits=configured.with_lookback_days(account_days),
            source=HistoricalRangeSource.PROVIDER_LIMIT,
            account_months=account_months,
        )
    if account_days < configured.lookback_days:
        return SearchWindow(
            limits=configured.with_lookback_days(account_days),
            source=HistoricalRangeSource.PROVIDER_LIMIT,
            account_months=account_months,
        )
    return SearchWindow(limits=configured, source=HistoricalRangeSource.CONFIGURED)


def _usable_months(months: int | None) -> int | None:
    """The account maximum, or ``None`` if urlscan reported nothing usable.

    Zero, negative and absent all mean the same thing here — we do not know how
    far back this credential may search — because urlscan defines no meaning
    for a zero-month range and guessing one would either forbid every search or
    permit an unbounded one.
    """
    if months is None or months < 1:
        return None
    return min(months, MAX_LOOKBACK_MONTHS)


def forensics_requested(
    request: ProviderRequest, policy: UrlscanLookupPolicy | None = None
) -> bool:
    """Whether this request explicitly asked for stored-artifact analysis.

    Both halves of the gate are checked here, in one place, so no caller can
    satisfy half of it by accident. An operator's ``allow_web_forensics=False``
    overrides both.

    Also requires the request to be passive — which every request is, since
    forensics never causes a visit. Checked anyway: if that ever stops being
    true, this returns ``False`` rather than quietly permitting an active run.
    """
    if policy is not None and not policy.allow_web_forensics:
        return False
    return (
        request.depth is FORENSICS_DEPTH
        and ProviderCapability.WEB_FORENSICS in request.requested_capabilities
        and request.activity_mode is ActivityMode.PASSIVE
    )


def build_urlscan_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
    max_concurrency: int = 4,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for urlscan.

    The cache scope is the part that is not tunable in spirit. An authenticated
    urlscan search can return scans that are visible only to the analyst's own
    key — unlisted and team-private ones. Serving that from a shared cache would
    hand one analyst another's private scans, so the scope stays ``USER``, which
    is also the framework default. Nothing here turns on ``GLOBAL``.

    TTLs follow the same reasoning as GTI's: a scan already happened and does
    not change, so successes keep for a while; "urlscan has never scanned this"
    changes the moment somebody scans it, so negative answers expire quickly.
    Partial results stay uncached so a truncated answer is never mistaken later
    for a complete one.
    """
    return ProviderExecutionPolicy(
        provider_id=URLSCAN_PROVIDER_ID,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=3600,
            no_data_ttl_seconds=300,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(),
        max_concurrency=max_concurrency,
    )
