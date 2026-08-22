"""urlscan quota and rate-limit discovery (Task 8).

urlscan meters two different things, and TI Recon has to keep them apart.

**Per-action allowances.** ``/user/quotas/`` reports an allowance for each
action — searching, retrieving results, and several kinds of *scanning*. TI
Recon never scans, so an exhausted scanning allowance says nothing about whether
a lookup can proceed. Since
:attr:`~ti_recon.providers.quota.ProviderQuotaSnapshot.is_exhausted` is true if
*any* bucket is spent, putting a spent ``public`` scan allowance into the gating
snapshot would switch urlscan off over an allowance no lookup consumes. Only the
read actions gate; the rest are parsed and returned alongside, so nothing is
silently discarded.

**Per-window throttling.** Every response carries ``X-Rate-Limit-*`` headers for
the window the request was metered against. Those become a
:class:`RateLimitSnapshot` on the result envelope, which is a different question
from "is this account's allowance spent".

Parsing is tolerant throughout: an unreadable bucket is skipped rather than
failing the whole reading, because a schema change to one allowance should not
blind us to the others.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, Final

from ti_recon.models.base import FrozenTiReconModel, utc_now
from ti_recon.providers.quota import ProviderQuotaSnapshot, QuotaBucket, QuotaPeriod
from ti_recon.providers.result import RateLimitSnapshot, RateLimitWindow
from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID
from ti_recon.providers.urlscan.errors import parse_reset_at

__all__ = [
    "GATING_ACTIONS",
    "QUOTA_PERIODS",
    "UrlscanQuotaReading",
    "parse_rate_limit_headers",
    "parse_user_quotas",
]

#: The actions TI Recon actually performs. Only these may block a lookup.
#:
#: ``search`` runs historical queries; ``retrieve`` reads stored results and
#: stored artifacts. Every other action urlscan meters — ``public``,
#: ``private``, ``unlisted``, ``livescan``, ``liveshot`` — is a *scan*, and this
#: integration cannot scan.
GATING_ACTIONS: Final[frozenset[str]] = frozenset({"search", "retrieve"})

#: Period names urlscan uses inside each action's block.
QUOTA_PERIODS: Final[dict[str, QuotaPeriod]] = {
    "minute": QuotaPeriod.MINUTE,
    "hour": QuotaPeriod.HOUR,
    "day": QuotaPeriod.DAY,
    "month": QuotaPeriod.MONTH,
}

#: Where the per-action blocks live in the response. Read from the envelope when
#: present and from the top level when not, so a flatter response still parses.
_LIMITS_KEY: Final[str] = "limits"

_HEADER_LIMIT: Final[str] = "x-rate-limit-limit"
_HEADER_REMAINING: Final[str] = "x-rate-limit-remaining"
_HEADER_RESET: Final[str] = "x-rate-limit-reset"
_HEADER_RESET_AFTER: Final[str] = "x-rate-limit-reset-after"
_HEADER_SCOPE: Final[str] = "x-rate-limit-scope"
_HEADER_ACTION: Final[str] = "x-rate-limit-action"
_HEADER_WINDOW: Final[str] = "x-rate-limit-window"

#: A reset offset longer than this is a metering window rather than a wait.
_MAX_RESET_SECONDS: Final[float] = 32 * 24 * 60 * 60


class UrlscanQuotaReading(FrozenTiReconModel):
    """One parsed ``/user/quotas/`` response.

    ``snapshot`` holds only the allowances that gate execution. ``non_gating``
    holds the scanning allowances — reported for traceability, never able to
    block a lookup TI Recon is actually capable of making.
    """

    snapshot: ProviderQuotaSnapshot
    non_gating: tuple[QuotaBucket, ...] = ()

    @property
    def is_exhausted(self) -> bool:
        """Whether a *gating* allowance is spent."""
        return self.snapshot.is_exhausted

    @property
    def bucket_names(self) -> tuple[str, ...]:
        gating = tuple(bucket.name for bucket in self.snapshot.buckets)
        return gating + tuple(bucket.name for bucket in self.non_gating)

    def can_perform(self, action: str) -> bool:
        """Whether every known allowance for ``action`` still has room.

        Unknown is not exhausted: an action urlscan reported nothing about is
        assumed available, because refusing to try on silence is worse than
        trying.
        """
        return not any(
            bucket.is_exhausted
            for bucket in self.snapshot.buckets
            if bucket.name.startswith(f"{action}_")
        )


def parse_user_quotas(
    payload: Mapping[str, Any],
    *,
    user_id: str | None = None,
    provider_connection_id: str | None = None,
    retrieved_at: datetime | None = None,
) -> UrlscanQuotaReading:
    """Turn a ``/user/quotas/`` body into a generic quota snapshot.

    Buckets are named ``<action>_<period>`` — urlscan's own vocabulary, so a
    snapshot stays readable without mapping anything onto ours.
    """
    now = retrieved_at or utc_now()
    limits = payload.get(_LIMITS_KEY)
    blocks: Mapping[str, Any] = limits if isinstance(limits, Mapping) else payload

    gating: list[QuotaBucket] = []
    other: list[QuotaBucket] = []
    for action, periods in sorted(blocks.items()):
        if not isinstance(periods, Mapping):
            continue
        target = gating if action in GATING_ACTIONS else other
        for period_name, counters in sorted(periods.items()):
            bucket = _bucket_from_counters(action, period_name, counters, now=now)
            if bucket is not None:
                target.append(bucket)

    snapshot = ProviderQuotaSnapshot(
        provider_id=URLSCAN_PROVIDER_ID,
        user_id=user_id,
        provider_connection_id=provider_connection_id,
        retrieved_at=now,
        buckets=tuple(gating),
    )
    return UrlscanQuotaReading(snapshot=snapshot, non_gating=tuple(other))


def parse_rate_limit_headers(
    headers: Mapping[str, str],
    *,
    operation: str | None = None,
    now: datetime | None = None,
) -> RateLimitSnapshot | None:
    """Read the ``X-Rate-Limit-*`` headers that came with one response.

    Returns ``None`` when urlscan said nothing measurable — an empty snapshot
    would look like a reading, and inventing numbers a scheduler would trust is
    worse than admitting we have none.
    """
    lowered = {name.lower(): value for name, value in headers.items()}
    limit = _non_negative_int(lowered.get(_HEADER_LIMIT))
    remaining = _non_negative_int(lowered.get(_HEADER_REMAINING))
    reset_after = _reset_seconds(lowered.get(_HEADER_RESET_AFTER))
    reset_at = parse_reset_at(lowered.get(_HEADER_RESET))
    if reset_at is None and reset_after is not None:
        reset_at = (now or utc_now()) + timedelta(seconds=reset_after)
    scope = _short_text(lowered.get(_HEADER_SCOPE))
    action = _short_text(lowered.get(_HEADER_ACTION))

    if limit is None and remaining is None and reset_at is None and scope is None:
        return None

    window_name = _short_text(lowered.get(_HEADER_WINDOW)) or scope or "window"
    window = RateLimitWindow(
        # The window carries the action it metered when urlscan names one, so a
        # search limit is never mistaken for a retrieval limit.
        window_name=f"{action}_{window_name}" if action else window_name,
        limit=limit,
        remaining=remaining,
        reset_at=reset_at,
        reset_after_seconds=reset_after,
    )
    return RateLimitSnapshot(
        operation=operation,
        limit=limit,
        remaining=remaining,
        reset_at=reset_at,
        scope=scope,
        windows=(window,),
    )


def _bucket_from_counters(
    action: str, period_name: str, counters: Any, *, now: datetime
) -> QuotaBucket | None:
    """Build one bucket, or ``None`` if urlscan sent nothing usable."""
    if not isinstance(counters, Mapping):
        return None
    allowed = _non_negative_int(counters.get("limit", counters.get("allowed")))
    used = _non_negative_int(counters.get("used"))
    remaining = _non_negative_int(counters.get("remaining"))
    if allowed is None and used is None and remaining is None:
        # A named allowance with no numbers tells us nothing, and an empty
        # bucket would read as "unknown remaining" rather than adding anything.
        return None
    return QuotaBucket(
        name=f"{action}_{period_name}",
        period=QUOTA_PERIODS.get(period_name.lower(), QuotaPeriod.CUSTOM),
        allowed=allowed,
        used=used,
        remaining=remaining,
        reset_at=_reset_instant(counters.get("reset"), now=now),
    )


def _reset_instant(value: Any, *, now: datetime) -> datetime | None:
    """Read a reset as an instant, whether urlscan sent an offset or a date."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        seconds = _reset_seconds(str(value))
        return None if seconds is None else now + timedelta(seconds=seconds)
    if isinstance(value, str):
        offset = _reset_seconds(value)
        if offset is not None:
            return now + timedelta(seconds=offset)
        return parse_reset_at(value)
    return None


def _reset_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, _MAX_RESET_SECONDS)


def _non_negative_int(value: Any) -> int | None:
    """Read a counter, ignoring anything that is not a plain whole number."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _short_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()[:64]
    return cleaned or None
