"""What GreyNoise says about its own limits (Task 9).

Named for what it can actually do. TI Recon draws a firm line between a
**rate limit** ("too fast, try shortly") and a **quota** ("your plan's allowance
for the period is spent"), and for GreyNoise only the first is observable
through the endpoints this integration calls.

GreyNoise has no zero-cost allowance endpoint that this integration reads, so
there is deliberately **no** :class:`~ti_recon.providers.quota.ProviderQuotaSnapshot`
produced for GreyNoise. Manufacturing one from a lookup response would give the
Task 6 quota pre-check numbers that look authoritative and are not — and an
invented allowance is worse than none, because the pre-check would switch a
working provider off without ever calling it. A GreyNoise result carries a
:class:`~ti_recon.providers.result.RateLimitSnapshot` when the response said
something measurable, and carries nothing when it did not.

Parsing is tolerant and additive: GreyNoise does not document these headers as
part of its API contract, so each one is read if present and ignored if absent,
and a response with none of them yields ``None`` rather than an empty snapshot
that would read like a measurement.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, Final

from ti_recon.models.base import utc_now
from ti_recon.providers.greynoise.errors import parse_utc_timestamp
from ti_recon.providers.result import RateLimitSnapshot, RateLimitWindow

__all__ = ["parse_rate_limit_headers"]

#: Both spellings appear in the wild; whichever arrives is used.
_LIMIT_HEADERS: Final[tuple[str, ...]] = ("x-ratelimit-limit", "x-rate-limit-limit")
_REMAINING_HEADERS: Final[tuple[str, ...]] = ("x-ratelimit-remaining", "x-rate-limit-remaining")
_RESET_HEADERS: Final[tuple[str, ...]] = ("x-ratelimit-reset", "x-rate-limit-reset")
_RETRY_AFTER_HEADER: Final[str] = "retry-after"

#: A reset offset longer than this is a metering window rather than a wait.
_MAX_RESET_SECONDS: Final[float] = 32 * 24 * 60 * 60


def parse_rate_limit_headers(
    headers: Mapping[str, str],
    *,
    operation: str | None = None,
    now: datetime | None = None,
) -> RateLimitSnapshot | None:
    """Read whatever metering headers came with one response.

    Returns ``None`` when GreyNoise said nothing measurable. The reset instant
    is derived from an offset when only an offset was sent, because the
    execution layer prefers an offset — it cannot be skewed by a clock
    difference between us and the provider.
    """
    lowered = {name.lower(): value for name, value in headers.items()}
    limit = _non_negative_int(_first(lowered, _LIMIT_HEADERS))
    remaining = _non_negative_int(_first(lowered, _REMAINING_HEADERS))

    raw_reset = _first(lowered, _RESET_HEADERS)
    reset_after = _seconds(raw_reset)
    reset_at = parse_utc_timestamp(raw_reset) if reset_after is None else None
    if reset_after is None:
        # A ``Retry-After`` is the same statement in a different header, and it
        # is the one a 429 actually carries.
        reset_after = _seconds(lowered.get(_RETRY_AFTER_HEADER))
    if reset_at is None and reset_after is not None:
        reset_at = (now or utc_now()) + timedelta(seconds=reset_after)

    if limit is None and remaining is None and reset_at is None:
        return None

    window = RateLimitWindow(
        # GreyNoise does not name the window it metered against, so the window
        # is named for what it is rather than guessed at.
        window_name="reported",
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
        windows=(window,),
    )


def _first(headers: Mapping[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = headers.get(name)
        if value is not None:
            return value
    return None


def _seconds(value: str | None) -> float | None:
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
