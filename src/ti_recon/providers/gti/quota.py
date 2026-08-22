"""GTI quota discovery (Task 7).

GTI reports an account's remaining entitlement at
``/users/{apikey}/overall_quotas``. Two things about that endpoint shape this
module.

**The API key is in the path.** So nothing here ever builds, stores, returns or
logs the path — the client builds it internally and hands over only the parsed
body. A failure is reported as "quota lookup failed" plus a normalized category,
never as the URL that failed.

**Not every reported bucket gates what we do.** The response includes
allowances for features TI Recon does not use, and
:attr:`ProviderQuotaSnapshot.is_exhausted` is true if *any* bucket is spent.
Putting a spent ``intelligence_searches_monthly`` into the snapshot would
therefore switch GTI off entirely over an allowance no lookup consumes. Only the
API-request buckets go into the gating snapshot; the rest are parsed and returned
alongside it so nothing is silently discarded.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final

from ti_recon.models.base import FrozenTiReconModel, utc_now
from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID
from ti_recon.providers.quota import ProviderQuotaSnapshot, QuotaBucket, QuotaPeriod

__all__ = [
    "GATING_QUOTA_PREFIX",
    "QUOTA_PERIOD_SUFFIXES",
    "GTIQuotaReading",
    "parse_overall_quotas",
    "period_for_bucket",
]

#: Buckets whose exhaustion actually blocks an IOC lookup. Everything GTI
#: reports is parsed, but only these may gate execution.
GATING_QUOTA_PREFIX: Final[str] = "api_requests"

#: GTI names its buckets by period suffix. Anything unrecognized becomes
#: ``CUSTOM`` rather than being dropped — a new period is still a real limit.
QUOTA_PERIOD_SUFFIXES: Final[dict[str, QuotaPeriod]] = {
    "minutely": QuotaPeriod.MINUTE,
    "hourly": QuotaPeriod.HOUR,
    "daily": QuotaPeriod.DAY,
    "monthly": QuotaPeriod.MONTH,
}

#: The response nests counters under a consumer scope. ``user`` is the analyst's
#: own allowance and is what we care about; ``group`` is checked as a fallback
#: for keys that only report at organization level.
_CONSUMER_PREFERENCE: Final[tuple[str, ...]] = ("user", "group")


class GTIQuotaReading(FrozenTiReconModel):
    """One parsed ``overall_quotas`` response.

    ``snapshot`` holds only the buckets that gate execution. ``non_gating``
    holds the rest — reported for traceability, never able to block a lookup.
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


def period_for_bucket(name: str) -> QuotaPeriod:
    """The period a GTI bucket name implies."""
    tail = name.rsplit("_", 1)[-1]
    return QUOTA_PERIOD_SUFFIXES.get(tail, QuotaPeriod.CUSTOM)


def parse_overall_quotas(
    payload: Mapping[str, Any],
    *,
    user_id: str | None = None,
    provider_connection_id: str | None = None,
    retrieved_at: datetime | None = None,
) -> GTIQuotaReading:
    """Turn an ``overall_quotas`` body into a generic quota snapshot.

    The payload is the ``data`` object, not the envelope around it — the client
    unwraps it, so this function never sees anything derived from the request.

    Tolerant by design: a bucket with an unreadable counter is skipped rather
    than failing the whole reading, because a schema change to one allowance
    should not blind us to the others.
    """
    gating: list[QuotaBucket] = []
    other: list[QuotaBucket] = []

    for name, block in sorted(payload.items()):
        bucket = _bucket_from_block(name, block)
        if bucket is None:
            continue
        if name.startswith(GATING_QUOTA_PREFIX):
            gating.append(bucket)
        else:
            other.append(bucket)

    snapshot = ProviderQuotaSnapshot(
        provider_id=GTI_PROVIDER_ID,
        user_id=user_id,
        provider_connection_id=provider_connection_id,
        retrieved_at=retrieved_at or utc_now(),
        buckets=tuple(gating),
    )
    return GTIQuotaReading(snapshot=snapshot, non_gating=tuple(other))


def _bucket_from_block(name: str, block: Any) -> QuotaBucket | None:
    """Build one bucket, or ``None`` if GTI sent nothing usable."""
    if not isinstance(block, Mapping):
        return None
    counters = _preferred_counters(block)
    if counters is None:
        return None
    allowed = _non_negative_int(counters.get("allowed"))
    used = _non_negative_int(counters.get("used"))
    if allowed is None and used is None:
        # A named bucket with no numbers tells us nothing, and an empty bucket
        # would read as "unknown remaining" rather than adding information.
        return None
    return QuotaBucket(
        name=name,
        period=period_for_bucket(name),
        allowed=allowed,
        used=used,
    )


def _preferred_counters(block: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for consumer in _CONSUMER_PREFERENCE:
        candidate = block.get(consumer)
        if isinstance(candidate, Mapping):
            return candidate
    # Some deployments report counters inline rather than per consumer.
    if any(key in block for key in ("allowed", "used")):
        return block
    return None


def _non_negative_int(value: Any) -> int | None:
    """Coerce a counter, refusing anything that is not a sane whole number."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    return number if number >= 0 else None
