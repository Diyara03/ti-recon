"""Censys credit discovery (Task 9).

Censys meters direct asset lookups with **credits**, and TI Recon has to be
careful about what that is. A credit balance is a purchased wallet, not a
calendar window: it does not refill at midnight, and no amount of waiting brings
it back. That is precisely the distinction
:mod:`ti_recon.providers.quota` exists to preserve — a rate limit is "too fast",
a quota is "spent" — and the two must not be collapsed, because the execution
layer schedules a retry for one and stops calling for the other.

So a credit reading becomes a
:class:`~ti_recon.providers.quota.ProviderQuotaSnapshot` with a single bucket
over :attr:`~ti_recon.providers.quota.QuotaPeriod.CUSTOM`. ``CUSTOM`` is the
honest period here: labelling a wallet ``MONTH`` would invite a scheduler to
believe it resets on the first, which nothing about the balance promises.

Why reading it is worth a request
---------------------------------

The credits endpoints cost zero credits. That makes them the only way to
validate a token, and to notice an exhausted balance, without spending the very
resource being measured. Every other Censys endpoint this integration calls
costs a credit, so "check whether the key works by looking something up" would
charge the analyst for the privilege of being told their key is fine.

Parsing is tolerant throughout: an unreadable counter is skipped rather than
failing the whole reading, because a schema change to one field should not blind
us to the others.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from ti_recon.models.base import FrozenTiReconModel, utc_now
from ti_recon.providers.censys.descriptor import CENSYS_PROVIDER_ID
from ti_recon.providers.censys.errors import parse_utc_timestamp
from ti_recon.providers.quota import ProviderQuotaSnapshot, QuotaBucket, QuotaPeriod

__all__ = [
    "ALLOWED_KEYS",
    "CREDIT_BUCKET_NAME",
    "REMAINING_KEYS",
    "USED_KEYS",
    "CensysCreditReading",
    "CensysCreditScope",
    "parse_credits",
]

#: The one bucket name a Censys quota snapshot uses. Fixed rather than derived
#: from the response, so a scope change cannot silently create a second bucket
#: that an exhaustion check would then read as an extra limit.
CREDIT_BUCKET_NAME: Final[str] = "credits"

#: Where a total allowance may appear, in preference order.
ALLOWED_KEYS: Final[tuple[str, ...]] = ("limit", "total", "allowed", "granted", "quota")

#: Where consumption may appear.
USED_KEYS: Final[tuple[str, ...]] = ("used", "consumed", "spent")

#: Where the remaining balance may appear. ``balance`` and ``available`` are
#: Censys's wallet vocabulary; the rest are the generic spellings.
REMAINING_KEYS: Final[tuple[str, ...]] = ("remaining", "balance", "available", "left")

#: Where the counters may be nested. Checked in order, and the first mapping
#: that yields a usable counter wins.
_CONTAINER_KEYS: Final[tuple[str, ...]] = ("credits", "resource", "result", "data")

#: Where a reset or expiry instant may appear, if the plan has one at all.
_RESET_KEYS: Final[tuple[str, ...]] = ("reset_at", "resets_at", "expires_at", "renews_at")


class CensysCreditScope(StrEnum):
    """Whose balance a reading describes.

    Recorded because the two are different numbers about different accounts, and
    a snapshot that did not say which it was could be compared with the wrong
    one.
    """

    USER = "user"
    ORGANIZATION = "organization"


class CensysCreditReading(FrozenTiReconModel):
    """One parsed credits response."""

    snapshot: ProviderQuotaSnapshot
    scope: CensysCreditScope

    @property
    def is_exhausted(self) -> bool:
        """Whether the balance is spent.

        An unknown balance is never exhausted: refusing to call Censys because
        it told us nothing measurable would be worse than trying.
        """
        return self.snapshot.is_exhausted

    @property
    def bucket(self) -> QuotaBucket | None:
        return self.snapshot.bucket(CREDIT_BUCKET_NAME)

    @property
    def remaining(self) -> int | None:
        bucket = self.bucket
        return bucket.remaining if bucket is not None else None


def parse_credits(
    payload: Mapping[str, Any],
    *,
    scope: CensysCreditScope,
    user_id: str | None = None,
    provider_connection_id: str | None = None,
    retrieved_at: datetime | None = None,
) -> CensysCreditReading:
    """Turn a credits response into a generic quota snapshot.

    A response with no readable counter produces an *empty* snapshot rather than
    a bucket of zeroes. That distinction is load-bearing: an empty snapshot means
    "we do not know", and Task 6 treats not knowing as permission to try, while a
    zero bucket means "spent" and stops the provider from being called at all.
    """
    now = retrieved_at or utc_now()
    counters = _counters(payload)
    allowed = _first_int(counters, ALLOWED_KEYS)
    used = _first_int(counters, USED_KEYS)
    remaining = _first_int(counters, REMAINING_KEYS)

    buckets: tuple[QuotaBucket, ...] = ()
    if allowed is not None or used is not None or remaining is not None:
        buckets = (
            QuotaBucket(
                name=CREDIT_BUCKET_NAME,
                # A wallet, not a window. See the module docstring.
                period=QuotaPeriod.CUSTOM,
                allowed=allowed,
                used=used,
                remaining=remaining,
                reset_at=_reset_instant(counters),
            ),
        )

    snapshot = ProviderQuotaSnapshot(
        provider_id=CENSYS_PROVIDER_ID,
        user_id=user_id,
        provider_connection_id=provider_connection_id,
        retrieved_at=now,
        buckets=buckets,
    )
    return CensysCreditReading(snapshot=snapshot, scope=scope)


def _counters(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Find the mapping that actually holds the counters.

    Censys nests the same numbers differently across endpoints and versions, so
    the containers are tried in order and the first one carrying a recognizable
    counter wins. The top level is tried last, which means a nested reading is
    never shadowed by a stray same-named key on the envelope.
    """
    for key in _CONTAINER_KEYS:
        nested = payload.get(key)
        if not isinstance(nested, Mapping):
            continue
        if _has_counter(nested):
            return nested
        # One more level: the platform wraps a resource inside a result.
        for inner_key in _CONTAINER_KEYS:
            deeper = nested.get(inner_key)
            if isinstance(deeper, Mapping) and _has_counter(deeper):
                return deeper
    return payload


def _has_counter(candidate: Mapping[str, Any]) -> bool:
    return any(
        _non_negative_int(candidate.get(key)) is not None
        for key in ALLOWED_KEYS + USED_KEYS + REMAINING_KEYS
    )


def _first_int(counters: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = _non_negative_int(counters.get(key))
        if value is not None:
            return value
    return None


def _reset_instant(counters: Mapping[str, Any]) -> datetime | None:
    for key in _RESET_KEYS:
        value = counters.get(key)
        if isinstance(value, str):
            parsed = parse_utc_timestamp(value)
            if parsed is not None:
                return parsed
    return None


def _non_negative_int(value: Any) -> int | None:
    """Read a counter, ignoring anything that is not a plain whole number."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None
