"""Provider account quota (Task 5 model, consumed by Task 6).

Rate limiting and account quota are related but not the same thing, and
collapsing them loses the distinction that matters operationally:

* a **rate limit** is short-term throttling — "too fast, try shortly";
* a **quota** is an entitlement for a period — "your plan's daily allowance is
  spent", which no amount of waiting inside one investigation will fix.

Providers expose quota in different shapes: several named buckets over several
periods, sometimes only one, sometimes none. So a snapshot holds a tuple of
buckets and every measurement is optional. A provider that tells us nothing
produces an empty snapshot, which is an honest answer.

These models live in the providers layer because an adapter is what reports
them; the execution layer stores and acts on them.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from ti_recon.models.base import FrozenTiReconModel, Identifier, UtcDatetime, utc_now

__all__ = ["ProviderQuotaSnapshot", "QuotaBucket", "QuotaPeriod"]


class QuotaPeriod(StrEnum):
    """The period a quota bucket is measured over.

    ``CUSTOM`` exists because provider periods are not ours to enumerate — a
    per-billing-cycle or per-campaign allowance should be representable without
    a change here.
    """

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    MONTH = "month"
    CUSTOM = "custom"


class QuotaBucket(FrozenTiReconModel):
    """One named allowance over one period.

    ``name`` is the provider's own name for the bucket, so a snapshot stays
    readable and no provider's vocabulary has to be mapped onto ours.
    """

    name: str = Field(min_length=1, max_length=64)
    period: QuotaPeriod
    allowed: int | None = Field(default=None, ge=0)
    used: int | None = Field(default=None, ge=0)
    remaining: int | None = Field(default=None, ge=0)
    reset_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _derive_remaining(self) -> QuotaBucket:
        """Fill in ``remaining`` when the provider gave allowance and usage.

        Derived rather than required, because providers report one shape or the
        other and callers should not have to know which.
        """
        if self.remaining is None and self.allowed is not None and self.used is not None:
            object.__setattr__(self, "remaining", max(0, self.allowed - self.used))
        return self

    @property
    def is_exhausted(self) -> bool:
        """Whether this allowance is spent.

        An unknown ``remaining`` is not treated as exhausted: refusing to call a
        provider because it told us nothing would be worse than trying.
        """
        return self.remaining is not None and self.remaining <= 0

    def delay_until_reset(self, now: datetime) -> float | None:
        """Seconds until this bucket refills, if the provider said."""
        if self.reset_at is None:
            return None
        return max(0.0, (self.reset_at - now).total_seconds())


class ProviderQuotaSnapshot(FrozenTiReconModel):
    """What one credential's quota looked like at one moment.

    Scoped to a user and, where known, to a specific provider connection: quota
    belongs to whoever's key is being spent, and one analyst's exhausted
    allowance says nothing about another's.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    user_id: Identifier | None = None
    provider_connection_id: Identifier | None = None
    retrieved_at: UtcDatetime = Field(default_factory=utc_now)
    buckets: tuple[QuotaBucket, ...] = ()

    @model_validator(mode="after")
    def _validate_snapshot(self) -> ProviderQuotaSnapshot:
        names = [bucket.name for bucket in self.buckets]
        if len(names) != len(set(names)):
            msg = "quota bucket names must be unique within a snapshot"
            raise ValueError(msg)
        return self

    def bucket(self, name: str) -> QuotaBucket | None:
        """The named bucket, or ``None`` if this provider does not report it."""
        for candidate in self.buckets:
            if candidate.name == name:
                return candidate
        return None

    @property
    def exhausted_buckets(self) -> tuple[QuotaBucket, ...]:
        return tuple(bucket for bucket in self.buckets if bucket.is_exhausted)

    @property
    def is_exhausted(self) -> bool:
        """Whether any allowance is spent.

        Any single exhausted bucket blocks the credential: a daily allowance
        being spent is not rescued by the monthly one having room.
        """
        return bool(self.exhausted_buckets)

    @property
    def is_empty(self) -> bool:
        return not self.buckets

    def next_reset_at(self, now: datetime) -> datetime | None:
        """The soonest moment an exhausted bucket refills, if any is known."""
        candidates = [
            bucket.reset_at
            for bucket in self.exhausted_buckets
            if bucket.reset_at is not None and bucket.reset_at > now
        ]
        return min(candidates) if candidates else None
