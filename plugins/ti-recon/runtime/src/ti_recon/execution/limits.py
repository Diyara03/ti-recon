"""Quota and cooldown tracking (Task 6).

Two pieces of state, both strictly scoped to one credential:

* **quota** — the last thing a provider said about this credential's remaining
  entitlement, so an investigation can skip a provider whose allowance is spent
  instead of spending a request to be told so;
* **cooldown** — a decision not to call something for a while, because we
  already know the answer would be a refusal.

Cooldowns are per *operation* by default, with provider-wide as an explicit
choice. That distinction is load-bearing: a provider commonly limits one action
much more tightly than the rest, and blocking a whole integration because its
cheapest search endpoint is throttled would throw away coverage we still have.

Only in-memory implementations exist. They are single-process: two workers do
not share a cooldown, so each will independently discover a throttled provider.
The protocols are the seams a Redis-backed implementation will slot into.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from pydantic import Field

from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.models import CooldownReason, ExecutionScope
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.result import RateLimitSnapshot

__all__ = [
    "MAX_COOLDOWN_SECONDS",
    "CooldownEntry",
    "CooldownStore",
    "InMemoryCooldownStore",
    "InMemoryQuotaStore",
    "QuotaStore",
    "cooldown_from_quota",
    "cooldown_from_rate_limit",
    "make_cooldown",
    "make_credential_cooldown",
]

#: A cooldown longer than this is capped. A provider that reports a reset a week
#: away is far more likely to be misreporting than to be right, and honouring it
#: literally would silently remove an integration for a week.
MAX_COOLDOWN_SECONDS: float = 60.0 * 60.0 * 6.0


class CooldownEntry(FrozenTiReconModel):
    """A decision not to call a provider (or one of its operations) for a while.

    Carries only identifiers, a reason and a time. There is no field that could
    hold credential material, and ``scope_identity`` is the non-secret identity
    string built from user, provider and connection ids.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    scope_identity: str = Field(min_length=1, max_length=400)
    reason: CooldownReason
    until: UtcDatetime
    operation: str | None = Field(default=None, max_length=64)
    detail: str | None = Field(default=None, max_length=200)

    @property
    def is_provider_wide(self) -> bool:
        """Whether this blocks every operation, not just one."""
        return self.operation is None

    def is_active_at(self, moment: datetime) -> bool:
        return moment < self.until

    def remaining_seconds(self, moment: datetime) -> float:
        return max(0.0, (self.until - moment).total_seconds())


@runtime_checkable
class QuotaStore(Protocol):
    """Storage for the latest quota snapshot per credential scope."""

    async def get(self, scope_identity: str) -> ProviderQuotaSnapshot | None:
        """The most recent snapshot, or ``None`` if unknown or too stale."""
        ...

    async def put(self, scope_identity: str, snapshot: ProviderQuotaSnapshot) -> None:
        """Record a snapshot."""
        ...

    async def clear(self, scope_identity: str) -> None:
        """Forget one scope's snapshot."""
        ...


@runtime_checkable
class CooldownStore(Protocol):
    """Storage for active cooldowns per credential scope."""

    async def set(self, entry: CooldownEntry) -> None:
        """Record a cooldown."""
        ...

    async def active(
        self, *, scope_identity: str, operation: str | None = None
    ) -> CooldownEntry | None:
        """The cooldown currently blocking ``operation``, if any.

        Must consider both the operation-specific entry and any provider-wide
        entry, since a provider-wide cooldown blocks every operation.
        """
        ...

    async def entries(self, *, scope_identity: str) -> tuple[CooldownEntry, ...]:
        """Every active cooldown for one scope."""
        ...

    async def clear(self, *, scope_identity: str, operation: str | None = None) -> None:
        """Lift one cooldown, or every cooldown for the scope."""
        ...


class InMemoryQuotaStore:
    """Process-local quota state.

    **NOT FOR PRODUCTION.** Single-process and lost on restart.

    Snapshots expire after ``ttl_seconds``. Stale quota data is worse than none:
    acting on an hour-old "allowance exhausted" would keep a provider switched
    off long after it refilled.
    """

    is_production_ready: bool = False

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        ttl_seconds: float = 300.0,
        max_entries: int = 10_000,
    ) -> None:
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)
        self._clock = SystemClock() if clock is None else clock
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._snapshots: OrderedDict[str, tuple[ProviderQuotaSnapshot, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, scope_identity: str) -> ProviderQuotaSnapshot | None:
        async with self._lock:
            record = self._snapshots.get(scope_identity)
            if record is None:
                return None
            snapshot, stored_at = record
            if self._clock.monotonic() - stored_at >= self._ttl:
                del self._snapshots[scope_identity]
                return None
            self._snapshots.move_to_end(scope_identity)
            return snapshot

    async def put(self, scope_identity: str, snapshot: ProviderQuotaSnapshot) -> None:
        async with self._lock:
            self._snapshots[scope_identity] = (snapshot, self._clock.monotonic())
            self._snapshots.move_to_end(scope_identity)
            while len(self._snapshots) > self._max_entries:
                self._snapshots.popitem(last=False)

    async def clear(self, scope_identity: str) -> None:
        async with self._lock:
            self._snapshots.pop(scope_identity, None)

    def __len__(self) -> int:
        return len(self._snapshots)

    def __repr__(self) -> str:
        return f"<InMemoryQuotaStore scopes={len(self._snapshots)}>"


class InMemoryCooldownStore:
    """Process-local cooldown state.

    **NOT FOR PRODUCTION.** Single-process: two workers each discover a
    throttled provider independently rather than sharing the knowledge.

    Entries expire by clock, and setting a cooldown that would end sooner than
    one already active leaves the longer one in place — new information should
    not be able to shorten a limit we have already been told about.
    """

    is_production_ready: bool = False

    def __init__(self, *, clock: Clock | None = None, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)
        self._clock = SystemClock() if clock is None else clock
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str | None], CooldownEntry] = OrderedDict()
        self._lock = asyncio.Lock()

    async def set(self, entry: CooldownEntry) -> None:
        index = (entry.scope_identity, entry.operation)
        async with self._lock:
            existing = self._entries.get(index)
            now = self._clock.now()
            if (
                existing is not None
                and existing.is_active_at(now)
                and existing.until >= entry.until
            ):
                return
            self._entries[index] = entry
            self._entries.move_to_end(index)
            self._prune_locked(now)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    async def active(
        self, *, scope_identity: str, operation: str | None = None
    ) -> CooldownEntry | None:
        now = self._clock.now()
        async with self._lock:
            self._prune_locked(now)
            candidates = [
                entry
                for index in {(scope_identity, operation), (scope_identity, None)}
                if (entry := self._entries.get(index)) is not None
            ]
        if not candidates:
            return None
        # The longest-lasting block wins: a provider-wide cooldown ending later
        # than an operation-specific one still blocks the operation.
        return max(candidates, key=lambda entry: entry.until)

    async def entries(self, *, scope_identity: str) -> tuple[CooldownEntry, ...]:
        now = self._clock.now()
        async with self._lock:
            self._prune_locked(now)
            found = [
                entry
                for (identity, _), entry in self._entries.items()
                if identity == scope_identity
            ]
        return tuple(sorted(found, key=lambda entry: (entry.operation or "", entry.until)))

    async def clear(self, *, scope_identity: str, operation: str | None = None) -> None:
        async with self._lock:
            if operation is None:
                for index in [index for index in self._entries if index[0] == scope_identity]:
                    del self._entries[index]
                return
            self._entries.pop((scope_identity, operation), None)

    def _prune_locked(self, now: datetime) -> None:
        for index in [
            index for index, entry in self._entries.items() if not entry.is_active_at(now)
        ]:
            del self._entries[index]

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"<InMemoryCooldownStore entries={len(self._entries)}>"


def make_cooldown(
    *,
    scope: ExecutionScope,
    reason: CooldownReason,
    seconds: float,
    now: datetime,
    operation: str | None = None,
    detail: str | None = None,
) -> CooldownEntry:
    """Build a cooldown entry, capped at :data:`MAX_COOLDOWN_SECONDS`."""
    capped = min(max(0.0, seconds), MAX_COOLDOWN_SECONDS)
    return CooldownEntry(
        provider_id=scope.provider_id,
        scope_identity=scope.identity,
        reason=reason,
        until=now + timedelta(seconds=capped),
        operation=operation,
        detail=detail,
    )


def make_credential_cooldown(
    *,
    scope: ExecutionScope,
    reason: CooldownReason,
    seconds: float,
    now: datetime,
    detail: str | None = None,
) -> CooldownEntry | None:
    """A cooldown keyed to the credential rather than to one provider.

    ``None`` when the scope names no credential group, which is the signal to
    fall back to an ordinary provider-scoped cooldown: suppression still happens,
    it simply covers less.

    Provider-wide by construction — no ``operation`` argument. A credential a
    provider has refused is refused for everything that credential could do, so
    narrowing this to one action would leave the others hammering the same
    refusal.
    """
    identity = scope.credential_identity
    if identity is None:
        return None
    capped = min(max(0.0, seconds), MAX_COOLDOWN_SECONDS)
    return CooldownEntry(
        provider_id=scope.provider_id,
        scope_identity=identity,
        reason=reason,
        until=now + timedelta(seconds=capped),
        operation=None,
        detail=detail,
    )


def cooldown_from_rate_limit(
    snapshot: RateLimitSnapshot,
    *,
    scope: ExecutionScope,
    now: datetime,
    operation: str | None = None,
    default_seconds: float = 60.0,
) -> CooldownEntry | None:
    """A cooldown derived from an exhausted rate-limit window, if any.

    Scoped to the operation the snapshot describes. A provider whose search
    action is throttled keeps serving its other actions — which is the whole
    reason cooldowns are per operation.
    """
    if not snapshot.is_throttled:
        return None
    delay = snapshot.longest_reset_delay(now)
    exhausted = snapshot.exhausted_windows
    detail = (
        f"exhausted windows: {', '.join(window.window_name for window in exhausted)}"
        if exhausted
        else "rate limit reported with no remaining requests"
    )
    return make_cooldown(
        scope=scope,
        reason=CooldownReason.RATE_LIMIT,
        seconds=delay if delay is not None else default_seconds,
        now=now,
        operation=operation or snapshot.operation,
        detail=detail,
    )


def cooldown_from_quota(
    snapshot: ProviderQuotaSnapshot,
    *,
    scope: ExecutionScope,
    now: datetime,
    default_seconds: float = 900.0,
) -> CooldownEntry | None:
    """A cooldown derived from an exhausted quota bucket, if any.

    Provider-wide, unlike a rate-limit cooldown: a spent account allowance
    applies to everything that credential could do, not to one action.
    """
    if not snapshot.is_exhausted:
        return None
    reset_at = snapshot.next_reset_at(now)
    seconds = (reset_at - now).total_seconds() if reset_at is not None else default_seconds
    names = ", ".join(bucket.name for bucket in snapshot.exhausted_buckets)
    return make_cooldown(
        scope=scope,
        reason=CooldownReason.QUOTA_EXHAUSTED,
        seconds=seconds,
        now=now,
        operation=None,
        detail=f"exhausted quota: {names}",
    )
