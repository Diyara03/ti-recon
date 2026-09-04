"""GreyNoise access levels, and remembering which one a credential has (Task 9).

GreyNoise exposes the same address through two very different doors. The full v3
IP context (``/v3/ip/{ip}``) carries the classification, the tags, the CVE
associations, the sensor metadata and the Business Services Intelligence record;
the Community endpoint (``/v3/community/{ip}``) carries a handful of fields and
is available far more widely. Which door a given API key may use depends on that
account's subscription, and TI Recon cannot know it in advance.

Why this is a module rather than three lines in the adapter
----------------------------------------------------------

Getting this wrong is expensive in two opposite directions.

**Probing every lookup wastes the analyst's allowance.** If a Community-only key
tried the paid endpoint before every single lookup, half of this integration's
requests would be 403s. So the resolved level is remembered per credential for a
bounded time.

**Guessing from a status code corrupts the answer.** A 401 means the key is
wrong; it must never be read as "this must be a Community account" and quietly
downgraded, because then a revoked key looks like a working free one and the
analyst is never told to fix it. Only a 403 — the credential is accepted but not
permitted here — may lead to a Community attempt, and only a Community call that
actually answers proves Community access.

So the rule is: 401 propagates untouched, 403 earns exactly one Community probe,
and the outcome of that probe is what gets remembered.

Isolation
---------

Access level is a property of *one credential*, so the store is keyed by the
Task 6 :class:`~ti_recon.execution.models.ExecutionScope` identity — user plus
provider connection, built from identifiers only. One analyst's entitlement is
never read for another, and rotating a key does not inherit the old key's level.
Like every other execution store in this repository, it is in-memory and
single-process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol

from ti_recon.execution.clock import Clock, SystemClock

__all__ = [
    "DEFAULT_ACCESS_TTL_SECONDS",
    "AccessLevelStore",
    "GreyNoiseAccessLevel",
    "GreyNoiseAccessMode",
    "InMemoryAccessLevelStore",
]

#: How long a resolved access level stays trusted.
#:
#: Long enough that a lookup almost never re-probes, short enough that an
#: upgraded subscription starts producing full context within the hour instead
#: of at the next restart.
DEFAULT_ACCESS_TTL_SECONDS: Final[int] = 3600


class GreyNoiseAccessMode(StrEnum):
    """What an operator configured, as opposed to what a credential can do.

    ``AUTO`` is the normal setting: try the full endpoint, fall back to
    Community only when GreyNoise says this key may not use the full one.

    ``FULL`` and ``COMMUNITY`` pin the choice. Pinning ``FULL`` on a
    Community-only key produces honest permission errors rather than a silent
    downgrade, which is what an operator who pinned it asked for; pinning
    ``COMMUNITY`` never touches the paid endpoint at all.
    """

    AUTO = "auto"
    FULL = "full"
    COMMUNITY = "community"


class GreyNoiseAccessLevel(StrEnum):
    """What a specific credential was actually observed to be able to do.

    Distinct from :class:`GreyNoiseAccessMode` on purpose. A mode is
    configuration and is the same for everyone; a level is a per-credential
    observation, and only a real response may set it.
    """

    FULL = "full"
    COMMUNITY = "community"


class AccessLevelStore(Protocol):
    """Where an observed access level is remembered, keyed by execution scope.

    ``scope_identity`` is a
    :attr:`~ti_recon.execution.models.ExecutionScope.identity` string — built
    from ids only, so nothing credential-bearing can reach a key here.
    """

    async def get(self, scope_identity: str) -> GreyNoiseAccessLevel | None: ...

    async def put(self, scope_identity: str, level: GreyNoiseAccessLevel) -> None: ...

    async def clear(self, scope_identity: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _Entry:
    level: GreyNoiseAccessLevel
    expires_at: datetime


class InMemoryAccessLevelStore:
    """A single-process :class:`AccessLevelStore` with a bounded TTL.

    Expiry is deliberate rather than permanent memory: a subscription can be
    upgraded or downgraded, and a level cached forever would keep an upgraded
    account on the Community endpoint indefinitely.
    """

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        ttl_seconds: int = DEFAULT_ACCESS_TTL_SECONDS,
        max_entries: int = 10_000,
    ) -> None:
        if ttl_seconds < 0:
            msg = "ttl_seconds must not be negative"
            raise ValueError(msg)
        if max_entries < 1:
            msg = "max_entries must be positive"
            raise ValueError(msg)
        self._clock = SystemClock() if clock is None else clock
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._entries: dict[str, _Entry] = {}

    async def get(self, scope_identity: str) -> GreyNoiseAccessLevel | None:
        entry = self._entries.get(scope_identity)
        if entry is None:
            return None
        if entry.expires_at <= self._clock.now():
            del self._entries[scope_identity]
            return None
        return entry.level

    async def put(self, scope_identity: str, level: GreyNoiseAccessLevel) -> None:
        if self._ttl == 0:
            # A zero TTL is how an operator switches remembering off; storing
            # an already-expired entry would just churn the dictionary.
            return
        if scope_identity not in self._entries and len(self._entries) >= self._max_entries:
            # Oldest expiry first: a bounded store must shed something, and the
            # entry closest to being useless is the cheapest to lose.
            oldest = min(self._entries, key=lambda key: self._entries[key].expires_at)
            del self._entries[oldest]
        self._entries[scope_identity] = _Entry(
            level=level,
            expires_at=self._clock.now() + timedelta(seconds=self._ttl),
        )

    async def clear(self, scope_identity: str) -> None:
        self._entries.pop(scope_identity, None)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"<InMemoryAccessLevelStore entries={len(self._entries)} ttl={self._ttl}s>"
