"""Injectable time and randomness (Task 6).

Every execution control in this package is time-dependent: TTLs expire,
backoff waits, cooldowns lift. If those read the wall clock directly, the only
way to test them is to actually wait — which makes the suite slow, flaky, and
quietly untested at the edges.

So time, sleeping and jitter all arrive through these seams. Production wires
:class:`SystemClock`, :class:`AsyncioSleeper` and :class:`RandomJitter`; tests
wire :class:`ManualClock`, :class:`RecordingSleeper` and :class:`FixedJitter`
and run instantly.

Two notions of time are kept apart on purpose:

* :meth:`Clock.now` is a timezone-aware UTC ``datetime`` and is what reaches
  domain models — a reset time an analyst may read has to be a real wall-clock
  instant.
* :meth:`Clock.monotonic` is what TTL and cooldown arithmetic uses, because it
  cannot jump backwards when the host's clock is corrected mid-flight.
"""

from __future__ import annotations

import asyncio
import random
import time
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

__all__ = [
    "AsyncioSleeper",
    "Clock",
    "FixedJitter",
    "JitterSource",
    "ManualClock",
    "NoJitter",
    "RandomJitter",
    "RecordingSleeper",
    "Sleeper",
    "SystemClock",
]


@runtime_checkable
class Clock(Protocol):
    """A source of both wall-clock and monotonic time."""

    def now(self) -> datetime:
        """The current instant as a timezone-aware UTC datetime."""
        ...

    def monotonic(self) -> float:
        """A monotonically increasing number of seconds, of arbitrary origin."""
        ...


class SystemClock:
    """The real clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class ManualClock:
    """A clock that only moves when told to.

    **Development and testing only.** Both notions of time advance together, so
    a test that advances 30 seconds expires a 30-second TTL and a cooldown that
    ends in 30 seconds.
    """

    def __init__(self, start: datetime | None = None, *, monotonic_start: float = 1000.0) -> None:
        moment = start or datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
        if moment.tzinfo is None:
            msg = "ManualClock requires a timezone-aware start"
            raise ValueError(msg)
        self._now = moment.astimezone(UTC)
        self._monotonic = monotonic_start

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        """Move both clocks forward. Time never runs backwards."""
        if seconds < 0:
            msg = "time cannot move backwards"
            raise ValueError(msg)
        self._now = self._now + timedelta(seconds=seconds)
        self._monotonic += seconds


@runtime_checkable
class Sleeper(Protocol):
    """An awaitable delay."""

    async def sleep(self, seconds: float) -> None:
        """Wait for ``seconds``."""
        ...


class AsyncioSleeper:
    """The real sleeper."""

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds))


class RecordingSleeper:
    """Records requested delays instead of waiting for them.

    **Development and testing only.** Given a :class:`ManualClock`, it also
    advances it, so code that sleeps and then re-checks the time behaves as it
    would in production — without the suite taking that long to run.
    """

    def __init__(self, clock: ManualClock | None = None) -> None:
        self._clock = clock
        self.slept: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        if self._clock is not None:
            self._clock.advance(max(0.0, seconds))
        # Yield control so concurrent tasks still interleave realistically.
        await asyncio.sleep(0)

    @property
    def total_slept(self) -> float:
        return sum(self.slept)


@runtime_checkable
class JitterSource(Protocol):
    """A source of bounded random delay padding."""

    def jitter(self, upper_bound: float) -> float:
        """A value in ``[0, upper_bound]``."""
        ...


class RandomJitter:
    """Uniform jitter, so simultaneous retries do not stay synchronized."""

    def __init__(self, rng: random.Random | None = None) -> None:
        # Not cryptographic: this only de-synchronizes retry timing.
        self._rng = rng or random.Random()

    def jitter(self, upper_bound: float) -> float:
        if upper_bound <= 0:
            return 0.0
        return self._rng.uniform(0.0, upper_bound)


class NoJitter:
    """No jitter at all. Makes backoff exactly reproducible."""

    def jitter(self, upper_bound: float) -> float:
        return 0.0


class FixedJitter:
    """Always the same fraction of the bound.

    **Development and testing only.** Lets a test assert an exact delay while
    still exercising the jitter code path.
    """

    def __init__(self, fraction: float = 1.0) -> None:
        if not 0.0 <= fraction <= 1.0:
            msg = "fraction must be within [0, 1]"
            raise ValueError(msg)
        self._fraction = fraction

    def jitter(self, upper_bound: float) -> float:
        return max(0.0, upper_bound) * self._fraction
