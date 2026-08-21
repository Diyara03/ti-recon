"""Concurrency limiting and in-flight request coalescing (Task 6).

Two independent protections against overwhelming a provider — or a user's
quota — with our own traffic:

* :class:`ConcurrencyLimiter` bounds how many calls one credential has in
  flight at once, so a wide investigation does not open thirty sockets to one
  API;
* :class:`SingleFlight` collapses *identical* concurrent requests into one real
  call, so a fan-out that asks the same question five times pays for it once.

Both are scoped by credential. One analyst's burst must not consume another's
execution slots, and two analysts asking the same question must not share a
result fetched with one of their keys.

Single-process only. Two workers do not share a semaphore, so the effective
provider concurrency is the configured limit times the worker count. A
distributed limiter is a later task; this is deliberately not pretending to be
one.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TypeVar, cast

__all__ = ["DEFAULT_MAX_CONCURRENCY", "ConcurrencyLimiter", "SingleFlight"]

T = TypeVar("T")

#: Default in-flight calls per credential scope. Configuration, not provider
#: guidance: no provider documents this number, and each real integration should
#: set its own.
DEFAULT_MAX_CONCURRENCY = 4


@dataclass(slots=True)
class _Gate:
    semaphore: asyncio.Semaphore
    #: Tasks currently holding *or waiting for* a slot. The gate may only be
    #: discarded at zero; discarding it while a task still holds a slot would
    #: hand the next arrival a fresh semaphore and quietly exceed the limit.
    users: int = 0
    active: int = 0


@dataclass(slots=True)
class _Flight:
    future: asyncio.Future[object]
    followers: int = field(default=0)


class ConcurrencyLimiter:
    """Bounds concurrent provider calls per credential scope.

    Gates are created on demand and dropped once nobody holds or awaits them,
    so a long-running process that has served a million scopes does not retain
    a million semaphores.
    """

    def __init__(self, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        if max_concurrency < 1:
            msg = "max_concurrency must be at least 1"
            raise ValueError(msg)
        self._max_concurrency = max_concurrency
        self._gates: dict[str, _Gate] = {}

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    @asynccontextmanager
    async def acquire(self, scope_key: str) -> AsyncIterator[None]:
        """Hold one slot for ``scope_key`` for the duration of the block."""
        gate = self._register(scope_key)
        try:
            await gate.semaphore.acquire()
            try:
                gate.active += 1
                yield
            finally:
                gate.active -= 1
                gate.semaphore.release()
        finally:
            # Runs even if the task was cancelled while waiting for a slot,
            # so a cancelled caller never leaks a gate.
            self._release(scope_key, gate)

    def active_count(self, scope_key: str) -> int:
        """Calls currently executing for one scope."""
        gate = self._gates.get(scope_key)
        return gate.active if gate is not None else 0

    @property
    def tracked_scopes(self) -> int:
        """Scopes currently holding gate state. Returns to zero when idle."""
        return len(self._gates)

    def _register(self, scope_key: str) -> _Gate:
        # No await in this block, so asyncio cannot interleave another task
        # between the lookup and the insert; an explicit lock would add nothing.
        gate = self._gates.get(scope_key)
        if gate is None:
            gate = _Gate(semaphore=asyncio.Semaphore(self._max_concurrency))
            self._gates[scope_key] = gate
        gate.users += 1
        return gate

    def _release(self, scope_key: str, gate: _Gate) -> None:
        gate.users -= 1
        if gate.users <= 0 and self._gates.get(scope_key) is gate:
            del self._gates[scope_key]

    def __repr__(self) -> str:
        return f"<ConcurrencyLimiter max={self._max_concurrency} scopes={len(self._gates)}>"


class SingleFlight:
    """Collapses identical concurrent work into one execution.

    The first caller for a key runs the work; everyone who arrives while it is
    still running awaits the same result. That saves quota, latency and
    duplicated parsing when a fan-out asks the same question several times.

    Failure and cancellation propagate to every waiter and always clear the
    registry, so a failed leader cannot wedge later callers.
    """

    def __init__(self) -> None:
        self._flights: dict[str, _Flight] = {}

    async def run(self, key: str, factory: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        """Run ``factory`` for ``key``, or await an identical run in progress.

        Returns ``(value, coalesced)`` — ``coalesced`` is ``True`` for a caller
        that rode along on somebody else's call, which is worth recording so a
        saved provider request is visible rather than invisible.
        """
        # As in the limiter: no await between the lookup and the insert, so this
        # is atomic with respect to other tasks.
        flight = self._flights.get(key)
        if flight is not None:
            flight.followers += 1
            # The future is untyped storage shared by callers of one key; the
            # key's identity is what guarantees they all expect the same type.
            return cast("T", await flight.future), True

        future: asyncio.Future[object] = asyncio.get_running_loop().create_future()
        future.add_done_callback(_mark_exception_retrieved)
        flight = _Flight(future=future)
        self._flights[key] = flight

        try:
            value = await factory()
        except asyncio.CancelledError:
            self._finish(key, flight)
            if not future.done():
                # Cancel rather than set_exception: followers still see a
                # CancelledError, and a cancelled future logs no warning when
                # nobody was waiting.
                future.cancel()
            raise
        except BaseException as error:
            self._finish(key, flight)
            if not future.done():
                future.set_exception(error)
            raise
        self._finish(key, flight)
        if not future.done():
            future.set_result(value)
        return value, False

    @property
    def in_flight(self) -> int:
        """Keys currently executing. Returns to zero when idle."""
        return len(self._flights)

    def followers_of(self, key: str) -> int:
        """How many callers are riding along on ``key`` right now."""
        flight = self._flights.get(key)
        return flight.followers if flight is not None else 0

    def _finish(self, key: str, flight: _Flight) -> None:
        if self._flights.get(key) is flight:
            del self._flights[key]

    def __repr__(self) -> str:
        return f"<SingleFlight in_flight={len(self._flights)}>"


def _mark_exception_retrieved(future: asyncio.Future[object]) -> None:
    """Silence asyncio's 'exception was never retrieved' warning.

    A leader can fail with no followers waiting. The exception is still raised
    to the leader's own caller; retrieving it here only stops asyncio logging it
    a second time at garbage-collection.
    """
    if not future.cancelled():
        future.exception()
