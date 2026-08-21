"""Bounded concurrency and in-flight coalescing (Task 6, step 4).

Every test here is wrapped in a timeout, so a deadlock or a leaked gate fails
the suite in a second rather than hanging CI.
"""

from __future__ import annotations

import asyncio

import pytest

from ti_recon.execution import (
    DEFAULT_MAX_CONCURRENCY,
    ConcurrencyLimiter,
    SingleFlight,
)

#: Every test that could hang wraps its awaits in ``asyncio.timeout(TIMEOUT)``.
#: A deadlock or a leaked gate then fails in a second instead of hanging CI, and
#: no timeout plugin is needed to get that.
TIMEOUT = 2.0


class ConcurrencyProbe:
    """Records how many calls were in flight at once."""

    def __init__(self) -> None:
        self.calls = 0
        self.active = 0
        self.peak = 0

    async def work(self, *, hold: float = 0.0) -> str:
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            # Yield enough times that any task able to run concurrently will.
            for _ in range(5):
                await asyncio.sleep(hold)
            return "done"
        finally:
            self.active -= 1


# --------------------------------------------------------------------------- #
# Bounded concurrency
# --------------------------------------------------------------------------- #


async def test_concurrency_limit_is_respected() -> None:
    limiter = ConcurrencyLimiter(max_concurrency=3)
    probe = ConcurrencyProbe()

    async def call() -> str:
        async with limiter.acquire("scope-a"):
            return await probe.work()

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(*(call() for _ in range(20)))

    assert probe.calls == 20
    assert probe.peak <= 3


async def test_a_limit_of_one_serializes_completely() -> None:
    limiter = ConcurrencyLimiter(max_concurrency=1)
    probe = ConcurrencyProbe()

    async def call() -> str:
        async with limiter.acquire("scope-a"):
            return await probe.work()

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(*(call() for _ in range(8)))

    assert probe.peak == 1


async def test_concurrency_is_configurable() -> None:
    assert ConcurrencyLimiter().max_concurrency == DEFAULT_MAX_CONCURRENCY
    assert ConcurrencyLimiter(max_concurrency=12).max_concurrency == 12


def test_a_zero_or_negative_limit_is_rejected() -> None:
    for value in (0, -1):
        with pytest.raises(ValueError, match="at least 1"):
            ConcurrencyLimiter(max_concurrency=value)


async def test_different_scopes_have_independent_slots() -> None:
    """One analyst's burst must not consume another's execution slots."""
    limiter = ConcurrencyLimiter(max_concurrency=1)
    order: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocker() -> None:
        async with limiter.acquire("user-a"):
            order.append("a-start")
            started.set()
            await release.wait()
            order.append("a-end")

    async def other_user() -> None:
        await started.wait()
        async with limiter.acquire("user-b"):
            order.append("b-ran")

    async with asyncio.timeout(TIMEOUT):
        task_a = asyncio.create_task(blocker())
        task_b = asyncio.create_task(other_user())
        await asyncio.sleep(0)
        await started.wait()
        await task_b
        release.set()
        await task_a

    # User B ran while user A still held its only slot.
    assert order == ["a-start", "b-ran", "a-end"]


async def test_active_count_reflects_running_work() -> None:
    limiter = ConcurrencyLimiter(max_concurrency=2)
    inside = asyncio.Event()
    release = asyncio.Event()

    async def call() -> None:
        async with limiter.acquire("scope-a"):
            inside.set()
            await release.wait()

    async with asyncio.timeout(TIMEOUT):
        task = asyncio.create_task(call())
        await inside.wait()
        assert limiter.active_count("scope-a") == 1
        release.set()
        await task

    assert limiter.active_count("scope-a") == 0


async def test_gate_state_is_released_when_idle() -> None:
    """A million served scopes must not retain a million semaphores."""
    limiter = ConcurrencyLimiter(max_concurrency=2)

    async def call(scope: str) -> None:
        async with limiter.acquire(scope):
            await asyncio.sleep(0)

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(*(call(f"scope-{index}") for index in range(50)))

    assert limiter.tracked_scopes == 0


async def test_gate_state_is_released_after_a_failure() -> None:
    limiter = ConcurrencyLimiter(max_concurrency=2)

    async with asyncio.timeout(TIMEOUT):
        with pytest.raises(RuntimeError, match="boom"):
            async with limiter.acquire("scope-a"):
                msg = "boom"
                raise RuntimeError(msg)

    assert limiter.tracked_scopes == 0
    assert limiter.active_count("scope-a") == 0


async def test_gate_state_is_released_after_cancellation_while_waiting() -> None:
    """A caller cancelled in the queue must not leak its gate."""
    limiter = ConcurrencyLimiter(max_concurrency=1)
    holding = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> None:
        async with limiter.acquire("scope-a"):
            holding.set()
            await release.wait()

    async def waiter() -> None:
        async with limiter.acquire("scope-a"):
            pass  # pragma: no cover - never reached; cancelled while queued

    async with asyncio.timeout(TIMEOUT):
        holder_task = asyncio.create_task(holder())
        await holding.wait()
        waiter_task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        waiter_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter_task
        release.set()
        await holder_task

    assert limiter.tracked_scopes == 0


async def test_the_limiter_does_not_deadlock_under_reentrant_scopes() -> None:
    """Nested acquisitions of *different* scopes must not block each other."""
    limiter = ConcurrencyLimiter(max_concurrency=1)
    async with asyncio.timeout(TIMEOUT), limiter.acquire("outer"), limiter.acquire("inner"):
        assert limiter.active_count("outer") == 1
        assert limiter.active_count("inner") == 1


def test_limiter_repr_is_safe() -> None:
    assert repr(ConcurrencyLimiter(max_concurrency=5)) == ("<ConcurrencyLimiter max=5 scopes=0>")


# --------------------------------------------------------------------------- #
# Single-flight coalescing
# --------------------------------------------------------------------------- #


async def test_identical_concurrent_requests_collapse_into_one_call() -> None:
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async def call() -> tuple[str, bool]:
        return await flight.run("key-a", lambda: probe.work())

    async with asyncio.timeout(TIMEOUT):
        results = await asyncio.gather(*(call() for _ in range(10)))

    assert probe.calls == 1
    assert all(value == "done" for value, _ in results)
    coalesced = [was_coalesced for _, was_coalesced in results]
    assert coalesced.count(False) == 1
    assert coalesced.count(True) == 9


async def test_two_concurrent_callers_share_one_call() -> None:
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async with asyncio.timeout(TIMEOUT):
        first = asyncio.create_task(flight.run("key-a", lambda: probe.work()))
        await asyncio.sleep(0)
        second = asyncio.create_task(flight.run("key-a", lambda: probe.work()))
        results = await asyncio.gather(first, second)

    assert probe.calls == 1
    assert [was_coalesced for _, was_coalesced in results] == [False, True]


async def test_different_keys_do_not_coalesce() -> None:
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(
            flight.run("observable-a", lambda: probe.work()),
            flight.run("observable-b", lambda: probe.work()),
            flight.run("observable-c", lambda: probe.work()),
        )

    assert probe.calls == 3


async def test_sequential_calls_do_not_coalesce() -> None:
    """Coalescing is only for work in flight, never a substitute for the cache."""
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async with asyncio.timeout(TIMEOUT):
        _, first_coalesced = await flight.run("key-a", lambda: probe.work())
        _, second_coalesced = await flight.run("key-a", lambda: probe.work())

    assert probe.calls == 2
    assert first_coalesced is False
    assert second_coalesced is False


async def test_followers_are_visible_while_the_leader_runs() -> None:
    flight = SingleFlight()
    inside = asyncio.Event()
    release = asyncio.Event()

    async def leader_work() -> str:
        inside.set()
        await release.wait()
        return "done"

    async with asyncio.timeout(TIMEOUT):
        leader = asyncio.create_task(flight.run("key-a", leader_work))
        await inside.wait()
        followers = [asyncio.create_task(flight.run("key-a", leader_work)) for _ in range(3)]
        await asyncio.sleep(0)
        assert flight.in_flight == 1
        assert flight.followers_of("key-a") == 3
        release.set()
        await asyncio.gather(leader, *followers)

    assert flight.in_flight == 0


async def test_a_failing_leader_fails_every_follower_with_the_same_error() -> None:
    flight = SingleFlight()
    attempts = 0
    inside = asyncio.Event()
    release = asyncio.Event()

    async def failing() -> str:
        nonlocal attempts
        attempts += 1
        inside.set()
        await release.wait()
        msg = "provider exploded"
        raise RuntimeError(msg)

    async with asyncio.timeout(TIMEOUT):
        leader = asyncio.create_task(flight.run("key-a", failing))
        await inside.wait()
        followers = [asyncio.create_task(flight.run("key-a", failing)) for _ in range(3)]
        await asyncio.sleep(0)
        release.set()
        results = await asyncio.gather(leader, *followers, return_exceptions=True)

    assert attempts == 1
    assert len(results) == 4
    for outcome in results:
        assert isinstance(outcome, RuntimeError)
        assert str(outcome) == "provider exploded"


async def test_a_failure_clears_the_registry() -> None:
    flight = SingleFlight()

    async def failing() -> str:
        msg = "boom"
        raise RuntimeError(msg)

    async with asyncio.timeout(TIMEOUT):
        with pytest.raises(RuntimeError, match="boom"):
            await flight.run("key-a", failing)

    assert flight.in_flight == 0


async def test_a_later_caller_retries_after_a_failure() -> None:
    """A failed leader must not wedge the key for everyone afterwards."""
    flight = SingleFlight()
    calls = 0

    async def sometimes_failing() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "first attempt fails"
            raise RuntimeError(msg)
        return "recovered"

    async with asyncio.timeout(TIMEOUT):
        with pytest.raises(RuntimeError, match="first attempt fails"):
            await flight.run("key-a", sometimes_failing)

        value, coalesced = await flight.run("key-a", sometimes_failing)
    assert value == "recovered"
    assert coalesced is False


async def test_cancelling_the_leader_clears_the_registry() -> None:
    flight = SingleFlight()
    inside = asyncio.Event()

    async def never_finishes() -> str:
        inside.set()
        await asyncio.Event().wait()
        return "unreachable"  # pragma: no cover - never reached

    async with asyncio.timeout(TIMEOUT):
        leader = asyncio.create_task(flight.run("key-a", never_finishes))
        await inside.wait()
        leader.cancel()
        with pytest.raises(asyncio.CancelledError):
            await leader

    assert flight.in_flight == 0


async def test_cancelling_the_leader_propagates_to_followers() -> None:
    flight = SingleFlight()
    inside = asyncio.Event()

    async def never_finishes() -> str:
        inside.set()
        await asyncio.Event().wait()
        return "unreachable"  # pragma: no cover - never reached

    async with asyncio.timeout(TIMEOUT):
        leader = asyncio.create_task(flight.run("key-a", never_finishes))
        await inside.wait()
        follower = asyncio.create_task(flight.run("key-a", never_finishes))
        await asyncio.sleep(0)
        leader.cancel()
        outcomes = await asyncio.gather(leader, follower, return_exceptions=True)

    assert all(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes)
    assert flight.in_flight == 0


async def test_cancelling_a_follower_leaves_the_leader_alone() -> None:
    flight = SingleFlight()
    inside = asyncio.Event()
    release = asyncio.Event()

    async def work() -> str:
        inside.set()
        await release.wait()
        return "done"

    async with asyncio.timeout(TIMEOUT):
        leader = asyncio.create_task(flight.run("key-a", work))
        await inside.wait()
        follower = asyncio.create_task(flight.run("key-a", work))
        await asyncio.sleep(0)
        follower.cancel()
        with pytest.raises(asyncio.CancelledError):
            await follower
        release.set()
        value, coalesced = await leader

    assert value == "done"
    assert coalesced is False
    assert flight.in_flight == 0


async def test_the_registry_returns_to_empty_after_many_keys() -> None:
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async with asyncio.timeout(TIMEOUT):
        await asyncio.gather(
            *(flight.run(f"key-{index}", lambda: probe.work()) for index in range(50))
        )

    assert flight.in_flight == 0
    assert flight.followers_of("key-0") == 0


def test_single_flight_repr_is_safe() -> None:
    assert repr(SingleFlight()) == "<SingleFlight in_flight=0>"


# --------------------------------------------------------------------------- #
# The two together
# --------------------------------------------------------------------------- #


async def test_coalescing_outside_the_limiter_keeps_slots_for_real_calls() -> None:
    """Followers must not hold execution slots while waiting on a leader."""
    limiter = ConcurrencyLimiter(max_concurrency=1)
    flight = SingleFlight()
    probe = ConcurrencyProbe()

    async def guarded() -> str:
        async with limiter.acquire("scope-a"):
            return await probe.work()

    async def call() -> tuple[str, bool]:
        return await flight.run("key-a", guarded)

    async with asyncio.timeout(TIMEOUT):
        results = await asyncio.gather(*(call() for _ in range(10)))

    assert probe.calls == 1
    assert limiter.tracked_scopes == 0
    assert all(value == "done" for value, _ in results)
