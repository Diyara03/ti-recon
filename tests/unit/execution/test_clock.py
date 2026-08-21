"""Injectable time and randomness (Task 6, step 1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ti_recon.execution import (
    AsyncioSleeper,
    Clock,
    FixedJitter,
    JitterSource,
    ManualClock,
    NoJitter,
    RandomJitter,
    RecordingSleeper,
    Sleeper,
    SystemClock,
)


def test_system_clock_returns_timezone_aware_utc() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_system_clock_monotonic_does_not_go_backwards() -> None:
    clock = SystemClock()
    first = clock.monotonic()
    assert clock.monotonic() >= first


def test_manual_clock_is_frozen_until_advanced() -> None:
    clock = ManualClock()
    first = clock.now()
    assert clock.now() == first
    clock.advance(30)
    assert clock.now() == first + timedelta(seconds=30)


def test_manual_clock_advances_both_notions_of_time_together() -> None:
    clock = ManualClock()
    wall = clock.now()
    monotonic = clock.monotonic()
    clock.advance(12.5)
    assert clock.now() == wall + timedelta(seconds=12.5)
    assert clock.monotonic() == pytest.approx(monotonic + 12.5)


def test_manual_clock_refuses_to_go_backwards() -> None:
    with pytest.raises(ValueError, match="backwards"):
        ManualClock().advance(-1)


def test_manual_clock_requires_an_aware_start() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ManualClock(start=datetime(2026, 1, 1))  # noqa: DTZ001


def test_manual_clock_normalizes_a_non_utc_start() -> None:
    from datetime import timezone

    clock = ManualClock(start=datetime(2026, 1, 1, 15, 0, tzinfo=timezone(timedelta(hours=3))))
    assert clock.now() == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


async def test_recording_sleeper_records_instead_of_waiting() -> None:
    sleeper = RecordingSleeper()
    await sleeper.sleep(30)
    await sleeper.sleep(2.5)
    assert sleeper.slept == [30, 2.5]
    assert sleeper.total_slept == pytest.approx(32.5)


async def test_recording_sleeper_advances_its_clock() -> None:
    """Code that sleeps then re-reads the time must behave as in production."""
    clock = ManualClock()
    sleeper = RecordingSleeper(clock)
    start = clock.now()
    await sleeper.sleep(45)
    assert clock.now() == start + timedelta(seconds=45)


async def test_recording_sleeper_ignores_negative_delays() -> None:
    clock = ManualClock()
    sleeper = RecordingSleeper(clock)
    start = clock.monotonic()
    await sleeper.sleep(-5)
    assert clock.monotonic() == start


async def test_asyncio_sleeper_clamps_negative_delays() -> None:
    await AsyncioSleeper().sleep(-1)


def test_no_jitter_adds_nothing() -> None:
    assert NoJitter().jitter(10.0) == 0.0


def test_fixed_jitter_is_a_fraction_of_the_bound() -> None:
    assert FixedJitter(0.5).jitter(10.0) == pytest.approx(5.0)
    assert FixedJitter(1.0).jitter(10.0) == pytest.approx(10.0)
    assert FixedJitter(0.0).jitter(10.0) == 0.0


def test_fixed_jitter_rejects_a_fraction_outside_the_unit_interval() -> None:
    for fraction in (-0.1, 1.1):
        with pytest.raises(ValueError, match=r"\[0, 1\]"):
            FixedJitter(fraction)


def test_random_jitter_stays_within_its_bound() -> None:
    import random

    jitter = RandomJitter(random.Random(1234))
    for _ in range(200):
        value = jitter.jitter(4.0)
        assert 0.0 <= value <= 4.0


def test_random_jitter_is_seedable_for_reproducibility() -> None:
    import random

    first = [RandomJitter(random.Random(7)).jitter(5.0) for _ in range(3)]
    second = [RandomJitter(random.Random(7)).jitter(5.0) for _ in range(3)]
    assert first == second


@pytest.mark.parametrize("bound", [0.0, -1.0])
def test_jitter_of_a_non_positive_bound_is_zero(bound: float) -> None:
    import random

    assert RandomJitter(random.Random(1)).jitter(bound) == 0.0
    assert FixedJitter().jitter(bound) == 0.0


def test_implementations_satisfy_their_protocols() -> None:
    assert isinstance(SystemClock(), Clock)
    assert isinstance(ManualClock(), Clock)
    assert isinstance(AsyncioSleeper(), Sleeper)
    assert isinstance(RecordingSleeper(), Sleeper)
    assert isinstance(NoJitter(), JitterSource)
    assert isinstance(FixedJitter(), JitterSource)
    assert isinstance(RandomJitter(), JitterSource)
