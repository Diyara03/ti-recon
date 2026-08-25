"""GreyNoise access levels and the store that remembers them (Task 9).

Access level is a property of one credential, so the store's isolation is the
thing worth testing hardest: one analyst's entitlement must never decide which
endpoint another analyst's lookup uses.
"""

from __future__ import annotations

import pytest

from ti_recon.execution.clock import ManualClock
from ti_recon.execution.models import ExecutionScope
from ti_recon.providers.greynoise import (
    DEFAULT_ACCESS_TTL_SECONDS,
    GreyNoiseAccessLevel,
    GreyNoiseAccessMode,
    InMemoryAccessLevelStore,
)


def scope(user_id: str, connection_id: str = "conn-1") -> str:
    return ExecutionScope.for_user(
        provider_id="greynoise", user_id=user_id, provider_connection_id=connection_id
    ).identity


def test_the_configured_mode_and_the_observed_level_are_separate_vocabularies() -> None:
    """A mode is what an operator chose; a level is what a response proved."""
    assert {mode.value for mode in GreyNoiseAccessMode} == {"auto", "full", "community"}
    assert {level.value for level in GreyNoiseAccessLevel} == {"full", "community"}
    assert "auto" not in {level.value for level in GreyNoiseAccessLevel}


async def test_a_remembered_level_is_returned() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.COMMUNITY)
    assert await store.get(scope("analyst-a")) is GreyNoiseAccessLevel.COMMUNITY


async def test_nothing_is_remembered_for_an_unseen_credential() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    assert await store.get(scope("analyst-a")) is None


async def test_one_analysts_level_is_never_read_for_another() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.COMMUNITY)
    assert await store.get(scope("analyst-b")) is None


async def test_a_rotated_connection_does_not_inherit_the_old_level() -> None:
    """A new key may have a different subscription; it starts unknown."""
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.put(scope("analyst-a", "conn-old"), GreyNoiseAccessLevel.COMMUNITY)
    assert await store.get(scope("analyst-a", "conn-new")) is None


async def test_a_level_expires_so_an_upgraded_plan_is_noticed() -> None:
    clock = ManualClock()
    store = InMemoryAccessLevelStore(clock=clock, ttl_seconds=60)
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.COMMUNITY)

    clock.advance(59)
    assert await store.get(scope("analyst-a")) is GreyNoiseAccessLevel.COMMUNITY
    clock.advance(2)
    assert await store.get(scope("analyst-a")) is None


async def test_a_zero_ttl_switches_remembering_off() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock(), ttl_seconds=0)
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.FULL)
    assert await store.get(scope("analyst-a")) is None
    assert len(store) == 0


async def test_a_level_can_be_cleared() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.FULL)
    await store.clear(scope("analyst-a"))
    assert await store.get(scope("analyst-a")) is None


async def test_clearing_an_unknown_scope_is_not_an_error() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.clear(scope("nobody"))


async def test_a_downgrade_overwrites_what_was_remembered() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.FULL)
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.COMMUNITY)
    assert await store.get(scope("analyst-a")) is GreyNoiseAccessLevel.COMMUNITY
    assert len(store) == 1


async def test_the_store_is_bounded() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock(), max_entries=2)
    for index in range(5):
        await store.put(scope(f"analyst-{index}"), GreyNoiseAccessLevel.FULL)
    assert len(store) == 2


async def test_the_newest_entry_survives_eviction() -> None:
    clock = ManualClock()
    store = InMemoryAccessLevelStore(clock=clock, max_entries=1)
    await store.put(scope("analyst-a"), GreyNoiseAccessLevel.FULL)
    clock.advance(1)
    await store.put(scope("analyst-b"), GreyNoiseAccessLevel.COMMUNITY)
    assert await store.get(scope("analyst-b")) is GreyNoiseAccessLevel.COMMUNITY
    assert await store.get(scope("analyst-a")) is None


@pytest.mark.parametrize(("ttl", "max_entries"), [(-1, 10), (60, 0), (60, -3)])
def test_an_unusable_configuration_is_refused(ttl: int, max_entries: int) -> None:
    with pytest.raises(ValueError, match="must"):
        InMemoryAccessLevelStore(ttl_seconds=ttl, max_entries=max_entries)


def test_the_default_ttl_is_bounded_and_short_enough_to_notice_a_change() -> None:
    assert 0 < DEFAULT_ACCESS_TTL_SECONDS <= 24 * 3600


def test_the_store_repr_reveals_nothing_but_counts() -> None:
    store = InMemoryAccessLevelStore(clock=ManualClock())
    assert "entries=0" in repr(store)
