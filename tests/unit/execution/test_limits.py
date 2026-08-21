"""Rate-limit, quota and cooldown tracking (Task 6, step 3).

All expiry is driven by a manual clock; nothing here waits.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from fixtures.execution import make_scope
from ti_recon.execution import (
    MAX_COOLDOWN_SECONDS,
    CooldownEntry,
    CooldownReason,
    CooldownStore,
    InMemoryCooldownStore,
    InMemoryQuotaStore,
    ManualClock,
    QuotaStore,
    cooldown_from_quota,
    cooldown_from_rate_limit,
    make_cooldown,
)
from ti_recon.providers import (
    ProviderQuotaSnapshot,
    QuotaBucket,
    QuotaPeriod,
    RateLimitSnapshot,
    RateLimitWindow,
)

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Multi-window rate limits
# --------------------------------------------------------------------------- #


def test_a_snapshot_can_carry_several_windows() -> None:
    """Modelling one global 'remaining' would lose which window is exhausted."""
    snapshot = RateLimitSnapshot(
        operation="search",
        windows=(
            RateLimitWindow(
                window_name="minute", limit=60, remaining=0, reset_at=NOW + timedelta(seconds=20)
            ),
            RateLimitWindow(window_name="hour", limit=1000, remaining=880),
            RateLimitWindow(window_name="day", limit=10_000, remaining=4200),
        ),
    )
    assert snapshot.operation == "search"
    assert len(snapshot.windows) == 3
    minute = snapshot.window("minute")
    assert minute is not None
    assert minute.is_exhausted is True
    assert snapshot.window("hour") is not None
    assert snapshot.window("week") is None


def test_window_names_are_provider_defined_not_a_fixed_vocabulary() -> None:
    snapshot = RateLimitSnapshot(
        windows=(
            RateLimitWindow(window_name="per_billing_cycle", limit=5, remaining=5),
            RateLimitWindow(window_name="burst_10s", limit=3, remaining=3),
        )
    )
    assert {window.window_name for window in snapshot.windows} == {
        "per_billing_cycle",
        "burst_10s",
    }


def test_empty_snapshot_stays_empty_and_honest() -> None:
    assert RateLimitSnapshot().is_empty is True
    assert RateLimitSnapshot().is_throttled is False
    assert RateLimitSnapshot().longest_reset_delay(NOW) is None


def test_windows_alone_make_a_snapshot_non_empty() -> None:
    snapshot = RateLimitSnapshot(windows=(RateLimitWindow(window_name="minute", remaining=5),))
    assert snapshot.is_empty is False


def test_unknown_remaining_is_not_exhaustion() -> None:
    """Declining to call a provider that told us nothing is worse than trying."""
    assert RateLimitWindow(window_name="minute").is_exhausted is False
    assert RateLimitWindow(window_name="minute", limit=100).is_exhausted is False


def test_window_reset_prefers_a_relative_offset() -> None:
    window = RateLimitWindow(
        window_name="minute",
        remaining=0,
        reset_after_seconds=15.0,
        reset_at=NOW + timedelta(hours=3),
    )
    assert window.delay_until_reset(NOW) == pytest.approx(15.0)


def test_window_reset_falls_back_to_the_absolute_instant() -> None:
    window = RateLimitWindow(
        window_name="minute", remaining=0, reset_at=NOW + timedelta(seconds=45)
    )
    assert window.delay_until_reset(NOW) == pytest.approx(45.0)


def test_window_reset_is_none_when_unstated() -> None:
    assert RateLimitWindow(window_name="minute", remaining=0).delay_until_reset(NOW) is None


def test_past_reset_times_are_clamped_to_zero() -> None:
    window = RateLimitWindow(window_name="minute", remaining=0, reset_at=NOW - timedelta(minutes=5))
    assert window.delay_until_reset(NOW) == 0.0


def test_longest_reset_delay_waits_for_every_exhausted_window() -> None:
    """A request needs all exhausted windows refilled, so the longest wins."""
    snapshot = RateLimitSnapshot(
        windows=(
            RateLimitWindow(window_name="minute", remaining=0, reset_after_seconds=20.0),
            RateLimitWindow(window_name="hour", remaining=0, reset_after_seconds=1800.0),
            RateLimitWindow(window_name="day", remaining=500, reset_after_seconds=80_000.0),
        )
    )
    assert snapshot.longest_reset_delay(NOW) == pytest.approx(1800.0)


def test_headline_counters_also_signal_throttling() -> None:
    snapshot = RateLimitSnapshot(remaining=0, reset_at=NOW + timedelta(seconds=30))
    assert snapshot.is_throttled is True
    assert snapshot.longest_reset_delay(NOW) == pytest.approx(30.0)


def test_duplicate_window_names_are_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        RateLimitSnapshot(
            windows=(
                RateLimitWindow(window_name="minute", remaining=1),
                RateLimitWindow(window_name="minute", remaining=2),
            )
        )


# --------------------------------------------------------------------------- #
# Quota snapshots
# --------------------------------------------------------------------------- #


def make_quota(
    *,
    user_id: str = "user-a",
    connection_id: str | None = "conn-a",
    buckets: tuple[QuotaBucket, ...] = (),
) -> ProviderQuotaSnapshot:
    return ProviderQuotaSnapshot(
        provider_id="fake_provider",
        user_id=user_id,
        provider_connection_id=connection_id,
        retrieved_at=NOW,
        buckets=buckets,
    )


def test_quota_supports_several_periods_at_once() -> None:
    snapshot = make_quota(
        buckets=(
            QuotaBucket(
                name="api_requests_hourly", period=QuotaPeriod.HOUR, allowed=1000, used=250
            ),
            QuotaBucket(
                name="api_requests_daily", period=QuotaPeriod.DAY, allowed=20_000, used=9_000
            ),
            QuotaBucket(
                name="api_requests_monthly", period=QuotaPeriod.MONTH, allowed=500_000, used=12_000
            ),
        )
    )
    assert len(snapshot.buckets) == 3
    hourly = snapshot.bucket("api_requests_hourly")
    assert hourly is not None
    assert hourly.remaining == 750
    assert snapshot.is_exhausted is False


def test_remaining_is_derived_from_allowance_and_usage() -> None:
    bucket = QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=100, used=100)
    assert bucket.remaining == 0
    assert bucket.is_exhausted is True


def test_remaining_is_not_derived_below_zero() -> None:
    bucket = QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=100, used=140)
    assert bucket.remaining == 0


def test_explicit_remaining_is_not_overwritten() -> None:
    bucket = QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=100, used=10, remaining=42)
    assert bucket.remaining == 42


def test_unknown_quota_remaining_is_not_exhaustion() -> None:
    assert QuotaBucket(name="daily", period=QuotaPeriod.DAY).is_exhausted is False


def test_any_exhausted_bucket_blocks_the_credential() -> None:
    """A spent daily allowance is not rescued by the monthly one having room."""
    snapshot = make_quota(
        buckets=(
            QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=100, used=100),
            QuotaBucket(name="monthly", period=QuotaPeriod.MONTH, allowed=10_000, used=500),
        )
    )
    assert snapshot.is_exhausted is True
    assert [bucket.name for bucket in snapshot.exhausted_buckets] == ["daily"]


def test_next_reset_is_the_soonest_exhausted_bucket() -> None:
    snapshot = make_quota(
        buckets=(
            QuotaBucket(
                name="hourly",
                period=QuotaPeriod.HOUR,
                remaining=0,
                reset_at=NOW + timedelta(minutes=20),
            ),
            QuotaBucket(
                name="daily", period=QuotaPeriod.DAY, remaining=0, reset_at=NOW + timedelta(hours=9)
            ),
        )
    )
    assert snapshot.next_reset_at(NOW) == NOW + timedelta(minutes=20)


def test_next_reset_ignores_resets_already_past() -> None:
    snapshot = make_quota(
        buckets=(
            QuotaBucket(
                name="hourly",
                period=QuotaPeriod.HOUR,
                remaining=0,
                reset_at=NOW - timedelta(minutes=5),
            ),
        )
    )
    assert snapshot.next_reset_at(NOW) is None


def test_bucket_delay_until_reset() -> None:
    bucket = QuotaBucket(
        name="daily", period=QuotaPeriod.DAY, remaining=0, reset_at=NOW + timedelta(hours=2)
    )
    assert bucket.delay_until_reset(NOW) == pytest.approx(7200)
    assert QuotaBucket(name="daily", period=QuotaPeriod.DAY).delay_until_reset(NOW) is None


def test_duplicate_quota_bucket_names_are_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        make_quota(
            buckets=(
                QuotaBucket(name="daily", period=QuotaPeriod.DAY, remaining=1),
                QuotaBucket(name="daily", period=QuotaPeriod.DAY, remaining=2),
            )
        )


def test_quota_snapshot_serializes_round_trip() -> None:
    snapshot = make_quota(
        buckets=(
            QuotaBucket(name="hourly", period=QuotaPeriod.HOUR, allowed=1000, used=1),
            QuotaBucket(name="custom_cycle", period=QuotaPeriod.CUSTOM, allowed=5, used=5),
        )
    )
    payload = snapshot.model_dump(mode="json")
    restored = ProviderQuotaSnapshot.model_validate(payload)
    assert restored == snapshot
    assert json.loads(snapshot.model_dump_json())["buckets"][0]["period"] == "hour"


def test_quota_snapshot_has_no_credential_field() -> None:
    """Quota is scoped by identifiers, never by the key being spent."""
    assert set(ProviderQuotaSnapshot.model_fields) == {
        "provider_id",
        "user_id",
        "provider_connection_id",
        "retrieved_at",
        "buckets",
    }


def test_empty_quota_snapshot_is_honest() -> None:
    snapshot = make_quota()
    assert snapshot.is_empty is True
    assert snapshot.is_exhausted is False


# --------------------------------------------------------------------------- #
# Quota store
# --------------------------------------------------------------------------- #


async def test_quota_store_round_trip() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    scope = make_scope()
    snapshot = make_quota()
    await store.put(scope.identity, snapshot)
    assert await store.get(scope.identity) == snapshot


async def test_quota_store_returns_none_for_an_unknown_scope() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    assert await store.get("nobody") is None


async def test_quota_state_is_per_user_isolated() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    scope_a = make_scope(user_id="user-a", connection_id="conn-a")
    scope_b = make_scope(user_id="user-b", connection_id="conn-b")

    exhausted = make_quota(
        user_id="user-a",
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=10, used=10),),
    )
    await store.put(scope_a.identity, exhausted)

    stored_a = await store.get(scope_a.identity)
    assert stored_a is not None
    assert stored_a.is_exhausted is True
    assert await store.get(scope_b.identity) is None


async def test_quota_state_is_per_connection_isolated() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    first = make_scope(user_id="user-a", connection_id="conn-1")
    second = make_scope(user_id="user-a", connection_id="conn-2")
    await store.put(first.identity, make_quota())
    assert await store.get(second.identity) is None


async def test_stale_quota_snapshots_expire() -> None:
    """Acting on hour-old exhaustion would keep a provider off after it refilled."""
    clock = ManualClock()
    store = InMemoryQuotaStore(clock=clock, ttl_seconds=300)
    scope = make_scope()
    await store.put(scope.identity, make_quota())

    clock.advance(299)
    assert await store.get(scope.identity) is not None
    clock.advance(1)
    assert await store.get(scope.identity) is None


async def test_quota_store_clear_and_bounds() -> None:
    store = InMemoryQuotaStore(clock=ManualClock(), max_entries=2)
    for index in range(3):
        await store.put(f"scope-{index}", make_quota())
    assert len(store) == 2
    await store.clear("scope-2")
    assert await store.get("scope-2") is None


def test_quota_store_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="positive"):
        InMemoryQuotaStore(ttl_seconds=0)
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryQuotaStore(max_entries=0)


def test_quota_store_is_labelled_not_production_ready() -> None:
    assert InMemoryQuotaStore.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemoryQuotaStore.__doc__ or "")
    assert isinstance(InMemoryQuotaStore(), QuotaStore)


async def test_quota_store_repr_reveals_no_state() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    await store.put(make_scope().identity, make_quota())
    assert repr(store) == "<InMemoryQuotaStore scopes=1>"


# --------------------------------------------------------------------------- #
# Cooldowns
# --------------------------------------------------------------------------- #


async def test_cooldown_is_created_and_found() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    entry = make_cooldown(
        scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=120, now=clock.now()
    )
    await store.set(entry)

    found = await store.active(scope_identity=scope.identity, operation="search")
    assert found is not None
    assert found.reason is CooldownReason.RATE_LIMIT
    assert found.is_provider_wide is True
    assert found.remaining_seconds(clock.now()) == pytest.approx(120)


async def test_cooldown_expires_on_the_clock() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=60, now=clock.now())
    )

    clock.advance(59)
    assert await store.active(scope_identity=scope.identity) is not None
    clock.advance(1)
    assert await store.active(scope_identity=scope.identity) is None
    assert len(store) == 0


async def test_operation_specific_cooldown_does_not_block_other_operations() -> None:
    """A throttled search endpoint must not switch off the whole integration."""
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(
            scope=scope,
            reason=CooldownReason.RATE_LIMIT,
            seconds=300,
            now=clock.now(),
            operation="search",
        )
    )

    assert await store.active(scope_identity=scope.identity, operation="search") is not None
    assert await store.active(scope_identity=scope.identity, operation="retrieve") is None
    assert await store.active(scope_identity=scope.identity, operation="scan") is None


async def test_provider_wide_cooldown_blocks_every_operation() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(
            scope=scope,
            reason=CooldownReason.QUOTA_EXHAUSTED,
            seconds=3600,
            now=clock.now(),
        )
    )
    for operation in ("search", "retrieve", "scan", None):
        assert await store.active(scope_identity=scope.identity, operation=operation) is not None


async def test_the_longest_lasting_block_wins() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(
            scope=scope,
            reason=CooldownReason.RATE_LIMIT,
            seconds=30,
            now=clock.now(),
            operation="search",
        )
    )
    await store.set(
        make_cooldown(
            scope=scope,
            reason=CooldownReason.QUOTA_EXHAUSTED,
            seconds=3600,
            now=clock.now(),
        )
    )
    found = await store.active(scope_identity=scope.identity, operation="search")
    assert found is not None
    assert found.reason is CooldownReason.QUOTA_EXHAUSTED


async def test_a_shorter_cooldown_does_not_shorten_an_active_one() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(
            scope=scope, reason=CooldownReason.QUOTA_EXHAUSTED, seconds=3600, now=clock.now()
        )
    )
    await store.set(
        make_cooldown(scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=5, now=clock.now())
    )
    found = await store.active(scope_identity=scope.identity)
    assert found is not None
    assert found.remaining_seconds(clock.now()) == pytest.approx(3600)


async def test_a_longer_cooldown_extends_an_active_one() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=30, now=clock.now())
    )
    await store.set(
        make_cooldown(
            scope=scope, reason=CooldownReason.QUOTA_EXHAUSTED, seconds=600, now=clock.now()
        )
    )
    found = await store.active(scope_identity=scope.identity)
    assert found is not None
    assert found.remaining_seconds(clock.now()) == pytest.approx(600)


async def test_an_expired_cooldown_can_be_replaced_by_a_shorter_one() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=60, now=clock.now())
    )
    clock.advance(61)
    await store.set(
        make_cooldown(scope=scope, reason=CooldownReason.RATE_LIMIT, seconds=10, now=clock.now())
    )
    found = await store.active(scope_identity=scope.identity)
    assert found is not None
    assert found.remaining_seconds(clock.now()) == pytest.approx(10)


async def test_user_a_cooldown_does_not_affect_user_b() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope_a = make_scope(user_id="user-a", connection_id="conn-a")
    scope_b = make_scope(user_id="user-b", connection_id="conn-b")
    await store.set(
        make_cooldown(
            scope=scope_a, reason=CooldownReason.QUOTA_EXHAUSTED, seconds=3600, now=clock.now()
        )
    )
    assert await store.active(scope_identity=scope_a.identity) is not None
    assert await store.active(scope_identity=scope_b.identity) is None


async def test_cooldown_is_isolated_per_provider() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    one = make_scope(provider_id="provider_one")
    two = make_scope(provider_id="provider_two")
    await store.set(
        make_cooldown(
            scope=one, reason=CooldownReason.PROVIDER_UNAVAILABLE, seconds=60, now=clock.now()
        )
    )
    assert await store.active(scope_identity=two.identity) is None


async def test_entries_lists_every_active_cooldown_for_a_scope() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    await store.set(
        make_cooldown(
            scope=scope,
            reason=CooldownReason.RATE_LIMIT,
            seconds=60,
            now=clock.now(),
            operation="search",
        )
    )
    await store.set(
        make_cooldown(
            scope=scope, reason=CooldownReason.TRANSIENT_FAILURES, seconds=30, now=clock.now()
        )
    )
    entries = await store.entries(scope_identity=scope.identity)
    assert len(entries) == 2
    assert {entry.operation for entry in entries} == {None, "search"}


async def test_clear_lifts_one_or_all_cooldowns() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    scope = make_scope()
    for operation in ("search", "retrieve"):
        await store.set(
            make_cooldown(
                scope=scope,
                reason=CooldownReason.RATE_LIMIT,
                seconds=60,
                now=clock.now(),
                operation=operation,
            )
        )
    await store.clear(scope_identity=scope.identity, operation="search")
    assert await store.active(scope_identity=scope.identity, operation="search") is None
    assert await store.active(scope_identity=scope.identity, operation="retrieve") is not None

    await store.clear(scope_identity=scope.identity)
    assert await store.entries(scope_identity=scope.identity) == ()


async def test_cooldown_store_is_bounded() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock, max_entries=2)
    for index in range(4):
        await store.set(
            make_cooldown(
                scope=make_scope(user_id=f"user-{index}"),
                reason=CooldownReason.RATE_LIMIT,
                seconds=60,
                now=clock.now(),
            )
        )
    assert len(store) <= 2


def test_cooldown_store_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryCooldownStore(max_entries=0)


def test_cooldown_store_is_labelled_not_production_ready() -> None:
    assert InMemoryCooldownStore.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemoryCooldownStore.__doc__ or "")
    assert isinstance(InMemoryCooldownStore(), CooldownStore)


async def test_cooldown_store_repr_reveals_no_state() -> None:
    clock = ManualClock()
    store = InMemoryCooldownStore(clock=clock)
    await store.set(
        make_cooldown(
            scope=make_scope(), reason=CooldownReason.RATE_LIMIT, seconds=60, now=clock.now()
        )
    )
    assert repr(store) == "<InMemoryCooldownStore entries=1>"


def test_cooldown_entry_carries_no_credential_field() -> None:
    assert set(CooldownEntry.model_fields) == {
        "provider_id",
        "scope_identity",
        "reason",
        "until",
        "operation",
        "detail",
    }


def test_no_secret_appears_in_a_cooldown_key_or_entry() -> None:
    secret = "vt-key-AAAA1111-SECRET"
    entry = make_cooldown(
        scope=make_scope(user_id="user-a", connection_id="conn-a"),
        reason=CooldownReason.RATE_LIMIT,
        seconds=60,
        now=NOW,
        operation="search",
    )
    payload = json.dumps(entry.model_dump(mode="json"))
    assert secret not in payload
    assert entry.scope_identity == "user|user-a|fake_provider|conn-a"


def test_cooldown_duration_is_capped() -> None:
    """A provider reporting a reset a week away is likelier wrong than right."""
    entry = make_cooldown(
        scope=make_scope(),
        reason=CooldownReason.QUOTA_EXHAUSTED,
        seconds=60 * 60 * 24 * 7,
        now=NOW,
    )
    assert entry.remaining_seconds(NOW) == pytest.approx(MAX_COOLDOWN_SECONDS)


def test_negative_cooldown_durations_are_clamped() -> None:
    entry = make_cooldown(
        scope=make_scope(), reason=CooldownReason.RATE_LIMIT, seconds=-10, now=NOW
    )
    assert entry.is_active_at(NOW) is False


def test_cooldown_reasons_are_the_documented_four() -> None:
    assert {reason.value for reason in CooldownReason} == {
        "rate_limit",
        "quota_exhausted",
        "transient_failures",
        "provider_unavailable",
    }


# --------------------------------------------------------------------------- #
# Deriving cooldowns
# --------------------------------------------------------------------------- #


def test_rate_limit_cooldown_is_scoped_to_the_throttled_operation() -> None:
    snapshot = RateLimitSnapshot(
        operation="search",
        windows=(RateLimitWindow(window_name="minute", remaining=0, reset_after_seconds=45.0),),
    )
    entry = cooldown_from_rate_limit(snapshot, scope=make_scope(), now=NOW)
    assert entry is not None
    assert entry.operation == "search"
    assert entry.is_provider_wide is False
    assert entry.reason is CooldownReason.RATE_LIMIT
    assert entry.remaining_seconds(NOW) == pytest.approx(45.0)
    assert entry.detail is not None
    assert "minute" in entry.detail


def test_healthy_rate_limits_produce_no_cooldown() -> None:
    snapshot = RateLimitSnapshot(
        operation="search",
        windows=(RateLimitWindow(window_name="minute", limit=60, remaining=59),),
    )
    assert cooldown_from_rate_limit(snapshot, scope=make_scope(), now=NOW) is None


def test_rate_limit_cooldown_falls_back_to_a_default_without_a_reset() -> None:
    snapshot = RateLimitSnapshot(
        operation="search", windows=(RateLimitWindow(window_name="minute", remaining=0),)
    )
    entry = cooldown_from_rate_limit(snapshot, scope=make_scope(), now=NOW, default_seconds=90.0)
    assert entry is not None
    assert entry.remaining_seconds(NOW) == pytest.approx(90.0)


def test_rate_limit_cooldown_operation_can_be_overridden() -> None:
    snapshot = RateLimitSnapshot(windows=(RateLimitWindow(window_name="minute", remaining=0),))
    entry = cooldown_from_rate_limit(snapshot, scope=make_scope(), now=NOW, operation="lookup")
    assert entry is not None
    assert entry.operation == "lookup"


def test_quota_cooldown_is_provider_wide() -> None:
    """A spent account allowance applies to everything that key could do."""
    snapshot = make_quota(
        buckets=(
            QuotaBucket(
                name="daily",
                period=QuotaPeriod.DAY,
                allowed=100,
                used=100,
                reset_at=NOW + timedelta(hours=3),
            ),
        )
    )
    entry = cooldown_from_quota(snapshot, scope=make_scope(), now=NOW)
    assert entry is not None
    assert entry.is_provider_wide is True
    assert entry.reason is CooldownReason.QUOTA_EXHAUSTED
    assert entry.remaining_seconds(NOW) == pytest.approx(3 * 3600)
    assert entry.detail is not None
    assert "daily" in entry.detail


def test_healthy_quota_produces_no_cooldown() -> None:
    snapshot = make_quota(
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=100, used=1),)
    )
    assert cooldown_from_quota(snapshot, scope=make_scope(), now=NOW) is None


def test_quota_cooldown_falls_back_to_a_default_without_a_reset() -> None:
    snapshot = make_quota(buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, remaining=0),))
    entry = cooldown_from_quota(snapshot, scope=make_scope(), now=NOW, default_seconds=1200.0)
    assert entry is not None
    assert entry.remaining_seconds(NOW) == pytest.approx(1200.0)


def test_an_unreported_quota_bucket_lookup_returns_none() -> None:
    snapshot = make_quota(
        buckets=(QuotaBucket(name="daily", period=QuotaPeriod.DAY, allowed=10, used=1),)
    )
    assert snapshot.bucket("daily") is not None
    assert snapshot.bucket("weekly") is None
