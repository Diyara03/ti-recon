"""Provider result cache (Task 6, step 1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from fixtures.execution import (
    make_envelope,
    make_object,
    make_request,
    make_scope,
)
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    CacheKey,
    CachePolicy,
    CacheScope,
    ExecutionScope,
    InMemoryProviderCache,
    ManualClock,
    build_cache_key,
)
from ti_recon.providers import CacheabilityHint, ProviderDescriptor, ProviderRequest

DESCRIPTOR = ProviderDescriptor(
    provider_id="fake_provider",
    display_name="Fake Provider",
    adapter_version="0.1.0",
    api_version="v1",
    source_family="aggregator",
    supported_object_types=frozenset(
        {IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR, IntelObjectType.FILE}
    ),
    capabilities=frozenset(
        {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
    ),
)


def key_for(
    *,
    scope: ExecutionScope | None = None,
    descriptor: ProviderDescriptor | None = None,
    request: ProviderRequest | None = None,
) -> CacheKey:
    return build_cache_key(
        scope=scope or make_scope(),
        descriptor=descriptor or DESCRIPTOR,
        request=request or make_request(),
    )


# --------------------------------------------------------------------------- #
# Hit / miss / expiry
# --------------------------------------------------------------------------- #


async def test_cache_miss_returns_none() -> None:
    clock = ManualClock()
    cache = InMemoryProviderCache(clock=clock)
    assert await cache.get(key_for()) is None


async def test_cache_hit_returns_the_stored_result() -> None:
    clock = ManualClock()
    cache = InMemoryProviderCache(clock=clock)
    key = key_for()
    envelope = make_envelope()
    await cache.set(key, envelope, 60)

    hit = await cache.get(key)
    assert hit is not None
    assert hit.provider == envelope.provider
    assert hit.status is ProviderRunStatus.SUCCESS
    assert len(hit.evidence) == 1


async def test_entry_expires_once_the_ttl_has_passed() -> None:
    clock = ManualClock()
    cache = InMemoryProviderCache(clock=clock)
    key = key_for()
    await cache.set(key, make_envelope(), 60)

    clock.advance(59)
    assert await cache.get(key) is not None
    clock.advance(1)
    assert await cache.get(key) is None


async def test_expired_entry_is_dropped_not_merely_hidden() -> None:
    clock = ManualClock()
    cache = InMemoryProviderCache(clock=clock)
    key = key_for()
    await cache.set(key, make_envelope(), 10)
    clock.advance(11)
    await cache.get(key)
    assert len(cache) == 0


async def test_zero_ttl_is_not_stored() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    key = key_for()
    await cache.set(key, make_envelope(), 0)
    assert len(cache) == 0


async def test_invalidate_and_clear() -> None:
    clock = ManualClock()
    cache = InMemoryProviderCache(clock=clock)
    key = key_for()
    await cache.set(key, make_envelope(), 60)
    await cache.invalidate(key)
    assert await cache.get(key) is None
    # Invalidating a missing entry is a no-op, not an error.
    await cache.invalidate(key)

    await cache.set(key, make_envelope(), 60)
    await cache.clear()
    assert len(cache) == 0


class WallClockJump:
    """Wall time leaps forward; monotonic time stands still.

    Models a host clock being corrected (or NTP stepping) mid-flight.
    """

    def __init__(self) -> None:
        self._now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
        self._monotonic = 1000.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def jump_wall_clock(self, hours: int) -> None:
        self._now = self._now + timedelta(hours=hours)


async def test_expiry_follows_monotonic_time_not_the_wall_clock() -> None:
    """A host clock correction must not expire a still-fresh entry."""
    clock = WallClockJump()
    cache = InMemoryProviderCache(clock=clock)
    key = key_for()
    await cache.set(key, make_envelope(), 60)

    clock.jump_wall_clock(24)

    assert await cache.get(key) is not None


async def test_cache_is_bounded_and_evicts_least_recently_used() -> None:
    cache = InMemoryProviderCache(clock=ManualClock(), max_entries=2)
    keys = [
        key_for(request=make_request(intel_object=make_object(value=f"host{i}.example")))
        for i in range(3)
    ]
    for key in keys:
        await cache.set(key, make_envelope(), 60)
    assert len(cache) == 2
    assert await cache.get(keys[0]) is None
    assert await cache.get(keys[2]) is not None


def test_max_entries_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryProviderCache(max_entries=0)


def test_cache_is_labelled_not_production_ready() -> None:
    assert InMemoryProviderCache.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemoryProviderCache.__doc__ or "")


async def test_repr_reveals_no_cached_content() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    await cache.set(key_for(), make_envelope(), 60)
    text = repr(cache)
    assert "entries=1" in text
    assert "user-a" not in text
    assert "evil.example" not in text


# --------------------------------------------------------------------------- #
# Mutation safety
# --------------------------------------------------------------------------- #


async def test_caller_cannot_mutate_the_stored_copy_through_a_hit() -> None:
    """Evidence attributes are a mutable dict inside a frozen model."""
    cache = InMemoryProviderCache(clock=ManualClock())
    key = key_for()
    await cache.set(key, make_envelope(), 60)

    first = await cache.get(key)
    assert first is not None
    first.evidence[0].attributes["malicious_vendors"] = 999
    first.evidence[0].attributes["injected"] = True

    second = await cache.get(key)
    assert second is not None
    assert second.evidence[0].attributes == {"malicious_vendors": 7}


async def test_caller_cannot_mutate_the_stored_copy_through_the_original() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    key = key_for()
    envelope = make_envelope()
    await cache.set(key, envelope, 60)

    envelope.evidence[0].attributes["mutated_after_set"] = True

    hit = await cache.get(key)
    assert hit is not None
    assert "mutated_after_set" not in hit.evidence[0].attributes


async def test_each_hit_returns_an_independent_copy() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    key = key_for()
    await cache.set(key, make_envelope(), 60)
    a = await cache.get(key)
    b = await cache.get(key)
    assert a is not None
    assert b is not None
    assert a is not b
    assert a.evidence[0].attributes is not b.evidence[0].attributes


# --------------------------------------------------------------------------- #
# Key identity
# --------------------------------------------------------------------------- #


def test_identical_requests_produce_identical_keys() -> None:
    assert key_for().storage_key == key_for().storage_key


def test_investigation_id_does_not_change_the_key() -> None:
    """The same analyst asking the same question is the same question."""
    a = key_for(request=make_request(investigation_id="inv-1"))
    b = key_for(request=make_request(investigation_id="inv-2"))
    assert a.storage_key == b.storage_key


@pytest.mark.parametrize(
    "overrides",
    [
        {"operation": ProviderOperation.PIVOT},
        {"requested_capabilities": frozenset({ProviderCapability.MALWARE_INTELLIGENCE})},
        {
            "requested_capabilities": frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
            )
        },
        {"depth": InvestigationDepth.DEEP},
        {"max_results": 10},
        {"max_pages": 2},
        {"intel_object": make_object(IntelObjectType.IPV4_ADDR, "198.51.100.7")},
        {"intel_object": make_object(IntelObjectType.FILE)},
    ],
)
def test_request_semantics_change_the_key(overrides: dict[str, object]) -> None:
    baseline = key_for()
    changed = key_for(request=make_request(**overrides))
    assert baseline.storage_key != changed.storage_key


def test_capability_order_does_not_change_the_key() -> None:
    """Capabilities are a set; the key must not depend on iteration order."""
    a = key_for(
        request=make_request(
            requested_capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
            )
        )
    )
    b = key_for(
        request=make_request(
            requested_capabilities=frozenset(
                {ProviderCapability.MALWARE_INTELLIGENCE, ProviderCapability.REPUTATION}
            )
        )
    )
    assert a.storage_key == b.storage_key


def test_adapter_and_api_version_change_the_key() -> None:
    """Upgrading a parser must not serve results the old parser produced."""
    baseline = key_for()
    new_adapter = key_for(descriptor=DESCRIPTOR.model_copy(update={"adapter_version": "0.2.0"}))
    new_api = key_for(descriptor=DESCRIPTOR.model_copy(update={"api_version": "v4"}))
    assert baseline.storage_key != new_adapter.storage_key
    assert baseline.storage_key != new_api.storage_key


# --------------------------------------------------------------------------- #
# Isolation
# --------------------------------------------------------------------------- #


async def test_user_a_cannot_read_user_b_cache_entry() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    key_a = key_for(scope=make_scope(user_id="user-a", connection_id="conn-a"))
    key_b = key_for(scope=make_scope(user_id="user-b", connection_id="conn-b"))

    await cache.set(key_a, make_envelope(), 60)

    assert await cache.get(key_a) is not None
    assert await cache.get(key_b) is None


def test_different_users_produce_different_keys() -> None:
    a = key_for(scope=make_scope(user_id="user-a", connection_id="conn-a"))
    b = key_for(scope=make_scope(user_id="user-b", connection_id="conn-b"))
    assert a.storage_key != b.storage_key
    assert a.scope_identity != b.scope_identity


def test_same_user_different_provider_connection_is_isolated() -> None:
    """Rotating to a new connection must not reuse the old one's results."""
    a = key_for(scope=make_scope(user_id="user-a", connection_id="conn-1"))
    b = key_for(scope=make_scope(user_id="user-a", connection_id="conn-2"))
    assert a.storage_key != b.storage_key


def test_same_user_different_provider_is_isolated() -> None:
    a = key_for(scope=make_scope(provider_id="provider_one"))
    b = key_for(scope=make_scope(provider_id="provider_two"))
    assert a.storage_key != b.storage_key


def test_user_scope_is_the_default() -> None:
    assert make_scope().scope is CacheScope.USER
    assert CachePolicy().scope is CacheScope.USER


def test_global_scope_must_be_asked_for_explicitly() -> None:
    scope = ExecutionScope.global_for_provider(provider_id="local_warning_list")
    assert scope.scope is CacheScope.GLOBAL
    assert scope.user_id is None
    global_key = build_cache_key(scope=scope, descriptor=DESCRIPTOR, request=make_request())
    user_key = key_for()
    assert global_key.storage_key != user_key.storage_key
    assert global_key.storage_key.startswith("v1|global|")


async def test_global_scope_entry_is_not_reachable_from_a_user_scope() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    global_key = build_cache_key(
        scope=ExecutionScope.global_for_provider(provider_id="fake_provider"),
        descriptor=DESCRIPTOR,
        request=make_request(),
    )
    await cache.set(global_key, make_envelope(), 60)
    assert await cache.get(key_for()) is None


def test_no_secret_can_appear_in_a_cache_key() -> None:
    """The key is built from identifiers, options and versions only."""
    secret = "vt-key-AAAA1111-SECRET"
    key = key_for(
        scope=ExecutionScope.for_user(
            provider_id="fake_provider", user_id="user-a", provider_connection_id="conn-a"
        )
    )
    assert secret not in key.storage_key
    assert secret not in key.scope_identity
    # Structural guarantee: the scope model has nowhere to put one.
    assert set(ExecutionScope.model_fields) == {
        "provider_id",
        "user_id",
        "provider_connection_id",
        "scope",
    }


def test_scope_identity_is_stable_and_readable() -> None:
    scope = make_scope(user_id="user-a", connection_id="conn-a")
    assert scope.identity == "user|user-a|fake_provider|conn-a"
    assert scope.operation_key("search") == "user|user-a|fake_provider|conn-a|search"
    assert scope.operation_key() == "user|user-a|fake_provider|conn-a|*"


def test_scope_is_immutable() -> None:
    with pytest.raises(ValidationError, match="frozen"):
        make_scope().provider_id = "other"


# --------------------------------------------------------------------------- #
# Cache policy
# --------------------------------------------------------------------------- #


def test_success_uses_the_success_ttl() -> None:
    policy = CachePolicy(success_ttl_seconds=1800)
    envelope = make_envelope(status=ProviderRunStatus.SUCCESS)
    assert policy.ttl_for(envelope, make_request()) == 1800


def test_no_data_uses_a_shorter_negative_ttl() -> None:
    policy = CachePolicy()
    assert policy.no_data_ttl_seconds < policy.success_ttl_seconds
    envelope = make_envelope(status=ProviderRunStatus.NO_DATA, with_evidence=False)
    assert policy.ttl_for(envelope, make_request()) == policy.no_data_ttl_seconds


def test_partial_is_not_cached_by_default() -> None:
    envelope = make_envelope(status=ProviderRunStatus.PARTIAL)
    assert CachePolicy().ttl_for(envelope, make_request()) is None


def test_partial_can_be_cached_with_an_explicit_short_ttl() -> None:
    policy = CachePolicy(partial_ttl_seconds=30)
    envelope = make_envelope(status=ProviderRunStatus.PARTIAL)
    assert policy.ttl_for(envelope, make_request()) == 30


@pytest.mark.parametrize(
    "status",
    [
        ProviderRunStatus.NOT_CONFIGURED,
        ProviderRunStatus.NOT_SUPPORTED,
        ProviderRunStatus.PLAN_LIMITED,
        ProviderRunStatus.QUOTA_EXCEEDED,
        ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ],
)
def test_failure_statuses_are_never_cached(status: ProviderRunStatus) -> None:
    envelope = make_envelope(status=status, with_evidence=False)
    assert CachePolicy().ttl_for(envelope, make_request()) is None


def test_error_status_is_never_cached() -> None:
    from ti_recon.enums import ProviderErrorCategory
    from ti_recon.providers import ProviderResultEnvelope

    envelope = ProviderResultEnvelope(
        provider="fake_provider",
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.ERROR,
        adapter_version="0.1.0",
        api_version="v1",
        error_category=ProviderErrorCategory.TRANSIENT_ERROR,
    )
    assert CachePolicy().ttl_for(envelope, make_request()) is None


def test_disabled_policy_caches_nothing() -> None:
    policy = CachePolicy(enabled=False)
    assert policy.is_request_cacheable(make_request()) is False
    assert policy.ttl_for(make_envelope(), make_request()) is None


def test_active_operations_are_not_cached_by_default() -> None:
    policy = CachePolicy()
    active = make_request(
        operation=ProviderOperation.ACTIVE_ACTION,
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )
    assert policy.is_request_cacheable(active) is False
    assert policy.ttl_for(make_envelope(), active) is None


def test_active_mode_alone_bypasses_the_cache() -> None:
    policy = CachePolicy()
    active = make_request(
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )
    assert policy.is_request_cacheable(active) is False


def test_active_caching_can_be_enabled_explicitly() -> None:
    policy = CachePolicy(cache_active_operations=True)
    active = make_request(
        operation=ProviderOperation.ACTIVE_ACTION,
        activity_mode=ActivityMode.ACTIVE,
        requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
    )
    assert policy.is_request_cacheable(active) is True


def test_adapter_saying_uncacheable_wins() -> None:
    envelope = make_envelope(cacheability=CacheabilityHint(cacheable=False))
    assert CachePolicy().ttl_for(envelope, make_request()) is None


def test_provider_hint_may_shorten_the_ttl() -> None:
    envelope = make_envelope(cacheability=CacheabilityHint(ttl_seconds=45))
    assert CachePolicy(success_ttl_seconds=3600).ttl_for(envelope, make_request()) == 45


def test_provider_hint_may_not_extend_the_ttl() -> None:
    envelope = make_envelope(cacheability=CacheabilityHint(ttl_seconds=99_999))
    assert CachePolicy(success_ttl_seconds=600).ttl_for(envelope, make_request()) == 600


def test_provider_hint_can_be_ignored_by_policy() -> None:
    envelope = make_envelope(cacheability=CacheabilityHint(ttl_seconds=45))
    policy = CachePolicy(success_ttl_seconds=600, respect_provider_hint=False)
    assert policy.ttl_for(envelope, make_request()) == 600


def test_ttl_is_clamped_to_the_policy_maximum() -> None:
    policy = CachePolicy(success_ttl_seconds=100_000, max_ttl_seconds=3600)
    assert policy.ttl_for(make_envelope(), make_request()) == 3600


def test_zero_ttl_means_do_not_cache() -> None:
    policy = CachePolicy(success_ttl_seconds=0)
    assert policy.ttl_for(make_envelope(), make_request()) is None


def test_disabled_global_policy_is_rejected() -> None:
    with pytest.raises(ValidationError, match="global scope"):
        CachePolicy(enabled=False, scope=CacheScope.GLOBAL)


def test_cacheable_statuses_are_the_documented_three() -> None:
    from ti_recon.execution import CACHEABLE_STATUSES

    assert CACHEABLE_STATUSES == {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.NO_DATA,
        ProviderRunStatus.PARTIAL,
    }
    for status in ProviderRunStatus:
        cacheable = CachePolicy(partial_ttl_seconds=30)._status_ttl(status) is not None
        assert cacheable is (status in CACHEABLE_STATUSES)
