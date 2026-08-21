"""GTI quota discovery, mapping and secret safety (Task 7)."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from pydantic import SecretStr
from vt.error import APIError

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderErrorCategory
from ti_recon.execution import InMemoryQuotaStore, ManualClock
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.providers.gti import (
    GATING_QUOTA_PREFIX,
    GTIAdapter,
    GTILookupPolicy,
    parse_overall_quotas,
)
from ti_recon.providers.quota import QuotaPeriod

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"
OTHER_SECRET = "vt-key-BELONGS-TO-SOMEONE-ELSE-999"


def credential(
    *, secret: str = SECRET, user_id: str = "analyst-a", connection_id: str = "conn-a"
) -> CredentialMaterial:
    return CredentialMaterial(
        connection_id=connection_id,
        user_id=user_id,
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def make_adapter(
    client: FakeGTIClient | None = None, **kwargs: Any
) -> tuple[GTIAdapter, FakeGTIClient, FakeGTIClientFactory]:
    fake = client if client is not None else FakeGTIClient()
    factory = FakeGTIClientFactory(client=fake)
    adapter = GTIAdapter(client_factory=factory, clock=ManualClock(), **kwargs)
    return adapter, fake, factory


# --------------------------------------------------------------------------- #
# Parsing overall_quotas
# --------------------------------------------------------------------------- #


def test_hourly_daily_and_monthly_map_to_generic_buckets() -> None:
    reading = parse_overall_quotas(payloads.overall_quotas_payload()["data"])
    names = {bucket.name: bucket for bucket in reading.snapshot.buckets}

    assert names["api_requests_hourly"].period is QuotaPeriod.HOUR
    assert names["api_requests_daily"].period is QuotaPeriod.DAY
    assert names["api_requests_monthly"].period is QuotaPeriod.MONTH


def test_remaining_is_derived_from_allowed_and_used() -> None:
    reading = parse_overall_quotas(payloads.overall_quotas_payload()["data"])
    hourly = reading.snapshot.bucket("api_requests_hourly")
    assert hourly is not None
    assert hourly.allowed == 1_000
    assert hourly.used == 120
    assert hourly.remaining == 880


def test_the_snapshot_is_scoped_to_the_credential() -> None:
    reading = parse_overall_quotas(
        payloads.overall_quotas_payload()["data"],
        user_id="analyst-a",
        provider_connection_id="conn-a",
    )
    assert reading.snapshot.provider_id == "gti"
    assert reading.snapshot.user_id == "analyst-a"
    assert reading.snapshot.provider_connection_id == "conn-a"


def test_an_exhausted_api_allowance_is_reported_as_exhausted() -> None:
    payload = payloads.overall_quotas_payload(daily_used=20_000, daily_allowed=20_000)
    reading = parse_overall_quotas(payload["data"])
    assert reading.is_exhausted is True
    assert [b.name for b in reading.snapshot.exhausted_buckets] == ["api_requests_daily"]


def test_a_non_api_allowance_cannot_block_lookups() -> None:
    """A spent search allowance must not switch off IOC enrichment."""
    payload = payloads.overall_quotas_payload()
    payload["data"]["intelligence_searches_monthly"] = {"user": {"used": 300, "allowed": 300}}
    reading = parse_overall_quotas(payload["data"])

    assert reading.is_exhausted is False
    assert "intelligence_searches_monthly" not in {b.name for b in reading.snapshot.buckets}
    # Not discarded either: reported for traceability.
    assert "intelligence_searches_monthly" in {b.name for b in reading.non_gating}
    assert "intelligence_searches_monthly" in reading.bucket_names


def test_only_api_request_buckets_gate_execution() -> None:
    reading = parse_overall_quotas(payloads.overall_quotas_payload()["data"])
    for bucket in reading.snapshot.buckets:
        assert bucket.name.startswith(GATING_QUOTA_PREFIX)
    for bucket in reading.non_gating:
        assert not bucket.name.startswith(GATING_QUOTA_PREFIX)


def test_group_counters_are_used_when_there_is_no_user_block() -> None:
    reading = parse_overall_quotas({"api_requests_daily": {"group": {"used": 10, "allowed": 100}}})
    bucket = reading.snapshot.bucket("api_requests_daily")
    assert bucket is not None
    assert bucket.remaining == 90


def test_inline_counters_are_accepted() -> None:
    reading = parse_overall_quotas({"api_requests_daily": {"used": 5, "allowed": 50}})
    bucket = reading.snapshot.bucket("api_requests_daily")
    assert bucket is not None
    assert bucket.remaining == 45


def test_an_unknown_period_becomes_custom_rather_than_being_dropped() -> None:
    """A new GTI period is still a real limit."""
    reading = parse_overall_quotas({"api_requests_per_sprint": {"user": {"used": 1, "allowed": 9}}})
    bucket = reading.snapshot.bucket("api_requests_per_sprint")
    assert bucket is not None
    assert bucket.period is QuotaPeriod.CUSTOM


@pytest.mark.parametrize(
    "block",
    [
        "not-a-mapping",
        {"user": "not-a-mapping"},
        {"user": {}},
        {"user": {"allowed": "many", "used": None}},
        {"user": {"allowed": True}},
        {"user": {"allowed": -5}},
    ],
)
def test_an_unreadable_bucket_is_skipped_not_fatal(block: Any) -> None:
    """A schema change to one allowance must not blind us to the others."""
    reading = parse_overall_quotas(
        {
            "api_requests_daily": {"user": {"used": 1, "allowed": 10}},
            "api_requests_hourly": block,
        }
    )
    assert [b.name for b in reading.snapshot.buckets] == ["api_requests_daily"]


def test_an_empty_payload_yields_an_empty_snapshot() -> None:
    reading = parse_overall_quotas({})
    assert reading.snapshot.is_empty is True
    assert reading.is_exhausted is False
    assert reading.non_gating == ()


def test_buckets_are_ordered_deterministically() -> None:
    first = parse_overall_quotas(payloads.overall_quotas_payload()["data"])
    second = parse_overall_quotas(payloads.overall_quotas_payload()["data"])
    assert [b.name for b in first.snapshot.buckets] == [b.name for b in second.snapshot.buckets]


def test_a_snapshot_serializes_without_anything_key_shaped() -> None:
    reading = parse_overall_quotas(
        payloads.overall_quotas_payload()["data"],
        user_id="analyst-a",
        provider_connection_id="conn-a",
    )
    payload = json.dumps(reading.snapshot.model_dump(mode="json"))
    assert SECRET not in payload
    assert "overall_quotas" not in payload
    assert "/users/" not in payload


# --------------------------------------------------------------------------- #
# Adapter quota fetching
# --------------------------------------------------------------------------- #


async def test_fetch_quota_reads_and_parses() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, client, factory = make_adapter(fake)

    reading = await adapter.fetch_quota(credential())

    assert reading.snapshot.bucket("api_requests_daily") is not None
    assert client.operations("quota")
    assert factory.created_for == [SECRET]
    assert client.closed is True


async def test_a_quota_failure_raises_a_normalized_error_without_the_path() -> None:
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.PERMISSION_ERROR, "gti", operation="quota_lookup"
        )
    )
    adapter, _, _ = make_adapter(fake)

    with pytest.raises(ProviderError) as excinfo:
        await adapter.fetch_quota(credential())

    rendered = str(excinfo.value)
    assert SECRET not in rendered
    assert "overall_quotas" not in rendered


async def test_quota_state_is_isolated_between_users() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    fake_a = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake_b = FakeGTIClient(
        quota_payload=payloads.overall_quotas_payload(daily_used=1, daily_allowed=99)
    )
    factory = FakeGTIClientFactory(per_key={SECRET: fake_a, OTHER_SECRET: fake_b})
    adapter = GTIAdapter(client_factory=factory, quota_store=store, clock=ManualClock())

    reading_a = await adapter.fetch_quota(credential())
    reading_b = await adapter.fetch_quota(
        credential(secret=OTHER_SECRET, user_id="analyst-b", connection_id="conn-b")
    )

    daily_a = reading_a.snapshot.bucket("api_requests_daily")
    daily_b = reading_b.snapshot.bucket("api_requests_daily")
    assert daily_a is not None
    assert daily_b is not None
    assert daily_a.allowed == 20_000
    assert daily_b.allowed == 99
    assert reading_a.snapshot.user_id == "analyst-a"
    assert reading_b.snapshot.user_id == "analyst-b"
    assert factory.created_for == [SECRET, OTHER_SECRET]


async def test_one_users_credential_never_builds_another_users_client() -> None:
    factory = FakeGTIClientFactory(
        client=FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    )
    adapter = GTIAdapter(client_factory=factory, clock=ManualClock())

    await adapter.fetch_quota(credential(secret=SECRET))
    await adapter.fetch_quota(credential(secret=OTHER_SECRET, user_id="analyst-b"))

    assert factory.created_for == [SECRET, OTHER_SECRET]


async def test_the_quota_endpoint_path_is_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The key is in that path, so the path itself is the secret."""
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.TRANSIENT_ERROR, "gti", operation="quota_lookup"
        )
    )
    adapter, client, _ = make_adapter(fake)

    with caplog.at_level(logging.DEBUG):
        snapshot = await adapter._refresh_quota_if_stale(client, credential())

    assert snapshot is None
    assert "GTI quota lookup failed" in caplog.text
    assert SECRET not in caplog.text
    assert "/users/" not in caplog.text
    assert "overall_quotas" not in caplog.text


async def test_a_failed_quota_refresh_does_not_break_enrichment() -> None:
    """Quota is context; losing it must not fail a good IOC lookup."""
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.PERMISSION_ERROR, "gti", operation="quota_lookup"
        )
    )
    adapter, client, _ = make_adapter(fake)
    assert await adapter._refresh_quota_if_stale(client, credential()) is None


# --------------------------------------------------------------------------- #
# Quota caching
# --------------------------------------------------------------------------- #


async def test_quota_is_not_refetched_while_the_store_is_warm() -> None:
    """No quota call before every IOC lookup."""
    store = InMemoryQuotaStore(clock=ManualClock(), ttl_seconds=300)
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=fake),
        quota_store=store,
        clock=ManualClock(),
    )

    first = await adapter._refresh_quota_if_stale(fake, credential())
    second = await adapter._refresh_quota_if_stale(fake, credential())

    assert first is not None
    assert second is None
    assert len(fake.operations("quota")) == 1


async def test_quota_is_refetched_once_the_store_entry_expires() -> None:
    clock = ManualClock()
    store = InMemoryQuotaStore(clock=clock, ttl_seconds=300)
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=fake),
        quota_store=store,
        clock=clock,
    )

    await adapter._refresh_quota_if_stale(fake, credential())
    clock.advance(301)
    await adapter._refresh_quota_if_stale(fake, credential())

    assert len(fake.operations("quota")) == 2


async def test_the_refreshed_snapshot_is_written_where_the_executor_reads_it() -> None:
    """Both sides must address the same quota entry."""
    from ti_recon.execution import ExecutionScope

    store = InMemoryQuotaStore(clock=ManualClock())
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=fake),
        quota_store=store,
        clock=ManualClock(),
    )
    await adapter._refresh_quota_if_stale(fake, credential())

    executor_key = ExecutionScope.for_user(
        provider_id="gti", user_id="analyst-a", provider_connection_id="conn-a"
    ).identity
    assert await store.get(executor_key) is not None


async def test_quota_refresh_can_be_switched_off_by_policy() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, _, _ = make_adapter(fake, lookup_policy=GTILookupPolicy(refresh_quota_on_lookup=False))
    assert await adapter._refresh_quota_if_stale(fake, credential()) is None
    assert fake.operations("quota") == []


async def test_a_zero_ttl_disables_refresh() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, _, _ = make_adapter(fake, lookup_policy=GTILookupPolicy(quota_ttl_seconds=0))
    assert adapter.lookup_policy.quota_refresh_enabled is False
    assert await adapter._refresh_quota_if_stale(fake, credential()) is None


async def test_quota_refresh_works_without_a_store() -> None:
    """The store is optional; without one every refresh reads through."""
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, _, _ = make_adapter(fake)
    assert await adapter._refresh_quota_if_stale(fake, credential()) is not None
    assert await adapter._refresh_quota_if_stale(fake, credential()) is not None
    assert len(fake.operations("quota")) == 2


# --------------------------------------------------------------------------- #
# Credential validation
# --------------------------------------------------------------------------- #


async def test_a_successful_quota_lookup_validates_the_credential() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())

    assert result.status is CredentialStatus.ACTIVE
    assert result.is_usable is True
    assert result.provider_id == "gti"


async def test_a_missing_credential_is_invalid() -> None:
    adapter, _, _ = make_adapter()
    result = await adapter.validate_credentials(None)
    assert result.status is CredentialStatus.INVALID


@pytest.mark.parametrize(
    "code",
    ["AuthenticationRequiredError", "WrongCredentialsError", "UserNotActiveError"],
)
async def test_authentication_failures_mark_the_credential_invalid(code: str) -> None:
    from ti_recon.providers.gti.errors import translate_gti_error

    fake = FakeGTIClient(
        quota_error=translate_gti_error(
            APIError(code, "rejected"), provider_id="gti", operation="quota_lookup"
        )
    )
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())
    assert result.status is CredentialStatus.INVALID
    assert result.is_usable is False


async def test_forbidden_does_not_invalidate_a_working_key() -> None:
    """A 403 usually means this key may not do this one thing."""
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.PERMISSION_ERROR, "gti", operation="quota_lookup"
        )
    )
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())
    assert result.status is CredentialStatus.UNKNOWN
    assert result.is_usable is True


async def test_a_plan_limitation_does_not_invalidate_a_working_key() -> None:
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED, "gti", operation="quota_lookup"
        )
    )
    adapter, _, _ = make_adapter(fake)
    result = await adapter.validate_credentials(credential())
    assert result.status is CredentialStatus.UNKNOWN


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.TRANSIENT_ERROR,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.UNKNOWN_ERROR,
    ],
)
async def test_transient_problems_never_invalidate_a_credential(
    category: ProviderErrorCategory,
) -> None:
    """A provider outage must not disable every analyst's key."""
    fake = FakeGTIClient(quota_error=provider_error_for(category, "gti", operation="quota_lookup"))
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())
    assert result.status is CredentialStatus.UNKNOWN


async def test_quota_exhaustion_proves_the_credential_works() -> None:
    """An allowance belongs to an account; an unknown key could not spend one."""
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.QUOTA_EXCEEDED, "gti", operation="quota_lookup"
        )
    )
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())
    assert result.status is CredentialStatus.ACTIVE


async def test_validation_detail_never_carries_the_key() -> None:
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.AUTHENTICATION_ERROR,
            "gti",
            operation="quota_lookup",
            message=f"apikey={SECRET} rejected",
        )
    )
    adapter, _, _ = make_adapter(fake)

    result = await adapter.validate_credentials(credential())
    assert SECRET not in result.model_dump_json()


async def test_validation_closes_its_client() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, client, _ = make_adapter(fake)
    await adapter.validate_credentials(credential())
    assert client.closed is True


# --------------------------------------------------------------------------- #
# Capability discovery and health
# --------------------------------------------------------------------------- #


async def test_capability_discovery_costs_no_api_call() -> None:
    """Probing each capability would spend a request and still be a guess."""
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, client, factory = make_adapter(fake)

    discovery = await adapter.discover_capabilities(credential())

    assert discovery.capabilities == adapter.descriptor.capabilities
    assert discovery.plan_hint == "entitlement is determined per request"
    assert client.calls == []
    assert factory.created_for == []


async def test_health_is_unknown_without_a_credential() -> None:
    from ti_recon.providers.capabilities import ProviderHealth

    adapter, client, _ = make_adapter()
    report = await adapter.health(None)
    assert report.health is ProviderHealth.UNKNOWN
    assert client.calls == []


async def test_health_is_available_when_quota_answers() -> None:
    from ti_recon.providers.capabilities import ProviderHealth

    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    adapter, _, _ = make_adapter(fake)
    report = await adapter.health(credential())
    assert report.health is ProviderHealth.AVAILABLE


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        (ProviderErrorCategory.PROVIDER_UNAVAILABLE, "unavailable"),
        (ProviderErrorCategory.TRANSIENT_ERROR, "unavailable"),
        (ProviderErrorCategory.PERMISSION_ERROR, "degraded"),
    ],
)
async def test_health_reflects_the_failure_kind(
    category: ProviderErrorCategory, expected: str
) -> None:
    fake = FakeGTIClient(quota_error=provider_error_for(category, "gti", operation="quota_lookup"))
    adapter, _, _ = make_adapter(fake)
    report = await adapter.health(credential())
    assert report.health.value == expected
    assert SECRET not in report.model_dump_json()


# --------------------------------------------------------------------------- #
# The adapter itself
# --------------------------------------------------------------------------- #


def test_the_adapter_repr_reveals_no_credential() -> None:
    adapter, _, _ = make_adapter()
    text = repr(adapter)
    assert SECRET not in text
    assert "www.virustotal.com" in text


def test_the_gti_package_never_sleeps() -> None:
    """Backoff belongs to Task 6's executor, so nothing here may wait."""
    import inspect

    import ti_recon.providers.gti.adapter as adapter_module
    import ti_recon.providers.gti.client as client_module
    import ti_recon.providers.gti.errors as errors_module
    import ti_recon.providers.gti.quota as quota_module

    for module in (adapter_module, client_module, errors_module, quota_module):
        source = inspect.getsource(module)
        assert "asyncio.sleep" not in source
        assert "time.sleep" not in source
        for library in ("tenacity", "backoff", "retrying"):
            assert f"import {library}" not in source


async def test_a_failing_call_is_attempted_exactly_once() -> None:
    """The behavioural proof that this adapter has no retry loop of its own."""
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.TRANSIENT_ERROR, "gti", operation="quota_lookup"
        )
    )
    adapter, client, _ = make_adapter(fake)

    with pytest.raises(ProviderError):
        await adapter.fetch_quota(credential())

    assert len(client.operations("quota")) == 1


def test_the_adapter_classifies_unexpected_errors_conservatively() -> None:
    adapter, _, _ = make_adapter()
    assert (
        adapter.classify_error(provider_error_for(ProviderErrorCategory.RATE_LIMITED, "gti"))
        is ProviderErrorCategory.RATE_LIMITED
    )
    assert adapter.classify_error(TimeoutError()) is ProviderErrorCategory.TRANSIENT_ERROR
    assert adapter.classify_error(ValueError("bad shape")) is ProviderErrorCategory.SCHEMA_ERROR
    assert adapter.classify_error(RuntimeError()) is ProviderErrorCategory.UNKNOWN_ERROR
