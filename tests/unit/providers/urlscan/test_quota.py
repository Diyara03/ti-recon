"""urlscan quota and rate-limit parsing (Task 8).

The decision under test is which allowances are allowed to stop a lookup. TI
Recon never scans, so a spent scanning allowance must not disable the provider.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderPermissionError,
    ProviderQuotaExceededError,
    ProviderTransientError,
)
from ti_recon.providers.quota import QuotaPeriod
from ti_recon.providers.urlscan import (
    URLSCAN_PROVIDER_ID,
    credential_status_for,
    credential_validation_for,
    parse_rate_limit_headers,
    parse_user_quotas,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

QUOTAS: dict[str, Any] = {
    "limits": {
        "public": {
            "day": {"limit": 5000, "used": 5000, "remaining": 0},
            "hour": {"limit": 500, "used": 500, "remaining": 0},
        },
        "private": {"day": {"limit": 1000, "used": 1000, "remaining": 0}},
        "livescan": {"minute": {"limit": 10, "used": 10, "remaining": 0}},
        "search": {
            "day": {"limit": 1000, "used": 40, "remaining": 960, "reset": 3600},
            "minute": {"limit": 60, "used": 2, "remaining": 58},
        },
        "retrieve": {"day": {"limit": 10000, "used": 120, "remaining": 9880}},
    }
}


def test_only_read_actions_can_gate_a_lookup() -> None:
    reading = parse_user_quotas(QUOTAS, retrieved_at=NOW)
    gating = {bucket.name for bucket in reading.snapshot.buckets}
    assert gating == {"search_day", "search_minute", "retrieve_day"}


def test_exhausted_scanning_allowances_never_disable_the_provider() -> None:
    """Every scan bucket here is spent, and none of them is a lookup."""
    reading = parse_user_quotas(QUOTAS, retrieved_at=NOW)
    assert reading.is_exhausted is False
    assert reading.snapshot.is_exhausted is False
    assert {bucket.name for bucket in reading.non_gating} == {
        "public_day",
        "public_hour",
        "private_day",
        "livescan_minute",
    }


def test_nothing_is_silently_discarded() -> None:
    reading = parse_user_quotas(QUOTAS, retrieved_at=NOW)
    assert len(reading.bucket_names) == 7


def test_a_spent_read_allowance_does_gate() -> None:
    payload = {"limits": {"search": {"day": {"limit": 100, "used": 100, "remaining": 0}}}}
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    assert reading.is_exhausted is True
    assert reading.can_perform("search") is False
    # A different action is unaffected by search running out.
    assert reading.can_perform("retrieve") is True


def test_an_unreported_action_is_assumed_available() -> None:
    """Silence is not exhaustion."""
    reading = parse_user_quotas({"limits": {}}, retrieved_at=NOW)
    assert reading.can_perform("search") is True
    assert reading.snapshot.is_empty is True


def test_counters_and_periods_are_read() -> None:
    reading = parse_user_quotas(QUOTAS, retrieved_at=NOW)
    day = reading.snapshot.bucket("search_day")
    assert day is not None
    assert (day.allowed, day.used, day.remaining) == (1000, 40, 960)
    assert day.period is QuotaPeriod.DAY
    minute = reading.snapshot.bucket("search_minute")
    assert minute is not None
    assert minute.period is QuotaPeriod.MINUTE


def test_a_reset_offset_becomes_an_instant() -> None:
    reading = parse_user_quotas(QUOTAS, retrieved_at=NOW)
    day = reading.snapshot.bucket("search_day")
    assert day is not None
    assert day.reset_at == NOW + timedelta(hours=1)


def test_a_reset_timestamp_is_read_as_given() -> None:
    payload = {
        "limits": {"search": {"day": {"limit": 10, "used": 1, "reset": "2026-08-23T00:00:00Z"}}}
    }
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    bucket = reading.snapshot.bucket("search_day")
    assert bucket is not None
    assert bucket.reset_at == datetime(2026, 8, 23, tzinfo=UTC)


def test_a_flat_response_without_an_envelope_still_parses() -> None:
    payload = {"search": {"day": {"limit": 10, "used": 1}}}
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    assert reading.snapshot.bucket("search_day") is not None


@pytest.mark.parametrize(
    "payload",
    [
        {"limits": {"search": "unexpected"}},
        {"limits": {"search": {"day": "unexpected"}}},
        {"limits": {"search": {"day": {}}}},
        {"limits": {"search": {"day": {"limit": "many", "used": None}}}},
        {"limits": {"search": {"day": {"limit": True}}}},
        {"limits": {"search": {"day": {"limit": -5}}}},
    ],
)
def test_an_unreadable_bucket_is_skipped_rather_than_fatal(payload: dict[str, Any]) -> None:
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    assert reading.snapshot.is_empty is True


def test_an_unrecognized_period_is_kept_as_custom() -> None:
    payload = {"limits": {"search": {"fortnight": {"limit": 10, "used": 1}}}}
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    bucket = reading.snapshot.bucket("search_fortnight")
    assert bucket is not None
    assert bucket.period is QuotaPeriod.CUSTOM


def test_an_unusable_reset_is_dropped_not_guessed() -> None:
    payload = {"limits": {"search": {"day": {"limit": 10, "used": 1, "reset": "whenever"}}}}
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    bucket = reading.snapshot.bucket("search_day")
    assert bucket is not None
    assert bucket.reset_at is None


@pytest.mark.parametrize("reset", [True, {"in": 60}, None, -30])
def test_odd_reset_shapes_are_dropped(reset: Any) -> None:
    payload = {"limits": {"search": {"day": {"limit": 10, "used": 1, "reset": reset}}}}
    bucket = parse_user_quotas(payload, retrieved_at=NOW).snapshot.bucket("search_day")
    assert bucket is not None
    assert bucket.reset_at is None


def test_the_snapshot_is_scoped_to_whose_key_is_being_spent() -> None:
    reading = parse_user_quotas(
        QUOTAS, user_id="user-a", provider_connection_id="conn-1", retrieved_at=NOW
    )
    assert reading.snapshot.provider_id == URLSCAN_PROVIDER_ID
    assert reading.snapshot.user_id == "user-a"
    assert reading.snapshot.provider_connection_id == "conn-1"
    assert reading.snapshot.retrieved_at == NOW


# --------------------------------------------------------------------------- #
# Per-response rate limits
# --------------------------------------------------------------------------- #


def test_rate_limit_headers_become_a_snapshot() -> None:
    snapshot = parse_rate_limit_headers(
        {
            "X-Rate-Limit-Limit": "100",
            "X-Rate-Limit-Remaining": "97",
            "X-Rate-Limit-Reset": "2026-08-22T12:01:00Z",
            "X-Rate-Limit-Scope": "minute",
            "X-Rate-Limit-Action": "search",
        },
        operation="urlscan.search",
        now=NOW,
    )
    assert snapshot is not None
    assert (snapshot.limit, snapshot.remaining, snapshot.scope) == (100, 97, "minute")
    assert snapshot.reset_at == datetime(2026, 8, 22, 12, 1, tzinfo=UTC)
    assert snapshot.operation == "urlscan.search"
    assert [window.window_name for window in snapshot.windows] == ["search_minute"]


def test_a_metered_action_is_named_so_windows_are_not_confused() -> None:
    """A search limit must not be read as a retrieval limit."""
    snapshot = parse_rate_limit_headers(
        {"X-Rate-Limit-Remaining": "5", "X-Rate-Limit-Action": "retrieve"}, now=NOW
    )
    assert snapshot is not None
    assert snapshot.windows[0].window_name.startswith("retrieve")


def test_a_reset_offset_header_is_turned_into_an_instant() -> None:
    snapshot = parse_rate_limit_headers(
        {"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset-After": "45"}, now=NOW
    )
    assert snapshot is not None
    assert snapshot.reset_at == NOW + timedelta(seconds=45)
    assert snapshot.windows[0].reset_after_seconds == 45.0
    assert snapshot.windows[0].is_exhausted is True


def test_silence_produces_no_snapshot_rather_than_an_empty_one() -> None:
    assert parse_rate_limit_headers({}) is None
    assert parse_rate_limit_headers({"Server": "nginx"}) is None


def test_unreadable_counters_are_ignored() -> None:
    assert parse_rate_limit_headers({"X-Rate-Limit-Limit": "lots"}) is None


def test_a_window_name_falls_back_when_urlscan_names_none() -> None:
    snapshot = parse_rate_limit_headers({"X-Rate-Limit-Remaining": "3"}, now=NOW)
    assert snapshot is not None
    assert snapshot.windows[0].window_name == "window"


# --------------------------------------------------------------------------- #
# What a failure says about the key
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        (ProviderErrorCategory.AUTHENTICATION_ERROR, CredentialStatus.INVALID),
        (ProviderErrorCategory.PERMISSION_ERROR, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.PLAN_LIMITED, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.QUOTA_EXCEEDED, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.RATE_LIMITED, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.TRANSIENT_ERROR, CredentialStatus.UNKNOWN),
        (ProviderErrorCategory.SCHEMA_ERROR, CredentialStatus.UNKNOWN),
        (ProviderErrorCategory.NOT_FOUND, CredentialStatus.UNKNOWN),
    ],
)
def test_only_a_rejected_key_is_invalid(
    category: ProviderErrorCategory, expected: CredentialStatus
) -> None:
    assert credential_status_for(category) is expected


def test_a_successful_check_reports_an_active_key() -> None:
    validation = credential_validation_for(URLSCAN_PROVIDER_ID)
    assert validation.status is CredentialStatus.ACTIVE
    assert validation.is_usable is True
    assert validation.detail is None


def test_a_rejected_key_is_reported_invalid() -> None:
    validation = credential_validation_for(
        URLSCAN_PROVIDER_ID,
        ProviderAuthenticationError(URLSCAN_PROVIDER_ID, operation="urlscan.quotas"),
    )
    assert validation.status is CredentialStatus.INVALID
    assert validation.is_usable is False


@pytest.mark.parametrize(
    "error",
    [
        ProviderPermissionError(URLSCAN_PROVIDER_ID),
        ProviderQuotaExceededError(URLSCAN_PROVIDER_ID),
        ProviderTransientError(URLSCAN_PROVIDER_ID),
    ],
)
def test_a_working_key_is_not_disabled_by_something_else_being_in_the_way(
    error: Exception,
) -> None:
    validation = credential_validation_for(URLSCAN_PROVIDER_ID, error)  # type: ignore[arg-type]
    assert validation.is_usable is True


def test_a_validation_detail_carries_no_credential_material() -> None:
    error = ProviderAuthenticationError(
        URLSCAN_PROVIDER_ID, message="api_key=urlscan-key-SHOULD-NOT-LEAK-12345 rejected"
    )
    validation = credential_validation_for(URLSCAN_PROVIDER_ID, error)
    assert "urlscan-key-SHOULD-NOT-LEAK-12345" not in (validation.detail or "")


def test_a_numeric_reset_sent_as_a_string_is_still_an_offset() -> None:
    payload = {"limits": {"search": {"day": {"limit": 10, "used": 1, "reset": "3600"}}}}
    bucket = parse_user_quotas(payload, retrieved_at=NOW).snapshot.bucket("search_day")
    assert bucket is not None
    assert bucket.reset_at == NOW + timedelta(hours=1)


# --------------------------------------------------------------------------- #
# The account's maximum searchable range
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "payload",
    [
        {"limits": {}, "maxSearchRangeMonths": 6},
        {"limits": {"maxSearchRangeMonths": 6}},
        {"limits": {"search": {"maxSearchRangeMonths": 6}}},
        {"limits": {}, "max_search_range_months": 6},
    ],
)
def test_the_account_search_range_is_read_wherever_urlscan_puts_it(
    payload: dict[str, Any],
) -> None:
    assert parse_user_quotas(payload, retrieved_at=NOW).max_search_range_months == 6


def test_an_absent_search_range_is_unknown_rather_than_unlimited() -> None:
    """The caller's own lookback is finite, so unknown can never widen a query."""
    assert parse_user_quotas(QUOTAS, retrieved_at=NOW).max_search_range_months is None


@pytest.mark.parametrize(
    "value",
    ["many", None, 0, -3, True, {"months": 6}],
)
def test_an_unreadable_search_range_is_ignored(value: Any) -> None:
    payload = {"limits": {"search": {"maxSearchRangeMonths": value}}}
    assert parse_user_quotas(payload, retrieved_at=NOW).max_search_range_months is None


def test_an_absurd_search_range_is_capped() -> None:
    payload = {"maxSearchRangeMonths": 100_000}
    assert parse_user_quotas(payload, retrieved_at=NOW).max_search_range_months == 600


def test_reading_the_search_range_does_not_disturb_the_allowances() -> None:
    payload = dict(QUOTAS)
    payload["maxSearchRangeMonths"] = 3
    reading = parse_user_quotas(payload, retrieved_at=NOW)
    assert reading.max_search_range_months == 3
    assert {bucket.name for bucket in reading.snapshot.buckets} == {
        "search_day",
        "search_minute",
        "retrieve_day",
    }
