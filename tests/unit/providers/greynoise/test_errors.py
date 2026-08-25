"""Mapping GreyNoise failures onto normalized categories (Task 9).

The distinction these tests exist to protect: a rejected key and an unentitled
key are different facts, and conflating them either disables a working
free-tier credential or hides a revoked one behind a "limited plan" message.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.providers.greynoise import (
    QUOTA_RETRY_AFTER_THRESHOLD_SECONDS,
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    scrub_detail,
    translate_status_error,
)

FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-1234567890"


# --------------------------------------------------------------------------- #
# The distinction that matters
# --------------------------------------------------------------------------- #


def test_a_rejected_key_is_an_authentication_error() -> None:
    assert category_for_status(401) is ProviderErrorCategory.AUTHENTICATION_ERROR


def test_a_rejected_key_is_never_reported_as_a_plan_limit() -> None:
    """Otherwise a revoked key looks like a free account and is never fixed."""
    category = category_for_status(401)
    assert category is not ProviderErrorCategory.PLAN_LIMITED
    assert category is not ProviderErrorCategory.PERMISSION_ERROR


def test_a_forbidden_endpoint_is_a_permission_fact_not_an_entitlement_claim() -> None:
    """GreyNoise answers 403 for both; the honest reading is the narrower one."""
    assert category_for_status(403) is ProviderErrorCategory.PERMISSION_ERROR


def test_an_unknown_address_is_recorded_as_no_data() -> None:
    category = category_for_status(404)
    assert category is ProviderErrorCategory.NOT_FOUND
    error = translate_status_error(
        httpx.Response(404), provider_id="greynoise", operation="greynoise.community"
    )
    assert error.run_status is ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# 429: a window or an allowance
# --------------------------------------------------------------------------- #


def test_a_throttled_window_is_retryable() -> None:
    assert category_for_status(429) is ProviderErrorCategory.RATE_LIMITED
    assert category_for_status(429, retry_after_seconds=30.0) is (
        ProviderErrorCategory.RATE_LIMITED
    )


def test_a_long_wait_is_an_exhausted_allowance_rather_than_a_pause() -> None:
    category = category_for_status(429, retry_after_seconds=QUOTA_RETRY_AFTER_THRESHOLD_SECONDS + 1)
    assert category is ProviderErrorCategory.QUOTA_EXCEEDED


def test_a_silent_429_stays_retryable() -> None:
    """With no ``Retry-After`` the benign reading wins."""
    assert category_for_status(429, retry_after_seconds=None) is (
        ProviderErrorCategory.RATE_LIMITED
    )


def test_a_retry_after_is_carried_onto_the_error() -> None:
    error = translate_status_error(
        httpx.Response(429, headers={"Retry-After": "12"}),
        provider_id="greynoise",
        operation="greynoise.ip_context",
    )
    assert error.retry_after_seconds == 12.0
    assert error.is_retryable is True


# --------------------------------------------------------------------------- #
# Everything else
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "category"),
    [
        (400, ProviderErrorCategory.INVALID_REQUEST),
        (422, ProviderErrorCategory.INVALID_REQUEST),
        (408, ProviderErrorCategory.TRANSIENT_ERROR),
        (500, ProviderErrorCategory.TRANSIENT_ERROR),
        (502, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (503, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (504, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (599, ProviderErrorCategory.TRANSIENT_ERROR),
        (451, ProviderErrorCategory.INVALID_REQUEST),
        (100, ProviderErrorCategory.UNKNOWN_ERROR),
    ],
)
def test_statuses_map_to_normalized_categories(
    status: int, category: ProviderErrorCategory
) -> None:
    assert category_for_status(status) is category


def test_only_the_status_code_is_kept_as_a_provider_error_code() -> None:
    error = translate_status_error(
        httpx.Response(503), provider_id="greynoise", operation="greynoise.ip_context"
    )
    assert error.provider_error_code == "503"


# --------------------------------------------------------------------------- #
# Nothing credential-shaped survives into a message
# --------------------------------------------------------------------------- #


def test_a_body_message_is_kept_when_it_is_plain_prose() -> None:
    error = translate_status_error(
        httpx.Response(
            403,
            json={"message": "This endpoint requires a paid plan."},
            headers={"content-type": "application/json"},
        ),
        provider_id="greynoise",
        operation="greynoise.ip_context",
    )
    assert "paid plan" in str(error)


def test_a_message_quoting_the_key_is_dropped_entirely() -> None:
    error = translate_status_error(
        httpx.Response(
            401,
            json={"message": f"key {FAKE_KEY} is not valid"},
            headers={"content-type": "application/json"},
        ),
        provider_id="greynoise",
        operation="greynoise.ip_context",
    )
    assert FAKE_KEY not in str(error)
    assert "SHOULD-NOT-LEAK" not in str(error)


def test_a_non_json_body_contributes_nothing() -> None:
    error = translate_status_error(
        httpx.Response(500, text=f"<html>{FAKE_KEY}</html>"),
        provider_id="greynoise",
        operation="greynoise.ip_context",
    )
    assert FAKE_KEY not in str(error)


def test_scrub_detail_drops_anything_with_a_long_opaque_token() -> None:
    assert scrub_detail(f"lookup failed for {FAKE_KEY}") is None
    assert scrub_detail("lookup failed") == "lookup failed"
    assert scrub_detail(None) is None
    assert scrub_detail("   ") is None


def test_scrub_detail_removes_a_named_credential_assignment() -> None:
    cleaned = scrub_detail("api_key=abc rejected")
    assert cleaned is None or "abc" not in cleaned


# --------------------------------------------------------------------------- #
# Timestamps and offsets
# --------------------------------------------------------------------------- #


def test_a_bare_date_is_read_as_utc() -> None:
    parsed = parse_utc_timestamp("2026-08-20")
    assert parsed == datetime(2026, 8, 20, tzinfo=UTC)


def test_a_zulu_instant_is_read_as_utc() -> None:
    parsed = parse_utc_timestamp("2026-08-20T04:05:06Z")
    assert parsed == datetime(2026, 8, 20, 4, 5, 6, tzinfo=UTC)


def test_an_offset_instant_is_normalized_to_utc() -> None:
    parsed = parse_utc_timestamp("2026-08-20T06:05:06+02:00")
    assert parsed == datetime(2026, 8, 20, 4, 5, 6, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "   ", "not-a-date", "2026-13-45"])
def test_an_unreadable_timestamp_is_none(value: str | None) -> None:
    assert parse_utc_timestamp(value) is None


@pytest.mark.parametrize("value", [None, "", "soon", "-5"])
def test_an_unreadable_retry_after_is_none(value: str | None) -> None:
    assert parse_retry_after(value) is None


def test_an_absurd_retry_after_is_clamped() -> None:
    assert parse_retry_after("999999999") == 24 * 60 * 60


# --------------------------------------------------------------------------- #
# What a failure says about the credential
# --------------------------------------------------------------------------- #


def test_only_a_rejected_key_is_marked_invalid() -> None:
    assert credential_status_for(ProviderErrorCategory.AUTHENTICATION_ERROR) is (
        CredentialStatus.INVALID
    )


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.PLAN_LIMITED,
        ProviderErrorCategory.QUOTA_EXCEEDED,
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.NOT_FOUND,
    ],
)
def test_a_working_key_stays_active_through_every_other_refusal(
    category: ProviderErrorCategory,
) -> None:
    """A free-tier key touching a paid endpoint must not be disabled."""
    assert credential_status_for(category) is CredentialStatus.ACTIVE


def test_an_unrelated_failure_says_nothing_about_the_credential() -> None:
    assert credential_status_for(ProviderErrorCategory.TRANSIENT_ERROR) is (
        CredentialStatus.UNKNOWN
    )
    assert credential_status_for(ProviderErrorCategory.SCHEMA_ERROR) is CredentialStatus.UNKNOWN


def test_a_successful_check_reports_an_active_credential() -> None:
    validation = credential_validation_for("greynoise")
    assert validation.status is CredentialStatus.ACTIVE
    assert validation.is_usable is True


def test_a_validation_detail_never_carries_the_key() -> None:
    error = translate_status_error(
        httpx.Response(
            401,
            json={"message": f"bad key {FAKE_KEY}"},
            headers={"content-type": "application/json"},
        ),
        provider_id="greynoise",
        operation="greynoise.community",
    )
    validation = credential_validation_for("greynoise", error)
    assert validation.status is CredentialStatus.INVALID
    assert FAKE_KEY not in validation.model_dump_json()
