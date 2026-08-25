"""Mapping Censys failures onto normalized categories (Task 9).

The distinction these tests exist to protect: a rate limit lifts by itself and
is worth retrying, an empty credit balance does not and every retry against it
is a wasted request. Task 6 treats the two completely differently, so routing a
status to the wrong one either burns credits or puts a working token on a long
cooldown.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.providers.censys import (
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    scrub_detail,
    translate_status_error,
)

FAKE_TOKEN = "censys-pat-SHOULD-NOT-LEAK-1234567890"


# --------------------------------------------------------------------------- #
# Credits and rate limits are not the same resource
# --------------------------------------------------------------------------- #


def test_too_many_requests_is_a_rate_limit_and_stays_retryable() -> None:
    category = category_for_status(429)
    assert category is ProviderErrorCategory.RATE_LIMITED
    assert category is not ProviderErrorCategory.QUOTA_EXCEEDED


def test_payment_required_is_an_exhausted_balance() -> None:
    """Waiting achieves nothing when the wallet is empty."""
    assert category_for_status(402) is ProviderErrorCategory.QUOTA_EXCEEDED


def test_a_spent_balance_is_not_retryable() -> None:
    error = translate_status_error(
        httpx.Response(402), provider_id="censys", operation="censys.host"
    )
    assert error.is_retryable is False
    assert error.run_status is ProviderRunStatus.QUOTA_EXCEEDED


def test_a_throttled_minute_is_retryable() -> None:
    error = translate_status_error(
        httpx.Response(429), provider_id="censys", operation="censys.host"
    )
    assert error.is_retryable is True


def test_a_permission_refusal_is_neither_a_quota_nor_a_bad_token() -> None:
    """A long cooldown over an entitlement it will never gain by waiting."""
    category = category_for_status(403)
    assert category is ProviderErrorCategory.PERMISSION_ERROR
    assert category is not ProviderErrorCategory.QUOTA_EXCEEDED
    assert category is not ProviderErrorCategory.AUTHENTICATION_ERROR


# --------------------------------------------------------------------------- #
# Everything else
# --------------------------------------------------------------------------- #


def test_a_rejected_token_is_an_authentication_error() -> None:
    assert category_for_status(401) is ProviderErrorCategory.AUTHENTICATION_ERROR


def test_an_unscanned_asset_is_recorded_as_no_data() -> None:
    """ "Never scanned" is real intelligence, not a failure."""
    error = translate_status_error(
        httpx.Response(404), provider_id="censys", operation="censys.host"
    )
    assert error.category is ProviderErrorCategory.NOT_FOUND
    assert error.run_status is ProviderRunStatus.NO_DATA


@pytest.mark.parametrize(
    ("status", "category"),
    [
        (400, ProviderErrorCategory.INVALID_REQUEST),
        (406, ProviderErrorCategory.INVALID_REQUEST),
        (410, ProviderErrorCategory.NOT_FOUND),
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


def test_a_wrong_schema_request_is_an_invalid_request() -> None:
    """406 means the Accept header asked for something Censys cannot serve."""
    assert category_for_status(406) is ProviderErrorCategory.INVALID_REQUEST


def test_only_the_status_code_is_kept_as_a_provider_error_code() -> None:
    error = translate_status_error(
        httpx.Response(503), provider_id="censys", operation="censys.host"
    )
    assert error.provider_error_code == "503"


def test_a_retry_after_is_carried_onto_the_error() -> None:
    error = translate_status_error(
        httpx.Response(429, headers={"Retry-After": "30"}),
        provider_id="censys",
        operation="censys.host",
    )
    assert error.retry_after_seconds == 30.0


# --------------------------------------------------------------------------- #
# Nothing credential-shaped survives into a message
# --------------------------------------------------------------------------- #


def test_a_body_message_is_kept_when_it_is_plain_prose() -> None:
    error = translate_status_error(
        httpx.Response(
            402,
            json={"message": "Insufficient credits."},
            headers={"content-type": "application/json"},
        ),
        provider_id="censys",
        operation="censys.host",
    )
    assert "Insufficient credits" in str(error)


def test_a_message_quoting_the_token_is_dropped_entirely() -> None:
    error = translate_status_error(
        httpx.Response(
            401,
            json={"message": f"Bearer {FAKE_TOKEN} is invalid"},
            headers={"content-type": "application/json"},
        ),
        provider_id="censys",
        operation="censys.host",
    )
    assert FAKE_TOKEN not in str(error)
    assert "SHOULD-NOT-LEAK" not in str(error)


def test_a_non_json_body_contributes_nothing() -> None:
    error = translate_status_error(
        httpx.Response(500, text=f"<html>{FAKE_TOKEN}</html>"),
        provider_id="censys",
        operation="censys.host",
    )
    assert FAKE_TOKEN not in str(error)


def test_a_detail_can_be_discarded_entirely() -> None:
    error = translate_status_error(
        httpx.Response(
            403,
            json={"message": "Forbidden for this account"},
            headers={"content-type": "application/json"},
        ),
        provider_id="censys",
        operation="censys.host",
        include_detail=False,
    )
    assert "Forbidden for this account" not in str(error)


def test_scrub_detail_drops_anything_with_a_long_opaque_token() -> None:
    assert scrub_detail(f"lookup failed for {FAKE_TOKEN}") is None
    assert scrub_detail("lookup failed") == "lookup failed"
    assert scrub_detail(None) is None


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #


def test_a_sub_second_instant_is_read_as_utc() -> None:
    assert parse_utc_timestamp("2026-08-21T04:05:06.123Z") == datetime(
        2026, 8, 21, 4, 5, 6, 123_000, tzinfo=UTC
    )


def test_a_naive_instant_is_read_as_utc_rather_than_local() -> None:
    assert parse_utc_timestamp("2026-08-21T04:05:06") == datetime(2026, 8, 21, 4, 5, 6, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "   ", "yesterday"])
def test_an_unreadable_timestamp_is_none(value: str | None) -> None:
    assert parse_utc_timestamp(value) is None


@pytest.mark.parametrize("value", [None, "", "soon", "-1"])
def test_an_unreadable_retry_after_is_none(value: str | None) -> None:
    assert parse_retry_after(value) is None


# --------------------------------------------------------------------------- #
# What a failure says about the credential
# --------------------------------------------------------------------------- #


def test_only_a_rejected_token_is_marked_invalid() -> None:
    assert credential_status_for(ProviderErrorCategory.AUTHENTICATION_ERROR) is (
        CredentialStatus.INVALID
    )


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.QUOTA_EXCEEDED,
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.NOT_FOUND,
    ],
)
def test_an_empty_wallet_never_disables_a_working_token(
    category: ProviderErrorCategory,
) -> None:
    assert credential_status_for(category) is CredentialStatus.ACTIVE


def test_an_unrelated_failure_says_nothing_about_the_credential() -> None:
    assert credential_status_for(ProviderErrorCategory.TRANSIENT_ERROR) is (
        CredentialStatus.UNKNOWN
    )


def test_a_successful_check_reports_an_active_credential() -> None:
    validation = credential_validation_for("censys")
    assert validation.status is CredentialStatus.ACTIVE
    assert validation.is_usable is True


def test_a_validation_detail_never_carries_the_token() -> None:
    error = translate_status_error(
        httpx.Response(
            401,
            json={"message": f"token {FAKE_TOKEN} rejected"},
            headers={"content-type": "application/json"},
        ),
        provider_id="censys",
        operation="censys.user_credits",
    )
    validation = credential_validation_for("censys", error)
    assert validation.status is CredentialStatus.INVALID
    assert FAKE_TOKEN not in validation.model_dump_json()
