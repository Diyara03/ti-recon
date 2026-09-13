"""Translating abuse.ch outcomes into normalized categories (Task 10).

The abuse.ch APIs put the real outcome in the body of an HTTP 200, so this
module is the one that decides whether a lookup succeeded. Two things must hold
above all: a rejected credential must never read as "nothing found", and a
fair-use block must never read as a bad key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.providers.abusech.errors import (
    NO_DATA_QUERY_STATUSES,
    SUCCESS_QUERY_STATUSES,
    UNREADABLE_QUERY_STATUS,
    category_for_query_status,
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    query_status_of,
    scrub_detail,
    translate_query_status,
    translate_status_error,
)
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderPermissionError,
    ProviderRateLimitedError,
)

LEAKY = "abusech-key-SHOULD-NOT-LEAK-1234567890"


# --------------------------------------------------------------------------- #
# HTTP statuses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, ProviderErrorCategory.AUTHENTICATION_ERROR),
        (403, ProviderErrorCategory.PERMISSION_ERROR),
        # Absence is reported only in the body; an HTTP 404 is an endpoint
        # fact, never "IOC unknown", so it is a shape error rather than NO_DATA.
        (404, ProviderErrorCategory.SCHEMA_ERROR),
        (405, ProviderErrorCategory.INVALID_REQUEST),
        (429, ProviderErrorCategory.RATE_LIMITED),
        (408, ProviderErrorCategory.TRANSIENT_ERROR),
        (500, ProviderErrorCategory.TRANSIENT_ERROR),
        (502, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (418, ProviderErrorCategory.INVALID_REQUEST),
        (599, ProviderErrorCategory.TRANSIENT_ERROR),
        (200, ProviderErrorCategory.UNKNOWN_ERROR),
    ],
)
def test_http_statuses_map_onto_categories(status: int, expected: ProviderErrorCategory) -> None:
    assert category_for_status(status) is expected


def test_a_status_error_carries_the_code_and_never_a_body() -> None:
    error = translate_status_error(
        httpx.Response(429, json={"query_status": "rate_limited"}, headers={"Retry-After": "12"}),
        provider_id="threatfox",
        operation="threatfox.search_ioc",
    )
    assert isinstance(error, ProviderRateLimitedError)
    assert error.provider_error_code == "429"
    assert error.retry_after_seconds == 12.0


def test_a_non_json_error_body_contributes_nothing() -> None:
    error = translate_status_error(
        httpx.Response(500, text="<html>boom</html>"),
        provider_id="urlhaus",
        operation="urlhaus.url",
    )
    assert error.category is ProviderErrorCategory.TRANSIENT_ERROR


def test_an_error_body_that_echoes_the_key_is_dropped() -> None:
    error = translate_status_error(
        httpx.Response(401, json={"message": f"Auth-Key {LEAKY} rejected"}),
        provider_id="threatfox",
        operation="threatfox.search_ioc",
    )
    assert isinstance(error, ProviderAuthenticationError)
    assert LEAKY not in str(error)
    assert "SHOULD-NOT-LEAK" not in str(error)


def test_detail_can_be_suppressed_entirely() -> None:
    error = translate_status_error(
        httpx.Response(400, json={"message": "bad search term"}),
        provider_id="threatfox",
        operation="op",
        include_detail=False,
    )
    assert "bad search term" not in str(error)


# --------------------------------------------------------------------------- #
# scrub_detail
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("bad search term", True),
        ("  spaced  ", True),
        ("", False),
        (None, False),
        (f"key={LEAKY}", False),
    ],
)
def test_a_provider_message_is_kept_only_when_it_is_plainly_prose(
    value: str | None, kept: bool
) -> None:
    result = scrub_detail(value)
    assert (result is not None) is kept
    if result is not None:
        assert LEAKY not in result


def test_a_long_opaque_token_never_survives_a_message() -> None:
    """It is never worth its diagnostic value, redacted or dropped."""
    opaque = "z" * 40
    result = scrub_detail(f"search failed for {opaque}")
    assert result is None or opaque not in result


def test_a_message_is_length_bounded() -> None:
    result = scrub_detail("prose " * 200)
    assert result is None or len(result) <= 200


# --------------------------------------------------------------------------- #
# Body statuses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"query_status": "ok"}, "ok"),
        ({"query_status": "OK"}, "ok"),
        ({"query_status": " hash_not_found "}, "hash_not_found"),
        ({"query_status": ""}, UNREADABLE_QUERY_STATUS),
        ({"query_status": "has spaces"}, UNREADABLE_QUERY_STATUS),
        ({"query_status": "Unknown Auth-Key"}, UNREADABLE_QUERY_STATUS),
        ({"query_status": "9leading_digit"}, UNREADABLE_QUERY_STATUS),
        ({"query_status": "x" * 200}, UNREADABLE_QUERY_STATUS),
        ({"query_status": 7}, UNREADABLE_QUERY_STATUS),
        ({}, None),
        ("not a dict", None),
    ],
)
def test_a_body_status_is_validated_before_it_is_trusted(
    payload: Any, expected: str | None
) -> None:
    """It ends up in an exception message and in metrics."""
    assert query_status_of(payload) == expected


def test_an_unreadable_status_is_a_schema_error_never_success_or_no_data() -> None:
    """Present but unusable is a shape change; absent means success (Task 24 Phase 3)."""
    assert category_for_query_status(UNREADABLE_QUERY_STATUS) is ProviderErrorCategory.SCHEMA_ERROR
    error = translate_query_status(UNREADABLE_QUERY_STATUS, provider_id="threatfox", operation="x")
    assert error is not None
    assert error.category is ProviderErrorCategory.SCHEMA_ERROR
    assert error.run_status is not ProviderRunStatus.NO_DATA
    assert translate_query_status(None, provider_id="threatfox", operation="x") is None


def test_success_and_absence_are_different_answers() -> None:
    assert "ok" in SUCCESS_QUERY_STATUSES
    for status in SUCCESS_QUERY_STATUSES:
        assert category_for_query_status(status) is None
    for status in NO_DATA_QUERY_STATUSES:
        assert category_for_query_status(status) is ProviderErrorCategory.NOT_FOUND


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("no_api_key", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("invalid_api_key", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("unauthorized", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("user_blacklisted", ProviderErrorCategory.PERMISSION_ERROR),
        ("illegal_hash", ProviderErrorCategory.INVALID_REQUEST),
        ("invalid_hash", ProviderErrorCategory.INVALID_REQUEST),
        ("http_post_expected", ProviderErrorCategory.INVALID_REQUEST),
        ("rate_limited", ProviderErrorCategory.RATE_LIMITED),
        ("something_new", ProviderErrorCategory.UNKNOWN_ERROR),
    ],
)
def test_body_statuses_map_onto_categories(status: str, expected: ProviderErrorCategory) -> None:
    assert category_for_query_status(status) is expected


def test_an_unknown_status_is_an_error_and_never_a_success() -> None:
    """A status nobody has seen must not be read as "nothing found"."""
    error = translate_query_status("brand_new_failure", provider_id="urlhaus", operation="op")
    assert error is not None
    assert error.category is ProviderErrorCategory.UNKNOWN_ERROR


def test_a_missing_status_is_not_treated_as_a_failure() -> None:
    """Some responses omit it; losing real evidence over that would be worse."""
    assert translate_query_status(None, provider_id="urlhaus", operation="op") is None
    assert translate_query_status("ok", provider_id="urlhaus", operation="op") is None


def test_a_translated_body_status_carries_the_token_as_its_code() -> None:
    error = translate_query_status("user_blacklisted", provider_id="threatfox", operation="op")
    assert isinstance(error, ProviderPermissionError)
    assert error.provider_error_code == "user_blacklisted"
    assert "user_blacklisted" in str(error)


def test_an_illegal_request_is_typed_as_one() -> None:
    error = translate_query_status("illegal_search_term", provider_id="threatfox", operation="op")
    assert isinstance(error, ProviderInvalidRequestError)


# --------------------------------------------------------------------------- #
# Retry-After and timestamps
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30", 30.0),
        (" 30 ", 30.0),
        ("0", 0.0),
        ("-5", None),
        ("Wed, 21 Oct 2026 07:28:00 GMT", None),
        (None, None),
    ],
)
def test_only_a_numeric_retry_after_is_read(value: str | None, expected: float | None) -> None:
    """An absolute instant from a provider can be skewed against our clock."""
    assert parse_retry_after(value) == expected


def test_an_absurd_retry_after_is_capped() -> None:
    capped = parse_retry_after("99999999")
    assert capped is not None
    assert capped < 99999999


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-08-21 04:05:06 UTC", datetime(2026, 8, 21, 4, 5, 6, tzinfo=UTC)),
        ("2026-08-21 04:05:06", datetime(2026, 8, 21, 4, 5, 6, tzinfo=UTC)),
        ("2026-08-21T04:05:06Z", datetime(2026, 8, 21, 4, 5, 6, tzinfo=UTC)),
        ("2026-08-21T04:05:06+02:00", datetime(2026, 8, 21, 2, 5, 6, tzinfo=UTC)),
    ],
)
def test_both_timestamp_spellings_are_read_as_utc(value: str, expected: datetime) -> None:
    """A naive value is UTC: the provider is not reporting our timezone."""
    assert parse_utc_timestamp(value) == expected


@pytest.mark.parametrize("value", [None, "", "   ", "2026-13-45", "not a date", 20260821])
def test_an_unreadable_timestamp_is_dropped(value: Any) -> None:
    assert parse_utc_timestamp(value) is None


# --------------------------------------------------------------------------- #
# What a failure says about a shared key
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        (ProviderErrorCategory.AUTHENTICATION_ERROR, CredentialStatus.INVALID),
        (ProviderErrorCategory.PERMISSION_ERROR, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.QUOTA_EXCEEDED, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.RATE_LIMITED, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.NOT_FOUND, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.INVALID_REQUEST, CredentialStatus.ACTIVE),
        (ProviderErrorCategory.TRANSIENT_ERROR, CredentialStatus.UNKNOWN),
        (ProviderErrorCategory.SCHEMA_ERROR, CredentialStatus.UNKNOWN),
    ],
)
def test_only_a_rejected_key_is_invalid(
    category: ProviderErrorCategory, expected: CredentialStatus
) -> None:
    """One key serves three providers: a ThreatFox refusal must not disable two."""
    assert credential_status_for(category) is expected


def test_a_successful_probe_validates_the_key() -> None:
    validation = credential_validation_for("threatfox", None)
    assert validation.status is CredentialStatus.ACTIVE
    assert validation.provider_id == "threatfox"


def test_a_failed_probe_reports_a_category_and_never_a_secret() -> None:
    error = translate_query_status("no_api_key", provider_id="threatfox", operation="op")
    validation = credential_validation_for("threatfox", error)
    assert validation.status is CredentialStatus.INVALID
    assert LEAKY not in (validation.detail or "")
