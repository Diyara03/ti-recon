"""Normalizing urlscan failures (Task 8).

The engine above never sees an HTTP status. These tests pin the translation and
the redaction that goes with it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderRateLimitedError,
)
from ti_recon.providers.urlscan import (
    category_for_status,
    parse_reset_at,
    parse_retry_after,
    scrub_detail,
    translate_status_error,
)

PROVIDER = "urlscan"
FAKE_KEY = "urlscan-key-SHOULD-NOT-LEAK-12345"


def make_response(
    status_code: int,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, str] | None = None,
    text: str | None = None,
) -> httpx.Response:
    if json_body is not None:
        return httpx.Response(status_code, json=json_body, headers=headers)
    return httpx.Response(status_code, text=text or "", headers=headers)


# --------------------------------------------------------------------------- #
# Status mapping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, ProviderErrorCategory.AUTHENTICATION_ERROR),
        (403, ProviderErrorCategory.PERMISSION_ERROR),
        (404, ProviderErrorCategory.NOT_FOUND),
        (410, ProviderErrorCategory.NOT_FOUND),
        (400, ProviderErrorCategory.INVALID_REQUEST),
        (422, ProviderErrorCategory.INVALID_REQUEST),
        (408, ProviderErrorCategory.TRANSIENT_ERROR),
        (500, ProviderErrorCategory.TRANSIENT_ERROR),
        (503, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (504, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
    ],
)
def test_known_statuses(status: int, expected: ProviderErrorCategory) -> None:
    assert category_for_status(status) is expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (599, ProviderErrorCategory.TRANSIENT_ERROR),
        (418, ProviderErrorCategory.INVALID_REQUEST),
        (204, ProviderErrorCategory.UNKNOWN_ERROR),
    ],
)
def test_unmapped_statuses_fall_back_by_class(status: int, expected: ProviderErrorCategory) -> None:
    assert category_for_status(status) is expected


def test_a_missing_scan_is_recorded_as_no_data_not_as_an_error() -> None:
    """ "urlscan has never seen this" is intelligence, not a failure."""
    error = translate_status_error(
        make_response(404), provider_id=PROVIDER, operation="urlscan.result"
    )
    assert isinstance(error, ProviderNotFoundError)
    assert error.run_status is ProviderRunStatus.NO_DATA
    assert error.is_retryable is False


def test_a_rejected_key_is_an_authentication_error() -> None:
    error = translate_status_error(
        make_response(401), provider_id=PROVIDER, operation="urlscan.search"
    )
    assert isinstance(error, ProviderAuthenticationError)
    assert error.is_retryable is False


# --------------------------------------------------------------------------- #
# 429: a window that reopens vs a quota that does not
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scope", ["minute", "hour", "", None, "unexpected"])
def test_short_windows_are_rate_limits(scope: str | None) -> None:
    assert category_for_status(429, rate_limit_scope=scope) is ProviderErrorCategory.RATE_LIMITED


@pytest.mark.parametrize("scope", ["day", "Daily", "MONTH", "monthly"])
def test_long_windows_are_exhausted_quota(scope: str) -> None:
    assert category_for_status(429, rate_limit_scope=scope) is ProviderErrorCategory.QUOTA_EXCEEDED


def test_a_minute_window_is_retryable_and_carries_its_reset() -> None:
    reset = "2026-08-22T10:15:00Z"
    error = translate_status_error(
        make_response(
            429,
            headers={
                "X-Rate-Limit-Scope": "minute",
                "X-Rate-Limit-Reset": reset,
                "Retry-After": "30",
            },
        ),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert isinstance(error, ProviderRateLimitedError)
    assert error.is_retryable is True
    assert error.retry_after_seconds == 30.0
    assert error.reset_at == datetime(2026, 8, 22, 10, 15, tzinfo=UTC)


def test_a_daily_window_is_not_something_to_sit_and_wait_for() -> None:
    error = translate_status_error(
        make_response(429, headers={"X-Rate-Limit-Scope": "day"}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert isinstance(error, ProviderQuotaExceededError)
    assert error.is_retryable is False
    assert error.run_status is ProviderRunStatus.QUOTA_EXCEEDED


# --------------------------------------------------------------------------- #
# Header parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("30", 30.0), (" 5 ", 5.0), ("0", 0.0), (None, None), ("soon", None), ("-1", None)],
)
def test_retry_after_parsing(raw: str | None, expected: float | None) -> None:
    assert parse_retry_after(raw) == expected


def test_retry_after_is_capped() -> None:
    assert parse_retry_after("999999999") == 24 * 60 * 60


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-22T10:15:00Z", datetime(2026, 8, 22, 10, 15, tzinfo=UTC)),
        ("2026-08-22T10:15:00+00:00", datetime(2026, 8, 22, 10, 15, tzinfo=UTC)),
        ("2026-08-22T12:15:00+02:00", datetime(2026, 8, 22, 10, 15, tzinfo=UTC)),
        ("not-a-time", None),
        ("", None),
        (None, None),
    ],
)
def test_reset_parsing(raw: str | None, expected: datetime | None) -> None:
    assert parse_reset_at(raw) == expected


def test_a_naive_reset_is_read_as_utc_not_local_time() -> None:
    parsed = parse_reset_at("2026-08-22T10:15:00")
    assert parsed == datetime(2026, 8, 22, 10, 15, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Detail redaction
# --------------------------------------------------------------------------- #


def test_a_plain_message_survives() -> None:
    assert scrub_detail("  search query was invalid  ") == "search query was invalid"


def test_a_named_credential_is_redacted() -> None:
    detail = scrub_detail(f"api_key={FAKE_KEY} rejected")
    assert detail is not None
    assert FAKE_KEY not in detail


def test_an_unnamed_opaque_token_drops_the_whole_message() -> None:
    """The redactor can only remove what it can name; this catches the rest."""
    assert scrub_detail(f"key {FAKE_KEY} may not read this scan") is None


def test_a_quoted_url_drops_the_whole_message() -> None:
    """A submitted URL can carry a token in its query string."""
    assert scrub_detail("could not scan https://evil.example/login?token=abc123def456") is None


def test_an_empty_message_is_dropped() -> None:
    assert scrub_detail("") is None
    assert scrub_detail(None) is None


def test_a_long_message_is_bounded() -> None:
    detail = scrub_detail(" ".join(["word"] * 500))
    assert detail is not None
    assert len(detail) <= 220


def test_a_json_error_body_contributes_a_short_message() -> None:
    error = translate_status_error(
        make_response(400, json_body={"message": "query is malformed"}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert "query is malformed" in str(error)


def test_a_non_json_error_body_is_never_echoed() -> None:
    error = translate_status_error(
        make_response(500, text="<html>stack trace with secrets</html>"),
        provider_id=PROVIDER,
        operation="urlscan.result",
    )
    assert "stack trace" not in str(error)
    assert "<html>" not in str(error)


def test_a_secret_in_an_error_body_never_reaches_the_message() -> None:
    error = translate_status_error(
        make_response(403, json_body={"message": f"key {FAKE_KEY} may not read this scan"}),
        provider_id=PROVIDER,
        operation="urlscan.result",
    )
    assert FAKE_KEY not in str(error)


def test_detail_can_be_suppressed_entirely() -> None:
    error = translate_status_error(
        make_response(403, json_body={"message": "denied for reasons"}),
        provider_id=PROVIDER,
        operation="urlscan.dom",
        include_detail=False,
    )
    assert "denied for reasons" not in str(error)


def test_the_status_code_is_the_only_provider_code_recorded() -> None:
    error = translate_status_error(
        make_response(503), provider_id=PROVIDER, operation="urlscan.search"
    )
    assert error.provider_error_code == "503"


def test_a_message_that_names_a_credential_field_is_dropped() -> None:
    """Redaction removes values; a bare field name still signals the wrong content."""
    assert scrub_detail("password rejected") is None


def test_a_json_content_type_with_a_broken_body_contributes_nothing() -> None:
    error = translate_status_error(
        httpx.Response(400, content=b"{not json", headers={"Content-Type": "application/json"}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert str(error).endswith("urlscan.search: invalid_request")


def test_a_json_array_body_contributes_nothing() -> None:
    error = translate_status_error(
        httpx.Response(400, json=["nope"]), provider_id=PROVIDER, operation="urlscan.search"
    )
    assert "nope" not in str(error)


def test_a_body_with_no_known_field_contributes_nothing() -> None:
    error = translate_status_error(
        make_response(400, json_body={"unexpected": "shape"}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert "shape" not in str(error)


def test_the_second_known_field_is_used_when_the_first_is_absent() -> None:
    error = translate_status_error(
        make_response(400, json_body={"description": "query is malformed"}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert "query is malformed" in str(error)


def test_a_blank_message_falls_through_to_no_detail() -> None:
    error = translate_status_error(
        make_response(400, json_body={"message": "   "}),
        provider_id=PROVIDER,
        operation="urlscan.search",
    )
    assert str(error).endswith("urlscan.search: invalid_request")
