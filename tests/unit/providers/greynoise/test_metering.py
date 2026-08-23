"""What GreyNoise says about its own limits (Task 9).

GreyNoise does not document these headers as part of its API contract, so the
parser is tolerant by design. The property worth protecting is the honest one: a
response that said nothing measurable produces no snapshot at all, rather than an
empty one that would read like a measurement.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ti_recon.providers.greynoise import parse_rate_limit_headers

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def test_a_silent_response_produces_no_snapshot() -> None:
    """Inventing numbers a scheduler would trust is worse than having none."""
    assert parse_rate_limit_headers({}, now=NOW) is None


@pytest.mark.parametrize(
    "headers",
    [
        {"content-type": "application/json"},
        {"x-ratelimit-limit": "not-a-number"},
        {"x-ratelimit-remaining": "-4"},
        {"x-ratelimit-reset": "whenever"},
        {"retry-after": "soon"},
    ],
)
def test_nothing_measurable_produces_no_snapshot(headers: dict[str, str]) -> None:
    assert parse_rate_limit_headers(headers, now=NOW) is None


def test_a_reported_allowance_becomes_a_snapshot() -> None:
    snapshot = parse_rate_limit_headers(
        {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "7"}, now=NOW
    )
    assert snapshot is not None
    assert snapshot.limit == 100
    assert snapshot.remaining == 7
    assert len(snapshot.windows) == 1
    assert snapshot.windows[0].window_name == "reported"


def test_the_hyphenated_spelling_reads_the_same() -> None:
    """Both spellings appear in the wild; whichever arrives is used."""
    snapshot = parse_rate_limit_headers(
        {"x-rate-limit-limit": "50", "x-rate-limit-remaining": "0"}, now=NOW
    )
    assert snapshot is not None
    assert snapshot.limit == 50
    assert snapshot.is_throttled is True


def test_an_offset_reset_becomes_an_instant() -> None:
    snapshot = parse_rate_limit_headers({"x-ratelimit-reset": "30"}, now=NOW)
    assert snapshot is not None
    assert snapshot.reset_at == NOW + timedelta(seconds=30)
    assert snapshot.windows[0].reset_after_seconds == 30.0


def test_an_absolute_reset_is_read_as_an_instant() -> None:
    snapshot = parse_rate_limit_headers({"x-ratelimit-reset": "2026-08-23T12:05:00Z"}, now=NOW)
    assert snapshot is not None
    assert snapshot.reset_at == datetime(2026, 8, 23, 12, 5, tzinfo=UTC)
    # No offset was sent, so none is invented.
    assert snapshot.windows[0].reset_after_seconds is None


def test_a_retry_after_stands_in_for_a_missing_reset() -> None:
    """It is the same statement in the header a 429 actually carries."""
    snapshot = parse_rate_limit_headers({"retry-after": "12"}, now=NOW)
    assert snapshot is not None
    assert snapshot.reset_at == NOW + timedelta(seconds=12)
    assert snapshot.windows[0].reset_after_seconds == 12.0


def test_a_reset_header_wins_over_a_retry_after() -> None:
    snapshot = parse_rate_limit_headers({"x-ratelimit-reset": "5", "retry-after": "600"}, now=NOW)
    assert snapshot is not None
    assert snapshot.windows[0].reset_after_seconds == 5.0


def test_an_absurd_reset_offset_is_clamped() -> None:
    snapshot = parse_rate_limit_headers({"retry-after": "99999999"}, now=NOW)
    assert snapshot is not None
    reset_after = snapshot.windows[0].reset_after_seconds
    assert reset_after is not None
    assert reset_after <= 32 * 24 * 60 * 60


def test_a_negative_offset_is_ignored() -> None:
    assert parse_rate_limit_headers({"retry-after": "-30"}, now=NOW) is None


def test_the_operation_travels_with_the_snapshot() -> None:
    snapshot = parse_rate_limit_headers(
        {"x-ratelimit-remaining": "3"}, operation="greynoise.ip_context", now=NOW
    )
    assert snapshot is not None
    assert snapshot.operation == "greynoise.ip_context"


def test_header_names_are_matched_case_insensitively() -> None:
    snapshot = parse_rate_limit_headers({"X-RATELIMIT-REMAINING": "9"}, now=NOW)
    assert snapshot is not None
    assert snapshot.remaining == 9


def test_a_zero_remaining_is_a_measurement_rather_than_silence() -> None:
    snapshot = parse_rate_limit_headers({"x-ratelimit-remaining": "0"}, now=NOW)
    assert snapshot is not None
    assert snapshot.remaining == 0
    assert snapshot.is_throttled is True
