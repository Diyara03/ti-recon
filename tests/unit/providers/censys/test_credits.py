"""Censys credit discovery (Task 9).

A credit balance is a purchased wallet, not a calendar window. The tests that
matter most are the ones separating "we do not know" from "spent": the first
means Task 6 may try, the second means it must not, and getting them the wrong
way round either burns credits or switches a working provider off.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.censys import payloads
from ti_recon.providers.censys import (
    CREDIT_BUCKET_NAME,
    CensysCreditScope,
    parse_credits,
)
from ti_recon.providers.quota import QuotaPeriod

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def reading(payload: dict[str, Any], scope: CensysCreditScope = CensysCreditScope.USER) -> Any:
    return parse_credits(
        payload,
        scope=scope,
        user_id="analyst-a",
        provider_connection_id="conn-1",
        retrieved_at=NOW,
    )


# --------------------------------------------------------------------------- #
# A wallet, not a window
# --------------------------------------------------------------------------- #


def test_a_credit_balance_is_one_bucket_over_a_custom_period() -> None:
    """Labelling it MONTH would invite a scheduler to believe it resets."""
    parsed = reading(payloads.user_credits_payload())
    bucket = parsed.bucket
    assert bucket is not None
    assert bucket.name == CREDIT_BUCKET_NAME
    assert bucket.period is QuotaPeriod.CUSTOM
    assert bucket.period is not QuotaPeriod.MONTH


def test_the_counters_are_read_from_the_nested_user_shape() -> None:
    parsed = reading(payloads.user_credits_payload(remaining=240, limit=250))
    assert parsed.remaining == 240
    bucket = parsed.bucket
    assert bucket is not None
    assert bucket.allowed == 250
    assert bucket.used == 10


def test_the_counters_are_read_from_the_organization_shape_too() -> None:
    """A parser that only ever sees one nesting proves nothing about the other."""
    parsed = reading(
        payloads.organization_credits_payload(remaining=9_000), CensysCreditScope.ORGANIZATION
    )
    assert parsed.remaining == 9_000
    assert parsed.scope is CensysCreditScope.ORGANIZATION


def test_the_snapshot_is_scoped_to_the_credential_that_read_it() -> None:
    parsed = reading(payloads.user_credits_payload())
    assert parsed.snapshot.user_id == "analyst-a"
    assert parsed.snapshot.provider_connection_id == "conn-1"
    assert parsed.snapshot.provider_id == "censys"
    assert parsed.snapshot.retrieved_at == NOW


def test_the_scope_is_recorded_so_two_balances_are_never_compared() -> None:
    assert reading(payloads.user_credits_payload()).scope is CensysCreditScope.USER


# --------------------------------------------------------------------------- #
# Spent, and unknown
# --------------------------------------------------------------------------- #


def test_a_spent_wallet_is_exhausted() -> None:
    parsed = reading(payloads.user_credits_payload(remaining=0, limit=250))
    assert parsed.is_exhausted is True
    assert parsed.snapshot.is_exhausted is True


def test_a_wallet_with_room_is_not_exhausted() -> None:
    assert reading(payloads.user_credits_payload(remaining=1)).is_exhausted is False


def test_an_unreadable_response_is_unknown_rather_than_spent() -> None:
    """An empty snapshot means "try"; a zero bucket means "stop". Not the same."""
    parsed = reading({})
    assert parsed.snapshot.is_empty is True
    assert parsed.is_exhausted is False
    assert parsed.remaining is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"result": {}},
        {"result": {"credits": {}}},
        {"credits": "unexpected"},
        {"result": {"credits": {"remaining": "lots"}}},
        {"result": {"credits": {"remaining": -5}}},
        {"result": {"credits": {"remaining": True}}},
    ],
)
def test_a_shape_change_never_invents_a_zero_balance(payload: dict[str, Any]) -> None:
    parsed = reading(payload)
    assert parsed.is_exhausted is False
    assert parsed.snapshot.is_empty is True


def test_a_balance_reported_only_as_a_remaining_count_still_reads() -> None:
    parsed = reading({"credits": {"balance": 12}})
    assert parsed.remaining == 12


def test_a_balance_reported_as_a_limit_and_usage_derives_the_remainder() -> None:
    parsed = reading({"credits": {"total": 100, "consumed": 40}})
    assert parsed.remaining == 60


def test_a_string_counter_is_read_as_a_number() -> None:
    parsed = reading({"credits": {"remaining": "17"}})
    assert parsed.remaining == 17


def test_a_flat_response_reads_without_an_envelope() -> None:
    parsed = reading({"remaining": 5, "limit": 10})
    assert parsed.remaining == 5


def test_a_renewal_instant_is_kept_when_censys_sends_one() -> None:
    parsed = reading({"credits": {"remaining": 0, "renews_at": "2026-09-01T00:00:00Z"}})
    bucket = parsed.bucket
    assert bucket is not None
    assert bucket.reset_at == datetime(2026, 9, 1, tzinfo=UTC)


def test_an_unreadable_renewal_instant_is_simply_absent() -> None:
    parsed = reading({"credits": {"remaining": 0, "renews_at": "whenever"}})
    bucket = parsed.bucket
    assert bucket is not None
    assert bucket.reset_at is None


def test_only_one_bucket_is_ever_produced() -> None:
    """A second bucket would read as an extra limit to any exhaustion check."""
    parsed = reading(payloads.user_credits_payload())
    assert len(parsed.snapshot.buckets) == 1
