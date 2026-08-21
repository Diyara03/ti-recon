"""Retry and backoff policy (Task 6, step 2).

Every test here is instant: backoff is a pure function, and the retry decision
takes an injected clock reading and jitter source. Nothing sleeps.
"""

from __future__ import annotations

import itertools
import random
from datetime import UTC, datetime, timedelta

import pytest

from ti_recon.enums import ActivityMode, ProviderErrorCategory
from ti_recon.execution import (
    AUTOMATICALLY_RETRYABLE_CATEGORIES,
    CONDITIONALLY_RETRYABLE_CATEGORIES,
    NEVER_RETRYABLE_CATEGORIES,
    CooldownReason,
    FixedJitter,
    NoJitter,
    RandomJitter,
    RetryDecision,
    RetryOutcome,
    RetryPolicy,
    compute_backoff,
    decide_retry,
)
from ti_recon.providers.errors import (
    RETRYABLE_ERROR_CATEGORIES,
    ProviderError,
    provider_error_for,
)

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
POLICY = RetryPolicy()


def error_for(
    category: ProviderErrorCategory,
    *,
    retry_after_seconds: float | None = None,
    reset_at: datetime | None = None,
) -> ProviderError:
    return provider_error_for(
        category,
        "fake_provider",
        operation="lookup",
        retry_after_seconds=retry_after_seconds,
        reset_at=reset_at,
    )


def decide(
    category: ProviderErrorCategory,
    *,
    attempt: int = 1,
    policy: RetryPolicy = POLICY,
    activity_mode: ActivityMode = ActivityMode.PASSIVE,
    retry_after_seconds: float | None = None,
    reset_at: datetime | None = None,
) -> RetryDecision:
    return decide_retry(
        error=error_for(category, retry_after_seconds=retry_after_seconds, reset_at=reset_at),
        attempt=attempt,
        policy=policy,
        activity_mode=activity_mode,
        now=NOW,
        jitter=NoJitter(),
    )


# --------------------------------------------------------------------------- #
# The matrix
# --------------------------------------------------------------------------- #


def test_the_three_retry_sets_partition_every_category() -> None:
    """A category in none would silently become non-retryable; in two, ambiguous."""
    combined = (
        AUTOMATICALLY_RETRYABLE_CATEGORIES
        | CONDITIONALLY_RETRYABLE_CATEGORIES
        | NEVER_RETRYABLE_CATEGORIES
    )
    assert combined == set(ProviderErrorCategory)
    assert not (AUTOMATICALLY_RETRYABLE_CATEGORIES & CONDITIONALLY_RETRYABLE_CATEGORIES)
    assert not (AUTOMATICALLY_RETRYABLE_CATEGORIES & NEVER_RETRYABLE_CATEGORIES)
    assert not (CONDITIONALLY_RETRYABLE_CATEGORIES & NEVER_RETRYABLE_CATEGORIES)


def test_matrix_agrees_with_the_task_5_error_taxonomy() -> None:
    """The two layers must not disagree about what counts as transient."""
    assert (
        AUTOMATICALLY_RETRYABLE_CATEGORIES | CONDITIONALLY_RETRYABLE_CATEGORIES
    ) == RETRYABLE_ERROR_CATEGORIES


@pytest.mark.parametrize(
    "category",
    [ProviderErrorCategory.TRANSIENT_ERROR, ProviderErrorCategory.PROVIDER_UNAVAILABLE],
)
def test_transient_failures_retry(category: ProviderErrorCategory) -> None:
    decision = decide(category)
    assert decision.should_retry is True
    assert decision.outcome is RetryOutcome.RETRY_BACKOFF
    assert decision.delay_seconds > 0


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.AUTHENTICATION_ERROR,
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.PLAN_LIMITED,
        ProviderErrorCategory.NOT_FOUND,
        ProviderErrorCategory.INVALID_REQUEST,
        ProviderErrorCategory.PARTIAL_RESULT,
        ProviderErrorCategory.SCHEMA_ERROR,
    ],
)
def test_non_retryable_categories_do_not_retry(category: ProviderErrorCategory) -> None:
    decision = decide(category)
    assert decision.should_retry is False
    assert decision.outcome is RetryOutcome.STOP_NOT_RETRYABLE
    assert decision.cooldown_reason is None


def test_authentication_error_does_not_retry() -> None:
    """Retrying a rejected key burns quota and can trip abuse protection."""
    assert decide(ProviderErrorCategory.AUTHENTICATION_ERROR).should_retry is False


def test_plan_limited_does_not_retry() -> None:
    assert decide(ProviderErrorCategory.PLAN_LIMITED).should_retry is False


def test_partial_result_does_not_retry() -> None:
    """A partial result is a completed answer, not a failure to repeat."""
    assert decide(ProviderErrorCategory.PARTIAL_RESULT).should_retry is False


def test_unknown_error_does_not_retry_by_default() -> None:
    decision = decide(ProviderErrorCategory.UNKNOWN_ERROR)
    assert decision.should_retry is False


def test_unknown_error_can_retry_when_policy_opts_in() -> None:
    decision = decide(
        ProviderErrorCategory.UNKNOWN_ERROR,
        policy=RetryPolicy(retry_unknown_errors=True),
    )
    assert decision.should_retry is True


# --------------------------------------------------------------------------- #
# Quota vs rate limit
# --------------------------------------------------------------------------- #


def test_quota_exceeded_never_retries_and_sets_a_cooldown() -> None:
    decision = decide(ProviderErrorCategory.QUOTA_EXCEEDED)
    assert decision.should_retry is False
    assert decision.outcome is RetryOutcome.STOP_QUOTA_EXHAUSTED
    assert decision.cooldown_reason is CooldownReason.QUOTA_EXHAUSTED
    assert decision.cooldown_seconds == POLICY.quota_cooldown_seconds


def test_quota_cooldown_uses_the_provider_reset_time_when_given() -> None:
    decision = decide(ProviderErrorCategory.QUOTA_EXCEEDED, reset_at=NOW + timedelta(hours=2))
    assert decision.cooldown_seconds == pytest.approx(7200)


def test_quota_exhaustion_is_kept_separate_from_rate_limiting() -> None:
    quota = decide(ProviderErrorCategory.QUOTA_EXCEEDED)
    rate = decide(ProviderErrorCategory.RATE_LIMITED, retry_after_seconds=1.0)
    assert quota.cooldown_reason is CooldownReason.QUOTA_EXHAUSTED
    assert rate.should_retry is True


def test_short_rate_limit_retries_inline() -> None:
    decision = decide(ProviderErrorCategory.RATE_LIMITED, retry_after_seconds=2.0)
    assert decision.should_retry is True
    assert decision.outcome is RetryOutcome.RETRY_AFTER_RATE_LIMIT
    assert decision.delay_seconds == pytest.approx(2.0)


def test_short_rate_limit_from_a_reset_timestamp_retries_inline() -> None:
    decision = decide(ProviderErrorCategory.RATE_LIMITED, reset_at=NOW + timedelta(seconds=3))
    assert decision.should_retry is True
    assert decision.delay_seconds == pytest.approx(3.0)


def test_long_rate_limit_does_not_wait_and_sets_a_cooldown() -> None:
    """Nobody should watch a spinner because a window resets in an hour."""
    decision = decide(ProviderErrorCategory.RATE_LIMITED, reset_at=NOW + timedelta(hours=1))
    assert decision.should_retry is False
    assert decision.delay_seconds == 0.0
    assert decision.outcome is RetryOutcome.STOP_RATE_LIMIT_TOO_LONG
    assert decision.cooldown_reason is CooldownReason.RATE_LIMIT
    assert decision.cooldown_seconds == pytest.approx(3600)


def test_rate_limit_with_no_reset_hint_becomes_a_cooldown() -> None:
    """With nothing to wait for, hammering the endpoint is the wrong answer."""
    decision = decide(ProviderErrorCategory.RATE_LIMITED)
    assert decision.should_retry is False
    assert decision.outcome is RetryOutcome.STOP_RATE_LIMIT_UNKNOWN
    assert decision.cooldown_reason is CooldownReason.RATE_LIMIT
    assert decision.cooldown_seconds == POLICY.unknown_rate_limit_cooldown_seconds


def test_rate_limit_boundary_is_inclusive() -> None:
    policy = RetryPolicy(max_inline_wait_seconds=5.0)
    at_limit = decide(ProviderErrorCategory.RATE_LIMITED, retry_after_seconds=5.0, policy=policy)
    past_limit = decide(ProviderErrorCategory.RATE_LIMITED, retry_after_seconds=5.01, policy=policy)
    assert at_limit.should_retry is True
    assert past_limit.should_retry is False


def test_rate_limit_retry_stops_at_the_attempt_ceiling() -> None:
    policy = RetryPolicy(max_attempts=2)
    decision = decide(
        ProviderErrorCategory.RATE_LIMITED, attempt=2, retry_after_seconds=1.0, policy=policy
    )
    assert decision.should_retry is False
    assert decision.outcome is RetryOutcome.STOP_ATTEMPTS_EXHAUSTED
    assert decision.cooldown_reason is CooldownReason.RATE_LIMIT


def test_retry_after_seconds_wins_over_reset_at() -> None:
    """A relative offset cannot be skewed by a clock difference."""
    error = error_for(
        ProviderErrorCategory.RATE_LIMITED,
        retry_after_seconds=2.0,
        reset_at=NOW + timedelta(hours=5),
    )
    assert error.delay_until_reset(NOW) == pytest.approx(2.0)


def test_a_reset_time_already_in_the_past_is_clamped_to_zero() -> None:
    error = error_for(ProviderErrorCategory.RATE_LIMITED, reset_at=NOW - timedelta(minutes=5))
    assert error.delay_until_reset(NOW) == 0.0


def test_delay_until_reset_is_none_when_the_provider_said_nothing() -> None:
    assert error_for(ProviderErrorCategory.RATE_LIMITED).delay_until_reset(NOW) is None


# --------------------------------------------------------------------------- #
# Attempt ceiling and exhaustion cooldown
# --------------------------------------------------------------------------- #


def test_retry_stops_at_the_configured_maximum() -> None:
    policy = RetryPolicy(max_attempts=3)
    assert decide(ProviderErrorCategory.TRANSIENT_ERROR, attempt=1, policy=policy).should_retry
    assert decide(ProviderErrorCategory.TRANSIENT_ERROR, attempt=2, policy=policy).should_retry
    exhausted = decide(ProviderErrorCategory.TRANSIENT_ERROR, attempt=3, policy=policy)
    assert exhausted.should_retry is False
    assert exhausted.outcome is RetryOutcome.STOP_ATTEMPTS_EXHAUSTED


def test_a_single_attempt_policy_never_retries() -> None:
    decision = decide(
        ProviderErrorCategory.TRANSIENT_ERROR, attempt=1, policy=RetryPolicy(max_attempts=1)
    )
    assert decision.should_retry is False


def test_transient_exhaustion_applies_a_short_cooldown() -> None:
    """So the next hundred investigations do not each pay the retry budget."""
    decision = decide(ProviderErrorCategory.TRANSIENT_ERROR, attempt=3)
    assert decision.cooldown_reason is CooldownReason.TRANSIENT_FAILURES
    assert decision.cooldown_seconds == POLICY.transient_exhaustion_cooldown_seconds


def test_unavailable_exhaustion_records_the_provider_as_unavailable() -> None:
    decision = decide(ProviderErrorCategory.PROVIDER_UNAVAILABLE, attempt=3)
    assert decision.cooldown_reason is CooldownReason.PROVIDER_UNAVAILABLE


# --------------------------------------------------------------------------- #
# Active operations
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("category", list(ProviderErrorCategory))
def test_active_operations_never_retry_automatically(
    category: ProviderErrorCategory,
) -> None:
    """Submitting or detonating something twice is not a safe default."""
    decision = decide(category, activity_mode=ActivityMode.ACTIVE, retry_after_seconds=0.1)
    assert decision.should_retry is False
    assert decision.outcome is RetryOutcome.STOP_ACTIVE_OPERATION


# --------------------------------------------------------------------------- #
# Backoff arithmetic
# --------------------------------------------------------------------------- #


def test_backoff_grows_exponentially() -> None:
    policy = RetryPolicy(base_delay_seconds=0.5, max_delay_seconds=100.0)
    delays = [
        compute_backoff(attempt=attempt, policy=policy, jitter=NoJitter())
        for attempt in (1, 2, 3, 4)
    ]
    assert delays == [0.5, 1.0, 2.0, 4.0]


def test_backoff_is_strictly_increasing_until_the_cap() -> None:
    policy = RetryPolicy(base_delay_seconds=0.25, max_delay_seconds=64.0)
    delays = [
        compute_backoff(attempt=attempt, policy=policy, jitter=NoJitter())
        for attempt in range(1, 8)
    ]
    for earlier, later in itertools.pairwise(delays):
        assert later >= earlier


def test_backoff_respects_the_maximum() -> None:
    policy = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=8.0)
    for attempt in range(1, 10):
        assert compute_backoff(attempt=attempt, policy=policy, jitter=NoJitter()) <= 8.0


def test_jitter_never_pushes_the_delay_past_the_maximum() -> None:
    """The cap is applied after jitter, so it is a real ceiling."""
    policy = RetryPolicy(base_delay_seconds=4.0, max_delay_seconds=8.0, jitter_ratio=1.0)
    for attempt in range(1, 8):
        delay = compute_backoff(attempt=attempt, policy=policy, jitter=FixedJitter(1.0))
        assert delay <= 8.0


def test_jitter_is_bounded_by_the_configured_ratio() -> None:
    policy = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=100.0, jitter_ratio=0.25)
    plain = compute_backoff(attempt=3, policy=policy, jitter=NoJitter())
    jittered = compute_backoff(attempt=3, policy=policy, jitter=FixedJitter(1.0))
    assert jittered == pytest.approx(plain * 1.25)


def test_random_jitter_stays_within_the_ratio_over_many_draws() -> None:
    policy = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=100.0, jitter_ratio=0.5)
    jitter = RandomJitter(random.Random(99))
    plain = compute_backoff(attempt=2, policy=policy, jitter=NoJitter())
    for _ in range(200):
        delay = compute_backoff(attempt=2, policy=policy, jitter=jitter)
        assert plain <= delay <= plain * 1.5


def test_zero_jitter_ratio_makes_backoff_exactly_reproducible() -> None:
    policy = RetryPolicy(jitter_ratio=0.0)
    jitter = RandomJitter(random.Random(5))
    first = compute_backoff(attempt=2, policy=policy, jitter=jitter)
    second = compute_backoff(attempt=2, policy=policy, jitter=jitter)
    assert first == second


def test_backoff_defaults_to_no_jitter_when_none_is_supplied() -> None:
    policy = RetryPolicy(base_delay_seconds=1.0, jitter_ratio=1.0)
    assert compute_backoff(attempt=1, policy=policy) == 1.0


def test_backoff_rejects_a_zero_or_negative_attempt() -> None:
    for attempt in (0, -1):
        with pytest.raises(ValueError, match="1-based"):
            compute_backoff(attempt=attempt, policy=POLICY)


def test_backoff_does_not_overflow_at_a_large_attempt_number() -> None:
    policy = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=8.0)
    assert compute_backoff(attempt=10_000, policy=policy, jitter=NoJitter()) == 8.0


# --------------------------------------------------------------------------- #
# Policy shape
# --------------------------------------------------------------------------- #


def test_default_policy_is_conservative() -> None:
    policy = RetryPolicy()
    assert policy.max_attempts == 3
    assert policy.base_delay_seconds == 0.5
    assert policy.max_delay_seconds == 8.0
    assert policy.retry_unknown_errors is False


def test_policy_is_immutable() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="frozen"):
        RetryPolicy().max_attempts = 9


def test_decision_reports_whether_a_cooldown_applies() -> None:
    assert decide(ProviderErrorCategory.QUOTA_EXCEEDED).applies_cooldown is True
    assert decide(ProviderErrorCategory.TRANSIENT_ERROR).applies_cooldown is False


def test_error_metadata_carries_no_credential_material() -> None:
    from ti_recon.security import SENSITIVE_KEY_PATTERN

    error = provider_error_for(
        ProviderErrorCategory.RATE_LIMITED,
        "fake_provider",
        operation="search",
        retry_after_seconds=30.0,
        provider_error_code="RATE_LIMIT_EXCEEDED",
    )
    assert SENSITIVE_KEY_PATTERN.search(str(error)) is None
    assert error.provider_error_code == "RATE_LIMIT_EXCEEDED"
