"""Retry and backoff policy (Task 6).

Retry decisions are made from **normalized error categories**, never from HTTP
status codes. Interpreting a provider's HTTP conventions is the adapter's job
(``ProviderAdapter.classify_error``); by the time an error reaches here it is
already a category, so this module contains no provider-specific knowledge and
needs none.

The matrix is deliberately narrow. Retrying the wrong failure is not merely
useless — retrying an authentication error burns quota and can trip a
provider's abuse protection, and retrying a quota exhaustion turns one refusal
into a tight loop of refusals.

Implemented with the standard library. No retry dependency is added: the whole
decision is a pure function over a category, an attempt number and a policy,
and a third-party framework would add surface without removing any of the
domain logic that actually matters here.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import Field

from ti_recon.enums import ActivityMode, ProviderErrorCategory
from ti_recon.execution.clock import JitterSource, NoJitter
from ti_recon.execution.models import CooldownReason
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.errors import ProviderError

__all__ = [
    "AUTOMATICALLY_RETRYABLE_CATEGORIES",
    "CONDITIONALLY_RETRYABLE_CATEGORIES",
    "NEVER_RETRYABLE_CATEGORIES",
    "RetryDecision",
    "RetryOutcome",
    "RetryPolicy",
    "compute_backoff",
    "decide_retry",
]

#: Failures where the same call may simply work next time.
AUTOMATICALLY_RETRYABLE_CATEGORIES: Final[frozenset[ProviderErrorCategory]] = frozenset(
    {
        ProviderErrorCategory.TRANSIENT_ERROR,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    }
)

#: Retryable only if the provider told us when the limit lifts and that moment
#: is close enough to wait for.
CONDITIONALLY_RETRYABLE_CATEGORIES: Final[frozenset[ProviderErrorCategory]] = frozenset(
    {ProviderErrorCategory.RATE_LIMITED}
)

#: Everything else. Retrying these cannot help and can do harm.
#:
#: Derived by subtraction so the three sets always partition the category
#: vocabulary: a new category is "never retryable" until somebody deliberately
#: classifies it, rather than silently falling through an ``if`` chain.
NEVER_RETRYABLE_CATEGORIES: Final[frozenset[ProviderErrorCategory]] = frozenset(
    set(ProviderErrorCategory)
    - AUTOMATICALLY_RETRYABLE_CATEGORIES
    - CONDITIONALLY_RETRYABLE_CATEGORIES
)


class RetryOutcome(StrEnum):
    """Why the retry controller decided as it did.

    Recorded on the decision so an operator can tell "we gave up because the
    provider is down" from "we gave up because the key is wrong" without
    re-deriving it from the category.
    """

    RETRY_BACKOFF = "retry_backoff"
    RETRY_AFTER_RATE_LIMIT = "retry_after_rate_limit"
    STOP_ATTEMPTS_EXHAUSTED = "stop_attempts_exhausted"
    STOP_NOT_RETRYABLE = "stop_not_retryable"
    STOP_ACTIVE_OPERATION = "stop_active_operation"
    STOP_RATE_LIMIT_TOO_LONG = "stop_rate_limit_too_long"
    STOP_RATE_LIMIT_UNKNOWN = "stop_rate_limit_unknown"
    STOP_QUOTA_EXHAUSTED = "stop_quota_exhausted"


class RetryPolicy(FrozenTiReconModel):
    """How hard to try, and how long to wait.

    Every number here is a configuration default, not a statement about any
    provider's documented limits. Real per-provider values arrive with each real
    integration.
    """

    max_attempts: int = Field(default=3, ge=1, le=10)
    base_delay_seconds: float = Field(default=0.5, gt=0.0, le=60.0)
    max_delay_seconds: float = Field(default=8.0, gt=0.0, le=300.0)
    jitter_ratio: float = Field(default=0.25, ge=0.0, le=1.0)

    #: The longest a rate limit may be waited out inside a live investigation.
    #: Beyond this, the provider goes on cooldown and the investigation reports
    #: reduced coverage instead — nobody should watch a spinner because a quota
    #: window resets in forty minutes.
    max_inline_wait_seconds: float = Field(default=5.0, ge=0.0, le=120.0)

    #: ``UNKNOWN_ERROR`` means the adapter could not classify the failure.
    #: Defaults to no retry: an unclassified failure is as likely to be a bad
    #: request as a blip, and retrying a bad request is pure cost.
    retry_unknown_errors: bool = False

    #: Cooldown applied when a provider says "rate limited" without saying for
    #: how long. Without a hint there is nothing to wait for intelligently, and
    #: hammering the endpoint to find out is the wrong answer.
    unknown_rate_limit_cooldown_seconds: float = Field(default=60.0, ge=0.0, le=86_400.0)

    #: Cooldown applied on quota exhaustion when the provider gave no reset time.
    quota_cooldown_seconds: float = Field(default=900.0, ge=0.0, le=86_400.0)

    #: Cooldown applied after retries are exhausted against a provider that
    #: looks down, so the next hundred investigations do not each pay the full
    #: retry budget to rediscover it.
    transient_exhaustion_cooldown_seconds: float = Field(default=30.0, ge=0.0, le=86_400.0)


class RetryDecision(FrozenTiReconModel):
    """What to do after one failed provider attempt."""

    should_retry: bool
    delay_seconds: float = Field(default=0.0, ge=0.0)
    outcome: RetryOutcome
    cooldown_reason: CooldownReason | None = None
    cooldown_seconds: float | None = Field(default=None, ge=0.0)

    @property
    def applies_cooldown(self) -> bool:
        return self.cooldown_reason is not None


def compute_backoff(
    *,
    attempt: int,
    policy: RetryPolicy,
    jitter: JitterSource | None = None,
) -> float:
    """Exponential backoff with bounded jitter for a 1-based attempt number.

    Doubling spreads load off a struggling provider; jitter stops a fleet of
    workers that failed together from retrying in lockstep and re-creating the
    same spike. The cap is applied *after* jitter, so the configured maximum is
    a real ceiling rather than one jitter can exceed.
    """
    if attempt < 1:
        msg = "attempt numbers are 1-based"
        raise ValueError(msg)
    source = jitter or NoJitter()
    # Cap the exponent before it is used, so a large max_attempts cannot
    # produce an enormous intermediate float.
    exponent = min(attempt - 1, 32)
    delay = min(policy.base_delay_seconds * (2.0**exponent), policy.max_delay_seconds)
    padded = delay + source.jitter(delay * policy.jitter_ratio)
    return min(padded, policy.max_delay_seconds)


def decide_retry(
    *,
    error: ProviderError,
    attempt: int,
    policy: RetryPolicy,
    activity_mode: ActivityMode,
    now: datetime,
    jitter: JitterSource | None = None,
) -> RetryDecision:
    """Decide whether to retry after ``attempt`` failed with ``error``.

    ``attempt`` is 1-based and counts attempts already made.
    """
    category = error.category

    # Active operations submit, rescan or detonate something. Retrying one
    # without a provider-specific idempotency guarantee risks doing it twice.
    if activity_mode is ActivityMode.ACTIVE:
        return RetryDecision(should_retry=False, outcome=RetryOutcome.STOP_ACTIVE_OPERATION)

    if category is ProviderErrorCategory.QUOTA_EXCEEDED:
        return RetryDecision(
            should_retry=False,
            outcome=RetryOutcome.STOP_QUOTA_EXHAUSTED,
            cooldown_reason=CooldownReason.QUOTA_EXHAUSTED,
            cooldown_seconds=error.delay_until_reset(now) or policy.quota_cooldown_seconds,
        )

    if category is ProviderErrorCategory.RATE_LIMITED:
        return _decide_rate_limited(
            error=error, attempt=attempt, policy=policy, now=now, jitter=jitter
        )

    retryable = category in AUTOMATICALLY_RETRYABLE_CATEGORIES or (
        category is ProviderErrorCategory.UNKNOWN_ERROR and policy.retry_unknown_errors
    )
    if not retryable:
        return RetryDecision(should_retry=False, outcome=RetryOutcome.STOP_NOT_RETRYABLE)

    if attempt >= policy.max_attempts:
        return RetryDecision(
            should_retry=False,
            outcome=RetryOutcome.STOP_ATTEMPTS_EXHAUSTED,
            cooldown_reason=_exhaustion_reason(category),
            cooldown_seconds=policy.transient_exhaustion_cooldown_seconds,
        )

    return RetryDecision(
        should_retry=True,
        delay_seconds=compute_backoff(attempt=attempt, policy=policy, jitter=jitter),
        outcome=RetryOutcome.RETRY_BACKOFF,
    )


def _decide_rate_limited(
    *,
    error: ProviderError,
    attempt: int,
    policy: RetryPolicy,
    now: datetime,
    jitter: JitterSource | None,
) -> RetryDecision:
    delay = error.delay_until_reset(now)

    if delay is None:
        return RetryDecision(
            should_retry=False,
            outcome=RetryOutcome.STOP_RATE_LIMIT_UNKNOWN,
            cooldown_reason=CooldownReason.RATE_LIMIT,
            cooldown_seconds=policy.unknown_rate_limit_cooldown_seconds,
        )

    if delay > policy.max_inline_wait_seconds:
        return RetryDecision(
            should_retry=False,
            outcome=RetryOutcome.STOP_RATE_LIMIT_TOO_LONG,
            cooldown_reason=CooldownReason.RATE_LIMIT,
            cooldown_seconds=delay,
        )

    if attempt >= policy.max_attempts:
        return RetryDecision(
            should_retry=False,
            outcome=RetryOutcome.STOP_ATTEMPTS_EXHAUSTED,
            cooldown_reason=CooldownReason.RATE_LIMIT,
            cooldown_seconds=delay,
        )

    # Wait exactly as long as the provider asked, plus jitter, so a fleet of
    # workers released by the same reset does not stampede the endpoint.
    padded = delay + (jitter or NoJitter()).jitter(delay * policy.jitter_ratio)
    return RetryDecision(
        should_retry=True,
        delay_seconds=min(padded, policy.max_inline_wait_seconds),
        outcome=RetryOutcome.RETRY_AFTER_RATE_LIMIT,
    )


def _exhaustion_reason(category: ProviderErrorCategory) -> CooldownReason:
    if category is ProviderErrorCategory.PROVIDER_UNAVAILABLE:
        return CooldownReason.PROVIDER_UNAVAILABLE
    return CooldownReason.TRANSIENT_FAILURES
