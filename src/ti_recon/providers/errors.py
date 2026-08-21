"""Provider-neutral error taxonomy (Task 5).

Adapters translate their vendor's failure modes into these categories so the
engine can decide what to do without knowing any provider's HTTP conventions.
No provider-specific HTTP mapping is implemented here; that belongs to each
adapter.

Every message must be safe to log. Adapters must not build messages from raw
response bodies or request headers.
"""

from __future__ import annotations

from typing import ClassVar, Final

from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus

__all__ = [
    "PROVIDER_ERROR_RUN_STATUS",
    "RETRYABLE_ERROR_CATEGORIES",
    "ProviderAuthenticationError",
    "ProviderError",
    "ProviderErrorCategory",
    "ProviderInvalidRequestError",
    "ProviderNotFoundError",
    "ProviderPartialResultError",
    "ProviderPermissionError",
    "ProviderPlanLimitedError",
    "ProviderQuotaExceededError",
    "ProviderRateLimitedError",
    "ProviderSchemaError",
    "ProviderTransientError",
    "ProviderUnavailableError",
    "ProviderUnknownError",
    "UnsupportedProviderOperation",
]

#: How each error category is recorded on a :class:`~ti_recon.models.ProviderRun`.
PROVIDER_ERROR_RUN_STATUS: Final[dict[ProviderErrorCategory, ProviderRunStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: ProviderRunStatus.ERROR,
    ProviderErrorCategory.PERMISSION_ERROR: ProviderRunStatus.ERROR,
    ProviderErrorCategory.PLAN_LIMITED: ProviderRunStatus.PLAN_LIMITED,
    ProviderErrorCategory.RATE_LIMITED: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ProviderErrorCategory.QUOTA_EXCEEDED: ProviderRunStatus.QUOTA_EXCEEDED,
    ProviderErrorCategory.NOT_FOUND: ProviderRunStatus.NO_DATA,
    ProviderErrorCategory.INVALID_REQUEST: ProviderRunStatus.ERROR,
    ProviderErrorCategory.PARTIAL_RESULT: ProviderRunStatus.PARTIAL,
    ProviderErrorCategory.TRANSIENT_ERROR: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ProviderErrorCategory.PROVIDER_UNAVAILABLE: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ProviderErrorCategory.SCHEMA_ERROR: ProviderRunStatus.ERROR,
    ProviderErrorCategory.UNKNOWN_ERROR: ProviderRunStatus.ERROR,
}

#: Categories where retrying the same call could plausibly succeed.
#:
#: The retry engine itself is Task 6. This set only records which failures are
#: transient in nature, so nothing has to guess later.
RETRYABLE_ERROR_CATEGORIES: Final[frozenset[ProviderErrorCategory]] = frozenset(
    {
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.TRANSIENT_ERROR,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    }
)


class ProviderError(Exception):
    """Base class for normalized provider failures."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.UNKNOWN_ERROR

    def __init__(
        self,
        provider_id: str,
        *,
        message: str | None = None,
        operation: str | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.operation = operation
        self.retry_after_seconds = retry_after_seconds
        detail = message or self.category.value
        location = f"{provider_id}.{operation}" if operation else provider_id
        super().__init__(f"[{self.category.value}] {location}: {detail}")

    @property
    def run_status(self) -> ProviderRunStatus:
        """The :class:`ProviderRunStatus` this failure should be recorded as."""
        return PROVIDER_ERROR_RUN_STATUS[self.category]

    @property
    def is_retryable(self) -> bool:
        """Whether retrying could plausibly help (Task 6 consumes this)."""
        return self.category in RETRYABLE_ERROR_CATEGORIES


class ProviderAuthenticationError(ProviderError):
    """The credential was rejected."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.AUTHENTICATION_ERROR


class ProviderPermissionError(ProviderError):
    """The credential is valid but not permitted to perform this operation."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.PERMISSION_ERROR


class ProviderPlanLimitedError(ProviderError):
    """The account's plan does not include this data or endpoint."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.PLAN_LIMITED


class ProviderRateLimitedError(ProviderError):
    """Too many requests in the current window."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.RATE_LIMITED


class ProviderQuotaExceededError(ProviderError):
    """The account's quota for the period is exhausted."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.QUOTA_EXCEEDED


class ProviderNotFoundError(ProviderError):
    """The provider has no record of the requested object.

    Recorded as ``NO_DATA`` rather than an error: "the provider has never seen
    this" is a finding, not a failure.
    """

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.NOT_FOUND


class ProviderInvalidRequestError(ProviderError):
    """The request was malformed or unsupported for this object type."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.INVALID_REQUEST


class ProviderPartialResultError(ProviderError):
    """Only part of the expected data could be retrieved."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.PARTIAL_RESULT


class ProviderTransientError(ProviderError):
    """A temporary failure — a timeout, a reset connection, a 5xx."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.TRANSIENT_ERROR


class ProviderUnavailableError(ProviderError):
    """The provider is down or unreachable."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.PROVIDER_UNAVAILABLE


class ProviderSchemaError(ProviderError):
    """The provider returned something the adapter cannot parse.

    Distinct from a transient error on purpose: a schema change needs a code
    fix, and retrying will never help.
    """

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.SCHEMA_ERROR


class ProviderUnknownError(ProviderError):
    """An unclassified failure."""

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.UNKNOWN_ERROR


class UnsupportedProviderOperation(ProviderError):
    """This adapter does not implement the requested operation.

    A typed error rather than ``NotImplementedError``: an optional operation
    that a provider genuinely does not offer is a normal, expected outcome the
    engine must handle, not a programming mistake.
    """

    category: ClassVar[ProviderErrorCategory] = ProviderErrorCategory.INVALID_REQUEST

    def __init__(
        self,
        provider_id: str,
        *,
        operation: str,
        message: str | None = None,
    ) -> None:
        super().__init__(
            provider_id,
            message=message or f"operation {operation!r} is not supported",
            operation=operation,
        )

    @property
    def run_status(self) -> ProviderRunStatus:
        return ProviderRunStatus.NOT_SUPPORTED

    @property
    def is_retryable(self) -> bool:
        return False
