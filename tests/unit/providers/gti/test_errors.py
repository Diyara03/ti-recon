"""GTI error mapping onto normalized categories (Task 7)."""

from __future__ import annotations

import asyncio

import aiohttp
import pytest
from vt.error import APIError

from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.providers.errors import ProviderError
from ti_recon.providers.gti.errors import (
    ENTITLEMENT_SENSITIVE_CODE,
    GTI_ERROR_CATEGORIES,
    category_for_gti_code,
    scrub_secret,
    translate_gti_error,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"


def translate(
    error: BaseException, *, entitlement_sensitive: bool = False, **kwargs: object
) -> ProviderError:
    return translate_gti_error(
        error,
        provider_id="gti",
        operation="primary_lookup",
        entitlement_sensitive=entitlement_sensitive,
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# The documented mapping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("AuthenticationRequiredError", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("WrongCredentialsError", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("UserNotActiveError", ProviderErrorCategory.AUTHENTICATION_ERROR),
        ("ForbiddenError", ProviderErrorCategory.PERMISSION_ERROR),
        ("NotFoundError", ProviderErrorCategory.NOT_FOUND),
        ("BadRequestError", ProviderErrorCategory.INVALID_REQUEST),
        ("InvalidArgumentError", ProviderErrorCategory.INVALID_REQUEST),
        ("UnselectiveContentQueryError", ProviderErrorCategory.INVALID_REQUEST),
        ("UnsupportedContentQueryError", ProviderErrorCategory.INVALID_REQUEST),
        ("NotAvailableYet", ProviderErrorCategory.TRANSIENT_ERROR),
        ("QuotaExceededError", ProviderErrorCategory.QUOTA_EXCEEDED),
        ("TooManyRequestsError", ProviderErrorCategory.RATE_LIMITED),
        ("TransientError", ProviderErrorCategory.TRANSIENT_ERROR),
        ("DeadlineExceededError", ProviderErrorCategory.TRANSIENT_ERROR),
        ("FailedDependencyError", ProviderErrorCategory.TRANSIENT_ERROR),
        # vt-py's own shaping of responses it could not read (Task 24 Phase 3):
        # every 5xx, and a 4xx whose body is not JSON.
        ("ServerError", ProviderErrorCategory.TRANSIENT_ERROR),
        ("ClientError", ProviderErrorCategory.PROVIDER_UNAVAILABLE),
    ],
)
def test_documented_codes_map_as_specified(code: str, expected: ProviderErrorCategory) -> None:
    assert category_for_gti_code(code) is expected


@pytest.mark.parametrize("code", ["ServerError", "ClientError"])
def test_a_raw_response_body_never_becomes_the_error_message(code: str) -> None:
    """vt-py puts the whole body -- an HTML error page at best -- in the message."""
    error = translate(APIError(code, "<html><body>502 Bad Gateway sk-live-abcdef</body></html>"))
    assert "html" not in str(error).lower()
    assert "sk-live" not in str(error)
    assert error.category in {
        ProviderErrorCategory.TRANSIENT_ERROR,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    }


def test_an_unreadable_200_body_is_a_schema_error_not_an_outage() -> None:
    """Non-JSON with a 200, or JSON that does not parse, is a shape change:
    not retried as unreachable, not left unknown."""
    import json

    from aiohttp import ContentTypeError, RequestInfo

    info = RequestInfo(url=None, method="GET", headers={}, real_url=None)  # type: ignore[arg-type]
    content = translate(ContentTypeError(info, (), status=200, message="unexpected mimetype"))
    assert content.category is ProviderErrorCategory.SCHEMA_ERROR
    decode = translate(json.JSONDecodeError("Expecting value", "<html>", 0))
    assert decode.category is ProviderErrorCategory.SCHEMA_ERROR


def test_an_unknown_code_is_unknown_not_guessed() -> None:
    assert category_for_gti_code("SomeFutureGoogleError") is ProviderErrorCategory.UNKNOWN_ERROR


def test_every_mapped_category_is_a_real_category() -> None:
    for category in GTI_ERROR_CATEGORIES.values():
        assert category in set(ProviderErrorCategory)


# --------------------------------------------------------------------------- #
# Forbidden: permission vs entitlement
# --------------------------------------------------------------------------- #


def test_forbidden_is_a_permission_problem_by_default() -> None:
    assert (
        category_for_gti_code(ENTITLEMENT_SENSITIVE_CODE) is ProviderErrorCategory.PERMISSION_ERROR
    )


def test_forbidden_on_an_entitlement_gated_operation_is_plan_limited() -> None:
    """An Enterprise-only relationship being unavailable is a plan fact."""
    assert (
        category_for_gti_code(ENTITLEMENT_SENSITIVE_CODE, entitlement_sensitive=True)
        is ProviderErrorCategory.PLAN_LIMITED
    )


def test_entitlement_context_changes_nothing_else() -> None:
    """Only Forbidden is context-dependent."""
    for code in GTI_ERROR_CATEGORIES:
        if code == ENTITLEMENT_SENSITIVE_CODE:
            continue
        assert category_for_gti_code(code) is category_for_gti_code(
            code, entitlement_sensitive=True
        )


def test_neither_forbidden_reading_invalidates_the_credential() -> None:
    """A 403 must never disable a working Enterprise key."""
    for sensitive in (False, True):
        category = category_for_gti_code(
            ENTITLEMENT_SENSITIVE_CODE, entitlement_sensitive=sensitive
        )
        assert category is not ProviderErrorCategory.AUTHENTICATION_ERROR


# --------------------------------------------------------------------------- #
# Translation into typed provider errors
# --------------------------------------------------------------------------- #


def test_an_api_error_becomes_a_typed_provider_error() -> None:
    error = translate(APIError("NotFoundError", "Resource not found"))
    assert isinstance(error, ProviderError)
    assert error.category is ProviderErrorCategory.NOT_FOUND
    assert error.provider_error_code == "NotFoundError"
    assert error.operation == "primary_lookup"


def test_not_found_records_as_no_data_rather_than_a_failure() -> None:
    """ "GTI has never seen this" is a finding, not an error."""
    error = translate(APIError("NotFoundError", "not found"))
    assert error.run_status is ProviderRunStatus.NO_DATA


def test_rate_limited_is_retryable_and_quota_is_not() -> None:
    assert translate(APIError("TooManyRequestsError", "slow down")).is_retryable is True
    assert translate(APIError("QuotaExceededError", "spent")).is_retryable is False


def test_authentication_errors_are_not_retryable() -> None:
    assert translate(APIError("WrongCredentialsError", "bad key")).is_retryable is False


def test_a_timeout_is_transient() -> None:
    assert translate(TimeoutError()).category is ProviderErrorCategory.TRANSIENT_ERROR


def test_an_asyncio_timeout_is_the_same_builtin_on_this_python() -> None:
    """Documents why one isinstance check covers vt-py's and aiohttp's timeouts."""
    assert asyncio.TimeoutError is TimeoutError


def test_a_connection_failure_means_the_provider_is_unreachable() -> None:
    error = translate(aiohttp.ClientConnectionError("refused"))
    assert error.category is ProviderErrorCategory.PROVIDER_UNAVAILABLE
    assert error.is_retryable is True


def test_an_unexpected_exception_is_unknown_and_names_only_its_type() -> None:
    error = translate(RuntimeError("something surprising happened"))
    assert error.category is ProviderErrorCategory.UNKNOWN_ERROR
    assert "RuntimeError" in str(error)
    assert "something surprising happened" not in str(error)


def test_the_provider_code_is_preserved_for_diagnosis() -> None:
    error = translate(APIError("TooManyRequestsError", "slow down"))
    assert error.provider_error_code == "TooManyRequestsError"


# --------------------------------------------------------------------------- #
# Secret safety
# --------------------------------------------------------------------------- #


def test_a_message_containing_the_api_key_is_scrubbed() -> None:
    """The quota endpoint puts the key in a path, so error text is suspect."""
    error = translate(
        APIError(
            "ForbiddenError",
            f"GET /users/{SECRET}/overall_quotas was refused",
        ),
        secret=SECRET,
    )
    assert SECRET not in str(error)


def test_detail_can_be_discarded_entirely() -> None:
    error = translate(
        APIError("ForbiddenError", f"/users/{SECRET}/overall_quotas"),
        secret=SECRET,
        include_detail=False,
    )
    assert SECRET not in str(error)
    assert "overall_quotas" not in str(error)
    assert error.category is ProviderErrorCategory.PERMISSION_ERROR


def test_scrub_removes_the_known_secret_first() -> None:
    assert scrub_secret(f"path /users/{SECRET}/x", SECRET) == "path /users/[REDACTED]/x"


def test_scrub_also_redacts_generic_credential_patterns() -> None:
    cleaned = scrub_secret("failed with apikey=abcdef1234567890", None)
    assert cleaned is not None
    assert "abcdef1234567890" not in cleaned


def test_scrub_withholds_text_that_still_looks_like_a_credential() -> None:
    """Best-effort redaction plus a hard fallback."""
    assert scrub_secret("X-Api-Key aaaabbbbccccdddd rejected", None) is None


def test_scrub_passes_ordinary_text_through() -> None:
    assert scrub_secret("object not found", None) == "object not found"


def test_scrub_of_nothing_is_nothing() -> None:
    assert scrub_secret(None, SECRET) is None
    assert scrub_secret("", SECRET) is None


def test_no_translated_error_text_ever_matches_the_credential_guard() -> None:
    for code in [*GTI_ERROR_CATEGORIES, "SomeFutureGoogleError"]:
        error = translate(APIError(code, f"apikey={SECRET} rejected"), secret=SECRET)
        assert SECRET not in str(error)
        assert SENSITIVE_KEY_PATTERN.search(str(error)) is None
