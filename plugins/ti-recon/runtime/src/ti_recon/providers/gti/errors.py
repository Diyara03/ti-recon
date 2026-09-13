"""Mapping GTI/VirusTotal errors onto TI Recon's normalized categories (Task 7).

vt-py surfaces API failures as :class:`vt.APIError` with a string ``code`` such
as ``NotFoundError`` or ``QuotaExceededError``. This module is the only place
that knows those strings; everything above it reasons in
:class:`ProviderErrorCategory`, so the execution layer never learns a provider's
HTTP or SDK conventions.

Two decisions in here matter more than the table itself.

**Forbidden is not automatically an invalid credential.** GTI returns
``ForbiddenError`` both for "your key may not do this" and for "your plan does
not include this". Treating the second as an authentication failure would
disable a perfectly good Enterprise key because one Enterprise-only
relationship was unavailable. So a Forbidden on an operation known to be
entitlement-specific becomes ``PLAN_LIMITED``, and everything else becomes
``PERMISSION_ERROR`` — neither of which marks the credential invalid.

**Provider messages are redacted before they travel.** The quota endpoint
carries the API key in its path, so any error text derived from a request URL is
a potential leak. Messages are redacted and, if they still resemble credential
material, dropped entirely.
"""

from __future__ import annotations

from typing import Final

import aiohttp
from vt.error import APIError

from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN, redact_sensitive_text

__all__ = [
    "ENTITLEMENT_SENSITIVE_CODE",
    "GTI_ERROR_CATEGORIES",
    "category_for_gti_code",
    "scrub_secret",
    "translate_gti_error",
]

#: vt-py / GTI API error codes mapped onto TI Recon categories.
#:
#: Only ``ForbiddenError`` is context-dependent; see
#: :data:`ENTITLEMENT_SENSITIVE_CODE`.
GTI_ERROR_CATEGORIES: Final[dict[str, ProviderErrorCategory]] = {
    # --- credential is wrong or unusable -------------------------------------
    "AuthenticationRequiredError": ProviderErrorCategory.AUTHENTICATION_ERROR,
    "WrongCredentialsError": ProviderErrorCategory.AUTHENTICATION_ERROR,
    "UserNotActiveError": ProviderErrorCategory.AUTHENTICATION_ERROR,
    # --- credential is fine, this action is not permitted --------------------
    "ForbiddenError": ProviderErrorCategory.PERMISSION_ERROR,
    # --- the object simply is not there -------------------------------------
    "NotFoundError": ProviderErrorCategory.NOT_FOUND,
    # --- we asked for something malformed or unsupported --------------------
    "BadRequestError": ProviderErrorCategory.INVALID_REQUEST,
    "InvalidArgumentError": ProviderErrorCategory.INVALID_REQUEST,
    "UnselectiveContentQueryError": ProviderErrorCategory.INVALID_REQUEST,
    "UnsupportedContentQueryError": ProviderErrorCategory.INVALID_REQUEST,
    # --- limits -------------------------------------------------------------
    "QuotaExceededError": ProviderErrorCategory.QUOTA_EXCEEDED,
    "TooManyRequestsError": ProviderErrorCategory.RATE_LIMITED,
    # --- temporary ----------------------------------------------------------
    "NotAvailableYet": ProviderErrorCategory.TRANSIENT_ERROR,
    "TransientError": ProviderErrorCategory.TRANSIENT_ERROR,
    "DeadlineExceededError": ProviderErrorCategory.TRANSIENT_ERROR,
    "FailedDependencyError": ProviderErrorCategory.TRANSIENT_ERROR,
    # --- vt-py's own shaping of a response it could not read -----------------
    # vt-py returns ``APIError("ServerError", <body text>)`` for every status
    # of 500 and above, and ``APIError("ClientError", <body text>)`` for a 4xx
    # whose body is not JSON -- an edge proxy's HTML page, say. Neither is a
    # GTI error code, and before Task 24 Phase 3 both fell to UNKNOWN_ERROR:
    # an outage was never retried, never put the provider on cooldown, and
    # the raw body travelled into the error message. A 5xx is transient; a
    # non-JSON 4xx says nothing this layer can act on beyond "not now".
    "ServerError": ProviderErrorCategory.TRANSIENT_ERROR,
    "ClientError": ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: Codes whose ``message`` is a raw response body rather than a GTI sentence.
#: The body is never kept: it is an HTML page or a proxy's text at best, and
#: the generic redactor cannot vouch for it.
_BODY_TEXT_CODES: Final[frozenset[str]] = frozenset({"ServerError", "ClientError"})

#: The one code whose meaning depends on what was being attempted.
ENTITLEMENT_SENSITIVE_CODE: Final[str] = "ForbiddenError"

#: Length bound for any provider-supplied detail we keep.
_MAX_DETAIL_LENGTH: Final[int] = 200


def category_for_gti_code(
    code: str, *, entitlement_sensitive: bool = False
) -> ProviderErrorCategory:
    """Map a GTI error code onto a normalized category.

    ``entitlement_sensitive`` should be ``True`` when the failing operation is
    one an Enterprise/GTI entitlement gates. It only affects ``ForbiddenError``,
    which then reads as "your plan does not include this" rather than "you may
    not do this".
    """
    if code == ENTITLEMENT_SENSITIVE_CODE and entitlement_sensitive:
        return ProviderErrorCategory.PLAN_LIMITED
    return GTI_ERROR_CATEGORIES.get(code, ProviderErrorCategory.UNKNOWN_ERROR)


def scrub_secret(text: str | None, secret: str | None) -> str | None:
    """Remove a known secret literal from text, then redact generically.

    Belt and braces. The generic redactor catches credential-shaped patterns;
    this catches the specific key we happen to be holding, which is the case
    that actually matters for the quota endpoint's path.
    """
    if not text:
        return None
    cleaned = text
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = redact_sensitive_text(cleaned, max_length=_MAX_DETAIL_LENGTH)
    if not cleaned or SENSITIVE_KEY_PATTERN.search(cleaned):
        # Still credential-shaped after redaction: a diagnostic string is never
        # worth the risk, so it is dropped rather than recorded.
        return None
    return cleaned


def translate_gti_error(
    error: BaseException,
    *,
    provider_id: str,
    operation: str,
    entitlement_sensitive: bool = False,
    secret: str | None = None,
    include_detail: bool = True,
) -> ProviderError:
    """Turn any GTI client failure into a typed, normalized provider error.

    ``include_detail=False`` discards the provider's own message entirely. Used
    for the quota operation, whose request path contains the API key and whose
    error text therefore cannot be trusted at all.
    """
    code: str | None = None
    detail: str | None = None

    if isinstance(error, APIError):
        code = str(error.code)
        if code in _BODY_TEXT_CODES:
            detail = "provider returned an unreadable error response"
        else:
            detail = scrub_secret(str(error.message), secret) if include_detail else None
        category = category_for_gti_code(code, entitlement_sensitive=entitlement_sensitive)
    elif isinstance(error, TimeoutError):
        # On 3.11+ asyncio.TimeoutError is an alias of the builtin, so this one
        # check covers both vt-py's and aiohttp's timeout paths.
        category = ProviderErrorCategory.TRANSIENT_ERROR
        detail = "request timed out"
    elif isinstance(error, aiohttp.ContentTypeError | ValueError):
        # A 200 whose body is not the JSON the client asked for (aiohttp
        # refuses to decode it) or JSON that does not parse: a response shape
        # this integration cannot read, not an unreachable provider. Checked
        # before the generic aiohttp branch, because ContentTypeError is a
        # ClientError and would otherwise read as "unreachable" and be retried.
        category = ProviderErrorCategory.SCHEMA_ERROR
        detail = "provider response could not be read"
    elif isinstance(error, aiohttp.ClientError):
        # Connection refused, DNS failure, TLS problem: the provider is not
        # reachable rather than misbehaving.
        category = ProviderErrorCategory.PROVIDER_UNAVAILABLE
        detail = "provider unreachable"
    else:
        category = ProviderErrorCategory.UNKNOWN_ERROR
        detail = type(error).__name__

    return provider_error_for(
        category,
        provider_id,
        message=detail,
        operation=operation,
        provider_error_code=code,
    )
