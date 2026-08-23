"""Mapping Censys failures onto TI Recon's normalized categories (Task 9).

This module is the only place in the Censys package that knows what an HTTP
status code means. Everything above it reasons in
:class:`ProviderErrorCategory`, so the execution layer never learns Censys's
conventions — invariant 11.

The decision that matters here is the one Censys makes easy to get wrong:
**a rate limit and an empty credit balance are not the same thing.**

Censys meters two independent resources. Requests per minute is a throttle: it
lifts by itself, and retrying is exactly the right response. Credits are a
purchased balance: when they are gone, waiting achieves nothing and every retry
is a wasted request against an account that cannot pay for one. Task 6 already
models these separately — ``RATE_LIMITED`` is retryable and produces a short
cooldown, ``QUOTA_EXCEEDED`` is not — so the whole job here is to route each
status to the right one.

* ``429`` is the throttle. Always ``RATE_LIMITED``, never a credit statement.
* ``402`` is the balance. "Payment required" against a credit-metered API means
  the wallet is empty, so it becomes ``QUOTA_EXCEEDED`` and the execution layer
  stops asking.
* ``403`` is neither: the token is valid and this account may not do this. That
  is a permission fact, and marking it a quota problem would put a working
  credential on a long cooldown over an entitlement it will never gain by
  waiting.

``404`` is a finding rather than a failure. "Censys has never scanned this asset"
is real intelligence about exposure — and it is not evidence that nothing is
exposed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

import httpx

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.adapter import CredentialValidation
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN, redact_sensitive_text

__all__ = [
    "CENSYS_STATUS_CATEGORIES",
    "CREDENTIAL_STATUS_BY_CATEGORY",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "parse_retry_after",
    "parse_utc_timestamp",
    "scrub_detail",
    "translate_status_error",
]

#: HTTP status codes mapped onto TI Recon categories.
CENSYS_STATUS_CATEGORIES: Final[dict[int, ProviderErrorCategory]] = {
    # --- the token is wrong, missing or revoked ------------------------------
    401: ProviderErrorCategory.AUTHENTICATION_ERROR,
    # --- the token is fine, this account may not do this ---------------------
    403: ProviderErrorCategory.PERMISSION_ERROR,
    # --- the account has no credits left ------------------------------------
    402: ProviderErrorCategory.QUOTA_EXCEEDED,
    # --- the asset simply has never been scanned ----------------------------
    404: ProviderErrorCategory.NOT_FOUND,
    410: ProviderErrorCategory.NOT_FOUND,
    # --- we asked for something malformed -----------------------------------
    400: ProviderErrorCategory.INVALID_REQUEST,
    406: ProviderErrorCategory.INVALID_REQUEST,
    422: ProviderErrorCategory.INVALID_REQUEST,
    # --- too many requests per minute; this lifts on its own ----------------
    429: ProviderErrorCategory.RATE_LIMITED,
    # --- temporary ----------------------------------------------------------
    408: ProviderErrorCategory.TRANSIENT_ERROR,
    500: ProviderErrorCategory.TRANSIENT_ERROR,
    502: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    503: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    504: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: Length bound for any provider-supplied detail we keep.
_MAX_DETAIL_LENGTH: Final[int] = 200

#: Longest whitespace-delimited token a kept message may contain. A long opaque
#: token in an error string is never worth its diagnostic value, so its presence
#: drops the whole message; ordinary prose has no such token.
_MAX_TOKEN_LENGTH: Final[int] = 24

#: Above this, a ``Retry-After`` is a metering window rather than a pause worth
#: honouring inline; the value is still recorded on the error.
_MAX_SANE_RETRY_AFTER_SECONDS: Final[float] = 24 * 60 * 60


def scrub_detail(text: str | None) -> str | None:
    """Redact and bound a provider-supplied message, or drop it entirely.

    Censys error bodies quote the asset identity that was requested, which for a
    web property is a hostname somebody is investigating. A diagnostic string is
    never worth carrying credential-shaped text, so anything still suspicious
    after redaction is discarded.
    """
    if not text:
        return None
    cleaned = redact_sensitive_text(text.strip(), max_length=_MAX_DETAIL_LENGTH)
    if not cleaned or SENSITIVE_KEY_PATTERN.search(cleaned):
        return None
    if any(len(token) > _MAX_TOKEN_LENGTH for token in cleaned.split()):
        return None
    return cleaned


def category_for_status(status_code: int) -> ProviderErrorCategory:
    """Map an HTTP status onto a normalized category."""
    mapped = CENSYS_STATUS_CATEGORIES.get(status_code)
    if mapped is not None:
        return mapped
    if 500 <= status_code < 600:
        return ProviderErrorCategory.TRANSIENT_ERROR
    if 400 <= status_code < 500:
        return ProviderErrorCategory.INVALID_REQUEST
    return ProviderErrorCategory.UNKNOWN_ERROR


def parse_retry_after(value: str | None) -> float | None:
    """Read a ``Retry-After`` offset in seconds.

    Only the numeric form is accepted. An absolute instant from a provider can
    be skewed against our clock, and the execution layer already prefers an
    offset when it has one.
    """
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, _MAX_SANE_RETRY_AFTER_SECONDS)


def parse_utc_timestamp(value: str | None) -> datetime | None:
    """Read a Censys ISO-8601 timestamp as a timezone-aware instant.

    A naive value is read as UTC rather than as local time, because the provider
    is not reporting our timezone. Censys sends sub-second precision that
    :func:`datetime.fromisoformat` accepts as-is on Python 3.12.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _detail_from_body(response: httpx.Response) -> str | None:
    """Pull a short message out of an error body without trusting it.

    Only a couple of known scalar fields are read. The body is never echoed
    wholesale, and a body that is not JSON contributes nothing.
    """
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.lower():
        return None
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    for field in ("message", "error", "detail", "description"):
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            return scrub_detail(value)
    return None


def translate_status_error(
    response: httpx.Response,
    *,
    provider_id: str,
    operation: str,
    include_detail: bool = True,
) -> ProviderError:
    """Turn a non-2xx Censys response into a typed, normalized provider error."""
    category = category_for_status(response.status_code)
    detail = _detail_from_body(response) if include_detail else None
    return provider_error_for(
        category,
        provider_id,
        message=detail,
        operation=operation,
        retry_after_seconds=parse_retry_after(response.headers.get("Retry-After")),
        # The status code, not a body. Safe to log and enough to diagnose.
        provider_error_code=str(response.status_code),
    )


# --------------------------------------------------------------------------- #
# What a failure says about the credential itself
# --------------------------------------------------------------------------- #

#: How a failed call reflects on the token that made it.
#:
#: Only a rejected token is ``INVALID``. A permission refusal, an empty credit
#: balance and a throttled minute all mean the token is fine and something else
#: is in the way — marking any of them invalid would disable a working
#: credential over a spent wallet or a busy minute.
CREDENTIAL_STATUS_BY_CATEGORY: Final[dict[ProviderErrorCategory, CredentialStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: CredentialStatus.INVALID,
    ProviderErrorCategory.PERMISSION_ERROR: CredentialStatus.ACTIVE,
    ProviderErrorCategory.PLAN_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.QUOTA_EXCEEDED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.RATE_LIMITED: CredentialStatus.ACTIVE,
    # A token that reaches Censys and gets an honest "no such asset" back has
    # proved itself: the lookup was performed.
    ProviderErrorCategory.NOT_FOUND: CredentialStatus.ACTIVE,
}


def credential_status_for(category: ProviderErrorCategory) -> CredentialStatus:
    """What a failure category says about the credential.

    Anything not in the table is ``UNKNOWN``: a transient failure or a schema
    change is evidence about Censys, not about the analyst's token.
    """
    return CREDENTIAL_STATUS_BY_CATEGORY.get(category, CredentialStatus.UNKNOWN)


def credential_validation_for(
    provider_id: str, error: ProviderError | None = None
) -> CredentialValidation:
    """Record the outcome of a credential check.

    ``error=None`` means the check succeeded. ``detail`` carries only the
    already-redacted message from the error; the credential itself never
    appears, because nothing at this layer has ever seen it.
    """
    if error is None:
        return CredentialValidation(provider_id=provider_id, status=CredentialStatus.ACTIVE)
    return CredentialValidation(
        provider_id=provider_id,
        status=credential_status_for(error.category),
        detail=scrub_detail(str(error)),
    )
