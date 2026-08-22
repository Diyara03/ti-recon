"""Mapping urlscan.io failures onto TI Recon's normalized categories (Task 8).

This module is the only place in the urlscan package that knows what an HTTP
status code means. Everything above it reasons in
:class:`ProviderErrorCategory`, so the execution layer never learns urlscan's
conventions — invariant 11.

Three decisions matter more than the table itself.

**429 is a rate limit, not an exhausted quota.** urlscan meters per-minute,
per-hour and per-day windows and answers 429 for all of them. A minute window
reopens on its own and is worth retrying; a day window is not. The distinction
is recoverable from the ``X-Rate-Limit-*`` headers that accompany the response,
so the reset instant is read from them and a same-day exhaustion is reported as
``QUOTA_EXCEEDED`` rather than as something the retry engine should sit and wait
for.

**404 is a finding, not a failure.** "urlscan has never scanned this" is real
intelligence about an observable and is recorded as ``NO_DATA``.

**Provider text is never trusted verbatim.** urlscan echoes the submitted URL in
some error messages, and a submitted URL can carry a token in its query string.
Every detail we keep is redacted and length-bounded, and anything still
credential-shaped afterwards is dropped rather than recorded.
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
    "CREDENTIAL_STATUS_BY_CATEGORY",
    "RATE_LIMIT_SCOPE_HEADER",
    "URLSCAN_STATUS_CATEGORIES",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "parse_reset_at",
    "parse_retry_after",
    "scrub_detail",
    "translate_status_error",
]

#: HTTP status codes mapped onto TI Recon categories.
#:
#: 429 is absent on purpose: see :func:`category_for_status`, which needs the
#: response headers to tell a transient window from an exhausted daily quota.
URLSCAN_STATUS_CATEGORIES: Final[dict[int, ProviderErrorCategory]] = {
    # --- the credential is wrong or missing ---------------------------------
    401: ProviderErrorCategory.AUTHENTICATION_ERROR,
    # --- the credential is fine, this action is not permitted ---------------
    # Also what a private or team-restricted scan returns to a key that may not
    # see it, which is a permission fact rather than a bad key.
    403: ProviderErrorCategory.PERMISSION_ERROR,
    # --- the object simply is not there -------------------------------------
    404: ProviderErrorCategory.NOT_FOUND,
    410: ProviderErrorCategory.NOT_FOUND,
    # --- we asked for something malformed or unsupported --------------------
    400: ProviderErrorCategory.INVALID_REQUEST,
    422: ProviderErrorCategory.INVALID_REQUEST,
    431: ProviderErrorCategory.INVALID_REQUEST,
    # --- temporary ----------------------------------------------------------
    408: ProviderErrorCategory.TRANSIENT_ERROR,
    500: ProviderErrorCategory.TRANSIENT_ERROR,
    502: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    503: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    504: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: Which metering window a 429 came from: ``minute``, ``hour``, ``day``.
RATE_LIMIT_SCOPE_HEADER: Final[str] = "X-Rate-Limit-Scope"

#: Windows long enough that waiting for them is not a retry decision. A day-long
#: exhaustion is a quota fact the execution layer should record and route
#: around, not a pause it should schedule.
_QUOTA_SCOPES: Final[frozenset[str]] = frozenset({"day", "daily", "month", "monthly"})

#: Length bound for any provider-supplied detail we keep.
_MAX_DETAIL_LENGTH: Final[int] = 200

#: Longest whitespace-delimited token a kept message may contain.
#:
#: The generic redactor only removes values it can *name* — ``api_key=...``,
#: ``Bearer ...``. urlscan's messages quote things it cannot name: a submitted
#: URL with a token in its query, or a bare key in "key <value> may not read
#: this". A long opaque token in an error string is never worth its diagnostic
#: value, so its presence drops the whole message. Ordinary prose has no such
#: token, so real messages survive.
_MAX_TOKEN_LENGTH: Final[int] = 24

#: Above this, a Retry-After is almost certainly a metering window rather than a
#: pause worth honouring inline; the value is still recorded on the error.
_MAX_SANE_RETRY_AFTER_SECONDS: Final[float] = 24 * 60 * 60


def scrub_detail(text: str | None) -> str | None:
    """Redact and bound a provider-supplied message, or drop it entirely.

    urlscan error bodies can quote the URL that was looked up, and a URL can
    carry a token. A diagnostic string is never worth the risk of carrying one,
    so anything still credential-shaped after redaction is discarded.
    """
    if not text:
        return None
    cleaned = redact_sensitive_text(text.strip(), max_length=_MAX_DETAIL_LENGTH)
    if not cleaned or SENSITIVE_KEY_PATTERN.search(cleaned):
        return None
    if _contains_opaque_token(cleaned):
        return None
    return cleaned


def _contains_opaque_token(text: str) -> bool:
    """Whether any word is long enough to be credential material or a URL."""
    return any(len(token) > _MAX_TOKEN_LENGTH for token in text.split())


def category_for_status(
    status_code: int, *, rate_limit_scope: str | None = None
) -> ProviderErrorCategory:
    """Map an HTTP status onto a normalized category.

    ``rate_limit_scope`` is urlscan's ``X-Rate-Limit-Scope`` header and only
    affects 429: a per-day or per-month window that has run out is an exhausted
    quota, while a per-minute or per-hour one is a rate limit that will lift by
    itself.
    """
    if status_code == 429:
        scope = (rate_limit_scope or "").strip().lower()
        if scope in _QUOTA_SCOPES:
            return ProviderErrorCategory.QUOTA_EXCEEDED
        return ProviderErrorCategory.RATE_LIMITED
    mapped = URLSCAN_STATUS_CATEGORIES.get(status_code)
    if mapped is not None:
        return mapped
    if 500 <= status_code < 600:
        return ProviderErrorCategory.TRANSIENT_ERROR
    if 400 <= status_code < 500:
        return ProviderErrorCategory.INVALID_REQUEST
    return ProviderErrorCategory.UNKNOWN_ERROR


def parse_retry_after(value: str | None) -> float | None:
    """Read a ``Retry-After`` offset in seconds.

    Only the numeric form is accepted. The HTTP-date form is left to
    :func:`parse_reset_at`'s caller: an absolute instant from the provider can
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


def parse_reset_at(value: str | None) -> datetime | None:
    """Read urlscan's ``X-Rate-Limit-Reset`` as a timezone-aware instant.

    urlscan sends an ISO-8601 timestamp. A naive value is read as UTC rather
    than as local time, because the provider is not reporting our timezone.
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
    for field in ("message", "description", "error"):
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
    """Turn a non-2xx urlscan response into a typed, normalized provider error.

    ``include_detail=False`` discards the provider's own message entirely, for
    operations whose error text is not worth inspecting at all.
    """
    scope = response.headers.get(RATE_LIMIT_SCOPE_HEADER)
    category = category_for_status(response.status_code, rate_limit_scope=scope)
    detail = _detail_from_body(response) if include_detail else None
    return provider_error_for(
        category,
        provider_id,
        message=detail,
        operation=operation,
        retry_after_seconds=parse_retry_after(response.headers.get("Retry-After")),
        reset_at=parse_reset_at(response.headers.get("X-Rate-Limit-Reset")),
        # The status code, not a body. Safe to log and enough to diagnose.
        provider_error_code=str(response.status_code),
    )


# --------------------------------------------------------------------------- #
# What a failure says about the credential itself
# --------------------------------------------------------------------------- #

#: How a failed call reflects on the key that made it.
#:
#: Only a rejected key is ``INVALID``. A permission refusal, an exhausted
#: allowance or a throttled window all mean the key is fine and something else
#: is in the way — marking any of them invalid would disable a working
#: credential over a private scan or a busy minute.
CREDENTIAL_STATUS_BY_CATEGORY: Final[dict[ProviderErrorCategory, CredentialStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: CredentialStatus.INVALID,
    ProviderErrorCategory.PERMISSION_ERROR: CredentialStatus.ACTIVE,
    ProviderErrorCategory.PLAN_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.QUOTA_EXCEEDED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.RATE_LIMITED: CredentialStatus.ACTIVE,
}


def credential_status_for(category: ProviderErrorCategory) -> CredentialStatus:
    """What a failure category says about the credential.

    Anything not in the table is ``UNKNOWN``: a transient failure or a schema
    change is evidence about urlscan, not about the analyst's key.
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
