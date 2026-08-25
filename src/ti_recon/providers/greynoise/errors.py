"""Mapping GreyNoise failures onto TI Recon's normalized categories (Task 9).

This module is the only place in the GreyNoise package that knows what an HTTP
status code means. Everything above it reasons in
:class:`ProviderErrorCategory`, so the execution layer never learns GreyNoise's
conventions — invariant 11.

Three decisions matter more than the table itself.

**401 is never a plan limitation.** A rejected key and an unentitled key are
completely different facts: the first means the analyst must replace their
credential, the second means their subscription does not include the full IP
context and TI Recon should quietly use what it can. Conflating them is the
single easiest way to make this integration wrong — it would either disable a
working Community key or hide a revoked one behind a "limited plan" message. So
401 maps to ``AUTHENTICATION_ERROR`` and nothing downstream is allowed to treat
it as an access-level hint.

**403 alone is not evidence of a plan tier either.** GreyNoise answers 403 for
both "this key may not use this endpoint" and "your plan does not include this
data", so the honest normalization is ``PERMISSION_ERROR`` — this key may not do
this. Only a *subsequent successful Community call* turns that into a statement
about entitlement, and that inference lives in
:mod:`ti_recon.providers.greynoise.access`, not here.

**404 is a finding, not a failure.** "GreyNoise has never observed this address"
is real intelligence — and it is emphatically not "this address is safe". It is
recorded as ``NO_DATA`` so the coverage layer can tell an answered question from
an unanswered one.
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
    "GREYNOISE_STATUS_CATEGORIES",
    "QUOTA_RETRY_AFTER_THRESHOLD_SECONDS",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "parse_retry_after",
    "parse_utc_timestamp",
    "scrub_detail",
    "translate_status_error",
]

#: HTTP status codes mapped onto TI Recon categories.
#:
#: 429 is absent on purpose: see :func:`category_for_status`, which needs the
#: ``Retry-After`` value to tell a short window from a spent allowance.
GREYNOISE_STATUS_CATEGORIES: Final[dict[int, ProviderErrorCategory]] = {
    # --- the credential is wrong, missing or revoked ------------------------
    401: ProviderErrorCategory.AUTHENTICATION_ERROR,
    # --- the credential is fine, this endpoint is not permitted to it --------
    # GreyNoise uses this for both entitlement and permission. Reported as the
    # narrower of the two; the access layer decides whether it means "Community
    # only" by trying Community, never by reading this status.
    403: ProviderErrorCategory.PERMISSION_ERROR,
    # --- the address simply is not in GreyNoise's data ----------------------
    404: ProviderErrorCategory.NOT_FOUND,
    # --- we asked for something malformed -----------------------------------
    400: ProviderErrorCategory.INVALID_REQUEST,
    422: ProviderErrorCategory.INVALID_REQUEST,
    # --- temporary ----------------------------------------------------------
    408: ProviderErrorCategory.TRANSIENT_ERROR,
    500: ProviderErrorCategory.TRANSIENT_ERROR,
    502: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    503: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    504: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: A ``Retry-After`` longer than this turns a 429 into an exhausted allowance
#: rather than a throttled window.
#:
#: GreyNoise does not send a scope header saying *which* limit was hit, so the
#: length of the wait is the only signal available. An hour is well past any
#: burst window and well short of a daily reset, so a longer wait is reported as
#: ``QUOTA_EXCEEDED`` — something for the execution layer to record and route
#: around, not a pause worth scheduling. With no ``Retry-After`` at all the
#: benign reading wins and the failure stays retryable.
QUOTA_RETRY_AFTER_THRESHOLD_SECONDS: Final[float] = 60.0 * 60.0

#: Length bound for any provider-supplied detail we keep.
_MAX_DETAIL_LENGTH: Final[int] = 200

#: Longest whitespace-delimited token a kept message may contain.
#:
#: The generic redactor only removes values it can *name*. A long opaque token
#: in an error string is never worth its diagnostic value, so its presence drops
#: the whole message. Ordinary prose has no such token, so real messages survive.
_MAX_TOKEN_LENGTH: Final[int] = 24

#: Above this, a ``Retry-After`` is a metering window rather than a pause worth
#: honouring inline; the value is still recorded on the error.
_MAX_SANE_RETRY_AFTER_SECONDS: Final[float] = 24 * 60 * 60


def scrub_detail(text: str | None) -> str | None:
    """Redact and bound a provider-supplied message, or drop it entirely.

    GreyNoise error bodies quote the address that was looked up and, for a
    rejected key, sometimes the key itself. A diagnostic string is never worth
    the risk of carrying one, so anything still credential-shaped after
    redaction is discarded.
    """
    if not text:
        return None
    cleaned = redact_sensitive_text(text.strip(), max_length=_MAX_DETAIL_LENGTH)
    if not cleaned or SENSITIVE_KEY_PATTERN.search(cleaned):
        return None
    if any(len(token) > _MAX_TOKEN_LENGTH for token in cleaned.split()):
        return None
    return cleaned


def category_for_status(
    status_code: int, *, retry_after_seconds: float | None = None
) -> ProviderErrorCategory:
    """Map an HTTP status onto a normalized category.

    ``retry_after_seconds`` only affects 429 — see
    :data:`QUOTA_RETRY_AFTER_THRESHOLD_SECONDS`.
    """
    if status_code == 429:
        if (
            retry_after_seconds is not None
            and retry_after_seconds > QUOTA_RETRY_AFTER_THRESHOLD_SECONDS
        ):
            return ProviderErrorCategory.QUOTA_EXCEEDED
        return ProviderErrorCategory.RATE_LIMITED
    mapped = GREYNOISE_STATUS_CATEGORIES.get(status_code)
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
    """Read a GreyNoise timestamp as a timezone-aware instant.

    GreyNoise mixes plain dates (``2026-01-31``) with full instants
    (``2026-01-31T04:05:06Z``); both are accepted. A naive value is read as UTC
    rather than as local time, because the provider is not reporting our
    timezone.
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
    for field in ("message", "error", "detail"):
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
    """Turn a non-2xx GreyNoise response into a typed, normalized error."""
    retry_after = parse_retry_after(response.headers.get("Retry-After"))
    category = category_for_status(response.status_code, retry_after_seconds=retry_after)
    detail = _detail_from_body(response) if include_detail else None
    return provider_error_for(
        category,
        provider_id,
        message=detail,
        operation=operation,
        retry_after_seconds=retry_after,
        # The status code, not a body. Safe to log and enough to diagnose.
        provider_error_code=str(response.status_code),
    )


# --------------------------------------------------------------------------- #
# What a failure says about the credential itself
# --------------------------------------------------------------------------- #

#: How a failed call reflects on the key that made it.
#:
#: Only a rejected key is ``INVALID``. A permission refusal, a plan limit, an
#: exhausted allowance and a throttled window all mean the key is fine and
#: something else is in the way — marking any of them invalid would disable a
#: perfectly good Community key the moment it touched a paid endpoint.
CREDENTIAL_STATUS_BY_CATEGORY: Final[dict[ProviderErrorCategory, CredentialStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: CredentialStatus.INVALID,
    ProviderErrorCategory.PERMISSION_ERROR: CredentialStatus.ACTIVE,
    ProviderErrorCategory.PLAN_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.QUOTA_EXCEEDED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.RATE_LIMITED: CredentialStatus.ACTIVE,
    # A key that reaches GreyNoise and gets an honest "never seen it" back has
    # proved itself: the lookup was performed.
    ProviderErrorCategory.NOT_FOUND: CredentialStatus.ACTIVE,
}


def credential_status_for(category: ProviderErrorCategory) -> CredentialStatus:
    """What a failure category says about the credential.

    Anything not in the table is ``UNKNOWN``: a transient failure or a schema
    change is evidence about GreyNoise, not about the analyst's key.
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
