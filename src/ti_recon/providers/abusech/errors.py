"""Mapping abuse.ch failures onto TI Recon's normalized categories (Task 10).

This module is the only place in the abuse.ch packages that knows what an HTTP
status or a provider status token means. Everything above it reasons in
:class:`ProviderErrorCategory`, so the execution layer never learns abuse.ch's
conventions — invariant 11.

The decision that shapes this file: **a failure usually arrives inside a 200.**

All three APIs answer almost everything with HTTP 200 and put the real outcome in
a ``query_status`` field. A missing key, an unparseable hash, an unknown sample
and a successful lookup are all ``200 OK`` on the wire. An integration that
checked only the HTTP status would report every one of those as a success and
then normalize an empty document into "nothing found" — which is how a rejected
credential turns into "this file is not known malware".

So both layers are normalized, and the body's verdict wins: the HTTP status is
checked first because a 429 or a 503 never carries a usable body, and the query
status is checked second because on 200 it is the only thing that actually says
what happened.

What is not retried
-------------------

A rejected key, a malformed request and an honest "not found" are all final: the
same call will produce the same answer forever, and retrying it spends an
allowance abuse.ch meters for fair use. Only genuinely transient failures and
throttling are retryable, and Task 6 owns that decision from the category alone.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.adapter import CredentialValidation
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN, redact_sensitive_text

__all__ = [
    "ABUSE_CH_STATUS_CATEGORIES",
    "NO_DATA_QUERY_STATUSES",
    "QUERY_STATUS_CATEGORIES",
    "SUCCESS_QUERY_STATUSES",
    "category_for_query_status",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "parse_retry_after",
    "parse_utc_timestamp",
    "query_status_of",
    "scrub_detail",
    "translate_query_status",
    "translate_status_error",
]

#: HTTP status codes mapped onto TI Recon categories.
#:
#: Short, because abuse.ch rarely uses HTTP to say anything but "the request
#: arrived". The interesting outcomes are in the body — see
#: :func:`category_for_query_status`.
ABUSE_CH_STATUS_CATEGORIES: Final[dict[int, ProviderErrorCategory]] = {
    401: ProviderErrorCategory.AUTHENTICATION_ERROR,
    403: ProviderErrorCategory.PERMISSION_ERROR,
    404: ProviderErrorCategory.NOT_FOUND,
    405: ProviderErrorCategory.INVALID_REQUEST,
    400: ProviderErrorCategory.INVALID_REQUEST,
    413: ProviderErrorCategory.INVALID_REQUEST,
    422: ProviderErrorCategory.INVALID_REQUEST,
    429: ProviderErrorCategory.RATE_LIMITED,
    408: ProviderErrorCategory.TRANSIENT_ERROR,
    500: ProviderErrorCategory.TRANSIENT_ERROR,
    502: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    503: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    504: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: The body statuses that mean the lookup worked.
SUCCESS_QUERY_STATUSES: Final[frozenset[str]] = frozenset({"ok"})

#: The body statuses that mean "we looked, and there is no record".
#:
#: A finding rather than a failure, and emphatically not a statement that the
#: observable is safe — see each provider's document for what an absence does
#: and does not mean on that platform.
NO_DATA_QUERY_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "no_result",
        "no_results",
        "hash_not_found",
        "no_ioc_found",
        "url_not_found",
    }
)

#: Body statuses mapped onto TI Recon categories.
#:
#: One table for all three platforms: they share a vocabulary, and a token one
#: API has not documented yet should still be read correctly if it appears.
#: Anything genuinely unrecognized becomes ``UNKNOWN_ERROR`` rather than being
#: guessed at.
QUERY_STATUS_CATEGORIES: Final[dict[str, ProviderErrorCategory]] = {
    # --- the key is missing, malformed or rejected --------------------------
    "no_api_key": ProviderErrorCategory.AUTHENTICATION_ERROR,
    "invalid_api_key": ProviderErrorCategory.AUTHENTICATION_ERROR,
    "unauthorized": ProviderErrorCategory.AUTHENTICATION_ERROR,
    "unauthenticated": ProviderErrorCategory.AUTHENTICATION_ERROR,
    # --- the key is fine; this account may not use the service --------------
    #
    # abuse.ch blacklists an account whose query volume tripped its fair-use
    # controls, for up to 72 hours. Reported as a permission fact rather than a
    # bad key: the credential is intact, and marking it invalid would make an
    # analyst replace a key that was never the problem.
    "user_blacklisted": ProviderErrorCategory.PERMISSION_ERROR,
    "blacklisted": ProviderErrorCategory.PERMISSION_ERROR,
    # --- we asked for something the API cannot parse ------------------------
    "illegal_hash": ProviderErrorCategory.INVALID_REQUEST,
    "illegal_search_term": ProviderErrorCategory.INVALID_REQUEST,
    "illegal_query": ProviderErrorCategory.INVALID_REQUEST,
    "invalid_url": ProviderErrorCategory.INVALID_REQUEST,
    "invalid_host": ProviderErrorCategory.INVALID_REQUEST,
    "invalid_md5": ProviderErrorCategory.INVALID_REQUEST,
    "invalid_sha256": ProviderErrorCategory.INVALID_REQUEST,
    "no_hash_provided": ProviderErrorCategory.INVALID_REQUEST,
    "no_search_term": ProviderErrorCategory.INVALID_REQUEST,
    "no_url_provided": ProviderErrorCategory.INVALID_REQUEST,
    "no_host_provided": ProviderErrorCategory.INVALID_REQUEST,
    "http_post_expected": ProviderErrorCategory.INVALID_REQUEST,
    "unknown_query": ProviderErrorCategory.INVALID_REQUEST,
    # --- throttling ---------------------------------------------------------
    "rate_limited": ProviderErrorCategory.RATE_LIMITED,
    "too_many_requests": ProviderErrorCategory.RATE_LIMITED,
}

#: The shape a body status must have before it is trusted as an error code.
#: Provider text, so it is validated rather than passed through.
_QUERY_STATUS_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

#: Length bound for any provider-supplied detail we keep.
_MAX_DETAIL_LENGTH: Final[int] = 200

#: Longest whitespace-delimited token a kept message may contain. A long opaque
#: token in an error string is never worth its diagnostic value, so its presence
#: drops the whole message; ordinary prose has no such token.
_MAX_TOKEN_LENGTH: Final[int] = 24

#: Above this, a ``Retry-After`` is a metering window rather than a pause worth
#: honouring inline; the value is still recorded on the error.
_MAX_SANE_RETRY_AFTER_SECONDS: Final[float] = 24 * 60 * 60

#: abuse.ch timestamp forms, newest style first. Several fields use a space
#: separator and a trailing zone name rather than ISO-8601.
_TIMESTAMP_SUFFIX: Final[str] = " UTC"


def scrub_detail(text: str | None) -> str | None:
    """Redact and bound a provider-supplied message, or drop it entirely.

    abuse.ch error bodies quote the search term that was submitted, and a search
    term is an analyst's observable — sometimes a URL with a token in its query
    string. A diagnostic string is never worth the risk of carrying one, so
    anything still credential-shaped after redaction is discarded.
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
    mapped = ABUSE_CH_STATUS_CATEGORIES.get(status_code)
    if mapped is not None:
        return mapped
    if 500 <= status_code < 600:
        return ProviderErrorCategory.TRANSIENT_ERROR
    if 400 <= status_code < 500:
        return ProviderErrorCategory.INVALID_REQUEST
    return ProviderErrorCategory.UNKNOWN_ERROR


def query_status_of(payload: Any) -> str | None:
    """The body's ``query_status``, shape-checked, or ``None``.

    Validated before it is used as an error code or a lookup key: it is provider
    text that ends up in an exception message and in metrics, and an
    enum-shaped token is the only form worth trusting.
    """
    if not isinstance(payload, dict):
        return None
    raw = payload.get("query_status")
    if not isinstance(raw, str):
        return None
    candidate = raw.strip().lower()
    return candidate if _QUERY_STATUS_PATTERN.fullmatch(candidate) else None


def category_for_query_status(status: str) -> ProviderErrorCategory | None:
    """Map a body status onto a category, or ``None`` when it means success.

    ``NOT_FOUND`` for the "no record" statuses: an absence is a finding TI Recon
    records, not a failure of the lookup.
    """
    if status in SUCCESS_QUERY_STATUSES:
        return None
    if status in NO_DATA_QUERY_STATUSES:
        return ProviderErrorCategory.NOT_FOUND
    return QUERY_STATUS_CATEGORIES.get(status, ProviderErrorCategory.UNKNOWN_ERROR)


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


def parse_utc_timestamp(value: Any) -> datetime | None:
    """Read an abuse.ch timestamp as a timezone-aware instant.

    These APIs mix ``2026-08-21 04:05:06 UTC`` with ISO-8601, sometimes within
    one response. A naive value is read as UTC rather than as local time,
    because the provider is not reporting our timezone — and for abuse.ch it
    says ``UTC`` out loud most of the time.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.upper().endswith(_TIMESTAMP_SUFFIX):
        candidate = candidate[: -len(_TIMESTAMP_SUFFIX)].strip()
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
    for field in ("query_status", "message", "error", "detail"):
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
    """Turn a non-2xx abuse.ch response into a typed, normalized provider error."""
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


def translate_query_status(
    status: str | None,
    *,
    provider_id: str,
    operation: str,
) -> ProviderError | None:
    """Turn a body status into a typed error, or ``None`` when it means success.

    ``None`` for an absent status too: some responses omit it, and refusing to
    read a document because a field is missing would lose real evidence over a
    formatting difference.
    """
    if status is None or status in SUCCESS_QUERY_STATUSES:
        return None
    category = category_for_query_status(status)
    if category is None:  # pragma: no cover - guarded by the check above
        return None
    return provider_error_for(
        category,
        provider_id,
        message=f"provider reported {status}",
        operation=operation,
        # The token itself: short, enum-shaped and already validated.
        provider_error_code=status,
    )


# --------------------------------------------------------------------------- #
# What a failure says about the credential itself
# --------------------------------------------------------------------------- #

#: How a failed call reflects on the Auth-Key that made it.
#:
#: Only a rejected key is ``INVALID``. A fair-use block, a malformed request and
#: an honest "not found" all mean the key is fine — and because one key serves
#: all three abuse.ch providers, marking it invalid over a ThreatFox refusal
#: would disable URLhaus and MalwareBazaar too.
CREDENTIAL_STATUS_BY_CATEGORY: Final[dict[ProviderErrorCategory, CredentialStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: CredentialStatus.INVALID,
    ProviderErrorCategory.PERMISSION_ERROR: CredentialStatus.ACTIVE,
    ProviderErrorCategory.PLAN_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.QUOTA_EXCEEDED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.RATE_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.NOT_FOUND: CredentialStatus.ACTIVE,
    ProviderErrorCategory.INVALID_REQUEST: CredentialStatus.ACTIVE,
}


def credential_status_for(category: ProviderErrorCategory) -> CredentialStatus:
    """What a failure category says about the credential.

    Anything not in the table is ``UNKNOWN``: a transient failure or a schema
    change is evidence about abuse.ch, not about the analyst's key.
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
