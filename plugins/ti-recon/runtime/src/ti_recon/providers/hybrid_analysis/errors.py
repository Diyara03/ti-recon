"""Mapping Hybrid Analysis failures onto normalized categories (Task 12).

The only module in this package that knows what an HTTP status or a provider
message means. Everything above it reasons in :class:`ProviderErrorCategory`, so
the execution layer never learns Falcon Sandbox's conventions.

Three statuses need more than a lookup table.

**404 is ambiguous, so it is disambiguated by *what was asked*.** A hash search
that finds nothing is an absence — the provider looked and has no report — which
is ``NOT_FOUND`` and becomes ``NO_DATA``. A *report summary* returning 404 is a
different event: the index just told us that report existed, so it has been
removed or expired between the two calls. Treating that as whole-provider
``NO_DATA`` would discard the reports that did work.

**410 is a container, not a failure.** The API returns it for archive-type
reports, sometimes naming the child reports instead. It is a real semantic answer
about a real report, so it is neither a provider outage nor an absence — it is
recorded and the lookup carries on with whatever else it selected. Nothing here
recursively fetches the children: an archive of archives would otherwise become
an unbounded fan-out.

**Quota exhaustion arrives as prose.** The API signals it with messages rather
than distinct statuses, so the documented wordings are matched — carefully, since
a message is provider text.
"""

from __future__ import annotations

import re
from typing import Final

import httpx

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.adapter import CredentialValidation
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.security import SENSITIVE_KEY_PATTERN, redact_sensitive_text

__all__ = [
    "CONTAINER_REPORT_STATUS",
    "HYBRID_ANALYSIS_STATUS_CATEGORIES",
    "QUOTA_MESSAGE_PATTERNS",
    "category_for_status",
    "credential_validation_for",
    "scrub_detail",
    "translate_status_error",
]

#: The status the API uses for a report that is a container/archive rather than a
#: single analysable sample. Handled as a semantic state, never as a failure.
CONTAINER_REPORT_STATUS: Final[int] = 410

HYBRID_ANALYSIS_STATUS_CATEGORIES: Final[dict[int, ProviderErrorCategory]] = {
    400: ProviderErrorCategory.INVALID_REQUEST,
    401: ProviderErrorCategory.AUTHENTICATION_ERROR,
    403: ProviderErrorCategory.PERMISSION_ERROR,
    404: ProviderErrorCategory.NOT_FOUND,
    405: ProviderErrorCategory.INVALID_REQUEST,
    413: ProviderErrorCategory.INVALID_REQUEST,
    422: ProviderErrorCategory.INVALID_REQUEST,
    429: ProviderErrorCategory.RATE_LIMITED,
    408: ProviderErrorCategory.TRANSIENT_ERROR,
    500: ProviderErrorCategory.TRANSIENT_ERROR,
    502: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    503: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    504: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}

#: Documented message wordings that mean an allowance is spent rather than a
#: request was malformed. Matched case-insensitively on a bounded string; the
#: category, never the text, is what travels onwards.
QUOTA_MESSAGE_PATTERNS: Final[tuple[tuple[re.Pattern[str], ProviderErrorCategory], ...]] = (
    (
        re.compile(r"exceeded\s+maximum\s+api\s+requests", re.IGNORECASE),
        ProviderErrorCategory.RATE_LIMITED,
    ),
    (
        re.compile(r"quota\s+limit\s+has\s+been\s+exceeded", re.IGNORECASE),
        ProviderErrorCategory.QUOTA_EXCEEDED,
    ),
)

#: Length bound for any provider-supplied detail kept.
_MAX_DETAIL_LENGTH: Final[int] = 200

#: Longest whitespace-delimited token a kept message may contain. A long opaque
#: token in an error string is never worth its diagnostic value.
_MAX_TOKEN_LENGTH: Final[int] = 24

#: How a failure category reflects on the API key that made the call.
#:
#: Only a rejected key is ``INVALID``. A permission failure means the key works
#: but this endpoint is above its authorization level — a restricted key is
#: expected to hit that — and marking it invalid would make an analyst replace a
#: perfectly good key.
CREDENTIAL_STATUS_BY_CATEGORY: Final[dict[ProviderErrorCategory, CredentialStatus]] = {
    ProviderErrorCategory.AUTHENTICATION_ERROR: CredentialStatus.INVALID,
    ProviderErrorCategory.PERMISSION_ERROR: CredentialStatus.ACTIVE,
    ProviderErrorCategory.PLAN_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.QUOTA_EXCEEDED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.RATE_LIMITED: CredentialStatus.ACTIVE,
    ProviderErrorCategory.NOT_FOUND: CredentialStatus.ACTIVE,
    ProviderErrorCategory.INVALID_REQUEST: CredentialStatus.ACTIVE,
}


def category_for_status(status_code: int) -> ProviderErrorCategory:
    """Map an HTTP status onto a normalized category."""
    mapped = HYBRID_ANALYSIS_STATUS_CATEGORIES.get(status_code)
    if mapped is not None:
        return mapped
    if 500 <= status_code < 600:
        return ProviderErrorCategory.TRANSIENT_ERROR
    if 400 <= status_code < 500:
        return ProviderErrorCategory.INVALID_REQUEST
    return ProviderErrorCategory.UNKNOWN_ERROR


def scrub_detail(text: str | None) -> str | None:
    """Redact and bound a provider message, or drop it entirely.

    An error body may quote the request — and the request contains the hash under
    investigation. A diagnostic string is never worth carrying an observable or
    anything credential-shaped, so anything still suspicious after redaction is
    discarded rather than trimmed.
    """
    if not text:
        return None
    cleaned = redact_sensitive_text(text.strip(), max_length=_MAX_DETAIL_LENGTH)
    if not cleaned or SENSITIVE_KEY_PATTERN.search(cleaned):
        return None
    if any(len(token) > _MAX_TOKEN_LENGTH for token in cleaned.split()):
        return None
    return cleaned


def _detail_from_body(response: httpx.Response) -> str | None:
    """A short message from an error body, without trusting it.

    Two known scalar fields only. The body is never echoed wholesale, and a
    non-JSON body contributes nothing.
    """
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.lower():
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    for field in ("message", "validation_errors", "error"):
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            return scrub_detail(value)
    return None


def _category_from_message(
    response: httpx.Response, fallback: ProviderErrorCategory
) -> ProviderErrorCategory:
    """Upgrade a category when the body says an allowance is spent.

    The API reports quota exhaustion in prose rather than with its own status, so
    a 4xx that says "quota limit has been exceeded" is a spent allowance and not
    a bad request. Getting that wrong would make the execution layer retry a
    refusal that no retry can satisfy.
    """
    content_type = response.headers.get("content-type", "")
    if "json" not in content_type.lower():
        return fallback
    try:
        payload = response.json()
    except ValueError:
        return fallback
    if not isinstance(payload, dict):
        return fallback
    message = payload.get("message")
    if not isinstance(message, str):
        return fallback
    bounded = message[:_MAX_DETAIL_LENGTH]
    for pattern, category in QUOTA_MESSAGE_PATTERNS:
        if pattern.search(bounded):
            return category
    return fallback


def translate_status_error(
    response: httpx.Response,
    *,
    provider_id: str,
    operation: str,
) -> ProviderError:
    """Turn a non-2xx response into a typed, normalized provider error."""
    category = _category_from_message(response, category_for_status(response.status_code))
    return provider_error_for(
        category,
        provider_id,
        message=_detail_from_body(response),
        operation=operation,
        # The status code, not a body. Safe to log and enough to diagnose.
        provider_error_code=str(response.status_code),
    )


def credential_status_for(category: ProviderErrorCategory) -> CredentialStatus:
    """What a failure category says about the credential.

    Anything unlisted is ``UNKNOWN``: a transient failure or a schema change is
    evidence about the provider, not about the analyst's key.
    """
    return CREDENTIAL_STATUS_BY_CATEGORY.get(category, CredentialStatus.UNKNOWN)


def credential_validation_for(
    provider_id: str, error: ProviderError | None
) -> CredentialValidation:
    """Turn a validation probe's outcome into a credential verdict."""
    if error is None:
        return CredentialValidation(provider_id=provider_id, status=CredentialStatus.ACTIVE)
    return CredentialValidation(
        provider_id=provider_id,
        status=credential_status_for(error.category),
        detail=error.category.value,
    )
