"""Cross-cutting guards that keep credentials out of data and logs.

These are defence in depth, not the primary control. The primary control is
that credentials live only in the credential layer and are applied by the
transport; these guards catch an adapter that copies a request header or an
authenticated payload field into normalized output by mistake.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

__all__ = [
    "REDACTED",
    "SENSITIVE_KEY_PATTERN",
    "contains_credential_like_key",
    "reject_credential_like_keys",
]

#: Replacement used wherever a sensitive value would otherwise be rendered.
REDACTED: Final[str] = "[REDACTED]"

#: Key fragments that indicate credential material rather than intelligence.
#: Covers the header and field names used by the providers TI Recon will
#: integrate with (``x-apikey``, ``API-Key``, ``Auth-Key``, bearer tokens).
SENSITIVE_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"api[-_ ]?key|apikey"
    r"|auth[-_ ]?key"
    r"|authoriz(?:ation|ation_header)"
    r"|access[-_ ]?token|bearer|id[-_ ]?token|refresh[-_ ]?token"
    r"|secret|passwd|password|credential"
    r"|private[-_ ]?key|session[-_ ]?id|cookie|set[-_ ]?cookie"
    r")",
    re.IGNORECASE,
)


def contains_credential_like_key(data: Mapping[str, Any]) -> str | None:
    """Return the first credential-like key found in ``data``, recursively."""
    for key, value in data.items():
        if SENSITIVE_KEY_PATTERN.search(key):
            return key
        if isinstance(value, Mapping):
            nested = contains_credential_like_key(value)
            if nested is not None:
                return f"{key}.{nested}"
        elif isinstance(value, list | tuple):
            for item in value:
                if isinstance(item, Mapping):
                    nested = contains_credential_like_key(item)
                    if nested is not None:
                        return f"{key}.{nested}"
    return None


def reject_credential_like_keys(data: Mapping[str, Any], *, where: str) -> None:
    """Raise ``ValueError`` if ``data`` carries a credential-like key.

    The offending value is never included in the message — only the key path —
    so the guard cannot itself leak the secret it is protecting.
    """
    offending = contains_credential_like_key(data)
    if offending is not None:
        msg = f"{where} must not contain credential-like key {offending!r}"
        raise ValueError(msg)
