"""Bounded readers for abuse.ch responses (Task 10).

Pure functions, shared by the three adapters because all three face the same
problem: the interesting parts of an abuse.ch response are written by whoever
submitted the sample or the URL. A malware file name, a URLhaus tag, a
MalwareBazaar comment and a ThreatFox reference are all attacker-adjacent text
arriving over an authenticated channel.

So nothing here reflects a document into evidence. Every value is length-bounded,
every list is count-bounded, control characters are stripped, and a field that is
not the shape it should be is dropped rather than coerced.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

__all__ = [
    "MAX_LABEL",
    "MAX_TEXT",
    "count",
    "flag",
    "hex_digest",
    "mapping",
    "number",
    "scalar",
    "string_list",
    "text",
]

#: Longest single string kept from a response, and a shorter bound for
#: label-like values (a tag, a family name, a file type).
MAX_TEXT: Final[int] = 1024
MAX_LABEL: Final[int] = 200

_HEX: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]+\Z")


def text(value: Any, max_length: int = MAX_LABEL) -> str | None:
    """A bounded, control-character-free string, or ``None``.

    Control characters are stripped rather than escaped: nothing downstream has
    a use for them, and a stored newline is how provider text starts looking
    like structure to whatever renders it later.
    """
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character
        for character in value.strip()
        if ord(character) >= 0x20 and ord(character) != 0x7F
    )[:max_length]
    return cleaned or None


def scalar(value: Any, max_length: int = MAX_TEXT) -> Any:
    """A JSON scalar safe to store: bounded text, a number, or a bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return text(value, max_length)
    return None


def flag(value: Any) -> bool | None:
    """A boolean, or ``None``.

    abuse.ch sends booleans as real booleans in some fields and as the strings
    ``"true"``/``"false"`` in others, so both are read — but nothing else is.
    An unrecognized value stays ``None``, because guessing a boolean is how
    ``is_compromised`` silently becomes the wrong answer.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def number(value: Any) -> float | None:
    """A numeric value, or ``None``. Numeric strings are accepted."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None``. Numeric strings are accepted."""
    parsed = number(value)
    if parsed is None:
        return None
    whole = int(parsed)
    return whole if whole >= 0 else None


def hex_digest(value: Any, *, lengths: frozenset[int] | set[int]) -> str | None:
    """A lowercase hex digest of an accepted length, or ``None``.

    Shape-checked rather than passed through, because a digest is an identity:
    it becomes an object's canonical value, a pivot key, and sometimes part of a
    request. A value that is not a digest has no business being any of those.
    """
    candidate = text(value, 200)
    if candidate is None:
        return None
    lowered = candidate.lower()
    return lowered if len(lowered) in lengths and _HEX.fullmatch(lowered) else None


def string_list(value: Any, max_items: int, max_length: int = MAX_LABEL) -> list[str]:
    """A bounded list of bounded strings, de-duplicated, skipping anything else.

    abuse.ch returns ``null`` where a list is absent, and occasionally a bare
    string where a list is expected; both read as empty rather than raising.
    """
    if isinstance(value, str):
        single = text(value, max_length)
        return [single] if single else []
    if not isinstance(value, Sequence) or isinstance(value, bytes):
        return []
    items: list[str] = []
    for entry in value:
        cleaned = text(entry, max_length)
        if cleaned is None or cleaned in items:
            continue
        items.append(cleaned)
        if len(items) >= max_items:
            break
    return items


def mapping(value: Any) -> Mapping[str, Any]:
    """A mapping, or an empty one. Never raises on a shape change."""
    return value if isinstance(value, Mapping) else {}
