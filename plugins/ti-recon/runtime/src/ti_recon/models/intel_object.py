"""Canonical intelligence object (Task 3).

An :class:`IntelObject` is the single representation of "a thing intelligence
can be about": the observable an analyst submitted, and any object TI Recon
derives while enriching it (an ASN, a certificate, a malware family).

File hashes are **not** object types. A hash identifies a ``file`` object and
is carried in that object's ``hashes`` property, so the same file found by MD5
in one provider and by SHA-256 in another converges on one object type.
"""

from __future__ import annotations

import re
from typing import Any, Final

from pydantic import Field, model_validator

from ti_recon.enums import IntelObjectType, ObjectClass
from ti_recon.models.base import (
    Identifier,
    TiReconModel,
    UtcDatetime,
    new_id,
    utc_now,
)

__all__ = [
    "HASH_ALGORITHM_SLUGS",
    "HASH_HEX_LENGTHS",
    "HASH_PREFERENCE_ORDER",
    "IntelObject",
    "canonical_key_for",
    "hash_algorithm_for_hex_length",
    "strongest_hash",
]

#: STIX-style hash property names mapped to the slug used in canonical keys.
HASH_ALGORITHM_SLUGS: Final[dict[str, str]] = {
    "SHA-256": "sha256",
    "SHA-1": "sha1",
    "MD5": "md5",
}

#: Hex-digest length of each supported hash algorithm.
HASH_HEX_LENGTHS: Final[dict[str, int]] = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
}

#: Strongest first. Determines which hash names a ``file`` object.
HASH_PREFERENCE_ORDER: Final[tuple[str, ...]] = ("SHA-256", "SHA-1", "MD5")

_HEX_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]+\Z")


def hash_algorithm_for_hex_length(length: int) -> str | None:
    """Return the STIX hash property name for a hex digest of ``length``."""
    for name, expected in HASH_HEX_LENGTHS.items():
        if expected == length:
            return name
    return None


def strongest_hash(hashes: dict[str, str]) -> tuple[str, str] | None:
    """Return ``(algorithm_name, digest)`` for the strongest hash present."""
    for name in HASH_PREFERENCE_ORDER:
        digest = hashes.get(name)
        if digest:
            return name, digest
    return None


def canonical_key_for(
    object_type: IntelObjectType,
    canonical_value: str,
    properties: dict[str, Any] | None = None,
) -> str:
    """Build the canonical, de-duplicating key for an object.

    Non-file objects key on their type and canonical value. File objects key on
    the strongest available hash, e.g. ``file:sha256:<digest>``, so that a file
    referenced by different algorithms is still recognizable as a file.
    """
    if object_type is not IntelObjectType.FILE:
        return f"{object_type.value}:{canonical_value}"

    hashes = _extract_hashes(properties)
    best = strongest_hash(hashes) if hashes else None
    if best is None:
        msg = "file objects require at least one hash in properties['hashes']"
        raise ValueError(msg)
    algorithm, digest = best
    return f"file:{HASH_ALGORITHM_SLUGS[algorithm]}:{digest}"


def _extract_hashes(properties: dict[str, Any] | None) -> dict[str, str]:
    if not properties:
        return {}
    raw = properties.get("hashes")
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


class IntelObject(TiReconModel):
    """A single object that intelligence can be attached to.

    ``canonical_value`` is the normalized, comparable form; ``display_value``
    is the analyst-facing form (for example the Unicode label of an
    internationalized domain whose canonical value is punycode).
    """

    id: Identifier = Field(default_factory=new_id)
    object_class: ObjectClass
    object_type: IntelObjectType
    canonical_value: str = Field(min_length=1, max_length=4096)
    display_value: str = Field(min_length=1, max_length=4096)
    canonical_key: str = Field(default="", max_length=4200)
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_object(self) -> IntelObject:
        if self.object_type is IntelObjectType.FILE:
            self._validate_file_hashes()
        if not self.canonical_key:
            # Bypass validate_assignment: the key is derived, not user input.
            object.__setattr__(
                self,
                "canonical_key",
                canonical_key_for(self.object_type, self.canonical_value, self.properties),
            )
        return self

    def _validate_file_hashes(self) -> None:
        hashes = _extract_hashes(self.properties)
        if not hashes:
            msg = "file objects require properties['hashes'] with at least one digest"
            raise ValueError(msg)
        unknown = set(hashes) - set(HASH_HEX_LENGTHS)
        if unknown:
            msg = f"unsupported hash algorithm(s): {sorted(unknown)}"
            raise ValueError(msg)
        for name, digest in hashes.items():
            if not _HEX_RE.fullmatch(digest):
                msg = f"{name} digest must be lowercase hexadecimal"
                raise ValueError(msg)
            if len(digest) != HASH_HEX_LENGTHS[name]:
                msg = f"{name} digest must be {HASH_HEX_LENGTHS[name]} hex characters"
                raise ValueError(msg)

    @property
    def hashes(self) -> dict[str, str]:
        """Hashes carried by this object; empty for non-file objects."""
        return _extract_hashes(self.properties)

    def touch(self) -> None:
        """Record that this object's properties were updated."""
        self.updated_at = utc_now()
