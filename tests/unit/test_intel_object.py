"""IntelObject model invariants (Task 3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from ti_recon.enums import IntelObjectType, ObjectClass
from ti_recon.models.intel_object import (
    IntelObject,
    canonical_key_for,
    hash_algorithm_for_hex_length,
    strongest_hash,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def make_ip(value: str = "198.51.100.7") -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.IPV4_ADDR,
        canonical_value=value,
        display_value=value,
    )


def test_canonical_key_is_derived_when_absent() -> None:
    obj = make_ip()
    assert obj.canonical_key == "ipv4-addr:198.51.100.7"


def test_canonical_key_is_preserved_when_supplied() -> None:
    obj = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.DOMAIN_NAME,
        canonical_value="evil.example",
        display_value="evil.example",
        canonical_key="domain-name:evil.example",
    )
    assert obj.canonical_key == "domain-name:evil.example"


def test_timestamps_are_timezone_aware_utc() -> None:
    obj = make_ip()
    assert obj.created_at.tzinfo is not None
    assert obj.created_at.utcoffset() == timedelta(0)


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.IPV4_ADDR,
            canonical_value="198.51.100.7",
            display_value="198.51.100.7",
            created_at=datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001
        )


def test_non_utc_timestamps_are_normalized_to_utc() -> None:
    tzinfo = timezone(timedelta(hours=3))
    obj = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.IPV4_ADDR,
        canonical_value="198.51.100.7",
        display_value="198.51.100.7",
        created_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=tzinfo),
    )
    assert obj.created_at == datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)


def test_touch_advances_updated_at() -> None:
    obj = make_ip()
    before = obj.updated_at
    obj.touch()
    assert obj.updated_at >= before


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.IPV4_ADDR,
            canonical_value="198.51.100.7",
            display_value="198.51.100.7",
            verdict="malicious",  # type: ignore[call-arg]
        )


# --------------------------------------------------------------------------- #
# File hash representation
# --------------------------------------------------------------------------- #


def make_file(hashes: dict[str, str]) -> IntelObject:
    strongest = strongest_hash(hashes)
    assert strongest is not None
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest[1],
        display_value=strongest[1],
        properties={"hashes": dict(hashes)},
    )


@pytest.mark.parametrize(
    ("hashes", "expected_key"),
    [
        ({"SHA-256": SHA256}, f"file:sha256:{SHA256}"),
        ({"SHA-1": SHA1}, f"file:sha1:{SHA1}"),
        ({"MD5": MD5}, f"file:md5:{MD5}"),
        ({"MD5": MD5, "SHA-256": SHA256}, f"file:sha256:{SHA256}"),
        ({"MD5": MD5, "SHA-1": SHA1}, f"file:sha1:{SHA1}"),
    ],
)
def test_file_canonical_key_uses_strongest_hash(hashes: dict[str, str], expected_key: str) -> None:
    assert make_file(hashes).canonical_key == expected_key


def test_file_requires_at_least_one_hash() -> None:
    with pytest.raises(ValidationError, match="hashes"):
        IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.FILE,
            canonical_value=SHA256,
            display_value=SHA256,
        )


def test_file_rejects_unknown_hash_algorithm() -> None:
    with pytest.raises(ValidationError, match="unsupported hash algorithm"):
        IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.FILE,
            canonical_value="0" * 128,
            display_value="0" * 128,
            properties={"hashes": {"SHA-512": "0" * 128}},
        )


def test_file_rejects_wrong_digest_length() -> None:
    with pytest.raises(ValidationError, match="64 hex characters"):
        make_file({"SHA-256": SHA256[:-1]})


def test_file_rejects_non_hex_digest() -> None:
    with pytest.raises(ValidationError, match="hexadecimal"):
        make_file({"MD5": "z" * 32})


def test_file_rejects_uppercase_digest() -> None:
    """Canonical digests are lowercase so the canonical key de-duplicates."""
    with pytest.raises(ValidationError, match="hexadecimal"):
        make_file({"MD5": MD5.upper()})


def test_hashes_property_is_empty_for_non_file_objects() -> None:
    assert make_ip().hashes == {}


def test_hashes_property_exposes_file_hashes() -> None:
    assert make_file({"SHA-256": SHA256}).hashes == {"SHA-256": SHA256}


def test_hash_algorithm_lookup_by_length() -> None:
    assert hash_algorithm_for_hex_length(32) == "MD5"
    assert hash_algorithm_for_hex_length(40) == "SHA-1"
    assert hash_algorithm_for_hex_length(64) == "SHA-256"
    assert hash_algorithm_for_hex_length(128) is None


def test_strongest_hash_returns_none_when_empty() -> None:
    assert strongest_hash({}) is None


def test_canonical_key_for_file_without_hashes_is_an_error() -> None:
    with pytest.raises(ValueError, match="at least one hash"):
        canonical_key_for(IntelObjectType.FILE, SHA256, {})
