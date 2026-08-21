"""Turning GTI objects into TI Recon models (Task 7).

Pure functions over :class:`GTIObject`. No I/O, no vt-py, no clock reads that
are not passed in — so every rule here is testable against a stored fixture.

Two principles run through the whole module.

**Controlled normalization, not reflection.** GTI returns far more than TI Recon
models, and its schema evolves. Nothing here iterates a provider dictionary and
invents a field per key: each object type has an explicit allow-list of
attributes worth keeping, unknown attributes are ignored rather than exploded
into the model, and a missing optional attribute reads as absent rather than
raising.

**Identity and metadata are separate from assessment.** Stable facts about
*what an object is* — hashes, size, ASN, registrar, timestamps — go into
``IntelObject.properties``. Anything that is a judgement over time — reputation,
analysis statistics, the GTI assessment — becomes ``Evidence``, because it has a
provenance, an effect and a moment of observation that a property cannot carry.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from ti_recon.enums import IntelObjectType
from ti_recon.models.intel_object import HASH_HEX_LENGTHS, IntelObject
from ti_recon.providers.gti.client import GTIObject

__all__ = [
    "GTI_METADATA_FIELDS",
    "GTI_PROPERTY_NAMESPACE",
    "GTI_TIMESTAMP_FIELDS",
    "enrich_primary_object",
    "epoch_to_utc",
    "gti_hashes",
    "gti_metadata",
]

#: GTI-specific facts live under one key rather than being spread across
#: ``properties``, so their provenance stays obvious once several providers have
#: contributed to the same object.
GTI_PROPERTY_NAMESPACE: Final[str] = "gti"

#: Attributes GTI reports as unix epoch seconds. Converted to ISO-8601 UTC so a
#: serialized object carries an unambiguous instant rather than a bare integer.
GTI_TIMESTAMP_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "creation_date",
        "first_submission_date",
        "last_analysis_date",
        "last_modification_date",
        "last_submission_date",
        "last_update_date",
        "whois_date",
        "expiration_date",
    }
)

#: Per-object-type allow-list of stable metadata worth keeping.
#:
#: Deliberately narrow. Reputation, ``last_analysis_stats`` and
#: ``gti_assessment`` are absent because they are assessments rather than
#: properties and become evidence instead. Anything large or unbounded
#: (per-engine results, outgoing link lists, full behaviour reports) is absent
#: because it would bloat every object for data TI Recon does not model.
GTI_METADATA_FIELDS: Final[dict[IntelObjectType, tuple[str, ...]]] = {
    IntelObjectType.FILE: (
        "md5",
        "sha1",
        "sha256",
        "vhash",
        "size",
        "type_description",
        "type_tag",
        "type_extension",
        "meaningful_name",
        "magic",
        "tags",
        "times_submitted",
        "first_submission_date",
        "last_submission_date",
        "last_analysis_date",
        "last_modification_date",
    ),
    IntelObjectType.DOMAIN_NAME: (
        "registrar",
        "categories",
        "tags",
        "jarm",
        "tld",
        "creation_date",
        "expiration_date",
        "last_update_date",
        "last_modification_date",
        "last_analysis_date",
        "whois_date",
    ),
    IntelObjectType.IPV4_ADDR: (
        "asn",
        "as_owner",
        "network",
        "country",
        "continent",
        "regional_internet_registry",
        "tags",
        "jarm",
        "last_modification_date",
        "last_analysis_date",
    ),
    IntelObjectType.URL: (
        "url",
        "last_final_url",
        "title",
        "categories",
        "tags",
        "times_submitted",
        "first_submission_date",
        "last_submission_date",
        "last_analysis_date",
        "last_modification_date",
    ),
}
# IPv6 objects come from the same GTI collection and carry the same attributes.
GTI_METADATA_FIELDS[IntelObjectType.IPV6_ADDR] = GTI_METADATA_FIELDS[IntelObjectType.IPV4_ADDR]

#: GTI's lowercase hash attribute names mapped to the STIX-style names the Task 3
#: ``file`` object requires.
_HASH_ATTRIBUTE_NAMES: Final[dict[str, str]] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
}

#: Epoch values outside this range are nonsense rather than timestamps, and a
#: bad one should read as absent instead of producing a year-1970 or year-33000
#: date that looks authoritative.
_MIN_EPOCH: Final[int] = 0
_MAX_EPOCH: Final[int] = 4_102_444_800  # 2100-01-01Z


def epoch_to_utc(value: Any) -> datetime | None:
    """Convert a GTI epoch-seconds value into a UTC datetime, or ``None``.

    Returns ``None`` for anything that is not a plausible timestamp, so a
    schema change turns into a missing field rather than a wrong date.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    if not _MIN_EPOCH <= number <= _MAX_EPOCH:
        return None
    return datetime.fromtimestamp(number, tz=UTC)


def gti_hashes(gti_object: GTIObject) -> dict[str, str]:
    """The file hashes GTI reported, in Task 3's naming and casing.

    Only well-formed digests survive: a hash of the wrong length or with
    non-hex characters is dropped, because ``IntelObject`` would reject the whole
    object for it and one malformed digest should not cost us the rest.
    """
    hashes: dict[str, str] = {}
    for attribute, canonical_name in _HASH_ATTRIBUTE_NAMES.items():
        raw = gti_object.attribute(attribute)
        if not isinstance(raw, str):
            continue
        digest = raw.strip().lower()
        expected = HASH_HEX_LENGTHS[canonical_name]
        if len(digest) != expected:
            continue
        if any(character not in "0123456789abcdef" for character in digest):
            continue
        hashes[canonical_name] = digest
    return hashes


def gti_metadata(object_type: IntelObjectType, gti_object: GTIObject) -> dict[str, Any]:
    """The allow-listed metadata for one object type.

    Absent attributes are simply absent; nothing is defaulted, because an
    invented zero or empty string is indistinguishable from a real one.
    """
    metadata: dict[str, Any] = {}
    for field in GTI_METADATA_FIELDS.get(object_type, ()):
        if field not in gti_object.attributes:
            continue
        value = gti_object.attributes[field]
        if value is None:
            continue
        if field in GTI_TIMESTAMP_FIELDS:
            moment = epoch_to_utc(value)
            if moment is not None:
                metadata[field] = moment.isoformat()
            continue
        metadata[field] = _plain(value)
    return metadata


def enrich_primary_object(submitted: IntelObject, gti_object: GTIObject) -> IntelObject:
    """A copy of the submitted observable with what GTI knows about it added.

    The submitted object's ``id``, ``canonical_value`` and ``canonical_key`` are
    preserved on purpose. GTI often reveals a stronger identifier — a SHA-256 for
    a file submitted as an MD5 — and re-keying the object on that would be an
    identity-resolution decision. This layer reports; correlating two identifiers
    into one object is a later layer's call, and it has the full hash set here to
    do it with.
    """
    properties: dict[str, Any] = dict(submitted.properties)
    namespace = dict(gti_metadata(submitted.object_type, gti_object))
    namespace["object_id"] = gti_object.object_id
    namespace["object_type"] = gti_object.object_type

    if submitted.object_type is IntelObjectType.FILE:
        merged_hashes: dict[str, str] = dict(submitted.hashes)
        merged_hashes.update(gti_hashes(gti_object))
        if merged_hashes:
            properties["hashes"] = merged_hashes

    properties[GTI_PROPERTY_NAMESPACE] = namespace
    return submitted.model_copy(update={"properties": properties})


def _plain(value: Any) -> Any:
    """A JSON-safe copy of a provider value.

    Containers are copied so a normalized object cannot be mutated through the
    provider payload it came from, and unrecognized types are stringified rather
    than smuggled into a model that has to serialize.
    """
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return str(value)
