"""Turning ThreatFox records into TI Recon models (Task 10).

Pure functions over parsed records. No I/O, no clock reads that are not passed
in, so every rule here is testable against a stored fixture.

Four principles run through the module.

**One opinion per response.** ThreatFox may hold several current records for one
observable — three ports on an address, two campaigns on a domain. They become
**one** piece of directional evidence summarizing the matched set, not one per
record. Splitting them would let a well-documented indicator outvote three
independent providers with what is really one platform's view.

**Only validated records count.** Everything here operates on records that
already passed :mod:`ti_recon.providers.threatfox.matching`. The count that did
*not* pass is recorded in the coverage evidence, so a loose provider search is
visible rather than silently absorbed.

**Provider confidence is the provider's.** ThreatFox publishes a confidence level
per IOC and it goes in ``provider_confidence`` — the field the model has for
exactly that. It is not an Admiralty grade, and it is not the confidence a future
assessment layer computes. Those three stay separate.

**A miss is a horizon, not an acquittal.** ThreatFox expires IOCs from its API
after about six months. "No current record" therefore means "nothing unexpired
matched", which is a much weaker statement than "this was never malicious" — and
the coverage evidence says so explicitly rather than leaving a reader to assume.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import (
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_url,
)
from ti_recon.providers.abusech.errors import parse_utc_timestamp
from ti_recon.providers.abusech.evidence import (
    AbuseChNormalization,
    NormalizationContext,
    build_evidence,
)
from ti_recon.providers.abusech.values import (
    MAX_LABEL,
    MAX_TEXT,
    flag,
    hex_digest,
    number,
    string_list,
    text,
)
from ti_recon.providers.threatfox.descriptor import THREATFOX_PROVIDER_ID
from ti_recon.providers.threatfox.matching import ThreatFoxMatch

__all__ = [
    "IOC_EXPIRY_HORIZON_MONTHS",
    "MAX_ALIASES",
    "MAX_TAGS",
    "THREATFOX_NO_CURRENT_RECORD",
    "ThreatFoxRecord",
    "normalize_coverage",
    "normalize_hash_association",
    "normalize_ioc_match",
    "normalize_no_current_record",
    "normalize_related_samples",
    "records_of",
]

#: How long a ThreatFox IOC stays visible through the API.
#:
#: The platform expires indicators after roughly six months. They remain
#: visible in its web interface marked expired, but the API — the only thing
#: this integration reads — no longer returns them. Every result carries this
#: number so nobody has to know it to read the answer.
IOC_EXPIRY_HORIZON_MONTHS: Final[int] = 6

#: Reported when ThreatFox answered and had no current record.
THREATFOX_NO_CURRENT_RECORD: Final[str] = "THREATFOX_NO_CURRENT_RECORD"

#: Caps on provider-controlled lists.
MAX_TAGS: Final[int] = 20
MAX_ALIASES: Final[int] = 10

#: Allow-listed scalar fields from one record. Anything ThreatFox adds later is
#: ignored until it is listed here on purpose.
_RECORD_FIELDS: Final[tuple[str, ...]] = (
    "ioc_type",
    "ioc_type_desc",
    "threat_type",
    "threat_type_desc",
    "malware",
    "malware_printable",
    "malware_malpedia",
    "reporter",
    "reference",
)


class ThreatFoxRecord:
    """Defensive reader over one entry in a ThreatFox ``data`` list.

    Every accessor tolerates the field being absent, null or of the wrong type:
    the record is provider-controlled and its most interesting parts — the
    reference URL, the tags, the malware alias list — were written by whoever
    reported the indicator.
    """

    def __init__(self, entry: Mapping[str, Any]) -> None:
        self._entry = entry

    @property
    def ioc(self) -> str | None:
        return text(self._entry.get("ioc"), MAX_TEXT)

    @property
    def ioc_type(self) -> str | None:
        return text(self._entry.get("ioc_type"), 64)

    @property
    def confidence_level(self) -> float | None:
        """ThreatFox's own confidence, clamped to the model's range."""
        value = number(self._entry.get("confidence_level"))
        if value is None:
            return None
        return max(0.0, min(100.0, value))

    @property
    def first_seen(self) -> datetime | None:
        return parse_utc_timestamp(self._entry.get("first_seen"))

    @property
    def last_seen(self) -> datetime | None:
        return parse_utc_timestamp(self._entry.get("last_seen"))

    @property
    def is_compromised(self) -> bool | None:
        """Whether ThreatFox believes this is compromised legitimate infrastructure.

        Kept because it changes what an analyst should *do*, not what the
        evidence means. A compromised host is still a malicious IOC while it is
        serving; the difference is that blocking it has a victim, and that
        attributing it to an actor would be wrong. TI Recon records the
        distinction and draws no conclusion from it.
        """
        return flag(self._entry.get("is_compromised"))

    @property
    def tags(self) -> list[str]:
        return string_list(self._entry.get("tags"), MAX_TAGS, MAX_LABEL)

    @property
    def aliases(self) -> list[str]:
        """Malware aliases, which ThreatFox sends as a comma-separated string."""
        raw = text(self._entry.get("malware_alias"), MAX_TEXT)
        if raw is None:
            return []
        return string_list([part.strip() for part in raw.split(",")], MAX_ALIASES, MAX_LABEL)

    @property
    def threat_type(self) -> str | None:
        return text(self._entry.get("threat_type"), MAX_LABEL)

    @property
    def malware_name(self) -> str | None:
        """The printable family name, falling back to the canonical one."""
        return text(self._entry.get("malware_printable"), MAX_LABEL) or text(
            self._entry.get("malware"), MAX_LABEL
        )

    def scalars(self) -> dict[str, Any]:
        """The allow-listed scalar fields present on this record."""
        recorded: dict[str, Any] = {}
        for name in _RECORD_FIELDS:
            value = text(self._entry.get(name), MAX_TEXT)
            if value is not None:
                recorded[name] = value
        return recorded

    def sample_digests(self) -> list[str]:
        """SHA-256 digests of the samples ThreatFox links to this record.

        MalwareBazaar links are ignored: they are URLs into a sibling platform,
        and the digest is the pivot worth keeping. Nothing here follows either.
        """
        samples = self._entry.get("malware_samples")
        if not isinstance(samples, Sequence) or isinstance(samples, str | bytes):
            return []
        digests: list[str] = []
        for sample in samples:
            if not isinstance(sample, Mapping):
                continue
            digest = hex_digest(sample.get("sha256_hash"), lengths=frozenset({64}))
            if digest is not None and digest not in digests:
                digests.append(digest)
        return digests


def records_of(payload: Mapping[str, Any]) -> list[ThreatFoxRecord]:
    """Every readable record in a ThreatFox response.

    A response whose ``data`` is absent, null or not a list yields nothing
    rather than raising: a shape change should cost evidence, not the lookup.
    """
    data = payload.get("data")
    if not isinstance(data, Sequence) or isinstance(data, str | bytes):
        return []
    return [ThreatFoxRecord(entry) for entry in data if isinstance(entry, Mapping)]


# --------------------------------------------------------------------------- #
# The directional claim
# --------------------------------------------------------------------------- #


def normalize_ioc_match(
    context: NormalizationContext,
    matched: Sequence[tuple[ThreatFoxRecord, ThreatFoxMatch]],
    *,
    max_related: int,
) -> AbuseChNormalization:
    """One curated assertion covering every current record that matched.

    ThreatFox vets what it publishes, so a current record is a real assertion
    that the indicator is malware-related — and this is the one place in the
    ThreatFox package that produces a direction.

    Several matched records become one piece of evidence, not several. The
    strongest confidence ThreatFox assigned is carried as *its* confidence;
    averaging would invent a number the provider never stated.
    """
    if not matched:
        return AbuseChNormalization()

    primary_record, primary_match = matched[0]
    attributes: dict[str, Any] = primary_record.scalars()
    attributes["ioc"] = primary_match.ioc
    attributes["matched_component"] = primary_match.matched_component.value
    attributes["matched_records"] = len(matched)
    if primary_match.port is not None:
        attributes["port"] = primary_match.port

    if len(matched) > 1:
        # Every matched value, so an analyst sees the whole current picture
        # without the evidence layer pretending it is several findings.
        attributes["iocs"] = string_list([item.ioc for _, item in matched], max_related, MAX_TEXT)

    tags = _merged(record.tags for record, _ in matched)
    if tags:
        attributes["tags"] = tags[:MAX_TAGS]
    aliases = _merged(record.aliases for record, _ in matched)
    if aliases:
        attributes["malware_alias"] = aliases[:MAX_ALIASES]

    compromised = _first_flag(record.is_compromised for record, _ in matched)
    if compromised is not None:
        attributes["is_compromised"] = compromised

    confidence = max(
        (record.confidence_level for record, _ in matched if record.confidence_level is not None),
        default=None,
    )
    if confidence is not None:
        # Recorded in the attributes too, so a reader of the evidence body sees
        # the provider's own number without having to know the model's field.
        attributes["confidence_level"] = confidence

    first_seen = _earliest(record.first_seen for record, _ in matched)
    last_seen = _latest(record.last_seen for record, _ in matched)

    evidence = build_evidence(
        context.with_scope(primary_match.match_scope),
        provider_id=THREATFOX_PROVIDER_ID,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="threatfox_ioc",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        attributes=attributes,
        first_seen=first_seen,
        last_seen=last_seen,
        observed_at=last_seen or first_seen,
        provider_confidence=confidence,
    )

    related = _malware_association(context, matched, evidence_id=evidence.id)
    return AbuseChNormalization(evidence=(evidence,)).merge(related)


def normalize_hash_association(
    context: NormalizationContext,
    records: Sequence[ThreatFoxRecord],
    *,
    max_related: int,
    provider_total: int | None = None,
) -> AbuseChNormalization:
    """One assertion that ThreatFox links this sample to malware infrastructure.

    A hash search returns the IOCs a sample is associated with — often many.
    They become one piece of directional evidence about the file plus bounded
    related objects, never one malicious vote per returned IOC: that would let a
    sample with forty C2 addresses look like forty findings.

    The infrastructure itself becomes objects and ``contacts`` relationships, so
    a future query planner can pivot on them. Nothing here enriches them; that
    is the planner's decision, not this adapter's.
    """
    if not records:
        return AbuseChNormalization()

    kept = list(records[:max_related])
    attributes: dict[str, Any] = {
        "associated_iocs": len(records) if provider_total is None else provider_total,
        "normalized_count": len(kept),
        "truncated": len(records) > len(kept),
    }
    if provider_total is not None:
        attributes["provider_total"] = provider_total

    values = string_list([record.ioc for record in kept if record.ioc], max_related, MAX_TEXT)
    if values:
        attributes["iocs"] = values
    threat_types = _merged([record.threat_type] for record in kept if record.threat_type)
    if threat_types:
        attributes["threat_types"] = threat_types[:MAX_TAGS]
    tags = _merged(record.tags for record in kept)
    if tags:
        attributes["tags"] = tags[:MAX_TAGS]

    family = next((record.malware_name for record in kept if record.malware_name), None)
    if family is not None:
        attributes["malware_printable"] = family

    confidence = max(
        (record.confidence_level for record in kept if record.confidence_level is not None),
        default=None,
    )
    if confidence is not None:
        attributes["confidence_level"] = confidence

    first_seen = _earliest(record.first_seen for record in kept)
    last_seen = _latest(record.last_seen for record in kept)

    evidence = build_evidence(
        context,
        provider_id=THREATFOX_PROVIDER_ID,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="threatfox_hash_association",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        attributes=attributes,
        first_seen=first_seen,
        last_seen=last_seen,
        observed_at=last_seen or first_seen,
        provider_confidence=confidence,
    )

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    for record in kept:
        infrastructure = _infrastructure_object(record)
        if infrastructure is None:
            continue
        objects.append(infrastructure)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.CONTACTS,
                target_object_id=infrastructure.id,
                first_seen=record.first_seen,
                last_seen=record.last_seen,
                evidence_refs=(evidence.id,),
            )
        )

    result = AbuseChNormalization(
        evidence=(evidence,),
        objects=_unique(objects),
        relationships=tuple(relationships),
    )
    return result.merge(
        _malware_association(context, [(record, None) for record in kept], evidence_id=evidence.id)
    )


def normalize_related_samples(
    context: NormalizationContext,
    records: Sequence[ThreatFoxRecord],
    *,
    max_related: int,
    evidence_id: str,
) -> AbuseChNormalization:
    """The malware samples ThreatFox links to the matched records.

    Objects and relationships only: the samples are pivots for a later lookup,
    and nothing here downloads one or asks another provider about it.
    """
    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    for record in records:
        for digest in record.sample_digests():
            if len(objects) >= max_related:
                break
            sample = _file_object(digest)
            if sample is None or sample.id == context.subject_object_id:
                continue
            objects.append(sample)
            relationships.append(
                Relationship(
                    source_object_id=sample.id,
                    relationship_type=RelationshipType.CONTACTS,
                    target_object_id=context.subject_object_id,
                    first_seen=record.first_seen,
                    last_seen=record.last_seen,
                    evidence_refs=(evidence_id,),
                )
            )
    unique = _unique(objects)
    if not unique:
        return AbuseChNormalization()
    return AbuseChNormalization(objects=unique, relationships=tuple(relationships))


# --------------------------------------------------------------------------- #
# Coverage and absence
# --------------------------------------------------------------------------- #


def normalize_coverage(
    context: NormalizationContext,
    *,
    depth: str,
    exact_match: bool,
    returned: int,
    matched: int,
    max_related: int,
) -> AbuseChNormalization:
    """Record what was asked, what came back, and what the answer is worth.

    Two things here matter more than they look.

    ``expiration_horizon_months`` states the API's blind spot on the face of
    every result. ThreatFox drops IOCs from its API after about six months, so a
    miss covers only what is unexpired — and an analyst reading "ThreatFox: no
    record" should not have to know that to interpret it.

    ``discarded_non_matching`` counts records the provider returned that local
    validation rejected. For an address lookup that number is routinely non-zero
    by design, and publishing it is how a loose provider search stays visible
    instead of quietly becoming coverage it never had.
    """
    attributes: dict[str, Any] = {
        "depth": depth,
        "exact_match": exact_match,
        "current_api_only": True,
        "expiration_horizon_months": IOC_EXPIRY_HORIZON_MONTHS,
        "provider_records": returned,
        "matched_records": matched,
        "discarded_non_matching": max(0, returned - matched),
        "max_related": max_related,
    }
    evidence = build_evidence(
        context,
        provider_id=THREATFOX_PROVIDER_ID,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="threatfox_coverage",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
    )
    return AbuseChNormalization(evidence=(evidence,))


def normalize_no_current_record(context: NormalizationContext) -> AbuseChNormalization:
    """Record that ThreatFox answered and had nothing current.

    Context evidence, and nothing else. ThreatFox holds vetted indicators for
    about six months; an absence therefore means "not currently listed", which
    is compatible with having been listed last year and with never having been
    seen at all. Turning that into a benign signal would make an expired
    campaign look like a clean bill of health.
    """
    evidence = build_evidence(
        context,
        provider_id=THREATFOX_PROVIDER_ID,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="threatfox_no_current_record",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={
            "current_record": False,
            "expiration_horizon_months": IOC_EXPIRY_HORIZON_MONTHS,
        },
    )
    return AbuseChNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _malware_association(
    context: NormalizationContext,
    matched: Sequence[tuple[ThreatFoxRecord, ThreatFoxMatch | None]],
    *,
    evidence_id: str,
) -> AbuseChNormalization:
    """The malware families ThreatFox attributes, as objects and links.

    A family is a derived threat object rather than an observable: nobody
    submits "Dridex" for investigation, but knowing an indicator belongs to it
    is often the most useful thing ThreatFox returns.
    """
    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    seen: set[str] = set()
    for record, _ in matched:
        name = record.malware_name
        if name is None or name.lower() in seen:
            continue
        seen.add(name.lower())
        family = IntelObject(
            object_class=ObjectClass.THREAT,
            object_type=IntelObjectType.MALWARE,
            canonical_value=name,
            display_value=name,
        )
        objects.append(family)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.ASSOCIATED_WITH_MALWARE,
                target_object_id=family.id,
                first_seen=record.first_seen,
                last_seen=record.last_seen,
                evidence_refs=(evidence_id,),
            )
        )
    if not objects:
        return AbuseChNormalization()
    return AbuseChNormalization(objects=tuple(objects), relationships=tuple(relationships))


def _infrastructure_object(record: ThreatFoxRecord) -> IntelObject | None:
    """The observable a ThreatFox record names, validated like analyst input.

    An ``ip:port`` record yields the address: TI Recon has no object type for a
    port, and inventing one here would be a data-model decision made in a
    normalizer. The port survives on the evidence instead.
    """
    value = record.ioc
    if value is None:
        return None
    ioc_type = (record.ioc_type or "").lower()

    if ioc_type.startswith("url"):
        return _try(normalize_url, value)
    if ioc_type.startswith("domain"):
        return _try(normalize_domain, value)
    if ioc_type.startswith("ip"):
        host = value.rpartition(":")[0] if ":" in value else value
        return _try(normalize_ip, host)
    if "hash" in ioc_type or ioc_type in {"md5", "sha256"}:
        return _try(normalize_file_hash, value)
    return None


def _file_object(digest: str) -> IntelObject | None:
    return _try(normalize_file_hash, digest)


def _try(factory: Any, value: str) -> IntelObject | None:
    """Build an object, dropping anything the normalizer rejects.

    The same normalizer that validates analyst input validates provider output:
    a value ThreatFox returns is not more trustworthy than one a user typed.
    """
    try:
        built: IntelObject = factory(value)
    except NormalizationError:
        return None
    return built


def _merged(groups: Any) -> list[str]:
    """Every distinct string across several bounded lists, order preserved."""
    merged: list[str] = []
    for group in groups:
        for item in group:
            if item and item not in merged:
                merged.append(item)
    return merged


def _first_flag(values: Any) -> bool | None:
    for value in values:
        if value is not None:
            return bool(value)
    return None


def _earliest(values: Any) -> datetime | None:
    moments = [value for value in values if value is not None]
    return min(moments) if moments else None


def _latest(values: Any) -> datetime | None:
    moments = [value for value in values if value is not None]
    return max(moments) if moments else None


def _unique(objects: Sequence[IntelObject]) -> tuple[IntelObject, ...]:
    """De-duplicate by canonical key, keeping the first occurrence's identity."""
    seen: set[str] = set()
    unique: list[IntelObject] = []
    for item in objects:
        if item.canonical_key in seen:
            continue
        seen.add(item.canonical_key)
        unique.append(item)
    return tuple(unique)
