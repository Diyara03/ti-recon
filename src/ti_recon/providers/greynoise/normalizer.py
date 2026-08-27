"""Turning GreyNoise answers into TI Recon models (Task 9).

Pure functions over a parsed document. No I/O, no clock reads that are not
passed in, so every rule here is testable against a stored fixture.

Four principles run through the module.

**One provider, one source.** GreyNoise's classification, its tags, its CVE
associations and its Business Services record all come out of the same sensor
network and the same curation team. They are separate *claims* — different
classes, different specificity — but they share a lineage group, so a fusion
layer can never read "classified malicious, tagged Mirai, associated with a CVE"
as three sources agreeing. It is one source saying three things.

**Absence is a coverage fact, never a benign verdict.** ``noise: false``,
``riot: false``, ``found: false`` and a 404 all mean the same thing: GreyNoise
has no record. That is worth writing down — it is exactly what changes when an
address starts scanning — and it is emphatically not evidence of safety. The
sensor fleet is large; it is not everywhere.

**Business Services Intelligence is context, not a second opinion.** GreyNoise
describes BSI as context for triage rather than a general allow-list, and the
scanner classification already carries GreyNoise's assessment. Emitting a
trusted BSI record as benign *evidence* would count one provider's view twice
inside a single response — the exact vote-counting TI Recon exists to avoid — so
BSI is always ``CONTEXT_ONLY``. The trust level is preserved so a future fusion
layer can weigh it properly.

**A CVE association is an observation about traffic.** GreyNoise saying an
address has been seen in activity associated with CVE-2021-44228 means its
sensors saw that traffic *from* the address. It does not mean any target was
compromised, that an exploit succeeded, or that the address hosts malware. So
CVE data is context, and the module says so where it is built.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import normalize_domain
from ti_recon.providers.greynoise.descriptor import (
    GREYNOISE_ORIGIN_PROVIDER,
    GREYNOISE_PROVIDER_ID,
    GREYNOISE_SOURCE_FAMILY,
)
from ti_recon.providers.greynoise.errors import parse_utc_timestamp

__all__ = [
    "CLASSIFICATION_EFFECTS",
    "GREYNOISE_LINEAGE_GROUP",
    "GREYNOISE_NOT_OBSERVED",
    "GREYNOISE_PROPERTY_NAMESPACE",
    "MAX_CVES",
    "MAX_FINGERPRINTS",
    "MAX_PATHS",
    "MAX_PORTS",
    "MAX_TAGS",
    "SCANNER_METADATA_FIELDS",
    "TRUST_LEVEL_MEANINGS",
    "GreyNoiseDocument",
    "GreyNoiseNormalization",
    "NormalizationContext",
    "build_evidence",
    "count",
    "enrich_primary_object",
    "flag",
    "normalize_business_service",
    "normalize_classification",
    "normalize_cve_activity",
    "normalize_network_context",
    "normalize_not_observed",
    "normalize_scanner_observation",
    "normalize_tags",
    "string_list",
    "text",
]

#: GreyNoise-specific facts live under one key on an enriched object rather than
#: being spread across ``properties``, so their provenance stays obvious once
#: several providers have contributed to the same object.
GREYNOISE_PROPERTY_NAMESPACE: Final[str] = "greynoise"

#: Everything GreyNoise reports is one source and must never be treated as
#: several independent ones.
GREYNOISE_LINEAGE_GROUP: Final[str] = f"{GREYNOISE_SOURCE_FAMILY}:{GREYNOISE_ORIGIN_PROVIDER}"

#: Recorded when GreyNoise answered and had no record of the address.
GREYNOISE_NOT_OBSERVED: Final[str] = "GREYNOISE_NOT_OBSERVED"

#: How GreyNoise's scanner classification maps onto TI Recon's direction
#: vocabulary.
#:
#: ``suspicious`` maps to ``SUPPORTS_MALICIOUS`` because the current
#: :class:`~ti_recon.enums.EvidenceEffect` vocabulary is coarse — it records
#: which way a claim points, not how hard it pushes. That is *not* a claim that
#: GreyNoise called the address malicious, and the raw word is always preserved
#: in ``raw_classification`` so nothing downstream has to reconstruct it. A
#: presentation layer that renders "suspicious" as "malicious" is wrong, and the
#: attribute is there precisely so it does not have to.
#:
#: ``benign`` is GreyNoise asserting that the traffic comes from a known-good
#: scanner it has identified — an assertion, not an absence — so it points
#: toward benign. ``unknown`` points nowhere.
CLASSIFICATION_EFFECTS: Final[dict[str, EvidenceEffect]] = {
    "malicious": EvidenceEffect.SUPPORTS_MALICIOUS,
    "suspicious": EvidenceEffect.SUPPORTS_MALICIOUS,
    "benign": EvidenceEffect.SUPPORTS_BENIGN,
    "unknown": EvidenceEffect.CONTEXT_ONLY,
}

#: What a Business Services trust level means, in GreyNoise's own terms.
#:
#: Kept as text alongside the raw level so an analyst reading the evidence does
#: not have to look the scale up, and so nothing downstream is tempted to treat
#: level 3 — dynamic cloud address space that anybody can rent — as though it
#: were level 1.
TRUST_LEVEL_MEANINGS: Final[dict[str, str]] = {
    "1": "service ownership is reasonably trustworthy",
    "2": "common infrastructure that may also carry arbitrary customer activity",
    "3": "dynamic or cloud-hosted address space; not allow-list material",
}

#: Allow-listed metadata from the scanner block. Anything GreyNoise adds later
#: is ignored until it is listed here on purpose.
SCANNER_METADATA_FIELDS: Final[tuple[str, ...]] = (
    "asn",
    "organization",
    "source_country",
    "source_country_code",
    "source_city",
    "region",
    "rdns",
    "rdns_parent",
    "domain",
    "os",
    "category",
    "datacenter",
    "mobile",
    "sensor_count",
    "sensor_hits",
    "single_destination",
)

#: Caps on provider-controlled lists. GreyNoise reports what it observed, and
#: what it observed is chosen by whoever is scanning: a single address can be
#: tagged dozens of ways and can have requested thousands of paths.
MAX_TAGS: Final[int] = 25
MAX_CVES: Final[int] = 25
MAX_PORTS: Final[int] = 40
MAX_PATHS: Final[int] = 25
MAX_FINGERPRINTS: Final[int] = 10

#: Longest single string kept from the document, and a shorter bound for
#: label-like values (a country code, an organization name).
_MAX_TEXT: Final[int] = 1024
_MAX_LABEL: Final[int] = 200


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Everything evidence needs that does not come from the document.

    ``now`` is passed in rather than read, so normalization stays a pure
    function and its timestamps are deterministic under test.
    """

    investigation_id: str
    subject_object_id: str
    now: datetime
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE
    raw_reference_id: str | None = None


class GreyNoiseNormalization(FrozenTiReconModel):
    """What one GreyNoise document normalized into.

    ``degraded`` means a block TI Recon recognizes was present but unreadable.
    The adapter turns that into a ``PARTIAL`` result: the evidence that *did*
    parse is still worth having, and discarding a whole useful answer because
    one optional block changed shape would be the wrong trade.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()
    degraded: bool = False

    def merge(self, other: GreyNoiseNormalization) -> GreyNoiseNormalization:
        return GreyNoiseNormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
            warnings=self.warnings + other.warnings,
            degraded=self.degraded or other.degraded,
        )


class GreyNoiseDocument:
    """Defensive reader over one GreyNoise IP or Community response.

    Two response shapes reach this class. The full v3 IP context nests its
    fields under ``internet_scanner_intelligence`` and
    ``business_service_intelligence``; the Community response is flat, with
    ``classification``, ``noise`` and ``riot`` at the top level. Rather than
    branch on which endpoint answered, every accessor looks in the nested block
    first and at the top level second — so a Community document, a full
    document and a ``quick`` document all read through the same code and none of
    them can be silently misread as another.

    Every accessor tolerates the field being absent, null or of the wrong type:
    the document is provider-controlled and partly shaped by whoever is
    scanning.
    """

    #: Where the scanner block lives, newest naming first.
    _SCANNER_KEYS: Final[tuple[str, ...]] = ("internet_scanner_intelligence",)
    #: Where the Business Services block lives, newest naming first.
    _BUSINESS_KEYS: Final[tuple[str, ...]] = ("business_service_intelligence",)

    def __init__(self, payload: Mapping[str, Any], *, partial: bool = False) -> None:
        self._payload = payload
        self._partial = partial

    @property
    def partial(self) -> bool:
        """Whether GreyNoise trimmed this document for entitlement reasons."""
        return self._partial

    @property
    def scanner(self) -> Mapping[str, Any]:
        return self._first_block(self._SCANNER_KEYS)

    @property
    def business(self) -> Mapping[str, Any]:
        return self._first_block(self._BUSINESS_KEYS)

    @property
    def ip(self) -> str | None:
        return text(self._payload.get("ip"), 45)

    @property
    def scanner_found(self) -> bool | None:
        """Whether GreyNoise has a scanner record, or ``None`` if it did not say.

        ``noise`` is the Community spelling of the same fact. ``None`` and
        ``False`` are kept apart deliberately: "GreyNoise did not tell us" and
        "GreyNoise has no record" are different, and only the second is a
        coverage statement worth recording.
        """
        return self._flag_from(self.scanner, "found", "noise")

    @property
    def business_found(self) -> bool | None:
        """Whether GreyNoise has a Business Services record for the address."""
        return self._flag_from(self.business, "found", "riot")

    @property
    def classification(self) -> str | None:
        """The raw scanner classification, exactly as GreyNoise worded it."""
        value = self.scanner.get("classification", self._payload.get("classification"))
        cleaned = text(value, 32)
        return cleaned.lower() if cleaned is not None else None

    @property
    def first_seen(self) -> datetime | None:
        return parse_utc_timestamp(
            text(self.scanner.get("first_seen", self._payload.get("first_seen")), 64)
        )

    @property
    def last_seen(self) -> datetime | None:
        return parse_utc_timestamp(
            text(
                self.scanner.get(
                    "last_seen",
                    self.scanner.get("last_seen_timestamp", self._payload.get("last_seen")),
                ),
                64,
            )
        )

    @property
    def metadata(self) -> Mapping[str, Any]:
        value = self.scanner.get("metadata")
        return value if isinstance(value, Mapping) else {}

    @property
    def raw_data(self) -> Mapping[str, Any]:
        value = self.scanner.get("raw_data")
        return value if isinstance(value, Mapping) else {}

    @property
    def has_any_record(self) -> bool:
        """Whether GreyNoise had anything at all to say about the address."""
        return bool(self.scanner_found or self.business_found or self.classification)

    @property
    def is_empty(self) -> bool:
        """Whether the document carried no recognizable GreyNoise fields."""
        return not self.scanner and not self.business and self.classification is None

    def scanner_flag(self, name: str) -> bool | None:
        return self._flag_from(self.scanner, name)

    def scanner_text(self, name: str, max_length: int = _MAX_LABEL) -> str | None:
        return text(self.scanner.get(name, self._payload.get(name)), max_length)

    def business_text(self, name: str, max_length: int = _MAX_LABEL) -> str | None:
        return text(self.business.get(name, self._payload.get(name)), max_length)

    def _first_block(self, keys: tuple[str, ...]) -> Mapping[str, Any]:
        for key in keys:
            value = self._payload.get(key)
            if isinstance(value, Mapping):
                return value
        return {}

    def _flag_from(self, block: Mapping[str, Any], *names: str) -> bool | None:
        for name in names:
            value = flag(block.get(name))
            if value is not None:
                return value
        for name in names:
            value = flag(self._payload.get(name))
            if value is not None:
                return value
        return None


# --------------------------------------------------------------------------- #
# Classification: GreyNoise's own assessment
# --------------------------------------------------------------------------- #


def normalize_classification(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """GreyNoise's scanner classification, as one curated assertion.

    The only piece of GreyNoise evidence that carries a direction. Everything
    else this module produces is context, because everything else describes
    *what was observed* rather than *what GreyNoise concluded* — and a provider
    gets one opinion per response, not one per field.

    The raw word always travels with the evidence. ``suspicious`` and
    ``malicious`` share a direction in the current vocabulary and must not share
    a presentation.
    """
    classification = document.classification
    if classification is None:
        return GreyNoiseNormalization()

    effect = CLASSIFICATION_EFFECTS.get(classification)
    if effect is None:
        # An unrecognized classification is real data about a vocabulary that
        # changed, so it is kept — pointing nowhere, because guessing which way
        # a word we have never seen points is how a verdict gets invented.
        effect = EvidenceEffect.CONTEXT_ONLY

    attributes: dict[str, Any] = {"raw_classification": classification}
    actor = document.scanner_text("actor")
    if actor is not None:
        attributes["actor"] = actor
    found = document.scanner_found
    if found is not None:
        attributes["observed_scanning"] = found
    # GreyNoise's own permalink for the address. Community sends it at the top
    # level and the full context nests it, which ``scanner_text`` handles.
    link = document.scanner_text("link", _MAX_TEXT)
    if link is not None:
        attributes["reference"] = link

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="greynoise_classification",
        effect=effect,
        attributes=attributes,
        first_seen=document.first_seen,
        last_seen=document.last_seen,
        observed_at=document.last_seen,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


def normalize_not_observed(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """Record that GreyNoise answered and had no record of the address.

    Context evidence, and nothing else. GreyNoise not having seen an address
    means its sensors were not contacted by it — which is true of every
    attacker who has not yet scanned a GreyNoise sensor, and of every host that
    only ever attacks one target. Turning that into "likely benign" would make
    a targeted attacker look cleaner than a mass scanner, which is exactly
    backwards.
    """
    attributes: dict[str, Any] = {"observed_scanning": False}
    business_found = document.business_found
    if business_found is not None:
        attributes["known_business_service"] = business_found
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="greynoise_not_observed",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Business Services Intelligence
# --------------------------------------------------------------------------- #


def normalize_business_service(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """The Business Services record for the address, as context only.

    GreyNoise's own framing is that this identifies *common business services*
    an analyst is likely to see in an alert — a mail relay, a public resolver, a
    CDN edge — so that time is not spent investigating them. It is triage
    context, not a safe-list, and level 3 explicitly covers rented cloud address
    space where anybody's workload may be running.

    ``EvidenceClass.CONTEXT`` is used rather than merely setting a context
    effect, because the model then *forbids* this evidence from carrying a
    direction. The guarantee is structural rather than a convention somebody has
    to keep.
    """
    business = document.business
    found = document.business_found
    if not business and found is None:
        return GreyNoiseNormalization()

    attributes: dict[str, Any] = {"found": bool(found)}
    for name in ("name", "category", "reference"):
        value = document.business_text(name)
        if value is not None:
            attributes[name] = value
    for name in ("description", "explanation"):
        value = text(business.get(name), _MAX_TEXT)
        if value is not None:
            attributes[name] = value

    trust_level = _trust_level(business.get("trust_level"))
    if trust_level is not None:
        attributes["trust_level"] = trust_level
        meaning = TRUST_LEVEL_MEANINGS.get(trust_level)
        if meaning is not None:
            attributes["trust_level_meaning"] = meaning

    last_updated = parse_utc_timestamp(text(business.get("last_updated"), 64))
    if last_updated is not None:
        attributes["last_updated"] = last_updated.isoformat()

    if len(attributes) == 1 and not found:
        # "No business-services record" adds nothing on its own; the absence is
        # already carried by the classification or not-observed evidence.
        return GreyNoiseNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="greynoise_business_service",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=last_updated,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


def _trust_level(value: Any) -> str | None:
    """GreyNoise's trust level as a bare digit, however it was sent.

    Reported as a string in some responses and an integer in others; both become
    the same key so the meaning lookup never has to care.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    cleaned = text(value, 8)
    if cleaned is None or not cleaned.isdigit():
        return None
    return cleaned


# --------------------------------------------------------------------------- #
# What the sensors saw
# --------------------------------------------------------------------------- #


def normalize_scanner_observation(
    context: NormalizationContext,
    document: GreyNoiseDocument,
    *,
    include_sensor_detail: bool = True,
) -> GreyNoiseNormalization:
    """What GreyNoise's sensors actually observed, with no direction attached.

    First-hand observation: ports touched, paths requested, whether the traffic
    is spoofable, whether the source is a VPN exit or a Tor node. All facts
    about the traffic. Direction belongs to the classification evidence, and
    duplicating it here would be one provider voting twice.

    ``include_sensor_detail`` selects whether the bulky part of the document —
    ports, requested paths and client fingerprints — is normalized. It costs no
    extra request either way: the fields are already in the response, and the
    depth policy decides whether they are worth recording.

    ``spoofable`` deserves its own note: GreyNoise reporting that an address's
    traffic could have been spoofed is a reason to trust the *attribution* less,
    not a reason to trust the address more. It is recorded as the fact it is.
    """
    if not document.scanner and document.classification is None:
        return GreyNoiseNormalization()

    attributes: dict[str, Any] = {}
    for name in ("bot", "vpn", "tor", "spoofable"):
        value = document.scanner_flag(name)
        if value is not None:
            attributes[name] = value
    vpn_service = document.scanner_text("vpn_service")
    if vpn_service is not None:
        attributes["vpn_service"] = vpn_service

    if include_sensor_detail:
        ports = _scan_ports(document.raw_data.get("scan"))
        if ports:
            attributes["ports"] = ports
        paths = _web_paths(document.raw_data.get("web"))
        if paths:
            attributes["web_paths"] = paths
        for name in ("ja3", "ja4", "hassh"):
            fingerprints = _fingerprints(document.raw_data.get(name), name)
            if fingerprints:
                attributes[name] = fingerprints

    for name in ("sensor_count", "sensor_hits"):
        counter = count(document.metadata.get(name))
        if counter is not None:
            attributes[name] = counter

    if not attributes:
        return GreyNoiseNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="greynoise_scanner_observation",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        first_seen=document.first_seen,
        last_seen=document.last_seen,
        observed_at=document.last_seen,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


def _scan_ports(value: Any) -> list[dict[str, Any]]:
    """The ``port``/``protocol`` pairs GreyNoise observed, bounded."""
    if not isinstance(value, list):
        return []
    ports: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        port = count(entry.get("port"))
        protocol = text(entry.get("protocol"), 16)
        if port is None or port > 65535:
            continue
        key = (port, protocol or "")
        if key in seen:
            continue
        seen.add(key)
        item: dict[str, Any] = {"port": port}
        if protocol is not None:
            item["protocol"] = protocol.upper()
        ports.append(item)
        if len(ports) >= MAX_PORTS:
            break
    return ports


def _web_paths(value: Any) -> list[str]:
    """The HTTP paths the address requested, bounded in count and length."""
    if not isinstance(value, Mapping):
        return []
    return string_list(value.get("paths"), MAX_PATHS, _MAX_LABEL)


def _fingerprints(value: Any, key: str) -> list[str]:
    """TLS/SSH client fingerprints, bounded.

    A fingerprint is a pivot — the same scanning tool leaves the same one
    everywhere — and it is a short hex or hash-shaped string, so it is safe to
    keep. GreyNoise nests them as objects on some fields and as bare strings on
    others; both are handled.
    """
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for entry in value:
        candidate = (
            text(entry.get(key) or entry.get("fingerprint"), 128)
            if isinstance(entry, Mapping)
            else text(entry, 128)
        )
        if candidate is None or candidate in found:
            continue
        found.append(candidate)
        if len(found) >= MAX_FINGERPRINTS:
            break
    return found


# --------------------------------------------------------------------------- #
# Where the address lives
# --------------------------------------------------------------------------- #


def normalize_network_context(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """Ownership and geography for the address, plus the pivots they imply.

    Context only, and deliberately so: hosting facts point nowhere on their own,
    and letting "announced from country X" nudge a verdict is how a country
    becomes a proxy for guilt.

    Two relationships come out of this — the ASN that announces the address and
    the reverse-DNS name that points at it — and each references the evidence
    that justifies it, because a relationship nothing can explain is how a pivot
    graph turns into guesswork.
    """
    metadata = document.metadata
    if not metadata:
        return GreyNoiseNormalization()

    attributes: dict[str, Any] = {}
    for name in SCANNER_METADATA_FIELDS:
        value = scalar(metadata.get(name))
        if value is not None:
            attributes[name] = value
    if not attributes:
        return GreyNoiseNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="greynoise_network_context",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.last_seen,
    )

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []

    autonomous_system = _asn_object(metadata.get("asn"))
    if autonomous_system is not None:
        objects.append(autonomous_system)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.BELONGS_TO_ASN,
                target_object_id=autonomous_system.id,
                first_seen=document.first_seen,
                last_seen=document.last_seen,
                evidence_refs=(evidence.id,),
                raw_relationship_type="metadata.asn",
            )
        )

    reverse_name = _domain_object(metadata.get("rdns"))
    if reverse_name is not None:
        objects.append(reverse_name)
        # The name resolves to the address, not the other way round: reverse DNS
        # says "this address answers to this name", and recording the direction
        # backwards would make the pivot graph lie.
        relationships.append(
            Relationship(
                source_object_id=reverse_name.id,
                relationship_type=RelationshipType.RESOLVES_TO,
                target_object_id=context.subject_object_id,
                first_seen=document.first_seen,
                last_seen=document.last_seen,
                evidence_refs=(evidence.id,),
                raw_relationship_type="metadata.rdns",
            )
        )

    return GreyNoiseNormalization(
        evidence=(evidence,),
        objects=tuple(objects),
        relationships=tuple(relationships),
    )


def _asn_object(value: Any) -> IntelObject | None:
    """An ASN object from GreyNoise's ``ASnnnn`` string. Derived infrastructure."""
    candidate = text(value, 16)
    if candidate is None:
        return None
    normalized = candidate.upper()
    if not normalized.startswith("AS") or not normalized[2:].isdigit():
        return None
    return IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value=normalized,
        display_value=normalized,
    )


def _domain_object(value: Any) -> IntelObject | None:
    """A hostname GreyNoise reported, validated exactly like analyst input.

    A reverse-DNS name is chosen by whoever owns the address block, so it is not
    more trustworthy than something a user typed. Anything the normalizer
    rejects is dropped rather than kept.
    """
    candidate = text(value, 253)
    if candidate is None:
        return None
    try:
        return normalize_domain(candidate)
    except NormalizationError:
        return None


# --------------------------------------------------------------------------- #
# Tags and CVE associations
# --------------------------------------------------------------------------- #


def normalize_tags(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """Every tag GreyNoise applied, aggregated into exactly one observation.

    One piece of evidence, never one per tag. Tags are facets of a single
    provider's characterization of the same traffic — "SSH Bruteforcer" and
    "Mirai" on one address are one source describing one behaviour twice — and
    emitting them separately would let a well-tagged address outvote three
    independent providers.
    """
    tags = _tag_names(document.scanner.get("tags"))
    if not tags:
        return GreyNoiseNormalization()

    attributes: dict[str, Any] = {"tags": tags}
    categories = _tag_field(document.scanner.get("tags"), "category")
    if categories:
        attributes["tag_categories"] = categories
    intentions = _tag_field(document.scanner.get("tags"), "intention")
    if intentions:
        attributes["tag_intentions"] = intentions

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="greynoise_tags",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        first_seen=document.first_seen,
        last_seen=document.last_seen,
        observed_at=document.last_seen,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


def _tag_names(value: Any) -> list[str]:
    """Tag names, whether GreyNoise sent objects or bare strings."""
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for entry in value:
        raw = entry.get("name") if isinstance(entry, Mapping) else entry
        name = text(raw, _MAX_LABEL)
        if name is None or name in names:
            continue
        names.append(name)
        if len(names) >= MAX_TAGS:
            break
    return names


def _tag_field(value: Any, field: str) -> list[str]:
    """The distinct values of one field across the tag objects, bounded."""
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        candidate = text(entry.get(field), _MAX_LABEL)
        if candidate is None or candidate in found:
            continue
        found.append(candidate)
        if len(found) >= MAX_TAGS:
            break
    return found


def normalize_cve_activity(
    context: NormalizationContext, document: GreyNoiseDocument
) -> GreyNoiseNormalization:
    """CVEs GreyNoise associates with traffic from this address.

    Context, always. This says GreyNoise's sensors saw activity from the address
    associated with those CVEs. It does not say a target was compromised, that
    an exploit worked, that the address is running malware, or that the address
    is vulnerable itself — a scanner probing for Log4Shell is not a Log4Shell
    victim. ``EvidenceClass.CONTEXT`` makes the model refuse to let this claim
    carry a direction at all.
    """
    cves = _cve_ids(document.scanner.get("cves", document.scanner.get("cve")))
    if not cves:
        return GreyNoiseNormalization()
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="greynoise_cve_activity",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"cves": cves, "association": "observed_scanning_activity"},
        first_seen=document.first_seen,
        last_seen=document.last_seen,
        observed_at=document.last_seen,
    )
    return GreyNoiseNormalization(evidence=(evidence,))


def _cve_ids(value: Any) -> list[str]:
    """CVE identifiers, shape-checked and bounded.

    Validated rather than passed through: a CVE id is a pivot key, and a value
    that is not one has no business being stored as one.
    """
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for entry in value:
        candidate = text(entry.get("id") if isinstance(entry, Mapping) else entry, 32)
        if candidate is None:
            continue
        normalized = candidate.upper()
        head, _, tail = normalized.partition("-")
        year, _, sequence = tail.partition("-")
        if head != "CVE" or not year.isdigit() or not sequence.isdigit():
            continue
        if normalized in found:
            continue
        found.append(normalized)
        if len(found) >= MAX_CVES:
            break
    return found


# --------------------------------------------------------------------------- #
# The submitted object
# --------------------------------------------------------------------------- #


def enrich_primary_object(submitted: IntelObject, document: GreyNoiseDocument) -> IntelObject:
    """Attach stable GreyNoise facts to the submitted address.

    Only facts about *what the thing is* — who announces it, where it is, what
    it answers to. Judgements stay in evidence, where they have a provenance and
    a moment of observation that a property cannot carry.
    """
    metadata: dict[str, Any] = {}
    for name in ("asn", "organization", "source_country_code", "rdns", "domain", "category"):
        value = scalar(document.metadata.get(name))
        if value is not None:
            metadata[name] = value
    classification = document.classification
    if classification is not None:
        metadata["classification"] = classification
    found = document.scanner_found
    if found is not None:
        metadata["observed_scanning"] = found
    business_found = document.business_found
    if business_found is not None:
        metadata["known_business_service"] = business_found
    last_seen = document.last_seen
    if last_seen is not None:
        metadata["last_seen"] = last_seen.isoformat()
    if not metadata:
        return submitted

    enriched = submitted.model_copy(deep=True)
    namespace = dict(enriched.properties.get(GREYNOISE_PROPERTY_NAMESPACE, {}))
    namespace.update(metadata)
    enriched.properties[GREYNOISE_PROPERTY_NAMESPACE] = namespace
    enriched.touch()
    return enriched


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def build_evidence(
    context: NormalizationContext,
    *,
    evidence_class: EvidenceClass,
    claim_type: str,
    effect: EvidenceEffect,
    attributes: dict[str, Any],
    observed_at: datetime | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> Evidence:
    """Build one piece of evidence with this provider's fixed provenance.

    Origin, family and lineage group are not parameters. Everything GreyNoise
    reports is first-hand and belongs to one lineage group, and making that
    overridable would be an invitation to split one provider into several.

    ``source_reliability`` and ``information_credibility`` are never set here:
    Admiralty grading is TI Recon policy, not a provider's to claim.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=GREYNOISE_PROVIDER_ID,
        origin_provider=GREYNOISE_ORIGIN_PROVIDER,
        source_family=GREYNOISE_SOURCE_FAMILY,
        match_scope=context.match_scope,
        observed_at=observed_at,
        first_seen=first_seen,
        last_seen=last_seen,
        retrieved_at=context.now,
        lineage_group_id=GREYNOISE_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def text(value: Any, max_length: int) -> str | None:
    """A bounded, control-character-free string, or ``None``."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character
        for character in value.strip()
        if ord(character) >= 0x20 and ord(character) != 0x7F
    )[:max_length]
    return cleaned or None


def scalar(value: Any) -> Any:
    """A JSON scalar safe to store: bounded text, a number, or a bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return text(value, _MAX_TEXT)
    if isinstance(value, Sequence):
        items = string_list(value, MAX_TAGS, _MAX_LABEL)
        return items or None
    return None


def flag(value: Any) -> bool | None:
    """A boolean, or ``None`` if GreyNoise sent something else."""
    return value if isinstance(value, bool) else None


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    return number if number >= 0 else None


def string_list(value: Any, max_items: int, max_length: int) -> list[str]:
    """A bounded list of bounded strings, skipping anything else."""
    if not isinstance(value, list):
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
