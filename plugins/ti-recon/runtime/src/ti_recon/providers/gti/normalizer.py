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

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
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
from ti_recon.models.intel_object import HASH_HEX_LENGTHS, IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers.gti.client import GTIObject, GTIRelationshipDescriptor
from ti_recon.providers.gti.descriptor import (
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
)
from ti_recon.providers.gti.relationships import (
    Direction,
    GTIRelationshipSpec,
    TargetKind,
)

__all__ = [
    "ANALYSIS_STAT_FIELDS",
    "CONTRIBUTING_FACTORS",
    "GTI_ANALYSIS_STATS_UNREADABLE",
    "GTI_ASSESSMENT_UNAVAILABLE",
    "GTI_ASSESSMENT_UNREADABLE",
    "GTI_LINEAGE_GROUP",
    "GTI_METADATA_FIELDS",
    "GTI_PROPERTY_NAMESPACE",
    "GTI_THREAT_SEVERITY_UNREADABLE",
    "GTI_TIMESTAMP_FIELDS",
    "GTI_UNRESOLVABLE_RELATED_ITEM",
    "THREAT_SEVERITY_DATA_FIELDS",
    "VERDICT_EFFECTS",
    "ContributingFactor",
    "GTINormalization",
    "NormalizationContext",
    "RelatedItem",
    "effect_for_verdict",
    "enrich_primary_object",
    "epoch_to_utc",
    "gti_hashes",
    "gti_metadata",
    "normalize_analysis_stats",
    "normalize_assessment",
    "normalize_file_behavior",
    "normalize_inline_relationships",
    "normalize_related_items",
    "normalize_sandbox_verdicts",
    "normalize_threat_severity",
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


# --------------------------------------------------------------------------- #
# Provenance and lineage
# --------------------------------------------------------------------------- #

#: Every signal GTI produces shares one lineage group.
#:
#: This is the whole point of lineage. A GTI assessment, its contributing
#: factors and its aggregated analysis statistics are *parts of one source* —
#: including the Mandiant-curated components, which are internal to GTI rather
#: than a second opinion about it. Giving any of them a distinct group would let
#: a future fusion layer read one provider's internal reasoning as several
#: independent providers agreeing, which is exactly the inflated-confidence
#: mistake the model exists to prevent.
GTI_LINEAGE_GROUP: Final[str] = f"{GTI_SOURCE_FAMILY}:{GTI_ORIGIN_PROVIDER}"

#: Reported when GTI returned an object with no assessment block at all.
#: Common and benign: an account's entitlement, or simply no assessment yet.
#: Recorded rather than guessed about — nothing here infers *why*.
GTI_ASSESSMENT_UNAVAILABLE: Final[str] = "GTI_ASSESSMENT_UNAVAILABLE"

#: Reported when an assessment block was present but could not be read.
GTI_ASSESSMENT_UNREADABLE: Final[str] = "GTI_ASSESSMENT_UNREADABLE"

#: Reported when analysis statistics were present but unusable.
GTI_ANALYSIS_STATS_UNREADABLE: Final[str] = "GTI_ANALYSIS_STATS_UNREADABLE"

#: Reported when a ``threat_severity`` block was present but unusable.
GTI_THREAT_SEVERITY_UNREADABLE: Final[str] = "GTI_THREAT_SEVERITY_UNREADABLE"


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Everything evidence needs that does not come from the GTI object.

    ``now`` is passed in rather than read, so normalization stays a pure
    function and its timestamps are deterministic under test.
    """

    investigation_id: str
    subject_object_id: str
    now: datetime
    raw_reference_id: str | None = None


class GTINormalization(FrozenTiReconModel):
    """What one GTI response normalized into.

    ``degraded`` means a field TI Recon recognizes was present but unreadable.
    The adapter turns that into a ``PARTIAL`` result: the evidence that *did*
    parse is still worth having, and discarding a whole useful response because
    one optional attribute changed shape would be the wrong trade.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()
    degraded: bool = False

    def merge(self, other: GTINormalization) -> GTINormalization:
        return GTINormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
            warnings=self.warnings + other.warnings,
            degraded=self.degraded or other.degraded,
        )


# --------------------------------------------------------------------------- #
# gti_assessment
# --------------------------------------------------------------------------- #

#: How a GTI verdict maps onto an evidence direction.
#:
#: Two mappings matter and are easy to get wrong:
#:
#: * ``VERDICT_SUSPICIOUS`` points the same way as malicious, because a
#:   suspicious verdict is a concern rather than a neutral observation. The raw
#:   verdict is preserved in the attributes so a fusion layer can weigh
#:   "suspicious" less heavily than "malicious" — the direction is shared, the
#:   strength is not.
#: * ``VERDICT_UNDETECTED`` is **not** benign. It means nothing flagged the
#:   object, which is also true of every threat nobody has caught yet. Treating
#:   it as evidence of safety is how a fresh sample gets waved through.
VERDICT_EFFECTS: Final[dict[str, EvidenceEffect]] = {
    "VERDICT_MALICIOUS": EvidenceEffect.SUPPORTS_MALICIOUS,
    "VERDICT_SUSPICIOUS": EvidenceEffect.SUPPORTS_MALICIOUS,
    "VERDICT_BENIGN": EvidenceEffect.SUPPORTS_BENIGN,
    "VERDICT_UNDETECTED": EvidenceEffect.CONTEXT_ONLY,
    "VERDICT_UNKNOWN": EvidenceEffect.CONTEXT_ONLY,
}


def effect_for_verdict(verdict: str | None) -> EvidenceEffect:
    """The direction a GTI verdict points.

    An unrecognized or absent verdict is directionless rather than guessed at:
    a future verdict name must not accidentally inherit "malicious".
    """
    if verdict is None:
        return EvidenceEffect.CONTEXT_ONLY
    return VERDICT_EFFECTS.get(verdict, EvidenceEffect.CONTEXT_ONLY)


@dataclass(frozen=True, slots=True)
class ContributingFactor:
    """How one recognized contributing factor becomes evidence."""

    claim_type: str
    effect: EvidenceEffect
    evidence_class: EvidenceClass


#: The controlled normalization table for assessment contributing factors.
#:
#: Only recognized factors become evidence. Nothing iterates the block and
#: invents a claim per key: GTI adds factors over time, and an unrecognized
#: boolean turned into directional evidence would be a guess with real
#: consequences. Unrecognized factor *names* are recorded on the parent
#: assessment instead, so adding one later is a table entry rather than an
#: archaeology exercise.
CONTRIBUTING_FACTORS: Final[dict[str, ContributingFactor]] = {
    "mandiant_analyst_malicious": ContributingFactor(
        "gti.analyst_determination.malicious",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_analyst_benign": ContributingFactor(
        "gti.analyst_determination.benign",
        EvidenceEffect.SUPPORTS_BENIGN,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_association_actor": ContributingFactor(
        "gti.threat_actor_association",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_association_report": ContributingFactor(
        "gti.threat_report_association",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_association_malware": ContributingFactor(
        "gti.malware_association",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_domain_hijack": ContributingFactor(
        "gti.domain_hijack",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "mandiant_osint": ContributingFactor(
        "gti.osint_association",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    # A sandbox *verdict* is the sandbox's classification of what it watched,
    # not the watching itself: a curated assertion, like Hybrid Analysis's own
    # verdict in Task 12, so that an object-nature explanation (a test artifact
    # every sandbox flags) can account for it. What the sandbox *observed* --
    # contacts, drops -- stays ``DIRECT_OBSERVATION`` in the behaviour records.
    "malicious_sandbox_verdict": ContributingFactor(
        "gti.sandbox_verdict.malicious",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "matched_malicious_yara": ContributingFactor(
        "gti.yara_match.malicious",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    "gti_dtm_alert": ContributingFactor(
        "gti.dtm_alert",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    # Benign-leaning, and deliberately a curated assertion rather than context:
    # "this is known legitimate software" is a positive statement GTI is making,
    # not a neutral observation.
    "legitimate_software": ContributingFactor(
        "gti.legitimate_software",
        EvidenceEffect.SUPPORTS_BENIGN,
        EvidenceClass.CURATED_THREAT_ASSERTION,
    ),
    # Directionless: a widely-seen indicator is false-positive context, and a
    # safebrowsing or category label means different things per value, so the
    # value is preserved and the direction is left to the fusion layer.
    "pervasive_indicator": ContributingFactor(
        "gti.pervasive_indicator",
        EvidenceEffect.CONTEXT_ONLY,
        EvidenceClass.CONTEXT,
    ),
    "safebrowsing_verdict": ContributingFactor(
        "gti.safebrowsing_verdict",
        EvidenceEffect.CONTEXT_ONLY,
        EvidenceClass.CONTEXT,
    ),
    "normalised_categories": ContributingFactor(
        "gti.normalised_categories",
        EvidenceEffect.CONTEXT_ONLY,
        EvidenceClass.CONTEXT,
    ),
}

#: Factor keys that are scores rather than assertions. Kept on the parent
#: assessment: a number is not a claim with a direction.
_SCORE_FACTORS: Final[frozenset[str]] = frozenset({"mandiant_confidence_score"})


def normalize_assessment(context: NormalizationContext, gti_object: GTIObject) -> GTINormalization:
    """Normalize ``gti_assessment`` into one core claim plus recognized factors.

    The assessment is a *curated threat assertion*: GTI's own judgement, not an
    aggregation of other vendors' opinions. That stays true whatever the verdict
    — an "undetected" assessment is still GTI having looked — so the class is
    constant and only the effect carries direction.

    ``threat_score`` is preserved verbatim and never converted into a TI Recon
    risk score. They are different quantities on different scales owned by
    different layers, and silently equating them would put a provider's number
    where an engine's conclusion belongs.
    """
    block = gti_object.mapping("gti_assessment")
    if not block:
        return GTINormalization(warnings=(GTI_ASSESSMENT_UNAVAILABLE,))

    verdict = _nested_value(block, "verdict")
    if verdict is not None and not isinstance(verdict, str):
        # A present-but-unreadable verdict is the one thing worth degrading for:
        # the direction of the whole assessment depends on it.
        return GTINormalization(warnings=(GTI_ASSESSMENT_UNREADABLE,), degraded=True)

    attributes: dict[str, Any] = {"verdict": verdict}
    severity = _nested_value(block, "severity")
    if severity is not None:
        attributes["severity"] = _plain(severity)
    threat_score = _nested_value(block, "threat_score")
    if threat_score is not None:
        # Preserved as GTI's own quantity. Not a TI Recon risk score.
        attributes["threat_score"] = _plain(threat_score)
    description = block.get("description")
    if isinstance(description, str) and description.strip():
        attributes["description"] = description.strip()[:2000]

    confidence_raw = gti_object.attribute("gti_confidence_score")
    provider_confidence = _confidence(confidence_raw)
    if confidence_raw is not None:
        # Kept raw as well, so a value outside 0-100 stays traceable rather
        # than vanishing because the model would not accept it.
        attributes["gti_confidence_score"] = _plain(confidence_raw)

    factors = block.get("contributing_factors")
    factor_block = dict(factors) if isinstance(factors, Mapping) else {}
    recognized, unmapped, scores = _split_factors(factor_block)
    if unmapped:
        attributes["unmapped_contributing_factors"] = sorted(unmapped)
    attributes.update(scores)

    assessment = Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="gti_assessment",
        effect=effect_for_verdict(verdict),
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        provider_confidence=provider_confidence,
        # source_reliability and information_credibility are left unset on
        # purpose. Both are Admiralty grades owned by TI Recon policy, and an
        # adapter inventing one would be asserting an analytic judgement it has
        # no basis for. The future fusion layer assigns them.
        match_scope=MatchScope.EXACT_OBSERVABLE,
        last_seen=epoch_to_utc(gti_object.attribute("last_analysis_date")),
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )

    factor_evidence = tuple(
        _factor_evidence(context, assessment, name, value, factor)
        for name, value, factor in recognized
    )
    return GTINormalization(evidence=(assessment, *factor_evidence))


def _split_factors(
    block: Mapping[str, Any],
) -> tuple[list[tuple[str, Any, ContributingFactor]], list[str], dict[str, Any]]:
    """Partition a contributing-factors block into evidence, names and scores.

    A falsy factor produces nothing: ``"mandiant_association_report": false``
    means there is no association, and emitting evidence for it would invert
    the provider's meaning.
    """
    recognized: list[tuple[str, Any, ContributingFactor]] = []
    unmapped: list[str] = []
    scores: dict[str, Any] = {}
    for name, value in sorted(block.items()):
        if name in _SCORE_FACTORS:
            scores[name] = _plain(value)
            continue
        factor = CONTRIBUTING_FACTORS.get(name)
        if factor is None:
            unmapped.append(name)
            continue
        if not value:
            continue
        recognized.append((name, value, factor))
    return recognized, unmapped, scores


def _factor_evidence(
    context: NormalizationContext,
    parent: Evidence,
    name: str,
    value: Any,
    factor: ContributingFactor,
) -> Evidence:
    """One contributing factor, tied to the assessment it came from.

    ``upstream_evidence_refs`` points at the parent assessment and the lineage
    group is shared, so a fusion layer can see these are components of one
    judgement rather than corroborating sources.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=factor.evidence_class,
        claim_type=factor.claim_type,
        effect=factor.effect,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        upstream_evidence_refs=(parent.id,),
        attributes={
            "factor": name,
            "value": _plain(value),
            # Recorded for traceability: several factors are Mandiant-curated
            # components of the GTI assessment rather than VirusTotal signals.
            "origin_component": "mandiant" if name.startswith("mandiant_") else "gti",
        },
        raw_reference_id=context.raw_reference_id,
    )


# --------------------------------------------------------------------------- #
# last_analysis_stats
# --------------------------------------------------------------------------- #

#: The counters GTI reports. Kept as a fixed list so a new key cannot silently
#: change what "malicious" means to the effect calculation below.
ANALYSIS_STAT_FIELDS: Final[tuple[str, ...]] = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "timeout",
    "failure",
    "type-unsupported",
    "confirmed-timeout",
)


def normalize_analysis_stats(
    context: NormalizationContext, gti_object: GTIObject
) -> GTINormalization:
    """Normalize ``last_analysis_stats`` into exactly one aggregated signal.

    One piece of evidence, never one per engine. A multi-engine aggregate is a
    single source that happens to summarize many opinions; splitting it would
    let one provider's roll-up masquerade as dozens of independent
    confirmations.

    The direction is deliberately asymmetric, and this is the important part:

    * any engine flagging malicious or suspicious points toward malicious;
    * **nothing** points toward benign. Not "60 undetected", which is equally
      true of every threat nobody has caught yet, and not "many harmless"
      either, since for most engines that only means "not in my database".

    No count is turned into a score and no threshold is applied — the full
    counters travel in the attributes so the fusion layer can weigh them with
    context this layer does not have.
    """
    stats = gti_object.mapping("last_analysis_stats")
    reputation = gti_object.attribute("reputation")
    if not stats and reputation is None:
        return GTINormalization()

    counters: dict[str, int] = {}
    for field in ANALYSIS_STAT_FIELDS:
        value = stats.get(field)
        if isinstance(value, bool) or not isinstance(value, int | float):
            continue
        counters[field] = int(value)

    if stats and not counters:
        return GTINormalization(warnings=(GTI_ANALYSIS_STATS_UNREADABLE,), degraded=True)

    flagged = counters.get("malicious", 0) + counters.get("suspicious", 0)
    effect = EvidenceEffect.SUPPORTS_MALICIOUS if flagged > 0 else EvidenceEffect.CONTEXT_ONLY

    attributes: dict[str, Any] = dict(counters)
    attributes["engines_total"] = sum(counters.values())
    if reputation is not None:
        # The community reputation score, kept with the aggregate it belongs
        # with rather than as a property of the object.
        attributes["reputation"] = _plain(reputation)

    first_seen = epoch_to_utc(gti_object.attribute("first_submission_date"))
    last_seen = epoch_to_utc(gti_object.attribute("last_analysis_date"))
    if first_seen is not None and last_seen is not None and last_seen < first_seen:
        # Provider timestamps occasionally disagree; an inverted range would be
        # rejected outright, and dropping the weaker one keeps the stronger.
        first_seen = None

    evidence = Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        claim_type="gti_analysis_stats",
        effect=effect,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        first_seen=first_seen,
        last_seen=last_seen,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )
    return GTINormalization(evidence=(evidence,))


def _nested_value(block: Mapping[str, Any], name: str) -> Any:
    """Read a GTI value that may be bare or wrapped in ``{"value": ...}``."""
    raw = block.get(name)
    if isinstance(raw, Mapping):
        return raw.get("value")
    return raw


def _confidence(value: Any) -> float | None:
    """A 0-100 provider confidence, or ``None`` if GTI sent something else."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if 0.0 <= number <= 100.0 else None


# --------------------------------------------------------------------------- #
# sandbox_verdicts
# --------------------------------------------------------------------------- #

#: The verdict categories a sandbox entry may carry, as the API documents them,
#: and the direction each one points. ``harmless`` and ``undetected`` are
#: context, never benign: a sample that sat still may have wanted a click, the
#: wrong OS or a live C2, and a sandbox that saw nothing did not see safety.
SANDBOX_VERDICT_EFFECTS: Final[dict[str, EvidenceEffect]] = {
    "malicious": EvidenceEffect.SUPPORTS_MALICIOUS,
    "suspicious": EvidenceEffect.SUPPORTS_MALICIOUS,
    "harmless": EvidenceEffect.CONTEXT_ONLY,
    "undetected": EvidenceEffect.CONTEXT_ONLY,
}

#: Reported when a ``sandbox_verdicts`` block was present but no entry could be
#: read. Degrading, like an unreadable severity block: a recognized field that
#: changed shape is worth saying so about.
GTI_SANDBOX_VERDICTS_UNREADABLE: Final[str] = "GTI_SANDBOX_VERDICTS_UNREADABLE"

#: The stated confidence (0-100, as the API documents it) below which a
#: sandbox's malicious verdict is not counted as *confident*. The midpoint of
#: the documented range: a sandbox that states less than even confidence in
#: its own verdict has not backed it. This is a counting floor for the
#: consensus test in ``claim_semantics``, never a weight -- a verdict below it
#: keeps its direction and its record, it simply does not count toward
#: consensus. A verdict with no stated confidence is counted separately and
#: never assumed confident.
SANDBOX_CONFIDENCE_FLOOR: Final[int] = 50

#: How many per-sandbox entries, and how many labels per entry, one record keeps.
_MAX_SANDBOXES: Final[int] = 10
_MAX_SANDBOX_LABELS: Final[int] = 5

#: The verdict rank used to pick the record's overall category: the strongest
#: category any sandbox stated. Divergence is preserved beside it, never voted on.
_SANDBOX_VERDICT_RANK: Final[tuple[str, ...]] = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
)


def normalize_sandbox_verdicts(
    context: NormalizationContext, gti_object: GTIObject
) -> GTINormalization:
    """Normalize the file-level ``sandbox_verdicts`` block into **one** record.

    Several sandboxes reporting on one sample are one provider observing one
    sample (Task 12's rule for Hybrid Analysis, applied to GTI's own sandboxes):
    one directional record per file, carrying every sandbox's category,
    confidence and classification labels, bounded, so an analyst can see who
    said what and fusion sees one claim from one origin. Two GTI sandboxes
    agreeing is never two sources.

    The record's direction is the strongest category any sandbox stated --
    ``malicious`` over ``suspicious`` -- and the raw category travels in
    ``verdict`` so the claim layer can keep a hedged verdict weaker than a firm
    one. A malicious verdict beside a harmless one is recorded as
    ``divergent`` rather than resolved.

    Class ``CURATED_THREAT_ASSERTION``: a verdict is the sandbox's judgement
    about what it watched, not the watching itself, so a test artifact that
    every sandbox flags can still be explained as one. Provider confidence is
    the highest confidence among the sandboxes that stated the chosen category.
    """
    block = gti_object.mapping("sandbox_verdicts")
    if not block:
        return GTINormalization()

    entries: list[dict[str, Any]] = []
    for key, raw in sorted(block.items()):
        if not isinstance(raw, Mapping):
            continue
        category = raw.get("category")
        if not isinstance(category, str) or category.strip().lower() not in SANDBOX_VERDICT_EFFECTS:
            continue
        entry: dict[str, Any] = {
            "sandbox_name": _sandbox_name(raw, key),
            "category": category.strip().lower(),
        }
        confidence = _confidence(raw.get("confidence"))
        if confidence is not None:
            entry["confidence"] = confidence
        for field in ("malware_classification", "malware_names"):
            labels = raw.get(field)
            if isinstance(labels, list):
                kept = [
                    str(item).strip() for item in labels if isinstance(item, str) and item.strip()
                ]
                if kept:
                    entry[field] = kept[:_MAX_SANDBOX_LABELS]
        entries.append(entry)
    if not entries:
        return GTINormalization(warnings=(GTI_SANDBOX_VERDICTS_UNREADABLE,), degraded=True)

    counts = {
        name: sum(1 for item in entries if item["category"] == name)
        for name in _SANDBOX_VERDICT_RANK
    }
    verdict = next(name for name in _SANDBOX_VERDICT_RANK if counts[name])
    agreeing = [item for item in entries if item["category"] == verdict]
    confidences = [item["confidence"] for item in agreeing if "confidence" in item]
    classifications = sorted(
        {label for item in agreeing for label in item.get("malware_classification", [])}
    )
    malicious_entries = [item for item in entries if item["category"] == "malicious"]
    malicious_confidences = [
        item["confidence"] for item in malicious_entries if "confidence" in item
    ]
    attributes: dict[str, Any] = {
        "verdict": verdict,
        "sandbox_count": len(entries),
        "malicious_count": counts["malicious"],
        "suspicious_count": counts["suspicious"],
        "harmless_count": counts["harmless"],
        "undetected_count": counts["undetected"],
        # Malicious beside harmless is environment-dependent malware describing
        # itself. Preserved, never averaged.
        "divergent": bool(counts["malicious"] and counts["harmless"]),
        # Counted over every entry, not the bounded list below, so the
        # consensus test in the claim layer sees the whole block.
        "confidence_floor": SANDBOX_CONFIDENCE_FLOOR,
        "confident_malicious_count": sum(
            1 for value in malicious_confidences if value >= SANDBOX_CONFIDENCE_FLOOR
        ),
        "malicious_without_confidence_count": len(malicious_entries) - len(malicious_confidences),
        "sandboxes": entries[:_MAX_SANDBOXES],
    }
    if malicious_confidences:
        attributes["malicious_confidence_min"] = min(malicious_confidences)
        attributes["malicious_confidence_max"] = max(malicious_confidences)
    if classifications:
        attributes["malware_classification"] = classifications[:_MAX_SANDBOX_LABELS]
    if len(entries) > _MAX_SANDBOXES:
        attributes["sandboxes_omitted"] = len(entries) - _MAX_SANDBOXES

    effect = SANDBOX_VERDICT_EFFECTS[verdict]
    evidence = Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=(
            EvidenceClass.CURATED_THREAT_ASSERTION
            if effect is EvidenceEffect.SUPPORTS_MALICIOUS
            else EvidenceClass.CONTEXT
        ),
        claim_type="gti.sandbox_verdicts",
        effect=effect,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        provider_confidence=max(confidences) if confidences else None,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        # No instant: a sandbox verdict carries no timestamp of its own, and the
        # object's last_analysis_date is when engines scanned it, not when a
        # sandbox ran it.
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )
    return GTINormalization(evidence=(evidence,))


def _sandbox_name(entry: Mapping[str, Any], key: str) -> str:
    name = entry.get("sandbox_name")
    if isinstance(name, str) and name.strip():
        return name.strip()[:80]
    return str(key)[:80]


# --------------------------------------------------------------------------- #
# threat_severity
# --------------------------------------------------------------------------- #

#: Named scalars inside ``threat_severity_data`` that TI Recon keeps.
#:
#: An allow-list rather than a copy of the block: GTI adds signals to it over
#: time, and a wholesale copy would grow every piece of evidence without anyone
#: deciding that it should. Unrecognized keys are still reported — by name — so
#: adding one later is a table entry rather than a discovery exercise.
THREAT_SEVERITY_DATA_FIELDS: Final[tuple[str, ...]] = (
    "popular_threat_category",
    "num_gav_detections",
    "belongs_to_bad_collection",
    "can_be_detonated",
    "type_tag",
)

#: ``threat_severity_data`` also carries a family of ``has_bad_*`` booleans, one
#: per relationship GTI found something bad on. They are collected by prefix
#: rather than enumerated: the set changes as GTI adds relationship types, and
#: listing the names we happened to know would silently drop the rest. Only the
#: *names GTI actually sent* are recorded, so nothing is invented either.
_BAD_RELATIONSHIP_PREFIX: Final[str] = "has_bad_"

#: Caps on the two list-valued attributes, so one severity claim cannot grow
#: without bound if GTI expands either family.
_MAX_SEVERITY_LIST: Final[int] = 30


def normalize_threat_severity(
    context: NormalizationContext, gti_object: GTIObject
) -> GTINormalization:
    """Normalize the top-level ``threat_severity`` block into one context claim.

    This is **not** ``gti_assessment.severity``. The two are easy to conflate and
    mean different things:

    * ``gti_assessment`` is GTI's curated judgement, with a verdict that points
      somewhere — it is a threat assertion;
    * ``threat_severity`` is a graded description of *how serious this would be*,
      derived largely from detection and relationship signals, with no verdict
      attached.

    So this is ``CONTEXT``: directionless by construction. A severity rating on
    its own says nothing about whether the observable is malicious, and letting
    ``SEVERITY_HIGH`` imply "malicious" would be the same mistake as reading a
    CVSS score as proof of exploitation. The level travels in the attributes,
    where the fusion layer can weigh it against evidence that *does* have a
    direction.

    Absent for most objects, and absence is not reported — unlike a missing
    assessment, it carries no entitlement signal worth surfacing.
    """
    block = gti_object.mapping("threat_severity")
    if not block:
        return GTINormalization()

    attributes: dict[str, Any] = {}

    level = block.get("threat_severity_level")
    if isinstance(level, str) and level.strip():
        attributes["threat_severity_level"] = level.strip()

    description = block.get("level_description")
    if isinstance(description, str) and description.strip():
        attributes["level_description"] = description.strip()[:2000]

    # GTI sends this one as a string of epoch seconds, unlike the integer epochs
    # elsewhere in the object. Handled locally rather than by relaxing
    # ``epoch_to_utc``, so every other call site keeps rejecting a string as the
    # schema change it would be there.
    analysed_at = _epoch_from_scalar(block.get("last_analysis_date"))
    if analysed_at is not None:
        attributes["last_analysis_date"] = analysed_at.isoformat()

    data = block.get("threat_severity_data")
    data_block = dict(data) if isinstance(data, Mapping) else {}
    attributes.update(_threat_severity_data(data_block))

    if not attributes:
        return GTINormalization(warnings=(GTI_THREAT_SEVERITY_UNREADABLE,), degraded=True)

    evidence = Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="gti_threat_severity",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        last_seen=analysed_at,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )
    return GTINormalization(evidence=(evidence,))


def _threat_severity_data(block: Mapping[str, Any]) -> dict[str, Any]:
    """The bounded, recognized parts of ``threat_severity_data``."""
    attributes: dict[str, Any] = {}
    flagged: list[str] = []
    unmapped: list[str] = []

    for name, value in sorted(block.items()):
        if name in THREAT_SEVERITY_DATA_FIELDS:
            if value is not None:
                attributes[name] = _plain(value)
            continue
        if name.startswith(_BAD_RELATIONSHIP_PREFIX):
            # A false flag means GTI looked and found nothing bad there, which
            # is the common case and not worth recording once per relationship.
            if value:
                flagged.append(name)
            continue
        unmapped.append(name)

    if flagged:
        attributes["bad_relationship_flags"] = flagged[:_MAX_SEVERITY_LIST]
    if unmapped:
        attributes["unmapped_threat_severity_fields"] = unmapped[:_MAX_SEVERITY_LIST]
    return attributes


def _epoch_from_scalar(value: Any) -> datetime | None:
    """An epoch that GTI may send as a number or as a numeric string."""
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate.isdigit():
            return None
        return epoch_to_utc(int(candidate))
    return epoch_to_utc(value)


# --------------------------------------------------------------------------- #
# Relationships
# --------------------------------------------------------------------------- #

#: GTI object types that identify themselves through their id alone, mapped to
#: the TI Recon object type they become.
_DESCRIPTOR_OBJECT_TYPES: Final[dict[str, IntelObjectType]] = {
    "domain": IntelObjectType.DOMAIN_NAME,
    "file": IntelObjectType.FILE,
}

#: Reported when a related item could not be turned into an object. Counted
#: rather than guessed at: inventing identity for a target we cannot name would
#: put a fabricated observable into the graph.
GTI_UNRESOLVABLE_RELATED_ITEM: Final[str] = "GTI_RELATED_ITEM_UNRESOLVABLE"


@dataclass(frozen=True, slots=True)
class RelatedItem:
    """One related thing GTI returned, from either endpoint.

    Descriptors and full objects are normalized through the same path so the
    retrieval choice stays a policy detail rather than leaking into every
    downstream branch.
    """

    object_type: str
    object_id: str
    attributes: Mapping[str, Any]
    context_attributes: Mapping[str, Any]

    @classmethod
    def from_descriptor(cls, descriptor: GTIRelationshipDescriptor) -> RelatedItem:
        return cls(
            object_type=descriptor.object_type,
            object_id=descriptor.object_id,
            attributes={},
            context_attributes=descriptor.context_attributes,
        )

    @classmethod
    def from_object(cls, gti_object: GTIObject) -> RelatedItem:
        return cls(
            object_type=gti_object.object_type,
            object_id=gti_object.object_id,
            attributes=gti_object.attributes,
            context_attributes=gti_object.context_attributes,
        )


def normalize_related_items(
    context: NormalizationContext,
    subject: IntelObject,
    spec: GTIRelationshipSpec,
    items: Sequence[RelatedItem],
) -> GTINormalization:
    """Normalize one relationship's results into objects, links and evidence.

    Every relationship gets its own evidence, because "this file contacted that
    domain" is a distinct factual claim that a later layer has to be able to
    weigh, cite or discount on its own. The evidence is ``CONTEXT_ONLY``: a
    contacted domain is a fact about behaviour, not an accusation, and treating
    every observed connection as incriminating is how legitimate CDN traffic
    becomes a verdict.
    """
    if spec.target_kind is TargetKind.THREAT_OBJECT:
        return _normalize_threat_items(context, subject, spec, items)

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    evidence: list[Evidence] = []
    unresolved = 0

    for item in items:
        related = _related_object(subject, spec, item)
        if related is None:
            unresolved += 1
            continue
        if related.canonical_key == subject.canonical_key:
            # GTI can return the subject as its own relative. Canonical keys are
            # compared rather than object ids: two freshly built objects for the
            # same observable have different ids but one identity, and the
            # resulting self-relationship carries no information and would be
            # rejected by Task 3 anyway.
            continue
        claim = _relationship_evidence(context, subject, spec, item, related)
        direction = _effective_direction(subject, spec)
        source, target = (
            (subject, related) if direction is Direction.OUTBOUND else (related, subject)
        )
        relationships.append(
            Relationship(
                source_object_id=source.id,
                relationship_type=spec.relationship_type,
                target_object_id=target.id,
                evidence_refs=(claim.id,),
                raw_relationship_type=spec.name,
            )
        )
        evidence.append(claim)
        objects.append(related)

    warnings = (GTI_UNRESOLVABLE_RELATED_ITEM,) if unresolved else ()
    return GTINormalization(
        evidence=tuple(evidence),
        objects=tuple(objects),
        relationships=tuple(relationships),
        warnings=warnings,
    )


def normalize_inline_relationships(
    context: NormalizationContext,
    subject: IntelObject,
    gti_object: GTIObject,
    specs: Mapping[str, GTIRelationshipSpec],
    *,
    max_per_relationship: int,
) -> GTINormalization:
    """Normalize relationships GTI already included in the primary response.

    These cost no additional call, so they are taken at every depth — including
    QUICK, whose whole point is to make exactly one request.
    """
    result = GTINormalization()
    if max_per_relationship <= 0:
        return result
    for name, block in sorted(gti_object.relationships.items()):
        spec = specs.get(name)
        if spec is None or not isinstance(block, Mapping):
            continue
        raw = block.get("data")
        entries = raw if isinstance(raw, list) else []
        items = [
            item
            for entry in entries[:max_per_relationship]
            if (item := _item_from_entry(entry)) is not None
        ]
        if items:
            result = result.merge(normalize_related_items(context, subject, spec, items))
    return result


def _item_from_entry(entry: Any) -> RelatedItem | None:
    if not isinstance(entry, Mapping):
        return None
    object_type = entry.get("type")
    object_id = entry.get("id")
    if not isinstance(object_type, str) or not isinstance(object_id, str):
        return None
    attributes = entry.get("attributes")
    context_attributes = entry.get("context_attributes")
    return RelatedItem(
        object_type=object_type,
        object_id=object_id,
        attributes=attributes if isinstance(attributes, Mapping) else {},
        context_attributes=(context_attributes if isinstance(context_attributes, Mapping) else {}),
    )


# --------------------------------------------------------------------------- #
# Threat associations
# --------------------------------------------------------------------------- #

#: GTI collection types that map onto a Task 3 object type. Only malware
#: families do: Task 3 has a ``malware`` object and no threat-actor, campaign or
#: report object, and inventing three new first-class types to hold a GTI id
#: would be a data-model decision made for one provider's convenience. Everything
#: else is recorded as an association claim, which loses nothing an analyst
#: needs and leaves the graph honest.
_NAMED_THREAT_COLLECTIONS: Final[frozenset[str]] = frozenset({"malware-family"})


def _normalize_threat_items(
    context: NormalizationContext,
    subject: IntelObject,
    spec: GTIRelationshipSpec,
    items: Sequence[RelatedItem],
) -> GTINormalization:
    """Normalize curated threat attribution.

    Every item produces an association claim carrying the collection type and
    id. Where GTI also gave a readable name *and* the collection is one Task 3
    models — today only a malware family — the association additionally becomes
    a real object and relationship.

    Names are never invented. A descriptor's id is an internal collection
    identifier, and turning ``collection--1a2b3c`` into a threat actor called
    "1a2b3c" would put a fabricated actor into the graph. Without a name, the
    association is still recorded; it simply stays a claim rather than a node.
    """
    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    evidence: list[Evidence] = []

    for item in items:
        collection_type = _collection_type(item)
        name = item.attributes.get("name")
        readable = name.strip() if isinstance(name, str) and name.strip() else None

        claim = _association_evidence(context, subject, spec, item, collection_type, readable)
        evidence.append(claim)

        if readable is None or collection_type not in _NAMED_THREAT_COLLECTIONS:
            continue
        malware = IntelObject(
            object_class=ObjectClass.THREAT,
            object_type=IntelObjectType.MALWARE,
            canonical_value=readable.lower(),
            display_value=readable,
            properties={GTI_PROPERTY_NAMESPACE: {"collection_id": item.object_id}},
        )
        if malware.canonical_key == subject.canonical_key:
            continue
        objects.append(malware)
        relationships.append(
            Relationship(
                source_object_id=subject.id,
                relationship_type=RelationshipType.ASSOCIATED_WITH_MALWARE,
                target_object_id=malware.id,
                evidence_refs=(claim.id,),
                raw_relationship_type=spec.name,
            )
        )

    return GTINormalization(
        evidence=tuple(evidence),
        objects=tuple(objects),
        relationships=tuple(relationships),
    )


def _collection_type(item: RelatedItem) -> str | None:
    """GTI's own label for what kind of collection this is."""
    value = item.attributes.get("collection_type")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = item.context_attributes.get("collection_type")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _association_evidence(
    context: NormalizationContext,
    subject: IntelObject,
    spec: GTIRelationshipSpec,
    item: RelatedItem,
    collection_type: str | None,
    name: str | None,
) -> Evidence:
    """One curated association claim.

    Directional: GTI tying an observable to a malware family, actor, campaign or
    threat report is an assertion that it is threat-relevant, not neutral
    context. The collection type travels in the attributes so a fusion layer can
    weigh a report mention differently from an actor attribution.
    """
    attributes: dict[str, Any] = {
        "relationship": spec.name,
        "gti_collection_id": item.object_id,
        "gti_target_type": item.object_type,
    }
    if collection_type is not None:
        attributes["gti_collection_type"] = collection_type
    if name is not None:
        attributes["name"] = name
    else:
        # Explicit, so a reader can tell "GTI did not name it" apart from
        # "nobody looked".
        attributes["name_available"] = False
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=subject.id,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type=f"gti.threat_association.{spec.name.replace('_', '-')}",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def _effective_direction(subject: IntelObject, spec: GTIRelationshipSpec) -> Direction:
    """The direction this relationship actually points for this subject.

    Almost always the spec's own direction. DNS resolution is the exception: it
    is always "domain resolves to address", so which end is the source depends
    on which end the investigation started from — GTI serves the same
    relationship from both sides.
    """
    if spec.target_kind is TargetKind.RESOLUTION_OBJECT and subject.object_type in {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
    }:
        return Direction.INBOUND
    return spec.direction


def _related_object(
    subject: IntelObject, spec: GTIRelationshipSpec, item: RelatedItem
) -> IntelObject | None:
    """Build the related observable, or ``None`` if it cannot be identified."""
    match spec.target_kind:
        case TargetKind.IDENTITY:
            return _identity_object(item)
        case TargetKind.URL_OBJECT:
            return _url_object(item)
        case TargetKind.RESOLUTION_OBJECT:
            return _resolution_counterpart(subject, item)
        case TargetKind.THREAT_OBJECT:  # pragma: no cover - routed before here
            return None


def _identity_object(item: RelatedItem) -> IntelObject | None:
    """An object whose descriptor id is its value."""
    value = item.object_id.strip()
    if not value:
        return None
    if item.object_type == "ip_address":
        return _ip_object(value)
    object_type = _DESCRIPTOR_OBJECT_TYPES.get(item.object_type)
    if object_type is None:
        return None
    if object_type is IntelObjectType.FILE:
        return _file_object(value)
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value.lower(),
        display_value=value,
    )


def _ip_object(value: str) -> IntelObject | None:
    """An address object, with the version read from the value itself."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    object_type = IntelObjectType.IPV4_ADDR if address.version == 4 else IntelObjectType.IPV6_ADDR
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=str(address),
        display_value=str(address),
    )


def _file_object(value: str) -> IntelObject | None:
    """A file object keyed by the hash GTI used as its id."""
    digest = value.strip().lower()
    algorithm = next(
        (name for name, length in HASH_HEX_LENGTHS.items() if len(digest) == length),
        None,
    )
    if algorithm is None or any(character not in "0123456789abcdef" for character in digest):
        return None
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {algorithm: digest}},
    )


def _url_object(item: RelatedItem) -> IntelObject | None:
    """A URL object, which needs the ``url`` attribute to exist at all.

    GTI's URL id is an opaque base64 identifier. Without the attribute there is
    no way to recover the URL, and putting the identifier in as if it were one
    would fabricate an observable.
    """
    for source in (item.attributes, item.context_attributes):
        value = source.get("url")
        if isinstance(value, str) and value.strip():
            url = value.strip()
            return IntelObject(
                object_class=ObjectClass.OBSERVABLE,
                object_type=IntelObjectType.URL,
                canonical_value=url,
                display_value=url,
            )
    return None


def _resolution_counterpart(subject: IntelObject, item: RelatedItem) -> IntelObject | None:
    """The other end of a DNS resolution.

    A GTI resolution's id concatenates an address and a hostname, so both are
    read from attributes. Whichever side is not the subject becomes the related
    object.
    """
    address = item.attributes.get("ip_address")
    hostname = item.attributes.get("host_name")
    if subject.object_type is IntelObjectType.DOMAIN_NAME:
        return _ip_object(address.strip()) if isinstance(address, str) else None
    if subject.object_type in {IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}:
        if not isinstance(hostname, str) or not hostname.strip():
            return None
        name = hostname.strip().lower()
        return IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.DOMAIN_NAME,
            canonical_value=name,
            display_value=name,
        )
    return None


def _relationship_evidence(
    context: NormalizationContext,
    subject: IntelObject,
    spec: GTIRelationshipSpec,
    item: RelatedItem,
    related: IntelObject,
) -> Evidence:
    attributes: dict[str, Any] = {
        "relationship": spec.name,
        "gti_target_type": item.object_type,
        "gti_target_id": item.object_id,
        "direction": spec.direction.value,
    }
    if item.context_attributes:
        attributes["context"] = _plain(dict(item.context_attributes))
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=subject.id,
        evidence_class=EvidenceClass.RELATIONSHIP,
        claim_type=f"gti.relationship.{spec.name.replace('_', '-')}",
        # A connection is a behavioural fact, not an accusation. Treating every
        # observed connection as incriminating is how legitimate CDN traffic
        # turns into a verdict.
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


# --------------------------------------------------------------------------- #
# File behaviour (DEEP only)
# --------------------------------------------------------------------------- #

#: Which behaviour-summary lists yield which kind of observable, and the
#: attribute that carries the identity inside each entry.
#:
#: An explicit table again: a sandbox report contains a great deal that TI Recon
#: does not model, and iterating whatever GTI happens to send would turn every
#: schema addition into unreviewed evidence.
_BEHAVIOR_SOURCES: Final[tuple[tuple[str, str, RelationshipType, str], ...]] = (
    ("dns_lookups", "hostname", RelationshipType.CONTACTS, "domain"),
    ("ip_traffic", "destination_ip", RelationshipType.CONTACTS, "ip_address"),
    ("http_conversations", "url", RelationshipType.CONTACTS, "url"),
    ("files_dropped", "sha256", RelationshipType.DROPS, "file"),
)

#: High-level summary fields kept as one context claim rather than expanded.
_BEHAVIOR_SUMMARY_FIELDS: Final[tuple[str, ...]] = (
    "tags",
    "verdicts",
    "calls_highlighted",
    "mutexes_created",
    "processes_created",
    "attack_techniques",
)

#: The behaviour summary's own ``verdicts`` values that state a classification,
#: and how firmly. An explicit table: the API documents ``verdicts`` as a list
#: without enumerating it, so nothing here infers direction from a word it does
#: not recognize. ``MALWARE`` and ``RANSOM`` are the ones GTI's sandboxes state
#: for the samples that matter; the remaining rows are the families GTI's own
#: classification vocabulary uses. Anything else -- including a benign-looking
#: word -- is recorded by name and produces no direction, because a sandbox that
#: saw nothing did not see safety.
BEHAVIOR_VERDICT_STRENGTH: Final[dict[str, str]] = {
    "MALWARE": "asserted",
    "RANSOM": "asserted",
    "TROJAN": "asserted",
    "BACKDOOR": "asserted",
    "STEALER": "asserted",
    "SPYWARE": "asserted",
    "WORM": "asserted",
    "BOT": "asserted",
    "MINER": "asserted",
    "PHISHING": "asserted",
    "SUSPICIOUS": "suspected",
    "GREYWARE": "suspected",
    "ADWARE": "suspected",
    "PUA": "suspected",
}

#: Bounds on the highlights a behaviour verdict carries. Semantic findings
#: only -- a technique id, a rule title, a signature name -- never the process
#: list, the registry accesses or the API calls, which are noise at this level.
_MAX_BEHAVIOR_HIGHLIGHTS: Final[int] = 8
_MAX_HIGHLIGHT_LENGTH: Final[int] = 160

#: Sigma rule levels worth surfacing beside a verdict.
_SIGMA_LEVELS_HIGHLIGHTED: Final[frozenset[str]] = frozenset({"critical", "high"})


def normalize_file_behavior(
    context: NormalizationContext,
    subject: IntelObject,
    summary: Mapping[str, Any],
    *,
    max_per_source: int,
) -> GTINormalization:
    """Normalize an aggregated sandbox behaviour summary.

    What a sample *did* when detonated is a direct observation, so contacted
    infrastructure and dropped files become evidence of class
    ``DIRECT_OBSERVATION`` — someone genuinely watched it happen, unlike a
    curated assertion or a reputation roll-up.

    It is still not a verdict. Contacting a domain during detonation is a fact
    about behaviour; deciding what that means about the sample belongs to the
    fusion layer, so every claim here is ``CONTEXT_ONLY``.

    Only the aggregated summary is read. Individual sandbox reports are not
    fetched: there can be many per sample, they duplicate each other heavily,
    and the summary is what an analyst actually reads.
    """
    if not summary or max_per_source <= 0:
        return GTINormalization()

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    evidence: list[Evidence] = []

    for source_field, identity_field, relationship_type, gti_type in _BEHAVIOR_SOURCES:
        entries = summary.get(source_field)
        if not isinstance(entries, list):
            continue
        seen: set[str] = set()
        for entry in entries:
            if len(seen) >= max_per_source:
                break
            value = entry.get(identity_field) if isinstance(entry, Mapping) else None
            if not isinstance(value, str) or not value.strip():
                continue
            item = RelatedItem(
                object_type=gti_type,
                object_id=value.strip(),
                attributes={"url": value.strip()} if gti_type == "url" else {},
                context_attributes={},
            )
            related = _url_object(item) if gti_type == "url" else _identity_object(item)
            if related is None or related.canonical_key in seen:
                continue
            if related.canonical_key == subject.canonical_key:
                continue
            seen.add(related.canonical_key)

            claim = _behavior_evidence(context, subject, source_field, related, entry)
            evidence.append(claim)
            objects.append(related)
            relationships.append(
                Relationship(
                    source_object_id=subject.id,
                    relationship_type=relationship_type,
                    target_object_id=related.id,
                    evidence_refs=(claim.id,),
                    raw_relationship_type=source_field,
                )
            )

    overview = _behavior_summary_evidence(context, subject, summary)
    if overview is not None:
        evidence.append(overview)
    verdict = _behavior_verdict_evidence(context, subject, summary)
    if verdict is not None:
        evidence.append(verdict)

    return GTINormalization(
        evidence=tuple(evidence),
        objects=tuple(objects),
        relationships=tuple(relationships),
    )


def _behavior_verdict_evidence(
    context: NormalizationContext, subject: IntelObject, summary: Mapping[str, Any]
) -> Evidence | None:
    """The sandboxes' aggregated classification of the sample, as one claim.

    ``verdicts`` is the summary's own statement of what the detonations amount
    to, and ``verdict_confidence`` is how sure it is. That is a classification
    -- a curated assertion, like the file-level sandbox verdicts -- and it is
    the *only* thing in the summary that carries a direction. Techniques,
    signatures, processes and registry keys are what the sample did; they
    travel as bounded highlights beside the verdict so an analyst can see why,
    and they never become evidence on their own, because legitimate software
    creates processes and touches the registry too.
    """
    raw = summary.get("verdicts")
    if not isinstance(raw, list):
        return None
    stated = [item.strip().upper() for item in raw if isinstance(item, str) and item.strip()]
    if not stated:
        return None
    recognized = [item for item in stated if item in BEHAVIOR_VERDICT_STRENGTH]
    unmapped = sorted({item for item in stated if item not in BEHAVIOR_VERDICT_STRENGTH})
    strengths = {BEHAVIOR_VERDICT_STRENGTH[item] for item in recognized}
    strength = "asserted" if "asserted" in strengths else ("suspected" if strengths else None)

    attributes: dict[str, Any] = {"verdicts": stated[:_MAX_SANDBOX_LABELS]}
    if unmapped:
        attributes["unmapped_verdicts"] = unmapped[:_MAX_SANDBOX_LABELS]
    confidence = _confidence(summary.get("verdict_confidence"))
    if confidence is not None:
        attributes["verdict_confidence"] = confidence
    highlights = _behavior_highlights(summary)
    if highlights:
        attributes["highlights"] = highlights
    if strength is None:
        # Words this table does not know, or a benign-looking one. Recorded as
        # context so the analyst can see what the summary said; no direction.
        attributes["verdict"] = "unclassified"
        effect = EvidenceEffect.CONTEXT_ONLY
        evidence_class = EvidenceClass.CONTEXT
    else:
        attributes["verdict"] = strength
        effect = EvidenceEffect.SUPPORTS_MALICIOUS
        evidence_class = EvidenceClass.CURATED_THREAT_ASSERTION

    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=subject.id,
        evidence_class=evidence_class,
        claim_type="gti.behavior.verdict",
        effect=effect,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        provider_confidence=confidence,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def _behavior_highlights(summary: Mapping[str, Any]) -> list[str]:
    """Bounded, semantic reasons drawn from the summary's own findings.

    Three sources, in a fixed order, each bounded: critical and high Sigma
    rule titles, MITRE ATT&CK technique ids with their severity, and signature
    match names. Descriptions are provider-authored text and are truncated;
    nothing here is executed, parsed for structure or matched against.
    """
    found: list[str] = []

    sigma = summary.get("sigma_analysis_results")
    if isinstance(sigma, list):
        for item in sigma:
            if not isinstance(item, Mapping):
                continue
            level = item.get("rule_level")
            title = item.get("rule_title")
            if (
                isinstance(level, str)
                and level.strip().lower() in _SIGMA_LEVELS_HIGHLIGHTED
                and isinstance(title, str)
                and title.strip()
            ):
                found.append(f"sigma {level.strip().lower()}: {title.strip()}")

    techniques = summary.get("mitre_attack_techniques")
    if isinstance(techniques, list):
        for item in techniques:
            if not isinstance(item, Mapping):
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or not identifier.strip():
                continue
            severity = item.get("severity")
            label = f"attack {identifier.strip()}"
            if isinstance(severity, str) and severity.strip():
                label += f" ({severity.strip().lower()})"
            description = item.get("signature_description")
            if isinstance(description, str) and description.strip():
                label += f": {description.strip()}"
            found.append(label)

    signatures = summary.get("signature_matches")
    if isinstance(signatures, list):
        for item in signatures:
            if not isinstance(item, Mapping):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                found.append(f"signature: {name.strip()}")

    return [_bounded_text(item) for item in found[:_MAX_BEHAVIOR_HIGHLIGHTS]]


def _bounded_text(value: str) -> str:
    """One line, control characters removed, length capped."""
    cleaned = "".join(ch for ch in value if ch.isprintable() and ch not in "\r\n")
    return cleaned[:_MAX_HIGHLIGHT_LENGTH]


def _behavior_evidence(
    context: NormalizationContext,
    subject: IntelObject,
    source_field: str,
    related: IntelObject,
    entry: Any,
) -> Evidence:
    attributes: dict[str, Any] = {
        "behavior_source": source_field,
        "target": related.canonical_value,
    }
    if isinstance(entry, Mapping):
        for detail in ("destination_port", "transport_layer_protocol", "path"):
            if detail in entry:
                attributes[detail] = _plain(entry[detail])
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=subject.id,
        # Something actually watched this happen in a sandbox.
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type=f"gti.behavior.{source_field.replace('_', '-')}",
        # A behavioural fact, not an accusation.
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def _behavior_summary_evidence(
    context: NormalizationContext, subject: IntelObject, summary: Mapping[str, Any]
) -> Evidence | None:
    """One context claim carrying the high-level behaviour overview."""
    attributes: dict[str, Any] = {}
    for field in _BEHAVIOR_SUMMARY_FIELDS:
        value = summary.get(field)
        if isinstance(value, list) and value:
            # Bounded: a sandbox can highlight hundreds of calls, and an
            # unbounded list would dwarf the evidence it belongs to.
            attributes[field] = [_plain(item) for item in value[:20]]
    if not attributes:
        return None
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=subject.id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="gti.behavior.summary",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        retrieved_at=context.now,
        lineage_group_id=GTI_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )
