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
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
)
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import HASH_HEX_LENGTHS, IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers.gti.client import GTIObject
from ti_recon.providers.gti.descriptor import (
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
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
    "GTI_TIMESTAMP_FIELDS",
    "VERDICT_EFFECTS",
    "ContributingFactor",
    "GTINormalization",
    "NormalizationContext",
    "effect_for_verdict",
    "enrich_primary_object",
    "epoch_to_utc",
    "gti_hashes",
    "gti_metadata",
    "normalize_analysis_stats",
    "normalize_assessment",
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
    "malicious_sandbox_verdict": ContributingFactor(
        "gti.sandbox_verdict.malicious",
        EvidenceEffect.SUPPORTS_MALICIOUS,
        EvidenceClass.DIRECT_OBSERVATION,
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
