"""Turning URLhaus records into TI Recon models (Task 10).

Pure functions over parsed responses. No I/O, no clock reads that are not passed
in, so every rule here is testable against a stored fixture.

URLhaus answers three questions and they are **not** the same claim
--------------------------------------------------------------------

*An exact URL* that URLhaus tracked was serving malware. That is a direct,
specific assertion about the artifact under investigation, and it supports
malicious at ``EXACT_OBSERVABLE`` scope.

*A host* that URLhaus has tracked malware URLs on is a weaker statement. The host
may be dedicated attacker infrastructure, or it may be a compromised WordPress
site, or shared hosting where one customer of thousands was breached. It supports
malicious at ``SAME_HOST`` scope — something on this host served malware — and
never claims that the host owner is the attacker or that everything on it is
hostile.

*A payload* that URLhaus collected is the case where presence proves the least,
and it gets its own rule below.

Offline is not benign
---------------------

``url_status`` says whether the URL is serving *right now*. An offline malicious
URL is still a malicious URL that was observed distributing malware; the status
is recorded so a freshness-aware fusion layer can weigh it, and it never changes
the direction of the evidence.

Relayed findings stay relayed
-----------------------------

URLhaus repeats VirusTotal detections and Spamhaus/SURBL blocklist statuses. None
of those become an extra malicious signal here: one response would otherwise
produce three votes, two of them belonging to sources TI Recon either queries
directly or has never queried at all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    MatchScope,
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
    relayed_summary,
)
from ti_recon.providers.abusech.family import (
    BLOCKLIST_RELAY_FAMILY,
    BLOCKLIST_RELAY_ORIGIN,
    VIRUSTOTAL_RELAY_FAMILY,
    VIRUSTOTAL_RELAY_ORIGIN,
)
from ti_recon.providers.abusech.values import (
    MAX_LABEL,
    MAX_TEXT,
    count,
    flag,
    hex_digest,
    mapping,
    string_list,
    text,
)
from ti_recon.providers.urlhaus.descriptor import URLHAUS_PROVIDER_ID

__all__ = [
    "BLOCKLIST_FIELDS",
    "MAX_TAGS",
    "PAYLOAD_FINGERPRINT_FIELDS",
    "URL_RECORD_FIELDS",
    "normalize_blocklists",
    "normalize_host_association",
    "normalize_not_tracked",
    "normalize_payload_record",
    "normalize_relayed_virustotal",
    "normalize_url_record",
]

#: Caps on provider-controlled lists.
MAX_TAGS: Final[int] = 20

#: Allow-listed scalar fields from a URL record.
URL_RECORD_FIELDS: Final[tuple[str, ...]] = (
    "id",
    "urlhaus_reference",
    "url_status",
    "host",
    "threat",
    "reporter",
)

#: Allow-listed fingerprint fields from a payload record. Each is a pivot: the
#: same packer, the same import table, the same fuzzy hash across two samples is
#: how a family is recognized.
PAYLOAD_FINGERPRINT_FIELDS: Final[tuple[str, ...]] = (
    "imphash",
    "ssdeep",
    "tlsh",
    "magika",
)

#: The blocklists URLhaus repeats. abuse.ch compiled none of them.
BLOCKLIST_FIELDS: Final[tuple[str, ...]] = ("spamhaus_dbl", "surbl")

#: Blocklist values that mean "not listed". Anything else is treated as a
#: listing, because the vocabulary is the blocklist's and it changes.
_NOT_LISTED: Final[frozenset[str]] = frozenset({"not listed", "not_listed", "unknown", ""})

#: Digest lengths a payload record may carry.
_MD5_LENGTHS: Final[frozenset[int]] = frozenset({32})
_SHA256_LENGTHS: Final[frozenset[int]] = frozenset({64})


# --------------------------------------------------------------------------- #
# An exact URL
# --------------------------------------------------------------------------- #


def normalize_url_record(
    context: NormalizationContext,
    payload: Mapping[str, Any],
    *,
    max_related: int,
) -> AbuseChNormalization:
    """URLhaus tracked this exact URL as a malware-distribution URL.

    The strongest thing URLhaus says, and the only place this module claims
    ``EXACT_OBSERVABLE``: the artifact under investigation is the artifact
    URLhaus recorded.

    ``url_status`` is preserved rather than acted on. An offline URL is a URL
    that *was* serving malware — history, not absolution — and collapsing that
    into "no longer malicious" is exactly the mistake a freshness-aware fusion
    layer exists to avoid making prematurely.
    """
    attributes: dict[str, Any] = {}
    for name in URL_RECORD_FIELDS:
        value = text(payload.get(name), MAX_TEXT)
        if value is not None:
            attributes[name] = value

    date_added = parse_utc_timestamp(payload.get("date_added"))
    last_online = parse_utc_timestamp(payload.get("last_online"))
    if date_added is not None:
        attributes["date_added"] = date_added.isoformat()
    if last_online is not None:
        attributes["last_online"] = last_online.isoformat()

    tags = string_list(payload.get("tags"), MAX_TAGS, MAX_LABEL)
    if tags:
        attributes["tags"] = tags
    reported = flag(payload.get("larted"))
    if reported is not None:
        # Whether URLhaus reported it for takedown. Operational context, not a
        # judgement: an unreported URL is not a less malicious one.
        attributes["reported_for_takedown"] = reported
    takedown = count(payload.get("takedown_time_seconds"))
    if takedown is not None:
        attributes["takedown_time_seconds"] = takedown

    if not attributes:
        return AbuseChNormalization()

    evidence = build_evidence(
        context,
        provider_id=URLHAUS_PROVIDER_ID,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="urlhaus_malware_url",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        attributes=attributes,
        first_seen=date_added,
        last_seen=last_online,
        observed_at=last_online or date_added,
    )

    result = AbuseChNormalization(evidence=(evidence,))
    result = result.merge(_host_link(context, payload.get("host"), evidence.id, date_added))
    return result.merge(
        _served_payloads(context, payload.get("payloads"), evidence.id, max_related=max_related)
    )


# --------------------------------------------------------------------------- #
# A host
# --------------------------------------------------------------------------- #


def normalize_host_association(
    context: NormalizationContext,
    payload: Mapping[str, Any],
    *,
    max_related: int,
) -> AbuseChNormalization:
    """URLhaus has tracked malware URLs on this host.

    Real evidence, deliberately narrower than an exact URL match. The scope is
    ``SAME_HOST``: *something on this host* served malware. The host may be
    dedicated attacker infrastructure, a compromised site, or shared hosting
    where one tenant was breached, and this adapter cannot tell which — so it
    reports the association and lets the scope carry the caveat rather than
    overstating it.

    Every associated URL becomes an object and a relationship, bounded by depth.
    None of them becomes a separate malicious vote: a host with fifty tracked
    URLs is one association, not fifty findings.
    """
    urls = payload.get("urls")
    entries = (
        [entry for entry in urls if isinstance(entry, Mapping)] if isinstance(urls, list) else []
    )
    provider_total = count(payload.get("url_count"))
    if not entries and provider_total is None:
        return AbuseChNormalization()

    kept = entries[:max_related]
    attributes: dict[str, Any] = {
        "normalized_count": len(kept),
        "truncated": len(entries) > len(kept),
    }
    host = text(payload.get("host"), MAX_LABEL)
    if host is not None:
        attributes["host"] = host
    if provider_total is not None:
        attributes["provider_total"] = provider_total
    reference = text(payload.get("urlhaus_reference"), MAX_TEXT)
    if reference is not None:
        attributes["urlhaus_reference"] = reference
    first_seen = parse_utc_timestamp(payload.get("firstseen"))
    if first_seen is not None:
        attributes["firstseen"] = first_seen.isoformat()

    statuses = string_list([text(entry.get("url_status"), 32) for entry in kept], MAX_TAGS, 32)
    if statuses:
        # Which of the tracked URLs are still live. Context for freshness, not a
        # direction: an all-offline host is not thereby clean.
        attributes["url_statuses"] = statuses
    threats = string_list([text(entry.get("threat"), MAX_LABEL) for entry in kept], MAX_TAGS)
    if threats:
        attributes["threats"] = threats

    evidence = build_evidence(
        # Narrowed deliberately: the malicious thing was a URL on this host.
        context.with_scope(MatchScope.SAME_HOST),
        provider_id=URLHAUS_PROVIDER_ID,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="urlhaus_host_malware_association",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        attributes=attributes,
        first_seen=first_seen,
        observed_at=first_seen,
    )

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    for entry in kept:
        target = _object_from(normalize_url, entry.get("url"), MAX_TEXT)
        if target is None:
            continue
        objects.append(target)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.HOSTS,
                target_object_id=target.id,
                first_seen=parse_utc_timestamp(entry.get("date_added")),
                evidence_refs=(evidence.id,),
            )
        )
    return AbuseChNormalization(
        evidence=(evidence,), objects=_unique(objects), relationships=tuple(relationships)
    )


# --------------------------------------------------------------------------- #
# A payload
# --------------------------------------------------------------------------- #


def normalize_payload_record(
    context: NormalizationContext,
    payload: Mapping[str, Any],
    *,
    max_related: int,
) -> AbuseChNormalization:
    """URLhaus collected this file from a URL it was monitoring.

    **Presence alone is context, never a direction — including when a family
    signature is present.**

    URLhaus says so itself: it collects whatever a tracked URL served, and a URL
    that distributed malware last week may serve an installer, an error page or
    a redirect today. The file's provenance is genuinely useful — it came off
    malware-distribution infrastructure — but "was downloaded from a URL URLhaus
    watches" is a statement about where the bytes were found, not about what
    they do.

    A signature *is* preserved when URLhaus has one, because it is the most
    useful pivot on the record. Turning it into a verdict here would be an
    adapter deciding maliciousness on a field it cannot verify; a future fusion
    layer weighs it against MalwareBazaar, GTI and sandbox behaviour, which is
    where that decision belongs.
    """
    attributes: dict[str, Any] = {}
    md5 = hex_digest(payload.get("md5_hash"), lengths=_MD5_LENGTHS)
    sha256 = hex_digest(payload.get("sha256_hash"), lengths=_SHA256_LENGTHS)
    if md5 is not None:
        attributes["md5_hash"] = md5
    if sha256 is not None:
        attributes["sha256_hash"] = sha256

    for name in ("file_type", "signature"):
        value = text(payload.get(name), MAX_LABEL)
        if value is not None:
            attributes[name] = value
    size = count(payload.get("file_size"))
    if size is not None:
        attributes["file_size"] = size
    for name in PAYLOAD_FINGERPRINT_FIELDS:
        value = text(payload.get(name), MAX_LABEL)
        if value is not None:
            attributes[name] = value

    first_seen = parse_utc_timestamp(payload.get("firstseen"))
    last_seen = parse_utc_timestamp(payload.get("lastseen"))
    if first_seen is not None:
        attributes["firstseen"] = first_seen.isoformat()
    if last_seen is not None:
        attributes["lastseen"] = last_seen.isoformat()

    urls = payload.get("urls")
    entries = (
        [entry for entry in urls if isinstance(entry, Mapping)] if isinstance(urls, list) else []
    )
    provider_total = count(payload.get("url_count"))
    if provider_total is not None:
        attributes["url_count"] = provider_total
    kept = entries[:max_related]
    attributes["normalized_count"] = len(kept)
    attributes["truncated"] = len(entries) > len(kept)

    if len(attributes) <= 2:
        return AbuseChNormalization()

    evidence = build_evidence(
        context,
        provider_id=URLHAUS_PROVIDER_ID,
        # An observation about provenance, not an assertion about the file.
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="urlhaus_payload_record",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        first_seen=first_seen,
        last_seen=last_seen,
        observed_at=last_seen or first_seen,
    )

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    for entry in kept:
        source = _object_from(normalize_url, entry.get("url"), MAX_TEXT)
        if source is None:
            continue
        objects.append(source)
        relationships.append(
            Relationship(
                source_object_id=source.id,
                relationship_type=RelationshipType.DOWNLOADS,
                target_object_id=context.subject_object_id,
                first_seen=parse_utc_timestamp(entry.get("firstseen")),
                last_seen=parse_utc_timestamp(entry.get("lastseen")),
                evidence_refs=(evidence.id,),
            )
        )
    return AbuseChNormalization(
        evidence=(evidence,), objects=_unique(objects), relationships=tuple(relationships)
    )


# --------------------------------------------------------------------------- #
# Relayed findings
# --------------------------------------------------------------------------- #


def normalize_relayed_virustotal(
    context: NormalizationContext, payload: Mapping[str, Any]
) -> AbuseChNormalization:
    """VirusTotal detections URLhaus repeats, attributed to VirusTotal.

    Never an independent signal. Google Threat Intelligence is already a direct
    TI Recon provider reading the same upstream data, so a VT count relayed here
    carries VirusTotal's origin *and the same source family a direct GTI result
    carries* — which is what stops one URLhaus response and one GTI lookup being
    counted as two sources agreeing.

    The detection ratio is kept because it is small, useful and now correctly
    attributed. The link is not: it is a URL into another service and nothing
    here follows one.
    """
    block = mapping(payload.get("virustotal"))
    if not block:
        for entry in payload.get("payloads") or []:
            if isinstance(entry, Mapping):
                block = mapping(entry.get("virustotal"))
                if block:
                    break
    if not block:
        return AbuseChNormalization()

    attributes: dict[str, Any] = {"present": True}
    ratio = text(block.get("result"), 32)
    if ratio is not None:
        attributes["detection_ratio"] = ratio
    percent = text(block.get("percent"), 16)
    if percent is not None:
        attributes["detection_percent"] = percent

    evidence = relayed_summary(
        context,
        provider_id=URLHAUS_PROVIDER_ID,
        claim_type="urlhaus_relayed_virustotal",
        origin_provider=VIRUSTOTAL_RELAY_ORIGIN,
        source_family=VIRUSTOTAL_RELAY_FAMILY,
        sources=[VIRUSTOTAL_RELAY_ORIGIN],
        attributes=attributes,
    )
    return AbuseChNormalization(evidence=(evidence,))


def normalize_blocklists(
    context: NormalizationContext, payload: Mapping[str, Any]
) -> AbuseChNormalization:
    """Spamhaus and SURBL statuses URLhaus repeats, attributed to those lists.

    One record for the whole set, never one per list. "URLhaus says malicious,
    Spamhaus says listed, SURBL says listed" is one response, not three sources
    — and abuse.ch compiled neither blocklist.
    """
    block = mapping(payload.get("blacklists"))
    if not block:
        return AbuseChNormalization()

    listings: dict[str, str] = {}
    for name in BLOCKLIST_FIELDS:
        status = text(block.get(name), MAX_LABEL)
        if status is None or status.lower() in _NOT_LISTED:
            continue
        listings[name] = status
    if not listings:
        return AbuseChNormalization()

    evidence = relayed_summary(
        context,
        provider_id=URLHAUS_PROVIDER_ID,
        claim_type="urlhaus_relayed_blocklists",
        origin_provider=BLOCKLIST_RELAY_ORIGIN,
        source_family=BLOCKLIST_RELAY_FAMILY,
        sources=sorted(listings),
        attributes={"listings": listings},
    )
    return AbuseChNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


def normalize_not_tracked(context: NormalizationContext, *, lookup: str) -> AbuseChNormalization:
    """Record that URLhaus answered and had no record.

    Context evidence, and nothing else. URLhaus tracks URLs somebody reported as
    serving malware; an absence means nobody reported this one, which is
    compatible with a distribution URL that went up an hour ago. Turning it into
    a benign signal would make the newest campaign look like the safest.
    """
    evidence = build_evidence(
        context,
        provider_id=URLHAUS_PROVIDER_ID,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="urlhaus_not_tracked",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"tracked": False, "lookup": lookup},
    )
    return AbuseChNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _host_link(
    context: NormalizationContext,
    host: Any,
    evidence_id: str,
    observed_at: datetime | None,
) -> AbuseChNormalization:
    """The host a tracked URL lives on, as an object and a ``hosts`` link."""
    value = text(host, MAX_LABEL)
    if value is None:
        return AbuseChNormalization()
    target = _object_from(normalize_domain, value, MAX_LABEL) or _object_from(
        normalize_ip, value, 45
    )
    if target is None or target.id == context.subject_object_id:
        return AbuseChNormalization()
    link = Relationship(
        source_object_id=target.id,
        relationship_type=RelationshipType.HOSTS,
        target_object_id=context.subject_object_id,
        first_seen=observed_at,
        evidence_refs=(evidence_id,),
    )
    return AbuseChNormalization(objects=(target,), relationships=(link,))


def _served_payloads(
    context: NormalizationContext,
    payloads: Any,
    evidence_id: str,
    *,
    max_related: int,
) -> AbuseChNormalization:
    """The files a tracked URL was observed serving, as bounded pivots.

    Objects and relationships only. Nothing here downloads one, and the
    provenance claim about each file belongs to a payload lookup rather than to
    this URL record.
    """
    if not isinstance(payloads, list):
        return AbuseChNormalization()
    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    for entry in payloads[:max_related]:
        if not isinstance(entry, Mapping):
            continue
        digest = hex_digest(entry.get("response_sha256"), lengths=_SHA256_LENGTHS) or hex_digest(
            entry.get("response_md5"), lengths=_MD5_LENGTHS
        )
        if digest is None:
            continue
        target = _object_from(normalize_file_hash, digest, 64)
        if target is None:
            continue
        objects.append(target)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.DOWNLOADS,
                target_object_id=target.id,
                first_seen=parse_utc_timestamp(entry.get("firstseen")),
                evidence_refs=(evidence_id,),
            )
        )
    if not objects:
        return AbuseChNormalization()
    return AbuseChNormalization(objects=_unique(objects), relationships=tuple(relationships))


def _object_from(factory: Any, value: Any, limit: int) -> IntelObject | None:
    """Build an object, dropping anything the normalizer rejects.

    The same normalizer that validates analyst input validates provider output:
    a URL URLhaus returns is not more trustworthy than one a user typed — and it
    is, by definition, a malware-distribution URL.
    """
    candidate = text(value, limit)
    if candidate is None:
        return None
    try:
        built: IntelObject = factory(candidate)
    except NormalizationError:
        return None
    return built


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
