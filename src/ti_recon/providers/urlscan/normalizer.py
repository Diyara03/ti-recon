"""Turning urlscan scan results into TI Recon models (Task 8).

Pure functions over a parsed result document. No I/O, no clock reads that are
not passed in, so every rule here is testable against a stored fixture.

Three principles run through the module.

**Controlled normalization, not reflection.** A urlscan result is a very large
document — every request the browser made, every header, every cookie. Nothing
here iterates it and invents a field per key: each block has an explicit
allow-list, unknown keys are ignored, and every list is capped, because a
hostile page can make any of them arbitrarily long.

**Facts, not the provider's roll-up.** urlscan reports four verdicts: its own,
an aggregate of third-party engines, community votes, and an ``overall`` that
combines all three. Only the first three become evidence. Normalizing
``overall`` as well would count one provider's opinion twice inside a single
response, which is exactly the vote-counting TI Recon exists to avoid.

**Lineage is not cosmetic.** urlscan's own verdict is first-hand: it judged what
its own browser saw. The engine aggregate is not — those are other vendors'
opinions that urlscan relays, so its origin says so and a fusion layer can never
mistake it for independent corroboration of urlscan's own view.
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
)
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers.urlscan.descriptor import (
    URLSCAN_ORIGIN_PROVIDER,
    URLSCAN_PROVIDER_ID,
    URLSCAN_SOURCE_FAMILY,
)
from ti_recon.providers.urlscan.errors import parse_utc_timestamp

__all__ = [
    "ENGINE_AGGREGATE_FAMILY",
    "MAX_BRANDS",
    "MAX_CATEGORIES",
    "MAX_TAGS",
    "PAGE_METADATA_FIELDS",
    "TASK_METADATA_FIELDS",
    "URLSCAN_ENGINES_ORIGIN",
    "URLSCAN_LINEAGE_GROUP",
    "URLSCAN_PROPERTY_NAMESPACE",
    "URLSCAN_SCAN_UNREADABLE",
    "URLSCAN_VERDICTS_UNREADABLE",
    "NormalizationContext",
    "ScanDocument",
    "UrlscanNormalization",
    "enrich_primary_object",
    "match_scope_for_scan",
    "normalize_page_context",
    "normalize_scan_observation",
    "normalize_verdicts",
]

#: urlscan-specific facts live under one key rather than being spread across
#: ``properties``, so their provenance stays obvious once several providers have
#: contributed to the same object.
URLSCAN_PROPERTY_NAMESPACE: Final[str] = "urlscan"

#: Everything urlscan observed itself is one source and must never be treated as
#: several independent ones.
URLSCAN_LINEAGE_GROUP: Final[str] = f"{URLSCAN_SOURCE_FAMILY}:{URLSCAN_ORIGIN_PROVIDER}"

#: The origin recorded for ``verdicts.engines``.
#:
#: urlscan does not produce those verdicts — it queries third-party blocklists
#: and scanning engines and reports what they said. Recording urlscan as the
#: origin would make its own verdict and a relayed blocklist hit look like two
#: independent sources agreeing. They are not, and
#: :attr:`Evidence.is_relayed` says so because transport and origin differ.
URLSCAN_ENGINES_ORIGIN: Final[str] = "url_scanning_engines"

#: The family a multi-engine aggregate belongs to.
#:
#: Deliberately *not* ``urlscan``. Two providers relaying overlapping sets of
#: blocklists are not independent of each other either, so every such aggregate
#: shares a family and a fusion layer can discount the overlap.
ENGINE_AGGREGATE_FAMILY: Final[str] = "multi_engine_aggregate"

#: The community votes origin. urlscan hosts the votes; its users cast them.
URLSCAN_COMMUNITY_ORIGIN: Final[str] = "urlscan_community"

#: Reported when a verdicts block was present but nothing in it could be read.
URLSCAN_VERDICTS_UNREADABLE: Final[str] = "URLSCAN_VERDICTS_UNREADABLE"

#: Reported when a result document had no usable scan metadata at all.
URLSCAN_SCAN_UNREADABLE: Final[str] = "URLSCAN_SCAN_UNREADABLE"

#: Caps on provider-controlled lists. A page chooses its own categories, brands
#: and tags only indirectly, but a compromised or hostile scan target should not
#: be able to grow a piece of evidence without bound.
MAX_CATEGORIES: Final[int] = 20
MAX_BRANDS: Final[int] = 10
MAX_TAGS: Final[int] = 20

#: Longest single string kept from the document.
_MAX_TEXT: Final[int] = 2048
#: Shorter bound for label-like values (a server banner, a country code).
_MAX_LABEL: Final[int] = 200

#: Allow-listed metadata from the ``page`` block: what the browser ended up on.
PAGE_METADATA_FIELDS: Final[tuple[str, ...]] = (
    "url",
    "domain",
    "ip",
    "asn",
    "asnname",
    "country",
    "city",
    "server",
    "mimeType",
    "status",
    "title",
    "tlsIssuer",
    "tlsValidFrom",
    "tlsValidDays",
    "tlsAgeDays",
    "redirected",
    "umbrellaRank",
)

#: Allow-listed metadata from the ``task`` block: what was submitted, and how.
TASK_METADATA_FIELDS: Final[tuple[str, ...]] = (
    "url",
    "domain",
    "time",
    "method",
    "source",
    "visibility",
    "tags",
    "uuid",
)


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Everything evidence needs that does not come from the scan document.

    ``now`` is passed in rather than read, so normalization stays a pure
    function and its timestamps are deterministic under test. ``match_scope``
    records how precisely this scan applies to the observable that was actually
    submitted — a scan of ``login.example.com`` is exact evidence for that URL
    and same-host evidence for the domain.
    """

    investigation_id: str
    subject_object_id: str
    now: datetime
    match_scope: MatchScope = MatchScope.UNKNOWN
    raw_reference_id: str | None = None


class UrlscanNormalization(FrozenTiReconModel):
    """What one urlscan document normalized into.

    ``degraded`` means a block TI Recon recognizes was present but unreadable.
    The adapter turns that into a ``PARTIAL`` result: the evidence that *did*
    parse is still worth having, and discarding a whole useful scan because one
    optional block changed shape would be the wrong trade.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()
    degraded: bool = False

    def merge(self, other: UrlscanNormalization) -> UrlscanNormalization:
        return UrlscanNormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
            warnings=self.warnings + other.warnings,
            degraded=self.degraded or other.degraded,
        )


class ScanDocument:
    """Defensive reader over one ``/api/v1/result/`` document.

    Every accessor tolerates the field being absent, null or of the wrong type,
    because the document is provider-controlled and partly attacker-influenced:
    a page's title, server banner and detected brands all originate with whoever
    is being investigated.
    """

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self._payload = payload

    def block(self, name: str) -> Mapping[str, Any]:
        value = self._payload.get(name)
        return value if isinstance(value, Mapping) else {}

    def nested(self, *names: str) -> Mapping[str, Any]:
        current: Mapping[str, Any] = self._payload
        for name in names:
            value = current.get(name)
            if not isinstance(value, Mapping):
                return {}
            current = value
        return current

    @property
    def scan_id(self) -> str | None:
        task = self.block("task")
        return text(task.get("uuid"), _MAX_LABEL) or text(self._payload.get("_id"), _MAX_LABEL)

    @property
    def scanned_at(self) -> datetime | None:
        return parse_utc_timestamp(text(self.block("task").get("time"), 64))

    @property
    def page_domain(self) -> str | None:
        return text(self.block("page").get("domain"), 253)

    @property
    def page_ip(self) -> str | None:
        return text(self.block("page").get("ip"), 45)

    @property
    def page_url(self) -> str | None:
        return text(self.block("page").get("url"), _MAX_TEXT)

    @property
    def submitted_url(self) -> str | None:
        return text(self.block("task").get("url"), _MAX_TEXT)

    @property
    def is_empty(self) -> bool:
        return not self.block("task") and not self.block("page")


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def match_scope_for_scan(subject: IntelObject, document: ScanDocument) -> MatchScope:
    """How precisely one scan applies to the observable that was submitted.

    This is the difference between "urlscan saw *this URL* serving a phishing
    kit" and "urlscan saw *something on this IP* serving one". Both are
    evidence; only the first is about the observable itself.
    """
    value = subject.canonical_value
    match subject.object_type:
        case IntelObjectType.URL:
            if document.page_url == value or document.submitted_url == value:
                return MatchScope.EXACT_OBSERVABLE
            return MatchScope.SAME_HOST
        case IntelObjectType.DOMAIN_NAME:
            if document.page_domain == value:
                return MatchScope.SAME_HOST
            if document.page_domain and document.page_domain.endswith(f".{value}"):
                return MatchScope.PARENT_DOMAIN
            # The domain was contacted by the page rather than being the page.
            return MatchScope.CLUSTER
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            return MatchScope.SAME_IP if document.page_ip == value else MatchScope.CLUSTER
        case IntelObjectType.FILE:
            # The observable is a response body the page served, not the page.
            return MatchScope.SAME_HOST
        case _:
            return MatchScope.UNKNOWN


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #


def normalize_verdicts(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Normalize the verdict blocks into separate, correctly-attributed evidence.

    Three pieces at most, each from a different source: urlscan's own judgement,
    the third-party engine aggregate it relays, and its community's votes.
    ``verdicts.overall`` is deliberately skipped — it is urlscan's roll-up of
    the other three, and emitting it too would count the same opinions twice.
    """
    verdicts = document.block("verdicts")
    if not verdicts:
        return UrlscanNormalization()

    results = [
        _urlscan_verdict_evidence(context, document),
        _engine_aggregate_evidence(context, document),
        _community_evidence(context, document),
    ]
    evidence = tuple(item for item in results if item is not None)
    if not evidence:
        return UrlscanNormalization(warnings=(URLSCAN_VERDICTS_UNREADABLE,), degraded=True)
    return UrlscanNormalization(evidence=evidence)


def _urlscan_verdict_evidence(
    context: NormalizationContext, document: ScanDocument
) -> Evidence | None:
    """urlscan's own judgement of what its browser saw.

    First-hand and therefore not relayed. The direction is asymmetric on
    purpose: ``malicious`` points toward malicious, but ``malicious: false``
    points nowhere. urlscan not flagging a page means its heuristics did not
    fire, which is equally true of every phishing kit deployed this morning.
    """
    block = document.nested("verdicts", "urlscan")
    if not block:
        return None
    malicious = flag(block.get("malicious"))
    score = number(block.get("score"))
    if malicious is None and score is None:
        return None

    attributes: dict[str, Any] = {"malicious": bool(malicious)}
    if score is not None:
        attributes["score"] = score
    categories = string_list(block.get("categories"), MAX_CATEGORIES, _MAX_LABEL)
    if categories:
        attributes["categories"] = categories
    brands = brand_names(block.get("brands"))
    if brands:
        # A detected brand on a domain that is not that brand's is the single
        # most useful phishing signal urlscan produces, so it travels with the
        # verdict rather than being buried in page context.
        attributes["brands"] = brands
    tags = string_list(block.get("tags"), MAX_TAGS, _MAX_LABEL)
    if tags:
        attributes["tags"] = tags

    return _evidence(
        context,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="urlscan_verdict",
        effect=(EvidenceEffect.SUPPORTS_MALICIOUS if malicious else EvidenceEffect.CONTEXT_ONLY),
        attributes=attributes,
        observed_at=document.scanned_at,
    )


def _engine_aggregate_evidence(
    context: NormalizationContext, document: ScanDocument
) -> Evidence | None:
    """Third-party engine results, as exactly one relayed signal.

    One piece of evidence, never one per engine: a multi-engine aggregate is a
    single source that summarizes many opinions, and splitting it would let one
    provider's roll-up masquerade as dozens of independent confirmations.

    As with every aggregate in TI Recon, only flagging points somewhere. "Zero
    of ninety engines flagged it" is not evidence of safety — for most engines
    it only means "not in my database".
    """
    block = document.nested("verdicts", "engines")
    if not block:
        return None
    flagged = count(block.get("maliciousTotal"))
    total = count(block.get("enginesTotal"))
    malicious_engines = string_list(block.get("malicious"), MAX_TAGS, _MAX_LABEL)
    benign_engines = string_list(block.get("benign"), MAX_TAGS, _MAX_LABEL)
    if flagged is None and total is None and not malicious_engines:
        return None
    if flagged is None:
        flagged = len(malicious_engines)

    attributes: dict[str, Any] = {"malicious_total": flagged}
    if total is not None:
        attributes["engines_total"] = total
    if malicious_engines:
        # Named so an analyst can see *which* blocklist fired; still one signal.
        attributes["malicious_engines"] = malicious_engines
    if benign_engines:
        attributes["benign_engines"] = benign_engines
    score = number(block.get("score"))
    if score is not None:
        attributes["score"] = score

    return _evidence(
        context,
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        claim_type="urlscan_engine_aggregate",
        effect=(EvidenceEffect.SUPPORTS_MALICIOUS if flagged > 0 else EvidenceEffect.CONTEXT_ONLY),
        attributes=attributes,
        observed_at=document.scanned_at,
        origin_provider=URLSCAN_ENGINES_ORIGIN,
        source_family=ENGINE_AGGREGATE_FAMILY,
        lineage_group_id=f"{ENGINE_AGGREGATE_FAMILY}:{URLSCAN_ENGINES_ORIGIN}",
    )


def _community_evidence(context: NormalizationContext, document: ScanDocument) -> Evidence | None:
    """Community votes, recorded and attributed to the community.

    Votes are the weakest thing urlscan reports and the easiest to influence, so
    they are relayed evidence with their own origin, and benign votes carry no
    direction: TI Recon requires an observation or an authority to support
    "benign", never a show of hands.
    """
    block = document.nested("verdicts", "community")
    if not block:
        return None
    votes_malicious = count(block.get("votesMalicious"))
    votes_benign = count(block.get("votesBenign"))
    if votes_malicious is None and votes_benign is None:
        return None

    attributes: dict[str, Any] = {
        "votes_malicious": votes_malicious or 0,
        "votes_benign": votes_benign or 0,
    }
    score = number(block.get("score"))
    if score is not None:
        attributes["score"] = score

    return _evidence(
        context,
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        claim_type="urlscan_community_votes",
        effect=(
            EvidenceEffect.SUPPORTS_MALICIOUS
            if (votes_malicious or 0) > 0
            else EvidenceEffect.CONTEXT_ONLY
        ),
        attributes=attributes,
        observed_at=document.scanned_at,
        origin_provider=URLSCAN_COMMUNITY_ORIGIN,
        lineage_group_id=f"{URLSCAN_SOURCE_FAMILY}:{URLSCAN_COMMUNITY_ORIGIN}",
    )


# --------------------------------------------------------------------------- #
# The scan itself
# --------------------------------------------------------------------------- #


def normalize_scan_observation(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Record that this scan happened, and what the browser landed on.

    A direct observation with no direction: "urlscan visited this URL at this
    time and got this status from this server" is a fact about the page, not an
    opinion about it. Direction belongs to the verdict evidence.
    """
    if document.is_empty:
        return UrlscanNormalization(warnings=(URLSCAN_SCAN_UNREADABLE,), degraded=True)

    attributes: dict[str, Any] = {}
    scan_id = document.scan_id
    if scan_id:
        attributes["scan_id"] = scan_id
    for name in TASK_METADATA_FIELDS:
        value = scalar(document.block("task").get(name))
        if value is not None and name != "uuid":
            attributes[f"task_{_snake(name)}"] = value
    for name in ("url", "domain", "ip", "status", "server", "mimeType", "title", "redirected"):
        value = scalar(document.block("page").get(name))
        if value is not None:
            attributes[f"page_{_snake(name)}"] = value

    if len(attributes) <= 1:
        return UrlscanNormalization(warnings=(URLSCAN_SCAN_UNREADABLE,), degraded=True)

    evidence = _evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="urlscan_scan_observation",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.scanned_at,
        first_seen=document.scanned_at,
        last_seen=document.scanned_at,
    )
    return UrlscanNormalization(evidence=(evidence,))


def normalize_page_context(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Hosting and TLS context for the page the browser ended on.

    Separate from the scan observation because it describes *infrastructure*
    rather than the visit: an ASN, a country, a certificate issuer. Context
    only — hosting facts point nowhere on their own, and letting "hosted in
    country X" nudge a verdict is how a country becomes a proxy for guilt.
    """
    page = document.block("page")
    if not page:
        return UrlscanNormalization()

    attributes: dict[str, Any] = {}
    for name in ("asn", "asnname", "country", "city", "server", "tlsIssuer"):
        value = text(page.get(name), _MAX_LABEL)
        if value is not None:
            attributes[_snake(name)] = value
    for name in ("tlsValidDays", "tlsAgeDays", "umbrellaRank"):
        value_number = count(page.get(name))
        if value_number is not None:
            attributes[_snake(name)] = value_number
    tls_valid_from = parse_utc_timestamp(text(page.get("tlsValidFrom"), 64))
    if tls_valid_from is not None:
        attributes["tls_valid_from"] = tls_valid_from.isoformat()

    if not attributes:
        return UrlscanNormalization()

    evidence = _evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="urlscan_page_context",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.scanned_at,
    )
    return UrlscanNormalization(evidence=(evidence,))


def enrich_primary_object(submitted: IntelObject, document: ScanDocument) -> IntelObject:
    """Attach stable urlscan facts to the submitted object.

    Only facts about *what the thing is* — where it resolved, who announces
    that address, what the server called itself. Judgements stay in evidence,
    where they have a provenance and a moment of observation that a property
    cannot carry.
    """
    metadata: dict[str, Any] = {}
    page = document.block("page")
    for name in PAGE_METADATA_FIELDS:
        value = scalar(page.get(name))
        if value is not None:
            metadata[_snake(name)] = value
    scan_id = document.scan_id
    if scan_id:
        metadata["last_scan_id"] = scan_id
    scanned_at = document.scanned_at
    if scanned_at is not None:
        metadata["last_scanned_at"] = scanned_at.isoformat()
    if not metadata:
        return submitted

    enriched = submitted.model_copy(deep=True)
    namespace = dict(enriched.properties.get(URLSCAN_PROPERTY_NAMESPACE, {}))
    namespace.update(metadata)
    enriched.properties[URLSCAN_PROPERTY_NAMESPACE] = namespace
    enriched.touch()
    return enriched


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _evidence(
    context: NormalizationContext,
    *,
    evidence_class: EvidenceClass,
    claim_type: str,
    effect: EvidenceEffect,
    attributes: dict[str, Any],
    observed_at: datetime | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    origin_provider: str = URLSCAN_ORIGIN_PROVIDER,
    source_family: str = URLSCAN_SOURCE_FAMILY,
    lineage_group_id: str = URLSCAN_LINEAGE_GROUP,
) -> Evidence:
    """Build one piece of evidence with this provider's fixed provenance.

    ``source_reliability`` and ``information_credibility`` are never set here:
    Admiralty grading is TI Recon policy, not a provider's to claim.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=URLSCAN_PROVIDER_ID,
        origin_provider=origin_provider,
        source_family=source_family,
        match_scope=context.match_scope,
        observed_at=observed_at,
        first_seen=first_seen,
        last_seen=last_seen,
        retrieved_at=context.now,
        lineage_group_id=lineage_group_id,
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
    """A boolean, or ``None`` if urlscan sent something else."""
    return value if isinstance(value, bool) else None


def number(value: Any) -> float | None:
    """A numeric score, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number_value = int(value)
    return number_value if number_value >= 0 else None


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


def brand_names(value: Any) -> list[str]:
    """The names of detected brands, from urlscan's list of brand objects."""
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for entry in value:
        if isinstance(entry, Mapping):
            name = text(entry.get("name"), _MAX_LABEL) or text(entry.get("key"), _MAX_LABEL)
        else:
            name = text(entry, _MAX_LABEL)
        if name is None or name in names:
            continue
        names.append(name)
        if len(names) >= MAX_BRANDS:
            break
    return names


def _snake(name: str) -> str:
    """urlscan's camelCase field names, in the repository's snake_case."""
    out: list[str] = []
    for index, character in enumerate(name):
        if character.isupper() and index:
            out.append("_")
        out.append(character.lower())
    return "".join(out)
