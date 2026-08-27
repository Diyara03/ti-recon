"""Bounded web observations from a urlscan scan (Task 8).

What a browser *did* when it loaded a page: where it was redirected, which hosts
it contacted, which addresses those resolved to, whose network announced them,
and the digests of the bodies it was served. This is urlscan's most distinctive
contribution — nobody else reports it first-hand — and it is also the part of a
result document most directly shaped by whoever is being investigated.

So everything here is bounded and allow-listed. A page can make a thousand
requests to a thousand hostnames; each list has a cap, each value is validated
by the same normalizer that validates analyst input, and anything that fails
validation is dropped rather than trusted.

**What is deliberately never kept.** Request and response *headers*, cookies,
``Set-Cookie`` values, POST bodies, storage contents and console output are all
present in a result document and none of them are read here. They carry session
material belonging to whoever ran the scan, and a stored header can turn an
investigation record into a credential leak. Only the shape of the traffic —
which host, which status, which digest — is normalized.

Relationships are only ever emitted with the evidence that justifies them: a
relationship nothing can explain is how a pivot graph turns into guesswork.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any, Final

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import (
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_url,
)
from ti_recon.providers.urlscan.normalizer import (
    NormalizationContext,
    ScanDocument,
    UrlscanNormalization,
    build_evidence,
    count,
    text,
)

__all__ = [
    "MAX_CONTACTED_ASNS",
    "MAX_CONTACTED_DOMAINS",
    "MAX_CONTACTED_IPS",
    "MAX_REDIRECT_HOPS",
    "MAX_SERVED_HASHES",
    "URLSCAN_REDIRECTS_UNREADABLE",
    "normalize_contacted_infrastructure",
    "normalize_redirect_chain",
    "normalize_served_bodies",
    "normalize_traffic_summary",
]

#: Caps on provider-controlled lists.
#:
#: Generous enough to describe a real page — a news site legitimately contacts
#: dozens of hosts — and small enough that a page designed to be expensive
#: cannot turn one lookup into thousands of objects.
MAX_CONTACTED_DOMAINS: Final[int] = 50
MAX_CONTACTED_IPS: Final[int] = 50
MAX_CONTACTED_ASNS: Final[int] = 20
MAX_SERVED_HASHES: Final[int] = 20

#: A redirect chain longer than this is a loop or a tracking maze; the first
#: hops are what identify the destination, so the tail is dropped and the
#: truncation is recorded rather than hidden.
MAX_REDIRECT_HOPS: Final[int] = 20

#: Reported when a request list was present but no hop could be read from it.
URLSCAN_REDIRECTS_UNREADABLE: Final[str] = "URLSCAN_REDIRECTS_UNREADABLE"

#: Statuses that mean "go here instead".
_REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})

#: Allow-listed counters from the ``stats`` block. Everything else there is
#: either derived from data we do not keep or unbounded.
_TRAFFIC_STAT_FIELDS: Final[tuple[str, ...]] = (
    "uniqIPs",
    "uniqCountries",
    "requests",
    "dataLength",
    "encodedDataLength",
    "securePercentage",
    "IPv6Percentage",
)


# --------------------------------------------------------------------------- #
# Redirects
# --------------------------------------------------------------------------- #


def normalize_redirect_chain(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Where the browser was sent, in order.

    A redirect chain is the single most useful thing urlscan observes: a link in
    an email rarely points at the phishing page directly, and the hops in
    between are the infrastructure worth pivoting on.

    Only the request URL and the redirect status are read from each entry. The
    ``redirectResponse`` block also carries headers and cookies, which are never
    touched.
    """
    hops = _redirect_hops(document)
    truncated = len(hops) > MAX_REDIRECT_HOPS

    steps: list[IntelObject] = []
    for url in hops[:MAX_REDIRECT_HOPS]:
        current = _url_object(url)
        if current is None:
            continue
        if steps and steps[-1].canonical_key == current.canonical_key:
            continue
        steps.append(current)

    if len(steps) < 2:
        # One URL is not a chain, and a chain of nothing is not an observation.
        return UrlscanNormalization()

    attributes: dict[str, Any] = {
        "chain": [step.canonical_value for step in steps],
        "hops": len(steps) - 1,
    }
    if truncated:
        # Recorded, never silent: a chain we cut short must not read as a chain
        # that ended.
        attributes["truncated"] = True

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="urlscan_redirect_chain",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.scanned_at,
    )
    links = tuple(
        Relationship(
            source_object_id=source.id,
            relationship_type=RelationshipType.REDIRECTS_TO,
            target_object_id=target.id,
            first_seen=document.scanned_at,
            last_seen=document.scanned_at,
            evidence_refs=(evidence.id,),
            raw_relationship_type="data.requests.redirectResponse",
        )
        for source, target in pairwise(steps)
    )
    return UrlscanNormalization(
        evidence=(evidence,),
        objects=_unique_objects(steps),
        relationships=links,
    )


def _redirect_hops(document: ScanDocument) -> list[str]:
    """The ordered URLs of the requests that were redirects, plus the landing URL."""
    requests = document.block("data").get("requests")
    if not isinstance(requests, list):
        return []
    hops: list[str] = []
    for entry in requests:
        url = _redirect_source(entry)
        if url is not None and url not in hops:
            hops.append(url)
        if len(hops) > MAX_REDIRECT_HOPS:
            break
    final = document.page_url
    if final and final not in hops:
        hops.append(final)
    return hops if len(hops) > 1 else []


def _redirect_source(entry: Any) -> str | None:
    """The URL of one request, if that request was a redirect."""
    if not isinstance(entry, Mapping):
        return None
    request = entry.get("request")
    if not isinstance(request, Mapping):
        return None
    redirect_response = request.get("redirectResponse")
    if not isinstance(redirect_response, Mapping):
        return None
    status = count(redirect_response.get("status"))
    if status is not None and status not in _REDIRECT_STATUSES:
        return None
    inner = request.get("request")
    if not isinstance(inner, Mapping):
        return None
    return text(inner.get("url"), 2048)


# --------------------------------------------------------------------------- #
# Contacted infrastructure
# --------------------------------------------------------------------------- #


def normalize_contacted_infrastructure(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Every host, address and network the page pulled resources from.

    Context, not accusation. A page contacting a CDN says nothing about either
    party; what it gives an analyst is a set of pivots, each backed by the scan
    that observed it.
    """
    lists = document.block("lists")
    if not lists:
        return UrlscanNormalization()

    domains = _objects_from(lists.get("domains"), normalize_domain, MAX_CONTACTED_DOMAINS)
    ips = _objects_from(lists.get("ips"), normalize_ip, MAX_CONTACTED_IPS)
    asns = _asn_objects(lists.get("asns"), MAX_CONTACTED_ASNS)
    if not domains and not ips and not asns:
        return UrlscanNormalization()

    attributes: dict[str, Any] = {}
    if domains:
        attributes["domains"] = [item.canonical_value for item in domains]
    if ips:
        attributes["ips"] = [item.canonical_value for item in ips]
    if asns:
        attributes["asns"] = [item.canonical_value for item in asns]
    countries = _string_values(lists.get("countries"), MAX_CONTACTED_ASNS, 8)
    if countries:
        attributes["countries"] = countries
    attributes["truncated"] = _was_truncated(lists)

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="urlscan_contacted_infrastructure",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.scanned_at,
    )

    page = _page_object(document)
    relationships: list[Relationship] = []
    if page is not None:
        relationships.extend(
            _links(page, domains, RelationshipType.CONTACTS, evidence, document, "lists.domains")
        )
        # `lists.ips` are the addresses the browser's own requests reached, so the
        # relationship is *contact*, not resolution. A page does not resolve, and
        # writing it as `resolves-to` both misdescribed the observation and put it
        # in the same bucket as passive DNS, whose pivot semantics are quite
        # different — a name that once pointed somewhere versus an address this
        # page actually talked to.
        relationships.extend(
            _links(page, ips, RelationshipType.CONTACTS, evidence, document, "lists.ips")
        )
        relationships.extend(
            _links(page, asns, RelationshipType.BELONGS_TO_ASN, evidence, document, "lists.asns")
        )

    objects = list(domains) + list(ips) + list(asns)
    if page is not None:
        objects.append(page)
    return UrlscanNormalization(
        evidence=(evidence,),
        objects=_unique_objects(objects),
        relationships=tuple(relationships),
    )


def normalize_served_bodies(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """The SHA-256 digests of the bodies the page served.

    A digest is a pivot: the same kit deployed on a hundred domains serves the
    same script, and that is how the hundredth domain is found. The bodies
    themselves are not retrieved here — that is web forensics, and it happens
    only when explicitly asked for.
    """
    digests = _objects_from(
        document.block("lists").get("hashes"), normalize_file_hash, MAX_SERVED_HASHES
    )
    if not digests:
        return UrlscanNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="urlscan_served_bodies",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"sha256": [item.canonical_value for item in digests]},
        observed_at=document.scanned_at,
    )
    page = _page_object(document)
    relationships = (
        tuple(_links(page, digests, RelationshipType.DOWNLOADS, evidence, document, "lists.hashes"))
        if page is not None
        else ()
    )
    objects = list(digests) + ([page] if page is not None else [])
    return UrlscanNormalization(
        evidence=(evidence,),
        objects=_unique_objects(objects),
        relationships=relationships,
    )


def normalize_traffic_summary(
    context: NormalizationContext, document: ScanDocument
) -> UrlscanNormalization:
    """Counters describing the page's traffic — how much, how spread out.

    Kept because "one page, forty hosts, six countries" is a shape worth seeing,
    and dropped into context rather than direction because a busy page is not a
    malicious one.
    """
    stats = document.block("stats")
    if not stats:
        return UrlscanNormalization()
    attributes: dict[str, Any] = {}
    for name in _TRAFFIC_STAT_FIELDS:
        value = count(stats.get(name))
        if value is not None:
            attributes[_snake(name)] = value
    if not attributes:
        return UrlscanNormalization()
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="urlscan_traffic_summary",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.scanned_at,
    )
    return UrlscanNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _objects_from(values: Any, factory: Any, limit: int) -> tuple[IntelObject, ...]:
    """Normalize a provider list into objects, dropping anything invalid.

    The same normalizer that validates analyst input validates provider output:
    a hostname urlscan reports is not more trustworthy than one a user typed.
    """
    if not isinstance(values, list):
        return ()
    objects: list[IntelObject] = []
    seen: set[str] = set()
    for value in values:
        candidate = text(value, 2048)
        if candidate is None:
            continue
        try:
            built = factory(candidate)
        except NormalizationError:
            continue
        if built.canonical_key in seen:
            continue
        seen.add(built.canonical_key)
        objects.append(built)
        if len(objects) >= limit:
            break
    return tuple(objects)


def _asn_objects(values: Any, limit: int) -> tuple[IntelObject, ...]:
    """ASN objects. Derived infrastructure, so never ``OBSERVABLE``."""
    if not isinstance(values, list):
        return ()
    objects: list[IntelObject] = []
    seen: set[str] = set()
    for value in values:
        candidate = text(value, 16)
        if candidate is None:
            continue
        normalized = candidate.upper()
        if not normalized.startswith("AS") or not normalized[2:].isdigit():
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        objects.append(
            IntelObject(
                object_class=ObjectClass.INFRASTRUCTURE,
                object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
                canonical_value=normalized,
                display_value=normalized,
            )
        )
        if len(objects) >= limit:
            break
    return tuple(objects)


def _url_object(value: str) -> IntelObject | None:
    try:
        return normalize_url(value)
    except NormalizationError:
        return None


def _page_object(document: ScanDocument) -> IntelObject | None:
    """The page the browser ended on, as the subject of these relationships."""
    url = document.page_url
    return _url_object(url) if url else None


def _links(
    source: IntelObject,
    targets: Sequence[IntelObject],
    relationship_type: RelationshipType,
    evidence: Evidence,
    document: ScanDocument,
    raw_type: str,
) -> list[Relationship]:
    return [
        Relationship(
            source_object_id=source.id,
            relationship_type=relationship_type,
            target_object_id=target.id,
            first_seen=document.scanned_at,
            last_seen=document.scanned_at,
            evidence_refs=(evidence.id,),
            raw_relationship_type=raw_type,
        )
        for target in targets
        if target.canonical_key != source.canonical_key
    ]


def _string_values(values: Any, limit: int, max_length: int) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        cleaned = text(value, max_length)
        if cleaned is None or cleaned in out:
            continue
        out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _was_truncated(lists: Mapping[str, Any]) -> bool:
    """Whether any list was longer than the cap TI Recon applies to it."""
    caps = {
        "domains": MAX_CONTACTED_DOMAINS,
        "ips": MAX_CONTACTED_IPS,
        "asns": MAX_CONTACTED_ASNS,
    }
    return any(
        isinstance(lists.get(name), list) and len(lists[name]) > cap for name, cap in caps.items()
    )


def _unique_objects(objects: Sequence[IntelObject]) -> tuple[IntelObject, ...]:
    """De-duplicate by canonical key, keeping the first occurrence's identity."""
    seen: set[str] = set()
    unique: list[IntelObject] = []
    for item in objects:
        if item.canonical_key in seen:
            continue
        seen.add(item.canonical_key)
        unique.append(item)
    return tuple(unique)


def _snake(name: str) -> str:
    out: list[str] = []
    for index, character in enumerate(name):
        if character.isupper() and index and not name[index - 1].isupper():
            out.append("_")
        out.append(character.lower())
    return "".join(out)
