"""Turning Censys asset observations into TI Recon models (Task 9).

Pure functions over a parsed asset document. No I/O, no clock reads that are not
passed in, so every rule here is testable against a stored fixture.

Four principles run through the module.

**Everything Censys sees is context.** Not one function in this file can produce
a direction. Censys reports exposure: an open port, a visible product version, a
served certificate, a reported CVE. None of those is an accusation. An exposed
RDP service is a risk to its owner, not evidence that its owner is an attacker;
an outdated nginx is not malware; a self-signed certificate is not a crime. So
every piece of evidence built here is ``CONTEXT_ONLY``, and most of it is
``EvidenceClass.CONTEXT`` as well, which makes the model *refuse* to attach a
direction rather than relying on this file to remember not to.

**One scan is one source.** A service, a certificate, a DNS name and a
vulnerability from the same response are four claims from one scan by one
scanner. They share a lineage group, so nothing downstream can read "port 443
open, Let's Encrypt certificate, two DNS names" as three providers agreeing.

**Controlled normalization, not reflection.** A Censys asset document is large
and partly attacker-shaped: a banner is whatever the host chose to send, a
certificate subject is whatever was requested, an HTTP title is whatever the page
says. Nothing here iterates a document and invents a field per key. Each block
has an explicit allow-list, unknown keys are ignored, and every list is capped
with the truncation recorded.

**Raw content is never kept.** Service banners, HTTP bodies, HTTP headers and
HTML titles are all present in a Censys response, and none of them are read.
Banners in particular are a favourite place for a host to put whatever it likes,
and a stored banner turns an investigation record into a channel for it. What is
kept is the *shape* of the exposure — which port, which protocol, which product,
which digest.

Fingerprints are not files
--------------------------

Censys reports SHA-256 digests in two places: certificate fingerprints and HTTP
body hashes. Neither becomes a ``file`` object. A certificate fingerprint
identifies a certificate, and TI Recon has an ``x509-certificate`` type for
exactly that; a body hash identifies a response body Censys saw, and it is kept
as a pivot string rather than promoted to a file that nobody has. Turning either
into a ``file`` would produce an object claiming to be a sample, which is the
kind of confident nonsense a data model exists to prevent.
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
from ti_recon.providers.censys.descriptor import (
    CENSYS_ORIGIN_PROVIDER,
    CENSYS_PROVIDER_ID,
    CENSYS_SOURCE_FAMILY,
)
from ti_recon.providers.censys.errors import parse_utc_timestamp

__all__ = [
    "AUTONOMOUS_SYSTEM_FIELDS",
    "CENSYS_LINEAGE_GROUP",
    "CENSYS_PROPERTY_NAMESPACE",
    "LOCATION_FIELDS",
    "MAX_CERTIFICATES",
    "MAX_DNS_NAMES",
    "MAX_ENDPOINTS",
    "MAX_LABELS",
    "MAX_PORTS",
    "MAX_SERVICES",
    "MAX_VULNERABILITIES",
    "OPERATING_SYSTEM_FIELDS",
    "SERVICE_FIELDS",
    "CensysDocument",
    "CensysNormalization",
    "NormalizationContext",
    "build_evidence",
    "count",
    "enrich_host_object",
    "enrich_web_property_object",
    "normalize_dns_names",
    "normalize_host_observation",
    "normalize_labels",
    "normalize_network_ownership",
    "normalize_not_observed",
    "normalize_services",
    "normalize_tls_certificates",
    "normalize_vulnerabilities",
    "normalize_web_property_observation",
    "text",
]

#: Censys-specific facts live under one key on an enriched object rather than
#: being spread across ``properties``, so their provenance stays obvious once
#: several providers have contributed to the same object.
CENSYS_PROPERTY_NAMESPACE: Final[str] = "censys"

#: Everything one Censys scan reports is one source and must never be treated as
#: several independent ones.
CENSYS_LINEAGE_GROUP: Final[str] = f"{CENSYS_SOURCE_FAMILY}:{CENSYS_ORIGIN_PROVIDER}"

#: Hard ceilings. A depth policy chooses a number at or below each of these; the
#: ceiling is what stops a policy — or a caller building one — from asking for an
#: unbounded expansion of a provider-controlled list.
MAX_SERVICES: Final[int] = 100
MAX_PORTS: Final[int] = 200
MAX_DNS_NAMES: Final[int] = 100
MAX_CERTIFICATES: Final[int] = 20
MAX_ENDPOINTS: Final[int] = 50
MAX_LABELS: Final[int] = 30
MAX_VULNERABILITIES: Final[int] = 50

#: How many software entries one service or web property may contribute.
MAX_SOFTWARE_PER_SERVICE: Final[int] = 5

#: Allow-listed autonomous-system fields.
AUTONOMOUS_SYSTEM_FIELDS: Final[tuple[str, ...]] = (
    "asn",
    "name",
    "description",
    "bgp_prefix",
    "country_code",
)

#: Allow-listed location fields. Coordinates and postal codes are deliberately
#: absent: neither adds anything to an exposure question, and both are more
#: precise than an investigation record needs to be about a datacentre.
LOCATION_FIELDS: Final[tuple[str, ...]] = (
    "country",
    "country_code",
    "city",
    "province",
    "continent",
    "timezone",
)

#: Allow-listed operating-system fields.
OPERATING_SYSTEM_FIELDS: Final[tuple[str, ...]] = ("vendor", "product", "version")

#: Allow-listed per-service fields.
#:
#: ``banner`` is conspicuously absent, along with every HTTP body and header
#: field. A banner is chosen by the host being scanned; keeping it would mean
#: storing attacker-authored text in an evidence record for no analytical gain
#: that the protocol and software fields do not already provide.
SERVICE_FIELDS: Final[tuple[str, ...]] = (
    "port",
    "transport_protocol",
    "protocol",
    "extended_service_name",
    "service_name",
)

#: Allow-listed per-endpoint fields for a web property.
_ENDPOINT_FIELDS: Final[tuple[str, ...]] = ("path", "status_code", "protocol")

#: Where the asset itself sits inside a Platform response. Checked in order, so a
#: flatter or differently-wrapped response still reads.
_RESOURCE_PATHS: Final[tuple[tuple[str, ...], ...]] = (
    ("result", "resource"),
    ("result",),
    ("resource",),
)

#: Where a "last observed" instant may appear.
_OBSERVED_KEYS: Final[tuple[str, ...]] = (
    "last_updated_at",
    "last_observed_at",
    "last_seen",
    "updated_at",
)

#: Where certificate leaf details may sit under a service's TLS block.
_LEAF_PATHS: Final[tuple[tuple[str, ...], ...]] = (
    ("certificates", "leaf_data"),
    ("certificate", "leaf_data"),
    ("leaf_data",),
)

#: Digest lengths a fingerprint may have: SHA-1 and SHA-256 in hex.
_FINGERPRINT_LENGTHS: Final[frozenset[int]] = frozenset({40, 64})

#: Longest single string kept from the document, and a shorter bound for
#: label-like values.
_MAX_TEXT: Final[int] = 1024
_MAX_LABEL: Final[int] = 200


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Everything evidence needs that does not come from the document.

    ``anchor_object_id`` is the object the *asset* describes, which is not always
    the submitted observable: an address-literal URL is looked up as a host, and
    the resulting DNS and ASN links belong to that address rather than to the
    URL. Keeping the two apart is what stops a relationship graph from claiming
    a URL belongs to an autonomous system.

    ``match_scope`` comes from the asset mapping, so "we asked about the host,
    not the page" travels with every piece of evidence instead of being decided
    twice.
    """

    investigation_id: str
    subject_object_id: str
    now: datetime
    anchor_object_id: str
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE
    raw_reference_id: str | None = None


class CensysNormalization(FrozenTiReconModel):
    """What one Censys document normalized into.

    ``degraded`` means a block TI Recon recognizes was present but unreadable.
    The adapter turns that into a ``PARTIAL`` result: the evidence that *did*
    parse is still worth having.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()
    degraded: bool = False

    def merge(self, other: CensysNormalization) -> CensysNormalization:
        return CensysNormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
            warnings=self.warnings + other.warnings,
            degraded=self.degraded or other.degraded,
        )


class CensysDocument:
    """Defensive reader over one Platform asset response.

    Every accessor tolerates the field being absent, null or of the wrong type,
    because the document is provider-controlled and partly shaped by whoever
    owns the asset: a certificate subject, a DNS name and an HTTP path all
    originate with the thing being investigated.
    """

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self._payload = payload
        self._resource = _locate_resource(payload)

    @property
    def resource(self) -> Mapping[str, Any]:
        return self._resource

    def block(self, name: str) -> Mapping[str, Any]:
        value = self._resource.get(name)
        return value if isinstance(value, Mapping) else {}

    def items(self, name: str) -> list[Any]:
        value = self._resource.get(name)
        return list(value) if isinstance(value, list) else []

    @property
    def ip(self) -> str | None:
        return text(self._resource.get("ip"), 45)

    @property
    def hostname(self) -> str | None:
        return text(self._resource.get("hostname"), 253)

    @property
    def port(self) -> int | None:
        return count(self._resource.get("port"))

    @property
    def observed_at(self) -> datetime | None:
        for key in _OBSERVED_KEYS:
            parsed = parse_utc_timestamp(text(self._resource.get(key), 64))
            if parsed is not None:
                return parsed
        return None

    @property
    def services(self) -> list[Mapping[str, Any]]:
        return [entry for entry in self.items("services") if isinstance(entry, Mapping)]

    @property
    def endpoints(self) -> list[Mapping[str, Any]]:
        for name in ("endpoints", "web_endpoints"):
            entries = [entry for entry in self.items(name) if isinstance(entry, Mapping)]
            if entries:
                return entries
        return []

    @property
    def is_empty(self) -> bool:
        """Whether the response carried no recognizable asset at all."""
        return not self._resource


def _locate_resource(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Find the asset inside whichever envelope Censys wrapped it in."""
    for path in _RESOURCE_PATHS:
        current: Any = payload
        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break
            current = current.get(key)
        if isinstance(current, Mapping) and current:
            return current
    return payload if any(key in payload for key in ("ip", "hostname")) else {}


# --------------------------------------------------------------------------- #
# The asset itself
# --------------------------------------------------------------------------- #


def normalize_host_observation(
    context: NormalizationContext, document: CensysDocument, *, max_ports: int = MAX_PORTS
) -> CensysNormalization:
    """Record that Censys scanned this address, and the shape of what answered.

    A direct observation with no direction: "these ports responded at this time,
    and this is the operating system Censys inferred" is a fact about the asset,
    not an opinion about it.
    """
    if document.is_empty:
        return CensysNormalization()

    attributes: dict[str, Any] = {}
    address = document.ip
    if address is not None:
        attributes["ip"] = address
    services = document.services
    attributes["service_count"] = len(services)
    ports = _ports(services, min(max_ports, MAX_PORTS))
    if ports:
        attributes["ports"] = ports
        if len(services) > len(ports):
            # Recorded, never silent: a list we cut short must not read as a
            # list that ended.
            attributes["ports_truncated"] = True

    operating_system = document.block("operating_system")
    for name in OPERATING_SYSTEM_FIELDS:
        value = text(operating_system.get(name), _MAX_LABEL)
        if value is not None:
            attributes[f"os_{name}"] = value

    observed_at = document.observed_at
    if observed_at is not None:
        attributes["observed_at"] = observed_at.isoformat()

    if len(attributes) <= 1:
        return CensysNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="censys_host_observation",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=observed_at,
        last_seen=observed_at,
    )
    return CensysNormalization(evidence=(evidence,))


def normalize_web_property_observation(
    context: NormalizationContext,
    document: CensysDocument,
    *,
    max_endpoints: int = MAX_ENDPOINTS,
    include_software: bool = True,
) -> CensysNormalization:
    """Record what Censys observed on one ``hostname:port``.

    Paths, status codes and body digests — the shape of the web property.
    Deliberately *not* bodies: Censys is not TI Recon's web-forensics provider,
    nothing here retrieves content, and a body digest is kept as a pivot rather
    than as a promise that the body is available somewhere.
    """
    if document.is_empty:
        return CensysNormalization()

    attributes: dict[str, Any] = {}
    hostname = document.hostname
    if hostname is not None:
        attributes["hostname"] = hostname
    port = document.port
    if port is not None:
        attributes["port"] = port

    endpoints = document.endpoints
    attributes["endpoint_count"] = len(endpoints)
    limit = min(max_endpoints, MAX_ENDPOINTS)
    kept: list[dict[str, Any]] = []
    digests: list[str] = []
    for entry in endpoints[:limit]:
        item: dict[str, Any] = {}
        for name in _ENDPOINT_FIELDS:
            value = scalar(entry.get(name))
            if value is not None:
                item[name] = value
        if include_software:
            software = _software(entry.get("software"))
            if software:
                item["software"] = software
        if item:
            kept.append(item)
        digests.extend(_body_hashes(entry))
    if kept:
        attributes["endpoints"] = kept
    if len(endpoints) > limit:
        attributes["endpoints_truncated"] = True
    if digests:
        # Fingerprints, not files. See the module docstring: nothing promotes one
        # of these to a ``file`` object, and nothing retrieves the body behind it.
        attributes["body_hashes"] = _bounded(digests, limit)

    if include_software:
        software = _software(document.resource.get("software"))
        if software:
            attributes["software"] = software

    observed_at = document.observed_at
    if observed_at is not None:
        attributes["observed_at"] = observed_at.isoformat()

    if len(attributes) <= 1:
        return CensysNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="censys_web_property_observation",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=observed_at,
        last_seen=observed_at,
    )
    return CensysNormalization(evidence=(evidence,))


def normalize_not_observed(
    context: NormalizationContext, *, asset_kind: str, asset_identifier: str
) -> CensysNormalization:
    """Record that Censys was asked about this asset and had no record of it.

    Context evidence, and nothing else. Censys not having scanned an asset means
    its scanners have not reached it — a host behind a firewall, a name that
    resolves nowhere public, a service that came up an hour ago. It is emphatically
    not evidence that nothing is exposed, and turning it into a benign signal
    would make the least-visible infrastructure look like the safest.
    """
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="censys_asset_not_observed",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"asset_kind": asset_kind, "asset": asset_identifier, "observed": False},
    )
    return CensysNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# Ownership
# --------------------------------------------------------------------------- #


def normalize_network_ownership(
    context: NormalizationContext, document: CensysDocument
) -> CensysNormalization:
    """Who announces the address, and roughly where it sits.

    Context only, and deliberately so: hosting facts point nowhere on their own,
    and letting "announced from country X" nudge a verdict is how a country
    becomes a proxy for guilt.
    """
    autonomous_system = document.block("autonomous_system")
    location = document.block("location")
    if not autonomous_system and not location:
        return CensysNormalization()

    attributes: dict[str, Any] = {}
    for name in AUTONOMOUS_SYSTEM_FIELDS:
        value = scalar(autonomous_system.get(name))
        if value is not None:
            attributes[f"as_{name}"] = value
    for name in LOCATION_FIELDS:
        value = text(location.get(name), _MAX_LABEL)
        if value is not None:
            attributes[name] = value
    if not attributes:
        return CensysNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="censys_network_ownership",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.observed_at,
    )

    objects: list[IntelObject] = []
    relationships: list[Relationship] = []
    asn_object = _asn_object(autonomous_system.get("asn"))
    if asn_object is not None:
        objects.append(asn_object)
        relationships.append(
            Relationship(
                source_object_id=context.anchor_object_id,
                relationship_type=RelationshipType.BELONGS_TO_ASN,
                target_object_id=asn_object.id,
                last_seen=document.observed_at,
                evidence_refs=(evidence.id,),
                raw_relationship_type="autonomous_system",
            )
        )
    return CensysNormalization(
        evidence=(evidence,), objects=tuple(objects), relationships=tuple(relationships)
    )


# --------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------- #


def normalize_services(
    context: NormalizationContext,
    document: CensysDocument,
    *,
    max_services: int = MAX_SERVICES,
    include_software: bool = True,
) -> CensysNormalization:
    """What is listening, and what software Censys could see behind it.

    One piece of evidence for the whole exposed surface rather than one per
    service. A host with forty open ports is one observation of one host, and
    splitting it into forty records would make a busy server look like a mountain
    of findings.

    No banners. See :data:`SERVICE_FIELDS`.
    """
    services = document.services
    if not services:
        return CensysNormalization()

    limit = min(max_services, MAX_SERVICES)
    kept: list[dict[str, Any]] = []
    for entry in services[:limit]:
        item: dict[str, Any] = {}
        for name in SERVICE_FIELDS:
            value = scalar(entry.get(name))
            if value is not None:
                item[name] = value
        if include_software:
            software = _software(entry.get("software"))
            if software:
                item["software"] = software
        labels = _label_values(entry.get("labels"), MAX_LABELS)
        if labels:
            item["labels"] = labels
        if item:
            kept.append(item)

    if not kept:
        return CensysNormalization()

    attributes: dict[str, Any] = {"services": kept, "service_count": len(services)}
    if len(services) > limit:
        attributes["truncated"] = True

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="censys_services",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.observed_at,
        last_seen=document.observed_at,
    )
    return CensysNormalization(evidence=(evidence,))


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def normalize_dns_names(
    context: NormalizationContext,
    document: CensysDocument,
    *,
    max_names: int = MAX_DNS_NAMES,
) -> CensysNormalization:
    """The names Censys associates with this address, forward and reverse.

    Host assets only: a web property *is* a name, so there is nothing to resolve.

    Each name becomes an object and a ``resolves-to`` link pointing at the
    address — the direction reverse DNS actually states. Names are validated by
    the same normalizer that validates analyst input, because a PTR record is
    chosen by whoever owns the address block and is no more trustworthy than
    something a user typed.
    """
    limit = min(max_names, MAX_DNS_NAMES)
    dns = document.block("dns")
    forward = _domain_objects(dns.get("names"), limit)
    reverse_block = dns.get("reverse_dns")
    reverse_source = (
        reverse_block.get("names") if isinstance(reverse_block, Mapping) else dns.get("reverse_dns")
    )
    reverse = _domain_objects(reverse_source, limit)
    if not forward and not reverse:
        return CensysNormalization()

    attributes: dict[str, Any] = {}
    if forward:
        attributes["names"] = [item.canonical_value for item in forward]
    if reverse:
        attributes["reverse_names"] = [item.canonical_value for item in reverse]

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="censys_dns_names",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
        observed_at=document.observed_at,
        last_seen=document.observed_at,
    )

    objects = _unique_objects(list(forward) + list(reverse))
    relationships = tuple(
        Relationship(
            source_object_id=item.id,
            relationship_type=RelationshipType.RESOLVES_TO,
            target_object_id=context.anchor_object_id,
            last_seen=document.observed_at,
            evidence_refs=(evidence.id,),
            raw_relationship_type="dns.names",
        )
        for item in objects
        if item.id != context.anchor_object_id
    )
    return CensysNormalization(evidence=(evidence,), objects=objects, relationships=relationships)


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def normalize_tls_certificates(
    context: NormalizationContext,
    document: CensysDocument,
    *,
    max_certificates: int = MAX_CERTIFICATES,
) -> CensysNormalization:
    """The certificates Censys saw being served, as certificates.

    A fingerprint becomes an ``x509-certificate`` object — never a ``file``.
    Certificates are among the best pivots in existence: the same certificate on
    two unrelated-looking hosts is often the strongest link between them, and
    that only works if the fingerprint is modelled as the certificate it
    identifies.

    Subject and issuer names are kept, bounded: both are chosen by whoever
    requested the certificate, so they are provider-relayed attacker input and
    are treated as such.
    """
    limit = min(max_certificates, MAX_CERTIFICATES)
    leaves = _leaf_certificates(document, limit)
    if not leaves:
        return CensysNormalization()

    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="censys_tls_certificates",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"certificates": [leaf.attributes for leaf in leaves]},
        observed_at=document.observed_at,
    )
    objects = _unique_objects([leaf.object for leaf in leaves])
    relationships = tuple(
        Relationship(
            source_object_id=context.anchor_object_id,
            relationship_type=RelationshipType.USES_CERTIFICATE,
            target_object_id=item.id,
            last_seen=document.observed_at,
            evidence_refs=(evidence.id,),
            raw_relationship_type="services.tls.certificate",
        )
        for item in objects
    )
    return CensysNormalization(evidence=(evidence,), objects=objects, relationships=relationships)


@dataclass(frozen=True, slots=True)
class _Leaf:
    """One observed leaf certificate: its object and its recorded attributes."""

    object: IntelObject
    attributes: dict[str, Any]


def _leaf_certificates(document: CensysDocument, limit: int) -> list[_Leaf]:
    """Every leaf certificate in the document, from services or the top level."""
    blocks: list[tuple[int | None, Mapping[str, Any]]] = []
    for service in document.services:
        tls = service.get("tls")
        if isinstance(tls, Mapping):
            blocks.append((count(service.get("port")), tls))
    top_level = document.block("tls")
    if top_level:
        blocks.append((document.port, top_level))

    leaves: list[_Leaf] = []
    seen: set[str] = set()
    for port, tls in blocks:
        leaf = _leaf_data(tls)
        fingerprint = _fingerprint(leaf)
        if fingerprint is None or fingerprint in seen:
            continue
        seen.add(fingerprint)
        attributes: dict[str, Any] = {"fingerprint_sha256": fingerprint}
        if port is not None:
            attributes["port"] = port
        for name in ("subject_dn", "issuer_dn"):
            value = text(leaf.get(name), _MAX_TEXT)
            if value is not None:
                attributes[name] = value
        names = _string_values(leaf.get("names"), MAX_DNS_NAMES, 253)
        if names:
            attributes["names"] = names
        leaves.append(
            _Leaf(
                object=IntelObject(
                    object_class=ObjectClass.INFRASTRUCTURE,
                    object_type=IntelObjectType.X509_CERTIFICATE,
                    canonical_value=fingerprint,
                    display_value=fingerprint,
                ),
                attributes=attributes,
            )
        )
        if len(leaves) >= limit:
            break
    return leaves


def _leaf_data(tls: Mapping[str, Any]) -> Mapping[str, Any]:
    for path in _LEAF_PATHS:
        current: Any = tls
        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break
            current = current.get(key)
        if isinstance(current, Mapping) and current:
            return current
    return tls


def _fingerprint(leaf: Mapping[str, Any]) -> str | None:
    """A certificate fingerprint, shape-checked before it becomes an identity.

    Only a hex digest of a recognized length is accepted. A value that is not
    one has no business being the canonical value of a certificate object.
    """
    for name in ("fingerprint_sha256", "fingerprint", "sha256_fingerprint"):
        candidate = text(leaf.get(name), 128)
        if candidate is None:
            continue
        normalized = candidate.lower()
        if len(normalized) in _FINGERPRINT_LENGTHS and all(
            character in "0123456789abcdef" for character in normalized
        ):
            return normalized
    return None


# --------------------------------------------------------------------------- #
# Labels and exposures
# --------------------------------------------------------------------------- #


def normalize_labels(
    context: NormalizationContext, document: CensysDocument, *, max_labels: int = MAX_LABELS
) -> CensysNormalization:
    """Censys's own labels for the asset — ``login-page``, ``remote-access``.

    Context, always. A label says what a thing *is*, and Censys applies them to
    the entire internet: "login-page" describes millions of legitimate sign-in
    forms alongside every phishing kit. Treating a label as a direction would
    make every corporate VPN portal suspicious.
    """
    labels = _label_values(document.resource.get("labels"), min(max_labels, MAX_LABELS))
    if not labels:
        return CensysNormalization()
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="censys_labels",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={"labels": labels},
        observed_at=document.observed_at,
    )
    return CensysNormalization(evidence=(evidence,))


def normalize_vulnerabilities(
    context: NormalizationContext,
    document: CensysDocument,
    *,
    max_vulnerabilities: int = MAX_VULNERABILITIES,
) -> CensysNormalization:
    """Vulnerabilities and misconfigurations Censys reports on the asset.

    Context, and this is the one where the temptation is strongest. A reported
    CVE means Censys inferred, from a banner or a version string, that the
    service *may* be affected. It does not mean the host was exploited, that the
    finding was confirmed, or — most importantly — that the host is hostile.
    Vulnerable is not malicious; exposed is not compromised; outdated is not
    malware. ``EvidenceClass.CONTEXT`` makes the model refuse to let this claim
    carry a direction at all, so the temptation cannot be acted on by accident.

    A future fusion layer may reason about infrastructure risk separately. That
    is a different question from whether an indicator is malicious, and keeping
    them apart starts here.
    """
    limit = min(max_vulnerabilities, MAX_VULNERABILITIES)
    findings = _vulnerabilities(document, limit)
    if not findings:
        return CensysNormalization()
    evidence = build_evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="censys_vulnerabilities",
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes={
            "findings": findings,
            "basis": "inferred_from_observed_service_version",
        },
        observed_at=document.observed_at,
    )
    return CensysNormalization(evidence=(evidence,))


def _vulnerabilities(document: CensysDocument, limit: int) -> list[dict[str, Any]]:
    """Vulnerability entries from the asset and from each service, bounded."""
    sources: list[Any] = [
        document.resource.get("vulnerabilities"),
        document.resource.get("risks"),
    ]
    for service in document.services:
        sources.append(service.get("vulnerabilities"))
        sources.append(service.get("risks"))

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, list):
            continue
        for entry in source:
            item = _vulnerability_entry(entry)
            if item is None:
                continue
            key = str(item.get("id", ""))
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
            if len(findings) >= limit:
                return findings
    return findings


def _vulnerability_entry(entry: Any) -> dict[str, Any] | None:
    """One vulnerability, identified by a CVE id or a Censys risk name."""
    if isinstance(entry, str):
        identifier = _cve_id(entry) or text(entry, _MAX_LABEL)
        return {"id": identifier} if identifier else None
    if not isinstance(entry, Mapping):
        return None
    identifier = None
    for name in ("cve_id", "cve", "id", "name", "type"):
        identifier = _cve_id(entry.get(name)) or text(entry.get(name), _MAX_LABEL)
        if identifier is not None:
            break
    if identifier is None:
        return None
    item: dict[str, Any] = {"id": identifier}
    for name in ("severity", "cvss_score", "cvss", "category"):
        value = scalar(entry.get(name))
        if value is not None:
            item[name] = value
    return item


def _cve_id(value: Any) -> str | None:
    """A CVE identifier, shape-checked, or ``None``."""
    candidate = text(value, 32)
    if candidate is None:
        return None
    normalized = candidate.upper()
    head, _, tail = normalized.partition("-")
    year, _, sequence = tail.partition("-")
    if head != "CVE" or not year.isdigit() or not sequence.isdigit():
        return None
    return normalized


# --------------------------------------------------------------------------- #
# The submitted object
# --------------------------------------------------------------------------- #


def enrich_host_object(submitted: IntelObject, document: CensysDocument) -> IntelObject:
    """Attach stable host facts to the submitted object.

    Only facts about *what the thing is* — who announces it, where it is, how
    many services answered. Judgements stay in evidence, where they have a
    provenance and a moment of observation that a property cannot carry.
    """
    metadata: dict[str, Any] = {}
    autonomous_system = document.block("autonomous_system")
    for name in ("asn", "name", "bgp_prefix"):
        value = scalar(autonomous_system.get(name))
        if value is not None:
            metadata[f"as_{name}"] = value
    location = document.block("location")
    for name in ("country_code", "city"):
        value = text(location.get(name), _MAX_LABEL)
        if value is not None:
            metadata[name] = value
    services = document.services
    if services:
        metadata["service_count"] = len(services)
    return _with_namespace(submitted, metadata, document)


def enrich_web_property_object(submitted: IntelObject, document: CensysDocument) -> IntelObject:
    """Attach stable web-property facts to the submitted object."""
    metadata: dict[str, Any] = {}
    hostname = document.hostname
    if hostname is not None:
        metadata["hostname"] = hostname
    port = document.port
    if port is not None:
        metadata["port"] = port
    endpoints = document.endpoints
    if endpoints:
        metadata["endpoint_count"] = len(endpoints)
    return _with_namespace(submitted, metadata, document)


def _with_namespace(
    submitted: IntelObject, metadata: dict[str, Any], document: CensysDocument
) -> IntelObject:
    observed_at = document.observed_at
    if observed_at is not None:
        metadata["last_observed_at"] = observed_at.isoformat()
    if not metadata:
        return submitted
    enriched = submitted.model_copy(deep=True)
    namespace = dict(enriched.properties.get(CENSYS_PROPERTY_NAMESPACE, {}))
    namespace.update(metadata)
    enriched.properties[CENSYS_PROPERTY_NAMESPACE] = namespace
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

    Origin, family and lineage group are not parameters. Everything Censys
    reports here is first-hand and belongs to one lineage group, and making that
    overridable would be an invitation to split one scan into several sources.

    ``source_reliability`` and ``information_credibility`` are never set here:
    Admiralty grading is TI Recon policy, not a provider's to claim.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=CENSYS_PROVIDER_ID,
        origin_provider=CENSYS_ORIGIN_PROVIDER,
        source_family=CENSYS_SOURCE_FAMILY,
        match_scope=context.match_scope,
        observed_at=observed_at,
        first_seen=first_seen,
        last_seen=last_seen,
        retrieved_at=context.now,
        lineage_group_id=CENSYS_LINEAGE_GROUP,
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def _ports(services: Sequence[Mapping[str, Any]], limit: int) -> list[int]:
    """The distinct responding ports, bounded and sorted."""
    ports: set[int] = set()
    for service in services:
        port = count(service.get("port"))
        if port is not None and 1 <= port <= 65535:
            ports.add(port)
        if len(ports) >= limit:
            break
    return sorted(ports)


def _software(value: Any) -> list[dict[str, Any]]:
    """Vendor/product/version triples, bounded.

    A version string comes from a banner the host chose, so it is bounded like
    any other provider-relayed text rather than trusted as a version number.
    """
    if not isinstance(value, list):
        return []
    entries: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            name = text(entry, _MAX_LABEL)
            if name is not None:
                entries.append({"product": name})
        else:
            item = {
                name: text(entry.get(name), _MAX_LABEL)
                for name in ("vendor", "product", "version")
                if text(entry.get(name), _MAX_LABEL) is not None
            }
            if item:
                entries.append(item)
        if len(entries) >= MAX_SOFTWARE_PER_SERVICE:
            break
    return entries


def _body_hashes(entry: Mapping[str, Any]) -> list[str]:
    """Body digests from one endpoint. Fingerprints, never files."""
    digests: list[str] = []
    for name in ("body_hashes", "body_hash"):
        value = entry.get(name)
        if isinstance(value, str):
            cleaned = text(value, 128)
            if cleaned is not None:
                digests.append(cleaned)
        elif isinstance(value, list):
            digests.extend(_string_values(value, MAX_ENDPOINTS, 128))
    return digests


def _label_values(value: Any, limit: int) -> list[str]:
    """Label strings, whether Censys sent objects or bare strings."""
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for entry in value:
        raw = entry.get("value", entry.get("name")) if isinstance(entry, Mapping) else entry
        label = text(raw, _MAX_LABEL)
        if label is None or label in labels:
            continue
        labels.append(label)
        if len(labels) >= limit:
            break
    return labels


def _domain_objects(value: Any, limit: int) -> tuple[IntelObject, ...]:
    """Hostnames as objects, validated exactly like analyst input."""
    if not isinstance(value, list):
        return ()
    objects: list[IntelObject] = []
    seen: set[str] = set()
    for entry in value:
        candidate = text(entry.get("name") if isinstance(entry, Mapping) else entry, 253)
        if candidate is None:
            continue
        try:
            built = normalize_domain(candidate)
        except NormalizationError:
            continue
        if built.canonical_key in seen:
            continue
        seen.add(built.canonical_key)
        objects.append(built)
        if len(objects) >= limit:
            break
    return tuple(objects)


def _asn_object(value: Any) -> IntelObject | None:
    """An ASN object from Censys's numeric ``asn``. Derived infrastructure."""
    number = count(value)
    if number is None or number == 0:
        return None
    label = f"AS{number}"
    return IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value=label,
        display_value=label,
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


def _bounded(values: Sequence[str], limit: int) -> list[str]:
    """The first ``limit`` distinct values, order preserved."""
    out: list[str] = []
    for value in values:
        if value in out:
            continue
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _string_values(value: Any, limit: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for entry in value:
        cleaned = text(entry, max_length)
        if cleaned is None or cleaned in out:
            continue
        out.append(cleaned)
        if len(out) >= limit:
            break
    return out


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
    return None


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = int(value)
    return number if number >= 0 else None
