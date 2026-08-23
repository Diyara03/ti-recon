"""Normalizing Censys asset observations into TI Recon models (Task 9).

These are the semantic tests. Three of them carry most of the weight:

* nothing Censys reports can carry a direction — vulnerable is not malicious,
  exposed is not compromised, a label is not a classification;
* a banner, an HTTP body and an HTML title are all present in a real response
  and none of them are ever stored;
* a certificate fingerprint is a certificate and a body hash is a fingerprint;
  neither becomes a ``file`` object.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.censys import payloads
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.censys import (
    CENSYS_LINEAGE_GROUP,
    CENSYS_PROPERTY_NAMESPACE,
    MAX_CERTIFICATES,
    MAX_DNS_NAMES,
    MAX_ENDPOINTS,
    MAX_LABELS,
    MAX_SERVICES,
    MAX_VULNERABILITIES,
    CensysDocument,
    NormalizationContext,
    enrich_host_object,
    enrich_web_property_object,
    normalize_dns_names,
    normalize_host_observation,
    normalize_labels,
    normalize_network_ownership,
    normalize_not_observed,
    normalize_services,
    normalize_tls_certificates,
    normalize_vulnerabilities,
    normalize_web_property_observation,
)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
OBSERVED_AT = datetime(2026, 8, 21, 4, 5, 6, tzinfo=UTC)


def subject(value: str = payloads.HOST_IP) -> IntelObject:
    return normalize_observable(value).intel_object


def context(
    subject_object: IntelObject | None = None,
    *,
    anchor: IntelObject | None = None,
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE,
) -> NormalizationContext:
    target = subject_object or subject()
    return NormalizationContext(
        investigation_id="inv-1",
        subject_object_id=target.id,
        now=NOW,
        anchor_object_id=(anchor or target).id,
        match_scope=match_scope,
    )


def host(payload: dict[str, Any] | None = None) -> CensysDocument:
    return CensysDocument(payloads.host_payload() if payload is None else payload)


def web_property(payload: dict[str, Any] | None = None) -> CensysDocument:
    return CensysDocument(payloads.web_property_payload() if payload is None else payload)


def host_with(**resource_overrides: Any) -> CensysDocument:
    return CensysDocument(payloads.host_payload(**resource_overrides))


# --------------------------------------------------------------------------- #
# Locating the asset inside whatever envelope Censys used
# --------------------------------------------------------------------------- #


def test_the_asset_is_found_inside_the_platform_envelope() -> None:
    parsed = host()
    assert parsed.ip == payloads.HOST_IP
    assert parsed.observed_at == OBSERVED_AT
    assert parsed.is_empty is False


def test_a_flatter_response_still_reads() -> None:
    parsed = CensysDocument({"ip": payloads.HOST_IP})
    assert parsed.ip == payloads.HOST_IP
    assert parsed.is_empty is False


def test_a_resource_wrapped_without_a_result_still_reads() -> None:
    parsed = CensysDocument({"resource": {"ip": payloads.HOST_IP}})
    assert parsed.ip == payloads.HOST_IP


def test_an_unrecognizable_response_is_empty() -> None:
    assert CensysDocument({}).is_empty is True
    assert CensysDocument({"unexpected": "shape"}).is_empty is True


def test_a_non_mapping_block_is_tolerated() -> None:
    parsed = CensysDocument({"result": {"resource": {"ip": "198.51.100.7", "location": "nope"}}})
    assert parsed.block("location") == {}
    assert parsed.services == []
    assert parsed.endpoints == []


def test_a_web_property_reads_its_hostname_and_port() -> None:
    parsed = web_property()
    assert parsed.hostname == payloads.WEB_PROPERTY_HOST
    assert parsed.port == 443


# --------------------------------------------------------------------------- #
# Nothing Censys reports carries a direction
# --------------------------------------------------------------------------- #


def every_host_normalization() -> tuple[Any, ...]:
    parsed = host()
    return (
        normalize_host_observation(context(), parsed),
        normalize_network_ownership(context(), parsed),
        normalize_services(context(), parsed),
        normalize_dns_names(context(), parsed),
        normalize_tls_certificates(context(), parsed),
        normalize_labels(context(), parsed),
        normalize_vulnerabilities(context(), parsed),
    )


def test_no_normalization_can_produce_a_direction() -> None:
    """Exposure is not an accusation, at any depth, for any field."""
    for result in every_host_normalization():
        assert result.evidence
        for evidence in result.evidence:
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_a_web_property_carries_no_direction_either() -> None:
    parsed = web_property()
    for result in (
        normalize_web_property_observation(context(), parsed),
        normalize_tls_certificates(context(), parsed),
        normalize_labels(context(), parsed),
    ):
        assert result.evidence
        for evidence in result.evidence:
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_an_exposed_remote_access_service_is_not_an_accusation() -> None:
    """Open RDP is a risk to its owner, not evidence its owner is an attacker."""
    evidence = normalize_services(context(), host()).evidence[0]
    ports = [service["port"] for service in evidence.attributes["services"]]
    assert 3389 in ports
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


# --------------------------------------------------------------------------- #
# The host observation
# --------------------------------------------------------------------------- #


def test_the_host_observation_records_the_responding_ports() -> None:
    evidence = normalize_host_observation(context(), host()).evidence[0]
    assert evidence.claim_type == "censys_host_observation"
    assert evidence.evidence_class is EvidenceClass.DIRECT_OBSERVATION
    assert evidence.attributes["ports"] == [22, 443, 3389]
    assert evidence.attributes["service_count"] == 3


def test_the_host_observation_records_the_inferred_operating_system() -> None:
    evidence = normalize_host_observation(context(), host()).evidence[0]
    assert evidence.attributes["os_vendor"] == "Canonical"
    assert evidence.attributes["os_product"] == "Ubuntu"
    assert evidence.attributes["os_version"] == "22.04"


def test_the_host_observation_records_when_censys_last_looked() -> None:
    evidence = normalize_host_observation(context(), host()).evidence[0]
    assert evidence.observed_at == OBSERVED_AT
    assert evidence.last_seen == OBSERVED_AT


def test_the_ports_are_bounded_and_the_truncation_is_recorded() -> None:
    services = [{"port": port} for port in range(1, 60)]
    evidence = normalize_host_observation(
        context(), host_with(services=services), max_ports=10
    ).evidence[0]
    assert len(evidence.attributes["ports"]) == 10
    assert evidence.attributes["ports_truncated"] is True


def test_an_empty_document_produces_no_host_observation() -> None:
    assert normalize_host_observation(context(), CensysDocument({})).evidence == ()


# --------------------------------------------------------------------------- #
# Raw content is never kept
# --------------------------------------------------------------------------- #


def test_no_service_banner_is_ever_stored() -> None:
    """A banner is whatever the scanned host chose to send."""
    serialized = str([result.model_dump() for result in every_host_normalization()])
    assert "ATTACKER-CONTROLLED-TEXT" not in serialized
    assert "SSH-2.0-OpenSSH" not in serialized
    assert "banner" not in serialized


def test_no_http_body_or_title_is_ever_stored() -> None:
    parsed = web_property()
    serialized = str(
        [
            normalize_web_property_observation(context(), parsed).model_dump(),
            normalize_tls_certificates(context(), parsed).model_dump(),
            normalize_labels(context(), parsed).model_dump(),
        ]
    )
    assert "ATTACKER CONTROLLED PAGE" not in serialized
    assert "<html>" not in serialized
    assert "html_title" not in serialized
    assert "Sign in" not in serialized


def test_no_coordinates_or_postal_code_reach_the_evidence() -> None:
    """Neither adds anything to an exposure question."""
    evidence = normalize_network_ownership(context(), host()).evidence[0]
    assert "coordinates" not in evidence.attributes
    assert "latitude" not in evidence.attributes
    assert "postal_code" not in evidence.attributes


def test_an_unlisted_service_field_is_ignored() -> None:
    services = [{"port": 443, "surprise_field": "value", "banner": "x"}]
    evidence = normalize_services(context(), host_with(services=services)).evidence[0]
    assert "surprise_field" not in evidence.attributes["services"][0]
    assert "banner" not in evidence.attributes["services"][0]


# --------------------------------------------------------------------------- #
# Ownership
# --------------------------------------------------------------------------- #


def test_the_ownership_evidence_is_context() -> None:
    evidence = normalize_network_ownership(context(), host()).evidence[0]
    assert evidence.claim_type == "censys_network_ownership"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.attributes["as_asn"] == 64500
    assert evidence.attributes["as_name"] == "EXAMPLE-AS"
    assert evidence.attributes["as_bgp_prefix"] == "198.51.100.0/24"
    assert evidence.attributes["country_code"] == "NL"


def test_the_autonomous_system_becomes_an_object_the_address_belongs_to() -> None:
    target = subject()
    result = normalize_network_ownership(context(target), host())
    asn = next(
        item for item in result.objects if item.object_type is IntelObjectType.AUTONOMOUS_SYSTEM
    )
    assert asn.canonical_value == "AS64500"
    assert asn.object_class is ObjectClass.INFRASTRUCTURE
    link = next(
        item
        for item in result.relationships
        if item.relationship_type is RelationshipType.BELONGS_TO_ASN
    )
    assert link.source_object_id == target.id
    assert link.target_object_id == asn.id


def test_a_missing_autonomous_system_number_produces_no_object() -> None:
    result = normalize_network_ownership(
        context(), host_with(autonomous_system={"name": "EXAMPLE-AS"})
    )
    assert all(item.object_type is not IntelObjectType.AUTONOMOUS_SYSTEM for item in result.objects)
    assert result.relationships == ()


def test_no_ownership_block_produces_no_evidence() -> None:
    assert (
        normalize_network_ownership(context(), CensysDocument({"ip": "198.51.100.7"})).evidence
        == ()
    )


# --------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------- #


def test_the_exposed_surface_is_one_observation_not_one_per_service() -> None:
    """Forty open ports on one host is one observation of one host."""
    result = normalize_services(context(), host())
    assert len(result.evidence) == 1
    assert len(result.evidence[0].attributes["services"]) == 3


def test_a_service_records_its_protocol_and_software() -> None:
    services = normalize_services(context(), host()).evidence[0].attributes["services"]
    ssh = next(service for service in services if service["port"] == 22)
    assert ssh["transport_protocol"] == "TCP"
    assert ssh["protocol"] == "SSH"
    assert ssh["software"] == [{"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.9p1"}]
    assert ssh["labels"] == ["remote-access"]


def test_software_can_be_left_out() -> None:
    services = (
        normalize_services(context(), host(), include_software=False)
        .evidence[0]
        .attributes["services"]
    )
    assert all("software" not in service for service in services)


def test_the_service_list_is_bounded_and_the_truncation_is_recorded() -> None:
    services = [{"port": port, "protocol": "HTTP"} for port in range(1, 60)]
    evidence = normalize_services(context(), host_with(services=services), max_services=5).evidence[
        0
    ]
    assert len(evidence.attributes["services"]) == 5
    assert evidence.attributes["service_count"] == 59
    assert evidence.attributes["truncated"] is True


def test_the_normalizer_ceiling_outranks_a_larger_request() -> None:
    services = [{"port": port} for port in range(1, MAX_SERVICES + 50)]
    evidence = normalize_services(
        context(), host_with(services=services), max_services=MAX_SERVICES + 40
    ).evidence[0]
    assert len(evidence.attributes["services"]) == MAX_SERVICES


def test_no_services_produces_no_evidence() -> None:
    assert normalize_services(context(), host_with(services=[])).evidence == ()


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def test_dns_names_become_objects_that_resolve_to_the_address() -> None:
    target = subject()
    result = normalize_dns_names(context(target), host())
    evidence = result.evidence[0]
    assert evidence.claim_type == "censys_dns_names"
    assert "login.example.com" in evidence.attributes["names"]
    assert evidence.attributes["reverse_names"] == ["host-7.example.net"]

    for link in result.relationships:
        assert link.relationship_type is RelationshipType.RESOLVES_TO
        assert link.target_object_id == target.id


def test_an_invalid_dns_name_is_dropped_rather_than_trusted() -> None:
    """A PTR record is chosen by whoever owns the address block."""
    evidence = normalize_dns_names(context(), host()).evidence[0]
    assert "not a hostname" not in evidence.attributes["names"]


def test_dns_names_are_bounded() -> None:
    names = [f"host-{index}.example.com" for index in range(MAX_DNS_NAMES + 20)]
    evidence = normalize_dns_names(
        context(), host_with(dns={"names": names}), max_names=MAX_DNS_NAMES
    ).evidence[0]
    assert len(evidence.attributes["names"]) == MAX_DNS_NAMES


def test_a_reverse_dns_list_without_a_wrapper_still_reads() -> None:
    evidence = normalize_dns_names(
        context(), host_with(dns={"reverse_dns": ["host-9.example.net"]})
    ).evidence[0]
    assert evidence.attributes["reverse_names"] == ["host-9.example.net"]


def test_no_dns_block_produces_no_evidence() -> None:
    assert normalize_dns_names(context(), host_with(dns={})).evidence == ()


def test_every_relationship_references_the_evidence_that_justifies_it() -> None:
    for result in every_host_normalization():
        evidence_ids = {item.id for item in result.evidence}
        for relationship in result.relationships:
            assert relationship.evidence_refs
            assert set(relationship.evidence_refs) <= evidence_ids


# --------------------------------------------------------------------------- #
# Certificates: fingerprints are certificates, never files
# --------------------------------------------------------------------------- #


def test_a_served_certificate_becomes_an_x509_object() -> None:
    target = subject()
    result = normalize_tls_certificates(context(target), host())
    certificate = result.objects[0]
    assert certificate.object_type is IntelObjectType.X509_CERTIFICATE
    assert certificate.canonical_value == payloads.LEAF_FINGERPRINT
    link = result.relationships[0]
    assert link.relationship_type is RelationshipType.USES_CERTIFICATE
    assert link.source_object_id == target.id
    assert link.target_object_id == certificate.id


def test_a_fingerprint_never_becomes_a_file_object() -> None:
    """It identifies a certificate, not a sample nobody has."""
    result = normalize_tls_certificates(context(), host())
    assert all(item.object_type is not IntelObjectType.FILE for item in result.objects)


def test_the_certificate_evidence_records_the_subject_and_issuer() -> None:
    evidence = normalize_tls_certificates(context(), host()).evidence[0]
    certificate = evidence.attributes["certificates"][0]
    assert certificate["fingerprint_sha256"] == payloads.LEAF_FINGERPRINT
    assert certificate["subject_dn"] == "CN=login.example.com"
    assert certificate["issuer_dn"].startswith("CN=Example CA")
    assert certificate["port"] == 443
    assert "login.example.com" in certificate["names"]


def test_a_certificate_is_context_rather_than_a_judgement() -> None:
    evidence = normalize_tls_certificates(context(), host()).evidence[0]
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_a_web_propertys_top_level_certificate_is_read_too() -> None:
    result = normalize_tls_certificates(context(), web_property())
    assert result.objects
    assert result.objects[0].canonical_value == payloads.LEAF_FINGERPRINT


def test_the_same_certificate_on_two_ports_is_one_object() -> None:
    services = [
        {"port": 443, "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": "a" * 64}}}},
        {"port": 8443, "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": "a" * 64}}}},
    ]
    result = normalize_tls_certificates(context(), host_with(services=services))
    assert len(result.objects) == 1


@pytest.mark.parametrize(
    "fingerprint",
    ["", "not-hex", "a" * 63, "z" * 64, "0x" + "a" * 62],
)
def test_a_value_that_is_not_a_digest_never_becomes_a_certificate(fingerprint: str) -> None:
    services = [
        {"port": 443, "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": fingerprint}}}}
    ]
    result = normalize_tls_certificates(context(), host_with(services=services))
    assert result.objects == ()


def test_a_sha1_fingerprint_is_accepted() -> None:
    services = [
        {"port": 443, "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": "b" * 40}}}}
    ]
    result = normalize_tls_certificates(context(), host_with(services=services))
    assert result.objects[0].canonical_value == "b" * 40


def test_certificates_are_bounded() -> None:
    services = [
        {
            "port": 1000 + index,
            "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": f"{index:064x}"}}},
        }
        for index in range(MAX_CERTIFICATES + 10)
    ]
    result = normalize_tls_certificates(
        context(), host_with(services=services), max_certificates=MAX_CERTIFICATES
    )
    assert len(result.objects) == MAX_CERTIFICATES


def test_no_tls_produces_no_certificate_evidence() -> None:
    assert normalize_tls_certificates(context(), host_with(services=[])).evidence == ()


# --------------------------------------------------------------------------- #
# Labels
# --------------------------------------------------------------------------- #


def test_labels_are_context_and_never_a_classification() -> None:
    """ "login-page" describes millions of legitimate sign-in forms."""
    evidence = normalize_labels(context(), host()).evidence[0]
    assert evidence.claim_type == "censys_labels"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert set(evidence.attributes["labels"]) == {"remote-access", "login-page"}


def test_labels_are_read_whether_they_are_strings_or_objects() -> None:
    evidence = normalize_labels(context(), host()).evidence[0]
    assert "login-page" in evidence.attributes["labels"]


def test_labels_are_bounded() -> None:
    labels = [f"label-{index}" for index in range(MAX_LABELS + 20)]
    evidence = normalize_labels(
        context(), host_with(labels=labels), max_labels=MAX_LABELS
    ).evidence[0]
    assert len(evidence.attributes["labels"]) == MAX_LABELS


def test_no_labels_produces_no_evidence() -> None:
    assert normalize_labels(context(), host_with(labels=[])).evidence == ()


# --------------------------------------------------------------------------- #
# Vulnerabilities
# --------------------------------------------------------------------------- #


def test_a_reported_vulnerability_cannot_carry_a_direction() -> None:
    """Vulnerable is not malicious; exposed is not compromised."""
    evidence = normalize_vulnerabilities(context(), host()).evidence[0]
    assert evidence.claim_type == "censys_vulnerabilities"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_a_vulnerability_says_what_it_was_inferred_from() -> None:
    evidence = normalize_vulnerabilities(context(), host()).evidence[0]
    assert evidence.attributes["basis"] == "inferred_from_observed_service_version"


def test_the_vulnerability_identity_and_severity_are_kept() -> None:
    findings = normalize_vulnerabilities(context(), host()).evidence[0].attributes["findings"]
    assert findings[0]["id"] == "CVE-2021-23017"
    assert findings[0]["severity"] == "high"
    assert findings[0]["cvss_score"] == 7.7


def test_a_bare_cve_string_is_read() -> None:
    evidence = normalize_vulnerabilities(
        context(), host_with(vulnerabilities=["CVE-2024-0001"])
    ).evidence[0]
    assert evidence.attributes["findings"][0]["id"] == "CVE-2024-0001"


def test_a_censys_risk_name_is_read_alongside_cves() -> None:
    evidence = normalize_vulnerabilities(
        context(), host_with(risks=[{"name": "expired-certificate", "severity": "low"}])
    ).evidence[0]
    identifiers = [finding["id"] for finding in evidence.attributes["findings"]]
    assert "expired-certificate" in identifiers


def test_the_same_finding_reported_twice_is_recorded_once() -> None:
    """The asset block and a service block often repeat the same CVE."""
    evidence = normalize_vulnerabilities(
        context(),
        host_with(
            services=[{"port": 443, "vulnerabilities": [{"cve_id": "CVE-2024-0001"}]}],
            vulnerabilities=["CVE-2024-0001"],
        ),
    ).evidence[0]
    identifiers = [finding["id"] for finding in evidence.attributes["findings"]]
    assert identifiers == ["CVE-2024-0001"]


def test_vulnerabilities_are_bounded() -> None:
    findings = [f"CVE-2026-{index:05d}" for index in range(MAX_VULNERABILITIES + 20)]
    evidence = normalize_vulnerabilities(
        context(), host_with(vulnerabilities=findings), max_vulnerabilities=MAX_VULNERABILITIES
    ).evidence[0]
    assert len(evidence.attributes["findings"]) == MAX_VULNERABILITIES


def test_no_vulnerabilities_produces_no_evidence() -> None:
    parsed = host_with(services=[{"port": 22}])
    assert normalize_vulnerabilities(context(), parsed).evidence == ()


# --------------------------------------------------------------------------- #
# Web properties
# --------------------------------------------------------------------------- #


def test_the_web_property_observation_records_its_endpoints() -> None:
    evidence = normalize_web_property_observation(context(), web_property()).evidence[0]
    assert evidence.claim_type == "censys_web_property_observation"
    assert evidence.attributes["hostname"] == payloads.WEB_PROPERTY_HOST
    assert evidence.attributes["port"] == 443
    assert evidence.attributes["endpoint_count"] == 2
    paths = [endpoint["path"] for endpoint in evidence.attributes["endpoints"]]
    assert paths == ["/", "/admin"]


def test_an_endpoint_records_its_status_and_protocol() -> None:
    evidence = normalize_web_property_observation(context(), web_property()).evidence[0]
    admin = next(
        endpoint for endpoint in evidence.attributes["endpoints"] if endpoint["path"] == "/admin"
    )
    assert admin["status_code"] == 403
    assert admin["protocol"] == "HTTP"


def test_a_body_hash_is_kept_as_a_fingerprint_and_never_as_a_file() -> None:
    result = normalize_web_property_observation(context(), web_property())
    evidence = result.evidence[0]
    assert evidence.attributes["body_hashes"] == ["sha256:" + "b" * 64]
    assert all(item.object_type is not IntelObjectType.FILE for item in result.objects)


def test_the_web_property_software_is_recorded() -> None:
    evidence = normalize_web_property_observation(context(), web_property()).evidence[0]
    assert {"vendor": "F5", "product": "NGINX", "version": "1.18.0"} in evidence.attributes[
        "software"
    ]


def test_endpoints_are_bounded_and_the_truncation_is_recorded() -> None:
    endpoints = [{"path": f"/p{index}"} for index in range(MAX_ENDPOINTS + 20)]
    payload = payloads.web_property_payload(endpoints=endpoints)
    evidence = normalize_web_property_observation(
        context(), CensysDocument(payload), max_endpoints=5
    ).evidence[0]
    assert len(evidence.attributes["endpoints"]) == 5
    assert evidence.attributes["endpoints_truncated"] is True


def test_an_empty_web_property_produces_no_observation() -> None:
    assert normalize_web_property_observation(context(), CensysDocument({})).evidence == ()


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


def test_an_unscanned_asset_is_context_and_nothing_else() -> None:
    """The least-visible infrastructure must not look like the safest."""
    evidence = normalize_not_observed(
        context(), asset_kind="host", asset_identifier=payloads.HOST_IP
    ).evidence[0]
    assert evidence.claim_type == "censys_asset_not_observed"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.attributes["observed"] is False
    assert evidence.attributes["asset"] == payloads.HOST_IP


# --------------------------------------------------------------------------- #
# Lineage: one scan, one source
# --------------------------------------------------------------------------- #


def test_every_claim_from_one_scan_shares_one_lineage_group() -> None:
    """Ports, a certificate and two DNS names are not three providers agreeing."""
    evidence = [item for result in every_host_normalization() for item in result.evidence]
    assert len(evidence) > 3
    assert {item.lineage_group_id for item in evidence} == {CENSYS_LINEAGE_GROUP}


def test_nothing_censys_reports_is_marked_relayed() -> None:
    for item in normalize_services(context(), host()).evidence:
        assert item.transport_provider == "censys"
        assert item.origin_provider == "censys"
        assert item.is_relayed is False


def test_the_provider_never_grades_its_own_reliability() -> None:
    for result in every_host_normalization():
        for evidence in result.evidence:
            assert evidence.source_reliability is None
            assert evidence.information_credibility is None
            assert evidence.provider_confidence is None


def test_the_match_scope_travels_from_the_asset_mapping() -> None:
    """A web property is where a URL lives, and every claim says so."""
    scoped = context(match_scope=MatchScope.SAME_HOST)
    for evidence in normalize_web_property_observation(scoped, web_property()).evidence:
        assert evidence.match_scope is MatchScope.SAME_HOST


# --------------------------------------------------------------------------- #
# The anchor
# --------------------------------------------------------------------------- #


def test_relationships_hang_off_the_anchor_rather_than_the_subject() -> None:
    """An address-literal URL is looked up as a host; the links belong to it."""
    url = subject("http://198.51.100.7/panel")
    address = subject("198.51.100.7")
    scoped = context(url, anchor=address, match_scope=MatchScope.SAME_IP)

    result = normalize_network_ownership(scoped, host())
    link = result.relationships[0]
    assert link.source_object_id == address.id
    assert link.source_object_id != url.id
    # The evidence still describes the URL under investigation.
    assert result.evidence[0].subject_object_id == url.id


# --------------------------------------------------------------------------- #
# Object enrichment
# --------------------------------------------------------------------------- #


def test_stable_host_facts_are_attached_under_a_namespaced_key() -> None:
    enriched = enrich_host_object(subject(), host())
    namespace = enriched.properties[CENSYS_PROPERTY_NAMESPACE]
    assert namespace["as_asn"] == 64500
    assert namespace["as_name"] == "EXAMPLE-AS"
    assert namespace["country_code"] == "NL"
    assert namespace["service_count"] == 3
    assert namespace["last_observed_at"].startswith("2026-08-21")


def test_stable_web_property_facts_are_attached_too() -> None:
    enriched = enrich_web_property_object(subject("https://login.example.com/x"), web_property())
    namespace = enriched.properties[CENSYS_PROPERTY_NAMESPACE]
    assert namespace["hostname"] == payloads.WEB_PROPERTY_HOST
    assert namespace["port"] == 443
    assert namespace["endpoint_count"] == 2


def test_enrichment_does_not_mutate_the_submitted_object() -> None:
    original = subject()
    enriched = enrich_host_object(original, host())
    assert original.properties == {}
    assert enriched is not original


def test_an_empty_document_leaves_the_object_alone() -> None:
    original = subject()
    assert enrich_host_object(original, CensysDocument({})) is original
