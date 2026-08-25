"""Normalizing GreyNoise documents into TI Recon models (Task 9).

These are the semantic tests. Three of them carry most of the weight:

* ``suspicious`` and ``malicious`` share a direction and must never share a
  presentation;
* Business Services Intelligence is context and must never become a second,
  independent benign vote;
* absence — ``noise: false``, ``riot: false``, no record at all — is a coverage
  fact and never a benign verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.greynoise import payloads
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
from ti_recon.providers.greynoise import (
    CLASSIFICATION_EFFECTS,
    GREYNOISE_LINEAGE_GROUP,
    GREYNOISE_PROPERTY_NAMESPACE,
    MAX_CVES,
    MAX_PATHS,
    MAX_PORTS,
    MAX_TAGS,
    TRUST_LEVEL_MEANINGS,
    GreyNoiseDocument,
    NormalizationContext,
    enrich_primary_object,
    normalize_business_service,
    normalize_classification,
    normalize_cve_activity,
    normalize_network_context,
    normalize_not_observed,
    normalize_scanner_observation,
    normalize_tags,
)

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def subject(value: str = payloads.SCANNER_IP) -> IntelObject:
    return normalize_observable(value).intel_object


def context(subject_object: IntelObject | None = None) -> NormalizationContext:
    target = subject_object or subject()
    return NormalizationContext(
        investigation_id="inv-1",
        subject_object_id=target.id,
        now=NOW,
        match_scope=MatchScope.EXACT_OBSERVABLE,
    )


def document(payload: dict[str, Any] | None = None) -> GreyNoiseDocument:
    return GreyNoiseDocument(payloads.full_context_payload() if payload is None else payload)


# --------------------------------------------------------------------------- #
# The document reads both response shapes
# --------------------------------------------------------------------------- #


def test_the_nested_v3_shape_is_read() -> None:
    parsed = document()
    assert parsed.classification == "malicious"
    assert parsed.scanner_found is True
    assert parsed.business_found is False
    assert parsed.ip == payloads.SCANNER_IP


def test_the_flat_community_shape_is_read_by_the_same_accessors() -> None:
    parsed = GreyNoiseDocument(payloads.community_payload())
    assert parsed.classification == "malicious"
    assert parsed.scanner_found is True
    assert parsed.business_found is False


def test_an_unstated_flag_is_none_rather_than_false() -> None:
    """ "GreyNoise did not say" and "GreyNoise has no record" are different."""
    parsed = GreyNoiseDocument({"ip": payloads.SCANNER_IP})
    assert parsed.scanner_found is None
    assert parsed.business_found is None


def test_an_unrecognizable_document_is_empty() -> None:
    assert GreyNoiseDocument({}).is_empty is True
    assert GreyNoiseDocument({"unexpected": "shape"}).is_empty is True
    assert document().is_empty is False


def test_a_non_mapping_block_is_tolerated() -> None:
    parsed = GreyNoiseDocument(
        {"internet_scanner_intelligence": "unexpected", "classification": "benign"}
    )
    assert parsed.classification == "benign"
    assert parsed.metadata == {}
    assert parsed.raw_data == {}


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def test_malicious_points_toward_malicious() -> None:
    result = normalize_classification(context(), document())
    evidence = result.evidence[0]
    assert evidence.claim_type == "greynoise_classification"
    assert evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert evidence.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION


def test_suspicious_shares_a_direction_with_malicious_but_not_a_word() -> None:
    """The coarse vocabulary must not turn "suspicious" into "malicious"."""
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["classification"] = "suspicious"
    evidence = normalize_classification(context(), document(payload)).evidence[0]
    assert evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert evidence.attributes["raw_classification"] == "suspicious"
    assert "malicious" not in evidence.attributes.values()


def test_benign_is_an_assertion_and_points_toward_benign() -> None:
    """A known-good scanner is something GreyNoise asserts, not an absence."""
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["classification"] = "benign"
    evidence = normalize_classification(context(), document(payload)).evidence[0]
    assert evidence.effect is EvidenceEffect.SUPPORTS_BENIGN
    assert evidence.attributes["raw_classification"] == "benign"


def test_unknown_points_nowhere() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["classification"] = "unknown"
    evidence = normalize_classification(context(), document(payload)).evidence[0]
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_a_classification_nobody_has_seen_before_points_nowhere() -> None:
    """A changed vocabulary is data, not a licence to guess a direction."""
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["classification"] = "extremely-rude"
    evidence = normalize_classification(context(), document(payload)).evidence[0]
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.attributes["raw_classification"] == "extremely-rude"


def test_a_missing_classification_produces_no_assertion() -> None:
    payload = payloads.full_context_payload()
    del payload["internet_scanner_intelligence"]["classification"]
    assert normalize_classification(context(), document(payload)).evidence == ()


def test_the_raw_classification_is_always_preserved() -> None:
    for word in CLASSIFICATION_EFFECTS:
        payload = payloads.full_context_payload()
        payload["internet_scanner_intelligence"]["classification"] = word
        evidence = normalize_classification(context(), document(payload)).evidence[0]
        assert evidence.attributes["raw_classification"] == word


def test_the_classification_carries_first_and_last_seen() -> None:
    evidence = normalize_classification(context(), document()).evidence[0]
    assert evidence.first_seen == datetime(2026, 2, 1, tzinfo=UTC)
    assert evidence.last_seen == datetime(2026, 8, 20, tzinfo=UTC)


def test_the_classification_carries_the_actor_and_the_permalink() -> None:
    evidence = normalize_classification(context(), document()).evidence[0]
    assert evidence.attributes["actor"] == "unknown"
    assert evidence.attributes["reference"].startswith("https://viz.greynoise.io/")


def test_the_provider_never_grades_its_own_reliability() -> None:
    """Admiralty grading is TI Recon policy, not a provider's to claim."""
    evidence = normalize_classification(context(), document()).evidence[0]
    assert evidence.source_reliability is None
    assert evidence.information_credibility is None
    assert evidence.provider_confidence is None


# --------------------------------------------------------------------------- #
# Business Services Intelligence
# --------------------------------------------------------------------------- #


def bsi_document() -> GreyNoiseDocument:
    return GreyNoiseDocument(payloads.business_service_payload())


def test_a_business_service_record_is_context_only() -> None:
    evidence = normalize_business_service(context(), bsi_document()).evidence[0]
    assert evidence.claim_type == "greynoise_business_service"
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.evidence_class is EvidenceClass.CONTEXT


def test_even_the_highest_trust_level_creates_no_benign_vote() -> None:
    """A trusted service is triage context, not a second opinion."""
    evidence = normalize_business_service(context(), bsi_document()).evidence[0]
    assert evidence.attributes["trust_level"] == "1"
    assert evidence.effect is not EvidenceEffect.SUPPORTS_BENIGN


def test_the_trust_level_meaning_travels_with_the_level() -> None:
    evidence = normalize_business_service(context(), bsi_document()).evidence[0]
    assert evidence.attributes["trust_level_meaning"] == TRUST_LEVEL_MEANINGS["1"]


@pytest.mark.parametrize("level", ["1", "2", "3"])
def test_every_trust_level_is_preserved_for_a_future_fusion_layer(level: str) -> None:
    payload = payloads.business_service_payload()
    payload["business_service_intelligence"]["trust_level"] = level
    evidence = normalize_business_service(context(), GreyNoiseDocument(payload)).evidence[0]
    assert evidence.attributes["trust_level"] == level
    assert evidence.attributes["trust_level_meaning"] == TRUST_LEVEL_MEANINGS[level]


def test_an_integer_trust_level_reads_the_same_as_a_string_one() -> None:
    payload = payloads.business_service_payload()
    payload["business_service_intelligence"]["trust_level"] = 2
    evidence = normalize_business_service(context(), GreyNoiseDocument(payload)).evidence[0]
    assert evidence.attributes["trust_level"] == "2"


def test_the_service_name_category_and_reference_are_kept() -> None:
    evidence = normalize_business_service(context(), bsi_document()).evidence[0]
    assert evidence.attributes["name"] == "Example Public Resolver"
    assert evidence.attributes["category"] == "public_dns"
    assert evidence.attributes["reference"].startswith("https://")
    assert "description" in evidence.attributes
    assert "explanation" in evidence.attributes


def test_an_absent_business_record_adds_nothing() -> None:
    """The absence is already carried by the classification evidence."""
    assert normalize_business_service(context(), document()).evidence == ()


def test_a_nonsense_trust_level_is_dropped_rather_than_stored() -> None:
    payload = payloads.business_service_payload()
    payload["business_service_intelligence"]["trust_level"] = "very trustworthy indeed"
    evidence = normalize_business_service(context(), GreyNoiseDocument(payload)).evidence[0]
    assert "trust_level" not in evidence.attributes


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


def test_not_being_observed_is_context_and_nothing_else() -> None:
    evidence = normalize_not_observed(context(), GreyNoiseDocument({})).evidence[0]
    assert evidence.claim_type == "greynoise_not_observed"
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.attributes["observed_scanning"] is False


def test_no_scanning_record_never_becomes_a_benign_signal() -> None:
    """``found: false`` produces a coverage fact, and no assertion at all."""
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"] = {"found": False}
    parsed = document(payload)
    assert normalize_classification(context(), parsed).evidence == ()

    recorded = normalize_not_observed(context(), parsed).evidence
    assert len(recorded) == 1
    assert recorded[0].effect is EvidenceEffect.CONTEXT_ONLY
    assert recorded[0].attributes["observed_scanning"] is False


def test_riot_false_never_becomes_a_malicious_signal() -> None:
    payload = payloads.community_payload(riot=False, classification="unknown")
    parsed = GreyNoiseDocument(payload)
    for evidence in (
        normalize_classification(context(), parsed).evidence
        + normalize_business_service(context(), parsed).evidence
    ):
        assert evidence.effect is not EvidenceEffect.SUPPORTS_MALICIOUS


# --------------------------------------------------------------------------- #
# Sensor observations
# --------------------------------------------------------------------------- #


def test_the_sensor_observation_carries_facts_and_no_direction() -> None:
    evidence = normalize_scanner_observation(context(), document()).evidence[0]
    assert evidence.claim_type == "greynoise_scanner_observation"
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.evidence_class is EvidenceClass.DIRECT_OBSERVATION


def test_spoofable_and_vpn_are_recorded_as_the_facts_they_are() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"].update(
        {"spoofable": True, "vpn": True, "vpn_service": "ExampleVPN", "tor": False, "bot": True}
    )
    evidence = normalize_scanner_observation(context(), document(payload)).evidence[0]
    assert evidence.attributes["spoofable"] is True
    assert evidence.attributes["vpn"] is True
    assert evidence.attributes["vpn_service"] == "ExampleVPN"
    assert evidence.attributes["tor"] is False
    assert evidence.attributes["bot"] is True


def test_sensor_detail_is_included_when_asked_for() -> None:
    evidence = normalize_scanner_observation(
        context(), document(), include_sensor_detail=True
    ).evidence[0]
    assert {"port": 22, "protocol": "TCP"} in evidence.attributes["ports"]
    assert "/.env" in evidence.attributes["web_paths"]
    assert evidence.attributes["ja3"] == ["a" * 32]
    assert evidence.attributes["hassh"] == ["b" * 32]


def test_sensor_detail_is_omitted_when_it_was_not_asked_for() -> None:
    """The fields were already paid for; depth decides whether to record them."""
    evidence = normalize_scanner_observation(
        context(), document(), include_sensor_detail=False
    ).evidence[0]
    assert "ports" not in evidence.attributes
    assert "web_paths" not in evidence.attributes
    assert "ja3" not in evidence.attributes


def test_sensor_counters_are_kept_at_every_depth() -> None:
    evidence = normalize_scanner_observation(
        context(), document(), include_sensor_detail=False
    ).evidence[0]
    assert evidence.attributes["sensor_count"] == 412
    assert evidence.attributes["sensor_hits"] == 90_112


def test_ports_are_bounded() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["raw_data"]["scan"] = [
        {"port": port, "protocol": "TCP"} for port in range(1, MAX_PORTS + 50)
    ]
    evidence = normalize_scanner_observation(context(), document(payload)).evidence[0]
    assert len(evidence.attributes["ports"]) == MAX_PORTS


def test_paths_are_bounded_and_deduplicated() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["raw_data"]["web"]["paths"] = [
        f"/path-{index}" for index in range(MAX_PATHS + 20)
    ] + ["/path-0"]
    evidence = normalize_scanner_observation(context(), document(payload)).evidence[0]
    paths = evidence.attributes["web_paths"]
    assert len(paths) == MAX_PATHS
    assert len(set(paths)) == len(paths)


def test_a_nonsense_port_is_dropped() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["raw_data"]["scan"] = [
        {"port": 70_000, "protocol": "TCP"},
        {"port": "twenty-two"},
        {"port": 443, "protocol": "TCP"},
    ]
    evidence = normalize_scanner_observation(context(), document(payload)).evidence[0]
    assert evidence.attributes["ports"] == [{"port": 443, "protocol": "TCP"}]


def test_no_user_agent_string_is_stored() -> None:
    """Attacker-chosen text with no analytical value the paths do not already give."""
    evidence = normalize_scanner_observation(context(), document()).evidence[0]
    assert "useragents" not in evidence.attributes
    assert "curl/8.5.0" not in str(evidence.attributes)


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #


def test_every_tag_becomes_one_aggregated_observation() -> None:
    """Never one piece of evidence per tag: that would be one provider voting twice."""
    result = normalize_tags(context(), document())
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.claim_type == "greynoise_tags"
    assert evidence.attributes["tags"] == ["SSH Bruteforcer", "Log4Shell Scanner"]
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_tag_categories_and_intentions_travel_with_the_names() -> None:
    evidence = normalize_tags(context(), document()).evidence[0]
    assert evidence.attributes["tag_categories"] == ["activity"]
    assert evidence.attributes["tag_intentions"] == ["malicious"]


def test_a_tag_intention_of_malicious_does_not_become_a_direction() -> None:
    """The classification already carries GreyNoise's opinion, exactly once."""
    evidence = normalize_tags(context(), document()).evidence[0]
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_tags_are_bounded_and_deduplicated() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["tags"] = [
        {"name": f"Tag {index}"} for index in range(MAX_TAGS + 10)
    ] + [{"name": "Tag 0"}]
    evidence = normalize_tags(context(), document(payload)).evidence[0]
    tags = evidence.attributes["tags"]
    assert len(tags) == MAX_TAGS
    assert len(set(tags)) == len(tags)


def test_bare_string_tags_are_read_too() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["tags"] = ["Mirai", "Web Crawler"]
    evidence = normalize_tags(context(), document(payload)).evidence[0]
    assert evidence.attributes["tags"] == ["Mirai", "Web Crawler"]


def test_no_tags_produces_no_evidence() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["tags"] = []
    assert normalize_tags(context(), document(payload)).evidence == ()


# --------------------------------------------------------------------------- #
# CVE associations
# --------------------------------------------------------------------------- #


def test_a_cve_association_is_context_and_cannot_carry_a_direction() -> None:
    """A scanner probing for Log4Shell is not a Log4Shell victim."""
    evidence = normalize_cve_activity(context(), document()).evidence[0]
    assert evidence.claim_type == "greynoise_cve_activity"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_the_cve_association_says_what_it_is_an_association_with() -> None:
    evidence = normalize_cve_activity(context(), document()).evidence[0]
    assert evidence.attributes["association"] == "observed_scanning_activity"


def test_only_well_formed_cve_ids_are_kept() -> None:
    evidence = normalize_cve_activity(context(), document()).evidence[0]
    assert evidence.attributes["cves"] == ["CVE-2021-44228", "CVE-2023-1389"]
    assert "not-a-cve" not in evidence.attributes["cves"]


def test_cves_are_bounded() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["cves"] = [
        f"CVE-2026-{index:05d}" for index in range(MAX_CVES + 10)
    ]
    evidence = normalize_cve_activity(context(), document(payload)).evidence[0]
    assert len(evidence.attributes["cves"]) == MAX_CVES


def test_no_cves_produces_no_evidence() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["cves"] = []
    assert normalize_cve_activity(context(), document(payload)).evidence == ()


# --------------------------------------------------------------------------- #
# Network context and pivots
# --------------------------------------------------------------------------- #


def test_the_network_context_is_context_only() -> None:
    evidence = normalize_network_context(context(), document()).evidence[0]
    assert evidence.claim_type == "greynoise_network_context"
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_the_allow_listed_metadata_is_kept() -> None:
    evidence = normalize_network_context(context(), document()).evidence[0]
    assert evidence.attributes["asn"] == "AS64500"
    assert evidence.attributes["organization"] == "Example Hosting LLC"
    assert evidence.attributes["source_country_code"] == "NL"
    assert evidence.attributes["rdns"] == "scanner-7.node.example"


def test_an_unlisted_metadata_field_is_ignored() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["metadata"]["surprise_field"] = "value"
    evidence = normalize_network_context(context(), document(payload)).evidence[0]
    assert "surprise_field" not in evidence.attributes


def test_the_asn_becomes_an_object_the_address_belongs_to() -> None:
    target = subject()
    result = normalize_network_context(context(target), document())
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


def test_the_reverse_name_resolves_to_the_address_and_not_the_other_way() -> None:
    target = subject()
    result = normalize_network_context(context(target), document())
    link = next(
        item
        for item in result.relationships
        if item.relationship_type is RelationshipType.RESOLVES_TO
    )
    name = next(item for item in result.objects if item.object_type is IntelObjectType.DOMAIN_NAME)
    assert link.source_object_id == name.id
    assert link.target_object_id == target.id


def test_every_relationship_references_the_evidence_that_justifies_it() -> None:
    result = normalize_network_context(context(), document())
    evidence_ids = {item.id for item in result.evidence}
    for relationship in result.relationships:
        assert relationship.evidence_refs
        assert set(relationship.evidence_refs) <= evidence_ids


def test_an_invalid_reverse_name_is_dropped_rather_than_trusted() -> None:
    """A PTR record is chosen by whoever owns the address block."""
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["metadata"]["rdns"] = "not a hostname at all"
    result = normalize_network_context(context(), document(payload))
    assert all(item.object_type is not IntelObjectType.DOMAIN_NAME for item in result.objects)


def test_a_malformed_asn_is_dropped() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["metadata"]["asn"] = "AS-not-a-number"
    result = normalize_network_context(context(), document(payload))
    assert all(item.object_type is not IntelObjectType.AUTONOMOUS_SYSTEM for item in result.objects)


def test_no_metadata_produces_no_network_context() -> None:
    payload = payloads.community_payload()
    assert normalize_network_context(context(), GreyNoiseDocument(payload)).evidence == ()


# --------------------------------------------------------------------------- #
# Lineage: one provider, one source
# --------------------------------------------------------------------------- #


def test_every_claim_shares_one_lineage_group() -> None:
    """Classification, tags, CVEs and BSI are one source saying several things."""
    parsed = document()
    business = GreyNoiseDocument(payloads.business_service_payload())
    evidence = (
        normalize_classification(context(), parsed).evidence
        + normalize_tags(context(), parsed).evidence
        + normalize_cve_activity(context(), parsed).evidence
        + normalize_network_context(context(), parsed).evidence
        + normalize_business_service(context(), business).evidence
    )
    assert len({item.lineage_group_id for item in evidence}) == 1
    assert evidence[0].lineage_group_id == GREYNOISE_LINEAGE_GROUP


def test_nothing_greynoise_reports_is_marked_relayed() -> None:
    """It runs its own sensors and curates its own inventory."""
    for evidence in normalize_classification(context(), document()).evidence:
        assert evidence.transport_provider == "greynoise"
        assert evidence.origin_provider == "greynoise"
        assert evidence.is_relayed is False


def test_the_match_scope_is_the_address_itself() -> None:
    evidence = normalize_classification(context(), document()).evidence[0]
    assert evidence.match_scope is MatchScope.EXACT_OBSERVABLE


# --------------------------------------------------------------------------- #
# Object enrichment
# --------------------------------------------------------------------------- #


def test_stable_facts_are_attached_under_a_namespaced_key() -> None:
    enriched = enrich_primary_object(subject(), document())
    namespace = enriched.properties[GREYNOISE_PROPERTY_NAMESPACE]
    assert namespace["asn"] == "AS64500"
    assert namespace["classification"] == "malicious"
    assert namespace["observed_scanning"] is True
    assert namespace["last_seen"].startswith("2026-08-20")


def test_enrichment_does_not_mutate_the_submitted_object() -> None:
    original = subject()
    enriched = enrich_primary_object(original, document())
    assert original.properties == {}
    assert enriched is not original


def test_an_empty_document_leaves_the_object_alone() -> None:
    original = subject()
    assert enrich_primary_object(original, GreyNoiseDocument({})) is original
