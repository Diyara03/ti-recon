"""Normalizing urlscan scan intelligence (Task 8).

The rules under test are about attribution and direction: whose opinion each
piece of evidence is, and which way it points.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.urlscan.payloads import SCAN_ID, result_payload
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.urlscan.descriptor import (
    URLSCAN_PROVIDER_ID,
    URLSCAN_SOURCE_FAMILY,
)
from ti_recon.providers.urlscan.normalizer import (
    ENGINE_AGGREGATE_FAMILY,
    MAX_BRANDS,
    MAX_CATEGORIES,
    URLSCAN_ENGINES_ORIGIN,
    URLSCAN_PROPERTY_NAMESPACE,
    URLSCAN_SCAN_UNREADABLE,
    URLSCAN_VERDICTS_UNREADABLE,
    NormalizationContext,
    ScanDocument,
    enrich_primary_object,
    match_scope_for_scan,
    normalize_page_context,
    normalize_scan_observation,
    normalize_verdicts,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
SCANNED_AT = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)


def context(match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE) -> NormalizationContext:
    return NormalizationContext(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        now=NOW,
        match_scope=match_scope,
    )


def document(**overrides: Any) -> ScanDocument:
    return ScanDocument(result_payload(**overrides))


def observable(object_type: IntelObjectType, value: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
    )


def by_claim(evidence: tuple[Evidence, ...], claim_type: str) -> Evidence | None:
    for item in evidence:
        if item.claim_type == claim_type:
            return item
    return None


# --------------------------------------------------------------------------- #
# Verdicts: three sources, correctly attributed
# --------------------------------------------------------------------------- #


def test_the_three_verdict_sources_become_three_pieces_of_evidence() -> None:
    result = normalize_verdicts(context(), document())
    assert {item.claim_type for item in result.evidence} == {
        "urlscan_verdict",
        "urlscan_engine_aggregate",
        "urlscan_community_votes",
    }


def test_the_provider_roll_up_is_not_normalized_as_a_fourth_opinion() -> None:
    """`verdicts.overall` combines the other three; emitting it would double count."""
    result = normalize_verdicts(context(), document())
    assert all("overall" not in item.claim_type for item in result.evidence)
    assert len(result.evidence) == 3


def test_urlscans_own_verdict_is_first_hand() -> None:
    verdict = by_claim(normalize_verdicts(context(), document()).evidence, "urlscan_verdict")
    assert verdict is not None
    assert verdict.transport_provider == URLSCAN_PROVIDER_ID
    assert verdict.origin_provider == URLSCAN_PROVIDER_ID
    assert verdict.is_relayed is False
    assert verdict.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert verdict.effect is EvidenceEffect.SUPPORTS_MALICIOUS


def test_the_engine_aggregate_is_relayed_and_not_urlscans_own_family() -> None:
    """Otherwise urlscan's verdict and a blocklist hit look like two sources agreeing."""
    aggregate = by_claim(
        normalize_verdicts(context(), document()).evidence, "urlscan_engine_aggregate"
    )
    assert aggregate is not None
    assert aggregate.transport_provider == URLSCAN_PROVIDER_ID
    assert aggregate.origin_provider == URLSCAN_ENGINES_ORIGIN
    assert aggregate.is_relayed is True
    assert aggregate.source_family == ENGINE_AGGREGATE_FAMILY
    assert aggregate.source_family != URLSCAN_SOURCE_FAMILY


def test_the_engine_aggregate_and_the_urlscan_verdict_are_separate_lineages() -> None:
    evidence = normalize_verdicts(context(), document()).evidence
    verdict = by_claim(evidence, "urlscan_verdict")
    aggregate = by_claim(evidence, "urlscan_engine_aggregate")
    assert verdict is not None
    assert aggregate is not None
    assert not verdict.shares_lineage_with(aggregate)


def test_twelve_engines_are_still_one_piece_of_evidence() -> None:
    """A roll-up of many opinions is one source, never many."""
    evidence = normalize_verdicts(context(), document()).evidence
    aggregate = by_claim(evidence, "urlscan_engine_aggregate")
    assert aggregate is not None
    assert aggregate.attributes["engines_total"] == 12
    assert aggregate.attributes["malicious_total"] == 2
    assert aggregate.attributes["malicious_engines"] == ["GoogleSafeBrowsing", "PhishTank"]
    assert len([item for item in evidence if "engine" in item.claim_type]) == 1


def test_community_votes_are_attributed_to_the_community() -> None:
    votes = by_claim(normalize_verdicts(context(), document()).evidence, "urlscan_community_votes")
    assert votes is not None
    assert votes.origin_provider == "urlscan_community"
    assert votes.is_relayed is True
    assert votes.attributes == {"votes_malicious": 3, "votes_benign": 0, "score": 0.0}


# --------------------------------------------------------------------------- #
# Direction is asymmetric everywhere
# --------------------------------------------------------------------------- #


def test_urlscan_not_flagging_a_page_supports_nothing() -> None:
    """ "Our heuristics did not fire" is equally true of every kit deployed today."""
    payload = result_payload()
    payload["verdicts"]["urlscan"]["malicious"] = False
    payload["verdicts"]["urlscan"]["score"] = 0
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert verdict.effect is EvidenceEffect.CONTEXT_ONLY
    assert verdict.effect is not EvidenceEffect.SUPPORTS_BENIGN


def test_zero_of_ninety_engines_flagging_supports_nothing() -> None:
    payload = result_payload()
    payload["verdicts"]["engines"] = {
        "malicious": [],
        "benign": ["A", "B"],
        "maliciousTotal": 0,
        "enginesTotal": 90,
    }
    aggregate = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence,
        "urlscan_engine_aggregate",
    )
    assert aggregate is not None
    assert aggregate.effect is EvidenceEffect.CONTEXT_ONLY


def test_benign_votes_never_support_benign() -> None:
    """TI Recon requires an observation or an authority for benign, not a show of hands."""
    payload = result_payload()
    payload["verdicts"]["community"] = {"votesMalicious": 0, "votesBenign": 40}
    votes = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence,
        "urlscan_community_votes",
    )
    assert votes is not None
    assert votes.effect is EvidenceEffect.CONTEXT_ONLY


def test_a_single_malicious_vote_points_somewhere() -> None:
    payload = result_payload()
    payload["verdicts"]["community"] = {"votesMalicious": 1, "votesBenign": 40}
    votes = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence,
        "urlscan_community_votes",
    )
    assert votes is not None
    assert votes.effect is EvidenceEffect.SUPPORTS_MALICIOUS


def test_a_malicious_engine_list_without_a_total_is_still_counted() -> None:
    payload = result_payload()
    payload["verdicts"]["engines"] = {"malicious": ["GoogleSafeBrowsing"]}
    aggregate = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence,
        "urlscan_engine_aggregate",
    )
    assert aggregate is not None
    assert aggregate.attributes["malicious_total"] == 1
    assert aggregate.effect is EvidenceEffect.SUPPORTS_MALICIOUS


# --------------------------------------------------------------------------- #
# Detected brands and categories
# --------------------------------------------------------------------------- #


def test_a_detected_brand_travels_with_the_verdict() -> None:
    verdict = by_claim(normalize_verdicts(context(), document()).evidence, "urlscan_verdict")
    assert verdict is not None
    assert verdict.attributes["brands"] == ["Microsoft"]
    assert verdict.attributes["categories"] == ["phishing"]
    assert verdict.attributes["tags"] == ["credential-harvest"]


def test_brand_and_category_lists_are_bounded() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"]["brands"] = [{"name": f"Brand{index}"} for index in range(50)]
    payload["verdicts"]["urlscan"]["categories"] = [f"cat{index}" for index in range(50)]
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert len(verdict.attributes["brands"]) == MAX_BRANDS
    assert len(verdict.attributes["categories"]) == MAX_CATEGORIES


def test_a_brand_given_as_a_bare_string_is_still_read() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"]["brands"] = ["Microsoft", "Microsoft", 42]
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert verdict.attributes["brands"] == ["Microsoft"]


def test_a_brand_without_a_name_falls_back_to_its_key() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"]["brands"] = [{"key": "microsoft"}]
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert verdict.attributes["brands"] == ["microsoft"]


# --------------------------------------------------------------------------- #
# Missing and malformed blocks
# --------------------------------------------------------------------------- #


def test_no_verdicts_block_yields_nothing_rather_than_a_warning() -> None:
    result = normalize_verdicts(context(), ScanDocument({"task": {}}))
    assert result.evidence == ()
    assert result.warnings == ()
    assert result.degraded is False


def test_an_unreadable_verdicts_block_is_reported_as_degraded() -> None:
    result = normalize_verdicts(
        context(), ScanDocument({"verdicts": {"urlscan": {"score": "high"}}})
    )
    assert result.evidence == ()
    assert result.warnings == (URLSCAN_VERDICTS_UNREADABLE,)
    assert result.degraded is True


def test_one_unreadable_sub_verdict_does_not_discard_the_others() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"] = {"score": None, "malicious": None}
    result = normalize_verdicts(context(), ScanDocument(payload))
    assert {item.claim_type for item in result.evidence} == {
        "urlscan_engine_aggregate",
        "urlscan_community_votes",
    }
    assert result.degraded is False


# --------------------------------------------------------------------------- #
# The scan observation and page context
# --------------------------------------------------------------------------- #


def test_a_scan_is_a_direct_observation_with_no_direction() -> None:
    evidence = normalize_scan_observation(context(), document()).evidence
    assert len(evidence) == 1
    observation = evidence[0]
    assert observation.evidence_class is EvidenceClass.DIRECT_OBSERVATION
    assert observation.effect is EvidenceEffect.CONTEXT_ONLY
    assert observation.attributes["scan_id"] == SCAN_ID
    assert observation.attributes["page_status"] == "200"
    assert observation.attributes["task_visibility"] == "public"
    assert observation.observed_at == SCANNED_AT
    assert observation.first_seen == SCANNED_AT


def test_an_empty_document_is_degraded_rather_than_silently_empty() -> None:
    result = normalize_scan_observation(context(), ScanDocument({}))
    assert result.warnings == (URLSCAN_SCAN_UNREADABLE,)
    assert result.degraded is True


def test_a_document_with_only_a_scan_id_is_degraded() -> None:
    result = normalize_scan_observation(context(), ScanDocument({"task": {"uuid": SCAN_ID}}))
    assert result.degraded is True


def test_hosting_context_points_nowhere() -> None:
    """Letting "hosted in country X" nudge a verdict makes a country a proxy for guilt."""
    evidence = normalize_page_context(context(), document()).evidence
    assert len(evidence) == 1
    page_context = evidence[0]
    assert page_context.evidence_class is EvidenceClass.CONTEXT
    assert page_context.effect is EvidenceEffect.CONTEXT_ONLY
    assert page_context.attributes["asn"] == "AS64500"
    assert page_context.attributes["country"] == "US"
    assert page_context.attributes["tls_issuer"] == "R11"
    assert page_context.attributes["tls_valid_from"] == "2026-08-01T00:00:00+00:00"


def test_page_context_is_absent_rather_than_empty_when_urlscan_says_nothing() -> None:
    assert normalize_page_context(context(), ScanDocument({"page": {}})).evidence == ()
    assert normalize_page_context(context(), ScanDocument({"page": {"url": "x"}})).evidence == ()


# --------------------------------------------------------------------------- #
# Provenance rules that apply to every piece of evidence
# --------------------------------------------------------------------------- #


def all_evidence() -> tuple[Evidence, ...]:
    scan_document = document()
    result = (
        normalize_verdicts(context(), scan_document)
        .merge(normalize_scan_observation(context(), scan_document))
        .merge(normalize_page_context(context(), scan_document))
    )
    return result.evidence


def test_no_adapter_assigns_an_admiralty_grade() -> None:
    """Grading a source is TI Recon policy, never a provider's to claim."""
    for item in all_evidence():
        assert item.source_reliability is None
        assert item.information_credibility is None


def test_every_piece_of_evidence_carries_the_requested_scope_and_time() -> None:
    for item in all_evidence():
        assert item.match_scope is MatchScope.EXACT_OBSERVABLE
        assert item.retrieved_at == NOW
        assert item.transport_provider == URLSCAN_PROVIDER_ID


def test_no_evidence_carries_a_verdict_or_a_risk_score() -> None:
    """An adapter reports and classifies; it never concludes."""
    for item in all_evidence():
        assert "verdict" not in item.attributes
        assert "risk" not in item.attributes
        assert "confidence" not in item.attributes
        assert item.provider_confidence is None


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("object_type", "value", "expected"),
    [
        (
            IntelObjectType.URL,
            "https://login.evil.example/office/index.html",
            MatchScope.EXACT_OBSERVABLE,
        ),
        (IntelObjectType.URL, "https://login.evil.example/office/", MatchScope.EXACT_OBSERVABLE),
        (IntelObjectType.URL, "https://login.evil.example/other", MatchScope.SAME_HOST),
        (IntelObjectType.DOMAIN_NAME, "login.evil.example", MatchScope.SAME_HOST),
        (IntelObjectType.DOMAIN_NAME, "evil.example", MatchScope.PARENT_DOMAIN),
        (IntelObjectType.DOMAIN_NAME, "fonts.example.com", MatchScope.CLUSTER),
        (IntelObjectType.IPV4_ADDR, "198.51.100.7", MatchScope.SAME_IP),
        (IntelObjectType.IPV4_ADDR, "203.0.113.9", MatchScope.CLUSTER),
    ],
)
def test_scope_records_how_precisely_a_scan_applies(
    object_type: IntelObjectType, value: str, expected: MatchScope
) -> None:
    assert match_scope_for_scan(observable(object_type, value), document()) is expected


def test_a_file_is_evidence_about_the_page_that_served_it() -> None:
    digest = "a" * 64
    file_object = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {"SHA-256": digest}},
    )
    assert match_scope_for_scan(file_object, document()) is MatchScope.SAME_HOST


def test_an_object_type_urlscan_does_not_answer_for_has_unknown_scope() -> None:
    asn = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value="AS64500",
        display_value="AS64500",
    )
    assert match_scope_for_scan(asn, document()) is MatchScope.UNKNOWN


# --------------------------------------------------------------------------- #
# Object enrichment
# --------------------------------------------------------------------------- #


def test_stable_facts_become_properties_under_one_namespace() -> None:
    subject = observable(IntelObjectType.DOMAIN_NAME, "login.evil.example")
    enriched = enrich_primary_object(subject, document())
    namespace = enriched.properties[URLSCAN_PROPERTY_NAMESPACE]
    assert namespace["ip"] == "198.51.100.7"
    assert namespace["asn"] == "AS64500"
    assert namespace["server"] == "nginx/1.24.0"
    assert namespace["last_scan_id"] == SCAN_ID
    assert namespace["last_scanned_at"] == "2026-08-20T10:00:00+00:00"


def test_judgements_never_become_properties() -> None:
    """A verdict has a provenance and a moment; a property carries neither."""
    enriched = enrich_primary_object(
        observable(IntelObjectType.DOMAIN_NAME, "login.evil.example"), document()
    )
    namespace = enriched.properties[URLSCAN_PROPERTY_NAMESPACE]
    for forbidden in ("malicious", "score", "verdict", "brands", "categories"):
        assert forbidden not in namespace


def test_enrichment_does_not_mutate_the_submitted_object() -> None:
    subject = observable(IntelObjectType.DOMAIN_NAME, "login.evil.example")
    enrich_primary_object(subject, document())
    assert subject.properties == {}


def test_a_document_with_nothing_to_add_returns_the_object_unchanged() -> None:
    subject = observable(IntelObjectType.DOMAIN_NAME, "login.evil.example")
    assert enrich_primary_object(subject, ScanDocument({})) is subject


def test_existing_urlscan_properties_are_updated_not_replaced() -> None:
    subject = observable(IntelObjectType.DOMAIN_NAME, "login.evil.example")
    subject.properties[URLSCAN_PROPERTY_NAMESPACE] = {"earlier": "kept"}
    enriched = enrich_primary_object(subject, document())
    namespace = enriched.properties[URLSCAN_PROPERTY_NAMESPACE]
    assert namespace["earlier"] == "kept"
    assert namespace["ip"] == "198.51.100.7"


# --------------------------------------------------------------------------- #
# Sparse documents
# --------------------------------------------------------------------------- #


def test_each_verdict_source_is_independent_of_the_others_being_present() -> None:
    for present in ("urlscan", "engines", "community"):
        payload = result_payload()
        payload["verdicts"] = {present: payload["verdicts"][present]}
        result = normalize_verdicts(context(), ScanDocument(payload))
        assert len(result.evidence) == 1


def test_a_bare_verdict_carries_only_what_urlscan_reported() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"] = {"malicious": True}
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert verdict.attributes == {"malicious": True}


def test_an_engine_block_with_only_a_total_is_still_read() -> None:
    payload = result_payload()
    payload["verdicts"]["engines"] = {"enginesTotal": 90}
    aggregate = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence,
        "urlscan_engine_aggregate",
    )
    assert aggregate is not None
    assert aggregate.attributes == {"malicious_total": 0, "engines_total": 90}
    assert aggregate.effect is EvidenceEffect.CONTEXT_ONLY


def test_an_empty_community_block_yields_no_votes_evidence() -> None:
    payload = result_payload()
    payload["verdicts"]["community"] = {"votesTotal": 0}
    assert (
        by_claim(
            normalize_verdicts(context(), ScanDocument(payload)).evidence,
            "urlscan_community_votes",
        )
        is None
    )


def test_a_scan_without_an_id_still_records_what_was_seen() -> None:
    payload = result_payload()
    del payload["task"]["uuid"]
    evidence = normalize_scan_observation(context(), ScanDocument(payload)).evidence
    assert len(evidence) == 1
    assert "scan_id" not in evidence[0].attributes
    assert evidence[0].attributes["page_domain"] == "login.evil.example"


def test_boolean_and_list_fields_survive_normalization() -> None:
    payload = result_payload()
    payload["page"]["redirected"] = True
    evidence = normalize_scan_observation(context(), ScanDocument(payload)).evidence
    assert evidence[0].attributes["page_redirected"] is True
    assert evidence[0].attributes["task_tags"] == ["phishing-hunt"]


def test_duplicate_and_unusable_list_entries_are_dropped() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"]["categories"] = ["phishing", "phishing", None, 7, "  "]
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert verdict.attributes["categories"] == ["phishing"]


def test_a_brands_field_of_the_wrong_shape_is_ignored() -> None:
    payload = result_payload()
    payload["verdicts"]["urlscan"]["brands"] = {"name": "Microsoft"}
    verdict = by_claim(
        normalize_verdicts(context(), ScanDocument(payload)).evidence, "urlscan_verdict"
    )
    assert verdict is not None
    assert "brands" not in verdict.attributes


def test_nested_lookup_tolerates_a_block_of_the_wrong_type() -> None:
    assert ScanDocument({"verdicts": "nope"}).nested("verdicts", "urlscan") == {}
    assert ScanDocument({"verdicts": {"urlscan": 5}}).nested("verdicts", "urlscan") == {}


def test_an_engine_block_with_nothing_readable_yields_no_evidence() -> None:
    payload = result_payload()
    payload["verdicts"]["engines"] = {"benign": ["A"], "score": 0}
    assert (
        by_claim(
            normalize_verdicts(context(), ScanDocument(payload)).evidence,
            "urlscan_engine_aggregate",
        )
        is None
    )
