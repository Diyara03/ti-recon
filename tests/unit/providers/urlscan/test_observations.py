"""Bounded web observations (Task 8).

What a browser did when it loaded the page — and, just as important, what a
result document contains that TI Recon deliberately never keeps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.urlscan.payloads import result_payload
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.evidence import Evidence
from ti_recon.providers.urlscan.normalizer import NormalizationContext, ScanDocument
from ti_recon.providers.urlscan.observations import (
    MAX_CONTACTED_DOMAINS,
    MAX_REDIRECT_HOPS,
    MAX_SERVED_HASHES,
    normalize_contacted_infrastructure,
    normalize_redirect_chain,
    normalize_served_bodies,
    normalize_traffic_summary,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
SCANNED_AT = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)


def context() -> NormalizationContext:
    return NormalizationContext(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        now=NOW,
        match_scope=MatchScope.SAME_HOST,
    )


def document(**overrides: Any) -> ScanDocument:
    return ScanDocument(result_payload(**overrides))


def redirect_request(url: str, status: int = 302) -> dict[str, Any]:
    return {
        "request": {
            "request": {"url": url, "method": "GET"},
            "redirectResponse": {
                "status": status,
                "headers": {"set-cookie": "session=SHOULD-NOT-BE-KEPT"},
            },
        }
    }


# --------------------------------------------------------------------------- #
# Redirects
# --------------------------------------------------------------------------- #


def test_a_redirect_chain_becomes_an_observation_and_links() -> None:
    result = normalize_redirect_chain(context(), document())
    assert len(result.evidence) == 1
    chain = result.evidence[0]
    assert chain.claim_type == "urlscan_redirect_chain"
    assert chain.evidence_class is EvidenceClass.DIRECT_OBSERVATION
    assert chain.effect is EvidenceEffect.CONTEXT_ONLY
    assert chain.attributes["chain"] == [
        "https://evil.example/",
        "https://login.evil.example/office/index.html",
    ]
    assert chain.attributes["hops"] == 1
    assert [link.relationship_type for link in result.relationships] == [
        RelationshipType.REDIRECTS_TO
    ]


def test_every_relationship_is_backed_by_the_evidence_that_explains_it() -> None:
    result = normalize_redirect_chain(context(), document())
    evidence_ids = {item.id for item in result.evidence}
    for link in result.relationships:
        assert link.evidence_refs
        assert set(link.evidence_refs) <= evidence_ids


def test_redirect_hops_are_capped_and_the_cut_is_recorded() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        redirect_request(f"https://hop{index}.example/") for index in range(60)
    ]
    result = normalize_redirect_chain(context(), ScanDocument(payload))
    chain = result.evidence[0]
    assert len(chain.attributes["chain"]) <= MAX_REDIRECT_HOPS
    assert chain.attributes["truncated"] is True


def test_a_single_url_is_not_a_chain() -> None:
    payload = result_payload()
    payload["data"] = {"requests": []}
    assert normalize_redirect_chain(context(), ScanDocument(payload)).evidence == ()


def test_a_non_redirect_request_is_not_a_hop() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        {"request": {"request": {"url": "https://cdn.evil.example/kit.js"}}}
    ]
    assert normalize_redirect_chain(context(), ScanDocument(payload)).evidence == ()


def test_a_redirect_status_that_is_not_a_redirect_is_ignored() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [redirect_request("https://evil.example/", status=200)]
    assert normalize_redirect_chain(context(), ScanDocument(payload)).evidence == ()


def test_an_unparseable_hop_is_dropped_rather_than_trusted() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        redirect_request("javascript:alert(1)"),
        redirect_request("https://evil.example/"),
    ]
    chain = normalize_redirect_chain(context(), ScanDocument(payload)).evidence[0]
    assert chain.attributes["chain"] == [
        "https://evil.example/",
        "https://login.evil.example/office/index.html",
    ]


@pytest.mark.parametrize(
    "requests",
    ["not-a-list", [{"request": "wrong"}], [{"nope": 1}], [42]],
)
def test_a_malformed_request_list_yields_nothing(requests: Any) -> None:
    payload = result_payload()
    payload["data"] = {"requests": requests}
    assert normalize_redirect_chain(context(), ScanDocument(payload)).evidence == ()


def test_a_repeated_hop_is_collapsed() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        redirect_request("https://evil.example/"),
        redirect_request("https://evil.example/"),
    ]
    chain = normalize_redirect_chain(context(), ScanDocument(payload)).evidence[0]
    assert chain.attributes["hops"] == 1


# --------------------------------------------------------------------------- #
# What is never kept
# --------------------------------------------------------------------------- #


def all_observations(scan_document: ScanDocument) -> tuple[Evidence, ...]:
    result = (
        normalize_redirect_chain(context(), scan_document)
        .merge(normalize_contacted_infrastructure(context(), scan_document))
        .merge(normalize_served_bodies(context(), scan_document))
        .merge(normalize_traffic_summary(context(), scan_document))
    )
    return result.evidence


def test_headers_and_cookies_never_reach_evidence() -> None:
    """A stored header turns an investigation record into a credential leak."""
    payload = result_payload()
    payload["data"]["requests"].append(redirect_request("https://evil.example/"))
    text_of_everything = repr(
        [item.model_dump(mode="json") for item in all_observations(ScanDocument(payload))]
    )
    for forbidden in ("set-cookie", "SHOULD-NOT-BE-KEPT", "headers", "session="):
        assert forbidden not in text_of_everything


def test_no_evidence_attribute_is_credential_shaped() -> None:
    for item in all_observations(document()):
        for key in item.attributes:
            assert "cookie" not in key
            assert "header" not in key
            assert "token" not in key


# --------------------------------------------------------------------------- #
# Contacted infrastructure
# --------------------------------------------------------------------------- #


def test_contacted_hosts_addresses_and_networks_become_objects() -> None:
    result = normalize_contacted_infrastructure(context(), document())
    kinds = {item.object_type for item in result.objects}
    assert IntelObjectType.DOMAIN_NAME in kinds
    assert IntelObjectType.IPV4_ADDR in kinds
    assert IntelObjectType.AUTONOMOUS_SYSTEM in kinds


def test_contact_is_context_rather_than_accusation() -> None:
    """A page contacting a CDN says nothing about either party."""
    evidence = normalize_contacted_infrastructure(context(), document()).evidence[0]
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.attributes["domains"] == [
        "login.evil.example",
        "cdn.evil.example",
        "fonts.example.com",
    ]
    assert evidence.attributes["ips"] == ["198.51.100.7", "203.0.113.9"]
    assert evidence.attributes["asns"] == ["AS64500", "AS64501"]
    assert evidence.attributes["countries"] == ["US", "DE"]


def test_relationship_types_match_what_was_observed() -> None:
    """A page contacts an address; it does not resolve to one.

    `lists.ips` holds the addresses the browser's own requests reached, so both
    the domains and the addresses are *contact*. Writing the addresses as
    `resolves-to` described the wrong thing and, worse, put a live connection in
    the same bucket as passive DNS — a name that once pointed somewhere is a much
    weaker link than an address this page actually talked to.
    """
    result = normalize_contacted_infrastructure(context(), document())
    types = {link.relationship_type for link in result.relationships}
    assert types == {RelationshipType.CONTACTS, RelationshipType.BELONGS_TO_ASN}
    assert RelationshipType.RESOLVES_TO not in types


def test_every_relationship_keeps_the_field_it_came_from() -> None:
    """The canonical mapping is a judgement, so the original stays visible."""
    result = normalize_contacted_infrastructure(context(), document())
    raw = {link.raw_relationship_type for link in result.relationships}
    assert raw == {"lists.domains", "lists.ips", "lists.asns"}


def test_an_asn_is_derived_infrastructure_not_an_observable() -> None:
    result = normalize_contacted_infrastructure(context(), document())
    asns = [
        item for item in result.objects if item.object_type is IntelObjectType.AUTONOMOUS_SYSTEM
    ]
    assert asns
    for asn in asns:
        assert asn.object_class is ObjectClass.INFRASTRUCTURE


def test_provider_values_are_validated_by_the_same_normalizer_as_user_input() -> None:
    payload = result_payload()
    payload["lists"]["domains"] = ["ok.example", "not a domain", "", "http://x/"]
    payload["lists"]["ips"] = ["198.51.100.7", "999.1.1.1", None]
    payload["lists"]["asns"] = ["AS64500", "ASX", "64500"]
    evidence = normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence[0]
    assert evidence.attributes["domains"] == ["ok.example"]
    assert evidence.attributes["ips"] == ["198.51.100.7"]
    assert evidence.attributes["asns"] == ["AS64500"]


def test_contacted_lists_are_capped_and_the_cut_is_recorded() -> None:
    payload = result_payload()
    payload["lists"]["domains"] = [f"host{index}.example" for index in range(200)]
    evidence = normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence[0]
    assert len(evidence.attributes["domains"]) == MAX_CONTACTED_DOMAINS
    assert evidence.attributes["truncated"] is True


def test_an_untruncated_scan_says_so() -> None:
    evidence = normalize_contacted_infrastructure(context(), document()).evidence[0]
    assert evidence.attributes["truncated"] is False


def test_duplicate_entries_are_collapsed() -> None:
    payload = result_payload()
    payload["lists"]["domains"] = ["a.example", "A.example.", "a.example"]
    evidence = normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence[0]
    assert evidence.attributes["domains"] == ["a.example"]


@pytest.mark.parametrize("lists", [{}, {"domains": "nope"}, {"domains": [], "ips": []}])
def test_a_scan_with_no_usable_lists_yields_nothing(lists: Any) -> None:
    payload = result_payload()
    payload["lists"] = lists
    assert normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence == ()


def test_a_page_never_links_to_itself() -> None:
    payload = result_payload()
    payload["lists"] = {"domains": ["login.evil.example"]}
    payload["page"]["url"] = "login.evil.example"
    result = normalize_contacted_infrastructure(context(), ScanDocument(payload))
    for link in result.relationships:
        assert link.source_object_id != link.target_object_id


def test_relationships_are_omitted_when_the_page_url_is_unusable() -> None:
    payload = result_payload()
    payload["page"]["url"] = "not a url"
    result = normalize_contacted_infrastructure(context(), ScanDocument(payload))
    assert result.evidence
    assert result.relationships == ()


# --------------------------------------------------------------------------- #
# Served bodies
# --------------------------------------------------------------------------- #


def test_served_body_digests_become_file_objects_and_links() -> None:
    result = normalize_served_bodies(context(), document())
    assert result.evidence[0].attributes["sha256"] == ["a" * 64]
    files = [item for item in result.objects if item.object_type is IntelObjectType.FILE]
    assert files
    assert files[0].hashes == {"SHA-256": "a" * 64}
    assert [link.relationship_type for link in result.relationships] == [RelationshipType.DOWNLOADS]


def test_body_digests_are_capped() -> None:
    payload = result_payload()
    payload["lists"]["hashes"] = [f"{index:064x}" for index in range(100)]
    evidence = normalize_served_bodies(context(), ScanDocument(payload)).evidence[0]
    assert len(evidence.attributes["sha256"]) == MAX_SERVED_HASHES


def test_a_digest_that_is_not_a_hash_is_dropped() -> None:
    payload = result_payload()
    payload["lists"]["hashes"] = ["not-a-hash", "a" * 64]
    evidence = normalize_served_bodies(context(), ScanDocument(payload)).evidence[0]
    assert evidence.attributes["sha256"] == ["a" * 64]


def test_no_body_is_retrieved_while_normalizing() -> None:
    """Digests are pivots; fetching the bodies is forensics, and explicit."""
    result = normalize_served_bodies(context(), document())
    for item in result.evidence:
        assert "content" not in item.attributes
        assert "body" not in item.attributes


def test_a_scan_with_no_hashes_yields_nothing() -> None:
    payload = result_payload()
    payload["lists"]["hashes"] = []
    assert normalize_served_bodies(context(), ScanDocument(payload)).evidence == ()


def test_served_bodies_without_a_usable_page_still_record_the_digests() -> None:
    payload = result_payload()
    payload["page"]["url"] = "not a url"
    result = normalize_served_bodies(context(), ScanDocument(payload))
    assert result.evidence
    assert result.relationships == ()


# --------------------------------------------------------------------------- #
# Traffic summary
# --------------------------------------------------------------------------- #


def test_traffic_counters_are_context() -> None:
    """A busy page is not a malicious one."""
    evidence = normalize_traffic_summary(context(), document()).evidence[0]
    assert evidence.evidence_class is EvidenceClass.CONTEXT
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.attributes["uniq_ips"] == 2
    assert evidence.attributes["uniq_countries"] == 2
    assert evidence.attributes["requests"] == 14


def test_unreadable_counters_are_skipped() -> None:
    payload = result_payload()
    payload["stats"] = {"requests": "many", "uniqIPs": None}
    assert normalize_traffic_summary(context(), ScanDocument(payload)).evidence == ()


def test_no_stats_block_yields_nothing() -> None:
    payload = result_payload()
    del payload["stats"]
    assert normalize_traffic_summary(context(), ScanDocument(payload)).evidence == ()


def test_observed_times_come_from_the_scan() -> None:
    for item in all_observations(document()):
        assert item.observed_at == SCANNED_AT
        assert item.retrieved_at == NOW


def test_two_spellings_of_one_url_are_one_hop() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        redirect_request("https://evil.example"),
        redirect_request("https://evil.example/"),
    ]
    chain = normalize_redirect_chain(context(), ScanDocument(payload)).evidence[0]
    assert chain.attributes["chain"] == [
        "https://evil.example/",
        "https://login.evil.example/office/index.html",
    ]


def test_the_landing_url_is_not_repeated_when_it_is_already_a_hop() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        redirect_request("https://evil.example/"),
        redirect_request("https://login.evil.example/office/index.html"),
    ]
    chain = normalize_redirect_chain(context(), ScanDocument(payload)).evidence[0]
    assert chain.attributes["chain"].count("https://login.evil.example/office/index.html") == 1


def test_a_request_entry_without_an_inner_request_is_skipped() -> None:
    payload = result_payload()
    payload["data"]["requests"] = [
        {"request": {"redirectResponse": {"status": 302}}},
        redirect_request("https://evil.example/"),
    ]
    chain = normalize_redirect_chain(context(), ScanDocument(payload)).evidence[0]
    assert chain.attributes["chain"][0] == "https://evil.example/"


def test_addresses_alone_are_enough_to_record_infrastructure() -> None:
    payload = result_payload()
    payload["lists"] = {"ips": ["198.51.100.7"]}
    evidence = normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence[0]
    assert "domains" not in evidence.attributes
    assert evidence.attributes["ips"] == ["198.51.100.7"]


def test_country_lists_are_deduplicated_and_capped() -> None:
    payload = result_payload()
    payload["lists"]["countries"] = ["US", "US", None, *[f"C{index}" for index in range(50)]]
    evidence = normalize_contacted_infrastructure(context(), ScanDocument(payload)).evidence[0]
    assert evidence.attributes["countries"][0] == "US"
    assert len(evidence.attributes["countries"]) == 20
