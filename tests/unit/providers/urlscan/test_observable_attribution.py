"""A page's verdict belongs to the page, not to what the page contacted (Task 24, US-01).

A Search API hit says only that a historical scan matched the query. For an
address the query is ``page.ip:X OR ip:X``, so a hit may be a page hosted on X
or a page that merely loaded a resource from X. Before this change every
verdict record from such a scan was emitted with the queried address as its
subject at ``cluster`` scope, and fusion read a non-exact malicious claim as
corroborative support -- so an address that a flagged phishing page merely
loaded a font from came out SUSPICIOUS, exactly like the address that hosted
it. Contacted was being read as accused.

Now a verdict from an incidental scan has the scanned page as its subject, at
exact scope for that page, the page is in the envelope, and the observable is
linked to the page through the ``contacts`` relationship the scan already
asserts. Task 17 keeps the claim visible and never lets a claim about another
object vote for the observable. Where the page *is* the observable, or its
neighbourhood, nothing changes.
"""

from __future__ import annotations

from typing import Any

import fixtures.fusion as fusion_fixtures
from fixtures.urlscan.payloads import result_payload
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.providers.urlscan import UrlscanAdapter
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimSemantic,
    ClaimTranslationContext,
    translate_envelope,
)

VERDICT_CLAIMS = frozenset(
    {"urlscan_verdict", "urlscan_engine_aggregate", "urlscan_community_votes"}
)
DOCUMENT = result_payload()
PAGE_URL = DOCUMENT["page"]["url"]
PAGE_IP = DOCUMENT["page"]["ip"]
PAGE_DOMAIN = DOCUMENT["page"]["domain"]
CONTACTED_IP = next(ip for ip in DOCUMENT["lists"]["ips"] if ip != PAGE_IP)
CONTACTED_DOMAIN = next(name for name in DOCUMENT["lists"]["domains"] if name != PAGE_DOMAIN)


def envelope_for(
    root: IntelObject, document: dict[str, Any] | None = None
) -> ProviderResultEnvelope:
    request = ProviderRequest(
        investigation_id="inv-1",
        intel_object=root,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        depth=InvestigationDepth.STANDARD,
    )
    payload = UrlscanAdapter().normalize(request, DOCUMENT if document is None else document)
    return ProviderResultEnvelope.from_payload(
        provider="urlscan",
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        adapter_version="0.1.0",
        api_version="v1",
        payload=payload,
    )


def verdict_records(envelope: ProviderResultEnvelope) -> list[Any]:
    return [item for item in envelope.evidence if item.claim_type in VERDICT_CLAIMS]


def key_of(envelope: ProviderResultEnvelope, object_id: str) -> str | None:
    return next((o.canonical_key for o in envelope.objects if o.id == object_id), None)


def claims_of(envelope: ProviderResultEnvelope) -> tuple[Any, ...]:
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    return translate_envelope(envelope, context)


def fused_verdict(root: IntelObject, envelope: ProviderResultEnvelope) -> Verdict:
    return fusion_fixtures.fuse(
        fusion_fixtures.scenario(root).with_envelope(envelope)
    ).assessment.verdict


# --------------------------------------------------------------------------- #
# A -- the page is hosted on the queried address
# --------------------------------------------------------------------------- #


def test_a_page_hosted_on_the_queried_address_keeps_its_verdict_on_the_address() -> None:
    root = normalize_observable(PAGE_IP).intel_object
    envelope = envelope_for(root)
    records = verdict_records(envelope)
    assert len(records) == 3
    for record in records:
        assert record.subject_object_id == root.id
        assert record.match_scope is MatchScope.SAME_IP
    assert any(r.effect is EvidenceEffect.SUPPORTS_MALICIOUS for r in records)
    # The neighbourhood semantics are unchanged: a flagged page on this
    # address is real, non-decisive support about the address.
    assert fused_verdict(root, envelope) is Verdict.SUSPICIOUS


# --------------------------------------------------------------------------- #
# B -- the queried address was only contacted
# --------------------------------------------------------------------------- #


def test_b_a_contacted_address_receives_no_verdict_of_its_own() -> None:
    root = normalize_observable(CONTACTED_IP).intel_object
    envelope = envelope_for(root)
    records = verdict_records(envelope)
    assert len(records) == 3, "the verdict is kept, not deleted"
    page_key = normalize_observable(PAGE_URL).intel_object.canonical_key
    for record in records:
        assert record.subject_object_id != root.id
        assert key_of(envelope, record.subject_object_id) == page_key
        assert record.match_scope is MatchScope.EXACT_OBSERVABLE
        assert record.observed_at is not None, "the scan instant travels with the verdict"
        assert record.transport_provider == "urlscan"
    # No directional record about the address at all.
    assert not [
        item
        for item in envelope.evidence
        if item.subject_object_id == root.id and item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]


def test_b_the_page_to_address_contact_relationship_is_retained() -> None:
    root = normalize_observable(CONTACTED_IP).intel_object
    envelope = envelope_for(root)
    page_key = normalize_observable(PAGE_URL).intel_object.canonical_key
    contacts = [
        (key_of(envelope, r.source_object_id), key_of(envelope, r.target_object_id))
        for r in envelope.relationships
        if r.relationship_type.value == "contacts"
    ]
    assert (page_key, root.canonical_key) in contacts
    for relationship in envelope.relationships:
        assert relationship.first_seen is not None and relationship.last_seen is not None


def test_b_the_claims_are_about_the_page_and_the_address_stays_inconclusive() -> None:
    root = normalize_observable(CONTACTED_IP).intel_object
    envelope = envelope_for(root)
    claims = claims_of(envelope)
    assert claims, "the page's verdict is still a claim -- about the page"
    page_key = normalize_observable(PAGE_URL).intel_object.canonical_key
    assert {claim.subject_key for claim in claims} == {page_key}
    assert {claim.semantic for claim in claims} == {
        ClaimSemantic.MALICIOUS_REPUTATION,
        ClaimSemantic.AGGREGATED_REPUTATION,
    }
    # Before US-01 this address came out SUSPICIOUS from the same document.
    assert fused_verdict(root, envelope) is Verdict.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# C / D -- domains
# --------------------------------------------------------------------------- #


def test_c_the_pages_own_domain_keeps_normal_verdict_handling() -> None:
    root = normalize_observable(PAGE_DOMAIN).intel_object
    envelope = envelope_for(root)
    for record in verdict_records(envelope):
        assert record.subject_object_id == root.id
        assert record.match_scope is MatchScope.SAME_HOST
    assert fused_verdict(root, envelope) is Verdict.SUSPICIOUS


def test_d_a_contacted_domain_is_not_voted_against_by_the_pages_verdict() -> None:
    root = normalize_observable(CONTACTED_DOMAIN).intel_object
    envelope = envelope_for(root)
    page_key = normalize_observable(PAGE_URL).intel_object.canonical_key
    for record in verdict_records(envelope):
        assert key_of(envelope, record.subject_object_id) == page_key
    assert {claim.subject_key for claim in claims_of(envelope)} == {page_key}
    assert fused_verdict(root, envelope) is Verdict.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# E -- an unrelated flagged resource never moves the root
# --------------------------------------------------------------------------- #


def test_e_an_unrelated_malicious_resource_leaves_the_root_where_it_was() -> None:
    """The page hosted on the root is *not* flagged; a page elsewhere that
    loaded a script from the root is. The flagged page's verdict stays on that
    page and the root's assessment rests on the unflagged scan alone."""
    clean = result_payload(
        verdicts={
            "urlscan": {"score": 0, "malicious": False, "categories": []},
            "engines": {"maliciousTotal": 0, "enginesTotal": 10, "malicious": [], "benign": []},
            "community": {"votesMalicious": 0, "votesBenign": 0},
        }
    )
    root = normalize_observable(PAGE_IP).intel_object
    hosted = envelope_for(root, clean)
    # The same address, now merely contacted by a flagged page elsewhere.
    elsewhere = result_payload(
        page={
            **DOCUMENT["page"],
            "url": "https://other.example/x",
            "domain": "other.example",
            "ip": "203.0.113.77",
        },
        lists={**DOCUMENT["lists"], "ips": [PAGE_IP, "203.0.113.77"], "domains": ["other.example"]},
    )
    contacted = envelope_for(root, elsewhere)
    assert not [item for item in hosted.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY]
    for record in verdict_records(contacted):
        assert record.subject_object_id != root.id
    scene = fusion_fixtures.scenario(root).with_envelope(hosted).with_envelope(contacted)
    assert fusion_fixtures.fuse(scene).assessment.verdict is Verdict.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# The seam itself
# --------------------------------------------------------------------------- #


def test_a_page_that_cannot_be_normalized_keeps_the_old_scoping() -> None:
    """No page object, no re-subjecting: the record stays on the observable at
    the scope that says how loosely it applies, rather than vanishing."""
    broken = result_payload(page={**DOCUMENT["page"], "url": "not a url at all"})
    root = normalize_observable(CONTACTED_IP).intel_object
    envelope = envelope_for(root, broken)
    for record in verdict_records(envelope):
        assert record.subject_object_id == root.id
        assert record.match_scope is MatchScope.CLUSTER


def test_a_url_on_the_same_host_is_still_neighbourhood_evidence() -> None:
    """Same-host and parent-domain scopes are the existing neighbourhood rule
    and are not incidental: the page shares the observable's host."""
    root = normalize_observable("https://login.evil.example/other").intel_object
    assert root.object_type is IntelObjectType.URL
    envelope = envelope_for(root)
    for record in verdict_records(envelope):
        assert record.subject_object_id == root.id
        assert record.match_scope is MatchScope.SAME_HOST
