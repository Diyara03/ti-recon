"""The observable inherits a page's hosting facts only when it is that page (Task 24, US-03).

``enrich_primary_object`` copied ``page.ip``, the ASN, country, server and TLS
facts of whatever page a scan landed on into the submitted object's
properties, without asking whether the page had anything to do with the
observable. An address that a phishing page merely loaded a font from ended up
carrying that page's address and network as its own. The canonical identity
rule now gates the copy: the final page URL, the page's own domain or the
page's own address must equal the observable. Relationships are not affected
by the refusal.
"""

from __future__ import annotations

from typing import Any

from fixtures.urlscan.payloads import result_payload
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.urlscan import UrlscanAdapter
from ti_recon.providers.urlscan.identity import page_is_observable
from ti_recon.providers.urlscan.normalizer import (
    URLSCAN_PROPERTY_NAMESPACE,
    ScanDocument,
    enrich_primary_object,
)

DOCUMENT = result_payload()
PAGE = DOCUMENT["page"]
CONTACTED_IP = next(ip for ip in DOCUMENT["lists"]["ips"] if ip != PAGE["ip"])
CONTACTED_DOMAIN = next(n for n in DOCUMENT["lists"]["domains"] if n != PAGE["domain"])


def document(**overrides: Any) -> ScanDocument:
    return ScanDocument(result_payload(**overrides))


def namespace_of(value: str, doc: ScanDocument | None = None) -> dict[str, Any] | None:
    root = normalize_observable(value).intel_object
    enriched = enrich_primary_object(root, document() if doc is None else doc)
    return enriched.properties.get(URLSCAN_PROPERTY_NAMESPACE)


def test_a_an_incidental_address_inherits_nothing() -> None:
    assert namespace_of(CONTACTED_IP) is None


def test_b_the_hosting_address_keeps_the_pages_facts() -> None:
    namespace = namespace_of(PAGE["ip"])
    assert namespace is not None
    assert namespace["ip"] == PAGE["ip"]
    assert namespace["asn"] == PAGE["asn"]
    assert namespace["server"] == PAGE["server"]
    assert namespace["last_scanned_at"] == "2026-08-20T10:00:00+00:00"


def test_c_a_contacted_domain_inherits_nothing_and_the_pages_own_domain_does() -> None:
    assert namespace_of(CONTACTED_DOMAIN) is None
    assert namespace_of(PAGE["domain"]) is not None


def test_c_a_parent_domain_is_not_the_page() -> None:
    """A subdomain's hosting facts are the subdomain's."""
    assert namespace_of("evil.example") is None


def test_d_a_redirected_submission_does_not_inherit_the_final_pages_facts() -> None:
    """The scan was tasked with the submitted URL and landed elsewhere: the final
    page's address and certificate belong to the final page."""
    doc = document(task={**DOCUMENT["task"], "url": "https://start.example/go"})
    assert namespace_of("https://start.example/go", doc) is None
    assert namespace_of(PAGE["url"], doc) is not None


def test_d_the_final_page_url_itself_is_enriched() -> None:
    assert namespace_of(PAGE["url"]) is not None


def test_a_file_never_inherits_the_pages_hosting_facts() -> None:
    digest = "a" * 64
    root = normalize_observable(digest).intel_object
    assert root.object_type is IntelObjectType.FILE
    assert (
        enrich_primary_object(root, document()).properties.get(URLSCAN_PROPERTY_NAMESPACE) is None
    )


def test_e_relationships_survive_a_refused_enrichment() -> None:
    root = normalize_observable(CONTACTED_IP).intel_object
    request = ProviderRequest(
        investigation_id="inv-1",
        intel_object=root,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        depth=InvestigationDepth.STANDARD,
    )
    payload = UrlscanAdapter().normalize(request, DOCUMENT)
    kinds = {r.relationship_type.value for r in payload.relationships}
    assert {"contacts", "redirects-to", "belongs-to-asn", "downloads"} <= kinds
    root_copy = next(o for o in payload.objects if o.canonical_key == root.canonical_key)
    assert root_copy.properties.get(URLSCAN_PROPERTY_NAMESPACE) is None


def test_the_rule_is_the_same_one_the_normalizer_reads() -> None:
    root = normalize_observable(PAGE["ip"]).intel_object
    assert page_is_observable(
        root, page_url=PAGE["url"], page_domain=PAGE["domain"], page_ip=PAGE["ip"]
    )
    assert not page_is_observable(
        root, page_url=PAGE["url"], page_domain=PAGE["domain"], page_ip=CONTACTED_IP
    )
