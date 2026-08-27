"""Edges, assertions, provenance and the inference boundary (Task 14).

An edge says two objects are related in a particular way. An assertion says who
claimed that and how they came to know. Keeping them apart is what lets the graph
show corroboration without inventing it, and what stops a relayed finding reading
as an independent one.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fixtures.correlation import DIGEST_A, DIGEST_B, envelope, file_object, graph_for, observable
from ti_recon.correlation.models import (
    CorrelationIssueType,
    RelationBasis,
)
from ti_recon.enums import EvidenceClass, IntelObjectType, RelationshipType

OLD = datetime(2019, 3, 4, tzinfo=UTC)
RECENT = datetime(2026, 1, 9, tzinfo=UTC)


def contacts(source, target, raw="contacted_domains"):  # type: ignore[no-untyped-def]
    return (source, RelationshipType.CONTACTS, target, raw)


# --------------------------------------------------------------------------- #
# One semantic edge, several assertions
# --------------------------------------------------------------------------- #


def test_two_providers_claiming_one_relationship_make_one_edge() -> None:
    graph, engine = graph_for()
    for provider, family in (("gti", "google_ti"), ("hybrid_analysis", "hybrid_analysis")):
        sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
        engine.ingest(
            envelope(
                provider,
                source_family=family,
                objects=(sample, domain),
                links=(contacts(sample, domain),),
            )
        )
    assert graph.edge_count == 1
    edge = graph.edges[0]
    assert len(edge.assertions) == 2
    assert edge.asserting_source_families == ("google_ti", "hybrid_analysis")


def test_two_datasets_in_one_family_are_one_family() -> None:
    """ThreatFox and URLhaus agreeing is one ecosystem agreeing with itself."""
    graph, engine = graph_for()
    for provider in ("threatfox", "urlhaus"):
        sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
        engine.ingest(
            envelope(
                provider,
                source_family="abuse_ch",
                lineage_group_id=f"abuse_ch:{provider}",
                objects=(sample, domain),
                links=(contacts(sample, domain, raw=provider),),
            )
        )
    edge = graph.edges[0]
    assert len(edge.assertions) == 2
    assert edge.asserting_source_families == ("abuse_ch",)


def test_one_provider_repeating_itself_does_not_look_like_corroboration() -> None:
    """The same relationship in evidence, in related objects and in a summary."""
    graph, engine = graph_for()
    for _ in range(3):
        sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
        engine.ingest(
            envelope(
                "gti",
                source_family="google_ti",
                lineage_group_id="google_ti:file:1",
                objects=(sample, domain),
                links=(contacts(sample, domain),),
            )
        )
    edge = graph.edges[0]
    assert len(edge.assertions) == 1
    assert graph.assertions_deduplicated == 2


def test_one_provider_may_still_assert_two_different_relationships() -> None:
    """Deduplication is by claim, not by provider: a provider legitimately says
    two different things about one pair."""
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(
        envelope(
            "gti",
            source_family="google_ti",
            objects=(sample, domain),
            links=(
                contacts(sample, domain, raw="contacted_domains"),
                contacts(sample, domain, raw="embedded_domains"),
            ),
        )
    )
    assert graph.edge_count == 1
    assert {item.raw_relationship_type for item in graph.edges[0].assertions} == {
        "contacted_domains",
        "embedded_domains",
    }


def test_the_edge_key_carries_no_provider() -> None:
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(envelope("gti", objects=(sample, domain), links=(contacts(sample, domain),)))
    assert graph.edges[0].key == (
        f"file:sha256:{DIGEST_A}",
        RelationshipType.CONTACTS,
        "domain-name:evil.example",
    )


# --------------------------------------------------------------------------- #
# Orientation
# --------------------------------------------------------------------------- #


def test_inverse_provider_semantics_land_on_one_edge() -> None:
    """urlscan says a URL served a file; GTI says a file came from a URL."""
    graph, engine = graph_for()
    url, payload = observable("https://evil.example/a.exe"), file_object(sha256=DIGEST_B)
    engine.ingest(
        envelope(
            "urlscan",
            objects=(url, payload),
            links=((url, RelationshipType.DOWNLOADS, payload, "lists.hashes"),),
        )
    )
    url2, payload2 = observable("https://evil.example/a.exe"), file_object(sha256=DIGEST_B)
    engine.ingest(
        envelope(
            "gti",
            source_family="google_ti",
            objects=(url2, payload2),
            # Written the other way round on purpose.
            links=((payload2, RelationshipType.DOWNLOADS, url2, "itw_urls"),),
        )
    )
    download_edges = [
        edge for edge in graph.edges if edge.relationship_type is RelationshipType.DOWNLOADS
    ]
    assert len(download_edges) == 1
    assert download_edges[0].source_key == "url:https://evil.example/a.exe"
    assert len(download_edges[0].assertions) == 2


def test_endpoints_that_do_not_fit_the_relationship_are_reported() -> None:
    """A domain does not drop a file. Recorded rather than stored as though it
    made sense, because a graph that accepts anything explains nothing."""
    graph, engine = graph_for()
    domain, other = observable("evil.example"), observable("also.example")
    engine.ingest(
        envelope(
            "one",
            objects=(domain, other),
            links=((domain, RelationshipType.DROPS, other, "weird"),),
        )
    )
    assert graph.edge_count == 0
    assert graph.issues[0].issue_type is CorrelationIssueType.ENDPOINT_TYPE_MISMATCH


def test_a_relationship_pointing_at_an_absent_object_is_reported() -> None:
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    result = envelope("one", objects=(sample,), links=(contacts(sample, domain),))
    engine.ingest(result)
    assert graph.edge_count == 0
    assert graph.issues[0].issue_type is CorrelationIssueType.DANGLING_RELATIONSHIP


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


def test_a_relayed_relationship_keeps_the_origin_that_produced_it() -> None:
    """URLhaus relaying VirusTotal is not URLhaus having observed anything."""
    graph, engine = graph_for()
    url, payload = observable("https://evil.example/a.exe"), file_object(sha256=DIGEST_B)
    engine.ingest(
        envelope(
            "urlhaus",
            source_family="abuse_ch",
            origin_provider="virustotal",
            objects=(url, payload),
            links=((url, RelationshipType.DOWNLOADS, payload, "payloads"),),
        )
    )
    assertion = graph.edges[0].assertions[0]
    assert assertion.transport_provider == "urlhaus"
    assert assertion.origin_provider == "virustotal"


def test_a_watched_relationship_and_a_recorded_one_are_told_apart() -> None:
    """A sandbox execution is an observation; a passive-DNS row is a record.

    Both are intelligence and they support different conclusions, so calling
    everything "observed" would let a 2019 database row read as an eyewitness.
    """
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(
        envelope(
            "hybrid_analysis",
            objects=(sample, domain),
            links=(contacts(sample, domain, raw="network_observations"),),
            evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        )
    )
    sample2, domain2 = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(
        envelope(
            "gti",
            source_family="google_ti",
            objects=(sample2, domain2),
            links=(contacts(sample2, domain2),),
            evidence_class=EvidenceClass.RELATIONSHIP,
        )
    )
    bases = {item.basis for item in graph.edges[0].assertions}
    assert bases == {RelationBasis.PROVIDER_OBSERVED, RelationBasis.PROVIDER_REPORTED}


def test_an_engine_derived_edge_names_no_source_family() -> None:
    """TI Recon parsing a URL is not a source, and must never count as one."""
    graph, _engine = graph_for(observable("https://example.com/a"))
    edge = graph.edges[0]
    assert edge.relationship_type is RelationshipType.HOSTS
    assert edge.is_engine_derived_only
    assert edge.asserting_source_families == ()
    assert edge.assertions[0].transport_provider is None


def test_a_derived_edge_and_a_provider_edge_share_one_edge() -> None:
    """URLhaus asserts the same host relationship TI Recon derives.

    One edge, two assertions, one source family — the derived one contributes
    nothing to the family count.
    """
    graph, engine = graph_for(observable("https://evil.example/a"))
    url, host = observable("https://evil.example/a"), observable("evil.example")
    engine.ingest(
        envelope(
            "urlhaus",
            source_family="abuse_ch",
            objects=(url, host),
            links=((host, RelationshipType.HOSTS, url, "host"),),
        )
    )
    hosts_edges = [edge for edge in graph.edges if edge.relationship_type is RelationshipType.HOSTS]
    assert len(hosts_edges) == 1
    assert len(hosts_edges[0].assertions) == 2
    assert hosts_edges[0].asserting_source_families == ("abuse_ch",)
    assert not hosts_edges[0].is_engine_derived_only


def test_a_url_host_is_parsed_not_searched_for() -> None:
    """A path that looks like a hostname is not the authority."""
    graph, _ = graph_for(observable("https://example.com/evil.example/a"))
    assert graph.node("domain-name:example.com") is not None
    assert graph.node("domain-name:evil.example") is None


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #


def test_two_observations_at_different_times_are_both_kept() -> None:
    """A 2019 resolution and a 2026 one are two observations.

    Flattening them into "resolved continuously from 2019 to 2026" would state
    something no source claimed.
    """
    graph, engine = graph_for()
    for provider, family, when in (("gti", "google_ti", OLD), ("censys", "censys", RECENT)):
        domain, address = observable("evil.example"), observable("203.0.113.5")
        engine.ingest(
            envelope(
                provider,
                source_family=family,
                objects=(domain, address),
                links=((domain, RelationshipType.RESOLVES_TO, address, "resolutions"),),
                first_seen=when,
                last_seen=when,
            )
        )
    edge = graph.edges[0]
    assert len(edge.assertions) == 2
    assert {item.first_seen for item in edge.assertions} == {OLD, RECENT}
    # The bounding box is available for display, and says nothing about the gap.
    assert edge.earliest_observed == OLD
    assert edge.latest_observed == RECENT


def test_a_relationship_with_no_time_stays_unknown() -> None:
    """No clock is consulted. An undated claim is undated, not "now"."""
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(envelope("one", objects=(sample, domain), links=(contacts(sample, domain),)))
    assertion = graph.edges[0].assertions[0]
    assert assertion.first_seen is None
    assert assertion.last_seen is None
    assert graph.edges[0].earliest_observed is None


# --------------------------------------------------------------------------- #
# No inference
# --------------------------------------------------------------------------- #


def test_a_to_b_and_b_to_c_never_produces_a_to_c() -> None:
    graph, engine = graph_for()
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    address = observable("203.0.113.5")
    engine.ingest(
        envelope(
            "one",
            objects=(sample, domain, address),
            links=(
                contacts(sample, domain),
                (domain, RelationshipType.RESOLVES_TO, address, "resolutions"),
            ),
        )
    )
    assert graph.edge_count == 2
    assert (
        graph.edge((f"file:sha256:{DIGEST_A}", RelationshipType.CONTACTS, "ipv4-addr:203.0.113.5"))
        is None
    )
    assert all(
        edge.key
        != (f"file:sha256:{DIGEST_A}", RelationshipType.RELATED_TO, "ipv4-addr:203.0.113.5")
        for edge in graph.edges
    )


def test_two_samples_contacting_one_address_are_not_thereby_related() -> None:
    """The most tempting inference there is, and the one that produces the most
    false links: shared infrastructure is shared by everybody."""
    graph, engine = graph_for()
    address = observable("203.0.113.5")
    for digest in (DIGEST_A, DIGEST_B):
        sample = file_object(sha256=digest)
        engine.ingest(
            envelope(
                "one",
                objects=(sample, observable("203.0.113.5")),
                links=(contacts(sample, observable("203.0.113.5"), raw="ip_traffic"),),
            )
        )
    del address
    files = [node for node in graph.nodes if node.object_type is IntelObjectType.FILE]
    assert len(files) == 2
    assert not [
        edge
        for edge in graph.edges
        if edge.source_key.startswith("file:") and edge.target_key.startswith("file:")
    ]


def test_a_domain_does_not_inherit_the_certificate_of_its_address() -> None:
    graph, engine = graph_for()
    domain, address = observable("evil.example"), observable("203.0.113.5")
    from ti_recon.enums import ObjectClass
    from ti_recon.models.intel_object import IntelObject

    certificate = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.X509_CERTIFICATE,
        canonical_value="f" * 64,
        display_value="f" * 64,
    )
    engine.ingest(
        envelope(
            "censys",
            objects=(domain, address, certificate),
            links=(
                (domain, RelationshipType.RESOLVES_TO, address, "dns.names"),
                (address, RelationshipType.USES_CERTIFICATE, certificate, "services.tls"),
            ),
        )
    )
    assert graph.edge_count == 2
    assert not [
        edge
        for edge in graph.edges
        if edge.source_key.startswith("domain-name:") and edge.target_key.startswith("x509")
    ]


# --------------------------------------------------------------------------- #
# Order independence
# --------------------------------------------------------------------------- #


def _three_results() -> list[object]:
    def build(provider: str, family: str) -> object:
        sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
        return envelope(
            provider,
            source_family=family,
            objects=(sample, domain),
            links=(contacts(sample, domain, raw=provider),),
        )

    url, payload = observable("https://evil.example/a.exe"), file_object(sha256=DIGEST_B)
    return [
        build("gti", "google_ti"),
        build("hybrid_analysis", "hybrid_analysis"),
        envelope(
            "urlhaus",
            source_family="abuse_ch",
            objects=(url, payload),
            links=((url, RelationshipType.DOWNLOADS, payload, "payloads"),),
        ),
    ]


def _shape(results: list[object]) -> tuple[object, ...]:
    graph, engine = graph_for(file_object(sha256=DIGEST_A))
    for result in results:
        engine.ingest(result)  # type: ignore[arg-type]
    engine.derive_structural_edges_for_graph()
    return (
        tuple(node.node_key for node in graph.nodes),
        tuple(
            (edge.key[0], edge.key[1].value, edge.key[2], edge.asserting_source_families)
            for edge in graph.edges
        ),
    )


def test_provider_order_does_not_change_the_graph() -> None:
    """The property that makes a correlation engine trustworthy: the answer does
    not depend on which provider happened to reply first."""
    results = _three_results()
    forward = _shape(results)
    reverse = _shape(list(reversed(results)))
    middle = _shape([results[1], results[2], results[0]])
    assert forward == reverse == middle
