"""What counts as the same object (Task 14).

The whole value of a correlation graph rests on this file. If identity is too
loose every statement about "this object" is quietly untrue; if it is too strict
the graph fragments and two providers describing one sample never meet.
"""

from __future__ import annotations

from fixtures.correlation import DIGEST_A, DIGEST_B, envelope, file_object, graph_for, observable
from ti_recon.correlation.identity import FileIdentityResolver
from ti_recon.correlation.models import CorrelationIssueType, IdentityBasis
from ti_recon.enums import IntelObjectType, ObjectClass, RelationshipType
from ti_recon.models.intel_object import IntelObject

MD5_X = "d" * 32
SHA1_C = "c" * 40


# --------------------------------------------------------------------------- #
# Simple observables
# --------------------------------------------------------------------------- #


def test_the_same_address_is_one_node() -> None:
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("8.8.8.8"),)))
    engine.ingest(envelope("two", objects=(observable("8.8.8.8"),)))
    assert [node.node_key for node in graph.nodes] == ["ipv4-addr:8.8.8.8"]


def test_a_neighbouring_address_is_a_different_node() -> None:
    """Same /24, same owner, same everything except the address. Not the same."""
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("8.8.8.8"), observable("8.8.8.9"))))
    assert len(graph.nodes) == 2


def test_an_ipv6_address_merges_on_its_canonical_form() -> None:
    """Identity follows the existing normalizer rather than a second opinion."""
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("2001:DB8::0001"),)))
    engine.ingest(envelope("two", objects=(observable("2001:db8::1"),)))
    assert len(graph.nodes) == 1


def test_an_ipv4_mapped_ipv6_address_is_not_silently_an_ipv4_address() -> None:
    """Merging them would need normalization to say they are one observable, and
    it does not — so correlation must not decide that on its own."""
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("8.8.8.8"),)))
    engine.ingest(envelope("two", objects=(observable("::ffff:8.8.8.8"),)))
    assert len(graph.nodes) == 2


def test_domain_case_and_trailing_dot_do_not_make_two_nodes() -> None:
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("Example.COM"),)))
    engine.ingest(envelope("two", objects=(observable("example.com."),)))
    assert [node.node_key for node in graph.nodes] == ["domain-name:example.com"]


def test_different_domains_stay_apart() -> None:
    graph, engine = graph_for()
    engine.ingest(
        envelope("one", objects=(observable("example.com"), observable("evil.example.com")))
    )
    assert len(graph.nodes) == 2


def test_two_urls_on_one_host_are_two_nodes() -> None:
    """The correct correlation is a shared host, not a shared identity.

    Collapsing them is how a payload on a trusted site inherits the site's
    reputation, and how two unrelated pages become one thing.
    """
    graph, engine = graph_for()
    engine.ingest(
        envelope(
            "one",
            objects=(observable("https://example.com/a"), observable("https://example.com/b")),
        )
    )
    engine.derive_structural_edges_for_graph()
    urls = [node for node in graph.nodes if node.object_type is IntelObjectType.URL]
    assert len(urls) == 2
    # ...and both hang off the one host.
    host = graph.node("domain-name:example.com")
    assert host is not None
    assert len(graph.edges_from(host.node_key)) == 2


def test_a_url_query_difference_is_a_different_url() -> None:
    graph, engine = graph_for()
    engine.ingest(
        objects_envelope := envelope(
            "one",
            objects=(
                observable("https://example.com/a?id=1"),
                observable("https://example.com/a?id=2"),
            ),
        )
    )
    del objects_envelope
    assert len([node for node in graph.nodes if node.object_type is IntelObjectType.URL]) == 2


def test_the_same_canonical_url_merges() -> None:
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(observable("HTTPS://Example.com/a"),)))
    engine.ingest(envelope("two", objects=(observable("https://example.com/a"),)))
    assert len([node for node in graph.nodes if node.object_type is IntelObjectType.URL]) == 1


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


def test_a_shared_sha256_is_the_same_sample() -> None:
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(file_object(sha256=DIGEST_A, md5=MD5_X),)))
    engine.ingest(envelope("two", objects=(file_object(sha256=DIGEST_A, sha1=SHA1_C),)))
    files = [node for node in graph.nodes if node.object_type is IntelObjectType.FILE]
    assert len(files) == 1
    assert files[0].aliases == (f"sha256:{DIGEST_A}", f"sha1:{SHA1_C}", f"md5:{MD5_X}")


def test_a_shared_sha1_merges_when_nothing_stronger_disagrees() -> None:
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(file_object(sha1=SHA1_C),)))
    engine.ingest(envelope("two", objects=(file_object(sha1=SHA1_C, sha256=DIGEST_A),)))
    assert len([node for node in graph.nodes if node.object_type is IntelObjectType.FILE]) == 1


def test_a_shared_md5_merges_when_nothing_stronger_disagrees() -> None:
    """Permitted, and recorded as a *legacy* basis rather than a plain match.

    Providers still answer by MD5 and refusing to correlate at all would fragment
    real samples; pretending it is as strong as SHA-256 would be worse.
    """
    resolver = FileIdentityResolver()
    first = resolver.resolve(file_object(md5=MD5_X))
    second = resolver.resolve(file_object(md5=MD5_X, sha256=DIGEST_A))
    assert second.merged
    assert second.basis is IdentityBasis.LEGACY_MD5
    assert first.node_key == second.node_key


def test_a_conflicting_sha256_refuses_the_merge_and_says_why() -> None:
    """The textbook collision: same MD5, different SHA-256.

    Merging would fuse two samples into one node and attribute each one's
    behaviour to the other — the kind of error nothing downstream can detect.
    """
    graph, engine = graph_for()
    engine.ingest(envelope("one", objects=(file_object(md5=MD5_X, sha256=DIGEST_A),)))
    engine.ingest(envelope("two", objects=(file_object(md5=MD5_X, sha256=DIGEST_B),)))
    files = [node for node in graph.nodes if node.object_type is IntelObjectType.FILE]
    assert len(files) == 2
    issues = [
        issue
        for issue in graph.issues
        if issue.issue_type is CorrelationIssueType.FILE_HASH_CONFLICT
    ]
    assert len(issues) == 1
    assert "SHA-256 differs" in issues[0].detail
    assert set(issues[0].node_keys) == {f"file:sha256:{DIGEST_A}", f"file:sha256:{DIGEST_B}"}


def test_a_conflicting_sha1_also_refuses_the_merge() -> None:
    resolver = FileIdentityResolver()
    resolver.resolve(file_object(md5=MD5_X, sha1=SHA1_C))
    second = resolver.resolve(file_object(md5=MD5_X, sha1="e" * 40))
    assert not second.merged
    assert second.issue is not None


def test_a_conflicting_value_never_overwrites_a_held_one() -> None:
    """A conflict stops the merge; it does not quietly replace what was there."""
    resolver = FileIdentityResolver()
    resolver.resolve(file_object(md5=MD5_X, sha256=DIGEST_A))
    resolver.resolve(file_object(md5=MD5_X, sha256=DIGEST_B))
    assert resolver.aliases_for(f"file:sha256:{DIGEST_A}") == (
        f"sha256:{DIGEST_A}",
        f"md5:{MD5_X}",
    )


def test_a_record_binding_several_digests_states_its_own_basis() -> None:
    """A provider saying "these three digests are one sample" is different from
    TI Recon having matched on one of them."""
    resolver = FileIdentityResolver()
    resolution = resolver.resolve(file_object(sha256=DIGEST_A, sha1=SHA1_C, md5=MD5_X))
    assert resolution.basis is IdentityBasis.PROVIDER_MULTI_HASH_BINDING


def test_aliases_accumulate_in_either_arrival_order() -> None:
    forward = FileIdentityResolver()
    forward.resolve(file_object(sha256=DIGEST_A, md5=MD5_X))
    forward.resolve(file_object(sha256=DIGEST_A, sha1=SHA1_C))
    backward = FileIdentityResolver()
    backward.resolve(file_object(sha256=DIGEST_A, sha1=SHA1_C))
    backward.resolve(file_object(sha256=DIGEST_A, md5=MD5_X))
    assert forward.aliases_for(f"file:sha256:{DIGEST_A}") == backward.aliases_for(
        f"file:sha256:{DIGEST_A}"
    )


# --------------------------------------------------------------------------- #
# What must never be identity
# --------------------------------------------------------------------------- #


def test_similarity_properties_never_merge_two_files() -> None:
    """ssdeep, TLSH, imphash, icon hash, family, YARA rule, tags.

    Every one of these is a real analytic signal and none of them is identity. A
    fuzzy hash says two samples resemble each other, which is exactly the thing an
    attacker controls.
    """
    graph, engine = graph_for()
    shared = {
        "ssdeep": "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",
        "tlsh": "T1A1B2C3",
        "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
        "malware_family": "agenttesla",
        "yara": "win_agent_tesla",
    }
    first = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=DIGEST_A,
        display_value=DIGEST_A,
        properties={"hashes": {"SHA-256": DIGEST_A}, **shared},
    )
    second = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=DIGEST_B,
        display_value=DIGEST_B,
        properties={"hashes": {"SHA-256": DIGEST_B}, **shared},
    )
    engine.ingest(envelope("one", objects=(first, second)))
    assert len([node for node in graph.nodes if node.object_type is IntelObjectType.FILE]) == 2


def test_shared_infrastructure_properties_never_merge_two_addresses() -> None:
    """Same ASN, same /24, same hosting provider, same certificate issuer."""
    graph, engine = graph_for()
    shared = {"asn": "AS64500", "issuer": "Let's Encrypt"}
    left = observable("203.0.113.10").model_copy(update={"properties": shared})
    right = observable("203.0.113.11").model_copy(update={"properties": shared})
    engine.ingest(envelope("one", objects=(left, right)))
    assert len(graph.nodes) == 2


def test_identity_ignores_who_reported_it_and_what_they_called_it() -> None:
    """Provider, investigation, display value and labels describe an observation."""
    graph, engine = graph_for()
    plain = observable("evil.example")
    labelled = observable("evil.example").model_copy(
        update={"display_value": "evil[.]example", "properties": {"tags": ["c2"]}}
    )
    assert labelled.canonical_key == plain.canonical_key
    engine.ingest(envelope("gti", source_family="google_ti", objects=(plain,)))
    engine.ingest(envelope("urlhaus", source_family="abuse_ch", objects=(labelled,)))
    assert len(graph.nodes) == 1
    assert graph.nodes[0].source_families == ("abuse_ch", "google_ti")


def test_a_certificate_digest_is_a_certificate_not_a_file() -> None:
    """Both are 64 hex characters and they identify different things."""
    graph, engine = graph_for()
    certificate = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.X509_CERTIFICATE,
        canonical_value=DIGEST_A,
        display_value=DIGEST_A,
    )
    engine.ingest(envelope("one", objects=(certificate, file_object(sha256=DIGEST_A))))
    assert len(graph.nodes) == 2
    assert {node.node_key for node in graph.nodes} == {
        f"x509-certificate:{DIGEST_A}",
        f"file:sha256:{DIGEST_A}",
    }


def test_a_merged_relationship_does_not_become_a_self_loop() -> None:
    """When two records turn out to be one object, the link between them has
    nothing left to say — and a self-loop would look like a provider claim."""
    graph, engine = graph_for()
    left = file_object(sha256=DIGEST_A)
    right = file_object(sha256=DIGEST_A, md5=MD5_X)
    engine.ingest(
        envelope(
            "one",
            objects=(left, right),
            links=((left, RelationshipType.DROPS, right, "dropped_files"),),
        )
    )
    assert graph.edge_count == 0
    assert not graph.issues
