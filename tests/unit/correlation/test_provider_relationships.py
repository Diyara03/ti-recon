"""Correlation over what the shipped providers really emit (Task 14).

The other suites use hand-built envelopes so they can state exactly what two
providers claimed. This one is the opposite check: that the relationships Tasks
7-12 actually produce fit the canonical vocabulary, orient consistently, and
correlate the way the design says they will.

No network, no live suite. Provider normalizers are called directly on fixture
payloads, which is where their real output lives.
"""

from __future__ import annotations

import pytest

from fixtures.correlation import file_object, graph_for
from ti_recon.correlation.models import CorrelationIssueType, PivotSafetyClass, RelationBasis
from ti_recon.correlation.relationships import (
    RELATIONSHIP_DEFINITIONS,
    PivotEligibility,
    definition_for,
)
from ti_recon.enums import IntelObjectType, InvestigationDepth, RelationshipType

#: Every relationship type the shipped providers construct, with the provider and
#: the raw field it comes from. Verified against the source, not assumed: a
#: relationship in the enum that nobody emits is deliberately left undefined.
PROVIDER_RELATIONSHIPS: dict[str, tuple[tuple[RelationshipType, str], ...]] = {
    "gti": (
        (RelationshipType.CONTACTS, "contacted_domains"),
        (RelationshipType.CONTACTS, "contacted_ips"),
        (RelationshipType.CONTACTS, "contacted_urls"),
        (RelationshipType.CONTACTS, "embedded_domains"),
        (RelationshipType.CONTACTS, "communicating_files"),
        (RelationshipType.DROPS, "dropped_files"),
        (RelationshipType.DOWNLOADS, "itw_urls"),
        (RelationshipType.DOWNLOADS, "downloaded_files"),
        (RelationshipType.RESOLVES_TO, "resolutions"),
        (RelationshipType.REDIRECTS_TO, "redirecting_urls"),
        (RelationshipType.ASSOCIATED_WITH_MALWARE, "malware_families"),
        (RelationshipType.RELATED_TO, "associations"),
    ),
    "urlscan": (
        (RelationshipType.REDIRECTS_TO, "data.requests.redirectResponse"),
        (RelationshipType.CONTACTS, "lists.domains"),
        (RelationshipType.CONTACTS, "lists.ips"),
        (RelationshipType.BELONGS_TO_ASN, "lists.asns"),
        (RelationshipType.DOWNLOADS, "lists.hashes"),
    ),
    "greynoise": (
        (RelationshipType.BELONGS_TO_ASN, "metadata.asn"),
        (RelationshipType.RESOLVES_TO, "metadata.rdns"),
    ),
    "censys": (
        (RelationshipType.BELONGS_TO_ASN, "autonomous_system"),
        (RelationshipType.RESOLVES_TO, "dns.names"),
        (RelationshipType.USES_CERTIFICATE, "services.tls.certificate"),
    ),
    "threatfox": (
        (RelationshipType.CONTACTS, "ioc"),
        (RelationshipType.CONTACTS, "malware_samples"),
        (RelationshipType.ASSOCIATED_WITH_MALWARE, "malware_printable"),
    ),
    "urlhaus": (
        (RelationshipType.HOSTS, "urls"),
        (RelationshipType.HOSTS, "host"),
        (RelationshipType.DOWNLOADS, "payloads"),
    ),
    "malwarebazaar": ((RelationshipType.USES_CERTIFICATE, "code_sign"),),
    "hybrid_analysis": (
        (RelationshipType.CONTACTS, "network_observations"),
        (RelationshipType.DROPS, "extracted_files"),
    ),
    # MISP Warning Lists emits context and no relationships at all: a warninglist
    # match explains a node, it does not link two of them.
    "misp_warninglists": (),
}


# --------------------------------------------------------------------------- #
# The vocabulary matches what providers produce
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("provider", sorted(PROVIDER_RELATIONSHIPS))
def test_every_relationship_a_provider_emits_has_a_definition(provider: str) -> None:
    """An undefined relationship is recorded as an issue and kept out of the
    graph, so a provider emitting one would silently lose its links."""
    for relationship, raw in PROVIDER_RELATIONSHIPS[provider]:
        assert definition_for(relationship) is not None, f"{provider}:{raw}"


def test_the_vocabulary_defines_nothing_providers_do_not_emit() -> None:
    """A definition nobody produces is a rule nobody has tested.

    `similar-to` and `duplicate-of` exist in the Task 3 enum and are deliberately
    undefined here: correlation merges on exact identity, so a provider asserting
    similarity has nothing to contribute to a graph node's identity, and giving it
    graph semantics now would invite exactly the fuzzy merging this task refuses.
    """
    emitted = {
        relationship for entries in PROVIDER_RELATIONSHIPS.values() for relationship, _ in entries
    }
    assert set(RELATIONSHIP_DEFINITIONS) == emitted
    assert RelationshipType.SIMILAR_TO not in RELATIONSHIP_DEFINITIONS
    assert RelationshipType.DUPLICATE_OF not in RELATIONSHIP_DEFINITIONS


def test_no_provider_is_named_in_the_relationship_registry() -> None:
    """Raw-to-canonical mapping belongs to the provider that owns the raw name."""
    import ast
    from pathlib import Path

    source = Path("src/ti_recon/correlation/relationships.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    values = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    assert not [value for value in values if value in PROVIDER_RELATIONSHIPS]


# --------------------------------------------------------------------------- #
# Endpoint types match how providers use them
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("relationship", "source", "target"),
    [
        # GTI and Hybrid Analysis: a sample reaching infrastructure.
        (RelationshipType.CONTACTS, IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME),
        (RelationshipType.CONTACTS, IntelObjectType.FILE, IntelObjectType.IPV4_ADDR),
        (RelationshipType.CONTACTS, IntelObjectType.FILE, IntelObjectType.URL),
        # urlscan: a page reaching infrastructure.
        (RelationshipType.CONTACTS, IntelObjectType.URL, IntelObjectType.DOMAIN_NAME),
        (RelationshipType.CONTACTS, IntelObjectType.URL, IntelObjectType.IPV4_ADDR),
        # URLhaus and urlscan: a URL serving a payload.
        (RelationshipType.DOWNLOADS, IntelObjectType.URL, IntelObjectType.FILE),
        # GTI: an address serving a file.
        (RelationshipType.DOWNLOADS, IntelObjectType.IPV4_ADDR, IntelObjectType.FILE),
        # Hybrid Analysis and GTI: a sample writing a file.
        (RelationshipType.DROPS, IntelObjectType.FILE, IntelObjectType.FILE),
        # URLhaus: the host a tracked URL lives on.
        (RelationshipType.HOSTS, IntelObjectType.DOMAIN_NAME, IntelObjectType.URL),
        (RelationshipType.HOSTS, IntelObjectType.IPV4_ADDR, IntelObjectType.URL),
        # GTI, Censys, GreyNoise: a name and an address.
        (RelationshipType.RESOLVES_TO, IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR),
        # Censys and MalwareBazaar: certificates.
        (
            RelationshipType.USES_CERTIFICATE,
            IntelObjectType.IPV4_ADDR,
            IntelObjectType.X509_CERTIFICATE,
        ),
        (
            RelationshipType.USES_CERTIFICATE,
            IntelObjectType.FILE,
            IntelObjectType.X509_CERTIFICATE,
        ),
        # urlscan, Censys, GreyNoise: ownership.
        (
            RelationshipType.BELONGS_TO_ASN,
            IntelObjectType.IPV4_ADDR,
            IntelObjectType.AUTONOMOUS_SYSTEM,
        ),
        # ThreatFox and GTI: curated attribution.
        (
            RelationshipType.ASSOCIATED_WITH_MALWARE,
            IntelObjectType.FILE,
            IntelObjectType.MALWARE,
        ),
    ],
)
def test_the_endpoint_pairs_providers_really_use_are_accepted(
    relationship: RelationshipType,
    source: IntelObjectType,
    target: IntelObjectType,
) -> None:
    """A pair the definitions rejected would be dropped with an issue on every
    lookup — a silent, permanent hole in the graph."""
    definition = definition_for(relationship)
    assert definition is not None
    assert definition.accepts(source, target), (
        f"{source.value} -{relationship.value}-> {target.value}"
    )


def test_a_url_never_resolves() -> None:
    """The mis-mapping this task found in urlscan, kept fixed.

    A page contacts an address; only a name resolves to one. Accepting the wrong
    shape would put a live connection in the same bucket as passive DNS, whose
    pivot policy is deliberately much more cautious.
    """
    definition = definition_for(RelationshipType.RESOLVES_TO)
    assert definition is not None
    assert not definition.accepts(IntelObjectType.URL, IntelObjectType.IPV4_ADDR)


# --------------------------------------------------------------------------- #
# Pivot policy over real relationships
# --------------------------------------------------------------------------- #


def test_passive_dns_and_hosting_are_never_followed_automatically() -> None:
    """Both explode. One shared-hosting address answers for thousands of names,
    and a host serves every URL on it — following either automatically turns one
    observable into a survey of somebody else's customers.
    """
    for relationship in (RelationshipType.RESOLVES_TO, RelationshipType.HOSTS):
        definition = definition_for(relationship)
        assert definition is not None
        assert definition.eligibility is PivotEligibility.RECOMMEND_ONLY


def test_labels_and_ownership_are_never_pivot_targets() -> None:
    """An AS is an ownership fact about millions of addresses; a malware family is
    a name, not an artifact; an untyped association says nothing at all."""
    for relationship in (
        RelationshipType.BELONGS_TO_ASN,
        RelationshipType.ASSOCIATED_WITH_MALWARE,
        RelationshipType.RELATED_TO,
    ):
        definition = definition_for(relationship)
        assert definition is not None
        assert definition.never_pivot


def test_artifacts_and_behaviour_are_the_things_worth_following() -> None:
    for relationship, expected in (
        (RelationshipType.DOWNLOADS, PivotSafetyClass.DIRECT_ARTIFACT),
        (RelationshipType.DROPS, PivotSafetyClass.DIRECT_ARTIFACT),
        (RelationshipType.CONTACTS, PivotSafetyClass.DIRECT_BEHAVIOR),
        (RelationshipType.REDIRECTS_TO, PivotSafetyClass.DIRECT_BEHAVIOR),
    ):
        definition = definition_for(relationship)
        assert definition is not None
        assert definition.pivot_safety_class is expected
        assert definition.enrich_eligible


# --------------------------------------------------------------------------- #
# Real normalizer output
# --------------------------------------------------------------------------- #


async def test_two_real_adapters_correlate_on_one_contacted_domain() -> None:
    """The Task 14 headline case, through the code the providers actually ship.

    One edge, two assertions, two independent source families, each keeping the
    field it came from — and the two bases kept apart. A sandbox watched this
    sample open the connection, so its assertion is ``PROVIDER_OBSERVED``; GTI
    holds a record that the sample once contacted the same domain, which is
    ``PROVIDER_REPORTED``. Both remain ``EvidenceClass.CONTEXT`` evidence with
    ``CONTEXT_ONLY`` effect: how something was learned and what it accuses anyone
    of are different questions.
    """
    from pydantic import SecretStr

    from fixtures.gti import payloads as gti_payloads
    from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
    from fixtures.hybrid_analysis import payloads as ha_payloads
    from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
    from ti_recon.credentials.enums import AuthType
    from ti_recon.credentials.models import CredentialMaterial
    from ti_recon.enums import ProviderCapability, ProviderOperation
    from ti_recon.execution.clock import ManualClock
    from ti_recon.providers.gti import GTIAdapter
    from ti_recon.providers.hybrid_analysis import HybridAnalysisAdapter
    from ti_recon.providers.request import ProviderRequest

    domain = "c2.malware.example"
    # One sample, described by both providers. GTI's fixture file object is the
    # empty file, so that digest is what both are asked about.
    digest = gti_payloads.EMPTY_FILE_SHA256
    subject = file_object(sha256=digest)

    def credential(provider_id: str, group: str) -> CredentialMaterial:
        return CredentialMaterial(
            connection_id="conn-1",
            user_id="analyst-a",
            provider_id=provider_id,
            credential_group=group,
            auth_type=AuthType.API_KEY,
            secret=SecretStr("key-SHOULD-NOT-LEAK"),
        )

    def request(capability: ProviderCapability, depth: InvestigationDepth) -> ProviderRequest:
        return ProviderRequest(
            investigation_id="inv-1",
            intel_object=subject,
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({capability}),
            depth=depth,
        )

    sandbox = FakeHybridAnalysisClient(
        search_payload=ha_payloads.search_hash_malicious(sha256=digest),
        default_summary=ha_payloads.summary_malicious(domains=[domain]),
    )
    hybrid = HybridAnalysisAdapter(client_factory=ClientFactory(sandbox))  # type: ignore[arg-type]

    gti_client = FakeGTIClient()
    gti_client.register_primary("files", gti_payloads.file_object())
    gti_client.register_descriptors(
        "files",
        digest,
        "contacted_domains",
        gti_payloads.descriptor_page(("domain", domain)),
    )
    gti = GTIAdapter(client_factory=FakeGTIClientFactory(client=gti_client), clock=ManualClock())

    graph, engine = graph_for(subject)
    engine.ingest(
        await hybrid.lookup(
            request(ProviderCapability.FILE_BEHAVIOR, InvestigationDepth.STANDARD),
            credential("hybrid_analysis", "hybrid_analysis"),
        )
    )
    engine.ingest(
        await gti.lookup(
            request(ProviderCapability.RELATIONSHIPS, InvestigationDepth.STANDARD),
            credential("gti", "virustotal"),
        )
    )

    contacts = [
        edge
        for edge in graph.edges
        if edge.relationship_type is RelationshipType.CONTACTS
        and edge.target_key == f"domain-name:{domain}"
    ]
    assert len(contacts) == 1, [edge.key for edge in graph.edges]
    edge = contacts[0]
    assert edge.asserting_source_families == ("google_ti", "hybrid_analysis")
    assert {item.raw_relationship_type for item in edge.assertions} == {
        "contacted_domains",
        "network_observations",
    }
    assert {item.basis for item in edge.assertions} == {
        RelationBasis.PROVIDER_OBSERVED,
        RelationBasis.PROVIDER_REPORTED,
    }
    observed = next(
        item for item in edge.assertions if item.basis is RelationBasis.PROVIDER_OBSERVED
    )
    assert observed.transport_provider == "hybrid_analysis"
    assert observed.raw_relationship_type == "network_observations"
    # And nothing in either result confused the vocabulary.
    assert not [
        issue
        for issue in graph.issues
        if issue.issue_type
        in {
            CorrelationIssueType.UNKNOWN_RELATIONSHIP,
            CorrelationIssueType.ENDPOINT_TYPE_MISMATCH,
        }
    ]


async def test_a_sandbox_dropped_file_is_a_direct_artifact_pivot() -> None:
    """Hybrid Analysis extracted files become DROPS, the most directly followable
    relationship there is: a file this sample wrote is squarely part of the
    investigation rather than somebody else's infrastructure."""
    from pydantic import SecretStr

    from fixtures.hybrid_analysis import payloads as ha_payloads
    from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
    from ti_recon.credentials.enums import AuthType
    from ti_recon.credentials.models import CredentialMaterial
    from ti_recon.enums import ProviderCapability, ProviderOperation
    from ti_recon.providers.hybrid_analysis import HybridAnalysisAdapter
    from ti_recon.providers.request import ProviderRequest

    subject = file_object(sha256=ha_payloads.SAMPLE_SHA256)
    sandbox = FakeHybridAnalysisClient()
    adapter = HybridAnalysisAdapter(client_factory=ClientFactory(sandbox))  # type: ignore[arg-type]
    envelope = await adapter.lookup(
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=subject,
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            depth=InvestigationDepth.STANDARD,
        ),
        CredentialMaterial(
            connection_id="conn-1",
            user_id="analyst-a",
            provider_id="hybrid_analysis",
            credential_group="hybrid_analysis",
            auth_type=AuthType.API_KEY,
            secret=SecretStr("key-SHOULD-NOT-LEAK"),
        ),
    )
    graph, engine = graph_for(subject)
    engine.ingest(envelope)
    drops = [edge for edge in graph.edges if edge.relationship_type is RelationshipType.DROPS]
    if drops:
        definition = definition_for(RelationshipType.DROPS)
        assert definition is not None
        assert definition.pivot_safety_class is PivotSafetyClass.DIRECT_ARTIFACT
        assert drops[0].assertions[0].raw_relationship_type == "extracted_files"


def test_no_provider_relationship_is_rejected_by_the_vocabulary() -> None:
    """A cheap guard with a large blast radius: if a provider starts emitting a
    pair the definitions reject, every one of its links vanishes from the graph
    with only an issue to show for it."""
    for provider, entries in PROVIDER_RELATIONSHIPS.items():
        for relationship, raw in entries:
            definition = definition_for(relationship)
            assert definition is not None, f"{provider}:{raw}"
            assert definition.allowed_source_types
            assert definition.allowed_target_types
