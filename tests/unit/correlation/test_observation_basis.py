"""How a provider says it *watched* something happen (Task 14 correction).

Evidence class and observation basis are orthogonal, and conflating them was a
real error. A sandbox's contacted domain is `EvidenceClass.CONTEXT` with
`CONTEXT_ONLY` effect — it accuses nobody, since a detonating sample also reaches
CRLs, CDNs and time servers — and it is *also* something the sandbox watched
happen. Reading only the class made every sandbox observation arrive as though it
were a database lookup.

The fix lives in the provider: Hybrid Analysis sets
`Relationship.directly_observed` on the links that come from execution. The
correlation engine reads that field generically, with no provider named anywhere.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import SecretStr

from fixtures.correlation import graph_for
from fixtures.hybrid_analysis import payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from ti_recon.correlation.models import RelationBasis
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
    RelationshipType,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.hybrid_analysis import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    HybridAnalysisAdapter,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope

DIGEST = payloads.SAMPLE_SHA256


def subject() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=DIGEST,
        display_value=DIGEST,
        properties={"hashes": {"SHA-256": DIGEST}},
    )


def credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id="hybrid_analysis",
        credential_group="hybrid_analysis",
        auth_type=AuthType.API_KEY,
        secret=SecretStr("ha-key-SHOULD-NOT-LEAK"),
    )


async def sandbox_result(
    *,
    search_payload: object | None = None,
    summary: object | None = None,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderResultEnvelope:
    """One real Hybrid Analysis lookup, behind its fake client."""
    client = FakeHybridAnalysisClient(
        search_payload=search_payload,
        default_summary=summary,
    )
    adapter = HybridAnalysisAdapter(client_factory=ClientFactory(client))  # type: ignore[arg-type]
    return await adapter.lookup(
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=subject(),
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            depth=depth,
        ),
        credential(),
    )


def links(envelope: ProviderResultEnvelope, relationship: RelationshipType) -> list[object]:
    return [item for item in envelope.relationships if item.relationship_type is relationship]


# --------------------------------------------------------------------------- #
# The provider says it watched
# --------------------------------------------------------------------------- #


async def test_a_sandbox_contact_relationship_is_marked_observed() -> None:
    """A sandbox watched this sample open this connection."""
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(domains=["c2.malware.example"])
    )
    contacts = links(envelope, RelationshipType.CONTACTS)
    assert contacts
    assert all(item.directly_observed for item in contacts)  # type: ignore[attr-defined]
    assert {item.raw_relationship_type for item in contacts} == {  # type: ignore[attr-defined]
        "network_observations"
    }


async def test_a_sandbox_extracted_file_relationship_is_marked_observed() -> None:
    """A file the sample wrote while running is equally something watched."""
    envelope = await sandbox_result()
    drops = links(envelope, RelationshipType.DROPS)
    assert drops, "the fixture summary should carry extracted files"
    assert all(item.directly_observed for item in drops)  # type: ignore[attr-defined]
    assert {item.raw_relationship_type for item in drops} == {"extracted_files"}  # type: ignore[attr-defined]


async def test_a_run_that_never_finished_claims_no_observation() -> None:
    """A report that errored has no behavioural content, so nothing in it was
    watched happening. Claiming otherwise would turn an infrastructure failure
    into an eyewitness account.

    The relationships are still emitted — an errored run listing a host is a fact
    about the report — so this is a statement about the flag, not about whether the
    links exist.
    """
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(state="ERROR", domains=["c2.malware.example"])
    )
    assert envelope.relationships, "the links are kept; only the claim of observation is not"
    for item in envelope.relationships:
        assert item.directly_observed is False


async def test_a_partly_completed_run_still_watched_what_it_reports() -> None:
    """`PARTIAL_SUCCESS` means the run finished with behaviour worth reading, which
    is exactly the condition Task 12 already uses."""
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(state="PARTIAL_SUCCESS", domains=["c2.malware.example"])
    )
    assert envelope.relationships
    assert all(item.directly_observed for item in envelope.relationships)


async def test_the_flag_is_the_default_conservative_one_elsewhere() -> None:
    """Every other provider says nothing, and silence is never read as
    observation."""
    from ti_recon.models.relationship import Relationship

    link = Relationship(
        source_object_id="00000000-0000-4000-8000-000000000001",
        relationship_type=RelationshipType.RESOLVES_TO,
        target_object_id="00000000-0000-4000-8000-000000000002",
        evidence_refs=("00000000-0000-4000-8000-000000000003",),
    )
    assert link.directly_observed is False


# --------------------------------------------------------------------------- #
# What the correction must not change
# --------------------------------------------------------------------------- #


async def test_behaviour_evidence_stays_context_only() -> None:
    """The whole point: a watched connection is not thereby an accusation.

    A detonating sample also reaches certificate revocation lists, CDNs, time
    servers and telemetry endpoints, and the sandbox cannot tell those from a C2.
    """
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(domains=["c2.malware.example"])
    )
    behaviour = [item for item in envelope.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE]
    assert behaviour
    for item in behaviour:
        assert item.evidence_class is EvidenceClass.CONTEXT
        assert item.effect is EvidenceEffect.CONTEXT_ONLY


async def test_the_sandbox_verdict_is_not_reinterpreted() -> None:
    """The provider's own assessment is untouched by how its links are labelled.

    Its class, effect and direction are exactly what Task 12 decided, and no
    verdict became stronger because a relationship is now marked observed.
    """
    envelope = await sandbox_result()
    assessment = [item for item in envelope.evidence if item.claim_type == ASSESSMENT_CLAIM_TYPE]
    assert assessment
    for item in assessment:
        # Task 12's own choice, unchanged: a positive verdict is the provider's
        # curated conclusion about a run it performed.
        assert item.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
        assert item.effect is EvidenceEffect.SUPPORTS_MALICIOUS
        # And the verdict is an assessment, so it never carries an observation
        # flag: the sandbox watched a connection, it did not watch a conclusion.
        assert "directly_observed" not in item.attributes


async def test_family_and_classification_metadata_stay_reported() -> None:
    """A family label is what the provider concluded, not what it watched."""
    envelope = await sandbox_result()
    graph, engine = graph_for(subject())
    engine.ingest(envelope, anchor_key=f"file:sha256:{DIGEST}")
    # The sandbox emits no family relationship at all; if it ever did, the flag
    # would have to be set deliberately rather than inherited from the run.
    assert not [
        edge
        for edge in graph.edges
        if edge.relationship_type is RelationshipType.ASSOCIATED_WITH_MALWARE
    ]


async def test_no_edge_direction_or_effect_changed() -> None:
    """Orientation, endpoints and evidence effect are all as before."""
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(domains=["c2.malware.example"])
    )
    graph, engine = graph_for(subject())
    engine.ingest(envelope, anchor_key=f"file:sha256:{DIGEST}")
    contacts = [edge for edge in graph.edges if edge.relationship_type is RelationshipType.CONTACTS]
    assert contacts
    for edge in contacts:
        assert edge.source_key == f"file:sha256:{DIGEST}"
        assert edge.target_key.startswith(("domain-name:", "ipv4-addr:", "ipv6-addr:"))


# --------------------------------------------------------------------------- #
# Correlation reads the flag, generically
# --------------------------------------------------------------------------- #


async def test_correlation_records_the_sandbox_link_as_observed() -> None:
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(domains=["c2.malware.example"])
    )
    graph, engine = graph_for(subject())
    engine.ingest(envelope, anchor_key=f"file:sha256:{DIGEST}")
    edge = next(edge for edge in graph.edges if edge.target_key == "domain-name:c2.malware.example")
    assert [item.basis for item in edge.assertions] == [RelationBasis.PROVIDER_OBSERVED]
    # And it is still one source family with no direction attached to the edge.
    assert edge.asserting_source_families == ("hybrid_analysis",)


async def test_an_unfinished_run_is_recorded_as_reported() -> None:
    envelope = await sandbox_result(
        summary=payloads.summary_malicious(state="ERROR", domains=["c2.malware.example"])
    )
    graph, engine = graph_for(subject())
    engine.ingest(envelope, anchor_key=f"file:sha256:{DIGEST}")
    bases = {item.basis for edge in graph.edges for item in edge.assertions}
    assert RelationBasis.PROVIDER_OBSERVED not in bases


def test_the_engine_reads_the_field_and_names_no_provider() -> None:
    """The correction had to be provider-owned. A branch on a provider id inside
    the engine would have to be repeated for every future sandbox."""
    source = Path("src/ti_recon/correlation/engine.py").read_text(encoding="utf-8")
    assert "directly_observed" in source
    tree = ast.parse(source)
    docstrings = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    }
    assert not literals & {"hybrid_analysis", "sandbox", "gti", "urlscan"}


# --------------------------------------------------------------------------- #
# Pivot semantics are untouched
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("relationship", "expected_class"),
    [
        (RelationshipType.CONTACTS, "direct_behavior"),
        (RelationshipType.DROPS, "direct_artifact"),
    ],
)
def test_pivot_safety_classes_did_not_move(
    relationship: RelationshipType, expected_class: str
) -> None:
    """Observation basis is provenance. It is not an input to pivot policy, and a
    relationship did not become more followable because a sandbox watched it."""
    from ti_recon.correlation.relationships import definition_for

    definition = definition_for(relationship)
    assert definition is not None
    assert definition.pivot_safety_class.value == expected_class


def test_the_basis_is_absent_from_the_pivot_ranking() -> None:
    from ti_recon.correlation.pivots import PIVOT_RANKING_FACTORS

    assert not [item for item in PIVOT_RANKING_FACTORS if "observ" in item]
    assert not [item for item in PIVOT_RANKING_FACTORS if "basis" in item]
