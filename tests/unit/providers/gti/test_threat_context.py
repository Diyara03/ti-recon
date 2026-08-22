"""Curated threat associations and deep file behaviour (Task 7).

Both are Enterprise-leaning, both are expensive, and both are places where an
adapter could easily invent structure it does not have. The tests here are
mostly about what is *not* done: no names conjured from opaque ids, no new
first-class object types added for one provider, and no behaviour fetched
speculatively.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    RelationshipType,
)
from ti_recon.execution import ManualClock
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.providers.gti import GTIAdapter
from ti_recon.providers.gti.normalizer import GTI_LINEAGE_GROUP
from ti_recon.providers.gti.relationships import (
    LIMITS_BY_DEPTH,
    RELATIONSHIP_SPECS,
    GTIRelationshipDepth,
    Retrieval,
    TargetKind,
)

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"
SHA256 = payloads.EMPTY_FILE_SHA256

ALL_CAPABILITIES = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.RELATIONSHIPS,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.FILE_BEHAVIOR,
    }
)


def credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-a",
        user_id="analyst-a",
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(SECRET),
    )


def request_for(
    intel_object: IntelObject,
    *,
    capabilities: frozenset[ProviderCapability] = ALL_CAPABILITIES,
    **overrides: Any,
) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": capabilities,
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def make_adapter(client: FakeGTIClient) -> GTIAdapter:
    return GTIAdapter(client_factory=FakeGTIClientFactory(client=client), clock=ManualClock())


def file_subject() -> IntelObject:
    return normalize_observable(SHA256).intel_object


def collection(
    object_id: str, *, name: str | None = None, collection_type: str | None = None
) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    if name is not None:
        attributes["name"] = name
    if collection_type is not None:
        attributes["collection_type"] = collection_type
    return {"type": "collection", "id": object_id, "attributes": attributes}


# --------------------------------------------------------------------------- #
# Where threat relationships sit in the profiles
# --------------------------------------------------------------------------- #


def test_threat_relationships_are_entitlement_sensitive() -> None:
    for name in (
        "malware_families",
        "associations",
        "related_threat_actors",
        "related_reports",
        "campaigns",
    ):
        assert RELATIONSHIP_SPECS[name].entitlement_sensitive is True
        assert RELATIONSHIP_SPECS[name].target_kind is TargetKind.THREAT_OBJECT


def test_standard_favours_descriptors_and_deep_expands() -> None:
    """Descriptors say *that* an association exists; objects name it."""
    spec = RELATIONSHIP_SPECS["malware_families"]
    assert spec.retrieval_at(GTIRelationshipDepth.STANDARD) is Retrieval.DESCRIPTORS
    assert spec.retrieval_at(GTIRelationshipDepth.DEEP) is Retrieval.OBJECTS


def test_infrastructure_relationships_are_not_depth_dependent() -> None:
    spec = RELATIONSHIP_SPECS["contacted_domains"]
    for depth in GTIRelationshipDepth:
        assert spec.retrieval_at(depth) is Retrieval.DESCRIPTORS


def test_threat_expansion_has_its_own_tighter_cap() -> None:
    """Five actor or campaign objects is context; fifty is a research project."""
    deep = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP]
    assert deep.max_threat_objects_per_relationship < deep.max_results_per_relationship


def test_threat_relationships_carry_their_own_capabilities() -> None:
    assert (
        RELATIONSHIP_SPECS["malware_families"].capability is ProviderCapability.MALWARE_INTELLIGENCE
    )
    for name in ("associations", "related_threat_actors", "related_reports", "campaigns"):
        assert RELATIONSHIP_SPECS[name].capability is ProviderCapability.THREAT_ASSOCIATIONS


# --------------------------------------------------------------------------- #
# Capability gating
# --------------------------------------------------------------------------- #


async def test_a_reputation_only_lookup_requests_no_relationships() -> None:
    """Asking about reputation must not quietly buy a pivot graph."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(file_subject(), capabilities=frozenset({ProviderCapability.REPUTATION})),
        credential(),
    )

    assert fake.relationships_requested() == []


async def test_asking_only_for_threat_associations_skips_infrastructure() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files", SHA256, "associations", payloads.descriptor_page(("collection", "c-1"))
    )
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(
            file_subject(),
            capabilities=frozenset({ProviderCapability.THREAT_ASSOCIATIONS}),
        ),
        credential(),
    )

    requested = set(fake.relationships_requested())
    assert requested == {"associations"}


async def test_asking_only_for_relationships_skips_threat_attribution() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(file_subject(), capabilities=frozenset({ProviderCapability.RELATIONSHIPS})),
        credential(),
    )

    requested = set(fake.relationships_requested())
    assert "associations" not in requested
    assert "malware_families" not in requested


# --------------------------------------------------------------------------- #
# Association normalization
# --------------------------------------------------------------------------- #


async def test_a_descriptor_association_is_recorded_without_a_name() -> None:
    """An opaque collection id must not become a threat actor called anything."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files",
        SHA256,
        "associations",
        payloads.descriptor_page(("collection", "collection--1a2b3c")),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_subject()), credential())

    claims = [e for e in outcome.evidence if e.claim_type.startswith("gti.threat_association")]
    assert len(claims) == 1
    assert claims[0].attributes["gti_collection_id"] == "collection--1a2b3c"
    assert claims[0].attributes["name_available"] is False
    assert "name" not in claims[0].attributes
    # No object invented from an identifier nobody can read.
    assert not [o for o in outcome.objects if o.object_type is IntelObjectType.MALWARE]


async def test_an_association_claim_supports_malicious() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files", SHA256, "associations", payloads.descriptor_page(("collection", "c-1"))
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_subject()), credential())
    claim = next(e for e in outcome.evidence if e.claim_type.startswith("gti.threat_association"))
    assert claim.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert claim.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION


async def test_a_deep_malware_family_becomes_a_real_malware_object() -> None:
    """Task 3 already models malware, so a named family becomes a node."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects(
        "files",
        SHA256,
        "malware_families",
        payloads.object_page(
            collection("collection--m1", name="SyntheticRAT", collection_type="malware-family")
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    malware = [o for o in outcome.objects if o.object_type is IntelObjectType.MALWARE]
    assert len(malware) == 1
    assert malware[0].canonical_value == "syntheticrat"
    assert malware[0].display_value == "SyntheticRAT"
    assert malware[0].object_class is ObjectClass.THREAT
    assert malware[0].properties["gti"]["collection_id"] == "collection--m1"

    links = [
        link
        for link in outcome.relationships
        if link.relationship_type is RelationshipType.ASSOCIATED_WITH_MALWARE
    ]
    assert len(links) == 1
    assert links[0].evidence_refs


async def test_a_named_threat_actor_stays_an_association_not_a_new_object_type() -> None:
    """No first-class actor type is invented for one provider's convenience."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects(
        "files",
        SHA256,
        "related_threat_actors",
        payloads.object_page(
            collection("collection--a1", name="APT-SYNTHETIC", collection_type="threat-actor")
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    claim = next(
        e
        for e in outcome.evidence
        if e.claim_type == "gti.threat_association.related-threat-actors"
    )
    assert claim.attributes["name"] == "APT-SYNTHETIC"
    assert claim.attributes["gti_collection_type"] == "threat-actor"
    # The name is preserved as a claim; no ThreatActor object type exists.
    assert not [o for o in outcome.objects if o.object_type is IntelObjectType.MALWARE]
    assert "threat_actor" not in {t.value for t in IntelObjectType}


async def test_a_report_association_is_preserved_as_a_claim() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects(
        "files",
        SHA256,
        "related_reports",
        payloads.object_page(
            collection("report--r1", name="Synthetic Report", collection_type="report")
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    claim = next(
        e for e in outcome.evidence if e.claim_type == "gti.threat_association.related-reports"
    )
    assert claim.attributes["gti_collection_id"] == "report--r1"
    assert claim.attributes["name"] == "Synthetic Report"


async def test_association_evidence_shares_the_gti_lineage_group() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files", SHA256, "associations", payloads.descriptor_page(("collection", "c-1"))
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_subject()), credential())
    for evidence in outcome.evidence:
        assert evidence.lineage_group_id == GTI_LINEAGE_GROUP


async def test_deep_threat_expansion_is_bounded() -> None:
    many = payloads.object_page(
        *[
            collection(f"collection--{i}", name=f"Family{i}", collection_type="malware-family")
            for i in range(50)
        ]
    )
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects("files", SHA256, "malware_families", many)
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(file_subject(), depth=InvestigationDepth.DEEP), credential())

    limit = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP].max_threat_objects_per_relationship
    calls = [c for c in fake.operations("objects") if c.relationship == "malware_families"]
    assert calls
    for call in calls:
        assert call.limit is not None
        assert call.limit <= limit


async def test_a_plan_limited_association_leaves_the_lookup_useful() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.fail_relationship(
        "files",
        SHA256,
        "associations",
        provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED, "gti", operation="relationship_descriptors"
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_subject()), credential())

    assert "GTI_RELATIONSHIP_UNAVAILABLE:associations" in outcome.warnings
    assert [e for e in outcome.evidence if e.claim_type == "gti_assessment"]


# --------------------------------------------------------------------------- #
# File behaviour
# --------------------------------------------------------------------------- #


async def test_quick_makes_no_behaviour_request() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(file_subject(), depth=InvestigationDepth.QUICK), credential())
    assert fake.operations("behaviour") == []


async def test_standard_makes_no_behaviour_request() -> None:
    """Detonation data is expensive; it is never pulled speculatively."""
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.STANDARD), credential()
    )
    assert fake.operations("behaviour") == []


async def test_deep_without_the_capability_makes_no_behaviour_request() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(
            file_subject(),
            depth=InvestigationDepth.DEEP,
            capabilities=frozenset({ProviderCapability.RELATIONSHIPS}),
        ),
        credential(),
    )
    assert fake.operations("behaviour") == []


async def test_a_non_file_never_requests_behaviour() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("domains", payloads.domain_object())
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(
            normalize_observable("evil.example").intel_object,
            depth=InvestigationDepth.DEEP,
        ),
        credential(),
    )
    assert fake.operations("behaviour") == []


async def test_a_deep_file_investigation_reads_the_behaviour_summary() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    assert len(fake.operations("behaviour")) == 1
    domains = {
        o.canonical_value for o in outcome.objects if o.object_type is IntelObjectType.DOMAIN_NAME
    }
    assert {"c2.evil.example", "beacon.evil.example"} <= domains


async def test_behaviour_is_a_direct_observation_but_not_an_accusation() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    behavior = [e for e in outcome.evidence if e.claim_type.startswith("gti.behavior.")]
    assert behavior
    observations = [e for e in behavior if e.evidence_class is EvidenceClass.DIRECT_OBSERVATION]
    assert observations
    for evidence in behavior:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_behaviour_yields_contacts_and_drops() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    kinds = {link.relationship_type for link in outcome.relationships}
    assert RelationshipType.CONTACTS in kinds
    addresses = {
        o.canonical_value for o in outcome.objects if o.object_type is IntelObjectType.IPV4_ADDR
    }
    assert "198.51.100.9" in addresses
    urls = {o.canonical_value for o in outcome.objects if o.object_type is IntelObjectType.URL}
    assert "http://c2.evil.example/gate" in urls


async def test_the_behaviour_overview_is_one_context_claim() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    summary = [e for e in outcome.evidence if e.claim_type == "gti.behavior.summary"]
    assert len(summary) == 1
    assert summary[0].evidence_class is EvidenceClass.CONTEXT
    assert summary[0].attributes["tags"] == ["persistence", "network"]
    assert summary[0].attributes["verdicts"] == ["MALWARE"]


async def test_behaviour_output_is_bounded() -> None:
    payload = {
        "data": {"dns_lookups": [{"hostname": f"host{index}.evil.example"} for index in range(100)]}
    }
    fake = FakeGTIClient(behaviour_payload=payload)
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    domains = [o for o in outcome.objects if o.object_type is IntelObjectType.DOMAIN_NAME]
    limit = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP].max_results_per_relationship
    assert len(domains) <= limit


async def test_duplicate_behaviour_targets_collapse() -> None:
    payload = {"data": {"dns_lookups": [{"hostname": "c2.evil.example"} for _ in range(5)]}}
    fake = FakeGTIClient(behaviour_payload=payload)
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    domains = [o for o in outcome.objects if o.object_type is IntelObjectType.DOMAIN_NAME]
    assert len(domains) == 1


async def test_individual_sandbox_reports_are_never_fetched() -> None:
    """Only the aggregated summary; there can be many reports per sample."""
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(file_subject(), depth=InvestigationDepth.DEEP), credential())

    assert "behaviours" not in fake.relationships_requested()
    assert len(fake.operations("behaviour")) == 1


async def test_a_plan_limited_behaviour_summary_degrades() -> None:
    fake = FakeGTIClient(
        behaviour_error=provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED, "gti", operation="file_behavior_summary"
        )
    )
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    assert "GTI_FILE_BEHAVIOR_UNAVAILABLE" in outcome.warnings
    assert [e for e in outcome.evidence if e.claim_type == "gti_assessment"]


async def test_an_account_level_behaviour_failure_is_left_for_task_6() -> None:
    fake = FakeGTIClient(
        behaviour_error=provider_error_for(
            ProviderErrorCategory.RATE_LIMITED, "gti", operation="file_behavior_summary"
        )
    )
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    with pytest.raises(ProviderError) as excinfo:
        await adapter.lookup(
            request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
        )
    assert excinfo.value.category is ProviderErrorCategory.RATE_LIMITED


async def test_an_empty_behaviour_summary_is_not_an_error() -> None:
    fake = FakeGTIClient(behaviour_payload={"data": {}})
    fake.register_primary("files", payloads.file_object())
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )
    assert outcome.status.value in {"success", "partial"}
    assert not [e for e in outcome.evidence if e.claim_type.startswith("gti.behavior.")]


async def test_no_verdict_comes_out_of_behaviour_alone() -> None:
    fake = FakeGTIClient(behaviour_payload=payloads.behaviour_summary_payload())
    fake.register_primary("files", payloads.file_object(with_assessment=False))
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    behavior = [e for e in outcome.evidence if e.claim_type.startswith("gti.behavior.")]
    assert behavior
    assert not [e for e in behavior if e.effect is EvidenceEffect.SUPPORTS_MALICIOUS]
    assert "verdict" not in outcome.model_dump()
