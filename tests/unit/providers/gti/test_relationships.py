"""Bounded, descriptor-first relationship enrichment (Task 7).

The properties that matter here are all about restraint: a lookup must not turn
into an unbounded fan-out, must not request a relationship nobody verified, and
must survive an Enterprise relationship this key cannot see.
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
from ti_recon.providers.gti import GTIAdapter, url_identifier
from ti_recon.providers.gti.relationships import (
    LIMITS_BY_DEPTH,
    RELATIONSHIP_PLANS,
    RELATIONSHIP_SPECS,
    Direction,
    GTIRelationshipDepth,
    GTIRelationshipLimits,
    Retrieval,
    TargetKind,
    depth_for_investigation,
    relationship_plan,
)

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"
SHA256 = payloads.EMPTY_FILE_SHA256


def credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-a",
        user_id="analyst-a",
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(SECRET),
    )


def request_for(intel_object: IntelObject, **overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.RELATIONSHIPS}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def make_adapter(client: FakeGTIClient) -> GTIAdapter:
    return GTIAdapter(client_factory=FakeGTIClientFactory(client=client), clock=ManualClock())


def file_client(**descriptor_pages: dict[str, Any]) -> FakeGTIClient:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    for relationship, page in descriptor_pages.items():
        fake.register_descriptors("files", SHA256, relationship, page)
    return fake


# --------------------------------------------------------------------------- #
# Depth profiles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("investigation", "expected"),
    [
        (InvestigationDepth.QUICK, GTIRelationshipDepth.QUICK),
        (InvestigationDepth.STANDARD, GTIRelationshipDepth.STANDARD),
        (InvestigationDepth.DEEP, GTIRelationshipDepth.DEEP),
    ],
)
def test_investigation_depth_maps_to_a_gti_profile(
    investigation: InvestigationDepth, expected: GTIRelationshipDepth
) -> None:
    assert depth_for_investigation(investigation) is expected


def test_quick_requests_no_relationships() -> None:
    assert relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.QUICK) == ()
    assert LIMITS_BY_DEPTH[GTIRelationshipDepth.QUICK].expands is False


def test_the_three_depths_differ_meaningfully() -> None:
    quick = relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.QUICK)
    standard = relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.STANDARD)
    deep = relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.DEEP)

    assert len(quick) < len(standard) < len(deep)
    standard_limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.STANDARD]
    deep_limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP]
    assert standard_limits.max_results_per_relationship < deep_limits.max_results_per_relationship
    assert standard_limits.max_total_related_objects < deep_limits.max_total_related_objects


def test_the_file_standard_profile_prioritizes_what_a_sample_did() -> None:
    names = [
        spec.name for spec in relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.STANDARD)
    ]
    assert names == ["contacted_domains", "contacted_ips", "contacted_urls"]


def test_the_domain_and_ip_standard_profiles_prioritize_infrastructure() -> None:
    for object_type in (IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR):
        names = [
            spec.name for spec in relationship_plan(object_type, GTIRelationshipDepth.STANDARD)
        ]
        assert names == ["resolutions", "communicating_files"]


def test_the_url_standard_profile_prioritizes_served_and_communicating_files() -> None:
    names = [
        spec.name for spec in relationship_plan(IntelObjectType.URL, GTIRelationshipDepth.STANDARD)
    ]
    assert names == ["downloaded_files", "communicating_files"]


def test_ipv6_shares_the_ipv4_profile() -> None:
    assert (
        RELATIONSHIP_PLANS[IntelObjectType.IPV6_ADDR]
        is RELATIONSHIP_PLANS[IntelObjectType.IPV4_ADDR]
    )


def test_the_noisy_relationships_are_never_requested() -> None:
    """Votes, comments, screenshots and graphs are not intelligence."""
    planned = {
        spec.name
        for plans in RELATIONSHIP_PLANS.values()
        for depth in plans
        for spec in relationship_plan(IntelObjectType.FILE, depth)
    }
    for plans in RELATIONSHIP_PLANS.values():
        for names in plans.values():
            planned.update(names)
    for noisy in (
        "votes",
        "comments",
        "screenshots",
        "graphs",
        "behaviours",
        "similar_files",
        "submissions",
        "analyses",
    ):
        assert noisy not in planned


def test_every_planned_name_has_a_verified_spec() -> None:
    """A typo must not become an API call."""
    for plans in RELATIONSHIP_PLANS.values():
        for names in plans.values():
            for name in names:
                assert name in RELATIONSHIP_SPECS


def test_an_unknown_name_in_a_plan_is_skipped_rather_than_requested() -> None:
    plans = dict(RELATIONSHIP_PLANS[IntelObjectType.FILE])
    plans[GTIRelationshipDepth.STANDARD] = ("contacted_domains", "not_a_relationship")
    original = RELATIONSHIP_PLANS[IntelObjectType.FILE]
    RELATIONSHIP_PLANS[IntelObjectType.FILE] = plans
    try:
        names = [
            spec.name
            for spec in relationship_plan(IntelObjectType.FILE, GTIRelationshipDepth.STANDARD)
        ]
        assert names == ["contacted_domains"]
    finally:
        RELATIONSHIP_PLANS[IntelObjectType.FILE] = original


def test_the_type_limit_truncates_a_long_plan() -> None:
    specs = relationship_plan(
        IntelObjectType.FILE,
        GTIRelationshipDepth.DEEP,
        limits=GTIRelationshipLimits(
            max_relationship_types=2,
            max_results_per_relationship=5,
            max_total_related_objects=10,
        ),
    )
    assert len(specs) == 2


# --------------------------------------------------------------------------- #
# Descriptor-first
# --------------------------------------------------------------------------- #


def test_targets_identified_by_their_id_use_descriptors() -> None:
    for name in ("contacted_domains", "contacted_ips", "dropped_files"):
        spec = RELATIONSHIP_SPECS[name]
        assert spec.target_kind is TargetKind.IDENTITY
        assert spec.retrieval is Retrieval.DESCRIPTORS


def test_targets_needing_an_attribute_use_full_objects() -> None:
    """A URL id is opaque and a resolution id is a concatenation."""
    assert RELATIONSHIP_SPECS["contacted_urls"].retrieval is Retrieval.OBJECTS
    assert RELATIONSHIP_SPECS["resolutions"].retrieval is Retrieval.OBJECTS


async def test_a_standard_file_lookup_asks_for_descriptors() -> None:
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(normalize_observable(SHA256).intel_object), credential())

    descriptor_calls = fake.operations("descriptors")
    assert "contacted_domains" in {call.relationship for call in descriptor_calls}
    assert "contacted_domains" not in {call.relationship for call in fake.operations("objects")}


# --------------------------------------------------------------------------- #
# Bounding
# --------------------------------------------------------------------------- #


async def test_a_quick_lookup_makes_no_relationship_call() -> None:
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.QUICK),
        credential(),
    )

    assert fake.operations("descriptors") == []
    assert fake.operations("objects") == []


async def test_standard_relationship_counts_are_bounded() -> None:
    many = payloads.descriptor_page(
        *[("domain", f"host{index}.evil.example") for index in range(50)]
    )
    fake = file_client(contacted_domains=many)
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.STANDARD]
    for call in fake.operations("descriptors"):
        assert call.limit is not None
        assert call.limit <= limits.max_results_per_relationship
    assert len(outcome.relationships) <= limits.max_total_related_objects


async def test_deep_relationship_counts_are_bounded_too() -> None:
    many = payloads.descriptor_page(
        *[("domain", f"host{index}.evil.example") for index in range(200)]
    )
    fake = file_client(contacted_domains=many, embedded_domains=many)
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.DEEP),
        credential(),
    )

    limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP]
    assert len(outcome.objects) <= limits.max_total_related_objects + 1  # + the subject
    for call in fake.operations("descriptors"):
        assert call.limit is not None
        assert call.limit <= limits.max_results_per_relationship


async def test_the_total_cap_stops_the_walk_rather_than_trimming_afterwards() -> None:
    """A cap should prevent calls, not discard their results."""
    page = payloads.descriptor_page(
        *[("domain", f"host{index}.evil.example") for index in range(10)]
    )
    fake = file_client(contacted_domains=page, contacted_ips=page, embedded_domains=page)
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(
            normalize_observable(SHA256).intel_object,
            depth=InvestigationDepth.DEEP,
            max_results=5,
        ),
        credential(),
    )

    # Five objects allowed in total, five per relationship: one call suffices.
    assert len(fake.operations("descriptors")) == 1


async def test_request_max_results_narrows_the_page_size() -> None:
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, max_results=2),
        credential(),
    )

    assert fake.operations("descriptors")[0].limit == 2


async def test_request_max_results_cannot_raise_the_provider_cap() -> None:
    """A request asking for more does not get to widen a safety limit."""
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, max_results=9_999),
        credential(),
    )

    limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.STANDARD]
    assert fake.operations("descriptors")[0].limit == limits.max_results_per_relationship


async def test_pagination_is_never_followed() -> None:
    """One page per relationship, whatever the cursor says."""
    fake = file_client(
        contacted_domains={
            "data": [{"type": "domain", "id": "c2.evil.example"}],
            "meta": {"cursor": "keep-going"},
            "links": {"next": "https://www.virustotal.com/api/v3/next-page"},
        }
    )
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(normalize_observable(SHA256).intel_object), credential())

    per_relationship = [
        call for call in fake.operations("descriptors") if call.relationship == "contacted_domains"
    ]
    assert len(per_relationship) == 1


# --------------------------------------------------------------------------- #
# Normalized output
# --------------------------------------------------------------------------- #


async def test_a_contacted_domain_becomes_an_object_a_link_and_evidence() -> None:
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)
    subject = normalize_observable(SHA256).intel_object

    outcome = await adapter.lookup(request_for(subject), credential())

    domains = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.DOMAIN_NAME]
    assert [obj.canonical_value for obj in domains] == ["c2.evil.example"]

    links = [
        link
        for link in outcome.relationships
        if link.relationship_type is RelationshipType.CONTACTS
    ]
    assert len(links) == 1
    assert links[0].source_object_id == subject.id
    assert links[0].target_object_id == domains[0].id


async def test_every_relationship_references_evidence() -> None:
    """A link with nothing behind it is an assertion TI Recon cannot explain."""
    fake = file_client(
        contacted_domains=payloads.descriptor_page(
            ("domain", "c2.evil.example"), ("domain", "beacon.evil.example")
        ),
        contacted_ips=payloads.descriptor_page(("ip_address", "198.51.100.9")),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    evidence_ids = {evidence.id for evidence in outcome.evidence}
    assert outcome.relationships
    for link in outcome.relationships:
        assert link.evidence_refs
        assert set(link.evidence_refs) <= evidence_ids


async def test_relationship_evidence_is_context_not_an_accusation() -> None:
    """A contacted domain is a behavioural fact, not a verdict."""
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "cdn.example")))
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    relationship_evidence = [
        evidence
        for evidence in outcome.evidence
        if evidence.evidence_class is EvidenceClass.RELATIONSHIP
    ]
    assert relationship_evidence
    for evidence in relationship_evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
        assert evidence.claim_type.startswith("gti.relationship.")
        assert evidence.attributes["relationship"]


async def test_relationship_evidence_shares_the_gti_lineage_group() -> None:
    from ti_recon.providers.gti.normalizer import GTI_LINEAGE_GROUP

    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    for evidence in outcome.evidence:
        assert evidence.lineage_group_id == GTI_LINEAGE_GROUP


async def test_an_ipv6_target_is_typed_correctly() -> None:
    fake = file_client(contacted_ips=payloads.descriptor_page(("ip_address", "2001:db8::99")))
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    addresses = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.IPV6_ADDR]
    assert [obj.canonical_value for obj in addresses] == ["2001:db8::99"]


async def test_a_dropped_file_becomes_a_file_object_with_its_hash() -> None:
    other = "a" * 64
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files", SHA256, "dropped_files", payloads.descriptor_page(("file", other))
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.DEEP),
        credential(),
    )

    dropped = [
        obj
        for obj in outcome.objects
        if obj.object_type is IntelObjectType.FILE and obj.canonical_value == other
    ]
    assert dropped
    assert dropped[0].hashes == {"SHA-256": other}
    assert RelationshipType.DROPS in {link.relationship_type for link in outcome.relationships}


async def test_an_inbound_relationship_is_directed_by_meaning() -> None:
    """ "communicating_files" on a domain means the file contacted the domain."""
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    fake.register_descriptors(
        "domains",
        "evil.example",
        "communicating_files",
        payloads.descriptor_page(("file", SHA256)),
    )
    adapter = make_adapter(fake)
    subject = normalize_observable("evil.example").intel_object

    outcome = await adapter.lookup(request_for(subject), credential())

    links = [
        link
        for link in outcome.relationships
        if link.relationship_type is RelationshipType.CONTACTS
    ]
    assert links
    assert links[0].target_object_id == subject.id
    assert links[0].source_object_id != subject.id
    assert RELATIONSHIP_SPECS["communicating_files"].direction is Direction.INBOUND


async def test_a_resolution_yields_the_counterpart_address() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    fake.register_objects(
        "domains",
        "evil.example",
        "resolutions",
        {
            "data": [
                {
                    "type": "resolution",
                    "id": "198.51.100.7evil.example",
                    "attributes": {
                        "ip_address": "198.51.100.7",
                        "host_name": "evil.example",
                    },
                }
            ]
        },
    )
    adapter = make_adapter(fake)
    subject = normalize_observable("evil.example").intel_object

    outcome = await adapter.lookup(request_for(subject), credential())

    addresses = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.IPV4_ADDR]
    assert [obj.canonical_value for obj in addresses] == ["198.51.100.7"]
    resolves = [
        link
        for link in outcome.relationships
        if link.relationship_type is RelationshipType.RESOLVES_TO
    ]
    assert resolves[0].source_object_id == subject.id


async def test_a_resolution_from_an_ip_yields_the_hostname() -> None:
    fake = FakeGTIClient()
    fake.register_primary("ip_addresses", payloads.ip_object())
    fake.register_objects(
        "ip_addresses",
        "198.51.100.7",
        "resolutions",
        {
            "data": [
                {
                    "type": "resolution",
                    "id": "198.51.100.7evil.example",
                    "attributes": {
                        "ip_address": "198.51.100.7",
                        "host_name": "evil.example",
                    },
                }
            ]
        },
    )
    adapter = make_adapter(fake)
    subject = normalize_observable("198.51.100.7").intel_object

    outcome = await adapter.lookup(request_for(subject), credential())

    domains = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.DOMAIN_NAME]
    assert [obj.canonical_value for obj in domains] == ["evil.example"]
    resolves = [
        link
        for link in outcome.relationships
        if link.relationship_type is RelationshipType.RESOLVES_TO
    ]
    # Always domain -> ip, whichever end the investigation started from.
    assert resolves[0].target_object_id == subject.id


async def test_a_url_target_is_built_from_its_attribute_not_its_id() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    identifier = url_identifier("http://c2.evil.example/gate")
    fake.register_objects(
        "files",
        SHA256,
        "contacted_urls",
        payloads.object_page(
            payloads.url_object(object_id=identifier, url="http://c2.evil.example/gate")
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    urls = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.URL]
    assert [obj.canonical_value for obj in urls] == ["http://c2.evil.example/gate"]
    assert identifier not in {obj.canonical_value for obj in urls}


async def test_a_url_target_without_a_recoverable_url_is_counted_not_invented() -> None:
    """The id is opaque; fabricating a URL from it would poison the graph."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects(
        "files",
        SHA256,
        "contacted_urls",
        {"data": [{"type": "url", "id": "u-opaque-identifier", "attributes": {}}]},
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    assert not [obj for obj in outcome.objects if obj.object_type is IntelObjectType.URL]
    assert "GTI_RELATED_ITEM_UNRESOLVABLE" in outcome.warnings


async def test_a_malformed_descriptor_target_is_skipped_safely() -> None:
    fake = file_client(
        contacted_ips=payloads.descriptor_page(
            ("ip_address", "not-an-address"), ("ip_address", "198.51.100.9")
        )
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    addresses = [obj for obj in outcome.objects if obj.object_type is IntelObjectType.IPV4_ADDR]
    assert [obj.canonical_value for obj in addresses] == ["198.51.100.9"]


async def test_a_self_referential_relationship_is_dropped() -> None:
    """Task 3 rejects it, and it carries no information anyway."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_descriptors(
        "files", SHA256, "dropped_files", payloads.descriptor_page(("file", SHA256))
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.DEEP),
        credential(),
    )

    assert RelationshipType.DROPS not in {link.relationship_type for link in outcome.relationships}


async def test_relationships_inlined_in_the_primary_response_are_free() -> None:
    """QUICK still normalizes what GTI already sent, at zero extra cost."""
    fake = FakeGTIClient()
    fake.register_primary(
        "files",
        payloads.file_object(
            relationships={
                "contacted_domains": {"data": [{"type": "domain", "id": "inline.evil.example"}]}
            }
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.STANDARD),
        credential(),
    )

    assert "inline.evil.example" in {obj.canonical_value for obj in outcome.objects}


# --------------------------------------------------------------------------- #
# Graceful degradation
# --------------------------------------------------------------------------- #


async def test_a_plan_limited_relationship_keeps_the_primary_lookup() -> None:
    """One Enterprise relationship being unavailable is a coverage gap."""
    fake = file_client(contacted_ips=payloads.descriptor_page(("ip_address", "198.51.100.9")))
    fake.fail_relationship(
        "files",
        SHA256,
        "contacted_domains",
        provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED, "gti", operation="relationship_descriptors"
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )

    assert outcome.status.value in {"success", "partial"}
    assert outcome.evidence
    assert "GTI_RELATIONSHIP_UNAVAILABLE:contacted_domains" in outcome.warnings
    # The relationships that were permitted still came back.
    assert "198.51.100.9" in {obj.canonical_value for obj in outcome.objects}


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.PLAN_LIMITED,
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.NOT_FOUND,
        ProviderErrorCategory.INVALID_REQUEST,
    ],
)
async def test_relationship_level_refusals_degrade_rather_than_fail(
    category: ProviderErrorCategory,
) -> None:
    fake = file_client()
    fake.fail_relationship(
        "files",
        SHA256,
        "contacted_domains",
        provider_error_for(category, "gti", operation="relationship_descriptors"),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )
    assert "GTI_RELATIONSHIP_UNAVAILABLE:contacted_domains" in outcome.warnings


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.QUOTA_EXCEEDED,
        ProviderErrorCategory.AUTHENTICATION_ERROR,
        ProviderErrorCategory.TRANSIENT_ERROR,
    ],
)
async def test_account_level_failures_are_left_for_task_6(
    category: ProviderErrorCategory,
) -> None:
    """A rate limit is not a coverage gap; the executor decides what to do."""
    fake = file_client()
    fake.fail_relationship(
        "files",
        SHA256,
        "contacted_domains",
        provider_error_for(category, "gti", operation="relationship_descriptors"),
    )
    adapter = make_adapter(fake)

    with pytest.raises(ProviderError) as excinfo:
        await adapter.lookup(request_for(normalize_observable(SHA256).intel_object), credential())
    assert excinfo.value.category is category


async def test_a_relationship_returning_nothing_is_not_an_error() -> None:
    fake = file_client(contacted_domains={"data": []})
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )
    assert outcome.status.value == "success"


async def test_the_relationship_warning_names_only_the_relationship() -> None:
    fake = file_client()
    fake.fail_relationship(
        "files",
        SHA256,
        "contacted_domains",
        provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED,
            "gti",
            operation="relationship_descriptors",
            message=f"apikey={SECRET} not entitled",
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object), credential()
    )
    for warning in outcome.warnings:
        assert SECRET not in warning


# --------------------------------------------------------------------------- #
# No arbitrary relationship names
# --------------------------------------------------------------------------- #


async def test_only_planned_relationships_are_ever_requested() -> None:
    fake = file_client(contacted_domains=payloads.descriptor_page(("domain", "c2.evil.example")))
    adapter = make_adapter(fake)

    await adapter.lookup(
        request_for(normalize_observable(SHA256).intel_object, depth=InvestigationDepth.DEEP),
        credential(),
    )

    planned = set(RELATIONSHIP_PLANS[IntelObjectType.FILE][GTIRelationshipDepth.DEEP])
    for name in fake.relationships_requested():
        assert name in planned


def test_no_relationship_name_can_come_from_user_input() -> None:
    """Every name requested is a key in the verified table."""
    import inspect

    import ti_recon.providers.gti.adapter as adapter_module

    source = inspect.getsource(adapter_module)
    # The only source of relationship names is the plan.
    assert "relationship=spec.name" in source
    assert "relationship=request" not in source
