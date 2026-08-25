"""The ThreatFox adapter and descriptor (Task 10).

The semantics these protect: one request per lookup, one opinion per response,
a loose provider search that is always re-validated locally, provider confidence
that stays the provider's, and a miss that is a six-month horizon rather than an
acquittal.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.abusech import payloads
from fixtures.abusech.fake_clients import ClientFactory, FakeThreatFoxClient
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.abusech import ABUSE_CH_SOURCE_FAMILY, lineage_group_for
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    provider_error_for,
)
from ti_recon.providers.threatfox import (
    ALLOWED_QUERIES,
    IOC_EXPIRY_HORIZON_MONTHS,
    ThreatFoxAdapter,
    ThreatFoxLookupPolicy,
    build_threatfox_descriptor,
)

FAKE_KEY = "abusech-key-SHOULD-NOT-LEAK-1234567890"
SEARCH_IOC = FakeThreatFoxClient.SEARCH_IOC
SEARCH_HASH = FakeThreatFoxClient.SEARCH_HASH


def credential(user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="threatfox",
        credential_group="abuse_ch",
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def build(
    client: FakeThreatFoxClient | None = None,
    *,
    policy: ThreatFoxLookupPolicy | None = None,
) -> tuple[ThreatFoxAdapter, FakeThreatFoxClient]:
    fake = client if client is not None else FakeThreatFoxClient()
    adapter = ThreatFoxAdapter(
        client_factory=ClientFactory(fake),  # type: ignore[arg-type]
        lookup_policy=policy,
        clock=ManualClock(),
    )
    return adapter, fake


def request_for(raw: str | IntelObject, **overrides: Any) -> ProviderRequest:
    subject = raw if isinstance(raw, IntelObject) else normalize_observable(raw).intel_object
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": subject,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def file_object(hashes: dict[str, str]) -> IntelObject:
    strongest = hashes.get("SHA-256") or hashes.get("SHA-1") or next(iter(hashes.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": hashes},
    )


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


def evidence_of(envelope: Any, claim_type: str) -> Any:
    return next(item for item in envelope.evidence if item.claim_type == claim_type)


# --------------------------------------------------------------------------- #
# Descriptor
# --------------------------------------------------------------------------- #


def test_the_descriptor_identifies_threatfox() -> None:
    descriptor = build_threatfox_descriptor()
    assert descriptor.provider_id == "threatfox"
    assert descriptor.api_version == "v1"
    assert descriptor.requires_credentials is True


def test_threatfox_belongs_to_the_abusech_family_and_credential_group() -> None:
    descriptor = build_threatfox_descriptor()
    assert descriptor.source_family == ABUSE_CH_SOURCE_FAMILY
    assert descriptor.credential_group == "abuse_ch"


def test_the_supported_observable_matrix() -> None:
    types = build_threatfox_descriptor().supported_object_types
    assert IntelObjectType.IPV4_ADDR in types
    assert IntelObjectType.DOMAIN_NAME in types
    assert IntelObjectType.URL in types
    assert IntelObjectType.FILE in types
    # ThreatFox stores addresses as ip:port and the API does not establish how
    # an IPv6 literal is represented there.
    assert IntelObjectType.IPV6_ADDR not in types


def test_nothing_active_or_batch_is_declared() -> None:
    """ThreatFox accepts IOC submissions; this integration cannot make one."""
    descriptor = build_threatfox_descriptor()
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


def test_only_read_queries_are_permitted() -> None:
    """The allow-list is what makes passivity structural for a form-POST API."""
    assert ALLOWED_QUERIES == {"search_ioc", "search_hash"}
    for forbidden in ("submit_ioc", "get_iocs", "taginfo", "malwareinfo"):
        assert forbidden not in ALLOWED_QUERIES


def test_the_provider_is_discoverable_by_capability_not_by_name() -> None:
    registry = ProviderRegistry([ThreatFoxAdapter()])
    matches = registry.find_compatible(
        IntelObjectType.DOMAIN_NAME, ProviderCapability.THREAT_ASSOCIATIONS
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["threatfox"]


# --------------------------------------------------------------------------- #
# One request per lookup
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_makes_more_than_one_request(depth: InvestigationDepth) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.SCANNER_IP, depth=depth), credential())
    assert len(client.calls) == 1


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_ever_submits_or_hunts(depth: InvestigationDepth) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN, depth=depth), credential())
    assert {name for name, _ in client.calls} <= {SEARCH_IOC, SEARCH_HASH}


async def test_a_domain_is_searched_exactly() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert client.details(SEARCH_IOC) == [payloads.MALICIOUS_DOMAIN]
    assert client.exact_matches == [True]


async def test_a_url_is_searched_exactly_in_its_canonical_form() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    assert client.details(SEARCH_IOC) == [payloads.MALICIOUS_URL]
    assert client.exact_matches == [True]


async def test_an_address_is_searched_loosely_because_of_ip_port_storage() -> None:
    """An exact search for a bare address would match nothing."""
    adapter, client = build()
    await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert client.details(SEARCH_IOC) == [payloads.SCANNER_IP]
    assert client.exact_matches == [False]


# --------------------------------------------------------------------------- #
# Local validation of a loose search
# --------------------------------------------------------------------------- #


async def test_a_substring_record_never_becomes_evidence() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    ioc = evidence_of(envelope, "threatfox_ioc")
    assert ioc.attributes["ioc"] == f"{payloads.SCANNER_IP}:443"
    assert ioc.attributes["matched_records"] == 1
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert "SomethingElse" not in serialized


async def test_the_discarded_count_is_published_in_coverage() -> None:
    """A loose provider search stays visible instead of becoming silent coverage."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    coverage = evidence_of(envelope, "threatfox_coverage")
    assert coverage.attributes["provider_records"] == 2
    assert coverage.attributes["matched_records"] == 1
    assert coverage.attributes["discarded_non_matching"] == 1
    assert coverage.attributes["exact_match"] is False


async def test_a_response_where_nothing_matches_is_no_data() -> None:
    """ThreatFox answered; none of it was about this observable."""
    adapter, _ = build(
        FakeThreatFoxClient(
            ioc_payload={
                "query_status": "ok",
                "data": [{"ioc": "203.0.113.9:443", "ioc_type": "ip:port"}],
            }
        )
    )
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert "threatfox_no_current_record" in claims(envelope)
    assert evidence_of(envelope, "threatfox_coverage").attributes["discarded_non_matching"] == 1


# --------------------------------------------------------------------------- #
# The directional claim
# --------------------------------------------------------------------------- #


async def test_a_current_record_supports_malicious() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    ioc = evidence_of(envelope, "threatfox_ioc")
    assert ioc.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert ioc.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION


async def test_a_port_qualified_match_narrows_the_scope() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    ioc = evidence_of(envelope, "threatfox_ioc")
    assert ioc.match_scope is MatchScope.SAME_IP
    assert ioc.attributes["matched_component"] == "host"
    assert ioc.attributes["port"] == 443


async def test_the_curated_context_is_preserved() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    attributes = evidence_of(envelope, "threatfox_ioc").attributes
    assert attributes["threat_type"] == "botnet_cc"
    assert attributes["malware_printable"] == "Dridex"
    assert attributes["malware"] == "win.dridex"
    assert "Cridex" in attributes["malware_alias"]
    assert attributes["malware_malpedia"].startswith("https://malpedia")
    assert attributes["tags"] == ["dridex", "c2"]
    assert attributes["reference"].startswith("https://")


async def test_provider_confidence_is_the_providers_own_number() -> None:
    """Not an Admiralty grade, and not assessment confidence."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    ioc = evidence_of(envelope, "threatfox_ioc")
    assert ioc.provider_confidence == 75.0
    assert ioc.attributes["confidence_level"] == 75.0
    assert ioc.source_reliability is None
    assert ioc.information_credibility is None


async def test_a_discarded_records_confidence_is_never_borrowed() -> None:
    """The substring record claims 100; it must not raise the answer."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert evidence_of(envelope, "threatfox_ioc").provider_confidence == 75.0


async def test_is_compromised_is_preserved_without_being_interpreted() -> None:
    adapter, _ = build(FakeThreatFoxClient(ioc_payload=payloads.threatfox_domain_result()))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    ioc = evidence_of(envelope, "threatfox_ioc")
    assert ioc.attributes["is_compromised"] is True
    # Still a malicious IOC: a compromised host is serving malware while it is.
    assert ioc.effect is EvidenceEffect.SUPPORTS_MALICIOUS


async def test_several_current_records_become_one_claim() -> None:
    """A well-documented indicator must not outvote independent providers."""
    payload = payloads.threatfox_ioc_result()
    payload["data"].append(
        {
            "id": "43",
            "ioc": f"{payloads.SCANNER_IP}:8443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware_printable": "Dridex",
            "confidence_level": 90,
        }
    )
    adapter, _ = build(FakeThreatFoxClient(ioc_payload=payload))
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())

    directional = [
        item for item in envelope.evidence if item.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    ]
    assert len(directional) == 1
    attributes = directional[0].attributes
    assert attributes["matched_records"] == 2
    assert len(attributes["iocs"]) == 2
    # The strongest confidence ThreatFox assigned, not an invented average.
    assert directional[0].provider_confidence == 90.0


async def test_the_malware_family_becomes_an_association() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    family = next(item for item in envelope.objects if item.object_type is IntelObjectType.MALWARE)
    assert family.canonical_value == "Dridex"
    assert family.object_class is ObjectClass.THREAT
    link = next(
        item
        for item in envelope.relationships
        if item.relationship_type is RelationshipType.ASSOCIATED_WITH_MALWARE
    )
    assert link.target_object_id == family.id


async def test_related_samples_become_pivots_at_standard_depth() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    sample = next(item for item in envelope.objects if item.object_type is IntelObjectType.FILE)
    assert sample.hashes["SHA-256"] == payloads.SAMPLE_SHA256


async def test_quick_depth_keeps_no_nested_detail() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(payloads.SCANNER_IP, depth=InvestigationDepth.QUICK), credential()
    )
    assert all(item.object_type is not IntelObjectType.FILE for item in envelope.objects)


# --------------------------------------------------------------------------- #
# Hash search
# --------------------------------------------------------------------------- #


async def test_a_file_is_searched_by_its_strongest_accepted_digest_once() -> None:
    adapter, client = build()
    subject = file_object(
        {
            "SHA-256": payloads.SAMPLE_SHA256,
            "SHA-1": payloads.SAMPLE_SHA1,
            "MD5": payloads.SAMPLE_MD5,
        }
    )
    await adapter.lookup(request_for(subject), credential())
    assert client.details(SEARCH_HASH) == [payloads.SAMPLE_SHA256]
    assert len(client.calls) == 1


async def test_an_md5_only_file_is_searched_by_md5() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(file_object({"MD5": payloads.SAMPLE_MD5})), credential())
    assert client.details(SEARCH_HASH) == [payloads.SAMPLE_MD5]


async def test_a_sha1_only_file_is_not_supported_rather_than_guessed() -> None:
    """ThreatFox's hash search does not take SHA-1."""
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-1": payloads.SAMPLE_SHA1})), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA
    assert client.calls == []


async def test_no_sha1_is_ever_sent_to_threatfox() -> None:
    adapter, client = build()
    subject = file_object({"SHA-256": payloads.SAMPLE_SHA256, "SHA-1": payloads.SAMPLE_SHA1})
    await adapter.lookup(request_for(subject), credential())
    assert payloads.SAMPLE_SHA1 not in client.details(SEARCH_HASH)


async def test_a_hash_association_is_one_claim_with_bounded_pivots() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-256": payloads.SAMPLE_SHA256})), credential()
    )
    association = evidence_of(envelope, "threatfox_hash_association")
    assert association.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    directional = [
        item for item in envelope.evidence if item.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    ]
    assert len(directional) == 1
    assert association.attributes["normalized_count"] == 3
    assert association.attributes["truncated"] is False


async def test_hash_association_infrastructure_becomes_contacts_relationships() -> None:
    adapter, _ = build()
    request = request_for(file_object({"SHA-256": payloads.SAMPLE_SHA256}))
    envelope = await adapter.lookup(request, credential())
    contacts = [
        item
        for item in envelope.relationships
        if item.relationship_type is RelationshipType.CONTACTS
    ]
    assert contacts
    for link in contacts:
        assert link.source_object_id == request.intel_object.id
    kinds = {item.object_type for item in envelope.objects}
    assert IntelObjectType.IPV4_ADDR in kinds
    assert IntelObjectType.URL in kinds
    assert IntelObjectType.DOMAIN_NAME in kinds


async def test_related_records_are_bounded_and_truncation_is_recorded() -> None:
    payload = {
        "query_status": "ok",
        "data": [
            {
                "id": str(index),
                "ioc": f"203.0.113.{index % 250}:{1000 + index}",
                "ioc_type": "ip:port",
                "malware_printable": "Dridex",
            }
            for index in range(80)
        ],
    }
    adapter, _ = build(FakeThreatFoxClient(hash_payload=payload))
    envelope = await adapter.lookup(
        request_for(
            file_object({"SHA-256": payloads.SAMPLE_SHA256}),
            depth=InvestigationDepth.QUICK,
        ),
        credential(),
    )
    association = evidence_of(envelope, "threatfox_hash_association")
    assert association.attributes["normalized_count"] == 10
    assert association.attributes["truncated"] is True
    assert len(association.attributes["iocs"]) <= 10


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


async def test_no_current_record_is_no_data_and_not_benign() -> None:
    adapter, _ = build(FakeThreatFoxClient(ioc_payload=payloads.threatfox_no_result()))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    for evidence in envelope.evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_miss_records_the_six_month_api_horizon() -> None:
    """ "Not currently listed" is compatible with having been listed last year."""
    adapter, _ = build(FakeThreatFoxClient(ioc_payload=payloads.threatfox_no_result()))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    absence = evidence_of(envelope, "threatfox_no_current_record")
    assert absence.attributes["current_record"] is False
    assert absence.attributes["expiration_horizon_months"] == IOC_EXPIRY_HORIZON_MONTHS
    coverage = evidence_of(envelope, "threatfox_coverage")
    assert coverage.attributes["current_api_only"] is True


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


async def test_every_claim_carries_abusech_provenance() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    for evidence in envelope.evidence:
        assert evidence.transport_provider == "threatfox"
        assert evidence.origin_provider == "threatfox"
        assert evidence.source_family == ABUSE_CH_SOURCE_FAMILY
        assert evidence.lineage_group_id == lineage_group_for("threatfox")
        assert evidence.is_relayed is False


# --------------------------------------------------------------------------- #
# Errors, refusals and hygiene
# --------------------------------------------------------------------------- #


async def test_a_rejected_key_inside_a_200_is_raised_not_read_as_empty() -> None:
    """The failure that would otherwise become "this indicator is not known"."""
    adapter, _ = build(FakeThreatFoxClient(ioc_payload={"query_status": "no_api_key"}))
    with pytest.raises(ProviderAuthenticationError):
        await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())


async def test_an_illegal_search_term_is_an_invalid_request() -> None:
    adapter, _ = build(FakeThreatFoxClient(ioc_payload={"query_status": "illegal_search_term"}))
    with pytest.raises(ProviderInvalidRequestError):
        await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())


async def test_a_lookup_without_a_credential_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(ProviderInvalidRequestError, match="requires a credential"):
        await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), None)


async def test_an_active_action_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(request_for(payloads.MALICIOUS_DOMAIN), credential())


async def test_an_active_request_reaching_lookup_directly_is_refused() -> None:
    adapter, client = build()
    request = ProviderRequest(
        investigation_id="inv-1",
        intel_object=normalize_observable(payloads.MALICIOUS_DOMAIN).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        activity_mode=ActivityMode.ACTIVE,
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request, credential())
    assert client.calls == []


async def test_batch_lookup_is_unsupported() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.batch_lookup([request_for(payloads.MALICIOUS_DOMAIN)], credential())


async def test_a_credential_is_validated_against_a_reserved_address() -> None:
    """The check reveals nothing about any investigation."""
    adapter, client = build(FakeThreatFoxClient(ioc_payload=payloads.threatfox_no_result()))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert client.details(SEARCH_IOC) == ["192.0.2.1"]


async def test_a_rejected_key_validates_as_invalid() -> None:
    adapter, _ = build(FakeThreatFoxClient(ioc_payload={"query_status": "no_api_key"}))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_a_fair_use_block_leaves_the_shared_key_usable() -> None:
    """One Auth-Key serves all three providers; do not disable it over one."""
    adapter, _ = build(FakeThreatFoxClient(ioc_payload={"query_status": "user_blacklisted"}))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE


async def test_capability_discovery_makes_no_request() -> None:
    adapter, client = build()
    discovery = await adapter.discover_capabilities(credential())
    assert client.calls == []
    assert ProviderCapability.THREAT_ASSOCIATIONS in discovery.capabilities


async def test_health_is_unknown_without_a_credential() -> None:
    adapter, client = build()
    report = await adapter.health(None)
    assert report.health.value == "unknown"
    assert client.calls == []


async def test_health_is_unavailable_when_threatfox_is_down() -> None:
    adapter, client = build()
    client.fail(
        SEARCH_IOC, provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "threatfox")
    )
    report = await adapter.health(credential())
    assert report.health.value == "unavailable"


async def test_nothing_in_the_envelope_carries_the_key() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert FAKE_KEY not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized


async def test_the_envelope_carries_no_verdict() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert {"verdict", "risk_score", "confidence", "score"}.isdisjoint(envelope.model_dump())


async def test_the_client_is_closed_after_every_lookup() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert client.closed is True


def test_normalize_is_pure_and_needs_no_client() -> None:
    adapter, client = build()
    payload = adapter.normalize(request_for(payloads.SCANNER_IP), payloads.threatfox_ioc_result())
    assert payload.evidence
    assert client.calls == []
