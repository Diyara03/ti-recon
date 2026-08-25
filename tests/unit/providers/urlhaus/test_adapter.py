"""The URLhaus adapter, descriptor and semantics (Task 10).

Three claims that must never blur into each other: an exact URL, a host
association, and a payload's provenance. Plus the two rules most easily lost —
offline is not benign, and a relayed VirusTotal count is not a second opinion.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.abusech import payloads
from fixtures.abusech.fake_clients import ClientFactory, FakeUrlhausClient
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
from ti_recon.providers.abusech import (
    ABUSE_CH_SOURCE_FAMILY,
    BLOCKLIST_RELAY_ORIGIN,
    VIRUSTOTAL_RELAY_FAMILY,
    VIRUSTOTAL_RELAY_ORIGIN,
    lineage_group_for,
)
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    provider_error_for,
)
from ti_recon.providers.urlhaus import (
    ALLOWED_PATHS,
    UrlhausAdapter,
    UrlhausLookupPolicy,
    build_urlhaus_descriptor,
)

FAKE_KEY = "abusech-key-SHOULD-NOT-LEAK-1234567890"
URL = FakeUrlhausClient.LOOKUP_URL
HOST = FakeUrlhausClient.LOOKUP_HOST
PAYLOAD = FakeUrlhausClient.LOOKUP_PAYLOAD


def credential(user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="urlhaus",
        credential_group="abuse_ch",
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def build(
    client: FakeUrlhausClient | None = None,
    *,
    policy: UrlhausLookupPolicy | None = None,
) -> tuple[UrlhausAdapter, FakeUrlhausClient]:
    fake = client if client is not None else FakeUrlhausClient()
    adapter = UrlhausAdapter(
        client_factory=ClientFactory(fake),  # type: ignore[arg-type]
        lookup_policy=policy,
        clock=ManualClock(),
    )
    return adapter, fake


def file_object(hashes: dict[str, str]) -> IntelObject:
    strongest = hashes.get("SHA-256") or hashes.get("SHA-1") or next(iter(hashes.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": hashes},
    )


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


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


def evidence_of(envelope: Any, claim_type: str) -> Any:
    return next(item for item in envelope.evidence if item.claim_type == claim_type)


def directional(envelope: Any) -> list[Any]:
    return [item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY]


# --------------------------------------------------------------------------- #
# Descriptor and routing
# --------------------------------------------------------------------------- #


def test_urlhaus_belongs_to_the_abusech_family_and_credential_group() -> None:
    descriptor = build_urlhaus_descriptor()
    assert descriptor.provider_id == "urlhaus"
    assert descriptor.source_family == ABUSE_CH_SOURCE_FAMILY
    assert descriptor.credential_group == "abuse_ch"


def test_the_supported_observable_matrix() -> None:
    types = build_urlhaus_descriptor().supported_object_types
    assert IntelObjectType.URL in types
    assert IntelObjectType.DOMAIN_NAME in types
    assert IntelObjectType.IPV4_ADDR in types
    assert IntelObjectType.FILE in types
    assert IntelObjectType.IPV6_ADDR not in types


def test_nothing_active_is_declared() -> None:
    """URLhaus accepts submissions and serves downloads; this cannot."""
    descriptor = build_urlhaus_descriptor()
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


def test_web_behaviour_is_not_claimed() -> None:
    """URLhaus records that a URL served malware, not what a browser saw."""
    assert ProviderCapability.WEB_FORENSICS not in build_urlhaus_descriptor().capabilities
    assert ProviderCapability.WEB_BEHAVIOR not in build_urlhaus_descriptor().capabilities


def test_only_lookup_endpoints_are_permitted() -> None:
    assert ALLOWED_PATHS == {"v1/url/", "v1/host/", "v1/payload/"}
    for forbidden in ("download", "submit", "feed", "rescan"):
        assert not any(forbidden in path for path in ALLOWED_PATHS)


def test_the_provider_is_discoverable_by_capability_not_by_name() -> None:
    registry = ProviderRegistry([UrlhausAdapter()])
    matches = registry.find_compatible(IntelObjectType.URL, ProviderCapability.REPUTATION)
    assert [adapter.descriptor.provider_id for adapter in matches] == ["urlhaus"]


async def test_a_url_uses_the_url_endpoint() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    assert client.details(URL) == [payloads.MALICIOUS_URL]
    assert len(client.calls) == 1


async def test_a_domain_uses_the_host_endpoint() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert client.details(HOST) == [payloads.MALICIOUS_DOMAIN]


async def test_an_address_uses_the_host_endpoint() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.SCANNER_IP), credential())
    assert client.details(HOST) == [payloads.SCANNER_IP]


async def test_a_file_uses_the_payload_endpoint_with_its_strongest_digest() -> None:
    adapter, client = build()
    await adapter.lookup(
        request_for(file_object({"SHA-256": payloads.PAYLOAD_SHA256, "MD5": payloads.PAYLOAD_MD5})),
        credential(),
    )
    assert client.details(PAYLOAD) == [payloads.PAYLOAD_SHA256]
    assert len(client.calls) == 1


async def test_an_md5_only_file_is_looked_up_by_md5() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(file_object({"MD5": payloads.PAYLOAD_MD5})), credential())
    assert client.details(PAYLOAD) == [payloads.PAYLOAD_MD5]


async def test_a_sha1_only_file_is_not_supported() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-1": payloads.SAMPLE_SHA1})), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert client.calls == []


async def test_no_sha1_is_ever_sent_to_urlhaus() -> None:
    adapter, client = build()
    await adapter.lookup(
        request_for(
            file_object({"SHA-256": payloads.PAYLOAD_SHA256, "SHA-1": payloads.SAMPLE_SHA1})
        ),
        credential(),
    )
    assert payloads.SAMPLE_SHA1 not in client.details(PAYLOAD)


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_makes_more_than_one_request(depth: InvestigationDepth) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN, depth=depth), credential())
    assert len(client.calls) == 1


async def test_a_missed_url_is_never_retried_as_a_host_lookup() -> None:
    """Two different questions; widening one would answer the wrong thing."""
    adapter, client = build(FakeUrlhausClient(url_payload=payloads.urlhaus_no_results()))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert client.call_count(HOST) == 0
    assert client.call_count(URL) == 1


# --------------------------------------------------------------------------- #
# An exact URL
# --------------------------------------------------------------------------- #


async def test_a_tracked_url_supports_malicious_at_exact_scope() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    record = evidence_of(envelope, "urlhaus_malware_url")
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.match_scope is MatchScope.EXACT_OBSERVABLE


async def test_an_offline_url_remains_malicious_historical_evidence() -> None:
    """The fixture is offline on purpose."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    record = evidence_of(envelope, "urlhaus_malware_url")
    assert record.attributes["url_status"] == "offline"
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS


async def test_the_url_record_context_is_preserved() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    attributes = evidence_of(envelope, "urlhaus_malware_url").attributes
    assert attributes["id"] == "1234567"
    assert attributes["urlhaus_reference"].startswith("https://urlhaus.abuse.ch/")
    assert attributes["threat"] == "malware_download"
    assert attributes["host"] == payloads.MALICIOUS_DOMAIN
    assert attributes["tags"] == ["exe", "dridex"]
    assert attributes["reported_for_takedown"] is True
    assert attributes["takedown_time_seconds"] == 86_400
    assert attributes["date_added"].startswith("2026-06-01")


async def test_a_tracked_url_links_to_its_host_and_its_payload() -> None:
    adapter, _ = build()
    request = request_for(payloads.MALICIOUS_URL)
    envelope = await adapter.lookup(request, credential())

    host = next(
        item for item in envelope.objects if item.object_type is IntelObjectType.DOMAIN_NAME
    )
    hosts_link = next(
        item for item in envelope.relationships if item.relationship_type is RelationshipType.HOSTS
    )
    assert hosts_link.source_object_id == host.id
    assert hosts_link.target_object_id == request.intel_object.id

    served = next(item for item in envelope.objects if item.object_type is IntelObjectType.FILE)
    downloads = next(
        item
        for item in envelope.relationships
        if item.relationship_type is RelationshipType.DOWNLOADS
    )
    assert downloads.source_object_id == request.intel_object.id
    assert downloads.target_object_id == served.id


# --------------------------------------------------------------------------- #
# A host association
# --------------------------------------------------------------------------- #


async def test_a_host_association_is_narrower_than_an_exact_match() -> None:
    """Something on this host served malware — not the host owner's guilt."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    record = evidence_of(envelope, "urlhaus_host_malware_association")
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.match_scope is MatchScope.SAME_HOST
    assert record.match_scope is not MatchScope.EXACT_OBSERVABLE


async def test_a_host_with_many_urls_is_one_finding_not_many() -> None:
    adapter, _ = build(FakeUrlhausClient(host_payload=payloads.urlhaus_host_result(url_count=40)))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert len(directional(envelope)) == 1


async def test_associated_urls_become_bounded_pivots() -> None:
    adapter, _ = build(FakeUrlhausClient(host_payload=payloads.urlhaus_host_result(url_count=40)))
    request = request_for(payloads.MALICIOUS_DOMAIN, depth=InvestigationDepth.STANDARD)
    envelope = await adapter.lookup(request, credential())

    record = evidence_of(envelope, "urlhaus_host_malware_association")
    assert record.attributes["normalized_count"] == 25
    assert record.attributes["truncated"] is True
    assert record.attributes["provider_total"] == 40
    urls = [item for item in envelope.objects if item.object_type is IntelObjectType.URL]
    assert len(urls) == 25
    for link in envelope.relationships:
        assert link.relationship_type is RelationshipType.HOSTS
        assert link.source_object_id == request.intel_object.id


@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        (InvestigationDepth.QUICK, 10),
        (InvestigationDepth.STANDARD, 25),
        (InvestigationDepth.DEEP, 50),
    ],
)
async def test_depth_bounds_the_related_urls(depth: InvestigationDepth, expected: int) -> None:
    adapter, _ = build(FakeUrlhausClient(host_payload=payloads.urlhaus_host_result(url_count=60)))
    envelope = await adapter.lookup(
        request_for(payloads.MALICIOUS_DOMAIN, depth=depth), credential()
    )
    record = evidence_of(envelope, "urlhaus_host_malware_association")
    assert record.attributes["normalized_count"] == expected


async def test_url_statuses_are_recorded_without_becoming_a_direction() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    record = evidence_of(envelope, "urlhaus_host_malware_association")
    assert set(record.attributes["url_statuses"]) <= {"online", "offline"}


# --------------------------------------------------------------------------- #
# A payload
# --------------------------------------------------------------------------- #


async def test_payload_presence_alone_is_context_only() -> None:
    """URLhaus collects whatever a tracked URL served, malicious or not."""
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-256": payloads.PAYLOAD_SHA256})), credential()
    )
    record = evidence_of(envelope, "urlhaus_payload_record")
    assert record.effect is EvidenceEffect.CONTEXT_ONLY
    assert record.evidence_class is EvidenceClass.DIRECT_OBSERVATION
    assert directional(envelope) == []


async def test_a_payload_signature_is_preserved_without_becoming_a_verdict() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-256": payloads.PAYLOAD_SHA256})), credential()
    )
    record = evidence_of(envelope, "urlhaus_payload_record")
    assert record.attributes["signature"] == "Dridex"
    assert record.effect is EvidenceEffect.CONTEXT_ONLY


async def test_the_payload_fingerprints_are_preserved() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(file_object({"SHA-256": payloads.PAYLOAD_SHA256})), credential()
    )
    attributes = evidence_of(envelope, "urlhaus_payload_record").attributes
    assert attributes["md5_hash"] == payloads.PAYLOAD_MD5
    assert attributes["sha256_hash"] == payloads.PAYLOAD_SHA256
    assert attributes["file_type"] == "exe"
    assert attributes["file_size"] == 245_760
    assert attributes["imphash"] == "f" * 32
    assert attributes["ssdeep"].startswith("3072:")
    assert attributes["tlsh"].startswith("T1")
    assert attributes["magika"] == "PE executable"
    assert attributes["url_count"] == 2


async def test_the_serving_urls_become_downloads_relationships() -> None:
    adapter, _ = build()
    request = request_for(file_object({"SHA-256": payloads.PAYLOAD_SHA256}))
    envelope = await adapter.lookup(request, credential())
    urls = [item for item in envelope.objects if item.object_type is IntelObjectType.URL]
    assert len(urls) == 2
    for link in envelope.relationships:
        assert link.relationship_type is RelationshipType.DOWNLOADS
        assert link.target_object_id == request.intel_object.id


async def test_payload_urls_are_bounded_by_depth() -> None:
    payload = payloads.urlhaus_payload_result(
        urls=[
            {"url_id": str(index), "url": f"http://{payloads.MALICIOUS_DOMAIN}/{index}.exe"}
            for index in range(40)
        ]
    )
    adapter, _ = build(FakeUrlhausClient(payload_payload=payload))
    envelope = await adapter.lookup(
        request_for(
            file_object({"SHA-256": payloads.PAYLOAD_SHA256}),
            depth=InvestigationDepth.QUICK,
        ),
        credential(),
    )
    record = evidence_of(envelope, "urlhaus_payload_record")
    assert record.attributes["normalized_count"] == 10
    assert record.attributes["truncated"] is True


# --------------------------------------------------------------------------- #
# Relayed findings
# --------------------------------------------------------------------------- #


async def test_a_relayed_virustotal_result_is_never_an_independent_finding() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    relayed = evidence_of(envelope, "urlhaus_relayed_virustotal")
    assert relayed.effect is EvidenceEffect.CONTEXT_ONLY
    assert relayed.evidence_class is EvidenceClass.CONTEXT
    assert relayed.attributes["relayed"] is True


async def test_a_relayed_virustotal_result_shares_gtis_lineage() -> None:
    """One URLhaus response plus one GTI lookup must not read as two sources."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    relayed = evidence_of(envelope, "urlhaus_relayed_virustotal")
    assert relayed.origin_provider == VIRUSTOTAL_RELAY_ORIGIN
    assert relayed.source_family == VIRUSTOTAL_RELAY_FAMILY
    assert relayed.is_relayed is True
    assert relayed.source_family != ABUSE_CH_SOURCE_FAMILY


async def test_the_relayed_virustotal_link_is_not_stored() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert "virustotal.com" not in serialized


async def test_blocklist_statuses_become_one_relayed_record() -> None:
    """URLhaus + Spamhaus + SURBL is one response, not three votes."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    relayed = evidence_of(envelope, "urlhaus_relayed_blocklists")
    assert relayed.effect is EvidenceEffect.CONTEXT_ONLY
    assert relayed.origin_provider == BLOCKLIST_RELAY_ORIGIN
    assert sorted(relayed.attributes["sources"]) == ["spamhaus_dbl", "surbl"]
    assert len(directional(envelope)) == 1


async def test_an_unlisted_host_produces_no_blocklist_record() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert "urlhaus_relayed_blocklists" not in claims(envelope)


async def test_quick_depth_keeps_no_relayed_context() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(payloads.MALICIOUS_URL, depth=InvestigationDepth.QUICK), credential()
    )
    assert "urlhaus_relayed_virustotal" not in claims(envelope)
    assert "urlhaus_malware_url" in claims(envelope)


# --------------------------------------------------------------------------- #
# Absence and errors
# --------------------------------------------------------------------------- #


async def test_no_results_is_no_data_and_not_benign() -> None:
    adapter, _ = build(FakeUrlhausClient(host_payload=payloads.urlhaus_no_results()))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_DOMAIN), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    absence = evidence_of(envelope, "urlhaus_not_tracked")
    assert absence.attributes["tracked"] is False
    assert absence.effect is EvidenceEffect.CONTEXT_ONLY


@pytest.mark.parametrize("status", ["invalid_url", "invalid_host", "invalid_md5", "invalid_sha256"])
async def test_an_invalid_lookup_is_an_invalid_request(status: str) -> None:
    adapter, _ = build(FakeUrlhausClient(url_payload={"query_status": status}))
    with pytest.raises(ProviderInvalidRequestError):
        await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())


async def test_a_rejected_key_inside_a_200_is_raised() -> None:
    adapter, _ = build(FakeUrlhausClient(url_payload={"query_status": "no_api_key"}))
    with pytest.raises(ProviderAuthenticationError):
        await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())


async def test_an_unreadable_200_is_reported_as_an_absence() -> None:
    adapter, _ = build(FakeUrlhausClient(url_payload={"query_status": "ok"}))
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# Provenance, refusals and hygiene
# --------------------------------------------------------------------------- #


async def test_urlhaus_own_claims_carry_abusech_provenance() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    own = [item for item in envelope.evidence if not item.is_relayed]
    assert own
    for evidence in own:
        assert evidence.transport_provider == "urlhaus"
        assert evidence.origin_provider == "urlhaus"
        assert evidence.source_family == ABUSE_CH_SOURCE_FAMILY
        assert evidence.lineage_group_id == lineage_group_for("urlhaus")


async def test_no_provider_grades_its_own_reliability() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    for evidence in envelope.evidence:
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_an_active_action_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(request_for(payloads.MALICIOUS_URL), credential())


async def test_an_active_request_reaching_lookup_directly_is_refused() -> None:
    adapter, client = build()
    request = ProviderRequest(
        investigation_id="inv-1",
        intel_object=normalize_observable(payloads.MALICIOUS_URL).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        activity_mode=ActivityMode.ACTIVE,
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request, credential())
    assert client.calls == []


async def test_a_lookup_without_a_credential_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(ProviderInvalidRequestError, match="requires a credential"):
        await adapter.lookup(request_for(payloads.MALICIOUS_URL), None)


async def test_a_credential_is_validated_against_a_reserved_host() -> None:
    adapter, client = build(FakeUrlhausClient(host_payload=payloads.urlhaus_no_results()))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert client.details(HOST) == ["192.0.2.1"]


async def test_a_rejected_key_validates_as_invalid() -> None:
    adapter, _ = build(FakeUrlhausClient(host_payload={"query_status": "no_api_key"}))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_health_is_unavailable_when_urlhaus_is_down() -> None:
    adapter, client = build()
    client.fail(HOST, provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "urlhaus"))
    report = await adapter.health(credential())
    assert report.health.value == "unavailable"


async def test_nothing_in_the_envelope_carries_the_key() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert FAKE_KEY not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized


async def test_the_client_is_closed_after_every_lookup() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(payloads.MALICIOUS_URL), credential())
    assert client.closed is True


def test_normalize_is_pure_and_needs_no_client() -> None:
    adapter, client = build()
    payload = adapter.normalize(request_for(payloads.MALICIOUS_URL), payloads.urlhaus_url_result())
    assert payload.evidence
    assert client.calls == []
