"""The Censys adapter (Task 9).

Two behaviours carry this suite. Every asset read costs a credit, so the adapter
must never spend one to answer a question the free credit endpoint can answer —
and it must never search, at any depth. And a URL that maps onto an address
rather than a web property must say so, because "port 443 is open on this
address" is not "Censys has seen this page".
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.censys import payloads
from fixtures.censys.fake_client import FakeCensysClient, FakeCensysClientFactory
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.execution.limits import InMemoryQuotaStore
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.censys import (
    CENSYS_NOT_SUPPORTED,
    CensysAdapter,
    CensysCreditScope,
    CensysLookupPolicy,
    StaticOrganizationDirectory,
)
from ti_recon.providers.errors import (
    ProviderInvalidRequestError,
    ProviderQuotaExceededError,
    ProviderTransientError,
    provider_error_for,
)

FAKE_TOKEN = "censys-pat-SHOULD-NOT-LEAK-1234567890"
HOST = FakeCensysClient.HOST
WEB_PROPERTY = FakeCensysClient.WEB_PROPERTY
USER_CREDITS = FakeCensysClient.USER_CREDITS
ORGANIZATION_CREDITS = FakeCensysClient.ORGANIZATION_CREDITS


def credential(user_id: str = "analyst-a", connection_id: str = "conn-1") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id=connection_id,
        user_id=user_id,
        provider_id="censys",
        credential_group="censys",
        auth_type=AuthType.BEARER_TOKEN,
        secret=SecretStr(FAKE_TOKEN),
    )


def build(
    client: FakeCensysClient | None = None,
    *,
    policy: CensysLookupPolicy | None = None,
    organizations: StaticOrganizationDirectory | None = None,
    quota_store: InMemoryQuotaStore | None = None,
    clock: ManualClock | None = None,
) -> tuple[CensysAdapter, FakeCensysClient]:
    fake = client if client is not None else FakeCensysClient()
    the_clock = clock if clock is not None else ManualClock()
    adapter = CensysAdapter(
        client_factory=FakeCensysClientFactory(fake),  # type: ignore[arg-type]
        lookup_policy=policy,
        organizations=organizations,
        quota_store=quota_store,
        clock=the_clock,
    )
    return adapter, fake


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(payloads.HOST_IP).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.CURRENT_INFRASTRUCTURE}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def url_request(url: str, **overrides: Any) -> ProviderRequest:
    return request_for(intel_object=normalize_observable(url).intel_object, **overrides)


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


def coverage(envelope: Any) -> dict[str, Any]:
    return next(
        item.attributes for item in envelope.evidence if item.claim_type == "censys_asset_coverage"
    )


def file_subject(algorithm: str, digest: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {algorithm: digest}},
    )


# --------------------------------------------------------------------------- #
# One deterministic request per lookup
# --------------------------------------------------------------------------- #


async def test_an_address_reads_the_host_asset_once() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert client.details(HOST) == [payloads.HOST_IP]
    assert client.call_count(WEB_PROPERTY) == 0


async def test_a_url_reads_the_web_property_it_maps_onto() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(
        url_request(f"https://{payloads.WEB_PROPERTY_HOST}/login?x=1"), credential()
    )
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert client.details(WEB_PROPERTY) == [f"{payloads.WEB_PROPERTY_HOST}:443"]
    assert client.call_count(HOST) == 0


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_ever_reads_more_than_one_asset(depth: InvestigationDepth) -> None:
    """Depth must never mean "spend another credit"."""
    adapter, client = build()
    await adapter.lookup(request_for(depth=depth), credential())
    assert client.call_count(HOST) == 1
    assert client.call_count(WEB_PROPERTY) == 0


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_ever_searches(depth: InvestigationDepth) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(depth=depth), credential())
    assert {name for name, _ in client.calls} <= {
        HOST,
        WEB_PROPERTY,
        USER_CREDITS,
        ORGANIZATION_CREDITS,
    }


async def test_quick_keeps_a_summary_and_leaves_the_rest_out() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assert "censys_host_observation" in claims(envelope)
    assert "censys_network_ownership" in claims(envelope)
    assert "censys_services" not in claims(envelope)
    assert "censys_dns_names" not in claims(envelope)
    assert "censys_tls_certificates" not in claims(envelope)
    assert "censys_vulnerabilities" not in claims(envelope)


async def test_standard_adds_the_services_dns_certificates_and_exposures() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert {
        "censys_services",
        "censys_dns_names",
        "censys_tls_certificates",
        "censys_vulnerabilities",
        "censys_labels",
    } <= claims(envelope)


async def test_deep_records_more_of_the_same_document() -> None:
    services = [{"port": port, "protocol": "HTTP"} for port in range(1, 60)]
    client = FakeCensysClient(hosts={payloads.HOST_IP: payloads.host_payload(services=services)})
    adapter, _ = build(client)

    standard = await adapter.lookup(request_for(), credential())
    deep = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())

    def kept(envelope: Any) -> int:
        return len(
            next(
                item.attributes["services"]
                for item in envelope.evidence
                if item.claim_type == "censys_services"
            )
        )

    assert kept(deep) > kept(standard)


async def test_no_depth_changes_the_direction_of_the_evidence() -> None:
    """There is no direction to change: Censys evidence is always context."""
    adapter, _ = build()
    for depth in InvestigationDepth:
        envelope = await adapter.lookup(request_for(depth=depth), credential())
        for evidence in envelope.evidence:
            assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


# --------------------------------------------------------------------------- #
# Match scope and the derived anchor
# --------------------------------------------------------------------------- #


async def test_an_address_answers_for_itself_exactly() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert coverage(envelope)["match_scope"] == MatchScope.EXACT_OBSERVABLE.value
    for evidence in envelope.evidence:
        assert evidence.match_scope is MatchScope.EXACT_OBSERVABLE


async def test_a_web_property_is_where_the_url_lives_not_the_url() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        url_request(f"https://{payloads.WEB_PROPERTY_HOST}/login"), credential()
    )
    assert coverage(envelope)["match_scope"] == MatchScope.SAME_HOST.value
    for evidence in envelope.evidence:
        assert evidence.match_scope is MatchScope.SAME_HOST


async def test_an_address_literal_url_says_it_asked_about_the_address() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(url_request(f"http://{payloads.HOST_IP}/panel"), credential())
    assert client.details(HOST) == [payloads.HOST_IP]
    attributes = coverage(envelope)
    assert attributes["asset_kind"] == "host"
    assert attributes["match_scope"] == MatchScope.SAME_IP.value
    assert attributes["derived_from"] == "url_authority"


async def test_an_address_literal_urls_pivots_hang_off_the_address() -> None:
    """A URL does not belong to an autonomous system; the address does."""
    adapter, _ = build()
    request = url_request(f"http://{payloads.HOST_IP}/panel")
    envelope = await adapter.lookup(request, credential())

    derived = next(
        item
        for item in envelope.objects
        if item.object_type is IntelObjectType.IPV4_ADDR
        and item.canonical_value == payloads.HOST_IP
    )
    assert derived.id != request.intel_object.id
    asn_links = [
        link for link in envelope.relationships if link.relationship_type.value == "belongs-to-asn"
    ]
    assert asn_links
    for link in asn_links:
        assert link.source_object_id == derived.id


async def test_an_addresss_own_lookup_creates_no_duplicate_object() -> None:
    adapter, _ = build()
    request = request_for()
    envelope = await adapter.lookup(request, credential())
    addresses = [item for item in envelope.objects if item.object_type is IntelObjectType.IPV4_ADDR]
    assert len(addresses) == 1
    assert addresses[0].id == request.intel_object.id


async def test_a_relationship_always_references_evidence_in_the_envelope() -> None:
    adapter, _ = build()
    for request in (
        request_for(),
        url_request(f"https://{payloads.WEB_PROPERTY_HOST}/login"),
        url_request(f"http://{payloads.HOST_IP}/panel"),
    ):
        envelope = await adapter.lookup(request, credential())
        evidence_ids = {item.id for item in envelope.evidence}
        for relationship in envelope.relationships:
            assert set(relationship.evidence_refs) <= evidence_ids


# --------------------------------------------------------------------------- #
# Credits
# --------------------------------------------------------------------------- #


async def test_a_credential_is_validated_without_spending_a_credit() -> None:
    """The credit endpoints are free; an asset read is not."""
    adapter, client = build()
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert client.called(USER_CREDITS)
    assert not client.called(HOST)
    assert not client.called(WEB_PROPERTY)


async def test_a_rejected_token_validates_as_invalid() -> None:
    adapter, client = build()
    client.fail(
        USER_CREDITS, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "censys")
    )
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_an_empty_wallet_leaves_the_token_alone() -> None:
    adapter, client = build()
    client.fail(USER_CREDITS, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "censys"))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE


async def test_a_missing_credential_validates_as_invalid() -> None:
    adapter, client = build()
    validation = await adapter.validate_credentials(None)
    assert validation.status is CredentialStatus.INVALID
    assert client.calls == []


async def test_the_user_balance_is_read_when_no_organization_is_configured() -> None:
    adapter, client = build()
    reading = await adapter.fetch_credits(credential())
    assert reading.scope is CensysCreditScope.USER
    assert reading.remaining == 240
    assert not client.called(ORGANIZATION_CREDITS)


async def test_the_organization_balance_is_read_when_one_is_configured() -> None:
    directory = StaticOrganizationDirectory()
    directory.set(user_id="analyst-a", connection_id="conn-1", organization_id="org-1")
    adapter, client = build(organizations=directory)

    reading = await adapter.fetch_credits(credential())
    assert reading.scope is CensysCreditScope.ORGANIZATION
    assert client.details(ORGANIZATION_CREDITS) == ["org-1"]
    assert not client.called(USER_CREDITS)


async def test_one_analysts_organization_is_never_read_for_another() -> None:
    directory = StaticOrganizationDirectory()
    directory.set(user_id="analyst-a", connection_id="conn-1", organization_id="org-1")
    adapter, client = build(organizations=directory)

    reading = await adapter.fetch_credits(credential("analyst-b", "conn-1"))
    assert reading.scope is CensysCreditScope.USER
    assert not client.called(ORGANIZATION_CREDITS)


async def test_the_balance_travels_with_the_result() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.quota is not None
    assert envelope.quota.bucket("credits") is not None
    assert coverage(envelope)["credits_remaining"] == 240
    assert coverage(envelope)["credit_scope"] == "user"


async def test_the_balance_is_read_once_per_freshness_window() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    adapter, client = build(quota_store=store)
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(request_for(), credential())
    assert client.call_count(USER_CREDITS) == 1
    assert client.call_count(HOST) == 2


async def test_an_operator_can_switch_the_balance_refresh_off() -> None:
    """A Censys lookup then costs strictly one request per uncached asset."""
    adapter, client = build(policy=CensysLookupPolicy(refresh_credits_on_lookup=False))
    await adapter.lookup(request_for(), credential())
    assert not client.called(USER_CREDITS)
    assert client.call_count(HOST) == 1


async def test_a_failed_balance_read_never_fails_the_lookup() -> None:
    adapter, client = build()
    client.fail(USER_CREDITS, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "censys"))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert envelope.quota is None


async def test_a_zero_balance_is_reported_as_exhausted() -> None:
    client = FakeCensysClient(user_credits=payloads.user_credits_payload(remaining=0))
    adapter, _ = build(client)
    reading = await adapter.fetch_credits(credential())
    assert reading.is_exhausted is True


async def test_an_empty_wallet_is_recorded_where_the_precheck_will_see_it() -> None:
    store = InMemoryQuotaStore(clock=ManualClock())
    client = FakeCensysClient(user_credits=payloads.user_credits_payload(remaining=0))
    adapter, _ = build(client, quota_store=store)
    await adapter.lookup(request_for(), credential())

    snapshot = await store.get("user|analyst-a|censys|conn-1")
    assert snapshot is not None
    assert snapshot.is_exhausted is True


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


async def test_an_unscanned_asset_is_no_data_and_not_benign() -> None:
    adapter, _ = build(FakeCensysClient(hosts={}))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert "censys_asset_not_observed" in claims(envelope)
    for evidence in envelope.evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_an_unscanned_asset_still_records_which_asset_was_asked_about() -> None:
    adapter, _ = build(FakeCensysClient(web_properties={}))
    envelope = await adapter.lookup(
        url_request(f"https://{payloads.WEB_PROPERTY_HOST}/login"), credential()
    )
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert coverage(envelope)["asset"] == f"{payloads.WEB_PROPERTY_HOST}:443"


async def test_an_unscanned_asset_still_reports_the_balance() -> None:
    adapter, _ = build(FakeCensysClient(hosts={}))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.quota is not None


# --------------------------------------------------------------------------- #
# Unsupported observables
# --------------------------------------------------------------------------- #


async def test_a_bare_domain_is_not_supported_rather_than_empty() -> None:
    """Guessing 80 and 443 would report two ports as domain coverage."""
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(intel_object=normalize_observable("example.com").intel_object), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA
    assert CENSYS_NOT_SUPPORTED in envelope.warnings
    assert client.calls == []


async def test_a_bare_domain_explains_why() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(intel_object=normalize_observable("example.com").intel_object), credential()
    )
    assert envelope.error_message is not None
    assert "port" in envelope.error_message


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [("MD5", "c" * 32), ("SHA-1", "d" * 40), ("SHA-256", "a" * 64)],
)
async def test_a_file_hash_is_not_supported(algorithm: str, digest: str) -> None:
    """A file hash is never reinterpreted as a certificate fingerprint."""
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(intel_object=file_subject(algorithm, digest)), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert client.calls == []
    assert envelope.error_message is not None
    assert "certificate" in envelope.error_message


async def test_an_ftp_url_is_not_supported() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(url_request("ftp://example.com/pub"), credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert client.calls == []


async def test_no_credit_is_spent_on_an_unsupported_observable() -> None:
    adapter, client = build()
    await adapter.lookup(
        request_for(intel_object=normalize_observable("example.com").intel_object), credential()
    )
    assert not client.called(HOST)
    assert not client.called(USER_CREDITS)


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


async def test_a_lookup_without_a_credential_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(ProviderInvalidRequestError, match="requires a credential"):
        await adapter.lookup(request_for(), None)


async def test_an_active_action_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(request_for(), credential())


async def test_an_active_request_reaching_lookup_directly_is_refused() -> None:
    """A caller bypassing the executor still cannot make this integration act."""
    adapter, client = build()
    request = ProviderRequest(
        investigation_id="inv-1",
        intel_object=normalize_observable(payloads.HOST_IP).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.CURRENT_INFRASTRUCTURE}),
        activity_mode=ActivityMode.ACTIVE,
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request, credential())
    assert client.calls == []


async def test_batch_lookup_is_unsupported() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.batch_lookup([request_for()], credential())


async def test_an_asset_read_failure_is_raised_for_the_executor_to_classify() -> None:
    adapter, client = build()
    client.fail(HOST, provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, "censys"))
    with pytest.raises(ProviderQuotaExceededError):
        await adapter.lookup(request_for(), credential())


# --------------------------------------------------------------------------- #
# Capabilities and health
# --------------------------------------------------------------------------- #


async def test_capability_discovery_performs_no_request() -> None:
    adapter, client = build()
    discovery = await adapter.discover_capabilities(credential())
    assert client.calls == []
    assert discovery.capabilities == adapter.descriptor.capabilities
    assert discovery.plan_hint is not None
    assert "search" in discovery.plan_hint


async def test_health_is_unknown_without_a_credential() -> None:
    adapter, client = build()
    report = await adapter.health(None)
    assert report.health.value == "unknown"
    assert client.calls == []


async def test_health_is_checked_against_the_free_endpoint() -> None:
    adapter, client = build()
    report = await adapter.health(credential())
    assert report.health.value == "available"
    assert client.called(USER_CREDITS)
    assert not client.called(HOST)


async def test_health_is_unavailable_when_censys_is_down() -> None:
    adapter, client = build()
    client.fail(
        USER_CREDITS, provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "censys")
    )
    report = await adapter.health(credential())
    assert report.health.value == "unavailable"


# --------------------------------------------------------------------------- #
# Envelope hygiene
# --------------------------------------------------------------------------- #


async def test_the_envelope_carries_no_verdict() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    dumped = envelope.model_dump()
    assert {"verdict", "risk_score", "confidence", "score"}.isdisjoint(dumped)


async def test_nothing_in_the_envelope_carries_the_token() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert FAKE_TOKEN not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized


async def test_no_banner_or_body_reaches_the_envelope() -> None:
    adapter, _ = build()
    for request in (
        request_for(),
        url_request(f"https://{payloads.WEB_PROPERTY_HOST}/login"),
    ):
        envelope = await adapter.lookup(request, credential())
        serialized = json.dumps(envelope.model_dump(mode="json"))
        assert "ATTACKER-CONTROLLED-TEXT" not in serialized
        assert "ATTACKER CONTROLLED PAGE" not in serialized
        assert "<html>" not in serialized


async def test_the_submitted_object_comes_back_enriched() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    enriched = next(
        item for item in envelope.objects if item.object_type is IntelObjectType.IPV4_ADDR
    )
    assert enriched.properties["censys"]["as_name"] == "EXAMPLE-AS"


async def test_an_unreadable_document_degrades_the_run_to_partial() -> None:
    client = FakeCensysClient(hosts={payloads.HOST_IP: {"unexpected": "shape"}})
    adapter, _ = build(client)
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    assert "CENSYS_DOCUMENT_UNREADABLE" in envelope.warnings


async def test_the_client_is_closed_after_every_lookup() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    assert client.closed is True


async def test_the_client_is_closed_even_when_the_lookup_fails() -> None:
    adapter, client = build()
    client.fail(HOST, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "censys"))
    with pytest.raises(ProviderTransientError):
        await adapter.lookup(request_for(), credential())
    assert client.closed is True


# --------------------------------------------------------------------------- #
# The pure normalizer
# --------------------------------------------------------------------------- #


def test_normalize_is_pure_and_needs_no_client() -> None:
    adapter, client = build()
    payload = adapter.normalize(request_for(), payloads.host_payload())
    assert payload.evidence
    assert client.calls == []


def test_normalize_reports_an_unsupported_observable_rather_than_raising() -> None:
    adapter, _ = build()
    payload = adapter.normalize(
        request_for(intel_object=normalize_observable("example.com").intel_object),
        payloads.host_payload(),
    )
    assert payload.evidence == ()
    assert CENSYS_NOT_SUPPORTED in payload.warnings


def test_normalize_tolerates_an_empty_payload() -> None:
    adapter, _ = build()
    payload = adapter.normalize(request_for(), {})
    assert "CENSYS_DOCUMENT_UNREADABLE" in payload.warnings
