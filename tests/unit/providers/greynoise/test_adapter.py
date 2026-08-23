"""The GreyNoise adapter (Task 9).

The access-mode behaviour is what these tests exist for. Getting it wrong is
expensive in two directions: probing the paid endpoint every lookup burns a
free-tier analyst's allowance on 403s, and reading a status code as an
entitlement hint turns a revoked key into a working free one that nobody is ever
told to replace.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.greynoise import payloads
from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderPermissionError,
    ProviderTransientError,
    provider_error_for,
)
from ti_recon.providers.greynoise import (
    GREYNOISE_COMMUNITY_ACCESS_ONLY,
    GREYNOISE_NOT_SUPPORTED,
    GREYNOISE_PARTIAL_CONTEXT,
    GreyNoiseAccessLevel,
    GreyNoiseAccessMode,
    GreyNoiseAdapter,
    GreyNoiseLookupPolicy,
)

FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-1234567890"
PING = FakeGreyNoiseClient.PING
FULL = FakeGreyNoiseClient.FULL
QUICK = FakeGreyNoiseClient.QUICK
COMMUNITY = FakeGreyNoiseClient.COMMUNITY


def credential(user_id: str = "analyst-a", connection_id: str = "conn-1") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id=connection_id,
        user_id=user_id,
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def build(
    client: FakeGreyNoiseClient | None = None,
    *,
    policy: GreyNoiseLookupPolicy | None = None,
    clock: ManualClock | None = None,
) -> tuple[GreyNoiseAdapter, FakeGreyNoiseClient]:
    fake = client if client is not None else FakeGreyNoiseClient()
    the_clock = clock if clock is not None else ManualClock()
    # No access store is injected: the adapter builds one from its own policy,
    # which is what a deployment gets and therefore what should be under test.
    adapter = GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(fake),  # type: ignore[arg-type]
        lookup_policy=policy,
        clock=the_clock,
    )
    return adapter, fake


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(payloads.SCANNER_IP).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.SCANNER_CONTEXT}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


def coverage(envelope: Any) -> dict[str, Any]:
    return next(
        item.attributes for item in envelope.evidence if item.claim_type == "greynoise_coverage"
    )


# --------------------------------------------------------------------------- #
# Depth selects the endpoint variant, not the number of requests
# --------------------------------------------------------------------------- #


async def test_a_standard_lookup_reads_the_full_context_once() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert client.call_count(FULL) == 1
    assert client.call_count(QUICK) == 0
    assert client.call_count(COMMUNITY) == 0


async def test_quick_asks_the_same_endpoint_for_less() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assert client.call_count(QUICK) == 1
    assert client.call_count(FULL) == 0


async def test_deep_makes_no_extra_request() -> None:
    """Depth must never mean "call the provider more times"."""
    adapter, client = build()
    await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assert len(client.calls) == 1


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_depth_ever_hunts(depth: InvestigationDepth) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(depth=depth), credential())
    assert {name for name, _ in client.calls} <= {FULL, QUICK, COMMUNITY}


async def test_deep_records_the_sensor_detail_standard_leaves_out() -> None:
    adapter, _ = build()
    standard = await adapter.lookup(request_for(), credential())
    deep = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())

    def observation(envelope: Any) -> dict[str, Any]:
        return next(
            item.attributes
            for item in envelope.evidence
            if item.claim_type == "greynoise_scanner_observation"
        )

    assert "ports" not in observation(standard)
    assert "ports" in observation(deep)


async def test_quick_keeps_the_classification_and_leaves_out_the_rest() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assert "greynoise_classification" in claims(envelope)
    assert "greynoise_tags" not in claims(envelope)
    assert "greynoise_cve_activity" not in claims(envelope)
    assert "greynoise_network_context" not in claims(envelope)


async def test_standard_keeps_the_tags_cves_and_ownership() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert {"greynoise_tags", "greynoise_cve_activity", "greynoise_network_context"} <= claims(
        envelope
    )


async def test_no_depth_changes_the_direction_of_the_evidence() -> None:
    adapter, _ = build()
    directions = set()
    for depth in InvestigationDepth:
        envelope = await adapter.lookup(request_for(depth=depth), credential())
        directions.add(
            next(
                item.effect
                for item in envelope.evidence
                if item.claim_type == "greynoise_classification"
            )
        )
    assert directions == {EvidenceEffect.SUPPORTS_MALICIOUS}


# --------------------------------------------------------------------------- #
# AUTO: finding out which door a credential may use
# --------------------------------------------------------------------------- #


async def test_auto_tries_the_full_context_first() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    assert client.called(FULL)
    assert not client.called(COMMUNITY)


async def test_a_forbidden_full_context_earns_one_community_attempt() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    envelope = await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 1
    assert client.call_count(COMMUNITY) == 1
    assert envelope.status is ProviderRunStatus.SUCCESS


async def test_the_paid_endpoint_is_not_probed_again_for_the_same_credential() -> None:
    """One 403 is enough; re-probing would spend the analyst's allowance."""
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 1
    assert client.call_count(COMMUNITY) == 3


async def test_a_downgraded_lookup_records_the_coverage_gap() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    envelope = await adapter.lookup(request_for(), credential())
    assert GREYNOISE_COMMUNITY_ACCESS_ONLY in envelope.warnings
    attributes = coverage(envelope)
    assert attributes["access_level"] == "community"
    assert attributes["full_context_unavailable"] is True


async def test_a_downgraded_lookup_is_still_a_success() -> None:
    """A Community answer is complete for what Community is — so it caches."""
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert envelope.evidence


async def test_a_plan_limited_refusal_also_earns_the_probe() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PLAN_LIMITED, "greynoise"))
    await adapter.lookup(request_for(), credential())
    assert client.called(COMMUNITY)


async def test_one_analysts_access_level_is_never_used_for_another() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    await adapter.lookup(request_for(), credential("analyst-a"))
    assert client.call_count(FULL) == 1

    await adapter.lookup(request_for(), credential("analyst-b"))
    # The second analyst may well have a paid plan; their lookup tries the full
    # endpoint on its own account rather than inheriting the first one's answer.
    assert client.call_count(FULL) == 2


async def test_a_confirmed_full_credential_keeps_using_the_full_endpoint() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 2
    assert not client.called(COMMUNITY)


async def test_a_remembered_level_expires_so_an_upgrade_is_noticed() -> None:
    clock = ManualClock()
    policy = GreyNoiseLookupPolicy(access_ttl_seconds=60)
    adapter, client = build(policy=policy, clock=clock)
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 1

    client.succeed(FULL)
    clock.advance(61)
    envelope = await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 2
    assert coverage(envelope)["access_level"] == "full"


# --------------------------------------------------------------------------- #
# A rejected key is never a plan hint
# --------------------------------------------------------------------------- #


async def test_a_rejected_key_is_raised_and_never_probed() -> None:
    """Otherwise a revoked key looks like a free account and is never fixed."""
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise"))
    with pytest.raises(Exception) as excinfo:
        await adapter.lookup(request_for(), credential())
    assert getattr(excinfo.value, "category", None) is (ProviderErrorCategory.AUTHENTICATION_ERROR)
    assert not client.called(COMMUNITY)


async def test_a_rejected_key_leaves_nothing_remembered() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise"))
    with pytest.raises(ProviderAuthenticationError):
        await adapter.lookup(request_for(), credential())
    assert await adapter.access_store.get("user|analyst-a|greynoise|conn-1") is None


async def test_a_key_rejected_during_the_probe_is_reported_as_rejected() -> None:
    """The 403 mattered less than "your key is gone"; report the second."""
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    client.fail(
        COMMUNITY, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise")
    )
    with pytest.raises(Exception) as excinfo:
        await adapter.lookup(request_for(), credential())
    assert getattr(excinfo.value, "category", None) is (ProviderErrorCategory.AUTHENTICATION_ERROR)


async def test_an_unrelated_probe_failure_reports_the_original_refusal() -> None:
    """The 403 is what actually blocked the lookup; the probe's 503 is noise."""
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    client.fail(
        COMMUNITY, provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "greynoise")
    )
    with pytest.raises(ProviderPermissionError):
        await adapter.lookup(request_for(), credential())


async def test_an_operator_can_switch_the_probe_off() -> None:
    policy = GreyNoiseLookupPolicy(allow_community_probe=False)
    adapter, client = build(policy=policy)
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    with pytest.raises(ProviderPermissionError):
        await adapter.lookup(request_for(), credential())
    assert not client.called(COMMUNITY)


# --------------------------------------------------------------------------- #
# Pinned modes
# --------------------------------------------------------------------------- #


async def test_a_pinned_community_mode_never_touches_the_paid_endpoint() -> None:
    policy = GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY)
    adapter, client = build(policy=policy)
    envelope = await adapter.lookup(request_for(), credential())
    assert client.called(COMMUNITY)
    assert not client.called(FULL)
    assert envelope.status is ProviderRunStatus.SUCCESS


async def test_a_pinned_community_mode_is_a_choice_not_a_coverage_gap() -> None:
    policy = GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY)
    adapter, _ = build(policy=policy)
    envelope = await adapter.lookup(request_for(), credential())
    assert GREYNOISE_COMMUNITY_ACCESS_ONLY not in envelope.warnings
    assert "full_context_unavailable" not in coverage(envelope)


async def test_a_pinned_full_mode_reports_the_refusal_rather_than_downgrading() -> None:
    """An operator who pinned FULL asked for honest errors, not a quiet fallback."""
    policy = GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.FULL)
    adapter, client = build(policy=policy)
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    with pytest.raises(ProviderPermissionError):
        await adapter.lookup(request_for(), credential())
    assert not client.called(COMMUNITY)


# --------------------------------------------------------------------------- #
# Partial documents
# --------------------------------------------------------------------------- #


async def test_a_trimmed_document_is_partial_and_says_so() -> None:
    adapter, _ = build(FakeGreyNoiseClient(full_status=206))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    assert GREYNOISE_PARTIAL_CONTEXT in envelope.warnings
    assert coverage(envelope)["provider_reduced_response"] is True


async def test_a_trimmed_document_still_yields_the_evidence_that_parsed() -> None:
    adapter, _ = build(FakeGreyNoiseClient(full_status=206))
    envelope = await adapter.lookup(request_for(), credential())
    assert "greynoise_classification" in claims(envelope)


async def test_a_complete_document_is_not_partial() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert GREYNOISE_PARTIAL_CONTEXT not in envelope.warnings


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


async def test_an_unknown_address_is_no_data_and_not_benign() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert "greynoise_not_observed" in claims(envelope)
    for evidence in envelope.evidence:
        assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_community_404_is_also_no_data() -> None:
    policy = GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY)
    adapter, client = build(policy=policy)
    client.fail(COMMUNITY, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA


async def test_a_community_404_still_proves_community_access_works() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    client.fail(COMMUNITY, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(request_for(), credential())
    assert client.call_count(FULL) == 1


async def test_a_document_saying_it_has_no_record_is_recorded_as_such() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"] = {"found": False}
    adapter, _ = build(FakeGreyNoiseClient(full_payload=payload))
    envelope = await adapter.lookup(request_for(), credential())
    assert "greynoise_not_observed" in claims(envelope)


# --------------------------------------------------------------------------- #
# Unsupported observables
# --------------------------------------------------------------------------- #


def file_subject(algorithm: str, digest: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {algorithm: digest}},
    )


@pytest.mark.parametrize(
    "observable",
    ["2001:db8::1", "example.com", "https://example.com/a"],
)
async def test_an_unsupported_observable_is_not_supported_rather_than_empty(
    observable: str,
) -> None:
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(intel_object=normalize_observable(observable).intel_object), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA
    assert GREYNOISE_NOT_SUPPORTED in envelope.warnings
    assert client.calls == []


async def test_a_file_hash_is_not_supported() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(
        request_for(intel_object=file_subject("SHA-256", "a" * 64)), credential()
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert client.calls == []


async def test_an_unsupported_run_carries_a_readable_reason() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(intel_object=normalize_observable("example.com").intel_object), credential()
    )
    assert envelope.error_message is not None
    assert "IPv4" in envelope.error_message


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
        intel_object=normalize_observable(payloads.SCANNER_IP).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
        activity_mode=ActivityMode.ACTIVE,
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request, credential())
    assert client.calls == []


async def test_batch_lookup_is_unsupported() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.batch_lookup([request_for()], credential())


# --------------------------------------------------------------------------- #
# Credentials, capabilities, health
# --------------------------------------------------------------------------- #


async def test_a_credential_is_validated_against_the_ping_endpoint() -> None:
    """A credential check must not cost an intelligence lookup."""
    adapter, client = build()
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert client.call_count(PING) == 1
    assert not client.called(FULL)
    assert not client.called(QUICK)
    assert not client.called(COMMUNITY)


async def test_no_observable_is_named_when_validating_a_credential() -> None:
    """``/ping`` takes none, so nothing about any investigation is revealed."""
    adapter, client = build()
    await adapter.validate_credentials(credential())
    assert [name for name, _ in client.calls] == [PING]


async def test_a_rejected_ping_validates_as_invalid() -> None:
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise"))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_a_throttled_ping_leaves_the_key_alone() -> None:
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.RATE_LIMITED, "greynoise"))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE


async def test_a_transient_ping_failure_says_nothing_about_the_key() -> None:
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "greynoise"))
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.UNKNOWN
    assert validation.is_usable is True


async def test_a_validated_credential_never_carries_the_key() -> None:
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise"))
    validation = await adapter.validate_credentials(credential())
    assert FAKE_KEY not in validation.model_dump_json()
    assert "SHOULD-NOT-LEAK" not in validation.model_dump_json()


async def test_validating_a_credential_settles_no_access_level() -> None:
    """A ping proves reachability, never entitlement."""
    adapter, _ = build()
    await adapter.validate_credentials(credential())
    assert await adapter.access_store.get("user|analyst-a|greynoise|conn-1") is None


async def test_a_missing_credential_validates_as_invalid() -> None:
    adapter, client = build()
    validation = await adapter.validate_credentials(None)
    assert validation.status is CredentialStatus.INVALID
    assert client.calls == []


async def test_capability_discovery_performs_no_request() -> None:
    adapter, client = build()
    discovery = await adapter.discover_capabilities(credential())
    assert client.calls == []
    assert ProviderCapability.SCANNER_CONTEXT in discovery.capabilities


async def test_an_unknown_access_level_reports_the_full_capability_set() -> None:
    """Claiming less than we might manage would make a planner skip us."""
    adapter, _ = build()
    discovery = await adapter.discover_capabilities(credential())
    assert discovery.capabilities == adapter.descriptor.capabilities
    assert discovery.plan_hint is not None


async def test_a_community_credential_reports_the_capabilities_it_lacks() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    await adapter.lookup(request_for(), credential())

    discovery = await adapter.discover_capabilities(credential())
    assert ProviderCapability.NETWORK_OWNERSHIP not in discovery.capabilities
    assert ProviderCapability.RELATIONSHIPS not in discovery.capabilities
    assert ProviderCapability.SCANNER_CONTEXT in discovery.capabilities
    assert discovery.plan_hint == GreyNoiseAccessLevel.COMMUNITY.value


async def test_health_is_unknown_without_a_credential() -> None:
    adapter, client = build()
    report = await adapter.health(None)
    assert report.health.value == "unknown"
    assert client.calls == []


async def test_health_is_checked_with_ping_rather_than_a_lookup() -> None:
    adapter, client = build()
    report = await adapter.health(credential())
    assert report.health.value == "available"
    assert client.call_count(PING) == 1
    assert not client.called(FULL)
    assert not client.called(COMMUNITY)


async def test_health_is_unavailable_when_greynoise_is_down() -> None:
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, "greynoise"))
    report = await adapter.health(credential())
    assert report.health.value == "unavailable"


async def test_health_is_degraded_when_the_key_is_rejected() -> None:
    """The service answered; this key did not get in."""
    adapter, client = build()
    client.fail(PING, provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, "greynoise"))
    report = await adapter.health(credential())
    assert report.health.value == "degraded"
    assert report.detail is not None
    assert FAKE_KEY not in report.model_dump_json()


# --------------------------------------------------------------------------- #
# Envelope hygiene
# --------------------------------------------------------------------------- #


async def test_the_envelope_carries_no_verdict() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    dumped = envelope.model_dump()
    assert {"verdict", "risk_score", "confidence", "score"}.isdisjoint(dumped)


async def test_nothing_in_the_envelope_carries_the_key() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert FAKE_KEY not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized


async def test_metering_headers_become_a_rate_limit_snapshot() -> None:
    adapter, _ = build(
        FakeGreyNoiseClient(
            metering_headers={"x-ratelimit-remaining": "7", "x-ratelimit-limit": "100"}
        )
    )
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.rate_limit is not None
    assert envelope.rate_limit.remaining == 7
    assert envelope.rate_limit.limit == 100


async def test_a_silent_response_produces_no_invented_rate_limit() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.rate_limit is None


async def test_no_quota_snapshot_is_invented_for_greynoise() -> None:
    """There is no zero-cost allowance endpoint, so there is nothing to report."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.quota is None


async def test_the_submitted_object_comes_back_enriched() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    enriched = next(
        item for item in envelope.objects if item.object_type is IntelObjectType.IPV4_ADDR
    )
    assert enriched.properties["greynoise"]["classification"] == "malicious"


async def test_the_client_is_closed_after_every_lookup() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    assert client.closed is True


async def test_the_client_is_closed_even_when_the_lookup_fails() -> None:
    adapter, client = build()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.TRANSIENT_ERROR, "greynoise"))
    with pytest.raises(ProviderTransientError):
        await adapter.lookup(request_for(), credential())
    assert client.closed is True
