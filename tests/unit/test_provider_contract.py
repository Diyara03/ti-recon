"""Provider adapter contract invariants (Task 5).

These tests define what "a valid TI Recon provider adapter" means. Every future
adapter must satisfy them.
"""

from __future__ import annotations

import inspect
import json

import pytest
from pydantic import ValidationError

from fixtures.fake_providers import (
    FakeAggregatorProvider,
    FakeMinimalProvider,
    FakeScannerProvider,
    FakeWarningListProvider,
)
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceClass,
    IntelObjectType,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import (
    PROVIDER_ERROR_RUN_STATUS,
    RETRYABLE_ERROR_CATEGORIES,
    CacheabilityHint,
    NormalizedPayload,
    ProviderAdapter,
    ProviderDescriptor,
    ProviderError,
    ProviderHealth,
    ProviderNotFoundError,
    ProviderRateLimitedError,
    ProviderRequest,
    ProviderResultEnvelope,
    ProviderSchemaError,
    RateLimitSnapshot,
    UnsupportedProviderOperation,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

SECRET = "fake-key-AAAA1111"


def make_object(
    object_type: IntelObjectType = IntelObjectType.IPV4_ADDR,
    value: str = "198.51.100.7",
) -> IntelObject:
    if object_type is IntelObjectType.FILE:
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        return IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=object_type,
            canonical_value=digest,
            display_value=digest,
            properties={"hashes": {"SHA-256": digest}},
        )
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
    )


def make_request(
    capability: ProviderCapability = ProviderCapability.SCANNER_CONTEXT,
    object_type: IntelObjectType = IntelObjectType.IPV4_ADDR,
    **overrides: object,
) -> ProviderRequest:
    kwargs: dict[str, object] = {
        "investigation_id": "inv-1",
        "intel_object": make_object(object_type),
        "requested_capabilities": frozenset({capability}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)  # type: ignore[arg-type]


def make_credential() -> CredentialMaterial:
    from pydantic import SecretStr

    return CredentialMaterial(
        connection_id="conn-1",
        user_id="user-a",
        provider_id="fake_scanner",
        credential_group="fake_scanner",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(SECRET),
    )


# --------------------------------------------------------------------------- #
# Descriptor
# --------------------------------------------------------------------------- #


def test_descriptor_defaults_credential_group_to_provider_id() -> None:
    descriptor = FakeScannerProvider().descriptor
    assert descriptor.credential_group == "fake_scanner"


def test_descriptor_is_immutable() -> None:
    descriptor = FakeScannerProvider().descriptor
    with pytest.raises(ValidationError, match="frozen"):
        descriptor.provider_id = "other"


def test_descriptor_requires_at_least_one_capability() -> None:
    with pytest.raises(ValidationError):
        ProviderDescriptor(
            provider_id="fake_empty",
            display_name="Fake Empty",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset(),
        )


def test_descriptor_requires_at_least_one_object_type() -> None:
    with pytest.raises(ValidationError):
        ProviderDescriptor(
            provider_id="fake_empty",
            display_name="Fake Empty",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset(),
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        )


def test_descriptor_provider_id_format_is_enforced() -> None:
    for bad in ("Fake", "1fake", "fake-provider", "fake provider", ""):
        with pytest.raises(ValidationError):
            ProviderDescriptor(
                provider_id=bad,
                display_name="Fake",
                adapter_version="0.1.0",
                source_family="none",
                supported_object_types=frozenset({IntelObjectType.URL}),
                capabilities=frozenset({ProviderCapability.REPUTATION}),
            )


def test_active_capability_requires_supports_active() -> None:
    with pytest.raises(ValidationError, match="must set supports_active"):
        ProviderDescriptor(
            provider_id="fake_active",
            display_name="Fake Active",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
        )


def test_supports_active_requires_an_active_capability() -> None:
    with pytest.raises(ValidationError, match="must declare an active capability"):
        ProviderDescriptor(
            provider_id="fake_active",
            display_name="Fake Active",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset({ProviderCapability.REPUTATION}),
            supports_active=True,
        )


def test_supports_batch_must_agree_with_the_batch_capability() -> None:
    with pytest.raises(ValidationError, match="supports_batch must agree"):
        ProviderDescriptor(
            provider_id="fake_batch",
            display_name="Fake Batch",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset({ProviderCapability.REPUTATION}),
            supports_batch=True,
        )


def test_passive_capabilities_exclude_active_scan() -> None:
    descriptor = ProviderDescriptor(
        provider_id="fake_both",
        display_name="Fake Both",
        adapter_version="0.1.0",
        source_family="none",
        supported_object_types=frozenset({IntelObjectType.URL}),
        capabilities=frozenset({ProviderCapability.WEB_BEHAVIOR, ProviderCapability.ACTIVE_SCAN}),
        supports_active=True,
    )
    assert descriptor.passive_capabilities == frozenset({ProviderCapability.WEB_BEHAVIOR})


def test_supports_matches_on_object_type_and_capability() -> None:
    adapter = FakeScannerProvider()
    assert adapter.supports(IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT)
    assert not adapter.supports(IntelObjectType.URL, ProviderCapability.SCANNER_CONTEXT)
    assert not adapter.supports(IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION)


def test_assert_supports_raises_typed_error() -> None:
    adapter = FakeScannerProvider()
    with pytest.raises(UnsupportedProviderOperation):
        adapter.assert_supports(IntelObjectType.URL, ProviderCapability.SCANNER_CONTEXT)


# --------------------------------------------------------------------------- #
# Request carries no credential
# --------------------------------------------------------------------------- #


def test_request_has_no_credential_field() -> None:
    for name in ProviderRequest.model_fields:
        assert SENSITIVE_KEY_PATTERN.search(name) is None, name


def test_request_rejects_a_credential_field() -> None:
    with pytest.raises(ValidationError):
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=make_object(),
            requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
            api_key=SECRET,  # type: ignore[call-arg]
        )


def test_request_is_immutable() -> None:
    request = make_request()
    with pytest.raises(ValidationError, match="frozen"):
        request.depth = request.depth


def test_request_defaults_to_passive_lookup() -> None:
    request = make_request()
    assert request.activity_mode is ActivityMode.PASSIVE
    assert request.operation is ProviderOperation.LOOKUP


def test_passive_request_cannot_carry_an_active_operation() -> None:
    with pytest.raises(ValidationError, match="requires activity_mode=active"):
        make_request(operation=ProviderOperation.ACTIVE_ACTION)


def test_passive_request_cannot_request_an_active_capability() -> None:
    with pytest.raises(ValidationError, match="requires activity_mode=active"):
        make_request(capability=ProviderCapability.ACTIVE_SCAN)


def test_active_capability_is_allowed_in_active_mode() -> None:
    request = make_request(
        capability=ProviderCapability.ACTIVE_SCAN,
        activity_mode=ActivityMode.ACTIVE,
    )
    assert ProviderCapability.ACTIVE_SCAN in request.requested_capabilities


def test_request_requires_at_least_one_capability() -> None:
    with pytest.raises(ValidationError):
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=make_object(),
            requested_capabilities=frozenset(),
        )


# --------------------------------------------------------------------------- #
# Result envelope
# --------------------------------------------------------------------------- #


async def test_lookup_returns_a_valid_envelope() -> None:
    adapter = FakeScannerProvider()
    envelope = await adapter.lookup(make_request(), make_credential())
    assert isinstance(envelope, ProviderResultEnvelope)
    assert envelope.provider == "fake_scanner"
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert envelope.adapter_version == "0.1.0"
    assert envelope.api_version == "v1"
    assert envelope.retrieved_at.tzinfo is not None


async def test_envelope_evidence_is_task_3_evidence() -> None:
    adapter = FakeScannerProvider()
    envelope = await adapter.lookup(make_request(), make_credential())
    assert envelope.evidence
    for evidence in envelope.evidence:
        assert evidence.investigation_id == "inv-1"
        assert evidence.claim_type
        assert evidence.source_family
        assert evidence.lineage_group_id


async def test_envelope_evidence_must_name_the_envelope_provider_as_transport() -> None:
    adapter = FakeScannerProvider()
    envelope = await adapter.lookup(make_request(), make_credential())
    with pytest.raises(ValidationError, match="transport_provider"):
        envelope.model_copy(update={"provider": "someone_else"}).model_validate(
            envelope.model_copy(update={"provider": "someone_else"}).model_dump()
        )


async def test_envelope_carries_no_secret() -> None:
    adapter = FakeAggregatorProvider()
    envelope = await adapter.lookup(
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
        make_credential(),
    )
    payload = json.dumps(envelope.model_dump(mode="json"))
    assert SECRET not in payload
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_envelope_holds_a_raw_reference_not_a_raw_payload() -> None:
    adapter = FakeScannerProvider()
    envelope = await adapter.lookup(make_request(), make_credential())
    assert envelope.raw_reference is not None
    assert "body" not in envelope.raw_reference.model_dump()


async def test_relayed_evidence_keeps_a_distinct_origin() -> None:
    adapter = FakeAggregatorProvider()
    envelope = await adapter.lookup(
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
        make_credential(),
    )
    relayed = [evidence for evidence in envelope.evidence if evidence.is_relayed]
    assert len(relayed) == 1
    assert relayed[0].transport_provider == "fake_aggregator"
    assert relayed[0].origin_provider == "fake_scanner"
    assert relayed[0].lineage_group_id == "scanner_noise:fake_scanner"


async def test_relationships_reference_evidence_from_the_same_envelope() -> None:
    adapter = FakeAggregatorProvider()
    envelope = await adapter.lookup(
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
        make_credential(),
    )
    evidence_ids = {evidence.id for evidence in envelope.evidence}
    assert envelope.relationships
    for relationship in envelope.relationships:
        assert relationship.evidence_refs
        assert set(relationship.evidence_refs) <= evidence_ids


def test_envelope_has_no_verdict_or_risk_fields() -> None:
    """An adapter must not be able to express a conclusion."""
    fields = set(ProviderResultEnvelope.model_fields)
    assert fields.isdisjoint(
        {"verdict", "risk_score", "confidence", "assessment", "score", "malicious"}
    )


def test_adapter_has_no_verdict_method() -> None:
    names = {name for name, _ in inspect.getmembers(ProviderAdapter)}
    assert names.isdisjoint({"assess", "verdict", "score", "decide", "risk"})


def test_successful_envelope_may_not_carry_an_error_category() -> None:
    with pytest.raises(ValidationError, match="must not carry an error category"):
        ProviderResultEnvelope(
            provider="fake_scanner",
            operation=ProviderOperation.LOOKUP,
            status=ProviderRunStatus.SUCCESS,
            adapter_version="0.1.0",
            api_version="v1",
            error_category=ProviderErrorCategory.RATE_LIMITED,
        )


def test_failed_envelope_must_carry_an_error_category() -> None:
    with pytest.raises(ValidationError, match="must carry a normalized error category"):
        ProviderResultEnvelope(
            provider="fake_scanner",
            operation=ProviderOperation.LOOKUP,
            status=ProviderRunStatus.ERROR,
            adapter_version="0.1.0",
            api_version="v1",
        )


def test_envelope_rejects_credential_mentions_in_warnings() -> None:
    with pytest.raises(ValidationError, match="must not mention credential material"):
        ProviderResultEnvelope(
            provider="fake_scanner",
            operation=ProviderOperation.LOOKUP,
            status=ProviderRunStatus.NO_DATA,
            adapter_version="0.1.0",
            api_version="v1",
            warnings=("retry with a valid api_key",),
        )


def test_envelope_rejects_credential_mentions_in_error_message() -> None:
    with pytest.raises(ValidationError, match="must not mention credential material"):
        ProviderResultEnvelope(
            provider="fake_scanner",
            operation=ProviderOperation.LOOKUP,
            status=ProviderRunStatus.ERROR,
            adapter_version="0.1.0",
            api_version="v1",
            error_category=ProviderErrorCategory.AUTHENTICATION_ERROR,
            error_message="rejected Authorization header value abc123",
        )


def test_normalized_payload_rejects_credential_mentions_in_warnings() -> None:
    with pytest.raises(ValidationError, match="must not mention credential material"):
        NormalizedPayload(warnings=("bad Auth-Key",))


async def test_envelope_converts_to_a_provider_run() -> None:
    adapter = FakeScannerProvider()
    envelope = await adapter.lookup(make_request(), make_credential())
    run = envelope.to_provider_run(
        investigation_id="inv-1", capability=ProviderCapability.SCANNER_CONTEXT
    )
    assert run.provider == "fake_scanner"
    assert run.status is ProviderRunStatus.SUCCESS
    assert run.adapter_version == "0.1.0"
    assert run.raw_reference_id == envelope.raw_reference.id  # type: ignore[union-attr]


async def test_has_data_reports_emptiness_honestly() -> None:
    assert (await FakeScannerProvider().lookup(make_request(), make_credential())).has_data
    minimal = await FakeMinimalProvider().lookup(
        make_request(ProviderCapability.MALWARE_INTELLIGENCE, IntelObjectType.FILE),
        make_credential(),
    )
    assert minimal.has_data is False
    assert minimal.status is ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# Cacheability and rate limits
# --------------------------------------------------------------------------- #


def test_cacheability_defaults_to_cacheable_with_no_ttl() -> None:
    hint = CacheabilityHint()
    assert hint.cacheable is True
    assert hint.ttl_seconds is None


def test_uncacheable_result_may_not_declare_a_ttl() -> None:
    with pytest.raises(ValidationError, match="must not carry cache lifetimes"):
        CacheabilityHint(cacheable=False, ttl_seconds=60)


def test_rate_limit_snapshot_fields_are_all_optional() -> None:
    snapshot = RateLimitSnapshot()
    assert snapshot.is_empty is True


def test_rate_limit_snapshot_records_partial_information() -> None:
    snapshot = RateLimitSnapshot(remaining=4)
    assert snapshot.is_empty is False
    assert snapshot.limit is None
    assert snapshot.reset_at is None


def test_default_rate_limit_parsing_returns_none() -> None:
    """Most providers expose nothing; the default must not invent numbers."""
    assert FakeScannerProvider().parse_rate_limits({}) is None


def test_rate_limit_parsing_uses_provider_headers_when_present() -> None:
    snapshot = FakeScannerProvider().parse_rate_limits(
        {"x-fake-ratelimit-limit": "100", "x-fake-ratelimit-remaining": "42"}
    )
    assert snapshot is not None
    assert snapshot.remaining == 42


# --------------------------------------------------------------------------- #
# Optional operations
# --------------------------------------------------------------------------- #


async def test_unsupported_batch_lookup_raises_typed_error() -> None:
    adapter = FakeScannerProvider()
    with pytest.raises(UnsupportedProviderOperation) as excinfo:
        await adapter.batch_lookup([make_request()], make_credential())
    assert excinfo.value.run_status is ProviderRunStatus.NOT_SUPPORTED
    assert excinfo.value.is_retryable is False


async def test_unsupported_pivot_raises_typed_error() -> None:
    with pytest.raises(UnsupportedProviderOperation):
        await FakeScannerProvider().pivot(make_request(), make_credential())


async def test_active_action_is_unsupported_everywhere() -> None:
    for adapter in (
        FakeScannerProvider(),
        FakeAggregatorProvider(),
        FakeWarningListProvider(),
        FakeMinimalProvider(),
    ):
        with pytest.raises(UnsupportedProviderOperation):
            await adapter.active_action(make_request(), make_credential())


async def test_optional_operations_do_not_raise_notimplementederror() -> None:
    adapter = FakeScannerProvider()
    for coroutine in (
        adapter.pivot(make_request(), None),
        adapter.active_action(make_request(), None),
    ):
        with pytest.raises(UnsupportedProviderOperation) as excinfo:
            await coroutine
        assert not isinstance(excinfo.value, NotImplementedError)


async def test_supported_batch_lookup_works() -> None:
    adapter = FakeAggregatorProvider()
    requests = [
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
    ]
    results = await adapter.batch_lookup(requests, make_credential())
    assert len(results) == 2


# --------------------------------------------------------------------------- #
# Credentials, capabilities, health
# --------------------------------------------------------------------------- #


async def test_validate_credentials_reports_a_credential_status() -> None:
    result = await FakeScannerProvider().validate_credentials(make_credential())
    assert result.status is CredentialStatus.ACTIVE
    assert result.is_usable is True


async def test_validate_credentials_flags_a_missing_credential() -> None:
    result = await FakeScannerProvider().validate_credentials(None)
    assert result.status is CredentialStatus.INVALID
    assert result.is_usable is False


async def test_credential_free_provider_validates_without_a_credential() -> None:
    result = await FakeWarningListProvider().validate_credentials(None)
    assert result.status is CredentialStatus.ACTIVE


async def test_validation_detail_never_contains_the_secret() -> None:
    result = await FakeScannerProvider().validate_credentials(make_credential())
    assert SECRET not in result.model_dump_json()


async def test_capability_discovery_is_credential_scoped() -> None:
    discovery = await FakeAggregatorProvider().discover_capabilities(make_credential())
    assert ProviderCapability.REPUTATION in discovery.capabilities
    assert discovery.plan_hint == "fake-plan"


async def test_default_health_is_unknown_not_available() -> None:
    class Bare(FakeMinimalProvider):
        pass

    report = await ProviderAdapter.health(Bare())
    assert report.health is ProviderHealth.UNKNOWN


async def test_adapter_can_report_health() -> None:
    report = await FakeScannerProvider().health()
    assert report.health is ProviderHealth.AVAILABLE


def test_provider_health_is_separate_from_credential_and_run_status() -> None:
    """Three axes, three models, three field types — never one collapsed status."""
    from ti_recon.credentials.models import ProviderConnection
    from ti_recon.models.investigation import ProviderRun
    from ti_recon.providers.adapter import ProviderHealthReport

    assert ProviderHealthReport.model_fields["health"].annotation is ProviderHealth
    assert ProviderConnection.model_fields["status"].annotation is CredentialStatus
    assert ProviderRun.model_fields["status"].annotation is ProviderRunStatus
    # No model carries two of the three at once.
    for model in (ProviderHealthReport, ProviderConnection, ProviderRun):
        annotations = {field.annotation for field in model.model_fields.values()}
        assert len(annotations & {ProviderHealth, CredentialStatus, ProviderRunStatus}) == 1


# --------------------------------------------------------------------------- #
# All provider I/O is async
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "method_name",
    [
        "validate_credentials",
        "discover_capabilities",
        "lookup",
        "batch_lookup",
        "pivot",
        "active_action",
        "health",
    ],
)
def test_io_methods_are_coroutines(method_name: str) -> None:
    method = getattr(ProviderAdapter, method_name)
    assert inspect.iscoroutinefunction(method), method_name


@pytest.mark.parametrize("method_name", ["normalize", "classify_error", "parse_rate_limits"])
def test_pure_helpers_are_synchronous(method_name: str) -> None:
    method = getattr(ProviderAdapter, method_name)
    assert not inspect.iscoroutinefunction(method), method_name


# --------------------------------------------------------------------------- #
# Error taxonomy
# --------------------------------------------------------------------------- #


def test_every_error_category_maps_to_a_run_status() -> None:
    assert set(PROVIDER_ERROR_RUN_STATUS) == set(ProviderErrorCategory)


def test_not_found_is_recorded_as_no_data_not_an_error() -> None:
    error = ProviderNotFoundError("fake_scanner")
    assert error.run_status is ProviderRunStatus.NO_DATA


def test_rate_limited_is_retryable_and_schema_error_is_not() -> None:
    assert ProviderRateLimitedError("fake_scanner").is_retryable is True
    assert ProviderSchemaError("fake_scanner").is_retryable is False
    assert RETRYABLE_ERROR_CATEGORIES <= set(ProviderErrorCategory)


def test_error_text_is_safe_to_log() -> None:
    error = ProviderRateLimitedError("fake_scanner", operation="lookup", retry_after_seconds=30.0)
    text = str(error)
    assert "fake_scanner" in text
    assert "rate_limited" in text
    assert SENSITIVE_KEY_PATTERN.search(text) is None


def test_unsupported_operation_names_the_operation() -> None:
    error = UnsupportedProviderOperation("fake_scanner", operation="pivot")
    assert "pivot" in str(error)
    assert isinstance(error, ProviderError)


def test_classify_error_maps_onto_normalized_categories() -> None:
    adapter = FakeScannerProvider()
    assert (
        adapter.classify_error(ProviderRateLimitedError("fake_scanner"))
        is ProviderErrorCategory.RATE_LIMITED
    )
    assert adapter.classify_error(TimeoutError()) is ProviderErrorCategory.TRANSIENT_ERROR
    assert adapter.classify_error(ValueError()) is ProviderErrorCategory.SCHEMA_ERROR
    assert adapter.classify_error(RuntimeError()) is ProviderErrorCategory.UNKNOWN_ERROR


# --------------------------------------------------------------------------- #
# Normalization is pure
# --------------------------------------------------------------------------- #


def test_normalize_is_deterministic_and_needs_no_io() -> None:
    adapter = FakeScannerProvider()
    request = make_request()
    first = adapter.normalize(request, {"classification": "benign"})
    second = adapter.normalize(request, {"classification": "benign"})
    assert [e.claim_type for e in first.evidence] == [e.claim_type for e in second.evidence]
    assert first.evidence[0].attributes == second.evidence[0].attributes


def test_normalize_returns_evidence_with_full_provenance() -> None:
    payload = FakeAggregatorProvider().normalize(
        make_request(ProviderCapability.REPUTATION, IntelObjectType.DOMAIN_NAME),
        {"malicious": 3},
    )
    assert payload.evidence
    for evidence in payload.evidence:
        assert evidence.transport_provider == "fake_aggregator"
        assert evidence.origin_provider
        assert evidence.source_family
    classes = {evidence.evidence_class for evidence in payload.evidence}
    assert EvidenceClass.AGGREGATED_REPUTATION in classes


def test_empty_normalization_is_valid() -> None:
    payload = FakeWarningListProvider().normalize(make_request(), {"listed": False})
    assert payload.evidence == ()
    assert payload.objects == ()
    assert payload.relationships == ()


def test_descriptor_requires_passive_or_active_support() -> None:
    with pytest.raises(ValidationError, match="passive or active"):
        ProviderDescriptor(
            provider_id="fake_inert",
            display_name="Fake Inert",
            adapter_version="0.1.0",
            source_family="none",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset({ProviderCapability.REPUTATION}),
            supports_passive=False,
        )


def test_base_adapter_parse_rate_limits_returns_none() -> None:
    """The contract default must not invent limits an adapter never parsed."""
    assert ProviderAdapter.parse_rate_limits(FakeMinimalProvider(), {}) is None


def test_descriptor_keeps_an_explicit_credential_group() -> None:
    """Shared-credential providers name their group instead of themselves."""
    descriptor = ProviderDescriptor(
        provider_id="fake_grouped",
        display_name="Fake Grouped",
        adapter_version="0.1.0",
        source_family="grouped_family",
        credential_group="shared_group",
        supported_object_types=frozenset({IntelObjectType.URL}),
        capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    assert descriptor.credential_group == "shared_group"
