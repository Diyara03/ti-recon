"""Cross-layer foundation test (Tasks 1-5).

Walks one path through every layer that exists:

    user -> credential resolver -> provider registry -> adapter
         -> ProviderResultEnvelope -> Evidence -> Relationship

No provider API is contacted, no network I/O happens, and no verdict is
computed — there is no verdict engine, and this test asserts that the pipeline
stops at evidence.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.fake_providers import (
    FakeAggregatorProvider,
    FakeScannerProvider,
    FakeWarningListProvider,
    all_fake_adapters,
)
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialNotConfigured,
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    ActivityMode,
    CoverageRelevance,
    CoverageStatus,
    EvidenceClass,
    IntelObjectType,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models import CoverageItem, Investigation
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.versions import ENGINE_VERSION, POLICY_VERSION

USER_A = "analyst-a"
USER_B = "analyst-b"
KEY_A = "aggregator-key-AAAA1111"
KEY_B = "aggregator-key-BBBB2222"


class Stack:
    """The Tasks 1-5 foundation, wired together with in-memory backends."""

    def __init__(self) -> None:
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.registry = ProviderRegistry(all_fake_adapters())


@pytest.fixture
async def stack() -> Stack:
    stack = Stack()
    await stack.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    await stack.manager.create_connection(
        user_id=USER_B,
        provider_id="fake_aggregator",
        secret=KEY_B,
        auth_type=AuthType.API_KEY,
    )
    return stack


async def run_lookup(stack: Stack, user_id: str, raw_input: str) -> dict[str, Any]:
    """Normalize, plan nothing, resolve a credential, look up, keep the result."""
    normalized = normalize_observable(raw_input)
    intel_object = normalized.intel_object

    investigation = Investigation(
        primary_object_id=intel_object.id,
        original_input=normalized.original_input,
        activity_mode=ActivityMode.PASSIVE,
        requested_capabilities=[ProviderCapability.REPUTATION],
        engine_version=ENGINE_VERSION,
        policy_version=POLICY_VERSION,
    )

    matches = stack.registry.find_compatible(
        intel_object.object_type, ProviderCapability.REPUTATION
    )
    assert matches, "no provider covers this capability"
    adapter = matches[0]

    credential = await stack.resolver.resolve(
        authenticated_user_id=user_id, provider_id=adapter.descriptor.provider_id
    )

    request = ProviderRequest(
        investigation_id=investigation.id,
        intel_object=intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
    )
    envelope = await adapter.lookup(request, credential)

    return {
        "investigation": investigation,
        "intel_object": intel_object,
        "adapter": adapter,
        "credential": credential,
        "request": request,
        "envelope": envelope,
    }


# --------------------------------------------------------------------------- #
# The happy path, layer by layer
# --------------------------------------------------------------------------- #


async def test_registry_resolves_the_provider_by_capability(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    assert result["adapter"].descriptor.provider_id == "fake_aggregator"


async def test_correct_users_credential_is_selected(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    assert result["credential"].reveal() == KEY_A
    assert result["credential"].user_id == USER_A

    other = await run_lookup(stack, USER_B, "evil[.]example")
    assert other["credential"].reveal() == KEY_B


async def test_input_is_normalized_before_any_provider_is_called(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    intel_object = result["intel_object"]
    assert intel_object.object_type is IntelObjectType.DOMAIN_NAME
    assert intel_object.canonical_value == "evil.example"
    assert result["investigation"].original_input == "evil[.]example"


async def test_adapter_returns_normalized_evidence(stack: Stack) -> None:
    envelope = (await run_lookup(stack, USER_A, "evil[.]example"))["envelope"]
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert envelope.evidence
    classes = {evidence.evidence_class for evidence in envelope.evidence}
    assert EvidenceClass.AGGREGATED_REPUTATION in classes


async def test_provenance_is_retained_through_every_layer(stack: Stack) -> None:
    envelope = (await run_lookup(stack, USER_A, "evil[.]example"))["envelope"]
    for evidence in envelope.evidence:
        assert evidence.transport_provider == "fake_aggregator"
        assert evidence.origin_provider
        assert evidence.source_family
        assert evidence.lineage_group_id

    relayed = [evidence for evidence in envelope.evidence if evidence.is_relayed]
    assert len(relayed) == 1
    assert relayed[0].origin_provider == "fake_scanner"
    assert relayed[0].lineage_group_id == "scanner_noise:fake_scanner"


async def test_relayed_evidence_shares_lineage_with_the_origin_provider(
    stack: Stack,
) -> None:
    """Two providers reporting one upstream fact must not look independent."""
    aggregated = (await run_lookup(stack, USER_A, "evil[.]example"))["envelope"]
    relayed = next(e for e in aggregated.evidence if e.is_relayed)

    scanner = FakeScannerProvider()
    direct_request = ProviderRequest(
        investigation_id="inv-direct",
        intel_object=normalize_observable("198.51.100.7").intel_object,
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
    )
    direct = await scanner.lookup(direct_request, None)

    assert relayed.shares_lineage_with(direct.evidence[0])


async def test_relationship_references_evidence_from_the_same_lookup(
    stack: Stack,
) -> None:
    envelope = (await run_lookup(stack, USER_A, "evil[.]example"))["envelope"]
    assert envelope.relationships
    evidence_ids = {evidence.id for evidence in envelope.evidence}
    object_ids = {obj.id for obj in envelope.objects}
    for relationship in envelope.relationships:
        assert set(relationship.evidence_refs) <= evidence_ids
        assert relationship.target_object_id in object_ids


async def test_result_records_as_a_task_3_provider_run(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    run = result["envelope"].to_provider_run(
        investigation_id=result["investigation"].id,
        capability=ProviderCapability.REPUTATION,
    )
    assert run.investigation_id == result["investigation"].id
    assert run.provider == "fake_aggregator"
    assert run.status is ProviderRunStatus.SUCCESS
    assert run.error_code is None
    assert run.raw_reference_id == result["envelope"].raw_reference.id


async def test_coverage_can_be_reported_from_the_registry(stack: Stack) -> None:
    """A capability nobody covers is reported as a gap, not silence."""
    available = stack.registry.capabilities_for_object_type(IntelObjectType.DOMAIN_NAME)
    assert ProviderCapability.CERTIFICATE_CONTEXT not in available
    item = CoverageItem(
        capability=ProviderCapability.CERTIFICATE_CONTEXT,
        relevance=CoverageRelevance.RELEVANT,
        status=CoverageStatus.NOT_COVERED,
        reason="no registered provider offers certificate context for domains",
    )
    assert item.is_gap is True


# --------------------------------------------------------------------------- #
# Security properties across layers
# --------------------------------------------------------------------------- #


async def test_no_secret_appears_in_the_serialized_result(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    payload = json.dumps(result["envelope"].model_dump(mode="json"))
    assert KEY_A not in payload
    assert KEY_B not in payload


async def test_no_secret_appears_in_the_serialized_request(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    payload = json.dumps(result["request"].model_dump(mode="json"))
    assert KEY_A not in payload


async def test_no_secret_appears_in_the_whole_serialized_trail(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    run = result["envelope"].to_provider_run(
        investigation_id=result["investigation"].id,
        capability=ProviderCapability.REPUTATION,
    )
    trail = json.dumps(
        {
            "investigation": result["investigation"].model_dump(mode="json"),
            "request": result["request"].model_dump(mode="json"),
            "envelope": result["envelope"].model_dump(mode="json"),
            "run": run.model_dump(mode="json"),
        }
    )
    assert KEY_A not in trail
    lowered = trail.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_one_users_credential_is_never_used_for_another(stack: Stack) -> None:
    a = await run_lookup(stack, USER_A, "evil[.]example")
    b = await run_lookup(stack, USER_B, "evil[.]example")
    assert a["credential"].reveal() != b["credential"].reveal()


async def test_a_user_without_a_credential_cannot_borrow_one(stack: Stack) -> None:
    with pytest.raises(CredentialNotConfigured):
        await run_lookup(stack, "analyst-c", "evil[.]example")


async def test_a_credential_free_provider_needs_no_user_credential() -> None:
    """Coverage should not collapse just because a user has configured no keys."""
    registry = ProviderRegistry(all_fake_adapters())
    matches = registry.find_compatible(
        IntelObjectType.DOMAIN_NAME,
        ProviderCapability.FALSE_POSITIVE_CONTEXT,
        requires_credentials=False,
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["fake_warninglist"]
    envelope = await FakeWarningListProvider().lookup(
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=normalize_observable("evil.example").intel_object,
            requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        ),
        None,
    )
    assert envelope.status is ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# The pipeline stops at evidence
# --------------------------------------------------------------------------- #


async def test_no_verdict_is_produced_anywhere(stack: Stack) -> None:
    """There is no verdict engine yet, and nothing may pretend otherwise."""
    result = await run_lookup(stack, USER_A, "evil[.]example")
    envelope_fields = set(type(result["envelope"]).model_fields)
    assert envelope_fields.isdisjoint({"verdict", "risk_score", "confidence"})
    assert not hasattr(result["adapter"], "assess")
    assert not hasattr(stack.registry, "assess")


async def test_the_investigation_remains_passive_end_to_end(stack: Stack) -> None:
    result = await run_lookup(stack, USER_A, "evil[.]example")
    assert result["investigation"].activity_mode is ActivityMode.PASSIVE
    assert result["request"].activity_mode is ActivityMode.PASSIVE
    assert result["adapter"].descriptor.supports_active is False


async def test_batch_lookup_works_for_a_provider_that_declares_it(
    stack: Stack,
) -> None:
    adapter = FakeAggregatorProvider()
    credential = await stack.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    requests = [
        ProviderRequest(
            investigation_id="inv-1",
            intel_object=normalize_observable(value).intel_object,
            requested_capabilities=frozenset({ProviderCapability.REPUTATION}),
        )
        for value in ("evil.example", "worse.example")
    ]
    results = await adapter.batch_lookup(requests, credential)
    assert len(results) == 2
    assert all(envelope.status is ProviderRunStatus.SUCCESS for envelope in results)
