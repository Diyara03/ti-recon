"""Reusable provider adapter contract test suite.

Every provider adapter — including every real one added later — must pass this
suite. To apply it, subclass it in a ``Test*`` class and return the adapter:

    class TestMyProviderContract(ProviderAdapterContractTests):
        def make_adapter(self) -> ProviderAdapter:
            return MyProviderAdapter()

The suite drives the adapter entirely from its own descriptor, so it works for
any provider without being told which capabilities or object types to expect. It
performs no network I/O; an adapter whose ``lookup`` needs a transport should be
constructed with a mocked transport by ``make_adapter``.
"""

from __future__ import annotations

import inspect
import json
from typing import Final

import pytest

from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import (
    NormalizedPayload,
    ProviderAdapter,
    ProviderRequest,
    ProviderResultEnvelope,
    RateLimitSnapshot,
    UnsupportedProviderOperation,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

CONTRACT_SECRET: Final[str] = "contract-suite-secret-ZZZZ9999"

_SAMPLE_VALUES: Final[dict[IntelObjectType, str]] = {
    IntelObjectType.IPV4_ADDR: "198.51.100.7",
    IntelObjectType.IPV6_ADDR: "2001:db8::1",
    IntelObjectType.DOMAIN_NAME: "contract.example",
    IntelObjectType.URL: "https://contract.example/a",
    IntelObjectType.AUTONOMOUS_SYSTEM: "AS64500",
    IntelObjectType.X509_CERTIFICATE: "0" * 40,
    IntelObjectType.MALWARE: "ExampleRAT",
}

_SAMPLE_SHA256: Final[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def object_for_type(object_type: IntelObjectType) -> IntelObject:
    """Build a valid :class:`IntelObject` of the given type."""
    if object_type is IntelObjectType.FILE:
        return IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=object_type,
            canonical_value=_SAMPLE_SHA256,
            display_value=_SAMPLE_SHA256,
            properties={"hashes": {"SHA-256": _SAMPLE_SHA256}},
        )
    value = _SAMPLE_VALUES[object_type]
    object_class = (
        ObjectClass.THREAT if object_type is IntelObjectType.MALWARE else ObjectClass.OBSERVABLE
    )
    return IntelObject(
        object_class=object_class,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
    )


class ProviderAdapterContractTests:
    """Contract every provider adapter must satisfy."""

    def make_adapter(self) -> ProviderAdapter:
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Fixtures
    # ------------------------------------------------------------------ #

    @pytest.fixture
    def adapter(self) -> ProviderAdapter:
        return self.make_adapter()

    @pytest.fixture
    def credential(self, adapter: ProviderAdapter) -> CredentialMaterial | None:
        from pydantic import SecretStr

        descriptor = adapter.descriptor
        if not descriptor.requires_credentials:
            return None
        return CredentialMaterial(
            connection_id="contract-conn",
            user_id="contract-user",
            provider_id=descriptor.provider_id,
            credential_group=descriptor.credential_group,
            auth_type=AuthType.API_KEY,
            secret=SecretStr(CONTRACT_SECRET),
        )

    @staticmethod
    def _primary_object_type(adapter: ProviderAdapter) -> IntelObjectType:
        return sorted(adapter.descriptor.supported_object_types, key=lambda t: t.value)[0]

    @staticmethod
    def _primary_capability(adapter: ProviderAdapter) -> ProviderCapability:
        passive = adapter.descriptor.passive_capabilities - {ProviderCapability.BATCH_LOOKUP}
        pool = passive or adapter.descriptor.capabilities
        return sorted(pool, key=lambda c: c.value)[0]

    def _request(self, adapter: ProviderAdapter) -> ProviderRequest:
        return ProviderRequest(
            investigation_id="contract-inv",
            intel_object=object_for_type(self._primary_object_type(adapter)),
            operation=ProviderOperation.LOOKUP,
            requested_capabilities=frozenset({self._primary_capability(adapter)}),
            activity_mode=ActivityMode.PASSIVE,
        )

    # ------------------------------------------------------------------ #
    # Descriptor
    # ------------------------------------------------------------------ #

    def test_descriptor_is_valid(self, adapter: ProviderAdapter) -> None:
        descriptor = adapter.descriptor
        assert descriptor.provider_id
        assert descriptor.display_name
        assert descriptor.source_family
        assert descriptor.credential_group

    def test_descriptor_is_stable_across_accesses(self, adapter: ProviderAdapter) -> None:
        assert adapter.descriptor == adapter.descriptor

    def test_adapter_version_is_present(self, adapter: ProviderAdapter) -> None:
        assert adapter.descriptor.adapter_version.strip()

    def test_api_version_is_present(self, adapter: ProviderAdapter) -> None:
        """Either a real API version, or an explicit statement that there is none."""
        assert adapter.descriptor.api_version.strip()

    def test_supported_object_types_are_valid(self, adapter: ProviderAdapter) -> None:
        types = adapter.descriptor.supported_object_types
        assert types
        assert all(isinstance(object_type, IntelObjectType) for object_type in types)

    def test_capabilities_are_valid(self, adapter: ProviderAdapter) -> None:
        capabilities = adapter.descriptor.capabilities
        assert capabilities
        assert all(isinstance(capability, ProviderCapability) for capability in capabilities)

    def test_passive_provider_declares_a_passive_capability(self, adapter: ProviderAdapter) -> None:
        if adapter.descriptor.supports_passive:
            assert adapter.descriptor.passive_capabilities

    def test_supports_agrees_with_the_descriptor(self, adapter: ProviderAdapter) -> None:
        descriptor = adapter.descriptor
        for object_type in descriptor.supported_object_types:
            for capability in descriptor.capabilities:
                assert adapter.supports(object_type, capability)

    def test_unsupported_pair_is_reported_as_unsupported(self, adapter: ProviderAdapter) -> None:
        descriptor = adapter.descriptor
        unsupported_types = set(IntelObjectType) - set(descriptor.supported_object_types)
        unsupported_capabilities = set(ProviderCapability) - set(descriptor.capabilities)
        if unsupported_types:
            object_type = next(iter(unsupported_types))
            capability = next(iter(descriptor.capabilities))
            assert not adapter.supports(object_type, capability)
            with pytest.raises(UnsupportedProviderOperation):
                adapter.assert_supports(object_type, capability)
        if unsupported_capabilities:
            object_type = next(iter(descriptor.supported_object_types))
            capability = next(iter(unsupported_capabilities))
            assert not adapter.supports(object_type, capability)

    # ------------------------------------------------------------------ #
    # Async surface
    # ------------------------------------------------------------------ #

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
    def test_io_is_async(self, adapter: ProviderAdapter, method_name: str) -> None:
        assert inspect.iscoroutinefunction(getattr(adapter, method_name))

    @pytest.mark.parametrize("method_name", ["normalize", "classify_error"])
    def test_pure_helpers_are_synchronous(self, adapter: ProviderAdapter, method_name: str) -> None:
        assert not inspect.iscoroutinefunction(getattr(adapter, method_name))

    # ------------------------------------------------------------------ #
    # Unsupported operations fail cleanly
    # ------------------------------------------------------------------ #

    async def test_active_action_is_unsupported(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        """No adapter in this codebase may perform an active action."""
        with pytest.raises(UnsupportedProviderOperation) as excinfo:
            await adapter.active_action(self._request(adapter), credential)
        assert not isinstance(excinfo.value, NotImplementedError)

    async def test_undeclared_batch_lookup_fails_cleanly(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        if adapter.descriptor.supports_batch:
            pytest.skip("provider declares batch support")
        with pytest.raises(UnsupportedProviderOperation):
            await adapter.batch_lookup([self._request(adapter)], credential)

    async def test_undeclared_pivot_fails_cleanly(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        if ProviderCapability.RELATIONSHIPS in adapter.descriptor.capabilities:
            pytest.skip("provider declares relationship support")
        with pytest.raises(UnsupportedProviderOperation):
            await adapter.pivot(self._request(adapter), credential)

    # ------------------------------------------------------------------ #
    # Result envelope
    # ------------------------------------------------------------------ #

    async def test_lookup_returns_a_valid_envelope(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        assert isinstance(envelope, ProviderResultEnvelope)
        assert envelope.provider == adapter.descriptor.provider_id
        assert envelope.adapter_version == adapter.descriptor.adapter_version
        assert envelope.api_version == adapter.descriptor.api_version
        assert envelope.retrieved_at.tzinfo is not None

    async def test_envelope_evidence_is_valid_task_3_evidence(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        for evidence in envelope.evidence:
            assert evidence.investigation_id == "contract-inv"
            assert evidence.claim_type
            assert evidence.evidence_class
            assert evidence.effect
            assert evidence.retrieved_at.tzinfo is not None

    async def test_envelope_evidence_carries_provenance(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        for evidence in envelope.evidence:
            assert evidence.transport_provider == adapter.descriptor.provider_id
            assert evidence.origin_provider
            assert evidence.source_family
            assert evidence.lineage_group_id

    async def test_envelope_relationships_reference_evidence(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        evidence_ids = {evidence.id for evidence in envelope.evidence}
        for relationship in envelope.relationships:
            assert relationship.evidence_refs
            assert set(relationship.evidence_refs) <= evidence_ids

    async def test_envelope_states_no_verdict(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        dumped = envelope.model_dump()
        assert {"verdict", "risk_score", "confidence", "score"}.isdisjoint(dumped)

    async def test_envelope_converts_to_a_provider_run(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        run = envelope.to_provider_run(
            investigation_id="contract-inv",
            capability=self._primary_capability(adapter),
        )
        assert run.provider == adapter.descriptor.provider_id
        assert run.adapter_version == adapter.descriptor.adapter_version

    # ------------------------------------------------------------------ #
    # No secret serialization
    # ------------------------------------------------------------------ #

    async def test_envelope_serializes_without_the_secret(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        envelope = await adapter.lookup(self._request(adapter), credential)
        payload = json.dumps(envelope.model_dump(mode="json"))
        assert CONTRACT_SECRET not in payload
        lowered = payload.lower()
        for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
            assert token not in lowered

    async def test_validation_result_serializes_without_the_secret(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        result = await adapter.validate_credentials(credential)
        assert CONTRACT_SECRET not in result.model_dump_json()

    async def test_discovery_serializes_without_the_secret(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        discovery = await adapter.discover_capabilities(credential)
        assert CONTRACT_SECRET not in discovery.model_dump_json()

    async def test_health_report_serializes_without_the_secret(
        self, adapter: ProviderAdapter, credential: CredentialMaterial | None
    ) -> None:
        report = await adapter.health(credential)
        assert CONTRACT_SECRET not in report.model_dump_json()

    def test_repr_exposes_no_secret_surface(self, adapter: ProviderAdapter) -> None:
        assert SENSITIVE_KEY_PATTERN.search(repr(adapter)) is None

    # ------------------------------------------------------------------ #
    # Normalization and error classification
    # ------------------------------------------------------------------ #

    def test_normalize_accepts_an_empty_payload(self, adapter: ProviderAdapter) -> None:
        """A provider that returns nothing must not make the adapter throw."""
        payload = adapter.normalize(self._request(adapter), {})
        assert isinstance(payload, NormalizedPayload)

    def test_normalize_is_deterministic(self, adapter: ProviderAdapter) -> None:
        request = self._request(adapter)
        first = adapter.normalize(request, {})
        second = adapter.normalize(request, {})
        assert [evidence.claim_type for evidence in first.evidence] == [
            evidence.claim_type for evidence in second.evidence
        ]

    def test_classify_error_returns_a_normalized_category(self, adapter: ProviderAdapter) -> None:
        for error in (RuntimeError("boom"), TimeoutError(), ValueError("bad json")):
            assert isinstance(adapter.classify_error(error), ProviderErrorCategory)

    def test_parse_rate_limits_tolerates_absent_headers(self, adapter: ProviderAdapter) -> None:
        snapshot = adapter.parse_rate_limits({})
        assert snapshot is None or isinstance(snapshot, RateLimitSnapshot)
