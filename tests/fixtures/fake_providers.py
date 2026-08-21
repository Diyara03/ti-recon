"""Fake provider adapters for contract tests.

These are *not* provider integrations. They perform no network I/O and contain
no vendor API details — no hosts, endpoints, payload schemas or header names.
They exist to exercise the framework: capability matching, envelope shape,
lineage handling, and the behaviour of optional operations.

Each fake is shaped after a *category* of real provider (an aggregator, a
scanner, a warning list) so the registry can be tested on realistic capability
overlaps without naming a vendor.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    InformationCredibilityGrade,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
    SourceReliabilityGrade,
)
from ti_recon.models.evidence import Evidence, RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers import (
    CapabilityDiscovery,
    CredentialValidation,
    NormalizedPayload,
    ProviderAdapter,
    ProviderDescriptor,
    ProviderError,
    ProviderHealth,
    ProviderHealthReport,
    ProviderRequest,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)

__all__ = [
    "FakeAggregatorProvider",
    "FakeMinimalProvider",
    "FakeScannerProvider",
    "FakeWarningListProvider",
    "all_fake_adapters",
]


class _FakeAdapterBase(ProviderAdapter):
    """Shared behaviour: no I/O, deterministic answers."""

    _descriptor: ProviderDescriptor

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        if self._descriptor.requires_credentials and credential is None:
            return CredentialValidation(
                provider_id=self._descriptor.provider_id,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        return CredentialValidation(
            provider_id=self._descriptor.provider_id,
            status=CredentialStatus.ACTIVE,
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        return CapabilityDiscovery(
            provider_id=self._descriptor.provider_id,
            capabilities=self._descriptor.capabilities,
            plan_hint="fake-plan",
        )

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        if isinstance(error, ValueError):
            return ProviderErrorCategory.SCHEMA_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    def parse_rate_limits(self, headers: Mapping[str, str]) -> RateLimitSnapshot | None:
        remaining = headers.get("x-fake-ratelimit-remaining")
        if remaining is None:
            return None
        return RateLimitSnapshot(
            operation=ProviderOperation.LOOKUP.value,
            limit=int(headers.get("x-fake-ratelimit-limit", "0")),
            remaining=int(remaining),
            scope="minute",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        return ProviderHealthReport(
            provider_id=self._descriptor.provider_id,
            health=ProviderHealth.AVAILABLE,
        )

    def _raw_reference(self, request: ProviderRequest) -> RawEvidenceReference:
        return RawEvidenceReference(
            investigation_id=request.investigation_id,
            provider=self._descriptor.provider_id,
            operation=request.operation,
            storage_key=(
                f"raw/{self._descriptor.provider_id}/{request.operation.value}/"
                f"{request.intel_object.id}"
            ),
        )


class FakeScannerProvider(_FakeAdapterBase):
    """Shaped like an internet-scanner/background-noise provider.

    Reports on IP addresses only, and its claims are context rather than
    verdicts — which is the interesting case for evidence weighting.
    """

    _descriptor = ProviderDescriptor(
        provider_id="fake_scanner",
        display_name="Fake Scanner",
        adapter_version="0.1.0",
        api_version="v1",
        source_family="scanner_noise",
        supported_object_types=frozenset({IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}),
        capabilities=frozenset(
            {
                ProviderCapability.SCANNER_CONTEXT,
                ProviderCapability.FALSE_POSITIVE_CONTEXT,
                ProviderCapability.NETWORK_OWNERSHIP,
            }
        ),
    )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        classification = str(payload.get("classification", "unknown"))
        evidence = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="scanner.classification",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            provider_confidence=80.0,
            source_reliability=SourceReliabilityGrade.B,
            information_credibility=InformationCredibilityGrade.PROBABLY_TRUE,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            observed_at=T0 - timedelta(hours=1),
            attributes={"classification": classification},
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        return NormalizedPayload(evidence=(evidence,))

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        self.assert_supports(request.intel_object.object_type, ProviderCapability.SCANNER_CONTEXT)
        raw_reference = self._raw_reference(request)
        payload = self.normalize(request, {"classification": "benign"}, raw_reference=raw_reference)
        return ProviderResultEnvelope.from_payload(
            provider=self._descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.SUCCESS,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=payload,
            raw_reference=raw_reference,
        )


class FakeAggregatorProvider(_FakeAdapterBase):
    """Shaped like a multi-vendor reputation aggregator.

    Covers every submittable object type, supports batch lookup, and — the
    point of including it — relays third-party data, so lineage handling is
    exercised end to end.
    """

    _descriptor = ProviderDescriptor(
        provider_id="fake_aggregator",
        display_name="Fake Aggregator",
        adapter_version="0.2.0",
        api_version="v3",
        source_family="aggregator",
        supported_object_types=frozenset(
            {
                IntelObjectType.IPV4_ADDR,
                IntelObjectType.IPV6_ADDR,
                IntelObjectType.DOMAIN_NAME,
                IntelObjectType.URL,
                IntelObjectType.FILE,
            }
        ),
        capabilities=frozenset(
            {
                ProviderCapability.REPUTATION,
                ProviderCapability.MALWARE_INTELLIGENCE,
                ProviderCapability.RELATIONSHIPS,
                ProviderCapability.BATCH_LOOKUP,
            }
        ),
        supports_batch=True,
    )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        raw_id = raw_reference.id if raw_reference else None
        reputation = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
            claim_type="multi-vendor.detection-count",
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            provider_confidence=55.0,
            source_reliability=SourceReliabilityGrade.B,
            information_credibility=InformationCredibilityGrade.POSSIBLY_TRUE,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            first_seen=T0 - timedelta(days=20),
            last_seen=T0 - timedelta(days=1),
            attributes={
                "malicious_vendors": int(str(payload.get("malicious", 5))),
                "total_vendors": 90,
            },
            raw_reference_id=raw_id,
        )
        # Relayed: this provider resells another vendor's scanner data. Recording
        # the true origin is what stops it counting as independent confirmation.
        relayed = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="scanner.classification",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self._descriptor.provider_id,
            origin_provider="fake_scanner",
            source_family="scanner_noise",
            match_scope=MatchScope.EXACT_OBSERVABLE,
            attributes={"classification": "benign"},
            raw_reference_id=raw_id,
        )
        resolved_ip = IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.IPV4_ADDR,
            canonical_value="198.51.100.7",
            display_value="198.51.100.7",
        )
        resolution = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.DIRECT_OBSERVATION,
            claim_type="dns.a-record",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            attributes={"resolved_ip": resolved_ip.canonical_value},
            raw_reference_id=raw_id,
        )
        relationship = Relationship(
            source_object_id=request.intel_object.id,
            relationship_type=RelationshipType.RESOLVES_TO,
            target_object_id=resolved_ip.id,
            confidence=85.0,
            evidence_refs=(resolution.id,),
        )
        return NormalizedPayload(
            evidence=(reputation, relayed, resolution),
            objects=(resolved_ip,),
            relationships=(relationship,),
            warnings=("plan limits historical depth",),
        )

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        self.assert_supports(request.intel_object.object_type, ProviderCapability.REPUTATION)
        raw_reference = self._raw_reference(request)
        payload = self.normalize(request, {"malicious": 7}, raw_reference=raw_reference)
        return ProviderResultEnvelope.from_payload(
            provider=self._descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.SUCCESS,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=payload,
            raw_reference=raw_reference,
            rate_limit=RateLimitSnapshot(
                operation=ProviderOperation.LOOKUP.value,
                limit=500,
                remaining=499,
                scope="minute",
            ),
        )

    async def batch_lookup(
        self,
        requests: Sequence[ProviderRequest],
        credential: CredentialMaterial | None,
    ) -> Sequence[ProviderResultEnvelope]:
        return [await self.lookup(request, credential) for request in requests]


class FakeWarningListProvider(_FakeAdapterBase):
    """Shaped like a curated known-good list: no credential required."""

    _descriptor = ProviderDescriptor(
        provider_id="fake_warninglist",
        display_name="Fake Warning List",
        adapter_version="0.1.0",
        source_family="warning_list",
        supported_object_types=frozenset({IntelObjectType.IPV4_ADDR, IntelObjectType.DOMAIN_NAME}),
        capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        requires_credentials=False,
    )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        if not payload.get("listed"):
            return NormalizedPayload()
        evidence = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="warninglist.known-good-infrastructure",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            match_scope=MatchScope.PARENT_DOMAIN,
            attributes={"list": str(payload.get("list", "unknown"))},
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        return NormalizedPayload(evidence=(evidence,))

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        payload = self.normalize(request, {"listed": False})
        return ProviderResultEnvelope.from_payload(
            provider=self._descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.NO_DATA,
            adapter_version=self._descriptor.adapter_version,
            payload=payload,
        )


class FakeMinimalProvider(_FakeAdapterBase):
    """The smallest legal adapter: one capability, one object type, no extras.

    Used to check that the optional parts of the contract really are optional.
    """

    _descriptor = ProviderDescriptor(
        provider_id="fake_minimal",
        display_name="Fake Minimal",
        adapter_version="0.0.1",
        source_family="minimal",
        supported_object_types=frozenset({IntelObjectType.FILE}),
        capabilities=frozenset({ProviderCapability.MALWARE_INTELLIGENCE}),
    )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        return NormalizedPayload()

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=self._descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.NO_DATA,
            adapter_version=self._descriptor.adapter_version,
            payload=self.normalize(request, {}),
        )


def all_fake_adapters() -> list[ProviderAdapter]:
    """Every fake adapter, in a deterministic order."""
    return [
        FakeAggregatorProvider(),
        FakeMinimalProvider(),
        FakeScannerProvider(),
        FakeWarningListProvider(),
    ]
