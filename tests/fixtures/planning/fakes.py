"""Fake providers and outcomes for planner tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

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
    ProviderRunStatus,
)
from ti_recon.execution.models import ProviderExecutionOutcome
from ti_recon.models.evidence import Evidence, RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning.models import (
    CallCostClass,
    ProviderLocality,
    ProviderPlanningProfile,
)
from ti_recon.providers.adapter import (
    CapabilityDiscovery,
    CredentialValidation,
    ProviderAdapter,
    ProviderHealthReport,
)
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope

__all__ = [
    "EXPENSIVE_BEHAVIOR",
    "FAMILY_A",
    "FAMILY_B",
    "LOCAL_CONTEXT",
    "FakePlanningAdapter",
    "FakeProviderSpec",
    "build_registry",
    "fake_outcome",
    "file_object",
    "profile_for",
    "specs_for",
]

#: Two datasets in one family, two independent families, a local provider and an
#: expensive specialist — the minimum needed to exercise every novelty class.
FAMILY_A = "family_a"
FAMILY_B = "family_b"
LOCAL_CONTEXT = "local_context_family"
EXPENSIVE_BEHAVIOR = "behavior_family"

_ALL_TYPES = frozenset(
    {
        IntelObjectType.FILE,
        IntelObjectType.URL,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
    }
)


@dataclass(frozen=True)
class FakeProviderSpec:
    """Everything a fake provider needs to exist."""

    provider_id: str
    source_family: str
    capabilities: frozenset[ProviderCapability]
    locality: ProviderLocality = ProviderLocality.REMOTE
    cost_class: CallCostClass = CallCostClass.LOW
    object_types: frozenset[IntelObjectType] = field(default_factory=lambda: _ALL_TYPES)
    priority: int = 0
    minimum_depth: InvestigationDepth = InvestigationDepth.QUICK
    elevated: frozenset[ProviderCapability] = frozenset()
    auto_enrichment_allowed: bool = True
    supports_active: bool = False
    planning_capabilities: frozenset[ProviderCapability] | None = None


class FakePlanningAdapter(ProviderAdapter):
    """A registry-satisfying adapter that never performs I/O.

    The planner only reads its descriptor, and the orchestrator hands it to a
    fake executor, so ``lookup`` exists to satisfy the contract and records that
    it was reached.
    """

    def __init__(self, spec: FakeProviderSpec) -> None:
        self._spec = spec
        self.calls: list[tuple[str, frozenset[ProviderCapability]]] = []
        self._descriptor = ProviderDescriptor(
            provider_id=spec.provider_id,
            display_name=spec.provider_id,
            adapter_version="1.0.0",
            api_version="v1",
            source_family=spec.source_family,
            supported_object_types=spec.object_types,
            capabilities=spec.capabilities,
            supports_passive=True,
            supports_active=spec.supports_active,
            requires_credentials=spec.locality is ProviderLocality.REMOTE,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def spec(self) -> FakeProviderSpec:
        return self._spec

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:  # pragma: no cover - not exercised
        from ti_recon.credentials.enums import CredentialStatus

        return CredentialValidation(
            provider_id=self._spec.provider_id, status=CredentialStatus.ACTIVE
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:  # pragma: no cover - not exercised
        return CapabilityDiscovery(
            provider_id=self._spec.provider_id, capabilities=self._spec.capabilities
        )

    async def health(
        self, credential: CredentialMaterial | None = None
    ) -> ProviderHealthReport:  # pragma: no cover - not exercised
        return ProviderHealthReport(
            provider_id=self._spec.provider_id, health=ProviderHealth.AVAILABLE
        )

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:  # pragma: no cover - the fake executor answers
        self.calls.append((request.intel_object.canonical_value, request.requested_capabilities))
        return ProviderResultEnvelope(
            provider=self._spec.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.NO_DATA,
            adapter_version="1.0.0",
            api_version="v1",
        )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:  # pragma: no cover - not exercised
        return NormalizedPayload()

    def classify_error(
        self, error: Exception
    ) -> ProviderErrorCategory:  # pragma: no cover - not exercised
        return ProviderErrorCategory.UNKNOWN_ERROR


def profile_for(spec: FakeProviderSpec) -> ProviderPlanningProfile:
    return ProviderPlanningProfile(
        provider_id=spec.provider_id,
        source_family=spec.source_family,
        locality=spec.locality,
        cost_class=spec.cost_class,
        planning_capabilities=(
            spec.capabilities if spec.planning_capabilities is None else spec.planning_capabilities
        ),
        elevated_cost_capabilities=spec.elevated,
        minimum_depth=spec.minimum_depth,
        priority=spec.priority,
        auto_enrichment_allowed=spec.auto_enrichment_allowed,
    )


def specs_for() -> tuple[FakeProviderSpec, ...]:
    """The standard cast used by most planner tests."""
    return (
        FakeProviderSpec(
            provider_id="local_context",
            source_family=LOCAL_CONTEXT,
            capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            locality=ProviderLocality.LOCAL,
            cost_class=CallCostClass.ZERO,
            priority=90,
        ),
        FakeProviderSpec(
            provider_id="reputation_a",
            source_family=FAMILY_A,
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.THREAT_ASSOCIATIONS}
            ),
            priority=50,
        ),
        FakeProviderSpec(
            provider_id="reputation_a_second",
            source_family=FAMILY_A,
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.MALWARE_INTELLIGENCE}
            ),
            priority=40,
        ),
        FakeProviderSpec(
            provider_id="reputation_b",
            source_family=FAMILY_B,
            capabilities=frozenset({ProviderCapability.REPUTATION}),
            cost_class=CallCostClass.MEDIUM,
            priority=60,
        ),
        FakeProviderSpec(
            provider_id="expensive_behavior",
            source_family=EXPENSIVE_BEHAVIOR,
            capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            cost_class=CallCostClass.HIGH,
            object_types=frozenset({IntelObjectType.FILE}),
            minimum_depth=InvestigationDepth.STANDARD,
        ),
    )


def build_registry(
    specs: tuple[FakeProviderSpec, ...] | None = None,
) -> tuple[ProviderRegistry, Any]:
    """``(adapter registry, planning registry)`` for ``specs``."""
    from ti_recon.planning.policy import ProviderPlanningRegistry

    chosen = specs_for() if specs is None else specs
    adapters = [FakePlanningAdapter(spec) for spec in chosen]
    return (
        ProviderRegistry(adapters),
        ProviderPlanningRegistry(tuple(profile_for(spec) for spec in chosen)),
    )


def file_object(digest: str = "a" * 64, **properties: object) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {"SHA-256": digest}, **properties},
    )


def fake_outcome(
    provider_id: str,
    *,
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
    source_family: str | None = None,
    effect: EvidenceEffect | None = None,
    called_provider: bool = True,
    cache_hit: bool = False,
    error_category: ProviderErrorCategory | None = None,
    evidence_count: int = 1,
) -> ProviderExecutionOutcome:
    """A provider execution outcome, without executing anything.

    ``called_provider`` is derived from ``attempts`` in the real model, so it is
    set that way here too — a fake that diverged on exactly the field the budget
    is charged on would prove nothing.
    """
    evidence: tuple[Evidence, ...] = ()
    if effect is not None:
        cls = (
            EvidenceClass.CURATED_THREAT_ASSERTION
            if effect is EvidenceEffect.SUPPORTS_MALICIOUS
            else EvidenceClass.CONTEXT
        )
        family = source_family or provider_id
        evidence = tuple(
            Evidence(
                investigation_id="inv-1",
                subject_object_id="object-1",
                evidence_class=cls,
                claim_type=f"{provider_id}_claim_{index}",
                effect=effect,
                transport_provider=provider_id,
                origin_provider=provider_id,
                source_family=family,
            )
            for index in range(evidence_count)
        )
    result = ProviderResultEnvelope(
        provider=provider_id,
        operation=ProviderOperation.LOOKUP,
        status=status,
        adapter_version="1.0.0",
        api_version="v1",
        error_category=error_category,
        evidence=evidence,
    )
    now = datetime.now(UTC)
    return ProviderExecutionOutcome(
        provider_id=provider_id,
        operation=ProviderOperation.LOOKUP,
        status=status,
        scope_identity="scope-1",
        request_id="req-1",
        attempts=1 if called_provider else 0,
        cache_hit=cache_hit,
        error_category=error_category,
        result=result,
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
    )
