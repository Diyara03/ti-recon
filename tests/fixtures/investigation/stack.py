"""A whole investigation, end to end, with nothing external (Task 19).

Every layer here is real: the Task 13 planner, the Task 6 executor with its
cache, quota and cooldown stores, the Task 14 correlation engine, and all four
reasoning engines. Only the providers are fake, and they are scripted per
observable so a test can state "this source says this about that" and then assert
what the *real* chain concluded.

That matters more here than anywhere else in the suite. A Task 19 test that
stubbed the assessment would prove only that the workflow can copy a value
between two objects; the point is that a scripted provider answer travels through
qualification, explanation, fusion and readiness and comes out the other side as
a verdict nobody wrote down in advance.

The repository's non-loopback guard is active throughout, so a test that reached
the network would fail loudly rather than quietly succeed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from fixtures.planning.fakes import FakePlanningAdapter, FakeProviderSpec, profile_for
from ti_recon.correlation.metrics import InMemoryCorrelationMetricsSink
from ti_recon.correlation.models import DEFAULT_GRAPH_LIMITS, GraphLimits
from ti_recon.correlation.orchestrator import CorrelatedInvestigationOrchestrator
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryExecutionMetricsSink,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ManualClock,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RecordingSleeper,
)
from ti_recon.investigation import (
    InMemoryInvestigationMetricsSink,
    InvestigationOrchestrator,
    InvestigationRequest,
    ReasoningEngines,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization import normalize_observable
from ti_recon.planning import AdaptiveEnrichmentOrchestrator, AdaptiveEnrichmentPlanner
from ti_recon.planning.models import CallCostClass, ProviderLocality
from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import ClaimSemantic, claim_from
from ti_recon.reasoning.claims.translation import directional_evidence
from ti_recon.reasoning.engine import TemporalContextEngine
from ti_recon.reasoning.false_positive.engine import FalsePositiveReasoningEngine
from ti_recon.reasoning.fusion.engine import EvidenceFusionEngine
from ti_recon.reasoning.readiness.engine import AssessmentReadinessEngine

USER = "analyst-a"

#: A fake credential value chosen to be unmistakable if it ever leaks.
FAKE_SECRET_MARKER = "SHOULD-NOT-LEAK"


@dataclass(frozen=True)
class ScriptedEvidence:
    """What one provider says about one observable."""

    claim_type: str = "scripted_finding"
    effect: EvidenceEffect = EvidenceEffect.SUPPORTS_MALICIOUS
    evidence_class: EvidenceClass = EvidenceClass.CURATED_THREAT_ASSERTION
    semantic: ClaimSemantic = ClaimSemantic.MALICIOUS_REPUTATION
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE
    #: Relationships to publish alongside, as ``(type, value, raw name)``.
    relations: tuple[tuple[RelationshipType, str, str], ...] = ()
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS


def claim_evidence(
    semantic: ClaimSemantic,
    *,
    effect: EvidenceEffect = EvidenceEffect.SUPPORTS_MALICIOUS,
    evidence_class: EvidenceClass = EvidenceClass.CURATED_THREAT_ASSERTION,
    claim_type: str | None = None,
    relations: tuple[tuple[RelationshipType, str, str], ...] = (),
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
) -> ScriptedEvidence:
    """One scripted directional finding.

    The claim type defaults to the semantic's own name. Real providers use
    provider-prefixed types and a translator maps each to a proposition; the
    fixture needs the same one-to-one relationship, and a shared default would
    make two differently-scripted findings translate to whichever semantic was
    registered last.
    """
    return ScriptedEvidence(
        claim_type=claim_type or f"scripted_{semantic.value}",
        effect=effect,
        evidence_class=evidence_class,
        semantic=semantic,
        relations=relations,
        status=status,
    )


#: ``canonical value -> what this provider returns about it``.
EvidenceScript = Mapping[str, ScriptedEvidence]


class ScriptedProvider(FakePlanningAdapter):
    """A fake provider that answers from a script, and records what it was asked."""

    def __init__(
        self,
        spec_: FakeProviderSpec,
        script: EvidenceScript,
        *,
        gate: asyncio.Event | None = None,
    ) -> None:
        super().__init__(spec_)
        self._script = script
        #: When set, the provider waits on it before answering, so a test can
        #: cancel an investigation while a call is genuinely in flight.
        self._gate = gate
        self.requests: list[tuple[str, frozenset[ProviderCapability]]] = []

    async def lookup(
        self, request: ProviderRequest, credential: object | None = None
    ) -> ProviderResultEnvelope:
        del credential
        subject = request.intel_object
        self.requests.append((subject.canonical_value, request.requested_capabilities))
        if self._gate is not None:
            await self._gate.wait()
        scripted = self._script.get(subject.canonical_value)
        provider_id = self.descriptor.provider_id

        if scripted is None or scripted.status is not ProviderRunStatus.SUCCESS:
            return ProviderResultEnvelope(
                provider=provider_id,
                operation=request.operation,
                status=(ProviderRunStatus.NO_DATA if scripted is None else scripted.status),
                adapter_version="1.0.0",
                api_version="v1",
                objects=(subject,),
            )

        record = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=subject.id,
            evidence_class=scripted.evidence_class,
            claim_type=scripted.claim_type,
            effect=scripted.effect,
            transport_provider=provider_id,
            origin_provider=provider_id,
            source_family=self.descriptor.source_family,
            match_scope=scripted.match_scope,
        )
        objects: list[IntelObject] = [subject]
        links: list[Relationship] = []
        for relationship, value, raw in scripted.relations:
            related = normalize_observable(value).intel_object
            objects.append(related)
            links.append(
                Relationship(
                    source_object_id=subject.id,
                    relationship_type=relationship,
                    target_object_id=related.id,
                    evidence_refs=(record.id,),
                    raw_relationship_type=raw,
                )
            )
        return ProviderResultEnvelope(
            provider=provider_id,
            operation=request.operation,
            status=ProviderRunStatus.SUCCESS,
            adapter_version="1.0.0",
            api_version="v1",
            evidence=(record,),
            objects=tuple(objects),
            relationships=tuple(links),
        )


def _semantics_for(providers: Sequence[ScriptedProvider]) -> dict[str, Any]:
    """A claim translator per provider, honouring each script's semantic.

    Real translators live with real providers; a fake needs one too, or every
    scripted finding would arrive as ``UNCLASSIFIED_DIRECTIONAL`` and could never
    be decisive. This is the fixture's stand-in for
    ``providers/<name>/claim_semantics.py``.
    """
    semantics: dict[str, ClaimSemantic] = {}
    for provider in providers:
        for scripted in provider._script.values():
            semantics[scripted.claim_type] = scripted.semantic

    def translator(envelope: Any, context: Any) -> tuple[Any, ...]:
        return tuple(
            claim_from(
                record,
                policy_version=context.policy_version,
                semantic=semantics.get(record.claim_type, ClaimSemantic.UNCLASSIFIED_DIRECTIONAL),
                subject_key=context.subject_key_for(record.subject_object_id),
                source_partial=context.source_partial,
            )
            for record in directional_evidence(envelope)
        )

    return {provider.descriptor.provider_id: translator for provider in providers}


def spec(
    provider_id: str,
    *,
    family: str,
    capabilities: frozenset[ProviderCapability],
    locality: ProviderLocality = ProviderLocality.REMOTE,
    cost: CallCostClass = CallCostClass.LOW,
    priority: int = 50,
    minimum_depth: InvestigationDepth = InvestigationDepth.QUICK,
    invariant: bool = False,
    object_types: frozenset[IntelObjectType] | None = None,
) -> FakeProviderSpec:
    """One fake provider's planning identity."""
    return FakeProviderSpec(
        provider_id=provider_id,
        source_family=family,
        capabilities=capabilities,
        locality=locality,
        cost_class=cost,
        object_types=object_types
        or frozenset(
            {IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR}
        ),
        priority=priority,
        minimum_depth=minimum_depth,
        capability_invariant_response=invariant,
    )


def file_root(sha256: str) -> IntelObject:
    """A canonical file observable."""
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=sha256,
        display_value=sha256,
        properties={"hashes": {"SHA-256": sha256}},
    )


def observable_root(value: str) -> IntelObject:
    """A canonical observable parsed from a value."""
    return normalize_observable(value).intel_object


@dataclass
class InvestigationStack:
    """Real Tasks 6/13/14/15/16/17/18 with fake providers on top."""

    providers: list[ScriptedProvider] = field(default_factory=list)
    limits: GraphLimits = DEFAULT_GRAPH_LIMITS

    def __post_init__(self) -> None:
        self.registry = ProviderRegistry(list(self.providers))
        self.clock = ManualClock()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.execution_metrics = InMemoryExecutionMetricsSink()
        self.metrics = InMemoryInvestigationMetricsSink()
        self.executor = ProviderExecutor(
            credential_resolver=CredentialResolver(self.secrets, self.connections),
            cache=InMemoryProviderCache(clock=self.clock),
            quota_store=InMemoryQuotaStore(clock=self.clock),
            cooldown_store=InMemoryCooldownStore(clock=self.clock),
            limiter=ConcurrencyLimiter(max_concurrency=4),
            policies=ProviderPolicyRegistry(policies=[]),
            metrics=self.execution_metrics,
            clock=self.clock,
            sleeper=RecordingSleeper(self.clock),
            jitter=FixedJitter(0.0),
        )
        self.correlation = CorrelatedInvestigationOrchestrator(
            enrichment=AdaptiveEnrichmentOrchestrator(
                planner=AdaptiveEnrichmentPlanner(
                    registry=self.registry,
                    profiles=ProviderPlanningRegistry(
                        tuple(profile_for(item.spec) for item in self.providers)
                    ),
                ),
                executor=self.executor,
                registry=self.registry,
            ),
            limits=self.limits,
            metrics=InMemoryCorrelationMetricsSink(),
        )
        self.orchestrator = InvestigationOrchestrator(
            correlation=self.correlation,
            engines=ReasoningEngines(
                temporal=TemporalContextEngine(),
                false_positive=FalsePositiveReasoningEngine(),
                fusion=EvidenceFusionEngine(translators=_semantics_for(self.providers)),
                readiness=AssessmentReadinessEngine(),
            ),
            clock=self.clock,
            metrics=self.metrics,
        )

    async def add_credentials(self, user_id: str = USER) -> None:
        """One key per remote fake, for one analyst.

        Per user on purpose: credential resolution is scoped by
        ``authenticated_user_id``, so a second analyst needs their own connection
        and cannot ride on the first one's.
        """
        for provider in self.providers:
            if provider.descriptor.requires_credentials:
                await self.manager.create_connection(
                    user_id=user_id,
                    provider_id=provider.descriptor.provider_id,
                    secret=f"{provider.descriptor.provider_id}-key-{FAKE_SECRET_MARKER}",
                    auth_type=AuthType.API_KEY,
                    status=CredentialStatus.ACTIVE,
                )

    def context(self, user_id: str = USER) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id="req-1")

    async def investigate(
        self, request: InvestigationRequest, *, user_id: str = USER, **kwargs: Any
    ) -> Any:
        """Run one full investigation for one analyst."""
        return await self.orchestrator.investigate(request, self.context(user_id), **kwargs)

    def requests_for(self, provider_id: str) -> list[tuple[str, frozenset[Any]]]:
        """Everything one provider was actually asked."""
        return next(
            item.requests for item in self.providers if item.descriptor.provider_id == provider_id
        )
