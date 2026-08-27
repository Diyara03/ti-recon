"""A whole investigation stack, with providers that return related objects.

Everything here is fake and local to the process. The point is to exercise the
real Task 13 planner, the real Task 6 executor and the real correlation engine
without a single external request — the repository's non-loopback guard is active
throughout, so a test that accidentally reached the network would fail loudly.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

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
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization import normalize_observable
from ti_recon.planning import AdaptiveEnrichmentOrchestrator, AdaptiveEnrichmentPlanner
from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope

USER = "analyst-a"

#: ``canonical value of the subject -> [(relationship, related value, raw name)]``
RelationScript = Mapping[str, Sequence[tuple[RelationshipType, str, str]]]


class ScriptedAdapter(FakePlanningAdapter):
    """A fake provider that returns whatever a script says it saw.

    Lets a test state "this provider says the sample contacted these three things"
    and then assert what correlation and pivoting did with it, without inventing a
    fixture format.
    """

    def __init__(
        self,
        spec: FakeProviderSpec,
        script: RelationScript,
        *,
        evidence_class: EvidenceClass = EvidenceClass.DIRECT_OBSERVATION,
    ) -> None:
        super().__init__(spec)
        self._script = script
        self._evidence_class = evidence_class
        self.subjects: list[str] = []

    async def lookup(
        self, request: ProviderRequest, credential: object | None = None
    ) -> ProviderResultEnvelope:
        del credential
        subject = request.intel_object
        self.subjects.append(subject.canonical_value)
        entries = self._script.get(subject.canonical_value, ())

        record = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=subject.id,
            evidence_class=self._evidence_class,
            claim_type=f"{self.descriptor.provider_id}_relationship",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self.descriptor.provider_id,
            origin_provider=self.descriptor.provider_id,
            source_family=self.descriptor.source_family,
            lineage_group_id=f"{self.descriptor.provider_id}:{subject.canonical_value}",
        )
        objects: list[IntelObject] = [subject]
        links: list[Relationship] = []
        for relationship, value, raw in entries:
            related = normalize_observable(value).intel_object
            objects.append(related)
            source, target = (
                (related, subject) if relationship is RelationshipType.HOSTS else (subject, related)
            )
            links.append(
                Relationship(
                    source_object_id=source.id,
                    relationship_type=relationship,
                    target_object_id=target.id,
                    evidence_refs=(record.id,),
                    raw_relationship_type=raw,
                )
            )
        return ProviderResultEnvelope(
            provider=self.descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.SUCCESS,
            adapter_version="1.0.0",
            api_version="v1",
            evidence=(record,),
            objects=tuple(objects),
            relationships=tuple(links),
        )


class Stack:
    """Correlation orchestrator over real Task 13 and Task 6 machinery."""

    def __init__(
        self,
        adapters: Sequence[ScriptedAdapter],
        *,
        limits: GraphLimits = DEFAULT_GRAPH_LIMITS,
    ) -> None:
        self.adapters = list(adapters)
        self.registry = ProviderRegistry(list(adapters))
        self.clock = ManualClock()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.execution_metrics = InMemoryExecutionMetricsSink()
        self.metrics = InMemoryCorrelationMetricsSink()
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
        self.orchestrator = CorrelatedInvestigationOrchestrator(
            enrichment=AdaptiveEnrichmentOrchestrator(
                planner=AdaptiveEnrichmentPlanner(
                    registry=self.registry,
                    profiles=ProviderPlanningRegistry(
                        tuple(profile_for(item.spec) for item in adapters)
                    ),
                ),
                executor=self.executor,
                registry=self.registry,
            ),
            limits=limits,
            metrics=self.metrics,
        )

    async def add_credentials(self, user_id: str = USER) -> None:
        """A key per remote fake, for one analyst.

        Per user on purpose: credential resolution is scoped by
        ``authenticated_user_id``, so a second analyst needs their own connection
        and cannot ride on the first one's.
        """
        for adapter in self.adapters:
            if adapter.descriptor.requires_credentials:
                await self.manager.create_connection(
                    user_id=user_id,
                    provider_id=adapter.descriptor.provider_id,
                    secret=f"{adapter.descriptor.provider_id}-key-SHOULD-NOT-LEAK",
                    auth_type=AuthType.API_KEY,
                    status=CredentialStatus.ACTIVE,
                )

    def context(self, user_id: str = USER) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id="req-1")

    def subjects_for(self, provider_id: str) -> list[str]:
        """Every observable this provider was actually asked about."""
        return next(
            item.subjects for item in self.adapters if item.descriptor.provider_id == provider_id
        )

    @property
    def all_subjects(self) -> list[str]:
        return [value for adapter in self.adapters for value in adapter.subjects]


class BareObjectAdapter(ScriptedAdapter):
    """Returns a related object with no relationship at all.

    Real providers do this: an object appears in a response with nothing saying
    how it connects to the subject. The graph should keep it and refuse to pivot
    on it.
    """

    def __init__(self, spec: FakeProviderSpec, value: str = "lonely.example") -> None:
        super().__init__(spec, {})
        self._value = value

    async def lookup(
        self, request: ProviderRequest, credential: object | None = None
    ) -> ProviderResultEnvelope:
        del credential
        self.subjects.append(request.intel_object.canonical_value)
        return ProviderResultEnvelope(
            provider=self.descriptor.provider_id,
            operation=request.operation,
            status=ProviderRunStatus.SUCCESS,
            adapter_version="1.0.0",
            api_version="v1",
            objects=(
                request.intel_object,
                normalize_observable(self._value).intel_object,
            ),
        )
