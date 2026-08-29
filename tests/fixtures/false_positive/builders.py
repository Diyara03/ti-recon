"""Building Task 16 scenarios without providers.

Task 16 consumes Task 15's *generic* vocabulary, so its tests are written in that
vocabulary too: synthetic provider ids like ``alpha`` and ``beta``, evidence
described by effect, class and scope, and context signals built directly. That is
not a shortcut around realism -- it is the point. A test that reached for URLhaus
to express "an exact malicious URL" would be asserting that Task 16 works for
URLhaus, when the invariant is that it works for any provider that produces those
generic semantics, including ones that do not exist yet.

Two end-to-end tests elsewhere drive the real adapters and the real Task 15 engine
to prove the generic vocabulary is the one the shipped providers actually emit.

Nothing here reaches a network, a clock or a credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ti_recon.correlation.engine import CorrelationEngine
from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization import normalize_observable
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    SignalOrigin,
    SourceLifecycleState,
    TemporalFact,
    TemporalFactKind,
    TemporalQualification,
    dataset_subject,
    observable_subject,
)
from ti_recon.reasoning.models import EvidenceRef as QualificationEvidenceRef
from ti_recon.reasoning.results import QualificationCoverage, TemporalContextResult

#: The fixed instant every Task 15 result in these tests was evaluated at.
#: Task 16 carries it through and never reads a clock of its own.
AS_OF = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)

#: Versions the synthetic qualification claims to have been produced under.
QUALIFICATION_POLICY_VERSION = "1.0.0"
WARNINGLIST_MAP_VERSION = "1.0.0"


def observable(value: str) -> IntelObject:
    return normalize_observable(value).intel_object


def file_object(**hashes: str) -> IntelObject:
    named = {
        {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[key]: value
        for key, value in hashes.items()
    }
    strongest = named.get("SHA-256") or named.get("SHA-1") or next(iter(named.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": named},
    )


def evidence(
    subject: IntelObject,
    *,
    claim_type: str = "alpha_finding",
    effect: EvidenceEffect = EvidenceEffect.SUPPORTS_MALICIOUS,
    evidence_class: EvidenceClass = EvidenceClass.CURATED_THREAT_ASSERTION,
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE,
    provider: str = "alpha",
    origin_provider: str | None = None,
    source_family: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Evidence:
    """One provider claim, described only in generic terms.

    ``origin_provider`` differing from ``provider`` is what makes a piece of
    evidence relayed, exactly as Task 3 defines it -- so a relayed-source test
    needs no vendor at all.
    """
    return Evidence(
        investigation_id="inv-1",
        subject_object_id=subject.id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=provider,
        origin_provider=origin_provider or provider,
        source_family=source_family or provider,
        match_scope=match_scope,
        attributes=attributes or {},
    )


def envelope(
    *records: Evidence,
    provider: str = "alpha",
    objects: tuple[IntelObject, ...] = (),
    relationships: tuple[Relationship, ...] = (),
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
) -> ProviderResultEnvelope:
    return ProviderResultEnvelope(
        provider=provider,
        operation=ProviderOperation.LOOKUP,
        status=status,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=records,
        objects=objects,
        relationships=relationships,
    )


def signal(
    subject: IntelObject,
    signal_type: ContextSignalType,
    *,
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE,
    host_component_only: bool = False,
    source_key: str = "a-list",
    provider: str = "context",
    origin: SignalOrigin = SignalOrigin.ENGINE_POLICY,
    for_evidence: Evidence | None = None,
    source_partial: bool = False,
    detail: dict[str, Any] | None = None,
) -> ContextSignal:
    """One Task 15 context signal, attached to an object's canonical key."""
    return ContextSignal(
        signal_type=signal_type,
        subject=observable_subject(subject.canonical_key),
        origin=origin,
        match_scope=match_scope,
        host_component_only=host_component_only,
        transport_provider=provider,
        origin_provider=provider,
        source_family=provider,
        source_key=source_key,
        source_partial=source_partial,
        evidence=(QualificationEvidenceRef.of(for_evidence) if for_evidence is not None else None),
        detail=detail or {},
    )


def inactive_qualification(
    subject: IntelObject,
    record: Evidence,
    *,
    instant: datetime | None = None,
    lifecycle: SourceLifecycleState = SourceLifecycleState.INACTIVE_BY_SOURCE,
) -> TemporalQualification:
    """A Task 15 temporal fact carrying a source-stated lifecycle.

    The shape URLhaus's ``offline`` produces, expressed generically: an instant,
    a lifecycle the source stated, and the malicious evidence it belongs to.
    """
    fact = TemporalFact(
        subject=observable_subject(subject.canonical_key),
        kind=TemporalFactKind.LAST_ONLINE_AT,
        instant=instant or datetime(2026, 6, 20, 8, 0, tzinfo=UTC),
        transport_provider=record.transport_provider,
        origin_provider=record.origin_provider,
        source_family=record.source_family,
        raw_field="last_online",
        lifecycle=lifecycle,
        evidence=QualificationEvidenceRef.of(record),
    )
    age = (AS_OF - fact.instant).total_seconds()
    return TemporalQualification(fact=fact, age_seconds=age, age_days=age / 86_400.0)


def stale_dataset_qualification(
    family: str, *, provider: str | None = None
) -> TemporalQualification:
    """A Task 15 dataset-scoped fact saying one family's local corpus is stale.

    Shaped exactly as Task 15 emits it: a ``CONTEXT_DATASET`` subject, a
    snapshot instant, and ``DATASET_STALE`` carrying the family that owns the
    dataset. Building the real fact rather than only bumping a coverage counter
    is what lets a test prove the caveat lands on the right findings.
    """
    owner = provider or family
    fact = TemporalFact(
        subject=dataset_subject(owner, "warninglists"),
        kind=TemporalFactKind.SNAPSHOT_GENERATED_AT,
        instant=datetime(2026, 1, 2, 3, 4, tzinfo=UTC),
        transport_provider=owner,
        origin_provider=owner,
        source_family=family,
        raw_field="snapshot_generated_at",
        lifecycle=SourceLifecycleState.DATASET_STALE,
    )
    age = (AS_OF - fact.instant).total_seconds()
    return TemporalQualification(fact=fact, age_seconds=age, age_days=age / 86_400.0)


def qualification(
    *,
    signals: tuple[ContextSignal, ...] = (),
    temporal: tuple[TemporalQualification, ...] = (),
    stale_context_datasets: int = 0,
) -> TemporalContextResult:
    """A Task 15 result, built directly.

    Task 16 consumes this type and nothing beneath it, so a test can state
    exactly what context existed without routing through nine providers to get
    there.
    """
    return TemporalContextResult(
        evaluated_at=AS_OF,
        engine_version="0.1.0",
        context_policy_version=QUALIFICATION_POLICY_VERSION,
        warninglist_map_version=WARNINGLIST_MAP_VERSION,
        context_signals=tuple(sorted(signals, key=lambda item: item.ref)),
        temporal_qualifications=tuple(sorted(temporal, key=lambda item: item.fact.ref)),
        coverage=QualificationCoverage(stale_context_datasets=stale_context_datasets),
    )


def contact_envelope(
    source: IntelObject,
    target: IntelObject,
    *,
    provider: str = "sandbox_alpha",
    relationship: RelationshipType = RelationshipType.CONTACTS,
    directly_observed: bool = True,
) -> ProviderResultEnvelope:
    """One provider result asserting a link it watched happen."""
    record = Evidence(
        investigation_id="inv-1",
        subject_object_id=source.id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="alpha_contact",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=provider,
        origin_provider=provider,
        source_family=provider,
    )
    return ProviderResultEnvelope(
        provider=provider,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=(record,),
        objects=(source, target),
        relationships=(
            Relationship(
                source_object_id=source.id,
                relationship_type=relationship,
                target_object_id=target.id,
                evidence_refs=(record.id,),
                raw_relationship_type="contacted_hosts",
                directly_observed=directly_observed,
            ),
        ),
    )


@dataclass
class Scenario:
    """One investigation's inputs, ready to hand to the Task 16 engine."""

    root: IntelObject
    envelopes: list[ProviderResultEnvelope] = field(default_factory=list)
    signals: list[ContextSignal] = field(default_factory=list)
    temporal: list[TemporalQualification] = field(default_factory=list)
    stale_context_datasets: int = 0
    graph: InvestigationGraph | None = None

    def with_envelope(self, item: ProviderResultEnvelope) -> Scenario:
        self.envelopes.append(item)
        return self

    def with_signal(self, item: ContextSignal) -> Scenario:
        self.signals.append(item)
        return self

    def with_temporal(self, item: TemporalQualification) -> Scenario:
        self.temporal.append(item)
        return self

    def with_graph(self) -> Scenario:
        """Ingest every envelope into a real Task 14 graph.

        The real engine rather than a hand-built graph, so relationship
        orientation, endpoint validation and assertion provenance are whatever
        Task 14 actually produces.
        """
        graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
        engine = CorrelationEngine(graph=graph)
        engine.add_root(self.root)
        for item in self.envelopes:
            engine.ingest(item)
        self.graph = graph
        return self

    def qualification(self) -> TemporalContextResult:
        return qualification(
            signals=tuple(self.signals),
            temporal=tuple(self.temporal),
            stale_context_datasets=self.stale_context_datasets,
        )


def scenario(root: IntelObject) -> Scenario:
    return Scenario(root=root)
