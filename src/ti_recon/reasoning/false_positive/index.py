"""A read-only view over everything Task 16 reasons about.

Rules ask questions like "does this subject have directional malicious evidence
at exact scope?" and "does the target of this edge carry public-resolver
context?". Answering those by walking the inputs on every rule would be slow,
repetitive, and -- the part that actually matters -- would let one rule quietly
mutate what the next one sees.

So the index is built once, exposes only mappings, and copies nothing it does not
need. The provider results, the Task 15 qualification and the Task 14 graph are
all read and never written; a test asserts the graph is unchanged afterwards.

Subject identity comes from Task 15
-----------------------------------

Evidence carries ``subject_object_id``, a per-run UUID. Task 15's signals carry a
:class:`SubjectRef` keyed by canonical node key. Those have to line up or a rule
comparing "context on this subject" with "evidence about this subject" would
silently never match. Rather than re-derive the mapping, this module reuses
Task 15's own :class:`QualificationContext`, so both layers resolve identity the
same way by construction.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.models import GraphEdge
from ti_recon.enums import EvidenceEffect, MatchScope
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import QualificationContext
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    InterpretationCue,
    SourceLifecycleState,
    SubjectRef,
    TemporalQualification,
    edge_subject,
)
from ti_recon.reasoning.results import TemporalContextResult

__all__ = ["DIRECTIONAL_EFFECTS", "ReasoningIndex"]

#: Effects that make a piece of evidence a *claim* rather than context.
#:
#: Both directions, deliberately. Task 16 needs the benign side to notice that
#: evidence disagrees; a layer that only indexed the malicious side would report
#: an unresolved tension as a clean malicious picture.
DIRECTIONAL_EFFECTS: Final[frozenset[EvidenceEffect]] = frozenset(
    {EvidenceEffect.SUPPORTS_MALICIOUS, EvidenceEffect.SUPPORTS_BENIGN}
)


@dataclass(frozen=True)
class ReasoningIndex:
    """Immutable lookups over one investigation's evidence, context and graph."""

    #: The observable the investigation was about, as a canonical node key.
    #: Context found on a pivot is context about the pivot: a CDN range reached
    #: from a sample does not become "this sample has CDN context", and knowing
    #: which node is the root is what keeps that distinction available.
    root_key: str | None

    #: subject ref -> evidence about that subject, in a stable order.
    evidence_by_subject: Mapping[str, tuple[Evidence, ...]]
    #: evidence id -> the subject it concerns, for going the other way.
    subject_by_evidence: Mapping[str, SubjectRef]
    #: subject ref -> Task 15 context signals attached to it.
    signals_by_subject: Mapping[str, tuple[ContextSignal, ...]]
    #: subject ref -> Task 15 cues attached to it.
    cues_by_subject: Mapping[str, tuple[InterpretationCue, ...]]
    #: subject ref -> Task 15 temporal qualifications attached to it.
    temporal_by_subject: Mapping[str, tuple[TemporalQualification, ...]]
    #: node key -> edges whose *target* is that node. The direction rules care
    #: about: "what contacted this resolver", not "what did this resolver do".
    edges_into: Mapping[str, tuple[GraphEdge, ...]]
    #: Every graph edge, sorted, for rules that iterate rather than look up.
    edges: tuple[GraphEdge, ...]

    #: ``True`` when any provider reported the local context dataset as stale, so
    #: an explanation leaning on that dataset can say so rather than pretend its
    #: footing is as firm as a fresh one.
    stale_context_dataset: bool = False

    _all_evidence: tuple[Evidence, ...] = field(default=())

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #

    @property
    def all_evidence(self) -> tuple[Evidence, ...]:
        return self._all_evidence

    def directional(self, subject_ref: str, effect: EvidenceEffect) -> tuple[Evidence, ...]:
        """Evidence about one subject pointing one way."""
        return tuple(
            item for item in self.evidence_by_subject.get(subject_ref, ()) if item.effect is effect
        )

    def malicious_at_scope(
        self, subject_ref: str, scope: MatchScope | None = None
    ) -> tuple[Evidence, ...]:
        """Malicious-pointing evidence about one subject, optionally exact-scope.

        Scope matters more here than anywhere else in the package. "This host is
        associated with malware" and "this exact URL served malware" are
        different claims, and an explanation aimed at one must never be credited
        against the other.
        """
        found = self.directional(subject_ref, EvidenceEffect.SUPPORTS_MALICIOUS)
        if scope is None:
            return found
        return tuple(item for item in found if item.match_scope is scope)

    def signals(
        self, subject_ref: str, signal_type: ContextSignalType
    ) -> tuple[ContextSignal, ...]:
        return tuple(
            item
            for item in self.signals_by_subject.get(subject_ref, ())
            if item.signal_type is signal_type
        )

    def has_signal(self, subject_ref: str, signal_type: ContextSignalType) -> bool:
        return bool(self.signals(subject_ref, signal_type))

    def exact_scope_signals(
        self, subject_ref: str, signal_type: ContextSignalType
    ) -> tuple[ContextSignal, ...]:
        """Signals that speak for the observable itself rather than a piece of it.

        ``host_component_only`` is the authoritative flag -- Task 15 sets it when
        a match came from a URL's host -- and the scope check backs it up. A
        signal that is about the host cannot support an explanation about the
        artifact, and this is where that is enforced rather than remembered.
        """
        return tuple(
            item
            for item in self.signals(subject_ref, signal_type)
            if not item.host_component_only and item.match_scope is MatchScope.EXACT_OBSERVABLE
        )

    def host_scoped_signals(self, subject_ref: str) -> tuple[ContextSignal, ...]:
        """Signals attached to a subject that are really about its host."""
        return tuple(
            item
            for item in self.signals_by_subject.get(subject_ref, ())
            if item.host_component_only
        )

    def lifecycle_qualifications(
        self, subject_ref: str, state: SourceLifecycleState
    ) -> tuple[TemporalQualification, ...]:
        return tuple(
            item
            for item in self.temporal_by_subject.get(subject_ref, ())
            if item.fact.lifecycle is state
        )

    def subject_refs(self) -> tuple[str, ...]:
        """Every subject anything is known about, sorted.

        The union rather than just the ones with evidence: a rule about a graph
        edge whose target carries context needs that target even when no provider
        made a claim about it.
        """
        found = (
            set(self.evidence_by_subject)
            | set(self.signals_by_subject)
            | set(self.temporal_by_subject)
        )
        return tuple(sorted(found))

    # ------------------------------------------------------------------ #
    # Building
    # ------------------------------------------------------------------ #

    @classmethod
    def build(
        cls,
        *,
        qualification: TemporalContextResult,
        results: Sequence[ProviderResultEnvelope] = (),
        graph: InvestigationGraph | None = None,
        root: IntelObject | None = None,
    ) -> ReasoningIndex:
        """Index one investigation. Reads everything, mutates nothing."""
        objects: list[IntelObject] = []
        if graph is not None:
            objects.extend(node.intel_object for node in graph.nodes)
        for envelope in results:
            objects.extend(envelope.objects)
        context = QualificationContext.build(objects=tuple(objects), root=root)

        evidence_by_subject: dict[str, list[Evidence]] = defaultdict(list)
        subject_by_evidence: dict[str, SubjectRef] = {}
        all_evidence: list[Evidence] = []
        for envelope in sorted(results, key=lambda item: item.provider):
            for evidence in envelope.evidence:
                subject = context.subject_for(evidence.subject_object_id)
                evidence_by_subject[subject.ref].append(evidence)
                subject_by_evidence[evidence.id] = subject
                all_evidence.append(evidence)

        signals_by_subject: dict[str, list[ContextSignal]] = defaultdict(list)
        for signal in qualification.context_signals:
            signals_by_subject[signal.subject.ref].append(signal)

        cues_by_subject: dict[str, list[InterpretationCue]] = defaultdict(list)
        for cue in qualification.interpretation_cues:
            cues_by_subject[cue.subject.ref].append(cue)

        temporal_by_subject: dict[str, list[TemporalQualification]] = defaultdict(list)
        for item in qualification.temporal_qualifications:
            temporal_by_subject[item.fact.subject.ref].append(item)

        edges = () if graph is None else graph.edges
        edges_into: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in edges:
            edges_into[edge.target_key].append(edge)

        return cls(
            root_key=root.canonical_key if root is not None else None,
            evidence_by_subject={
                key: tuple(sorted(value, key=_evidence_sort_key))
                for key, value in evidence_by_subject.items()
            },
            subject_by_evidence=dict(subject_by_evidence),
            signals_by_subject={
                key: tuple(sorted(value, key=lambda item: item.ref))
                for key, value in signals_by_subject.items()
            },
            cues_by_subject={
                key: tuple(sorted(value, key=lambda item: item.key))
                for key, value in cues_by_subject.items()
            },
            temporal_by_subject={
                key: tuple(sorted(value, key=lambda item: item.fact.ref))
                for key, value in temporal_by_subject.items()
            },
            edges_into={key: tuple(value) for key, value in edges_into.items()},
            edges=edges,
            stale_context_dataset=qualification.coverage.stale_context_datasets > 0,
            _all_evidence=tuple(sorted(all_evidence, key=_evidence_sort_key)),
        )


def edge_ref(edge: GraphEdge) -> str:
    """The deterministic ref for a graph edge, keyed exactly as Task 15 keys it."""
    return edge_subject(edge.source_key, edge.relationship_type.value, edge.target_key).ref


def _evidence_sort_key(evidence: Evidence) -> tuple[str, str, str, str]:
    """Order evidence by what it says, never by when it arrived.

    Provider order is whatever Task 13 chose and Task 6 returned, and letting it
    reach the output would make two identical investigations serialize
    differently.
    """
    return (
        evidence.claim_type,
        evidence.transport_provider,
        evidence.effect.value,
        evidence.id,
    )
