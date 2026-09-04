"""The vendor-neutral qualification engine (Task 15).

Reads what Tasks 5-14 already produced — provider result envelopes and, when the
caller has one, a Task 14 investigation graph — and answers **what each finding
means in time and context**. It never answers what the case is.

Vendor neutrality is structural, not aspirational. This module names no provider
and knows no provider field: every field-name judgement lives in a provider's own
``qualification`` module, reached through
:func:`ti_recon.reasoning.catalog.default_qualifiers`, and a test reads this
file's AST to prove no vendor string got in. A provider added, removed, renamed
or left unconfigured changes who supplies facts and never how they are read.

What it does not do
-------------------

No network, no DNS, no socket, no provider call, no credential, no cache, no
Task 13 enrichment and no Task 14 pivot. It reasons entirely over data already in
hand, so it can run on a stored result years later and produce the same answer.
It also mutates nothing: no evidence effect, no evidence class, no lineage, no
match scope, no relationship and no graph edge is written by anything here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.enums import ProviderRunStatus
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.catalog import default_qualifiers
from ti_recon.reasoning.context import relayed_signals, sort_signals
from ti_recon.reasoning.cues import build_cues
from ti_recon.reasoning.extraction import (
    PARTIAL_STATUSES,
    ProviderQualification,
    ProviderQualifier,
    QualificationContext,
)
from ti_recon.reasoning.metrics import (
    NoOpQualificationMetricsSink,
    QualificationMetric,
    QualificationMetricsSink,
)
from ti_recon.reasoning.models import (
    ContextSignal,
    SourceLifecycleState,
    TemporalFact,
    TemporalFactKind,
    edge_subject,
)
from ti_recon.reasoning.policy import CONTEXT_POLICY_VERSION, WARNINGLIST_MAP_VERSION
from ti_recon.reasoning.results import QualificationCoverage, TemporalContextResult
from ti_recon.reasoning.temporal import qualify_facts, require_utc
from ti_recon.versions import ENGINE_VERSION

__all__ = ["TemporalContextEngine"]


@dataclass
class TemporalContextEngine:
    """Qualifies one investigation's findings in time and context.

    Pure and injectable, like every other engine here: the qualifier registry and
    the metrics sink arrive as arguments, and the clock arrives per call. There is
    no hidden state between runs.
    """

    qualifiers: Mapping[str, ProviderQualifier] = field(default_factory=default_qualifiers)
    metrics: QualificationMetricsSink = field(default_factory=NoOpQualificationMetricsSink)

    def evaluate(
        self,
        *,
        as_of: datetime,
        results: Sequence[ProviderResultEnvelope] = (),
        graph: InvestigationGraph | None = None,
        root: IntelObject | None = None,
    ) -> TemporalContextResult:
        """Qualify everything in hand against one explicit instant.

        ``as_of`` is required and must be timezone-aware. Nothing in Task 15 reads
        a wall clock, so the same inputs at the same ``as_of`` serialize
        identically forever — which is what lets a stored qualification be
        re-derived and compared rather than merely trusted.
        """
        moment = require_utc(as_of)
        context = self._context(results, graph, root)

        facts: list[TemporalFact] = []
        signals: list[ContextSignal] = []
        evidence_seen: list[Evidence] = []
        used: set[str] = set()
        unqualified: set[str] = set()
        partial_results = 0

        for envelope in sorted(results, key=_envelope_sort_key):
            evidence_seen.extend(envelope.evidence)
            partial = envelope.status in PARTIAL_STATUSES
            partial_results += int(partial)

            qualifier = self.qualifiers.get(envelope.provider)
            if qualifier is None:
                # Counted and named. A provider with no extractor is a blind spot
                # in the qualification layer, not an absence of findings.
                unqualified.add(envelope.provider)
                continue
            used.add(envelope.provider)
            produced: ProviderQualification = qualifier(
                envelope,
                QualificationContext(
                    node_keys=context.node_keys,
                    root_key=context.root_key,
                    source_partial=partial,
                ),
            )
            facts.extend(produced.temporal_facts)
            signals.extend(produced.context_signals)

        signals.extend(relayed_signals(evidence_seen, context))
        if graph is not None:
            facts.extend(_assertion_facts(graph))

        ordered_signals = sort_signals(signals)
        evaluation = qualify_facts(facts, as_of=moment)
        ordered_facts = tuple(item.fact for item in evaluation.qualifications)
        cues = build_cues(facts=ordered_facts, signals=ordered_signals, graph=graph)

        coverage = QualificationCoverage(
            provider_results_examined=len(results),
            evidence_items_examined=len(evidence_seen),
            evidence_with_temporal_facts=len(
                {fact.evidence.evidence_id for fact in ordered_facts if fact.evidence is not None}
            ),
            relationship_assertions_examined=(
                0 if graph is None else sum(len(edge.assertions) for edge in graph.edges)
            ),
            graph_nodes_examined=0 if graph is None else graph.node_count,
            graph_edges_examined=0 if graph is None else graph.edge_count,
            temporal_facts_extracted=len(ordered_facts),
            context_signals_generated=len(ordered_signals),
            interpretation_cues_generated=len(cues),
            temporal_issues=len(evaluation.issues),
            partial_provider_results=partial_results,
            stale_context_datasets=len(
                {
                    fact.subject.ref
                    for fact in ordered_facts
                    if fact.lifecycle is SourceLifecycleState.DATASET_STALE
                }
            ),
            qualifiers_available=tuple(sorted(self.qualifiers)),
            qualifiers_used=tuple(sorted(used)),
            providers_without_qualifier=tuple(sorted(unqualified)),
        )

        self._record(coverage, cues)
        return TemporalContextResult(
            evaluated_at=moment,
            engine_version=ENGINE_VERSION,
            context_policy_version=CONTEXT_POLICY_VERSION,
            warninglist_map_version=WARNINGLIST_MAP_VERSION,
            temporal_qualifications=evaluation.qualifications,
            context_signals=ordered_signals,
            interpretation_cues=cues,
            temporal_issues=evaluation.issues,
            coverage=coverage,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _context(
        self,
        results: Sequence[ProviderResultEnvelope],
        graph: InvestigationGraph | None,
        root: IntelObject | None,
    ) -> QualificationContext:
        """Index every object in play, so a fact attaches to a canonical key.

        Evidence points at a per-run object id. The graph keys nodes by canonical
        identity. Resolving one onto the other here is what lets a Task 15 result
        join straight onto a Task 14 graph — and what keeps an extractor from ever
        needing to know either.
        """
        objects: list[IntelObject] = []
        if graph is not None:
            objects.extend(node.intel_object for node in graph.nodes)
        for envelope in results:
            objects.extend(envelope.objects)
        return QualificationContext.build(objects=tuple(objects), root=root)

    def _record(
        self,
        coverage: QualificationCoverage,
        cues: Sequence[object],
    ) -> None:
        counts: dict[str, int] = {}
        for cue in cues:
            name = getattr(getattr(cue, "cue_type", None), "value", None)
            if isinstance(name, str):
                counts[name] = counts.get(name, 0) + 1
        self.metrics.record_qualification(
            QualificationMetric(
                provider_results=coverage.provider_results_examined,
                evidence_items=coverage.evidence_items_examined,
                temporal_facts=coverage.temporal_facts_extracted,
                temporal_issues=coverage.temporal_issues,
                context_signals=coverage.context_signals_generated,
                interpretation_cues=coverage.interpretation_cues_generated,
                cues_by_type=dict(sorted(counts.items())),
                providers_without_qualifier=len(coverage.providers_without_qualifier),
            )
        )


def _assertion_facts(graph: InvestigationGraph) -> list[TemporalFact]:
    """Per-assertion relationship times, kept per assertion.

    One edge, two assertions, one from 2025 and one from 2026, is **two
    observations** — never a continuous association across seven years. The
    aggregate bounds Task 14 exposes are display-only and are deliberately not
    read here: qualifying them would turn a bounding box into a claim.
    """
    found: list[TemporalFact] = []
    for edge in graph.edges:
        subject = edge_subject(edge.source_key, edge.relationship_type.value, edge.target_key)
        for index, assertion in enumerate(edge.assertions):
            marker = "|".join(assertion.dedupe_key) or f"index={index}"
            for kind, instant, raw in (
                (
                    TemporalFactKind.RELATIONSHIP_FIRST_OBSERVED,
                    assertion.first_seen,
                    "first_seen",
                ),
                (TemporalFactKind.RELATIONSHIP_LAST_OBSERVED, assertion.last_seen, "last_seen"),
                (
                    TemporalFactKind.RELATIONSHIP_LAST_OBSERVED,
                    None if assertion.last_seen is not None else assertion.observed_at,
                    "observed_at",
                ),
            ):
                if instant is None:
                    continue
                found.append(
                    TemporalFact(
                        subject=subject,
                        kind=kind,
                        instant=instant,
                        transport_provider=assertion.transport_provider,
                        origin_provider=assertion.origin_provider,
                        source_family=assertion.source_family,
                        lineage_group_id=assertion.lineage_group_id,
                        raw_field=raw,
                        relation_basis=assertion.basis,
                        detail=f"assertion={marker}"[:200],
                    )
                )
    return found


def _envelope_sort_key(envelope: ProviderResultEnvelope) -> tuple[str, str, str]:
    """Provider order, so extraction never depends on execution order."""
    return (
        envelope.provider,
        envelope.operation.value,
        envelope.status.value if isinstance(envelope.status, ProviderRunStatus) else "",
    )
