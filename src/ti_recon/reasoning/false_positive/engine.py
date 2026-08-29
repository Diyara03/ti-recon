"""The alternative-explanation engine (Task 16).

Reads what Tasks 5-15 produced -- provider result envelopes, a Task 15
qualification and, when the caller has one, a Task 14 graph -- and asks whether
any of that context legitimately explains a specific piece of evidence.

It never answers what the case is.

What it does not do
-------------------

No network, DNS, provider call, credential, cache, Task 13 enrichment, Task 14
pivot or dataset refresh. No wall clock either: ``as_of`` is carried through from
the qualification, so a stored result can be re-derived years later with the
machine offline and produce the same bytes.

And no mutation. The graph, the envelopes, the evidence and the Task 15 result
are all read; a test asserts the graph is unchanged afterwards, because the one
failure that would be invisible here is a rule quietly rewriting the history it
was asked to interpret.

Vendor neutrality
-----------------

This module and :mod:`rules` name no provider and read no ``claim_type``. Every
discriminator they use -- ``EvidenceEffect``, ``EvidenceClass``, ``MatchScope``,
a Task 15 signal type, a relationship type -- is generic, and a test reads the
AST and string literals of both files to keep it that way. A provider added,
removed or renamed changes who supplies the evidence and never how it is read.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.false_positive.index import DIRECTIONAL_EFFECTS, ReasoningIndex
from ti_recon.reasoning.false_positive.metrics import (
    NoOpReasoningMetricsSink,
    ReasoningMetric,
    ReasoningMetricsSink,
)
from ti_recon.reasoning.false_positive.models import ReasoningFinding, ReasoningRole
from ti_recon.reasoning.false_positive.policy import FALSE_POSITIVE_REASONING_POLICY_VERSION
from ti_recon.reasoning.false_positive.results import (
    FalsePositiveReasoningResult,
    ReasoningCoverage,
)
from ti_recon.reasoning.false_positive.rules import apply_rules
from ti_recon.reasoning.results import TemporalContextResult
from ti_recon.versions import ENGINE_VERSION

__all__ = ["FalsePositiveReasoningEngine"]

#: Role -> the coverage field that counts it. Written as data so adding a role
#: without counting it is a visible omission rather than a silent one.
_ROLE_COUNTERS: dict[ReasoningRole, str] = {
    ReasoningRole.ALTERNATIVE_EXPLANATION: "alternative_explanations",
    ReasoningRole.INTERPRETATION_LIMITATION: "interpretation_limitations",
    ReasoningRole.ANALYSIS_QUALITY_LIMITATION: "analysis_quality_limitations",
    ReasoningRole.ATTRIBUTION_CAUTION: "attribution_cautions",
    ReasoningRole.TEMPORAL_RELEVANCE: "temporal_relevance_findings",
    ReasoningRole.SOURCE_DEPENDENCE: "source_dependence_findings",
    ReasoningRole.UNRESOLVED_TENSION: "unresolved_tensions",
}


@dataclass
class FalsePositiveReasoningEngine:
    """Builds alternative explanations and limitations for one investigation.

    Pure and injectable, like every other engine here: the metrics sink arrives
    as an argument and there is no state between runs.
    """

    metrics: ReasoningMetricsSink = field(default_factory=NoOpReasoningMetricsSink)

    def evaluate(
        self,
        *,
        qualification: TemporalContextResult,
        results: Sequence[ProviderResultEnvelope] = (),
        graph: InvestigationGraph | None = None,
        root: IntelObject | None = None,
    ) -> FalsePositiveReasoningResult:
        """Reason over one qualified investigation.

        ``qualification`` is required: Task 16 explains context, and without
        Task 15 having said what the context *is* there is nothing to reason
        from. The envelopes supply the evidence being explained, and the graph
        supplies the relationships whose significance may be in question.
        """
        index = ReasoningIndex.build(
            qualification=qualification, results=results, graph=graph, root=root
        )
        findings = apply_rules(index)
        coverage = self._coverage(index, qualification, findings)
        self._record(findings, coverage)

        return FalsePositiveReasoningResult(
            policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
            qualification_policy_version=qualification.context_policy_version,
            engine_version=ENGINE_VERSION,
            as_of=qualification.evaluated_at,
            findings=findings,
            coverage=coverage,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _coverage(
        self,
        index: ReasoningIndex,
        qualification: TemporalContextResult,
        findings: tuple[ReasoningFinding, ...],
    ) -> ReasoningCoverage:
        """Count what was examined and, crucially, what went unexplained.

        The unexplained figure is computed from the findings' own ``EXPLAINS``
        links rather than tracked alongside them, so it cannot drift away from
        what the findings actually claim.
        """
        directional = tuple(
            item for item in index.all_evidence if item.effect in DIRECTIONAL_EFFECTS
        )
        explained = {ref for finding in findings for ref in finding.explained_evidence_ids}
        directional_ids = {item.id for item in directional}

        counts = dict.fromkeys(_ROLE_COUNTERS.values(), 0)
        for finding in findings:
            counts[_ROLE_COUNTERS[finding.role]] += 1

        return ReasoningCoverage(
            evidence_examined=len(index.all_evidence),
            directional_evidence_examined=len(directional),
            context_signals_examined=len(qualification.context_signals),
            interpretation_cues_examined=len(qualification.interpretation_cues),
            graph_relationships_examined=len(index.edges),
            directional_evidence_with_explanations=len(directional_ids & explained),
            directional_evidence_without_explanations=len(directional_ids - explained),
            rules_matched=tuple(sorted({finding.rule_id for finding in findings})),
            **counts,
        )

    def _record(self, findings: tuple[ReasoningFinding, ...], coverage: ReasoningCoverage) -> None:
        roles: dict[str, int] = {}
        reasons: dict[str, int] = {}
        for finding in findings:
            roles[finding.role.value] = roles.get(finding.role.value, 0) + 1
            reasons[finding.reason_code.value] = reasons.get(finding.reason_code.value, 0) + 1

        self.metrics.record_reasoning(
            ReasoningMetric(
                evidence_examined=coverage.evidence_examined,
                directional_evidence_examined=coverage.directional_evidence_examined,
                reasoning_findings=len(findings),
                findings_by_role=dict(sorted(roles.items())),
                findings_by_reason=dict(sorted(reasons.items())),
                rules_matched=len(coverage.rules_matched),
                directional_evidence_without_explanations=(
                    coverage.directional_evidence_without_explanations
                ),
            )
        )
