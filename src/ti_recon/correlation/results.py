"""What a correlated investigation returns (Task 14).

Deliberately not a verdict. There is no risk score, no confidence and no
malicious/benign field anywhere in this package: what it produces is a graph, a
ranked list of leads, and a full account of what was and was not done. Deciding
what any of it *means* is the fusion layer's job, and a correlation engine that
guessed would produce the hardest kind of error to find — a plausible conclusion
with nothing behind it.

Each Task 13 run stays identifiable by the node it was about and the hop it sat
at, rather than every provider outcome from every pivot being poured into one
list. "Which of these findings is about the thing I submitted?" has to remain
answerable.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.correlation.models import (
    CorrelationIssue,
    GraphEdge,
    GraphNode,
    GraphTruncation,
)
from ti_recon.correlation.pivots import PivotCandidate
from ti_recon.correlation.policy import (
    PivotBudget,
    PivotMode,
    PivotSelectionReason,
    PivotSkipReason,
)
from ti_recon.enums import InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.planning.models import AdaptiveEnrichmentResult

__all__ = ["CorrelatedEnrichmentResult", "PivotRun"]


class PivotRun(FrozenTiReconModel):
    """One pivot target that was actually enriched."""

    target_node_key: str = Field(min_length=1, max_length=300)
    hop: int = Field(ge=0)
    depth: InvestigationDepth
    selection_reason: PivotSelectionReason | None = None
    enrichment: AdaptiveEnrichmentResult
    #: Provider runs that actually contacted somebody. What the shared budget was
    #: charged, following Task 13's own accounting rather than counting decisions.
    remote_runs_used: int = Field(default=0, ge=0)


class CorrelatedEnrichmentResult(FrozenTiReconModel):
    """The root enrichment, the graph it produced, and every pivot decision."""

    root_enrichment: AdaptiveEnrichmentResult
    root_node_key: str = Field(min_length=1, max_length=300)
    graph_nodes: tuple[GraphNode, ...] = ()
    graph_edges: tuple[GraphEdge, ...] = ()
    pivot_mode: PivotMode = PivotMode.RECOMMEND
    #: Every node considered, ranked, including the ones that were skipped — "why
    #: was this *not* followed" is the more common question, and a list that
    #: omitted its rejections would answer it with silence.
    pivot_candidates: tuple[PivotCandidate, ...] = ()
    pivot_runs: tuple[PivotRun, ...] = ()
    pivot_budget: PivotBudget
    correlation_issues: tuple[CorrelationIssue, ...] = ()
    truncation: GraphTruncation = GraphTruncation()
    assertions_deduplicated: int = Field(default=0, ge=0)

    @property
    def enriched_node_keys(self) -> tuple[str, ...]:
        """Targets that went through Task 13, root included."""
        return (self.root_node_key, *(run.target_node_key for run in self.pivot_runs))

    @property
    def total_remote_pivot_runs(self) -> int:
        return sum(run.remote_runs_used for run in self.pivot_runs)

    def skipped_by_reason(self) -> dict[PivotSkipReason, int]:
        counts: dict[PivotSkipReason, int] = {}
        for candidate in self.pivot_candidates:
            if candidate.skip_reason is not None:
                counts[candidate.skip_reason] = counts.get(candidate.skip_reason, 0) + 1
        return counts
