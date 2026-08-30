"""State one investigation carries across enrichment rounds (Task 14 seam).

A single round needs none of this: :class:`CorrelatedInvestigationOrchestrator`
builds a graph, spends a pivot budget and returns. A *continuation* — Task 19
asking for specific missing information after readiness said something material
was absent — needs the second round to land in the same investigation rather than
beside it.

What must span rounds, and why each one matters:

* **the graph**, so what round two learns connects to what round one learned
  rather than forming a second, disconnected picture of the same observable;
* **the enriched-node set the graph already holds**, so a pivot target reached in
  round one is not reached again in round two — which is also how a *second hop*
  would appear without anyone deciding to allow one, since a target enriched
  earlier would look like a fresh first-hop candidate;
* **the pivot budget**, so a continuation does not receive a new allowance
  merely because new root evidence arrived;
* **the planning state**, so Task 13's remote budget and its record of calls
  already made are investigation-wide.

The session is deliberately a plain mutable holder rather than a model: it is
per-run scratch space owned by the caller, never part of a result, and never
shared between investigations.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.policy import PivotBudget
from ti_recon.enums import ProviderCapability
from ti_recon.execution.models import ProviderExecutionOutcome
from ti_recon.planning.state import PlanningState
from ti_recon.providers.result import ProviderResultEnvelope

__all__ = ["CorrelationSession"]


@dataclass
class CorrelationSession:
    """Per-investigation state shared by every enrichment round.

    Created fresh for each investigation. Nothing here may outlive one run, and
    nothing here belongs on an orchestrator: two investigations sharing any of
    these fields would share a graph, a budget and a record of what had been
    asked.
    """

    #: The one graph every round ingests into.
    graph: InvestigationGraph | None = None
    #: The pivot allowance, carried with what it has already spent.
    pivot_budget: PivotBudget | None = None
    #: Task 13's memory: remote budget spent, calls made, coverage reached.
    planning: PlanningState | None = None
    #: Capabilities the next round may pursue. Empty means no restriction.
    focus: frozenset[ProviderCapability] = frozenset()
    #: capability -> source families that may not answer *that* capability.
    #:
    #: Per capability rather than per round, so a family barred from supplying
    #: an independent challenge still answers every other question normally.
    excluded_families: dict[ProviderCapability, frozenset[str]] = field(default_factory=dict)

    #: Every provider outcome this investigation produced, root and pivot alike,
    #: in the order they completed.
    #:
    #: Correlation already collects these to ingest them; recording them here
    #: lets the reasoning stages above see exactly what correlation saw, rather
    #: than a separately-gathered set that could drift from it. They are
    #: execution records, not part of any result: the caller reads them and the
    #: session is discarded with the run.
    outcomes: list[ProviderExecutionOutcome] = field(default_factory=list)

    def record_outcomes(self, outcomes: Iterable[ProviderExecutionOutcome]) -> None:
        """Note what one enrichment produced."""
        self.outcomes.extend(outcomes)

    def envelopes(self) -> tuple[ProviderResultEnvelope, ...]:
        """The normalized results, in completion order.

        A failed execution carries no envelope, which is why this is a filter
        rather than a projection: the failure itself is already recorded as a
        planner attempt and reaches readiness through coverage.
        """
        return tuple(outcome.result for outcome in self.outcomes if outcome.result is not None)
