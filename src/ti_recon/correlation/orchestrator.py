"""Root enrichment, correlation, and bounded pivots (Task 14).

The only module in this package that can cause a provider to be contacted, and it
does so exclusively by handing an observable to Task 13. It selects no providers,
holds no credentials, and never touches an adapter: what a pivot *is*, here, is a
canonical observable passed to the planner, which then applies the same locality,
budget, cooldown and cache rules it applies to anything else.

It also never resolves anything. No DNS, no HTTP, no socket. A domain discovered
in a sandbox report is a string that gets looked up through third-party APIs, or
it is nothing.

The loop
--------

1. enrich the submitted observable through Task 13,
2. ingest every provider result into the graph,
3. rank pivot candidates,
4. if — and only if — the caller asked for ENRICH, take candidates in rank order
   while the *shared* budget lasts, each at a reduced depth, each through Task 13
   with the remaining budget handed down as a constraint,
5. ingest what they returned, which grows the graph but never queues more work.

Step 5 is where fan-out would come from and does not: objects discovered by a
pivot enter the graph at hop 2 and are never enriched.
"""

from __future__ import annotations

from ti_recon.correlation.engine import CorrelationEngine
from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.metrics import (
    CorrelationMetric,
    CorrelationMetricsSink,
    NoOpCorrelationMetricsSink,
)
from ti_recon.correlation.models import (
    DEFAULT_GRAPH_LIMITS,
    GraphLimits,
)
from ti_recon.correlation.pivots import PivotCandidate, PivotPlanner
from ti_recon.correlation.policy import (
    MAX_AUTOMATIC_PIVOT_HOP,
    PivotBudget,
    PivotMode,
    PivotPolicy,
    PivotSkipReason,
)
from ti_recon.correlation.results import CorrelatedEnrichmentResult, PivotRun
from ti_recon.enums import InvestigationDepth
from ti_recon.execution.models import ExecutionContext, ProviderExecutionOutcome
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning import (
    AdaptiveEnrichmentOrchestrator,
    AdaptiveEnrichmentResult,
    EnrichmentPlanningRequest,
    PlanningConstraints,
)

__all__ = ["CorrelatedInvestigationOrchestrator"]


class _OutcomeCollector:
    """Collects provider outcomes from one Task 13 run.

    Task 13 hands each outcome over as it completes and never reads this back, so
    collecting cannot influence which providers are chosen.
    """

    def __init__(self) -> None:
        self.outcomes: list[ProviderExecutionOutcome] = []

    def record_outcome(self, outcome: ProviderExecutionOutcome) -> None:
        self.outcomes.append(outcome)


class CorrelatedInvestigationOrchestrator:
    """Enriches an observable, correlates the results, and pivots within bounds."""

    def __init__(
        self,
        *,
        enrichment: AdaptiveEnrichmentOrchestrator,
        limits: GraphLimits = DEFAULT_GRAPH_LIMITS,
        metrics: CorrelationMetricsSink | None = None,
    ) -> None:
        self._enrichment = enrichment
        self._limits = limits
        self._metrics = NoOpCorrelationMetricsSink() if metrics is None else metrics

    async def run(
        self,
        request: EnrichmentPlanningRequest,
        context: ExecutionContext,
        *,
        investigation_id: str,
        pivot_policy: PivotPolicy | None = None,
    ) -> CorrelatedEnrichmentResult:
        """Investigate one observable and correlate everything it produced."""
        policy = PivotPolicy() if pivot_policy is None else pivot_policy
        graph = InvestigationGraph(
            investigation_id=investigation_id,
            authenticated_user_id=context.authenticated_user_id,
            limits=self._limits,
        )
        engine = CorrelationEngine(graph=graph)
        root_key = engine.add_root(request.intel_object)

        root_result, outcomes = await self._enrich(request, context, investigation_id)
        self._ingest(engine, outcomes, hop=0)
        graph.mark_enriched(root_key)

        budget = policy.budget_for(request.depth)
        candidates, dropped = self._rank(graph, policy, request)
        pivot_runs: list[PivotRun] = []

        if policy.mode is PivotMode.ENRICH:
            budget, pivot_runs = await self._pivot(
                engine=engine,
                graph=graph,
                request=request,
                context=context,
                investigation_id=investigation_id,
                policy=policy,
                budget=budget,
                candidates=candidates,
            )
            # Ranked again over the finished graph, so what a pivot discovered is
            # visible as a candidate too — carrying HOP_LIMIT, because seeing a
            # lead and being allowed to chase it are different things, and an
            # analyst asking "what else is in here?" should not be answered with
            # silence.
            candidates, dropped = self._rank(graph, policy, request)

        result = CorrelatedEnrichmentResult(
            root_enrichment=root_result,
            graph_nodes=graph.nodes,
            graph_edges=graph.edges,
            root_node_key=graph.root_key or "",
            pivot_mode=policy.mode,
            pivot_candidates=candidates,
            pivot_runs=tuple(pivot_runs),
            pivot_budget=budget,
            correlation_issues=tuple(graph.issues),
            truncation=graph.truncation.model_copy(update={"pivot_candidates_dropped": dropped}),
            assertions_deduplicated=graph.assertions_deduplicated,
        )
        self._metrics.record_correlation(_metric_for(result, graph))
        return result

    # ------------------------------------------------------------------ #
    # Task 13
    # ------------------------------------------------------------------ #

    async def _enrich(
        self,
        request: EnrichmentPlanningRequest,
        context: ExecutionContext,
        investigation_id: str,
    ) -> tuple[AdaptiveEnrichmentResult, tuple[ProviderExecutionOutcome, ...]]:
        """One Task 13 run, with its provider results collected on the way past."""
        collector = _OutcomeCollector()
        orchestrator = self._enrichment.with_outcome_sink(collector)
        result = await orchestrator.run(request, context, investigation_id=investigation_id)
        return result, tuple(collector.outcomes)

    def _ingest(
        self,
        engine: CorrelationEngine,
        outcomes: tuple[ProviderExecutionOutcome, ...],
        *,
        hop: int,
    ) -> None:
        for outcome in outcomes:
            if outcome.result is not None:
                engine.ingest(outcome.result, hop=hop)
        engine.derive_structural_edges_for_graph()

    # ------------------------------------------------------------------ #
    # Pivots
    # ------------------------------------------------------------------ #

    def _rank(
        self,
        graph: InvestigationGraph,
        policy: PivotPolicy,
        request: EnrichmentPlanningRequest,
    ) -> tuple[tuple[PivotCandidate, ...], int]:
        planner = PivotPlanner(policy=policy, max_candidates=self._limits.max_pivot_candidates)
        return planner.candidates(
            graph, allow_remote_lookup=request.constraints.allow_remote_lookup
        )

    async def _pivot(
        self,
        *,
        engine: CorrelationEngine,
        graph: InvestigationGraph,
        request: EnrichmentPlanningRequest,
        context: ExecutionContext,
        investigation_id: str,
        policy: PivotPolicy,
        budget: PivotBudget,
        candidates: tuple[PivotCandidate, ...],
    ) -> tuple[PivotBudget, list[PivotRun]]:
        """Enrich selected pivots in rank order, inside one shared budget."""
        runs: list[PivotRun] = []
        pivot_depth = policy.pivot_depth_for(request.depth)

        for candidate in candidates:
            # The budget is checked per candidate rather than once: a pivot that
            # spent three remote runs can exhaust what is left for the next one.
            if not candidate.eligible_for_enrichment or self._budget_skip(budget) is not None:
                continue

            node = graph.node(candidate.target_node_key)
            if node is None:  # pragma: no cover - candidates come from the graph
                continue

            run, outcomes = await self._run_pivot(
                node.intel_object,
                context=context,
                investigation_id=investigation_id,
                request=request,
                depth=pivot_depth,
                budget=budget,
                candidate=candidate,
                policy=policy,
            )
            # Marked enriched before ingestion, so a result naming the target
            # again — or naming the root, which a cycle does — cannot queue it a
            # second time. Objects a pivot discovered enter at the hop after the
            # automatic limit, which is what stops the graph recruiting more work.
            graph.mark_enriched(candidate.target_node_key)
            self._ingest(engine, outcomes, hop=MAX_AUTOMATIC_PIVOT_HOP + 1)
            budget = budget.charge(remote_runs=run.remote_runs_used)
            runs.append(run)

        return budget, runs

    async def _run_pivot(
        self,
        target: IntelObject,
        *,
        context: ExecutionContext,
        investigation_id: str,
        request: EnrichmentPlanningRequest,
        depth: InvestigationDepth,
        budget: PivotBudget,
        candidate: PivotCandidate,
        policy: PivotPolicy,
    ) -> tuple[PivotRun, tuple[ProviderExecutionOutcome, ...]]:
        """Hand one pivot target to Task 13, inside what is left of the budget."""
        constraints = PlanningConstraints(
            provider_allowlist=request.constraints.provider_allowlist,
            provider_denylist=request.constraints.provider_denylist,
            # Both switches must be on. Either one off leaves local providers,
            # which Task 13 selects by its own locality policy — no provider is
            # named here.
            allow_remote_lookup=(
                request.constraints.allow_remote_lookup and policy.allow_remote_pivot_lookup
            ),
            # The shared budget, handed down as a reduction. Without this each
            # pivot would receive a fresh depth-sized budget and five pivots would
            # cost five investigations.
            max_remote_provider_runs=budget.remote_remaining,
        )
        pivot_request = EnrichmentPlanningRequest(
            intel_object=target,
            depth=depth,
            constraints=constraints,
        )
        result, outcomes = await self._enrich(pivot_request, context, investigation_id)
        remote_runs = sum(1 for item in result.attempts if item.called_provider)
        return (
            PivotRun(
                target_node_key=candidate.target_node_key,
                hop=candidate.hop,
                depth=depth,
                selection_reason=candidate.selection_reason,
                enrichment=result,
                remote_runs_used=remote_runs,
            ),
            outcomes,
        )

    # ------------------------------------------------------------------ #
    # Budget
    # ------------------------------------------------------------------ #

    @staticmethod
    def _budget_skip(budget: PivotBudget) -> PivotSkipReason | None:
        if budget.targets_remaining <= 0:
            return PivotSkipReason.TARGET_BUDGET
        if budget.remote_remaining <= 0:
            return PivotSkipReason.REMOTE_BUDGET
        return None


def _metric_for(result: CorrelatedEnrichmentResult, graph: InvestigationGraph) -> CorrelationMetric:
    """Counts only — no observable value, no user, no investigation id."""
    skipped: dict[str, int] = {}
    for candidate in result.pivot_candidates:
        if candidate.skip_reason is not None:
            skipped[candidate.skip_reason.value] = skipped.get(candidate.skip_reason.value, 0) + 1
    return CorrelationMetric(
        depth=result.root_enrichment.depth,
        pivot_mode=result.pivot_mode,
        graph_nodes=len(result.graph_nodes),
        graph_edges=len(result.graph_edges),
        assertions=sum(len(edge.assertions) for edge in result.graph_edges),
        assertions_deduplicated=graph.assertions_deduplicated,
        identity_conflicts=sum(
            1
            for issue in result.correlation_issues
            if issue.issue_type.value == "file_hash_conflict"
        ),
        pivot_candidates=len(result.pivot_candidates),
        pivots_enriched=len(result.pivot_runs),
        pivots_skipped_by_reason=skipped,
        graph_truncated=result.truncation.any_truncation,
    )
