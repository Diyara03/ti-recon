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
from ti_recon.correlation.session import CorrelationSession
from ti_recon.enums import InvestigationDepth
from ti_recon.execution.models import ExecutionContext, ProviderExecutionOutcome
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning import (
    AdaptiveEnrichmentOrchestrator,
    AdaptiveEnrichmentResult,
    EnrichmentPlanningRequest,
    PlanningConstraints,
)
from ti_recon.planning.state import PlanningState

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
        self._budget_blocked: dict[str, PivotSkipReason] = {}

    async def run(
        self,
        request: EnrichmentPlanningRequest,
        context: ExecutionContext,
        *,
        investigation_id: str,
        pivot_policy: PivotPolicy | None = None,
        session: CorrelationSession | None = None,
    ) -> CorrelatedEnrichmentResult:
        """Investigate one observable and correlate everything it produced.

        ``session`` continues an earlier round of the same investigation. One
        graph, one pivot budget and one enriched-node set span every round: a
        fresh graph per round would disconnect what the rounds learned, hand a
        continuation a new pivot allowance, and let a target enriched in round
        one be enriched again in round two — which is also how a second hop would
        appear without anyone deciding to allow one.
        """
        policy = PivotPolicy() if pivot_policy is None else pivot_policy
        self._budget_blocked = {}
        if session is not None and session.graph is not None:
            graph = session.graph
        else:
            graph = InvestigationGraph(
                investigation_id=investigation_id,
                authenticated_user_id=context.authenticated_user_id,
                limits=self._limits,
            )
        engine = CorrelationEngine(graph=graph)
        root_key = engine.add_root(request.intel_object)

        root_result, outcomes = await self._enrich(
            request, context, investigation_id, session=session
        )
        self._ingest(engine, outcomes, hop=0, anchor_key=root_key)
        graph.mark_enriched(root_key)

        budget = (
            policy.budget_for(request.depth)
            if session is None or session.pivot_budget is None
            else session.pivot_budget
        )
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
                session=session,
            )
            # Ranked again over the finished graph, so what a pivot discovered is
            # visible as a candidate too — carrying HOP_LIMIT, because seeing a
            # lead and being allowed to chase it are different things, and an
            # analyst asking "what else is in here?" should not be answered with
            # silence.
            candidates, dropped = self._rank(graph, policy, request)
            candidates = self._apply_budget_skips(candidates)

        if session is not None:
            session.graph = graph
            session.pivot_budget = budget

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
        *,
        session: CorrelationSession | None = None,
        continue_planning: bool = True,
    ) -> tuple[AdaptiveEnrichmentResult, tuple[ProviderExecutionOutcome, ...]]:
        """One Task 13 run, with its provider results collected on the way past.

        ``continue_planning`` separates the two things a session holds. The root
        of a later round continues the *same* planning state: its budget, its
        record of calls made and its coverage. A pivot does not — it is a
        different observable with its own goals, and it spends the pivot
        allowance Task 14 handed down as a constraint, so carrying the root's
        planning memory into it would charge one budget twice and let the root's
        focus decide what a pivot may ask.

        The *outcomes* are recorded either way. Everything a provider returned
        about anything in this investigation belongs to the investigation, and
        the layers above read them from here: a pivot result that reached the
        graph but not the session would be correlated and then never qualified,
        explained, assessed or counted as coverage.
        """
        collector = _OutcomeCollector()
        orchestrator = self._enrichment.with_outcome_sink(collector)
        states: list[PlanningState] = []
        carried = session if session is not None and continue_planning else None
        result = await orchestrator.run(
            request,
            context,
            investigation_id=investigation_id,
            carry_over=None if carried is None else carried.planning,
            focus=frozenset() if carried is None else carried.focus,
            excluded_families=None if carried is None else carried.excluded_families,
            additional_coverage=(frozenset() if carried is None else carried.additional_coverage),
            state_sink=states,
        )
        if carried is not None and states:
            carried.planning = states[0]
        outcomes = tuple(collector.outcomes)
        if session is not None:
            session.record_outcomes(outcomes)
        return result, outcomes

    def _ingest(
        self,
        engine: CorrelationEngine,
        outcomes: tuple[ProviderExecutionOutcome, ...],
        *,
        hop: int,
        anchor_key: str,
    ) -> None:
        """Fold one enrichment's results into the graph, anchored to its target."""
        for outcome in outcomes:
            if outcome.result is not None:
                engine.ingest(outcome.result, hop=hop, anchor_key=anchor_key)
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
        session: CorrelationSession | None = None,
    ) -> tuple[PivotBudget, list[PivotRun]]:
        """Enrich selected pivots in rank order, inside one shared budget."""
        runs: list[PivotRun] = []
        pivot_depth = policy.pivot_depth_for(request.depth)

        for candidate in candidates:
            if not candidate.eligible_for_enrichment:
                continue
            # The budget is checked per candidate rather than once: a pivot that
            # spent three remote runs can exhaust what is left for the next one.
            blocked = self._budget_skip(budget)
            if blocked is not None:
                # Remembered so the re-ranked candidate list can say the target was
                # eligible and unaffordable, rather than leaving it looking chosen.
                self._budget_blocked[candidate.target_node_key] = blocked
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
                session=session,
            )
            # Marked enriched before ingestion, so a result naming the target
            # again — or naming the root, which a cycle does — cannot queue it a
            # second time. Objects a pivot discovered enter at the hop after the
            # automatic limit, which is what stops the graph recruiting more work.
            graph.mark_enriched(candidate.target_node_key)
            self._ingest(
                engine,
                outcomes,
                hop=MAX_AUTOMATIC_PIVOT_HOP + 1,
                anchor_key=candidate.target_node_key,
            )
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
        session: CorrelationSession | None = None,
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
        result, outcomes = await self._enrich(
            pivot_request,
            context,
            investigation_id,
            # The session takes the outcomes and not the planning state: a pivot
            # is a different observable spending the pivot allowance, and the
            # root's budget, attempts and focus are none of its business.
            session=session,
            continue_planning=False,
        )
        # Task 13's own accounting, not a second count of it: a provider that was
        # called still costs nothing here if it was local, and a cache hit,
        # cooldown or unconfigured credential costs nothing either. Counting
        # `called_provider` directly would charge the disclosure budget for a
        # lookup that disclosed nothing.
        remote_runs = result.budget.remote_runs_used
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

    def _apply_budget_skips(
        self, candidates: tuple[PivotCandidate, ...]
    ) -> tuple[PivotCandidate, ...]:
        """Mark candidates that were eligible but never affordable."""
        if not self._budget_blocked:
            return candidates
        return tuple(
            item.model_copy(
                update={
                    "eligible_for_enrichment": False,
                    "selection_reason": None,
                    "skip_reason": self._budget_blocked[item.target_node_key],
                }
            )
            if item.target_node_key in self._budget_blocked and item.skip_reason is None
            else item
            for item in candidates
        )

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
