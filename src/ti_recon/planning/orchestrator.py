"""Running a plan through the execution layer (Task 13).

Plan, execute, observe, re-plan — one remote provider at a time.

Why sequential
--------------

Launching four APIs at once would make the first answer useless: the point of an
adaptive planner is that a provider returning nothing, or returning strong
directional evidence, changes what is worth asking next. A fan-out spends the
whole budget before any of it can inform anything, which is the behaviour this
task exists to replace.

That is a deliberate trade of latency for provider usage. `ProviderExecutor`'s
concurrency remains available to callers outside this orchestrator, and a later
task can add planning *waves* if latency data ever justifies it — with real
numbers rather than an assumption.

Layer boundary
--------------

Every provider call goes through :class:`~ti_recon.execution.executor.ProviderExecutor`.
The orchestrator never touches an adapter's client, never resolves a credential,
never reads a cache and never retries. It selects and observes; Task 6 executes
safely. One failing provider does not end a run: an unconfigured key, a throttled
account or a broken endpoint each cost that provider and nothing else, and all of
them appear in the trace rather than being swallowed.
"""

from __future__ import annotations

from ti_recon.enums import ProviderCapability
from ti_recon.execution.executor import ProviderExecutor
from ti_recon.execution.models import ExecutionContext
from ti_recon.planning.metrics import (
    NoOpPlanningMetricsSink,
    PlanningMetricsSink,
    PlanningRunMetric,
    ProviderSelectionMetric,
    ProviderSkipMetric,
)
from ti_recon.planning.models import (
    AdaptiveEnrichmentResult,
    EnrichmentPlanningRequest,
    PlanningDecision,
    StopReason,
)
from ti_recon.planning.planner import AdaptiveEnrichmentPlanner
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.providers.request import ProviderRequest

__all__ = ["MAX_PLANNING_ROUNDS", "AdaptiveEnrichmentOrchestrator"]

#: Hard bound on planning rounds, independent of budget.
#:
#: The loop terminates on its own — every executed decision marks a
#: provider/capability pair attempted, and the set is finite — so this is a
#: backstop against a future policy that could stop making progress, not part of
#: the design. Hitting it is a bug, and it is better to stop than to spin.
MAX_PLANNING_ROUNDS: int = 64


class AdaptiveEnrichmentOrchestrator:
    """Drives planner and executor to enrich one observable."""

    def __init__(
        self,
        *,
        planner: AdaptiveEnrichmentPlanner,
        executor: ProviderExecutor,
        registry: ProviderRegistry,
        metrics: PlanningMetricsSink | None = None,
    ) -> None:
        self._planner = planner
        self._executor = executor
        self._registry = registry
        self._metrics = NoOpPlanningMetricsSink() if metrics is None else metrics

    @property
    def planner(self) -> AdaptiveEnrichmentPlanner:
        return self._planner

    async def run(
        self,
        request: EnrichmentPlanningRequest,
        context: ExecutionContext,
        *,
        investigation_id: str,
    ) -> AdaptiveEnrichmentResult:
        """Enrich one observable and return what was decided, done and learned.

        Enriches **the requested observable only**. Providers return related
        objects — domains a sample contacted, files it dropped, hosts serving a
        URL — and none of them is planned. Recursive pivoting needs pivot-value
        judgement, graph deduplication, fan-out limits and cycle prevention, and
        a task that does it properly; doing it here would turn one file into
        hundreds of queries.
        """
        state = self._planner.initial_state(request)
        decisions: list[PlanningDecision] = []
        stop_reason = StopReason.NO_ELIGIBLE_PROVIDER
        rounds = 0

        for _ in range(MAX_PLANNING_ROUNDS):
            decision = self._planner.next(request, state)
            decisions.append(decision)
            rounds += 1
            self._record_decision(request, decision)
            if decision.stop is not None:
                stop_reason = decision.stop
                break
            call = decision.call
            assert call is not None
            adapter = self._adapter_for(call.provider_id)
            if adapter is None:  # pragma: no cover - registry and profiles agree
                state.block(call.provider_id)
                continue
            outcome = await self._executor.execute(
                adapter,
                self._provider_request(request, call.capability, investigation_id),
                context,
            )
            state.observe(call, outcome)
        else:
            # Ran out of rounds without a stop decision. Reported honestly rather
            # than as a satisfied plan.
            stop_reason = StopReason.NO_ELIGIBLE_PROVIDER

        result = AdaptiveEnrichmentResult(
            target=request.intel_object,
            depth=request.depth,
            requested_capabilities=request.requested_capabilities,
            attempts=tuple(state.attempts),
            decisions=tuple(decisions),
            coverage=state.coverage_items(
                self._planner.depth_targets(request, state),
                self._planner.providers_considered(request),
            ),
            budget=state.budget,
            stop_reason=stop_reason,
        )
        self._metrics.record_run(
            PlanningRunMetric(
                object_type=request.intel_object.object_type,
                depth=request.depth,
                stop_reason=stop_reason,
                rounds=rounds,
                providers_called=sum(1 for attempt in result.attempts if attempt.called_provider),
                remote_runs_used=state.budget.remote_runs_used,
                high_cost_runs_used=state.budget.high_cost_runs_used,
                remote_budget=state.budget.max_remote_provider_runs,
                cache_hits=sum(1 for attempt in result.attempts if attempt.cache_hit),
                required_capability_uncovered=result.has_uncovered_required_capability,
            )
        )
        return result

    def _record_decision(
        self, request: EnrichmentPlanningRequest, decision: PlanningDecision
    ) -> None:
        """Emit what this round decided.

        Selections and skips both, because a skip is the more useful aggregate: a
        provider skipped as blocked all week is an entitlement problem, and one
        skipped as unsupported all week is a catalogue gap. Neither is visible
        from the calls that did happen.
        """
        object_type = request.intel_object.object_type
        if decision.call is not None:
            call = decision.call
            self._metrics.record_selection(
                ProviderSelectionMetric(
                    provider_id=call.provider_id,
                    capability=call.capability,
                    object_type=object_type,
                    depth=request.depth,
                    locality=call.locality,
                    cost_class=call.cost_class,
                    novelty=call.novelty,
                    reason=call.reason,
                )
            )
        for skipped in decision.skipped:
            self._metrics.record_skip(
                ProviderSkipMetric(
                    provider_id=skipped.provider_id,
                    capability=skipped.capability,
                    object_type=object_type,
                    depth=request.depth,
                    reason=skipped.reason,
                )
            )

    def _adapter_for(self, provider_id: str) -> ProviderAdapter | None:
        return next(
            (
                adapter
                for adapter in self._registry.list_all()
                if adapter.descriptor.provider_id == provider_id
            ),
            None,
        )

    def _provider_request(
        self,
        request: EnrichmentPlanningRequest,
        capability: ProviderCapability,
        investigation_id: str,
    ) -> ProviderRequest:
        """Build the Task 5 request for one planned call.

        The operation is always ``LOOKUP`` and the mode always ``PASSIVE``,
        carried from a request model that refuses to be anything else. There is no
        path from an automatic plan to a submission, a detonation or a rescan.
        """
        return ProviderRequest(
            investigation_id=investigation_id,
            intel_object=request.intel_object,
            operation=request.operation,
            requested_capabilities=frozenset({capability}),
            depth=request.depth,
            activity_mode=request.activity_mode,
        )
