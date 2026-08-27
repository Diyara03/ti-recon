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

from typing import Protocol, runtime_checkable

from ti_recon.enums import ProviderCapability
from ti_recon.execution.executor import ProviderExecutor
from ti_recon.execution.models import ExecutionContext, ProviderExecutionOutcome
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

__all__ = [
    "MAX_PLANNING_ROUNDS",
    "AdaptiveEnrichmentOrchestrator",
    "EnrichmentOutcomeSink",
]


@runtime_checkable
class EnrichmentOutcomeSink(Protocol):
    """Somewhere to hand each provider outcome as it arrives.

    :class:`~ti_recon.planning.models.AdaptiveEnrichmentResult` is a report: it
    carries what was decided and what was covered, deliberately not the provider
    payloads, because planning state that held them would be unbounded and would
    put provider content somewhere nobody was looking for it.

    A correlation layer needs those payloads — the objects and relationships are
    the whole input to a graph. Rather than widening the result model and pushing
    payloads through planning, the outcome is offered here as it happens. The
    orchestrator neither reads it back nor changes any decision because of it, so
    a sink cannot influence what gets asked.
    """

    def record_outcome(self, outcome: ProviderExecutionOutcome) -> None:
        """Take one completed provider execution, including its result envelope."""
        ...


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
        outcome_sink: EnrichmentOutcomeSink | None = None,
    ) -> None:
        self._planner = planner
        self._executor = executor
        self._registry = registry
        self._metrics = NoOpPlanningMetricsSink() if metrics is None else metrics
        self._outcome_sink = outcome_sink

    @property
    def planner(self) -> AdaptiveEnrichmentPlanner:
        return self._planner

    def with_outcome_sink(
        self, outcome_sink: EnrichmentOutcomeSink
    ) -> AdaptiveEnrichmentOrchestrator:
        """The same orchestrator, offering each outcome to ``outcome_sink``.

        A copy rather than a mutation: the planner, executor and registry are
        shared, so nothing about provider selection changes, and a caller that
        needs the payloads for one run cannot accidentally attach a collector to
        somebody else's.
        """
        return AdaptiveEnrichmentOrchestrator(
            planner=self._planner,
            executor=self._executor,
            registry=self._registry,
            metrics=self._metrics,
            outcome_sink=outcome_sink,
        )

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
                self._provider_request(request, call.capabilities, investigation_id),
                context,
            )
            if self._outcome_sink is not None:
                self._outcome_sink.record_outcome(outcome)
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
                    capabilities_requested=len(call.capabilities),
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
        capabilities: frozenset[ProviderCapability],
        investigation_id: str,
    ) -> ProviderRequest:
        """Build the Task 5 request for one planned call.

        Carries every capability the planner bundled into this decision, so a
        provider that answers four active goals with one read is asked once. The
        adapter decides what that means for its own request shape — Task 7 filters
        GTI's relationship plan by exactly this set — which is why the planner
        never needs to know how any provider spends it.

        The operation is always ``LOOKUP`` and the mode always ``PASSIVE``,
        carried from a request model that refuses to be anything else. There is no
        path from an automatic plan to a submission, a detonation or a rescan.
        """
        return ProviderRequest(
            investigation_id=investigation_id,
            intel_object=request.intel_object,
            operation=request.operation,
            requested_capabilities=capabilities,
            depth=request.depth,
            activity_mode=request.activity_mode,
        )
