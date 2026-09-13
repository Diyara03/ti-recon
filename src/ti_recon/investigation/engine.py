"""End-to-end investigation orchestration (Task 19).

Runs the engines Tasks 13-18 already built, in order, over one observable, and
decides when to stop asking. That is the whole job. There is no maliciousness
rule here, no coverage judgement, no provider choice and no verdict — every one
of those belongs to a layer that already has the vocabulary for it, and a second
opinion formed here would eventually disagree with the first.

The loop
--------

    collect (Task 13 -> Task 6, correlated by Task 14)
        -> analyse (Tasks 15, 16, 17, 18)
        -> if readiness asks for more, and something can be asked, collect again

Stopping is Task 18's decision, expressed on two axes. Coverage inadequate *and*
a path remaining is the only continuation trigger. A suspicious verdict is not
one; neither is an inconclusive one, a failed provider or a missing sandbox.
Those are all reasons a person might feel the investigation is unfinished, and
readiness has already weighed each against what the assessment actually rests on.

What never changes between rounds
---------------------------------

Depth, pivot mode and budget are ceilings the caller set. A continuation asks for
information *within* them:

* **budget carries, never resets.** A fresh allowance per round would make the
  loop's cost unbounded while every individual round looked well behaved.
* **depth never escalates.** A QUICK investigation that wanted DEEP work wanted a
  different investigation, and that is the caller's decision.
* **pivot mode never escalates.** ``RECOMMEND`` means the caller declined pivot
  enrichment; readiness wanting more data is not their consent.
* **calls are never repeated.** Task 13's state carries what has been asked, so a
  continuation cannot re-ask it.

Failures
--------

A provider that was unconfigured, rate limited, out of quota or simply broken is
an analytical input: the run continues, and Task 18 decides whether the gap
mattered. A *structural* failure — stages describing different observables, a
merge conflict between rounds — is a workflow error and is raised, because
returning INCONCLUSIVE would dress a software fault as an analytical conclusion.

Cancellation propagates untouched. Converting it into a provider failure would
turn "the caller went away" into "the source was unavailable", and the difference
matters to everyone reading the result afterwards.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from ti_recon.correlation.orchestrator import CorrelatedInvestigationOrchestrator
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.correlation.results import CorrelatedEnrichmentResult
from ti_recon.correlation.session import CorrelationSession
from ti_recon.enums import ProviderCapability
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.models import ExecutionContext
from ti_recon.investigation.analysis import AnalysisPass, ReasoningEngines, run_analysis_pass
from ti_recon.investigation.continuation import (
    corroboration_directives,
    directives_for,
    wants_continuation,
)
from ti_recon.investigation.merge import merge_enrichment_results
from ti_recon.investigation.metrics import (
    InvestigationMetric,
    InvestigationMetricsSink,
    NoOpInvestigationMetricsSink,
)
from ti_recon.investigation.models import (
    INVESTIGATION_WORKFLOW_VERSION,
    ContinuationDirective,
    ContinuationNeed,
    InvestigationObjective,
    InvestigationRequest,
    InvestigationRound,
    RoundTrigger,
    WorkflowIssue,
    WorkflowIssueType,
    WorkflowStopReason,
    result_id_for,
)
from ti_recon.investigation.results import InvestigationResult
from ti_recon.planning.models import (
    AdaptiveEnrichmentResult,
    EnrichmentPlanningRequest,
    PlanningConstraints,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    ReadinessPurpose,
    ReadinessStatus,
)

__all__ = ["InvestigationError", "InvestigationOrchestrator"]

#: Readiness states that end the investigation, and the reason each records.
_TERMINAL_REASONS: dict[tuple[ReadinessStatus, ContinuationState], WorkflowStopReason] = {
    (ReadinessStatus.UNRESOLVED, ContinuationState.BLOCKED): (WorkflowStopReason.READINESS_BLOCKED),
    (ReadinessStatus.UNRESOLVED, ContinuationState.EXHAUSTED): (
        WorkflowStopReason.READINESS_EXHAUSTED
    ),
}

#: A defensive ceiling, not the correctness mechanism. Termination comes from
#: finite candidates, a cumulative budget and no-progress detection; this only
#: bounds a loop that all three somehow failed to stop, and reaching it would be
#: a bug rather than a long investigation.
_MAX_ROUNDS: int = 32


class InvestigationError(RuntimeError):
    """A structural fault in the workflow, never an analytical outcome."""


@dataclass
class _RunState:
    """One investigation's mutable memory. Never held on the orchestrator.

    Two investigations sharing any of this would share a graph, a budget and a
    record of what had been asked — so it is created per run and discarded with
    it.
    """

    investigation_id: str
    session: CorrelationSession
    enrichments: list[AdaptiveEnrichmentResult] = field(default_factory=list)
    envelopes: list[ProviderResultEnvelope] = field(default_factory=list)
    rounds: list[InvestigationRound] = field(default_factory=list)
    issues: list[WorkflowIssue] = field(default_factory=list)
    correlation: CorrelatedEnrichmentResult | None = None
    attempted_capabilities: set[str] = field(default_factory=set)
    #: Whether the caller's corroboration round has been spent. One per run.
    corroborated: bool = False

    #: The capabilities Task 13 admitted for this root at this depth, frozen
    #: from the first round.
    #:
    #: Taken from Task 13's own coverage items, which are built from its goal
    #: set, so this is the planner's answer rather than a second copy of the
    #: depth table kept here to drift from it. A continuation may narrow this
    #: set and may never widen it: a capability the requested depth did not
    #: admit is not missing from the investigation, it was never part of it,
    #: and planning it would make QUICK quietly cost STANDARD.
    admissible: frozenset[ProviderCapability] = frozenset()

    def progress_key(self) -> tuple[int, int, int]:
        """A stable view of how much has actually been collected.

        Compared across a continuation to answer one question: did asking again
        add anything? Attempts, provider results and covered capabilities are all
        it takes — if none of the three moved, the next round would ask the same
        thing and get the same nothing.
        """
        attempts = sum(len(item.attempts) for item in self.enrichments)
        covered = len(self.attempted_capabilities)
        return (attempts, len(self.envelopes), covered)


@dataclass
class InvestigationOrchestrator:
    """Compose Tasks 13-18 into one bounded, reproducible investigation.

    Reusable and stateless between runs: every piece of run-specific memory lives
    in a per-run state object, so a second investigation through the same
    instance shares nothing with the first.

    Dependencies are injected. This class never builds a provider adapter, never
    holds a registry of its own and never names a provider — composing the real
    catalogue is a separate concern, kept where the provider imports already live.
    """

    correlation: CorrelatedInvestigationOrchestrator
    engines: ReasoningEngines
    clock: Clock = field(default_factory=SystemClock)
    metrics: InvestigationMetricsSink = field(default_factory=NoOpInvestigationMetricsSink)
    purpose: ReadinessPurpose = ReadinessPurpose.ANALYST_TRIAGE

    async def investigate(
        self,
        request: InvestigationRequest,
        context: ExecutionContext,
        *,
        pivot_policy: PivotPolicy | None = None,
        investigation_id: str | None = None,
    ) -> InvestigationResult:
        """Investigate one observable, end to end.

        The execution scope in ``context`` reaches every provider call in every
        round unchanged. Substituting a shared or default scope would cross the
        user isolation every cache, cooldown and entitlement store below depends
        on.
        """
        policy = PivotPolicy() if pivot_policy is None else pivot_policy
        state = _RunState(
            investigation_id=investigation_id or str(uuid.uuid4()),
            session=CorrelationSession(),
        )

        analysis = await self._collect_and_analyse(
            request, context, policy, state, trigger=RoundTrigger.INITIAL, directives=()
        )
        stop_reason = self._terminal_reason(analysis)

        while True:
            analysis, stop_reason = await self._continue_until_terminal(
                request, context, policy, state, analysis, stop_reason
            )
            if not self._wants_corroboration(request, state, stop_reason):
                break
            # The caller's objective, not readiness: adequate coverage is the
            # default stopping point, and this asks for one bounded round past
            # it. Spent exactly once, whatever it yields.
            state.corroborated = True
            analysis, stop_reason = await self._corroborate(
                request, context, policy, state, analysis, stop_reason
            )

        return self._compose(request, state, analysis, policy, stop_reason)

    async def _continue_until_terminal(
        self,
        request: InvestigationRequest,
        context: ExecutionContext,
        policy: PivotPolicy,
        state: _RunState,
        analysis: AnalysisPass,
        stop_reason: WorkflowStopReason | None,
    ) -> tuple[AnalysisPass, WorkflowStopReason]:
        """The readiness-driven continuation loop, unchanged in substance."""
        while stop_reason is None:
            if len(state.rounds) >= _MAX_ROUNDS:  # pragma: no cover - defensive
                msg = f"investigation exceeded {_MAX_ROUNDS} rounds without terminating"
                raise InvestigationError(msg)
            directives = directives_for(
                analysis.readiness,
                analysis.fusion,
                admissible=state.admissible,
            )
            if not directives:
                state.issues.append(
                    WorkflowIssue(
                        issue_type=WorkflowIssueType.UNACTIONABLE_INFORMATION_NEED,
                        detail=(
                            "readiness reported a remaining path, and no need named a "
                            "capability admissible at the requested depth"
                        ),
                        round_index=len(state.rounds),
                    )
                )
                stop_reason = WorkflowStopReason.NO_ACTIONABLE_CONTINUATION
                break

            before = state.progress_key()
            analysis = await self._collect_and_analyse(
                request,
                context,
                policy,
                state,
                trigger=RoundTrigger.READINESS_CONTINUATION,
                directives=directives,
            )
            if state.progress_key() == before:
                # The planner was asked and did nothing: every candidate for the
                # material need was already attempted, blocked, or unaffordable
                # within what remains. Asking again would produce this same
                # round, so the loop ends here rather than spinning.
                state.issues.append(
                    WorkflowIssue(
                        issue_type=WorkflowIssueType.CONTINUATION_WITHOUT_PROGRESS,
                        detail="a continuation round added no execution, result or coverage",
                        round_index=len(state.rounds) - 1,
                    )
                )
                stop_reason = self._no_progress_reason(state)
                break
            stop_reason = self._terminal_reason(analysis)
        return analysis, stop_reason

    @staticmethod
    def _wants_corroboration(
        request: InvestigationRequest, state: _RunState, stop_reason: WorkflowStopReason
    ) -> bool:
        """Only an explicit objective, only once, and only past adequate readiness.

        A run that stopped for any other reason -- blocked, exhausted, out of
        budget, nothing actionable -- has not reached the point the objective
        speaks to, and asking for a second source there would be asking for a
        first one.
        """
        return (
            request.objective is InvestigationObjective.CORROBORATE
            and not state.corroborated
            and stop_reason is WorkflowStopReason.READINESS_TERMINAL
        )

    async def _corroborate(
        self,
        request: InvestigationRequest,
        context: ExecutionContext,
        policy: PivotPolicy,
        state: _RunState,
        analysis: AnalysisPass,
        stop_reason: WorkflowStopReason,
    ) -> tuple[AnalysisPass, WorkflowStopReason | None]:
        """One bounded round seeking an independent adverse search.

        Everything about *what may be asked* is the planner's: the directives
        raise the family target of the admitted adverse-search capabilities by
        one and bar the families the verdict already rests on, and Task 13
        still ranks, refuses an attempted call, honours the blocked set and has
        to afford the call. Whether the answer really was independent is Task
        17's to settle from the returned provenance; the round's evidence is
        recomputed through every stage like any other, and if readiness then
        asks for more the ordinary continuation loop resumes. If nothing could
        be asked, the run keeps its terminal reason and says so in an issue --
        never a lower confidence, never a different verdict.
        """
        directives = corroboration_directives(analysis.fusion, admissible=state.admissible)
        if not directives:
            state.issues.append(
                WorkflowIssue(
                    issue_type=WorkflowIssueType.CORROBORATION_NOT_OBTAINED,
                    detail="no adverse-search capability is admissible at the requested depth",
                    round_index=len(state.rounds),
                )
            )
            return analysis, stop_reason
        analysis = await self._collect_and_analyse(
            request,
            context,
            policy,
            state,
            trigger=RoundTrigger.CORROBORATION,
            directives=directives,
        )
        # Obtained means a source *answered* -- with data or with none -- not
        # that the planner recorded an attempt. An unconfigured, blocked or
        # errored candidate moves the attempt count and corroborates nothing,
        # and a round that reached only such candidates must say so.
        answered = any(item.coverage_gained for item in state.enrichments[-1].attempts)
        if not answered:
            state.issues.append(
                WorkflowIssue(
                    issue_type=WorkflowIssueType.CORROBORATION_NOT_OBTAINED,
                    detail=(
                        "no eligible source independent of the assessment's basis "
                        "answered within the remaining allowance"
                    ),
                    round_index=len(state.rounds) - 1,
                )
            )
            return analysis, stop_reason
        return analysis, self._terminal_reason(analysis)

    # ------------------------------------------------------------------ #
    # One round
    # ------------------------------------------------------------------ #

    async def _collect_and_analyse(
        self,
        request: InvestigationRequest,
        context: ExecutionContext,
        policy: PivotPolicy,
        state: _RunState,
        *,
        trigger: RoundTrigger,
        directives: tuple[ContinuationDirective, ...],
    ) -> AnalysisPass:
        """Collect, then analyse everything collected so far.

        The analysis runs after the round's provider work is finished, never
        alongside it. Fusing while the same logical round still had work in
        flight would make the assessment depend on which provider happened to
        answer first.
        """
        state.session.focus = frozenset(item.capability for item in directives)
        # Per capability, never per round: a family barred from supplying an
        # independent challenge answers every other question exactly as before.
        state.session.excluded_families = {
            item.capability: item.avoid_source_families
            for item in directives
            if item.avoid_source_families
        }
        # Only a directive that says so raises the bar, and only for its own
        # capability. Task 13's default sufficiency is otherwise untouched:
        # nothing here reopens a goal that readiness did not ask about.
        state.session.additional_coverage = frozenset(
            item.capability
            for item in directives
            if item.need is ContinuationNeed.ADDITIONAL_COVERAGE
        )
        correlated = await self.correlation.run(
            self._planning_request(request, directives),
            context,
            investigation_id=state.investigation_id,
            pivot_policy=policy,
            session=state.session,
        )
        state.correlation = correlated
        state.enrichments.append(correlated.root_enrichment)
        if trigger is RoundTrigger.INITIAL:
            # Frozen once, from the round that ran under the caller's request
            # alone. Recomputing it later would let each round's own directives
            # widen the envelope they are supposed to be bounded by.
            state.admissible = frozenset(
                item.capability for item in correlated.root_enrichment.coverage
            )
        before_envelopes = len(state.envelopes)
        state.envelopes = list(state.session.envelopes())
        for attempt in correlated.root_enrichment.attempts:
            state.attempted_capabilities.add(attempt.capability.value)

        merged = merge_enrichment_results(state.enrichments)
        # One instant, taken after the round's collection finished and used by
        # all four stages, so the pass is internally consistent.
        as_of = self.clock.now()
        analysis = run_analysis_pass(
            engines=self.engines,
            as_of=as_of,
            root=request.root,
            envelopes=state.envelopes,
            graph=state.session.graph,
            planning=merged,
            purpose=self.purpose,
        )
        self._check_consistency(request, analysis)
        state.rounds.append(
            InvestigationRound(
                index=len(state.rounds),
                trigger=trigger,
                directives=directives,
                new_attempt_sequences=tuple(
                    attempt.sequence for attempt in correlated.root_enrichment.attempts
                ),
                new_provider_outcomes=len(state.envelopes) - before_envelopes,
                newly_covered_capabilities=tuple(
                    sorted(
                        {
                            attempt.capability.value
                            for attempt in correlated.root_enrichment.attempts
                        }
                    )
                ),
                graph_nodes=len(correlated.graph_nodes),
                graph_edges=len(correlated.graph_edges),
                evaluated_at=as_of,
                assessment_id=analysis.fusion.assessment.assessment_id,
                readiness_result_id=analysis.readiness.result_id,
                readiness_status=analysis.readiness.readiness_status.value,
                continuation_state=analysis.readiness.continuation_state.value,
            )
        )
        return analysis

    def _planning_request(
        self,
        request: InvestigationRequest,
        directives: tuple[ContinuationDirective, ...],
    ) -> EnrichmentPlanningRequest:
        """The Task 13 request for this round.

        Identical every round, deliberately. A continuation narrows *what is
        pursued* through the session's focus and exclusions; it never touches
        this request, because ``requested_capabilities`` is not a filter — Task
        13 turns every member into a ``REQUIRED``, ``IMMEDIATE`` goal whatever
        the depth template said. Adding a directive here would therefore do
        three things nobody asked for: create a goal the requested depth never
        admitted, activate a conditional goal whose trigger had not fired, and
        promote an optional goal to required. A continuation would then be able
        to turn QUICK into STANDARD one capability at a time.

        Directives never become provider names here either — they reach the
        planner as capabilities, and it decides who serves them.
        """
        return EnrichmentPlanningRequest(
            intel_object=request.root,
            depth=request.depth,
            requested_capabilities=request.requested_capabilities,
            operation=request.operation,
            activity_mode=request.activity_mode,
            constraints=PlanningConstraints(
                provider_allowlist=request.provider_allowlist,
                provider_denylist=request.provider_denylist,
                allow_remote_lookup=request.allow_remote_lookup,
                max_remote_provider_runs=request.max_remote_provider_runs,
            ),
        )

    # ------------------------------------------------------------------ #
    # Stopping
    # ------------------------------------------------------------------ #

    def _terminal_reason(self, analysis: AnalysisPass) -> WorkflowStopReason | None:
        """Whether readiness ended the investigation, and why.

        ``None`` means only one thing: readiness asked for more *and* said a path
        remained. Everything else stops, including the states that feel
        unfinished — READY_WITH_LIMITATIONS is terminal even with optional
        provider failures on the record, because tidying those up is spending
        budget on the workflow's discomfort rather than on the assessment.
        """
        readiness = analysis.readiness
        if wants_continuation(readiness):
            return None
        mapped = _TERMINAL_REASONS.get((readiness.readiness_status, readiness.continuation_state))
        if mapped is not None:
            return mapped
        if readiness.readiness_status is ReadinessStatus.UNRESOLVED:
            return WorkflowStopReason.READINESS_EXHAUSTED
        return WorkflowStopReason.READINESS_TERMINAL

    def _no_progress_reason(self, state: _RunState) -> WorkflowStopReason:
        """Why a continuation added nothing.

        A budget with nothing left to spend is a different situation from a
        planner that had nothing to try, and the caller can act on the first: a
        deeper or larger investigation would reach further. Preserving the
        distinction is why the workflow does not simply report NO_PROGRESS for
        both.
        """
        latest = state.enrichments[-1]
        if latest.budget.remote_remaining <= 0:
            return WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED
        return WorkflowStopReason.NO_PROGRESS

    # ------------------------------------------------------------------ #
    # Integrity
    # ------------------------------------------------------------------ #

    def _check_consistency(self, request: InvestigationRequest, analysis: AnalysisPass) -> None:
        """Every stage must be describing the same observable.

        A structural failure, raised rather than reported: an assessment of one
        object presented as an assessment of another is not a coverage
        limitation, and returning INCONCLUSIVE would make a software fault look
        like an analytical conclusion somebody could act on.
        """
        root_key = request.root.canonical_key
        if analysis.fusion.target_key != root_key:
            msg = (
                "fusion assessed a different observable: "
                f"{analysis.fusion.target_key!r} vs {root_key!r}"
            )
            raise InvestigationError(msg)
        if analysis.readiness.target_key != root_key:
            msg = (
                "readiness evaluated a different observable: "
                f"{analysis.readiness.target_key!r} vs {root_key!r}"
            )
            raise InvestigationError(msg)
        if analysis.readiness.assessment_id != analysis.fusion.assessment.assessment_id:
            msg = "readiness and fusion results come from different analysis passes"
            raise InvestigationError(msg)

    # ------------------------------------------------------------------ #
    # Result
    # ------------------------------------------------------------------ #

    def _compose(
        self,
        request: InvestigationRequest,
        state: _RunState,
        analysis: AnalysisPass,
        policy: PivotPolicy,
        stop_reason: WorkflowStopReason,
    ) -> InvestigationResult:
        """Assemble the final result from the final pass."""
        if state.correlation is None:  # pragma: no cover - a round always runs
            msg = "an investigation always performs at least one collection round"
            raise InvestigationError(msg)
        merged = merge_enrichment_results(state.enrichments)
        result = InvestigationResult(
            result_id=result_id_for(
                workflow_version=INVESTIGATION_WORKFLOW_VERSION,
                root_key=request.root.canonical_key,
                depth=request.depth,
                readiness_result_id=analysis.readiness.result_id,
                stop_reason=stop_reason,
                round_count=len(state.rounds),
            ),
            workflow_version=INVESTIGATION_WORKFLOW_VERSION,
            investigation_id=state.investigation_id,
            root=request.root,
            requested_depth=request.depth,
            pivot_mode=policy.mode.value,
            allow_remote_pivot_lookup=policy.allow_remote_pivot_lookup,
            objective=request.objective.value,
            enrichment=merged,
            correlation=state.correlation,
            qualification=analysis.qualification,
            reasoning=analysis.reasoning,
            assessment=analysis.fusion,
            readiness=analysis.readiness,
            rounds=tuple(state.rounds),
            stop_reason=stop_reason,
            issues=tuple(state.issues),
            evaluated_at=analysis.evaluated_at,
        )
        self._record(result)
        return result

    def _record(self, result: InvestigationResult) -> None:
        continued = [
            item for item in result.rounds if item.trigger is RoundTrigger.READINESS_CONTINUATION
        ]
        self.metrics.record(
            InvestigationMetric(
                workflow_stop_reason=result.stop_reason.value,
                final_verdict=result.assessment.assessment.verdict.value,
                final_confidence=result.assessment.assessment.confidence.value,
                final_readiness_status=result.readiness.readiness_status.value,
                requested_depth=result.requested_depth.value,
                rounds=len(result.rounds),
                continuation_attempted=bool(continued),
                continuation_progressed=bool(
                    continued and any(item.new_attempt_sequences for item in continued)
                ),
            )
        )
