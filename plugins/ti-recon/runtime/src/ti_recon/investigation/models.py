"""Workflow vocabulary and request model (Task 19).

Task 19 runs the engines Tasks 13-18 already built, in order, over one
observable. It decides *when to stop asking*, and nothing else: no verdict rule,
no coverage judgement, no provider choice. Everything in this module exists to
express that one decision and to record how it was reached.

The stop decision belongs to Task 18
------------------------------------

The workflow continues only when readiness says both that coverage is inadequate
*and* that an applicable path remains. Every other combination is terminal —
including the ones that feel unfinished. A `SUSPICIOUS` verdict is not a reason
to keep querying, and neither is an `INCONCLUSIVE` one; if more data would help,
Task 18 already says so, and if it does not, asking anyway is spending an
analyst's budget on the workflow's discomfort.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import (
    ActivityMode,
    CoverageRelevance,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.models.intel_object import IntelObject

__all__ = [
    "INVESTIGATION_WORKFLOW_VERSION",
    "RESULT_ID_LENGTH",
    "ContinuationDirective",
    "ContinuationNeed",
    "InvestigationObjective",
    "InvestigationRequest",
    "InvestigationRound",
    "RoundTrigger",
    "WorkflowIssue",
    "WorkflowIssueType",
    "WorkflowStopReason",
    "result_id_for",
]

#: Version of the workflow's *composition* semantics: stage ordering, when a
#: continuation is attempted, when it stops, how budgets carry and how the
#: result is assembled. It says nothing about the analytical policies, which
#: carry their own versions and travel on the result beside this one.
#:
#: Once 1.0.0 ships, a behavioural change here needs an explicit review: the
#: version is what tells two stored investigations apart.
INVESTIGATION_WORKFLOW_VERSION: Final[str] = "1.0.0"

RESULT_ID_LENGTH: Final[int] = 32


class InvestigationObjective(StrEnum):
    """What the caller wants the collection to stop on.

    The structured form of an analyst's intent, so nothing below the interface
    has to read prose. ``TRIAGE`` is the default and is what every existing
    caller gets: collection stops when readiness says the coverage is adequate
    for triage. ``CORROBORATE`` asks for one bounded extra round *after* that
    point -- an adverse search from a source family independent of the ones the
    assessment rests on, if one is eligible and the budget permits. It adds no
    capability, raises no depth, names no provider and never repeats a call;
    it changes only whether an adequate result is also asked to be corroborated
    before the run stops. It is never inferred from a verdict.
    """

    TRIAGE = "triage"
    CORROBORATE = "corroborate"


class RoundTrigger(StrEnum):
    """Why a round of evidence collection happened."""

    #: The investigation's first collection round.
    INITIAL = "initial"
    #: Task 18 reported a material gap with an applicable path remaining.
    READINESS_CONTINUATION = "readiness_continuation"
    #: The caller's objective asked for an independent second source after
    #: readiness was already adequate. At most one per investigation.
    CORROBORATION = "corroboration"


class WorkflowStopReason(StrEnum):
    """Why the workflow stopped asking for more.

    Deliberately says nothing about what was found. ``MALICIOUS_FOUND`` would be
    a second, competing verdict living outside Task 17, and a reader comparing
    the two would eventually find them disagreeing.
    """

    #: Readiness reached a terminal state: READY or READY_WITH_LIMITATIONS.
    READINESS_TERMINAL = "readiness_terminal"
    #: Coverage is inadequate and every material path is currently unusable.
    READINESS_BLOCKED = "readiness_blocked"
    #: Coverage is inadequate and no applicable source remains.
    READINESS_EXHAUSTED = "readiness_exhausted"
    #: A material need remains and this investigation's budget cannot fund it.
    #: A larger investigation could; this one may not grant itself one.
    CURRENT_BUDGET_EXHAUSTED = "current_budget_exhausted"
    #: Readiness asked for more, and nothing it asked for names a capability the
    #: workflow could legitimately request.
    NO_ACTIONABLE_CONTINUATION = "no_actionable_continuation"
    #: A continuation ran and added nothing: no attempt, no outcome, no coverage.
    #: Asking again would produce the same nothing.
    NO_PROGRESS = "no_progress"


class WorkflowIssueType(StrEnum):
    """Problems with the workflow itself, never with the intelligence."""

    #: Readiness claimed a path remained, and none of its needs named a
    #: capability. Recorded rather than guessed at.
    UNACTIONABLE_INFORMATION_NEED = "unactionable_information_need"
    #: A continuation round produced no new execution or coverage.
    CONTINUATION_WITHOUT_PROGRESS = "continuation_without_progress"
    #: The caller asked for corroboration and no independent eligible source
    #: could be asked: nothing admissible, nothing unattempted, or no budget.
    CORROBORATION_NOT_OBTAINED = "corroboration_not_obtained"


class WorkflowIssue(FrozenTiReconModel):
    """One workflow-level problem, recorded rather than swallowed."""

    issue_type: WorkflowIssueType
    detail: str = Field(min_length=1, max_length=300)
    round_index: int = Field(ge=0)


class InvestigationRequest(FrozenTiReconModel):
    """One investigation of one canonical observable.

    The root arrives already canonical. Turning ``"example.com"`` into an
    ``IntelObject`` is an interface concern — a CLI or an API decides what a
    user's string meant, and hands the domain layer something validated.

    ``depth`` and ``pivot_mode`` are ceilings the workflow may never raise. A
    readiness continuation asks for information *within* what was permitted; it
    cannot decide the investigation should have been deeper, or that pivots the
    caller declined are now worth running.
    """

    root: IntelObject
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    requested_capabilities: frozenset[ProviderCapability] = frozenset()
    #: What to stop on. ``TRIAGE`` stops when readiness is adequate;
    #: ``CORROBORATE`` spends at most one more round on an independent adverse
    #: search after that, if one is eligible and affordable.
    objective: InvestigationObjective = InvestigationObjective.TRIAGE
    #: Passed to Task 13 unchanged. ``max_remote_provider_runs`` there is
    #: reduction-only, which is what makes an investigation-wide budget safe.
    max_remote_provider_runs: int | None = Field(default=None, ge=0)
    allow_remote_lookup: bool = True
    provider_allowlist: frozenset[str] = frozenset()
    provider_denylist: frozenset[str] = frozenset()

    #: Whether the workflow may act on readiness at all. With continuation off,
    #: the investigation is exactly one collection round and one analysis pass.
    allow_readiness_continuation: bool = True

    @property
    def operation(self) -> ProviderOperation:
        """Always a passive lookup. Task 13 refuses to build anything else."""
        return ProviderOperation.LOOKUP

    @property
    def activity_mode(self) -> ActivityMode:
        """Always passive. No path from this workflow reaches an active action."""
        return ActivityMode.PASSIVE


class ContinuationNeed(StrEnum):
    """What kind of shortfall a directive is asking Task 13 to address.

    Two genuinely different requests, and collapsing them into one would either
    never obtain additional breadth or would quietly re-ask for everything.
    """

    #: Nobody has answered this capability yet. Ordinary planning handles it.
    MISSING_COVERAGE = "missing_coverage"
    #: Somebody answered, and Task 13's own goal is numerically satisfied, but a
    #: higher-layer requirement needs another eligible source. The capability
    #: was always admissible and active; only how much coverage is enough has
    #: changed, and only for this round.
    ADDITIONAL_COVERAGE = "additional_coverage"


class ContinuationDirective(FrozenTiReconModel):
    """One thing the workflow will ask Task 13 to try to find out.

    A *capability*, never a provider. Which source can serve it, whether one is
    configured, what it costs and whether it is worth the remaining budget are
    all Task 13's questions, answered with a catalogue and a ranking this layer
    does not have and must not imitate.

    ``avoid_source_families`` is a planning hint, not a claim. Readiness may need
    a search independent of the origin behind a benign assessment, and the only
    thing knowable before a call is which family a provider belongs to. Whether
    the answer *turns out* to be independent is decided afterwards, by Task 17,
    from the provenance the response actually carried.
    """

    requirement_id: str = Field(min_length=8, max_length=64)
    capability: ProviderCapability
    need: ContinuationNeed = ContinuationNeed.MISSING_COVERAGE
    criticality: CoverageRelevance
    reason: str = Field(min_length=1, max_length=64)
    avoid_source_families: frozenset[str] = frozenset()


class InvestigationRound(FrozenTiReconModel):
    """What one collection-and-analysis round did.

    References rather than copies. The evidence lives once, in the accumulated
    enrichment view and the graph; a round says what it added and which analysis
    it produced.
    """

    index: int = Field(ge=0)
    trigger: RoundTrigger
    directives: tuple[ContinuationDirective, ...] = ()
    #: Attempts recorded by this round, by their planner sequence numbers.
    new_attempt_sequences: tuple[int, ...] = ()
    new_provider_outcomes: int = Field(default=0, ge=0)
    #: Capabilities this round newly covered or partly covered.
    newly_covered_capabilities: tuple[str, ...] = ()
    graph_nodes: int = Field(default=0, ge=0)
    graph_edges: int = Field(default=0, ge=0)
    #: The instant Tasks 15-18 were evaluated against for this round.
    evaluated_at: UtcDatetime
    assessment_id: str = Field(min_length=8, max_length=64)
    readiness_result_id: str = Field(min_length=8, max_length=64)
    readiness_status: str = Field(min_length=1, max_length=32)
    continuation_state: str = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def _initial_round_has_no_directives(self) -> InvestigationRound:
        if self.index == 0 and self.trigger is not RoundTrigger.INITIAL:
            msg = "the first round is the initial one"
            raise ValueError(msg)
        if self.trigger is RoundTrigger.INITIAL and self.directives:
            msg = "the initial round is not driven by directives"
            raise ValueError(msg)
        return self


def result_id_for(
    *,
    workflow_version: str,
    root_key: str,
    depth: InvestigationDepth,
    readiness_result_id: str,
    stop_reason: WorkflowStopReason,
    round_count: int,
) -> str:
    """The investigation's record identity.

    **Record identity, not a cross-run semantic fingerprint.** It incorporates
    the readiness result id, which incorporates the Task 17 assessment id, which
    is built over ``Evidence.id`` — a UUID minted when the evidence was
    collected. So this is deterministic for one stored investigation and differs
    across fresh collections of the same intelligence, exactly as every id below
    it does. A durable cross-run fingerprint would need semantic identities all
    the way down and is a later product concern.
    """
    material = "|".join(
        (
            workflow_version,
            root_key,
            depth.value,
            readiness_result_id,
            stop_reason.value,
            str(round_count),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:RESULT_ID_LENGTH]
