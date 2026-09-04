"""What one complete investigation produced (Task 19).

References rather than copies. The evidence exists once — inside the accumulated
enrichment view and the graph — and everything else points at it. Duplicating
provider data into several places is how two copies of the same investigation
start to disagree.

One consistent final pass
-------------------------

The four analytical results are the outputs of the *same* final reasoning pass,
carried together. Earlier rounds' identities live in the round trace, where they
describe that round. Nothing here lets a caller pair a Task 16 result from one
round with a Task 17 result from another and believe it is looking at an
assessment somebody actually reached.

Deliberately absent: any narrative, any recommendation, any severity, any score.
The result is structured input for an interface layer, and what a reader should
*do* about it depends on an environment this engine has never seen.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.correlation.results import CorrelatedEnrichmentResult
from ti_recon.enums import InvestigationDepth
from ti_recon.investigation.models import (
    InvestigationRound,
    WorkflowIssue,
    WorkflowStopReason,
)
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning.models import AdaptiveEnrichmentResult
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.results import AssessmentReadinessResult
from ti_recon.reasoning.results import TemporalContextResult

__all__ = ["InvestigationResult"]


class InvestigationResult(FrozenTiReconModel):
    """One observable, investigated end to end."""

    result_id: str = Field(min_length=8, max_length=32)
    workflow_version: str = Field(min_length=1, max_length=32)
    investigation_id: str = Field(min_length=1, max_length=128)

    root: IntelObject
    requested_depth: InvestigationDepth
    pivot_mode: str = Field(min_length=1, max_length=32)
    #: Whether an enriching pivot was permitted to reach external providers.
    #:
    #: Recorded beside the mode because the two together are what decided
    #: disclosure: Task 14 gates remote pivot enrichment on both, so a result
    #: carrying only the mode cannot say whether anything about a related
    #: observable actually left the machine.
    allow_remote_pivot_lookup: bool = False

    #: Everything executed and covered, across every round.
    enrichment: AdaptiveEnrichmentResult
    #: The graph and pivot outcome as of the final round.
    correlation: CorrelatedEnrichmentResult

    #: The final pass. All four share one ``evaluated_at`` and one accumulated
    #: state; they are not independently replaceable.
    qualification: TemporalContextResult
    reasoning: FalsePositiveReasoningResult
    assessment: FusionResult
    readiness: AssessmentReadinessResult

    rounds: tuple[InvestigationRound, ...] = ()
    stop_reason: WorkflowStopReason
    issues: tuple[WorkflowIssue, ...] = ()

    #: The instant the final reasoning pass was evaluated against.
    evaluated_at: UtcDatetime
