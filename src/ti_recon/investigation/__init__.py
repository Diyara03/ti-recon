"""End-to-end investigation orchestration (Task 19).

Composes the engines Tasks 13-18 already built into one bounded, reproducible
workflow:

    Task 13 planning + execution, correlated by Task 14
        -> Task 15 temporal and context qualification
        -> Task 16 alternative-explanation reasoning
        -> Task 17 evidence fusion and assessment
        -> Task 18 readiness and coverage adequacy
        -> optionally ask Task 13 for what readiness said was missing

Task 19 decides *when to stop asking* and nothing else. It contains no
maliciousness rule, no coverage judgement and no provider choice — every one of
those belongs to a layer that already models it properly.

What it will not do
-------------------

It never selects a provider (Task 13 does, from the catalogue and the ranking),
never escalates depth or pivot mode past what the caller permitted, never grants
itself more budget, never repeats a call it has already made, and never converts
a cancellation into a provider failure. Provider failures are analytical inputs;
structural faults are raised, because returning INCONCLUSIVE would dress a
software error as a conclusion somebody could act on.

It is transport-neutral: no HTTP, no CLI, no MCP, no persistence. A future
interface wraps it. Everything one invocation needs arrives in the request, the
execution scope and the injected dependencies, so a stateless caller can invoke
it cleanly — but nothing survives the call, and no resumability is claimed.
"""

from ti_recon.investigation.analysis import (
    AnalysisPass,
    ReasoningEngines,
    run_analysis_pass,
)
from ti_recon.investigation.continuation import (
    benign_basis_families,
    directives_for,
    wants_continuation,
)
from ti_recon.investigation.engine import (
    InvestigationError,
    InvestigationOrchestrator,
)
from ti_recon.investigation.merge import MergeConflictError, merge_enrichment_results
from ti_recon.investigation.metrics import (
    InMemoryInvestigationMetricsSink,
    InvestigationMetric,
    InvestigationMetricsSink,
    NoOpInvestigationMetricsSink,
)
from ti_recon.investigation.models import (
    INVESTIGATION_WORKFLOW_VERSION,
    ContinuationDirective,
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

__all__ = [
    "INVESTIGATION_WORKFLOW_VERSION",
    "AnalysisPass",
    "ContinuationDirective",
    "InMemoryInvestigationMetricsSink",
    "InvestigationError",
    "InvestigationMetric",
    "InvestigationMetricsSink",
    "InvestigationObjective",
    "InvestigationOrchestrator",
    "InvestigationRequest",
    "InvestigationResult",
    "InvestigationRound",
    "MergeConflictError",
    "NoOpInvestigationMetricsSink",
    "ReasoningEngines",
    "RoundTrigger",
    "WorkflowIssue",
    "WorkflowIssueType",
    "WorkflowStopReason",
    "benign_basis_families",
    "directives_for",
    "merge_enrichment_results",
    "result_id_for",
    "run_analysis_pass",
    "wants_continuation",
]
