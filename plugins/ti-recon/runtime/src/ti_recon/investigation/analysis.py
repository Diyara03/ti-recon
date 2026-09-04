"""One reasoning pass over the whole investigation (Task 19).

Tasks 15 through 18 run in one fixed order, over everything collected so far,
against one instant. The sequence exists in exactly one place so a continuation
cannot accidentally run a different one — and so nobody can be tempted to skip a
stage because the answer looks obvious. Task 16 must ask whether the evidence has
an alternative reading even when the verdict seems certain; that is precisely
when it matters.

Recompute, never patch
----------------------

After new evidence arrives the pure engines run again over the accumulated state.
Nothing is edited in place. A patched verdict is a verdict nobody can re-derive,
and the engines are cheap, deterministic and side-effect free — re-running them
is both safer and simpler than reasoning about which conclusions a new claim
might have invalidated.

One instant per pass
--------------------

Task 15 requires an explicit timezone-aware ``as_of`` and reads no clock. The
same instant flows through all four stages of one pass, so the pass is internally
consistent; a later continuation gets its own instant, and the final result
records the one its final pass used.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.models.intel_object import IntelObject
from ti_recon.planning.models import AdaptiveEnrichmentResult
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.engine import TemporalContextEngine
from ti_recon.reasoning.false_positive.engine import FalsePositiveReasoningEngine
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.fusion.engine import EvidenceFusionEngine
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.engine import AssessmentReadinessEngine
from ti_recon.reasoning.readiness.models import ReadinessPurpose
from ti_recon.reasoning.readiness.results import AssessmentReadinessResult
from ti_recon.reasoning.results import TemporalContextResult

__all__ = ["AnalysisPass", "ReasoningEngines", "run_analysis_pass"]


@dataclass(frozen=True)
class ReasoningEngines:
    """The four pure engines one pass needs, injected rather than constructed."""

    temporal: TemporalContextEngine
    false_positive: FalsePositiveReasoningEngine
    fusion: EvidenceFusionEngine
    readiness: AssessmentReadinessEngine


@dataclass(frozen=True)
class AnalysisPass:
    """Everything one reasoning pass produced, from one instant.

    Held together deliberately. Pairing a Task 16 result from one round with a
    Task 17 result from another would be an assessment nobody actually reached,
    and keeping the four in one object makes that combination awkward to express
    rather than merely discouraged.
    """

    evaluated_at: datetime
    qualification: TemporalContextResult
    reasoning: FalsePositiveReasoningResult
    fusion: FusionResult
    readiness: AssessmentReadinessResult


def run_analysis_pass(
    *,
    engines: ReasoningEngines,
    as_of: datetime,
    root: IntelObject,
    envelopes: Sequence[ProviderResultEnvelope],
    graph: InvestigationGraph | None,
    planning: AdaptiveEnrichmentResult,
    purpose: ReadinessPurpose = ReadinessPurpose.ANALYST_TRIAGE,
) -> AnalysisPass:
    """Task 15 -> 16 -> 17 -> 18, over the accumulated investigation.

    Called once per round and nowhere else. Every stage sees the *whole*
    investigation rather than the latest delta: a claim collected in round one
    still qualifies, still explains, still fuses and still counts as coverage in
    round two, and an assessment built from only the newest evidence would be an
    assessment of a fragment.
    """
    qualification = engines.temporal.evaluate(
        as_of=as_of, results=envelopes, graph=graph, root=root
    )
    reasoning = engines.false_positive.evaluate(
        qualification=qualification, results=envelopes, graph=graph, root=root
    )
    fusion = engines.fusion.evaluate(
        qualification=qualification,
        reasoning=reasoning,
        results=envelopes,
        graph=graph,
        root=root,
    )
    readiness = engines.readiness.evaluate(
        fusion=fusion,
        planning=planning,
        qualification=qualification,
        reasoning=reasoning,
        purpose=purpose,
    )
    return AnalysisPass(
        evaluated_at=as_of,
        qualification=qualification,
        reasoning=reasoning,
        fusion=fusion,
        readiness=readiness,
    )
