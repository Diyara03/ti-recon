"""The readiness result (Task 18).

References the Task 17 assessment rather than restating it. The verdict and
confidence appear here as *copies for reading*, never as values this layer
computed or may recompute: an analyst looking at readiness should see the
assessment it is about without having to hold two objects side by side, and a
reader should never be in doubt about which layer decided what.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.enums import InvestigationDepth, Verdict
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.reasoning.fusion.models import AssessmentConfidence
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    CoverageAdequacy,
    InformationNeed,
    ReadinessCoverageSummary,
    ReadinessGap,
    ReadinessLimitation,
    ReadinessPurpose,
    ReadinessStatus,
    RequirementEvaluation,
)

__all__ = ["AssessmentReadinessResult", "ReadinessPolicyVersions"]


class ReadinessPolicyVersions(FrozenTiReconModel):
    """Every policy that shaped this answer, carried together.

    Readiness depends on Task 15's qualification, Task 16's explanations and
    Task 17's fusion as much as on its own rules, so a stored result records all
    four. Without them a re-derivation years later could not tell whether a
    different answer meant different evidence or different policy.
    """

    readiness_policy_version: str = Field(min_length=1, max_length=32)
    fusion_policy_version: str = Field(min_length=1, max_length=32)
    claim_semantics_policy_version: str = Field(min_length=1, max_length=32)
    false_positive_policy_version: str = Field(min_length=1, max_length=32)
    qualification_policy_version: str = Field(min_length=1, max_length=32)


class AssessmentReadinessResult(FrozenTiReconModel):
    """Whether the collection behind an assessment was adequate for a purpose.

    Two axes plus a derived headline, the requirement-by-requirement working, the
    gaps that matter and what would address them. No score, no percentage, no
    severity, no priority and no action -- see the package docstring for why each
    of those is absent rather than merely unimplemented.
    """

    result_id: str = Field(min_length=8, max_length=32)
    purpose: ReadinessPurpose
    target_key: str = Field(min_length=1, max_length=512)
    requested_depth: InvestigationDepth

    readiness_status: ReadinessStatus
    coverage_adequacy: CoverageAdequacy
    continuation_state: ContinuationState

    requirement_evaluations: tuple[RequirementEvaluation, ...] = ()
    gaps: tuple[ReadinessGap, ...] = ()
    information_needs: tuple[InformationNeed, ...] = ()
    limitations: tuple[ReadinessLimitation, ...] = ()

    #: The Task 17 assessment this is about.
    assessment_id: str = Field(min_length=8, max_length=32)
    #: Copied for reading. Never recomputed here, and never adjusted: an
    #: incomplete investigation does not make a correct assessment less correct.
    verdict: Verdict
    confidence: AssessmentConfidence
    verdict_rule_id: str = Field(min_length=1, max_length=128)

    coverage_summary: ReadinessCoverageSummary
    policy_versions: ReadinessPolicyVersions
    #: Task 15's instant, carried through. Nothing in this layer reads a clock,
    #: so the same inputs answer identically forever.
    evaluated_at: UtcDatetime
