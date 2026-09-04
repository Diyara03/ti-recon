"""Assessment readiness and coverage adequacy (Task 18).

Task 17 says what assessment the evidence justifies. Task 18 asks whether the
collection behind it was adequate — and these are genuinely different questions:

* ``MALICIOUS`` at ``HIGH`` confidence with no behavioural coverage is a correct
  assessment of an incomplete investigation. The confidence stays ``HIGH``; the
  missing coverage is recorded as a limitation.
* ``LIKELY_BENIGN`` from one unopposed assertion is a correct assessment nobody
  has tried to contradict. The verdict stands; readiness says an independent
  adverse search has not run.
* ``INCONCLUSIVE`` with every applicable source already asked is a finished
  search with an unresolved question — ``UNRESOLVED``, never ``READY``.

Five distinctions the layer exists to keep
------------------------------------------

* **verdict is not readiness** — one is about the observable, one about the run;
* **confidence is not completeness** — correctness and collection are separate;
* **NO_DATA is not NOT_RUN** — a source that answered "nothing known" completed
  its check, and that is not evidence of safety either;
* **EXHAUSTED is not ADEQUATE** — asking everything available and learning
  nothing does not resolve the question;
* **a provider failure is not a gap** — it matters only when it prevents a
  *material* requirement from being met.

What is deliberately absent: no score, no percentage, no severity, no priority,
no risk number, and no action. TI Recon does not know asset criticality, business
impact, user context or incident policy, so v1 answers for exactly one purpose —
:attr:`ReadinessPurpose.ANALYST_TRIAGE` — and says so.
"""

from ti_recon.reasoning.readiness.coverage import (
    STATUS_COMPLETION,
    capability_checks,
    completion_for,
    independent_families,
    yield_for,
)
from ti_recon.reasoning.readiness.engine import (
    AssessmentReadinessEngine,
    ReadinessInputMismatch,
)
from ti_recon.reasoning.readiness.gaps import (
    gaps_from_evaluations,
    information_needs_from_gaps,
    outlook_for,
)
from ti_recon.reasoning.readiness.metrics import (
    InMemoryReadinessMetricsSink,
    NoOpReadinessMetricsSink,
    ReadinessMetric,
    ReadinessMetricsSink,
)
from ti_recon.reasoning.readiness.models import (
    CheckCompletion,
    ContinuationState,
    CoverageAdequacy,
    CoverageRequirement,
    GapOutlook,
    GapType,
    InformationNeed,
    InformationYield,
    ReadinessCoverageSummary,
    ReadinessGap,
    ReadinessLimitation,
    ReadinessPurpose,
    ReadinessStatus,
    RequirementActivation,
    RequirementEvaluation,
    RequirementStatus,
    SourceCheck,
    gap_id_for,
    readiness_id_for,
    requirement_id_for,
)
from ti_recon.reasoning.readiness.policy import (
    DIRECTIONAL_SEARCH_CAPABILITIES,
    READINESS_POLICY_VERSION,
    STRONG_BASIS_RULES,
    adequacy_for,
    continuation_for,
    is_material,
    requires_independent_challenge,
    status_for,
)
from ti_recon.reasoning.readiness.requirements import (
    EvaluationInputs,
    activation_for,
    evaluate_requirement,
    requirements_from_goals,
)
from ti_recon.reasoning.readiness.results import (
    AssessmentReadinessResult,
    ReadinessPolicyVersions,
)

__all__ = [
    "DIRECTIONAL_SEARCH_CAPABILITIES",
    "READINESS_POLICY_VERSION",
    "STATUS_COMPLETION",
    "STRONG_BASIS_RULES",
    "AssessmentReadinessEngine",
    "AssessmentReadinessResult",
    "CheckCompletion",
    "ContinuationState",
    "CoverageAdequacy",
    "CoverageRequirement",
    "EvaluationInputs",
    "GapOutlook",
    "GapType",
    "InMemoryReadinessMetricsSink",
    "InformationNeed",
    "InformationYield",
    "NoOpReadinessMetricsSink",
    "ReadinessCoverageSummary",
    "ReadinessGap",
    "ReadinessInputMismatch",
    "ReadinessLimitation",
    "ReadinessMetric",
    "ReadinessMetricsSink",
    "ReadinessPolicyVersions",
    "ReadinessPurpose",
    "ReadinessStatus",
    "RequirementActivation",
    "RequirementEvaluation",
    "RequirementStatus",
    "SourceCheck",
    "activation_for",
    "adequacy_for",
    "capability_checks",
    "completion_for",
    "continuation_for",
    "evaluate_requirement",
    "gap_id_for",
    "gaps_from_evaluations",
    "independent_families",
    "information_needs_from_gaps",
    "is_material",
    "outlook_for",
    "readiness_id_for",
    "requirement_id_for",
    "requirements_from_goals",
    "requires_independent_challenge",
    "status_for",
    "yield_for",
]
