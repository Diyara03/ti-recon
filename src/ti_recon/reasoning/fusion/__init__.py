"""Evidence fusion and final assessment (Task 17).

The first layer allowed to reach a verdict. Everything below it deliberately
refused to: Task 15 qualified evidence in time and context, Task 16 asked whether
context explained it, and both avoided producing a number somebody downstream
would read instead of reasoning.

Five rules shape it:

* **Fusion reasons over propositions, not providers.** A claim says what a
  finding asserts; corroboration requires compatible propositions, so "this
  address scans the internet" can never vouch for "this address is a C2".
* **Providers are never counted.** Five sources repeating one upstream feed is
  one origin. Independence comes from lineage and originating family, and a
  relayed finding stays visible while contributing no second voice.
* **Specificity beats popularity.** One curated repository holding this exact
  file outweighs five providers agreeing it looks bad, so a single decisive claim
  can reach MALICIOUS and a single generic reputation claim cannot.
* **Only Task 16 EXPLAINS links remove support.** An attribution caution, a
  temporal note and an analysis-quality limitation are cautions, not
  explanations, and treating one as an explanation would clear real evidence.
* **Verdict and confidence are separate decisions.** Confidence says how sure we
  are the assessment is right, never how malicious the object is, and MALICIOUS
  at MEDIUM is an ordinary thing to say.

No score, no weight, no probability, no risk number, no action recommendation,
and no network.
"""

from ti_recon.reasoning.fusion.confidence import decide_confidence
from ti_recon.reasoning.fusion.dispositions import (
    dispositions_for,
    explained_evidence_ids,
    findings_touching,
    limiting_findings,
)
from ti_recon.reasoning.fusion.engine import EvidenceFusionEngine
from ti_recon.reasoning.fusion.independence import (
    breadth_of,
    group_key_for,
    independence_groups,
)
from ti_recon.reasoning.fusion.metrics import (
    FusionMetric,
    FusionMetricsSink,
    InMemoryFusionMetricsSink,
    NoOpFusionMetricsSink,
)
from ti_recon.reasoning.fusion.models import (
    ASSESSMENT_ID_LENGTH,
    STIX_CONFIDENCE,
    AssessmentConfidence,
    ClaimContribution,
    ClaimDecisionRole,
    ClaimDisposition,
    ContributionRole,
    CorroborationGroup,
    FusionAssessment,
    FusionConflict,
    FusionIssue,
    FusionIssueType,
    IndependenceGroup,
    PropositionGroup,
    SupportBreadth,
    assessment_id_for,
)
from ti_recon.reasoning.fusion.policy import (
    CONFIDENCE_CAPS,
    CONFIDENCE_RULES,
    DECISIVE_SEMANTICS,
    FUSION_POLICY_VERSION,
    REASON_CODES,
    VERDICT_RULES,
    WEAK_SEMANTICS,
    decision_role_for,
    is_benign_basis,
    is_decisive_basis,
)
from ti_recon.reasoning.fusion.results import FusionCoverage, FusionResult

__all__ = [
    "ASSESSMENT_ID_LENGTH",
    "CONFIDENCE_CAPS",
    "CONFIDENCE_RULES",
    "DECISIVE_SEMANTICS",
    "FUSION_POLICY_VERSION",
    "REASON_CODES",
    "STIX_CONFIDENCE",
    "VERDICT_RULES",
    "WEAK_SEMANTICS",
    "AssessmentConfidence",
    "ClaimContribution",
    "ClaimDecisionRole",
    "ClaimDisposition",
    "ContributionRole",
    "CorroborationGroup",
    "EvidenceFusionEngine",
    "FusionAssessment",
    "FusionConflict",
    "FusionCoverage",
    "FusionIssue",
    "FusionIssueType",
    "FusionMetric",
    "FusionMetricsSink",
    "FusionResult",
    "InMemoryFusionMetricsSink",
    "IndependenceGroup",
    "NoOpFusionMetricsSink",
    "PropositionGroup",
    "SupportBreadth",
    "assessment_id_for",
    "breadth_of",
    "decide_confidence",
    "decision_role_for",
    "dispositions_for",
    "explained_evidence_ids",
    "findings_touching",
    "group_key_for",
    "independence_groups",
    "is_benign_basis",
    "is_decisive_basis",
    "limiting_findings",
]
