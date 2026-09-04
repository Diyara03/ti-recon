"""What alternative-explanation reasoning returns (Task 16).

Deliberately not an assessment, and deliberately not named like one. There is no
verdict, no confidence, no score, no weight and no false-positive boolean
anywhere in this module, and a test walks the field names of every model in the
package to prove it. Task 17 owns fusion; this hands it structured material.

The most important thing this result exposes
--------------------------------------------

:attr:`FalsePositiveReasoningResult.unexplained_directional_evidence_ids`.

A layer that only reported what it *had* explained would be quietly optimistic:
the malicious evidence nobody could account for is exactly the evidence that
matters most, and it is the easiest thing to lose. So the split is computed
here, from the findings' own typed links, and neither side is labelled stronger
than the other -- the distinction is preserved, not scored.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.reasoning.false_positive.models import (
    ReasonCode,
    ReasoningFinding,
    ReasoningRole,
)

__all__ = ["FalsePositiveReasoningResult", "ReasoningCoverage"]


class ReasoningCoverage(FrozenTiReconModel):
    """What this run actually looked at, and what it produced.

    Counts only. Nothing here implies confidence: there is no "explanation
    strength", no ratio and no score, because a count of explanations is not a
    measure of doubt and would be read as one the moment it existed.
    """

    evidence_examined: int = Field(default=0, ge=0)
    #: Evidence that makes a claim rather than supplying context. The
    #: denominator that matters for "what did we fail to explain".
    directional_evidence_examined: int = Field(default=0, ge=0)
    context_signals_examined: int = Field(default=0, ge=0)
    interpretation_cues_examined: int = Field(default=0, ge=0)
    graph_relationships_examined: int = Field(default=0, ge=0)

    alternative_explanations: int = Field(default=0, ge=0)
    interpretation_limitations: int = Field(default=0, ge=0)
    analysis_quality_limitations: int = Field(default=0, ge=0)
    attribution_cautions: int = Field(default=0, ge=0)
    temporal_relevance_findings: int = Field(default=0, ge=0)
    source_dependence_findings: int = Field(default=0, ge=0)
    unresolved_tensions: int = Field(default=0, ge=0)

    #: The split Task 17 needs. Neither number is a verdict about anything.
    directional_evidence_with_explanations: int = Field(default=0, ge=0)
    directional_evidence_without_explanations: int = Field(default=0, ge=0)

    #: Rule ids that produced at least one finding, sorted. Low cardinality by
    #: construction: the set is closed and lives in the policy module.
    rules_matched: tuple[str, ...] = ()


class FalsePositiveReasoningResult(FrozenTiReconModel):
    """One investigation's alternative explanations and limitations.

    ``as_of`` is carried through from Task 15 rather than read from a clock, so a
    stored result stays re-derivable and this layer cannot become time-dependent
    in a place nothing hands it a time.
    """

    policy_version: str = Field(min_length=1, max_length=32)
    #: Task 15's policy version, kept beside this one. A finding derived from
    #: context that a later qualification policy would categorise differently is
    #: a finding somebody needs to be able to spot.
    qualification_policy_version: str = Field(min_length=1, max_length=32)
    engine_version: str = Field(min_length=1, max_length=32)
    as_of: UtcDatetime

    findings: tuple[ReasoningFinding, ...] = ()
    coverage: ReasoningCoverage = ReasoningCoverage()

    def of_role(self, role: ReasoningRole) -> tuple[ReasoningFinding, ...]:
        return tuple(item for item in self.findings if item.role is role)

    def of_reason(self, reason: ReasonCode) -> tuple[ReasoningFinding, ...]:
        return tuple(item for item in self.findings if item.reason_code is reason)

    def findings_for_evidence(self, evidence_id: str) -> tuple[ReasoningFinding, ...]:
        """Every finding that mentions one piece of evidence, in any relation."""
        return tuple(
            item for item in self.findings if any(link.ref == evidence_id for link in item.links)
        )

    @property
    def explained_evidence_ids(self) -> tuple[str, ...]:
        """Evidence some alternative explanation accounts for.

        Only explanations count. A limitation that qualifies a piece of evidence
        has not explained it, and conflating the two is how an unexplained
        detection would vanish from this set.
        """
        found: set[str] = set()
        for finding in self.findings:
            found.update(finding.explained_evidence_ids)
        return tuple(sorted(found))
