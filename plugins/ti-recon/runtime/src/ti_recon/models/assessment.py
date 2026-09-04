"""Assessment models (Task 3) -- **legacy; superseded by Task 17.**

These models were the Task 3 sketch of what a conclusion would have to look like,
written before there was an engine to produce one. They are retained for
backward compatibility and are exercised only by their own model tests.

**The authoritative assessment is**
:class:`ti_recon.reasoning.fusion.models.FusionAssessment`, returned inside a
:class:`ti_recon.reasoning.fusion.results.FusionResult`. New code -- Task 18
decision readiness, the MCP layer and any future interface included -- consumes
that and not these.

The two models disagree about something substantive, which is why one replaced
the other rather than wrapping it. :class:`Assessment` requires a numeric
``risk_score`` and a 0-100 ``confidence``, and :class:`AssessmentContribution`
multiplies four factors into an ``effective_contribution``. Task 17 concluded
that no such number is measurable here: there is no calibration set behind a
weight, and a figure like 73 reads as a probability nobody computed. Fusion
therefore emits a named verdict, a named confidence band, and the rule id that
chose each -- and its policy modules are tested to contain no arithmetic at all.

Nothing in this module computes anything, and nothing under
``ti_recon/reasoning/claims`` or ``ti_recon/reasoning/fusion`` imports it; a
boundary test pins that.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import AssessmentState, ContributionRole, Verdict
from ti_recon.models.base import (
    FrozenTiReconModel,
    Identifier,
    TiReconModel,
    UtcDatetime,
    new_id,
    utc_now,
)
from ti_recon.models.coverage import CoverageItem

__all__ = ["Assessment", "AssessmentContribution"]


class Assessment(TiReconModel):
    """The conclusion of an investigation.

    Evidence is referenced by role rather than merged into a score, so an
    analyst can always ask "which observations pushed this to malicious?" and
    get a list back. ``coverage`` travels with the verdict because a verdict
    without its blind spots is misleading.
    """

    id: Identifier = Field(default_factory=new_id)
    investigation_id: Identifier
    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=100.0)
    assessment_state: AssessmentState
    supporting_evidence_refs: tuple[Identifier, ...] = ()
    benign_evidence_refs: tuple[Identifier, ...] = ()
    context_evidence_refs: tuple[Identifier, ...] = ()
    conflict_refs: tuple[Identifier, ...] = ()
    coverage: tuple[CoverageItem, ...] = ()
    policy_version: str = Field(min_length=1, max_length=64)
    engine_version: str = Field(min_length=1, max_length=64)
    assessed_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_assessment(self) -> Assessment:
        roles = {
            "supporting": set(self.supporting_evidence_refs),
            "benign": set(self.benign_evidence_refs),
            "context": set(self.context_evidence_refs),
        }
        names = list(roles)
        for index, first in enumerate(names):
            for second in names[index + 1 :]:
                overlap = roles[first] & roles[second]
                if overlap:
                    msg = (
                        f"evidence cannot be both {first} and {second} in one "
                        f"assessment ({len(overlap)} overlapping reference(s))"
                    )
                    raise ValueError(msg)
        return self

    @property
    def coverage_gaps(self) -> tuple[CoverageItem, ...]:
        """Coverage items that a reader of this verdict needs to know about."""
        return tuple(item for item in self.coverage if item.is_gap)


class AssessmentContribution(FrozenTiReconModel):
    """How one piece of evidence influenced one assessment.

    This is the interpretation layer and is kept separate from ``Evidence`` on
    purpose: the same fact can contribute differently under a different policy
    version, and recomputing an interpretation must never rewrite the fact.

    ``base_strength`` is what the claim would be worth on its own. The four
    factors are dampeners in ``[0, 1]``:

    * ``freshness_factor`` — how much the claim's age discounts it;
    * ``independence_factor`` — discounted when the evidence shares lineage
      with other evidence already counted;
    * ``specificity_factor`` — discounted when the claim's match scope is
      broader than the object under investigation;
    * ``false_positive_factor`` — discounted by known false-positive context.

    Because every factor is a dampener, ``effective_contribution`` can never
    exceed ``base_strength``; that invariant is enforced.
    """

    id: Identifier = Field(default_factory=new_id)
    assessment_id: Identifier
    evidence_id: Identifier
    role: ContributionRole

    base_strength: float = Field(ge=0.0, le=100.0)

    freshness_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    independence_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    specificity_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    false_positive_factor: float = Field(default=1.0, ge=0.0, le=1.0)

    effective_contribution: float = Field(ge=0.0, le=100.0)

    reason_codes: tuple[str, ...] = ()
    computed_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_contribution(self) -> AssessmentContribution:
        # Floating point tolerance: the check exists to catch a policy that
        # amplifies evidence, not to police rounding.
        if self.effective_contribution > self.base_strength + 1e-9:
            msg = "effective_contribution must not exceed base_strength"
            raise ValueError(msg)
        if self.role is ContributionRole.CONTEXT and self.effective_contribution != 0.0:
            msg = "context contributions must not move the score"
            raise ValueError(msg)
        return self

    @property
    def combined_factor(self) -> float:
        """Product of the four dampening factors."""
        return (
            self.freshness_factor
            * self.independence_factor
            * self.specificity_factor
            * self.false_positive_factor
        )
