"""What fusion returns (Task 17).

The assessment is the headline; the rest of this model exists so the headline can
be argued with. Every claim that mattered, the proposition it asserted, which
sources were genuinely separate, which claims Task 16 explained and -- the field
that matters most -- which malicious claims nothing explained.

Nothing here carries a score, a weight or a probability, and a test walks the
field names of every model in the package to keep it that way.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel
from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.fusion.models import (
    ClaimContribution,
    ClaimDisposition,
    ContributionRole,
    CorroborationGroup,
    FusionAssessment,
    FusionConflict,
    FusionIssue,
    PropositionGroup,
)

__all__ = ["FusionCoverage", "FusionResult"]


class FusionCoverage(FrozenTiReconModel):
    """What this run examined and what it produced.

    Counts, and deliberately not a ratio. "Three of four malicious claims were
    explained" invites reading 75% as a confidence, which is exactly the
    arithmetic this layer refuses; the two absolute numbers say the same thing
    without inviting the multiplication.
    """

    directional_evidence_examined: int = Field(default=0, ge=0)
    claims_normalized: int = Field(default=0, ge=0)
    #: Directional claims nothing could classify. Visible, never decisive.
    claims_unclassified: int = Field(default=0, ge=0)
    propositions: int = Field(default=0, ge=0)
    #: Independent origins across every proposition. Provenance structure, never
    #: compared as a tally.
    independent_support_groups: int = Field(default=0, ge=0)

    explained_directional_claims: int = Field(default=0, ge=0)
    #: The number that matters: malicious support nothing accounted for.
    unexplained_directional_claims: int = Field(default=0, ge=0)
    benign_directional_claims: int = Field(default=0, ge=0)
    conflicts: int = Field(default=0, ge=0)
    partial_sources: int = Field(default=0, ge=0)

    reasoning_findings_consumed: int = Field(default=0, ge=0)
    graph_relationships_examined: int = Field(default=0, ge=0)


class FusionResult(FrozenTiReconModel):
    """One investigation's assessment, and everything behind it."""

    target_key: str = Field(min_length=1, max_length=700)
    assessment: FusionAssessment

    normalized_claims: tuple[NormalizedClaim, ...] = ()
    proposition_groups: tuple[PropositionGroup, ...] = ()
    corroboration_groups: tuple[CorroborationGroup, ...] = ()
    conflicts: tuple[FusionConflict, ...] = ()
    contributions: tuple[ClaimContribution, ...] = ()
    issues: tuple[FusionIssue, ...] = ()
    coverage: FusionCoverage = FusionCoverage()

    @property
    def explained_evidence_ids(self) -> tuple[str, ...]:
        """Evidence a Task 16 alternative explanation specifically accounted for."""
        return tuple(
            sorted(
                {
                    item.evidence_id
                    for item in self.contributions
                    if item.disposition is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
                }
            )
        )

    @property
    def unexplained_directional_evidence_ids(self) -> tuple[str, ...]:
        """Directional evidence nothing accounted for.

        What Task 18 and an analyst both need first. Computed from the
        contributions' own dispositions rather than tracked alongside them, so it
        cannot drift from what the assessment actually relied on.
        """
        return tuple(
            sorted(
                {
                    item.evidence_id
                    for item in self.contributions
                    if item.disposition
                    in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
                }
            )
        )

    def contributions_with_role(self, role: ContributionRole) -> tuple[ClaimContribution, ...]:
        return tuple(item for item in self.contributions if item.role is role)

    def claim(self, claim_id: str) -> NormalizedClaim | None:
        for item in self.normalized_claims:
            if item.claim_id == claim_id:
                return item
        return None
