"""Capability coverage reporting (Task 3).

Coverage is a first-class output, not diagnostics. Without it, "we found
nothing" and "we could not look" are indistinguishable, and an analyst has no
way to tell a clean result from a blind spot.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import CoverageRelevance, CoverageStatus, ProviderCapability
from ti_recon.models.base import FrozenTiReconModel

__all__ = ["CoverageItem"]


class CoverageItem(FrozenTiReconModel):
    """Whether one requested capability was actually satisfied.

    ``providers_considered`` lists provider ids that could have served the
    capability, whether or not they were reachable or configured. It contains no
    credential state — only which integrations were candidates.
    """

    capability: ProviderCapability
    relevance: CoverageRelevance
    status: CoverageStatus
    providers_considered: tuple[str, ...] = ()
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _validate_coverage(self) -> CoverageItem:
        if self.status in {CoverageStatus.NOT_COVERED, CoverageStatus.PARTIAL} and not (
            self.reason
        ):
            msg = "incomplete coverage must state a reason"
            raise ValueError(msg)
        return self

    @property
    def is_gap(self) -> bool:
        """Whether this item represents a coverage gap that matters."""
        return self.relevance in {
            CoverageRelevance.REQUIRED,
            CoverageRelevance.RELEVANT,
        } and self.status in {CoverageStatus.NOT_COVERED, CoverageStatus.PARTIAL}
