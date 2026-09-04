"""Capability coverage goals (Task 13).

Planning is expressed as *what is still missing*, never as *who has not been
called yet*. The planner asks "is anything covering FILE_BEHAVIOR?" rather than
"have we tried the sandbox?", which is what makes it survive a provider being
added, removed, renamed or unconfigured.

Goals are generated from the observable type, the depth and the capabilities the
registry can actually serve — never invented. A goal for a capability no provider
offers would produce a permanently unsatisfiable plan and a misleading coverage
gap.

Activation
----------

Some capabilities should not be bought up front. Sandbox behaviour and web
forensics are expensive and only sometimes informative, so they wait: for a
baseline to exist, for a reason to follow up, or for the caller to ask by name.
:class:`GoalActivation` and :attr:`CapabilityGoal.requires_trigger` express that
without naming any provider.

What a goal is not
------------------

A satisfied goal means *the information was collected*. It does not mean the
information was reassuring, and no goal here can be satisfied by absence:
"nothing found" is coverage of a source, not coverage of a question.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from ti_recon.enums import (
    CoverageRelevance,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "DEPTH_ORDER",
    "CapabilityGoal",
    "GoalActivation",
    "depth_at_least",
]

#: Depth ordering, so "at least STANDARD" is expressible without an enum change.
DEPTH_ORDER: dict[InvestigationDepth, int] = {
    InvestigationDepth.QUICK: 0,
    InvestigationDepth.STANDARD: 1,
    InvestigationDepth.DEEP: 2,
}


def depth_at_least(depth: InvestigationDepth, minimum: InvestigationDepth) -> bool:
    """Whether ``depth`` is at least as deep as ``minimum``."""
    return DEPTH_ORDER[depth] >= DEPTH_ORDER[minimum]


class GoalActivation(StrEnum):
    """When a goal becomes eligible to spend budget on."""

    #: From the first planning round. Baseline coverage.
    IMMEDIATE = "immediate"
    #: Once every required goal has been attempted. Specialized follow-up that
    #: only makes sense against a baseline — asking what a file *did* before
    #: knowing whether anyone has ever seen it is the wrong order.
    AFTER_BASELINE = "after_baseline"
    #: Only when the caller named the capability. For work nobody should pay for
    #: on an analyst's behalf.
    EXPLICIT_ONLY = "explicit_only"


class CapabilityGoal(FrozenTiReconModel):
    """One thing this enrichment is trying to learn."""

    capability: ProviderCapability
    relevance: CoverageRelevance = CoverageRelevance.RELEVANT

    #: How many *independent* source families should cover it. More than one is
    #: worth asking for on the primary directional capability and pointless
    #: beyond two — a third family answering the same question is a number going
    #: up, not information arriving.
    minimum_source_families: int = Field(default=1, ge=1, le=4)

    activation: GoalActivation = GoalActivation.IMMEDIATE

    #: Shallowest depth at which this goal exists at all.
    minimum_depth: InvestigationDepth = InvestigationDepth.QUICK

    #: When ``True``, an ``AFTER_BASELINE`` goal additionally needs a reason to
    #: follow up: directional evidence to explain, or a baseline that came back
    #: uncovered. Set for the depth where the follow-up is *conditional* and
    #: cleared for the depth where it is simply expected.
    requires_trigger: bool = False

    @property
    def is_required(self) -> bool:
        return self.relevance is CoverageRelevance.REQUIRED

    def exists_at(self, depth: InvestigationDepth) -> bool:
        return depth_at_least(depth, self.minimum_depth)

    def families_for_depth(self, depth: InvestigationDepth) -> int:
        """Family target, never asking for more than the depth warrants.

        A QUICK run wants one good answer, not a survey; asking it for two
        independent families would double its cost for a triage decision that
        does not need it.
        """
        if depth is InvestigationDepth.QUICK:
            return 1
        return self.minimum_source_families
