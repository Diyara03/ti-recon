"""How much of a sandbox report each depth keeps (Task 12).

Provider-neutral, because the reason for bounding is not provider-specific: a
single detonation can produce six hundred processes, four hundred signatures and
a thousand network connections, and none of that belongs in an evidence record
whole.

Depth here changes *presentation* of an already-fetched report, and separately
how many reports get fetched at all (:mod:`ti_recon.sandbox.selection`). The
totals a provider reported are always kept alongside the truncated detail, so a
bounded view never reads as a complete one.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel

__all__ = ["DEPTH_BOUNDS", "HARD_CEILINGS", "SandboxBounds", "bounds_for_depth"]


class SandboxBounds(FrozenTiReconModel):
    """Per-collection caps for one depth."""

    signatures: int = Field(ge=0)
    techniques: int = Field(ge=0)
    processes: int = Field(ge=0)
    network: int = Field(ge=0)
    extracted_files: int = Field(ge=0)
    certificates: int = Field(ge=0)
    tags: int = Field(ge=0)
    warnings: int = Field(ge=0)

    def capped(self) -> SandboxBounds:
        """This bound, clamped to the hard ceilings."""
        return SandboxBounds(
            **{name: min(getattr(self, name), HARD_CEILINGS[name]) for name in HARD_CEILINGS}
        )


#: Absolute maxima. A configured bound may be lower; nothing exceeds these.
HARD_CEILINGS: Final[dict[str, int]] = {
    "signatures": 100,
    "techniques": 100,
    "processes": 100,
    "network": 100,
    "extracted_files": 100,
    "certificates": 25,
    "tags": 100,
    "warnings": 25,
}

#: QUICK keeps nothing detailed because it fetches no report to detail — its
#: answer is the report index: how many runs exist, in which environments, with
#: which verdicts and states.
DEPTH_BOUNDS: Final[dict[InvestigationDepth, SandboxBounds]] = {
    InvestigationDepth.QUICK: SandboxBounds(
        signatures=0,
        techniques=0,
        processes=0,
        network=0,
        extracted_files=0,
        certificates=0,
        tags=10,
        warnings=5,
    ),
    InvestigationDepth.STANDARD: SandboxBounds(
        signatures=25,
        techniques=25,
        processes=25,
        network=25,
        extracted_files=15,
        certificates=10,
        tags=25,
        warnings=10,
    ),
    InvestigationDepth.DEEP: SandboxBounds(
        signatures=75,
        techniques=50,
        processes=75,
        network=75,
        extracted_files=50,
        certificates=20,
        tags=50,
        warnings=20,
    ),
}


def bounds_for_depth(
    depth: InvestigationDepth, configured: dict[InvestigationDepth, SandboxBounds] | None = None
) -> SandboxBounds:
    """The bounds for ``depth``, falling back to STANDARD.

    An unknown depth gets the middle option rather than the largest: a new depth
    value should not silently authorise the most expensive normalization.
    """
    table = DEPTH_BOUNDS if configured is None else configured
    return table.get(depth, DEPTH_BOUNDS[InvestigationDepth.STANDARD]).capped()
