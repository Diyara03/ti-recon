"""ThreatFox lookup and execution policy (Task 10).

:class:`ThreatFoxLookupPolicy` is provider-specific: how many related records
each depth normalizes. :func:`build_threatfox_execution_policy` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy`.

Depth never buys another request. A ThreatFox lookup is one form POST; depth
decides how many of the records already inside that response become objects and
relationships. Tag queries, malware-family history and the bulk IOC export are
hunting workflows that this integration cannot perform at any depth.

Positive results are cached briefly rather than for hours. ThreatFox is a live
picture of *current* infrastructure — an IOC that was a C2 this morning may be
sinkholed by tonight, and the platform expires records after six months — so a
long-lived cache entry would keep answering with a picture the provider itself
has moved on from.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.abusech.policy import (
    DEPTH_BOUNDS,
    AbuseChBounds,
    bounds_for_depth,
    build_abusech_execution_policy,
)
from ti_recon.providers.threatfox.descriptor import THREATFOX_PROVIDER_ID

__all__ = [
    "THREATFOX_NO_DATA_TTL_SECONDS",
    "THREATFOX_SUCCESS_TTL_SECONDS",
    "ThreatFoxLookupPolicy",
    "build_threatfox_execution_policy",
]

#: A current IOC is current for now. Half an hour keeps a burst of related
#: lookups cheap without outliving its subject.
THREATFOX_SUCCESS_TTL_SECONDS: Final[int] = 1800

#: "Not currently listed" is the answer most likely to change — it is exactly
#: what changes when an indicator is first reported.
THREATFOX_NO_DATA_TTL_SECONDS: Final[int] = 300


class ThreatFoxLookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a ThreatFox lookup is performed."""

    #: How much of one response each depth normalizes.
    depth_bounds: dict[InvestigationDepth, AbuseChBounds] = Field(
        default_factory=lambda: dict(DEPTH_BOUNDS)
    )

    def bounds(self, depth: InvestigationDepth) -> AbuseChBounds:
        """What ``depth`` keeps, falling back to the STANDARD shape."""
        return bounds_for_depth(depth, self.depth_bounds)


def build_threatfox_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for ThreatFox.

    Shares the abuse.ch posture — user-scoped cache, one request in flight,
    coalescing on — and shortens the positive TTL, because ThreatFox describes
    live infrastructure rather than a durable record.
    """
    return build_abusech_execution_policy(
        provider_id=THREATFOX_PROVIDER_ID,
        cache=cache,
        retry=retry,
        success_ttl_seconds=THREATFOX_SUCCESS_TTL_SECONDS,
        no_data_ttl_seconds=THREATFOX_NO_DATA_TTL_SECONDS,
    )
