"""URLhaus lookup and execution policy (Task 10).

Depth never buys another request: a URL, a host or a payload is one form POST,
and depth decides how many of the related records already inside that response
become objects and relationships. The feed exports and bulk downloads URLhaus
offers are not reachable at any depth.

Positive results are cached briefly. ``url_status`` flips between online and
offline as infrastructure is taken down and comes back, and a host accumulates
new URLs continuously, so a long-lived cache entry would keep answering with a
picture URLhaus has already updated.
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
from ti_recon.providers.urlhaus.descriptor import URLHAUS_PROVIDER_ID

__all__ = [
    "URLHAUS_NO_DATA_TTL_SECONDS",
    "URLHAUS_SUCCESS_TTL_SECONDS",
    "UrlhausLookupPolicy",
    "build_urlhaus_execution_policy",
]

#: Short, because online/offline state and a host's URL count both move.
URLHAUS_SUCCESS_TTL_SECONDS: Final[int] = 1800

#: "Not tracked" is what changes the moment somebody reports a new URL.
URLHAUS_NO_DATA_TTL_SECONDS: Final[int] = 300


class UrlhausLookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a URLhaus lookup is performed."""

    #: How much of one response each depth normalizes. A host lookup can return
    #: up to a hundred URLs and a payload can name dozens; these are the caps
    #: that keep one response from becoming a hundred objects.
    depth_bounds: dict[InvestigationDepth, AbuseChBounds] = Field(
        default_factory=lambda: dict(DEPTH_BOUNDS)
    )

    def bounds(self, depth: InvestigationDepth) -> AbuseChBounds:
        """What ``depth`` keeps, falling back to the STANDARD shape."""
        return bounds_for_depth(depth, self.depth_bounds)


def build_urlhaus_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for URLhaus."""
    return build_abusech_execution_policy(
        provider_id=URLHAUS_PROVIDER_ID,
        cache=cache,
        retry=retry,
        success_ttl_seconds=URLHAUS_SUCCESS_TTL_SECONDS,
        no_data_ttl_seconds=URLHAUS_NO_DATA_TTL_SECONDS,
    )
