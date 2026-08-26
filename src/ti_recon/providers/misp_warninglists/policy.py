"""Depth, bounds and execution policy for the local dataset (Task 11).

Depth changes presentation, never coverage
------------------------------------------

Every depth searches the **same** lists. This is a deliberate departure from the
remote providers, where QUICK legitimately means "spend less" because each
request costs an allowance. There is nothing to spend here, and a QUICK lookup
that consulted fewer warninglists would produce a *different answer* to the same
question — an analyst would have to know which depth ran to know what "no match"
covered. Coverage that varies by depth is worse than useless; it is misleading.

So depth bounds how many match summaries are rendered, and the coverage record
always reports ``total_matches`` alongside what was kept.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.misp_warninglists.descriptor import MISP_WARNINGLISTS_PROVIDER_ID

__all__ = [
    "DEPTH_MATCH_LIMITS",
    "MISP_WARNINGLISTS_MAX_CONCURRENCY",
    "MISP_WARNINGLISTS_NO_DATA_TTL_SECONDS",
    "MISP_WARNINGLISTS_SUCCESS_TTL_SECONDS",
    "MispWarningListsLookupPolicy",
    "build_misp_warninglists_execution_policy",
]

#: How many match records each depth renders. Not how many lists it checks.
DEPTH_MATCH_LIMITS: Final[dict[InvestigationDepth, int]] = {
    InvestigationDepth.QUICK: 10,
    InvestigationDepth.STANDARD: 25,
    InvestigationDepth.DEEP: 50,
}

#: Concurrency is a politeness setting for remote providers. Here it bounds CPU
#: on set lookups against an in-memory index, so it can be generous.
MISP_WARNINGLISTS_MAX_CONCURRENCY: Final[int] = 8

#: A cached answer stays valid as long as the dataset and profile behind it do,
#: and the cache key carries both — so the TTL is about memory hygiene rather
#: than correctness. Long, because recomputation is cheap and a stale answer is
#: impossible: refreshing the snapshot changes the key.
MISP_WARNINGLISTS_SUCCESS_TTL_SECONDS: Final[int] = 24 * 3600
MISP_WARNINGLISTS_NO_DATA_TTL_SECONDS: Final[int] = 24 * 3600


class MispWarningListsLookupPolicy(FrozenTiReconModel):
    """Per-depth presentation bounds."""

    depth_match_limits: dict[InvestigationDepth, int] = Field(
        default_factory=lambda: dict(DEPTH_MATCH_LIMITS)
    )

    def match_limit(self, depth: InvestigationDepth, ceiling: int) -> int:
        """How many match records to render, never above ``ceiling``."""
        configured = self.depth_match_limits.get(
            depth, DEPTH_MATCH_LIMITS[InvestigationDepth.STANDARD]
        )
        return min(configured, ceiling)


def build_misp_warninglists_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy for a local provider.

    ``CacheScope.USER`` even though the answer cannot vary by analyst. A global
    scope would be defensible — the dataset is identical for everyone and the
    descriptor is credential-free, which is exactly the case Task 6 permits it
    for — but user scoping costs almost nothing against an in-memory matcher and
    keeps one fewer shared store in a platform whose every other cache entry is
    per-analyst. Correctness never depends on the choice; the snapshot and
    profile fingerprints in the key already do that work.

    Retries are pointless and are configured away: a local match either works or
    the dataset is unusable, and repeating it changes neither.
    """
    return ProviderExecutionPolicy(
        provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=MISP_WARNINGLISTS_SUCCESS_TTL_SECONDS,
            no_data_ttl_seconds=MISP_WARNINGLISTS_NO_DATA_TTL_SECONDS,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(max_attempts=1),
        max_concurrency=MISP_WARNINGLISTS_MAX_CONCURRENCY,
        coalesce_requests=True,
        # There is no allowance to pre-check. Leaving it on would consult a quota
        # store that nothing ever writes.
        quota_precheck=False,
    )
