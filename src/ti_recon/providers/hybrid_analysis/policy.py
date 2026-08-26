"""Depth, bounds and execution policy for Hybrid Analysis (Task 12).

Depth here controls something the other providers' depths do not: **how many
physical requests a lookup makes**. A hash search is one request; each detailed
report summary is another. A restricted key allows roughly five requests a minute
and two hundred an hour, so the budgets are deliberately small.

    QUICK     1 request   the report index only
    STANDARD  2 requests  index + one representative summary
    DEEP      3 requests  index + two contrasting summaries

That is the *maximum*. A hash with no completed reports spends one request at
every depth, because there is nothing worth summarizing.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.hybrid_analysis.descriptor import HYBRID_ANALYSIS_PROVIDER_ID
from ti_recon.sandbox.bounds import DEPTH_BOUNDS, SandboxBounds, bounds_for_depth
from ti_recon.sandbox.selection import DEPTH_SUMMARY_BUDGET, MAX_SUMMARIES_PER_LOOKUP

__all__ = [
    "HYBRID_ANALYSIS_MAX_CONCURRENCY",
    "HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS",
    "HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS",
    "MAX_REQUESTS_PER_LOOKUP",
    "HybridAnalysisLookupPolicy",
    "build_hybrid_analysis_execution_policy",
]

#: One request in flight. A restricted key's allowance is small enough that two
#: concurrent lookups could exhaust a minute's budget between them, and the
#: provider also limits an API key to two source addresses per hour — so
#: parallelism here buys latency at the cost of reliability.
HYBRID_ANALYSIS_MAX_CONCURRENCY: Final[int] = 1

#: A completed sandbox report does not change: the sample ran, in that
#: environment, on that date. Cached for a day.
HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS: Final[int] = 24 * 3600

#: "No report" is precisely the fact that changes when somebody detonates the
#: sample, so it expires far sooner than a positive result.
HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS: Final[int] = 900

#: Physical request ceiling per logical lookup: the index plus the summary
#: budget. Stated as a constant so a test can assert the promise rather than
#: infer it.
MAX_REQUESTS_PER_LOOKUP: Final[int] = 1 + MAX_SUMMARIES_PER_LOOKUP


class HybridAnalysisLookupPolicy(FrozenTiReconModel):
    """How much of a report each depth normalizes, and how many to fetch."""

    depth_bounds: dict[InvestigationDepth, SandboxBounds] = Field(
        default_factory=lambda: dict(DEPTH_BOUNDS)
    )

    def bounds(self, depth: InvestigationDepth) -> SandboxBounds:
        return bounds_for_depth(depth, self.depth_bounds)

    def summary_budget(self, depth: InvestigationDepth) -> int:
        """How many report summaries ``depth`` may fetch, never above the ceiling."""
        return min(DEPTH_SUMMARY_BUDGET.get(depth, 1), MAX_SUMMARIES_PER_LOOKUP)


def build_hybrid_analysis_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for a small metered allowance.

    ``CacheScope.USER`` and never global. Even a public report is read with a
    specific account's key, against that account's quota and authorization level
    — so one analyst's answer is not another's to serve.
    """
    return ProviderExecutionPolicy(
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS,
            no_data_ttl_seconds=HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(),
        max_concurrency=HYBRID_ANALYSIS_MAX_CONCURRENCY,
        coalesce_requests=True,
    )
