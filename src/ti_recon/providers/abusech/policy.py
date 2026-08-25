"""abuse.ch execution and depth policy (Task 10).

Two kinds of policy live here, shared by the three providers because the
reasoning is identical for all of them.

:class:`AbuseChBounds` says how much of an already-returned response each depth
normalizes. :func:`build_abusech_execution_policy` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy`.

Depth never buys another request
--------------------------------

Every abuse.ch lookup in Task 10 is **one** form POST. Depth changes how many of
the related records inside that one response are turned into objects and
relationships — a URLhaus host record can carry a hundred malware URLs, a
ThreatFox hash search can return dozens of IOCs — and nothing else. It never
adds a request, never widens a search, and never changes which way evidence
points.

Tag queries, malware-family history, recent-additions feeds and bulk exports are
hunting, not enrichment. They belong to the future query planner, and no depth
here reaches them.

Fair use is a design constraint, not a footnote
-----------------------------------------------

abuse.ch meters by behaviour rather than by a published budget: unusual query
volume can get an account limited for up to 72 hours, and there is no per-endpoint
number to code against. So there is nothing to invent a quota from, and the
honest response is to be conservative by construction — one request in flight per
provider, caching on, single-flight on, and no redundant call anywhere.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "ABUSE_CH_MAX_CONCURRENCY",
    "DEPTH_BOUNDS",
    "MAX_RELATED_CEILING",
    "AbuseChBounds",
    "bounds_for_depth",
    "build_abusech_execution_policy",
]

#: One request in flight per provider.
#:
#: Deliberately the most conservative value available. abuse.ch publishes no
#: per-endpoint budget and limits accounts that look unusual, so a burst is the
#: one thing worth avoiding — and three providers sharing one key means three
#: adapters can look like one noisy account.
ABUSE_CH_MAX_CONCURRENCY: Final[int] = 1

#: The hard ceiling on related records normalized from one response, whatever a
#: depth policy asks for. The lists are provider-controlled: a host can carry a
#: hundred URLs, and a policy — however constructed — must not be able to ask
#: for an unbounded expansion.
MAX_RELATED_CEILING: Final[int] = 100


class AbuseChBounds(FrozenTiReconModel):
    """How many related records one depth turns into objects and relationships."""

    max_related: int = Field(default=25, ge=0, le=MAX_RELATED_CEILING)

    #: Nested detail that is cheap to read but bulky to keep: YARA rules,
    #: file-information blocks, per-URL payload lists.
    max_nested: int = Field(default=10, ge=0, le=MAX_RELATED_CEILING)

    #: Whether the deeper, optional context blocks are normalized at all.
    include_nested_detail: bool = True


#: What each depth keeps. Overridable per provider so an operator can trade
#: verbosity without touching code, and capped by the model either way.
DEPTH_BOUNDS: Final[dict[InvestigationDepth, AbuseChBounds]] = {
    InvestigationDepth.QUICK: AbuseChBounds(
        max_related=10, max_nested=0, include_nested_detail=False
    ),
    InvestigationDepth.STANDARD: AbuseChBounds(max_related=25, max_nested=10),
    InvestigationDepth.DEEP: AbuseChBounds(max_related=50, max_nested=25),
}


def bounds_for_depth(
    depth: InvestigationDepth,
    overrides: dict[InvestigationDepth, AbuseChBounds] | None = None,
) -> AbuseChBounds:
    """What one depth keeps, falling back to the STANDARD shape."""
    table = overrides if overrides else DEPTH_BOUNDS
    return table.get(depth, DEPTH_BOUNDS[InvestigationDepth.STANDARD])


def build_abusech_execution_policy(
    *,
    provider_id: str,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
    max_concurrency: int = ABUSE_CH_MAX_CONCURRENCY,
    success_ttl_seconds: int = 1800,
    no_data_ttl_seconds: int = 300,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for one abuse.ch provider.

    **The cache scope stays ``USER``**, even though much of this data is public.
    Access is per Auth-Key: fair-use limitation is per account, community and
    commercial entitlement differ, and a future enhanced tier may return more to
    some keys than to others. A shared cache would blur all three, and the cost
    of being wrong is an entitlement leak rather than a stale byte.

    **Positive results are not cached for long.** ThreatFox IOCs expire from the
    API after six months and infrastructure moves constantly; a URLhaus URL flips
    between online and offline. Half an hour keeps a burst of related lookups
    cheap without letting a stale answer outlive its subject.

    **Negative results expire sooner still.** "No current record" is the answer
    most likely to change — it is exactly what changes when an indicator is first
    reported — and on ThreatFox it is also the answer that carries the least
    information. Partial results are not cached at all, so a truncated answer
    cannot later be mistaken for a complete one.
    """
    return ProviderExecutionPolicy(
        provider_id=provider_id,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=success_ttl_seconds,
            no_data_ttl_seconds=no_data_ttl_seconds,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(),
        max_concurrency=max_concurrency,
        # Identical concurrent lookups collapse into one call. Worth more here
        # than usual: three providers share one metered account.
        coalesce_requests=True,
    )
