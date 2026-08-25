"""Censys execution and lookup policy (Task 9).

Two kinds of policy live here.

:class:`CensysLookupPolicy` is provider-specific: how much of one asset document
each depth normalizes, and how often a credit balance is worth re-reading.

:func:`build_censys_execution_policy` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy` — cache TTLs, retry
budget, concurrency. It is a *default*, not a claim about Censys's documented
limits; an operator tunes it, and Task 6 remains the only thing that acts on it.

What depth means here, and what it must not mean
------------------------------------------------

A Censys lookup is one direct request against one deterministic asset identity,
and it costs one credit. Depth does not buy a second request, a search, a
historical timeline or an ``at_time`` enumeration — none of those exist in this
integration, at any depth. Depth decides how much of the *already-paid-for*
document is normalized:

* ``QUICK`` keeps the summary: which ports answered, who announces the address,
  what Censys labels it. Enough to know whether the asset is worth a closer look.
* ``STANDARD`` adds the service list, the DNS names, the certificates and the
  reported vulnerabilities, at modest bounds.
* ``DEEP`` raises those bounds. Same request, same credit, more of the answer
  written down.

Nothing about a deeper lookup makes an asset look more malicious, because
nothing Censys reports has a direction to begin with.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.censys.descriptor import CENSYS_PROVIDER_ID
from ti_recon.providers.censys.normalizer import (
    MAX_CERTIFICATES,
    MAX_DNS_NAMES,
    MAX_ENDPOINTS,
    MAX_LABELS,
    MAX_PORTS,
    MAX_SERVICES,
    MAX_VULNERABILITIES,
)

__all__ = [
    "DEFAULT_MAX_CONCURRENCY",
    "DEPTH_DETAIL",
    "CensysDetail",
    "CensysLookupPolicy",
    "build_censys_execution_policy",
    "detail_for_depth",
]

#: One request at a time, by default.
#:
#: Deliberately the most conservative value available. Censys's per-minute
#: allowance depends on the plan, this integration cannot discover it, and a
#: free-tier token being throttled is a worse outcome than a slightly slower
#: investigation. An operator who knows their plan raises it.
DEFAULT_MAX_CONCURRENCY: Final[int] = 1


class CensysDetail(FrozenTiReconModel):
    """How much of one Censys asset document a given depth keeps.

    Every bound is capped at the normalizer's own ceiling, so a policy — however
    it was constructed — cannot ask for an unbounded expansion of a
    provider-controlled list.
    """

    include_services: bool = True
    include_dns: bool = True
    include_tls: bool = True
    include_software: bool = True
    include_vulnerabilities: bool = True
    include_labels: bool = True

    max_ports: int = Field(default=50, ge=0, le=MAX_PORTS)
    max_services: int = Field(default=25, ge=0, le=MAX_SERVICES)
    max_dns_names: int = Field(default=25, ge=0, le=MAX_DNS_NAMES)
    max_certificates: int = Field(default=5, ge=0, le=MAX_CERTIFICATES)
    max_endpoints: int = Field(default=10, ge=0, le=MAX_ENDPOINTS)
    max_labels: int = Field(default=15, ge=0, le=MAX_LABELS)
    max_vulnerabilities: int = Field(default=15, ge=0, le=MAX_VULNERABILITIES)


#: What each depth keeps. Overridable through
#: :attr:`CensysLookupPolicy.depth_detail` so an operator can trade verbosity
#: without touching code.
DEPTH_DETAIL: Final[dict[InvestigationDepth, CensysDetail]] = {
    InvestigationDepth.QUICK: CensysDetail(
        include_services=False,
        include_dns=False,
        include_tls=False,
        include_software=False,
        include_vulnerabilities=False,
        include_labels=True,
        max_ports=25,
        max_endpoints=5,
        max_labels=10,
    ),
    InvestigationDepth.STANDARD: CensysDetail(),
    InvestigationDepth.DEEP: CensysDetail(
        max_ports=MAX_PORTS,
        max_services=MAX_SERVICES,
        max_dns_names=MAX_DNS_NAMES,
        max_certificates=MAX_CERTIFICATES,
        max_endpoints=MAX_ENDPOINTS,
        max_labels=MAX_LABELS,
        max_vulnerabilities=MAX_VULNERABILITIES,
    ),
}


class CensysLookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a Censys lookup is performed."""

    #: How long a credit reading stays useful. Short, because a balance moves
    #: with every lookup; long enough that enrichment does not spend a call on
    #: credits before each asset read. The credit endpoints are free, so this is
    #: about latency rather than cost.
    credit_ttl_seconds: int = Field(default=300, ge=0, le=86_400)

    #: Whether a lookup may refresh the credit balance at all. Turning this off
    #: makes a Censys lookup strictly one request per uncached asset.
    refresh_credits_on_lookup: bool = True

    #: What each depth keeps.
    depth_detail: dict[InvestigationDepth, CensysDetail] = Field(
        default_factory=lambda: dict(DEPTH_DETAIL)
    )

    @property
    def credit_refresh_enabled(self) -> bool:
        return self.refresh_credits_on_lookup and self.credit_ttl_seconds > 0

    def detail(self, depth: InvestigationDepth) -> CensysDetail:
        """What ``depth`` keeps, falling back to the STANDARD shape."""
        return self.depth_detail.get(depth, DEPTH_DETAIL[InvestigationDepth.STANDARD])


def detail_for_depth(
    depth: InvestigationDepth, policy: CensysLookupPolicy | None = None
) -> CensysDetail:
    """What one depth keeps, with or without a configured policy."""
    if policy is not None:
        return policy.detail(depth)
    return DEPTH_DETAIL.get(depth, DEPTH_DETAIL[InvestigationDepth.STANDARD])


def build_censys_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for Censys.

    Three parts are load-bearing.

    **The cache scope stays ``USER``.** Censys visibility and entitlement are
    per-account: a free wallet and an organization plan do not see the same
    fields, and a lookup is charged to whichever account's token paid for it.
    Serving one analyst's asset document to another would hand out data the
    second analyst's plan may not include and would spend nobody's credit for it.
    Nothing here turns on ``GLOBAL``.

    **The cache matters more than usual.** Every asset read costs a credit, so a
    repeated lookup that hits the cache is not merely faster — it is the
    difference between one credit and two. Successes are therefore kept for a
    good while: an asset's exposure profile is the *last observed* scan, and
    Censys does not rescan the internet every hour.

    **Negative answers expire quickly, and partials are not kept at all.** "No
    such asset" changes the moment Censys next scans, and a document cut short by
    a depth bound or an unreadable block must never later be mistaken for a
    complete one.

    Concurrency defaults to one — see :data:`DEFAULT_MAX_CONCURRENCY`.
    """
    return ProviderExecutionPolicy(
        provider_id=CENSYS_PROVIDER_ID,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=6 * 3600,
            no_data_ttl_seconds=600,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(),
        max_concurrency=max_concurrency,
    )
