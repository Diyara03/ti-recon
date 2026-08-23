"""GreyNoise execution and lookup policy (Task 9).

Two kinds of policy live here.

:class:`GreyNoiseLookupPolicy` is provider-specific: which access mode to use,
how long a resolved access level stays trusted, whether a 403 may earn a single
Community probe, and how much of a full document each depth normalizes.

:func:`build_greynoise_execution_policy` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy` — cache TTLs, retry
budget, concurrency. It is a *default*, not a claim about GreyNoise's documented
limits; an operator tunes it, and Task 6 remains the only thing that acts on it.

What depth means here, and what it must not mean
------------------------------------------------

GreyNoise answers an address in one request. Depth therefore does **not** buy
more requests, more history or a wider search — there is no GNQL query, no
timeline and no bulk call in this integration, at any depth. What depth changes
is which endpoint variant is asked for and how much of the *already-returned*
document is normalized:

* ``QUICK`` asks for the reduced document (``?quick=true``) and keeps the
  classification and the business-services context. Cheapest possible answer to
  "is this address worth my attention at all".
* ``STANDARD`` asks for the full document and adds tags, CVE associations and
  network ownership.
* ``DEEP`` asks for the same full document and additionally normalizes the
  sensor detail already inside it — the ports touched, the paths requested, the
  client fingerprints left behind.

Nothing about a deeper lookup makes an address look more malicious. Depth
changes how much context is recorded, never which way the evidence points.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.greynoise.access import (
    DEFAULT_ACCESS_TTL_SECONDS,
    GreyNoiseAccessMode,
)
from ti_recon.providers.greynoise.descriptor import GREYNOISE_PROVIDER_ID

__all__ = [
    "DEPTH_DETAIL",
    "GreyNoiseDetail",
    "GreyNoiseLookupPolicy",
    "build_greynoise_execution_policy",
    "detail_for_depth",
]


class GreyNoiseDetail(FrozenTiReconModel):
    """How much of one GreyNoise answer a given depth asks for and keeps."""

    #: Ask GreyNoise for the reduced form of the full document. A *depth*
    #: choice, not an entitlement one: a full-access key at QUICK depth uses it
    #: deliberately, and a Community-only key never reaches this flag at all.
    quick: bool = False

    #: Tags — GreyNoise's characterization of the observed behaviour.
    include_tags: bool = True

    #: CVEs associated with the observed activity. Always context.
    include_cves: bool = True

    #: ASN, organization, geography and reverse DNS, plus the pivots they imply.
    include_network_context: bool = True

    #: The sensor detail already inside the document: ports, requested paths,
    #: client fingerprints. Off below DEEP because it is the bulkiest part of
    #: the answer and the least often needed, not because it costs a request.
    include_sensor_detail: bool = False


#: What each depth asks for. Overridable through
#: :attr:`GreyNoiseLookupPolicy.depth_detail` so an operator can trade verbosity
#: without touching code.
DEPTH_DETAIL: Final[dict[InvestigationDepth, GreyNoiseDetail]] = {
    InvestigationDepth.QUICK: GreyNoiseDetail(
        quick=True,
        include_tags=False,
        include_cves=False,
        include_network_context=False,
        include_sensor_detail=False,
    ),
    InvestigationDepth.STANDARD: GreyNoiseDetail(),
    InvestigationDepth.DEEP: GreyNoiseDetail(include_sensor_detail=True),
}


class GreyNoiseLookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a GreyNoise lookup is performed."""

    #: Which door to use. ``AUTO`` resolves per credential; ``FULL`` and
    #: ``COMMUNITY`` pin the choice. See
    #: :class:`~ti_recon.providers.greynoise.access.GreyNoiseAccessMode`.
    access_mode: GreyNoiseAccessMode = GreyNoiseAccessMode.AUTO

    #: How long a resolved access level stays trusted, per credential.
    access_ttl_seconds: int = Field(default=DEFAULT_ACCESS_TTL_SECONDS, ge=0, le=86_400)

    #: Whether a ``403`` from the full endpoint may earn one Community attempt.
    #:
    #: On by default, because that single probe is the only way to tell a
    #: Community subscription from a genuinely forbidden key — and because
    #: without it a free-tier analyst would get nothing rather than the smaller
    #: answer their plan does include. Turning it off makes a 403 final, which
    #: an operator who wants strictly paid-tier behaviour may prefer.
    #:
    #: Never consulted for a ``401``: a rejected key is never probed.
    allow_community_probe: bool = True

    #: What each depth asks for and keeps.
    depth_detail: dict[InvestigationDepth, GreyNoiseDetail] = Field(
        default_factory=lambda: dict(DEPTH_DETAIL)
    )

    @property
    def access_caching_enabled(self) -> bool:
        return self.access_ttl_seconds > 0

    def detail(self, depth: InvestigationDepth) -> GreyNoiseDetail:
        """What ``depth`` asks for, falling back to the STANDARD shape."""
        return self.depth_detail.get(depth, DEPTH_DETAIL[InvestigationDepth.STANDARD])


def detail_for_depth(
    depth: InvestigationDepth, policy: GreyNoiseLookupPolicy | None = None
) -> GreyNoiseDetail:
    """What one depth asks for, with or without a configured policy."""
    if policy is not None:
        return policy.detail(depth)
    return DEPTH_DETAIL.get(depth, DEPTH_DETAIL[InvestigationDepth.STANDARD])


def build_greynoise_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
    max_concurrency: int = 4,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for GreyNoise.

    The cache scope is the part that is not tunable in spirit. Two GreyNoise
    accounts do not see the same document for the same address — a Community key
    gets a handful of fields where a full key gets the tags, the CVEs and the
    sensor detail — so serving one analyst's answer to another would silently
    hand out data the second analyst's plan does not include, and would just as
    easily hand a full-tier analyst a Community-shaped answer. The scope stays
    ``USER``, which is also the framework default; nothing here turns on
    ``GLOBAL``.

    TTLs follow the shape of the data. A classification is stable over hours, so
    successes keep for a while. "GreyNoise has never observed this" is the
    answer most likely to change soon — it is exactly what changes the first
    time an address scans a sensor — so negative answers expire quickly. Partial
    results stay uncached, because a document GreyNoise trimmed for entitlement
    reasons must never later be mistaken for a complete one.
    """
    return ProviderExecutionPolicy(
        provider_id=GREYNOISE_PROVIDER_ID,
        cache=cache
        if cache is not None
        else CachePolicy(
            success_ttl_seconds=3600,
            no_data_ttl_seconds=300,
            partial_ttl_seconds=None,
        ),
        retry=retry if retry is not None else RetryPolicy(),
        max_concurrency=max_concurrency,
    )
