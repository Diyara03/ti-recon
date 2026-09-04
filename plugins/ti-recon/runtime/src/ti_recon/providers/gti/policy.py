"""GTI execution and lookup policy (Task 7).

Two kinds of policy live here.

``GTILookupPolicy`` is provider-specific: which v3 collection an object type maps
to, which attributes to leave out of a response, and how often quota is worth
re-checking.

``build_gti_execution_policy`` produces a Task 6
:class:`~ti_recon.execution.policy.ProviderExecutionPolicy` — cache TTLs, retry
budget, concurrency. It is a *default*, not a claim about GTI's documented
limits; an operator tunes it, and Task 6 remains the only thing that acts on it.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import IntelObjectType
from ti_recon.execution.policy import CachePolicy, ProviderExecutionPolicy
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID

__all__ = [
    "DEFAULT_EXCLUDED_ATTRIBUTES",
    "GTI_COLLECTION_FOR_OBJECT_TYPE",
    "GTILookupPolicy",
    "build_gti_execution_policy",
    "collection_for_object_type",
]

#: Which v3 collection answers for each observable type. File hashes of every
#: length resolve to ``files``, matching the Task 3 rule that a hash identifies
#: a ``file`` object rather than being an object type of its own.
GTI_COLLECTION_FOR_OBJECT_TYPE: Final[dict[IntelObjectType, str]] = {
    IntelObjectType.IPV4_ADDR: "ip_addresses",
    IntelObjectType.IPV6_ADDR: "ip_addresses",
    IntelObjectType.DOMAIN_NAME: "domains",
    IntelObjectType.URL: "urls",
    IntelObjectType.FILE: "files",
}

#: Left out of every normal enrichment response.
#:
#: ``last_analysis_results`` is the per-engine breakdown — dozens of vendor
#: verdicts. TI Recon normalizes the *aggregate* (``last_analysis_stats``) into
#: one piece of evidence and deliberately never treats individual engines as
#: independent providers, so fetching the breakdown would cost bandwidth for
#: data we must not use that way.
#:
#: Nothing else is excluded. Trimming further would be guessing at which fields
#: are unnecessary, and a wrongly excluded attribute is a silent gap in evidence.
DEFAULT_EXCLUDED_ATTRIBUTES: Final[tuple[str, ...]] = ("last_analysis_results",)


def collection_for_object_type(object_type: IntelObjectType) -> str | None:
    """The GTI collection for an object type, or ``None`` if GTI has none."""
    return GTI_COLLECTION_FOR_OBJECT_TYPE.get(object_type)


class GTILookupPolicy(FrozenTiReconModel):
    """Provider-specific knobs for how a GTI lookup is performed."""

    #: Attributes GTI is asked not to send.
    excluded_attributes: tuple[str, ...] = DEFAULT_EXCLUDED_ATTRIBUTES

    #: How long a quota reading stays useful. Short, because an allowance moves
    #: with every request; long enough that enrichment does not spend a call on
    #: quota before each lookup.
    quota_ttl_seconds: int = Field(default=300, ge=0, le=86_400)

    #: Whether a lookup may refresh quota at all. Turning this off makes GTI
    #: enrichment strictly one API call per uncached lookup.
    refresh_quota_on_lookup: bool = True

    @property
    def quota_refresh_enabled(self) -> bool:
        return self.refresh_quota_on_lookup and self.quota_ttl_seconds > 0


def build_gti_execution_policy(
    *,
    cache: CachePolicy | None = None,
    retry: RetryPolicy | None = None,
    max_concurrency: int = 4,
) -> ProviderExecutionPolicy:
    """A Task 6 execution policy tuned for GTI.

    The cache TTLs are the interesting part. A GTI verdict on a file is stable
    over hours, so successes are cached for a while; "GTI has never seen this"
    changes the moment a sample is first submitted, so negative results get a
    much shorter life. Partial results stay uncached, because a
    subscription-truncated answer must not later be mistaken for a complete one.
    """
    return ProviderExecutionPolicy(
        provider_id=GTI_PROVIDER_ID,
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
