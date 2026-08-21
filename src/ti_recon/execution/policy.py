"""Execution policy (Task 6).

Policy is data, not code: every threshold here is a configuration choice that a
provider may override, never a claim about what a provider's API actually
permits. Real per-provider values arrive with each real integration.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import ActivityMode, ProviderOperation, ProviderRunStatus
from ti_recon.execution.coordination import DEFAULT_MAX_CONCURRENCY
from ti_recon.execution.models import CacheScope
from ti_recon.execution.retry import RetryPolicy
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope

__all__ = [
    "CACHEABLE_STATUSES",
    "CachePolicy",
    "ProviderExecutionPolicy",
    "ProviderPolicyRegistry",
]

#: Statuses a result may ever be cached under. Everything else is a failure or
#: a configuration problem, and caching those would turn a transient outage
#: into a persistent one.
CACHEABLE_STATUSES: Final[frozenset[ProviderRunStatus]] = frozenset(
    {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.NO_DATA,
        ProviderRunStatus.PARTIAL,
    }
)

_ONE_DAY: Final[int] = 60 * 60 * 24


class CachePolicy(FrozenTiReconModel):
    """When a provider result may be reused, and for how long.

    Defaults are deliberately conservative:

    * ``NO_DATA`` gets a much shorter TTL than ``SUCCESS``. "This provider has
      never seen it" is the answer most likely to change soon — it is exactly
      what changes when an indicator is first reported.
    * ``PARTIAL`` is not cached at all by default (``partial_ttl_seconds=None``).
      A partial result usually reflects what a subscription is entitled to
      return, and caching a truncated answer risks it being mistaken later for a
      complete one.
    * Active operations are never cached, because they are not reads.
    """

    enabled: bool = True
    scope: CacheScope = CacheScope.USER
    success_ttl_seconds: int = Field(default=3600, ge=0, le=_ONE_DAY * 30)
    no_data_ttl_seconds: int = Field(default=300, ge=0, le=_ONE_DAY * 30)
    partial_ttl_seconds: int | None = Field(default=None, ge=0, le=_ONE_DAY * 30)
    cache_active_operations: bool = False
    respect_provider_hint: bool = True
    max_ttl_seconds: int = Field(default=_ONE_DAY, ge=1, le=_ONE_DAY * 30)

    @model_validator(mode="after")
    def _validate_policy(self) -> CachePolicy:
        if self.scope is CacheScope.GLOBAL and not self.enabled:
            msg = "a disabled cache policy must not also declare global scope"
            raise ValueError(msg)
        return self

    def is_request_cacheable(self, request: ProviderRequest) -> bool:
        """Whether this request may participate in the cache at all.

        Checked before a provider is called, so an active operation never even
        produces a cache key.
        """
        if not self.enabled:
            return False
        is_active = (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        )
        return not (is_active and not self.cache_active_operations)

    def ttl_for(self, envelope: ProviderResultEnvelope, request: ProviderRequest) -> int | None:
        """Seconds this result may be cached for, or ``None`` to not cache it."""
        if not self.is_request_cacheable(request):
            return None
        if not envelope.cacheability.cacheable:
            # The adapter knows something we do not; it wins.
            return None

        ttl = self._status_ttl(envelope.status)
        if ttl is None:
            return None

        hint = envelope.cacheability.ttl_seconds
        if self.respect_provider_hint and hint is not None:
            # A provider hint may only shorten, never extend, our own policy.
            ttl = min(ttl, hint)

        ttl = min(ttl, self.max_ttl_seconds)
        return ttl if ttl > 0 else None

    def _status_ttl(self, status: ProviderRunStatus) -> int | None:
        match status:
            case ProviderRunStatus.SUCCESS:
                return self.success_ttl_seconds
            case ProviderRunStatus.NO_DATA:
                return self.no_data_ttl_seconds
            case ProviderRunStatus.PARTIAL:
                return self.partial_ttl_seconds
            case _:
                return None


class ProviderExecutionPolicy(FrozenTiReconModel):
    """How one provider should be executed.

    Every value is configuration. None of it is a claim about what a provider's
    API actually permits — real per-provider numbers arrive with each real
    integration, from that provider's documentation.
    """

    provider_id: str | None = Field(default=None, max_length=64)
    cache: CachePolicy = CachePolicy()
    retry: RetryPolicy = RetryPolicy()
    max_concurrency: int = Field(default=DEFAULT_MAX_CONCURRENCY, ge=1, le=64)

    #: Collapse identical concurrent passive requests into one provider call.
    coalesce_requests: bool = True

    #: Skip a provider whose last known quota was exhausted, instead of
    #: spending a request to be told so again.
    quota_precheck: bool = True

    #: Cooldown applied when a response reports an exhausted rate-limit window
    #: but no reset time.
    rate_limit_cooldown_seconds: float = Field(default=60.0, ge=0.0, le=86_400.0)

    #: Cooldown applied when a response reports exhausted quota with no reset.
    quota_cooldown_seconds: float = Field(default=900.0, ge=0.0, le=86_400.0)


class ProviderPolicyRegistry:
    """Per-provider execution policy, with a default for everything else.

    A provider with no registered policy gets the default rather than an error:
    an integration should work before it is tuned.
    """

    def __init__(
        self,
        *,
        default: ProviderExecutionPolicy | None = None,
        policies: Iterable[ProviderExecutionPolicy] = (),
    ) -> None:
        self._default = ProviderExecutionPolicy() if default is None else default
        self._policies: dict[str, ProviderExecutionPolicy] = {}
        for policy in policies:
            self.register(policy)

    def register(self, policy: ProviderExecutionPolicy) -> None:
        """Register a provider-specific policy."""
        if policy.provider_id is None:
            msg = "a registered policy must name the provider it applies to"
            raise ValueError(msg)
        self._policies[policy.provider_id] = policy

    def get(self, provider_id: str) -> ProviderExecutionPolicy:
        """The policy for ``provider_id``, falling back to the default."""
        return self._policies.get(provider_id, self._default)

    @property
    def default(self) -> ProviderExecutionPolicy:
        return self._default

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._policies

    def __len__(self) -> int:
        return len(self._policies)

    def __repr__(self) -> str:
        return f"<ProviderPolicyRegistry providers={sorted(self._policies)}>"
