"""Shared execution vocabulary (Task 6).

The isolation identity every execution control keys on, and the enums that
several modules need. Deliberately dependency-light so the cache, limits and
coordination modules can all import it without forming a cycle.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from ti_recon.enums import (
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.base import (
    FrozenTiReconModel,
    Identifier,
    UtcDatetime,
    new_id,
)
from ti_recon.models.investigation import ProviderRun
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.result import ProviderResultEnvelope, RateLimitSnapshot
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "CacheScope",
    "CooldownReason",
    "ExecutionContext",
    "ExecutionScope",
    "ProviderExecutionOutcome",
]


class CacheScope(StrEnum):
    """Who a cached provider result may be served to.

    ``USER`` is the default and the only scope enabled unless a provider policy
    says otherwise. Provider results are obtained with one analyst's credential,
    against one analyst's quota, and may reflect what that analyst's plan is
    entitled to see — serving them to somebody else is both a data-sharing and
    an entitlement problem.

    ``GLOBAL`` exists for sources where the answer genuinely cannot vary by
    caller (a local warning list, say). It must be turned on explicitly per
    provider; nothing enables it by default.
    """

    USER = "user"
    GLOBAL = "global"


class CooldownReason(StrEnum):
    """Why a provider or operation is temporarily not being called."""

    RATE_LIMIT = "rate_limit"
    QUOTA_EXHAUSTED = "quota_exhausted"
    TRANSIENT_FAILURES = "transient_failures"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


class ExecutionScope(FrozenTiReconModel):
    """The isolation boundary for every execution control.

    Cache entries, quota state, cooldowns, concurrency slots and in-flight
    coalescing are all keyed by this. One scope must never be able to read,
    block, or consume another's.

    ``provider_connection_id`` is preferred over ``user_id`` when available: it
    identifies the specific credential the work is being done with, so rotating
    a key or configuring a second connection does not silently reuse results
    fetched under the old one.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    user_id: Identifier | None = None
    provider_connection_id: Identifier | None = None
    scope: CacheScope = CacheScope.USER

    @classmethod
    def for_user(
        cls,
        *,
        provider_id: str,
        user_id: str,
        provider_connection_id: str | None = None,
    ) -> ExecutionScope:
        """A user-isolated scope."""
        return cls(
            provider_id=provider_id,
            user_id=user_id,
            provider_connection_id=provider_connection_id,
            scope=CacheScope.USER,
        )

    @classmethod
    def global_for_provider(cls, *, provider_id: str) -> ExecutionScope:
        """A shared scope, for providers whose answers cannot vary by caller.

        Never constructed implicitly — a provider policy has to ask for it.
        """
        return cls(provider_id=provider_id, scope=CacheScope.GLOBAL)

    @property
    def identity(self) -> str:
        """The stable, non-secret identity string for this scope.

        Built from identifiers only. No credential, secret reference or
        authorization material can reach it, because none of those are fields
        on this model.
        """
        if self.scope is CacheScope.GLOBAL:
            return f"global|{self.provider_id}"
        connection = self.provider_connection_id or "-"
        return f"user|{self.user_id or '-'}|{self.provider_id}|{connection}"

    def operation_key(self, operation: str | None = None) -> str:
        """The scope identity narrowed to one operation, or provider-wide."""
        return f"{self.identity}|{operation or '*'}"


class ExecutionContext(FrozenTiReconModel):
    """Who the work is being done for.

    Identity only. ``authenticated_user_id`` must come from the request's
    verified identity — never from a caller-supplied argument, an MCP tool
    parameter, or anything a model could influence.

    The provider and connection are deliberately *not* fields here: the provider
    comes from the adapter's own descriptor, and the connection is discovered by
    resolving this user's credential metadata. Accepting either from a caller
    would let one be paired with a mismatched identity.
    """

    authenticated_user_id: Identifier
    request_id: Identifier = Field(default_factory=new_id)
    credential_group: str | None = Field(default=None, max_length=64)


class ProviderExecutionOutcome(FrozenTiReconModel):
    """The result of executing one provider operation, including how it went.

    Kept separate from :class:`ProviderResultEnvelope`. The envelope is what the
    provider said; this is what *we* did to obtain it — how many attempts, cache
    or not, cooldown applied or not. Merging the two would mean rewriting a
    provider fact every time execution mechanics changed.

    Carries no verdict, risk score or confidence: the execution layer decides
    nothing about maliciousness.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    operation: ProviderOperation
    status: ProviderRunStatus
    request_id: Identifier
    scope_identity: str = Field(min_length=1, max_length=400)

    result: ProviderResultEnvelope | None = None
    error_category: ProviderErrorCategory | None = None
    error_message: str | None = Field(default=None, max_length=500)

    attempts: int = Field(default=0, ge=0)
    cache_hit: bool = False
    coalesced: bool = False

    started_at: UtcDatetime
    completed_at: UtcDatetime
    duration_ms: float = Field(ge=0.0)

    cooldown_applied: bool = False
    cooldown_until: UtcDatetime | None = None
    cooldown_reason: CooldownReason | None = None

    rate_limit_snapshot: RateLimitSnapshot | None = None
    quota_snapshot: ProviderQuotaSnapshot | None = None

    @model_validator(mode="after")
    def _validate_outcome(self) -> ProviderExecutionOutcome:
        if self.completed_at < self.started_at:
            msg = "completed_at must not precede started_at"
            raise ValueError(msg)
        if self.status in _RESULT_REQUIRED_STATUSES and self.result is None:
            msg = f"a {self.status.value} outcome must carry a provider result"
            raise ValueError(msg)
        if self.result is not None and self.result.status is not self.status:
            msg = "outcome status must match the provider result it carries"
            raise ValueError(msg)
        if self.status is ProviderRunStatus.ERROR and self.error_category is None:
            msg = "a failed outcome must carry a normalized error category"
            raise ValueError(msg)
        if self.cooldown_applied and self.cooldown_until is None:
            msg = "an applied cooldown must record when it lifts"
            raise ValueError(msg)
        if self.cooldown_applied and self.cooldown_reason is None:
            msg = "an applied cooldown must record why"
            raise ValueError(msg)
        if self.cache_hit and self.attempts:
            msg = "a cache hit must not report provider attempts"
            raise ValueError(msg)
        if self.error_message and SENSITIVE_KEY_PATTERN.search(self.error_message):
            msg = "error_message must not mention credential material"
            raise ValueError(msg)
        return self

    @property
    def called_provider(self) -> bool:
        """Whether this outcome cost a real provider request."""
        return self.attempts > 0

    @property
    def retry_count(self) -> int:
        """Attempts beyond the first."""
        return max(0, self.attempts - 1)

    @property
    def has_data(self) -> bool:
        """Whether the provider contributed anything.

        ``False`` says the provider had nothing to add — never that the
        observable is benign. This layer has no such notion.
        """
        return self.result is not None and self.result.has_data

    def to_provider_run(
        self, *, investigation_id: Identifier, capability: ProviderCapability
    ) -> ProviderRun:
        """Record this execution as a Task 3 :class:`ProviderRun`.

        Uses the execution timings rather than the envelope's, so a cache hit is
        recorded as the fast operation it actually was, while the envelope keeps
        the provider's original ``retrieved_at`` untouched.
        """
        return ProviderRun(
            investigation_id=investigation_id,
            provider=self.provider_id,
            capability=capability,
            operation=self.operation,
            status=self.status,
            cache_hit=self.cache_hit,
            started_at=self.started_at,
            completed_at=self.completed_at,
            api_version=self.result.api_version if self.result else None,
            adapter_version=self.result.adapter_version if self.result else None,
            error_code=self.error_category,
            raw_reference_id=(
                self.result.raw_reference.id if self.result and self.result.raw_reference else None
            ),
        )


#: Statuses that only make sense if a provider result came back.
#:
#: Only ``SUCCESS``. Two near-misses are deliberately excluded:
#:
#: * ``NO_DATA`` — a normalized "not found" is a legitimate answer with no
#:   envelope behind it.
#: * ``PARTIAL`` — usually an envelope carrying reduced evidence, but an adapter
#:   may also *raise* ``PARTIAL_RESULT`` when it could not retrieve enough to
#:   build one. Task 5 maps that category to ``PARTIAL``, so requiring a result
#:   here would make a legal adapter behaviour unrepresentable.
_RESULT_REQUIRED_STATUSES = frozenset({ProviderRunStatus.SUCCESS})
