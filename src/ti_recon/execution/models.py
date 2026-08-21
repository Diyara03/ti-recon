"""Shared execution vocabulary (Task 6).

The isolation identity every execution control keys on, and the enums that
several modules need. Deliberately dependency-light so the cache, limits and
coordination modules can all import it without forming a cycle.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, Identifier

__all__ = ["CacheScope", "CooldownReason", "ExecutionScope"]


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
