"""Provider result cache (Task 6).

Caching provider results saves quota, latency and duplicated work. It also
introduces the sharpest data-isolation risk in the platform: a result fetched
with one analyst's Enterprise credential, against their quota, reflecting their
plan's entitlements, must never be handed to a different analyst.

So isolation is built into the key rather than checked around it. A cache key
cannot be constructed without naming a scope, and the scope's identity is part
of the stored key — there is no lookup that spans users.

Only :class:`InMemoryProviderCache` exists. The protocol is the seam a
``RedisProviderCache`` will slot into later without the executor changing.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.models import CacheScope, ExecutionScope
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope

__all__ = ["CacheKey", "InMemoryProviderCache", "ProviderCache", "build_cache_key"]

#: Version marker mixed into every key. Bumping it invalidates every cached
#: entry at once, which is what a change to the key recipe requires.
_KEY_SCHEMA_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class CacheKey:
    """A scoped, deterministic cache key.

    ``scope_identity`` is kept separate from ``digest`` so the storage key is
    obviously partitioned by scope and cannot collide across users even if two
    digests ever did.
    """

    scope: CacheScope
    scope_identity: str
    digest: str

    @property
    def storage_key(self) -> str:
        return f"{_KEY_SCHEMA_VERSION}|{self.scope_identity}|{self.digest}"

    def __str__(self) -> str:
        return self.storage_key


def build_cache_key(
    *,
    scope: ExecutionScope,
    descriptor: ProviderDescriptor,
    request: ProviderRequest,
) -> CacheKey:
    """Build the cache key for one provider request.

    Everything that changes the *meaning* of a request is in the key. Two things
    are deliberately excluded:

    * ``investigation_id`` — the same analyst asking about the same observable
      twenty minutes later, in a different investigation, is asking the same
      question. Including it would make the cache almost never hit.
    * anything secret — the key is built from identifiers, request options and
      version strings only. There is no field on the inputs that could carry
      credential material.

    ``api_version`` and ``adapter_version`` are included so that upgrading an
    adapter, or a provider moving to a new API version, does not serve results
    parsed by the old code.
    """
    capabilities = ",".join(
        sorted(capability.value for capability in request.requested_capabilities)
    )
    parts = (
        f"scope={scope.scope.value}",
        f"identity={scope.identity}",
        f"provider={descriptor.provider_id}",
        f"operation={request.operation.value}",
        f"object={request.intel_object.canonical_key}",
        f"capabilities={capabilities}",
        f"depth={request.depth.value}",
        f"activity={request.activity_mode.value}",
        f"max_results={request.max_results if request.max_results is not None else '-'}",
        f"max_pages={request.max_pages if request.max_pages is not None else '-'}",
        f"api_version={descriptor.api_version}",
        f"adapter_version={descriptor.adapter_version}",
    )
    canonical = "\n".join(parts)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return CacheKey(scope=scope.scope, scope_identity=scope.identity, digest=digest)


@runtime_checkable
class ProviderCache(Protocol):
    """Storage for provider results, always addressed by a scoped key."""

    async def get(self, key: CacheKey) -> ProviderResultEnvelope | None:
        """Return the cached result, or ``None`` on a miss or expiry."""
        ...

    async def set(self, key: CacheKey, envelope: ProviderResultEnvelope, ttl_seconds: int) -> None:
        """Store a result for ``ttl_seconds``."""
        ...

    async def invalidate(self, key: CacheKey) -> None:
        """Drop one entry. Dropping a missing entry is a no-op."""
        ...

    async def clear(self) -> None:
        """Drop everything."""
        ...


@dataclass(slots=True)
class _Entry:
    envelope: ProviderResultEnvelope
    expires_at_monotonic: float


class InMemoryProviderCache:
    """Process-local provider result cache.

    **NOT FOR PRODUCTION.** Entries live in one process's heap: they are lost on
    restart, not shared between workers, and give no cross-process coordination.
    A distributed implementation is a later task.

    Two details matter more than they look:

    * expiry uses monotonic time, so a host clock correction cannot resurrect an
      expired entry or expire a fresh one;
    * results are deep-copied on the way in and on the way out. Envelopes are
      frozen, but the ``attributes`` dict inside a piece of evidence is not, and
      a caller that mutated it would silently corrupt what every later reader
      sees.
    """

    is_production_ready: bool = False

    def __init__(self, *, clock: Clock | None = None, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)
        self._clock = SystemClock() if clock is None else clock
        self._max_entries = max_entries
        # Ordered so eviction can drop the least recently used entry rather than
        # growing without bound in a long-running process.
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

    async def get(self, key: CacheKey) -> ProviderResultEnvelope | None:
        storage_key = key.storage_key
        entry = self._entries.get(storage_key)
        if entry is None:
            return None
        if entry.expires_at_monotonic <= self._clock.monotonic():
            del self._entries[storage_key]
            return None
        self._entries.move_to_end(storage_key)
        return entry.envelope.model_copy(deep=True)

    async def set(self, key: CacheKey, envelope: ProviderResultEnvelope, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        storage_key = key.storage_key
        self._entries[storage_key] = _Entry(
            envelope=envelope.model_copy(deep=True),
            expires_at_monotonic=self._clock.monotonic() + ttl_seconds,
        )
        self._entries.move_to_end(storage_key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    async def invalidate(self, key: CacheKey) -> None:
        self._entries.pop(key.storage_key, None)

    async def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        """Report size only — never keys, scopes or cached content."""
        return f"<InMemoryProviderCache entries={len(self._entries)}>"
