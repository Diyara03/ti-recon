"""Bounding what one remote analyst can start at once (Task 22).

Task 13 bounds the work *inside* one investigation — how many providers it may
call, how deep it may go, how far it may pivot. It says nothing about how many
investigations one person may have running, because over stdio the answer was
structural: one process, one analyst, one conversation, one call at a time.

Over HTTP it is not. An authenticated caller can open as many concurrent
requests as they like, and a DEEP investigation with pivot enrichment is the most
expensive thing this system does. So the remote profile adds one small control
the local profile does not need.

**One active investigation per tenant per process.** Deliberately the simplest
policy that closes the hole, and deliberately not a queue: a caller who is told
"try again" immediately still has a working service, whereas a caller waiting
behind an unbounded backlog has a slow one and a server holding memory for
requests nobody is waiting on any more.

``provider_status`` never takes a slot. It reads local configuration, contacts
nothing, and blocking it would make the diagnostic unavailable exactly when
somebody is trying to work out why their investigation is stuck.

This is not Task 6's provider concurrency, which bounds calls to one provider
under one credential and stays exactly as it was. This bounds whole
investigations, per tenant, and exists only on the remote path.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

__all__ = ["TenantBusyError", "TenantInvestigationLimiter"]


class TenantBusyError(RuntimeError):
    """This tenant already has an investigation running.

    A refusal, not a delay. The caller is told plainly and can retry; nothing is
    queued on their behalf.
    """


class TenantInvestigationLimiter:
    """At most one concurrent investigation per tenant, in one process.

    Keyed by the pseudonymous tenant id and nothing else — no observable, no
    subject, no token, no client id. Entries are removed as soon as a tenant has
    nothing running, so a long-lived server that has served a million analysts
    holds no record of any of them.

    Process-local, like every other execution store in the repository. That is
    what makes the remote deployment single-worker until Task 24 gives Task 6 a
    shared backend: four workers would enforce this four times independently.
    """

    def __init__(self, *, max_concurrent: int = 1) -> None:
        if max_concurrent < 1:
            msg = "max_concurrent must be at least 1"
            raise ValueError(msg)
        self._max_concurrent = max_concurrent
        self._active: dict[str, int] = {}

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    def active_count(self, tenant_id: str) -> int:
        """How many investigations this tenant has running right now."""
        return self._active.get(tenant_id, 0)

    @property
    def tracked_tenants(self) -> int:
        """Tenants currently holding a slot. Zero when the server is idle."""
        return len(self._active)

    @asynccontextmanager
    async def hold(self, tenant_id: str) -> AsyncIterator[None]:
        """Hold this tenant's slot for the duration of the block.

        Released in ``finally``, so completion, a provider raising, a structural
        fault and cancellation all give the slot back. A slot leaked on the
        cancellation path would lock an analyst out of their own account for the
        life of the process — and cancellation is the *common* case, because a
        client that goes away mid-investigation is ordinary.

        No ``await`` separates the check from the reservation, so two coroutines
        on one event loop cannot both observe a free slot.
        """
        if self._active.get(tenant_id, 0) >= self._max_concurrent:
            raise TenantBusyError(tenant_id)
        self._active[tenant_id] = self._active.get(tenant_id, 0) + 1
        try:
            yield
        finally:
            self._release(tenant_id)

    def _release(self, tenant_id: str) -> None:
        remaining = self._active.get(tenant_id, 0) - 1
        if remaining > 0:
            self._active[tenant_id] = remaining
        else:
            # Dropped rather than left at zero: the dict would otherwise grow by
            # one entry per analyst who ever connected and never shrink.
            self._active.pop(tenant_id, None)

    def __repr__(self) -> str:
        return (
            f"<TenantInvestigationLimiter max={self._max_concurrent} tenants={len(self._active)}>"
        )
