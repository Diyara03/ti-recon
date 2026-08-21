"""Provider-connection storage (Task 4).

Every operation is scoped by ``user_id``. There is deliberately no
``get(connection_id)`` and no global listing: an unscoped read is the shape
cross-tenant leaks take, so the interface does not offer one.

Only an in-memory implementation exists; persistence is a later task.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from ti_recon.credentials.models import ProviderConnection

__all__ = ["ConnectionRepository", "InMemoryConnectionRepository"]


@runtime_checkable
class ConnectionRepository(Protocol):
    """Async storage for :class:`ProviderConnection` records."""

    async def save(self, connection: ProviderConnection) -> None:
        """Insert or update a connection."""
        ...

    async def get(self, user_id: str, connection_id: str) -> ProviderConnection | None:
        """Return the user's connection, or ``None`` if they have no such connection."""
        ...

    async def find_by_group(self, user_id: str, credential_group: str) -> ProviderConnection | None:
        """Return the user's connection for a credential group, if any."""
        ...

    async def list_for_user(self, user_id: str) -> list[ProviderConnection]:
        """Return all of the user's connections, in deterministic order."""
        ...

    async def delete(self, user_id: str, connection_id: str) -> bool:
        """Delete the user's connection; return whether anything was deleted."""
        ...


class InMemoryConnectionRepository:
    """Process-local connection storage.

    **NOT FOR PRODUCTION.** State is lost on restart and not shared between
    workers.

    At most one connection may exist per ``(user_id, credential_group)``, which
    keeps credential resolution deterministic: there is never a question of
    which of a user's two keys for the same provider should be used.
    """

    is_production_ready: bool = False

    def __init__(self) -> None:
        self._connections: dict[tuple[str, str], ProviderConnection] = {}
        self._lock = asyncio.Lock()

    async def save(self, connection: ProviderConnection) -> None:
        async with self._lock:
            existing = self._find_by_group(connection.user_id, connection.credential_group)
            if existing is not None and existing.id != connection.id:
                msg = (
                    f"user already has a connection for credential group "
                    f"{connection.credential_group!r}"
                )
                raise ValueError(msg)
            self._connections[(connection.user_id, connection.id)] = connection

    async def get(self, user_id: str, connection_id: str) -> ProviderConnection | None:
        async with self._lock:
            return self._connections.get((user_id, connection_id))

    async def find_by_group(self, user_id: str, credential_group: str) -> ProviderConnection | None:
        async with self._lock:
            return self._find_by_group(user_id, credential_group)

    async def list_for_user(self, user_id: str) -> list[ProviderConnection]:
        async with self._lock:
            owned = [
                connection
                for (owner, _), connection in self._connections.items()
                if owner == user_id
            ]
        return sorted(owned, key=lambda connection: (connection.credential_group, connection.id))

    async def delete(self, user_id: str, connection_id: str) -> bool:
        async with self._lock:
            return self._connections.pop((user_id, connection_id), None) is not None

    def _find_by_group(self, user_id: str, credential_group: str) -> ProviderConnection | None:
        for (owner, _), connection in self._connections.items():
            if owner == user_id and connection.credential_group == credential_group:
                return connection
        return None

    def __len__(self) -> int:
        return len(self._connections)

    def __repr__(self) -> str:
        return f"<InMemoryConnectionRepository connections={len(self._connections)}>"
