"""Secret store abstraction (Task 4).

The store is intentionally minimal — put, get, delete, exists — and every
operation is keyed by a :class:`SecretRef` that carries the owner. There is no
"list all secrets" and no "get by bare key": both would make cross-tenant
leakage a one-line mistake.

Only an in-memory implementation exists. A production backend (HashiCorp Vault,
a cloud KMS-backed store) is a later task; this Protocol is the seam it will
slot into.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from ti_recon.credentials.errors import SecretNotFound
from ti_recon.credentials.models import SecretRef

__all__ = ["InMemorySecretStore", "SecretStore"]


@runtime_checkable
class SecretStore(Protocol):
    """Async storage for provider credential material."""

    async def put_secret(self, ref: SecretRef, secret: SecretStr) -> None:
        """Store (or overwrite) the secret at ``ref``."""
        ...

    async def get_secret(self, ref: SecretRef) -> SecretStr:
        """Return the secret at ``ref``.

        Raises :class:`SecretNotFound` if no secret exists at ``ref`` for that
        owner — including when a secret with the same key exists under a
        different owner.
        """
        ...

    async def delete_secret(self, ref: SecretRef) -> None:
        """Remove the secret at ``ref``. Deleting a missing secret is a no-op."""
        ...

    async def exists(self, ref: SecretRef) -> bool:
        """Whether a secret is stored at ``ref``."""
        ...


class InMemorySecretStore:
    """Process-local secret store.

    **NOT FOR PRODUCTION.** Secrets are held unencrypted in process memory,
    are lost on restart, are not shared between workers, and are not audited.
    It exists so the credential layer can be developed and tested without
    standing up a vault.

    Isolation is enforced here rather than assumed: entries are keyed by
    ``(owner_user_id, key)``, so a caller holding another user's key string
    still cannot read their secret.
    """

    #: Read by callers that refuse to start with a development-only backend.
    is_production_ready: bool = False

    def __init__(self) -> None:
        self._secrets: dict[tuple[str, str], SecretStr] = {}
        self._lock = asyncio.Lock()

    async def put_secret(self, ref: SecretRef, secret: SecretStr) -> None:
        async with self._lock:
            self._secrets[self._index(ref)] = secret

    async def get_secret(self, ref: SecretRef) -> SecretStr:
        async with self._lock:
            secret = self._secrets.get(self._index(ref))
        if secret is None:
            raise SecretNotFound(ref.key)
        return secret

    async def delete_secret(self, ref: SecretRef) -> None:
        async with self._lock:
            self._secrets.pop(self._index(ref), None)

    async def exists(self, ref: SecretRef) -> bool:
        async with self._lock:
            return self._index(ref) in self._secrets

    @staticmethod
    def _index(ref: SecretRef) -> tuple[str, str]:
        return (ref.owner_user_id, ref.key)

    def __len__(self) -> int:
        return len(self._secrets)

    def __repr__(self) -> str:
        """Report size only — never keys, owners or values."""
        return f"<InMemorySecretStore entries={len(self._secrets)}>"
