"""Credential lifecycle management (Task 4).

Every method takes the acting user's id and scopes its work to that user. A
connection id alone is never enough to reach a record — passing someone else's
connection id behaves exactly as if the record did not exist.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import SecretStr

from ti_recon.credentials.enums import AuthType, CredentialStatus, PolicyStatus
from ti_recon.credentials.errors import ConnectionNotFound
from ti_recon.credentials.groups import credential_group_for
from ti_recon.credentials.models import ProviderConnection, SecretRef
from ti_recon.credentials.repository import ConnectionRepository
from ti_recon.credentials.secret_store import SecretStore
from ti_recon.models.base import new_id, utc_now

__all__ = ["CredentialManager"]

_logger = logging.getLogger(__name__)


class CredentialManager:
    """Create, replace, disable and remove per-user provider credentials."""

    def __init__(self, secret_store: SecretStore, repository: ConnectionRepository) -> None:
        self._secrets = secret_store
        self._repository = repository

    async def create_connection(
        self,
        *,
        user_id: str,
        provider_id: str,
        secret: str | SecretStr,
        auth_type: AuthType,
        credential_group: str | None = None,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
        status: CredentialStatus = CredentialStatus.UNKNOWN,
        policy_status: PolicyStatus = PolicyStatus.ALLOWED,
    ) -> ProviderConnection:
        """Store a new credential and return its connection metadata.

        The returned connection contains a ``secret_reference``, never the
        secret. A newly added credential starts as ``UNKNOWN`` rather than
        ``ACTIVE``: nothing has validated it yet, and claiming otherwise would
        make a typo look like a working integration.
        """
        group = credential_group or credential_group_for(provider_id)
        reference = SecretRef(owner_user_id=user_id, key=new_id())
        await self._secrets.put_secret(reference, _as_secret(secret))
        connection = ProviderConnection(
            user_id=user_id,
            provider_id=provider_id,
            credential_group=group,
            auth_type=auth_type,
            secret_reference=reference,
            status=status,
            policy_status=policy_status,
            label=label,
            metadata=metadata or {},
        )
        try:
            await self._repository.save(connection)
        except Exception:
            # Do not leave an orphaned secret behind if the record cannot be
            # written; the secret is unreachable without the connection anyway.
            await self._secrets.delete_secret(reference)
            raise
        _logger.info(
            "credential connection created",
            extra={"provider": provider_id, "credential_group": group},
        )
        return connection

    async def replace_credential(
        self,
        *,
        user_id: str,
        connection_id: str,
        secret: str | SecretStr,
        status: CredentialStatus = CredentialStatus.UNKNOWN,
    ) -> ProviderConnection:
        """Rotate the secret behind an existing connection.

        Order matters: write the new secret, switch the reference, then remove
        the old secret. Any other order leaves a window in which the connection
        points at a secret that is already gone.
        """
        connection = await self._require_connection(user_id, connection_id)
        old_reference = connection.secret_reference
        new_reference = SecretRef(owner_user_id=user_id, key=new_id())

        await self._secrets.put_secret(new_reference, _as_secret(secret))
        updated = connection.model_copy(
            update={
                "secret_reference": new_reference,
                "status": status,
                "last_validated_at": None,
                "updated_at": utc_now(),
            }
        )
        try:
            await self._repository.save(updated)
        except Exception:
            await self._secrets.delete_secret(new_reference)
            raise
        await self._secrets.delete_secret(old_reference)
        _logger.info(
            "credential replaced",
            extra={
                "provider": connection.provider_id,
                "credential_group": connection.credential_group,
            },
        )
        return updated

    async def disable_connection(self, *, user_id: str, connection_id: str) -> ProviderConnection:
        """Mark a connection unusable while keeping the stored secret."""
        return await self.set_status(
            user_id=user_id,
            connection_id=connection_id,
            status=CredentialStatus.DISABLED,
        )

    async def set_status(
        self,
        *,
        user_id: str,
        connection_id: str,
        status: CredentialStatus,
    ) -> ProviderConnection:
        """Record the outcome of a credential validation, or disable/re-enable."""
        connection = await self._require_connection(user_id, connection_id)
        update: dict[str, Any] = {"status": status, "updated_at": utc_now()}
        if status is CredentialStatus.ACTIVE:
            update["last_validated_at"] = utc_now()
        updated = connection.model_copy(update=update)
        await self._repository.save(updated)
        return updated

    async def record_usage(self, *, user_id: str, connection_id: str) -> ProviderConnection:
        """Record that a connection was used for a provider call."""
        connection = await self._require_connection(user_id, connection_id)
        updated = connection.model_copy(update={"last_used_at": utc_now()})
        await self._repository.save(updated)
        return updated

    async def disconnect(self, *, user_id: str, connection_id: str) -> bool:
        """Remove a connection and its secret. Returns whether it existed."""
        connection = await self._repository.get(user_id, connection_id)
        if connection is None:
            return False
        await self._repository.delete(user_id, connection_id)
        await self._secrets.delete_secret(connection.secret_reference)
        _logger.info(
            "credential connection removed",
            extra={
                "provider": connection.provider_id,
                "credential_group": connection.credential_group,
            },
        )
        return True

    async def get_connection(
        self, *, user_id: str, connection_id: str
    ) -> ProviderConnection | None:
        """Return connection metadata, or ``None`` if this user has no such connection."""
        return await self._repository.get(user_id, connection_id)

    async def list_connections(self, *, user_id: str) -> list[ProviderConnection]:
        """Return all of this user's connections."""
        return await self._repository.list_for_user(user_id)

    async def find_connection_for_provider(
        self, *, user_id: str, provider_id: str, credential_group: str | None = None
    ) -> ProviderConnection | None:
        """Return the connection that would serve ``provider_id`` for this user."""
        group = credential_group or credential_group_for(provider_id)
        return await self._repository.find_by_group(user_id, group)

    async def _require_connection(self, user_id: str, connection_id: str) -> ProviderConnection:
        connection = await self._repository.get(user_id, connection_id)
        if connection is None:
            raise ConnectionNotFound(connection_id)
        return connection


def _as_secret(secret: str | SecretStr) -> SecretStr:
    """Wrap raw credential material, rejecting empty input.

    An empty secret would be stored happily and then fail at request time as a
    confusing provider authentication error.
    """
    wrapped = secret if isinstance(secret, SecretStr) else SecretStr(secret)
    if not wrapped.get_secret_value():
        msg = "secret must not be empty"
        raise ValueError(msg)
    return wrapped
