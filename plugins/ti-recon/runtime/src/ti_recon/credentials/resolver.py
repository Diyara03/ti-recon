"""User-scoped credential resolution (Task 4).

Resolution is always keyed by ``(authenticated_user_id, credential group)``.
The parameter is named ``authenticated_user_id`` on purpose: it must come from
the request's verified identity, never from a caller-supplied argument, an MCP
tool parameter or anything a model could influence.
"""

from __future__ import annotations

import logging

from ti_recon.credentials.errors import (
    CredentialNotConfigured,
    CredentialUnusable,
    PolicyDenied,
)
from ti_recon.credentials.groups import credential_group_for
from ti_recon.credentials.models import (
    USABLE_POLICY_STATUSES,
    CredentialMaterial,
    ProviderConnection,
)
from ti_recon.credentials.repository import ConnectionRepository
from ti_recon.credentials.secret_store import SecretStore

__all__ = ["CredentialResolver"]

_logger = logging.getLogger(__name__)


class CredentialResolver:
    """Resolves a provider credential for one authenticated user."""

    def __init__(self, secret_store: SecretStore, repository: ConnectionRepository) -> None:
        self._secrets = secret_store
        self._repository = repository

    async def resolve(
        self,
        *,
        authenticated_user_id: str,
        provider_id: str,
        credential_group: str | None = None,
    ) -> CredentialMaterial:
        """Return the credential this user has configured for ``provider_id``.

        Raises :class:`CredentialNotConfigured` when the user has no connection,
        :class:`PolicyDenied` when policy forbids the provider, and
        :class:`CredentialUnusable` when the credential is known to be bad.

        A user can only ever reach their own secrets: the connection lookup is
        scoped to them, and the secret reference on that connection is
        validated to be owned by them.
        """
        group = credential_group or credential_group_for(provider_id)
        connection = await self._repository.find_by_group(authenticated_user_id, group)
        if connection is None:
            raise CredentialNotConfigured(provider_id, group)
        self._assert_ownership(connection, authenticated_user_id)

        if connection.policy_status not in USABLE_POLICY_STATUSES:
            raise PolicyDenied(provider_id, connection.policy_status)
        if not connection.is_usable:
            raise CredentialUnusable(provider_id, connection.status)

        secret = await self._secrets.get_secret(connection.secret_reference)
        _logger.debug(
            "credential resolved",
            extra={"provider": provider_id, "credential_group": group},
        )
        return CredentialMaterial(
            connection_id=connection.id,
            user_id=connection.user_id,
            provider_id=provider_id,
            credential_group=group,
            auth_type=connection.auth_type,
            secret=secret,
        )

    async def resolve_connection(
        self,
        *,
        authenticated_user_id: str,
        provider_id: str,
        credential_group: str | None = None,
    ) -> ProviderConnection | None:
        """Return this user's connection metadata, without touching the secret.

        Exists so a caller can establish *which credential* work will be done
        with — for cache and quota scoping — before deciding whether a provider
        call is needed at all. A request served from cache should never cause a
        secret to be read out of the store.

        Returns ``None`` when this user has no connection, identically to a
        connection that belongs to somebody else.
        """
        group = credential_group or credential_group_for(provider_id)
        connection = await self._repository.find_by_group(authenticated_user_id, group)
        if connection is None:
            return None
        self._assert_ownership(connection, authenticated_user_id)
        return connection

    async def has_credential(
        self,
        *,
        authenticated_user_id: str,
        provider_id: str,
        credential_group: str | None = None,
    ) -> bool:
        """Whether this user has a usable credential for ``provider_id``.

        Used to decide whether a provider is worth calling at all, without
        resolving — and therefore without touching — the secret.
        """
        group = credential_group or credential_group_for(provider_id)
        connection = await self._repository.find_by_group(authenticated_user_id, group)
        return connection is not None and connection.is_usable

    @staticmethod
    def _assert_ownership(connection: ProviderConnection, authenticated_user_id: str) -> None:
        """Belt-and-braces check that a repository cannot hand over a foreign record."""
        if (
            connection.user_id != authenticated_user_id
            or connection.secret_reference.owner_user_id != authenticated_user_id
        ):  # pragma: no cover - unreachable unless a repository misbehaves
            msg = "connection ownership mismatch"
            raise PermissionError(msg)
