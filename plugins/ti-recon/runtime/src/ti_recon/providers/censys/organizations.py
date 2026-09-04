"""Resolving a Censys organization id, per connection (Task 9).

Censys reports credits at two addresses: one for the user the token belongs to,
and one for a named organization. Which one applies is a property of the
credential, not of the deployment — one analyst's token belongs to an
organization account and another's does not.

Why the id does not live on the credential
------------------------------------------

An organization id is not a secret; it appears in a URL path.
:class:`~ti_recon.credentials.models.CredentialMaterial` deliberately carries
nothing but identifiers and the secret, and widening it to hold provider-specific
non-secret configuration would make every future provider's settings travel with
every resolved secret. Instead the id lives where other non-secret per-connection
configuration already lives — ``ProviderConnection.metadata`` — and is looked up
through this small indirection.

Why the lookup is scoped by user *and* connection
-------------------------------------------------

Because a lookup keyed by connection alone is a cross-tenant bug waiting to
happen. The organization id decides which account's credit balance is read; if
one analyst's connection id could resolve another analyst's organization, TI
Recon would report the wrong balance and, worse, would send a request against an
account the caller has nothing to do with. Every method here takes both, and
:class:`ConnectionOrganizationDirectory` resolves through the Task 4 repository,
which already refuses to hand one user another's connection.

Why the id is validated before use
----------------------------------

It is interpolated into a request path. Connection metadata is operator-supplied
rather than analyst-supplied, so this is defence in depth rather than the primary
control — but a path parameter that has not been shape-checked is exactly the
kind of thing that turns into a traversal. An unusable value resolves to
``None``, which falls back to the user-scoped endpoint; it never becomes part of
a URL.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Final, Protocol

from ti_recon.credentials.repository import ConnectionRepository
from ti_recon.providers.censys.descriptor import CENSYS_PROVIDER_ID

__all__ = [
    "ORGANIZATION_ID_PATTERN",
    "ORGANIZATION_METADATA_KEY",
    "ConnectionOrganizationDirectory",
    "OrganizationDirectory",
    "StaticOrganizationDirectory",
    "normalize_organization_id",
]

_logger = logging.getLogger(__name__)

#: Where an organization id is expected in ``ProviderConnection.metadata``.
ORGANIZATION_METADATA_KEY: Final[str] = "organization_id"

#: The shape an organization id must have to reach a request path. Deliberately
#: strict: identifiers, not text. No dots, no slashes, no percent signs, so no
#: value that passes can traverse or escape a path segment.
ORGANIZATION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def normalize_organization_id(value: object) -> str | None:
    """A usable organization id, or ``None``.

    ``None`` covers both "not configured" and "configured with something that
    must not reach a URL". Callers treat them the same way — fall back to the
    user-scoped endpoint — because in both cases there is no organization to ask
    about.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or not ORGANIZATION_ID_PATTERN.fullmatch(candidate):
        return None
    return candidate


class OrganizationDirectory(Protocol):
    """Resolves the Censys organization one credential belongs to."""

    async def organization_id_for(self, *, user_id: str, connection_id: str) -> str | None: ...


class ConnectionOrganizationDirectory:
    """Reads the organization id out of the user's own provider connection.

    The repository lookup is scoped by ``user_id``, so this cannot return an
    organization belonging to anybody else — the isolation is the Task 4
    repository's, not a rule this class remembers to follow.
    """

    def __init__(
        self,
        repository: ConnectionRepository,
        *,
        metadata_key: str = ORGANIZATION_METADATA_KEY,
    ) -> None:
        self._repository = repository
        self._metadata_key = metadata_key

    async def organization_id_for(self, *, user_id: str, connection_id: str) -> str | None:
        connection = await self._repository.get(user_id, connection_id)
        if connection is None:
            return None
        raw = connection.metadata.get(self._metadata_key)
        organization_id = normalize_organization_id(raw)
        if organization_id is None and raw is not None:
            # Logged rather than raised: a malformed id must not fail a lookup
            # that the user-scoped endpoint can still answer. The value itself is
            # never logged — only that there was one and it was unusable.
            _logger.info(
                "censys organization id ignored as unusable",
                extra={
                    "provider": CENSYS_PROVIDER_ID,
                    "metadata_key": self._metadata_key,
                },
            )
        return organization_id


class StaticOrganizationDirectory:
    """An in-memory directory, for tests and single-tenant deployments.

    Keyed by ``(user_id, connection_id)`` rather than by connection alone, so it
    has the same cross-user property as the repository-backed implementation: a
    connection id on its own resolves nothing.
    """

    def __init__(self, organizations: Mapping[tuple[str, str], str] | None = None) -> None:
        self._organizations = dict(organizations or {})

    def set(self, *, user_id: str, connection_id: str, organization_id: str) -> None:
        normalized = normalize_organization_id(organization_id)
        if normalized is None:
            msg = "organization_id has an unusable shape"
            raise ValueError(msg)
        self._organizations[(user_id, connection_id)] = normalized

    async def organization_id_for(self, *, user_id: str, connection_id: str) -> str | None:
        return self._organizations.get((user_id, connection_id))

    def __len__(self) -> int:
        return len(self._organizations)

    def __repr__(self) -> str:
        return f"<StaticOrganizationDirectory entries={len(self._organizations)}>"
