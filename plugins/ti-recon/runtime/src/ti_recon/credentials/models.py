"""Credential models (Task 4).

The central rule: a :class:`ProviderConnection` holds a *reference* to secret
material, never the material itself. Connections are what the rest of the
system passes around, lists in an API response and writes to a log; keeping the
secret out of them by construction is stronger than remembering to redact it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from pydantic import Field, SecretStr, model_validator

from ti_recon.credentials.enums import AuthType, CredentialStatus, PolicyStatus
from ti_recon.models.base import (
    FrozenTiReconModel,
    Identifier,
    TiReconModel,
    UtcDatetime,
    new_id,
    utc_now,
)
from ti_recon.security import reject_credential_like_keys

__all__ = [
    "UNUSABLE_CREDENTIAL_STATUSES",
    "USABLE_POLICY_STATUSES",
    "CredentialMaterial",
    "ProviderConnection",
    "SecretRef",
]

#: Statuses that record a known failure; the credential must be replaced first.
UNUSABLE_CREDENTIAL_STATUSES: Final[frozenset[CredentialStatus]] = frozenset(
    {
        CredentialStatus.INVALID,
        CredentialStatus.EXPIRED,
        CredentialStatus.REVOKED,
        CredentialStatus.DISABLED,
    }
)

#: Policy states under which a connection may still be used.
USABLE_POLICY_STATUSES: Final[frozenset[PolicyStatus]] = frozenset(
    {PolicyStatus.ALLOWED, PolicyStatus.RESTRICTED}
)


class SecretRef(FrozenTiReconModel):
    """A pointer to secret material held in a :class:`SecretStore`.

    The owner is part of the reference, not a separate argument. A store lookup
    therefore cannot be performed without naming whose secret is wanted, which
    removes the class of bug where a caller passes a bare key it obtained from
    somewhere else and reads another user's credential.
    """

    owner_user_id: Identifier
    key: str = Field(min_length=1, max_length=200)

    def __str__(self) -> str:
        return f"secret-ref:{self.owner_user_id}/{self.key}"


class ProviderConnection(TiReconModel):
    """One user's configured access to one provider (or credential group).

    Three independent status axes are tracked deliberately:

    * ``status`` — is the credential itself usable;
    * ``policy_status`` — does organizational policy permit using it;
    * provider health and per-run status, which live in the provider layer.

    Collapsing any of these would make "provider is down" and "your key was
    revoked" indistinguishable to an analyst.
    """

    id: Identifier = Field(default_factory=new_id)
    user_id: Identifier
    provider_id: str = Field(min_length=1, max_length=64)
    credential_group: str = Field(min_length=1, max_length=64)
    auth_type: AuthType
    secret_reference: SecretRef
    status: CredentialStatus = CredentialStatus.UNKNOWN
    policy_status: PolicyStatus = PolicyStatus.ALLOWED
    label: str | None = Field(default=None, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)
    last_validated_at: UtcDatetime | None = None
    last_used_at: UtcDatetime | None = None
    expires_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _validate_connection(self) -> ProviderConnection:
        if self.secret_reference.owner_user_id != self.user_id:
            msg = "secret_reference must be owned by the connection's user"
            raise ValueError(msg)
        reject_credential_like_keys(self.metadata, where="ProviderConnection.metadata")
        return self

    @property
    def is_usable(self) -> bool:
        """Whether this connection may be used for a lookup right now."""
        return self.is_usable_at(utc_now())

    def is_usable_at(self, moment: datetime) -> bool:
        """Whether this connection is usable at ``moment``.

        ``UNKNOWN`` counts as usable: a freshly added key has not been validated
        yet, and the way to find out whether it works is to use it. Statuses
        that record a known failure do not.
        """
        if self.status in UNUSABLE_CREDENTIAL_STATUSES:
            return False
        if self.policy_status not in USABLE_POLICY_STATUSES:
            return False
        return not (self.expires_at is not None and self.expires_at <= moment)


class CredentialMaterial(FrozenTiReconModel):
    """A resolved credential, held in memory only for the duration of a call.

    The secret is wrapped in ``SecretStr`` so it cannot reach a log, a
    traceback or a serialized payload by accident. Reading it requires calling
    :meth:`reveal` — a deliberately conspicuous name, so every place that
    handles the raw value is one grep away.
    """

    connection_id: Identifier
    user_id: Identifier
    provider_id: str = Field(min_length=1, max_length=64)
    credential_group: str = Field(min_length=1, max_length=64)
    auth_type: AuthType
    secret: SecretStr

    def reveal(self) -> str:
        """Return the raw secret. Only the transport layer should call this."""
        return self.secret.get_secret_value()
