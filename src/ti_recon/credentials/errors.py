"""Credential-layer errors.

No error in this module may include secret material in its message. Messages
name the provider, the credential group and the status — never the value.
"""

from __future__ import annotations

from ti_recon.credentials.enums import CredentialStatus, PolicyStatus

__all__ = [
    "ConnectionNotFound",
    "CredentialError",
    "CredentialNotConfigured",
    "CredentialUnusable",
    "PolicyDenied",
    "SecretNotFound",
    "SecretStoreError",
]


class CredentialError(Exception):
    """Base class for credential-layer failures."""


class CredentialNotConfigured(CredentialError):
    """No usable provider connection exists for this user and provider.

    Deliberately indistinguishable from "a connection exists but belongs to
    someone else": telling a caller that another user has configured a provider
    is itself a cross-tenant information leak.
    """

    def __init__(self, provider_id: str, credential_group: str) -> None:
        self.provider_id = provider_id
        self.credential_group = credential_group
        super().__init__(
            f"no credential configured for provider {provider_id!r} "
            f"(credential group {credential_group!r})"
        )


class ConnectionNotFound(CredentialError):
    """This user has no connection with the given id.

    Raised identically whether the id does not exist or belongs to someone
    else, so the error cannot be used to probe other users' configuration.
    """

    def __init__(self, connection_id: str) -> None:
        self.connection_id = connection_id
        super().__init__(f"no provider connection {connection_id!r} for this user")


class CredentialUnusable(CredentialError):
    """A connection exists but its credential cannot currently be used."""

    def __init__(self, provider_id: str, status: CredentialStatus) -> None:
        self.provider_id = provider_id
        self.status = status
        super().__init__(
            f"credential for provider {provider_id!r} is not usable (status {status.value})"
        )


class PolicyDenied(CredentialError):
    """Organizational policy forbids using this provider connection."""

    def __init__(self, provider_id: str, policy_status: PolicyStatus) -> None:
        self.provider_id = provider_id
        self.policy_status = policy_status
        super().__init__(
            f"policy forbids using provider {provider_id!r} (policy status {policy_status.value})"
        )


class SecretStoreError(CredentialError):
    """The secret store could not complete an operation."""


class SecretNotFound(SecretStoreError):
    """No secret exists at the given reference for the given owner.

    Raised both when the reference does not exist and when it exists but is
    owned by another user, so the store cannot be used as an oracle for what
    other users have configured.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"no secret found for reference {key!r}")
