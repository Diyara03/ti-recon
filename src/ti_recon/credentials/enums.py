"""Credential-layer vocabularies (Task 4)."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["AuthType", "CredentialStatus", "PolicyStatus"]


class AuthType(StrEnum):
    """How a provider expects its credential to be presented.

    ``AUTH_KEY`` is separate from ``API_KEY`` because some providers (the
    abuse.ch family, for instance) use an ``Auth-Key`` header shared across
    several services, which is a different credential-grouping shape.
    """

    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    AUTH_KEY = "auth_key"
    OAUTH = "oauth"


class CredentialStatus(StrEnum):
    """State of the credential itself.

    Kept strictly separate from provider runtime status and provider health: a
    provider being down says nothing about whether a key is valid, and a revoked
    key says nothing about whether the provider is up.
    """

    ACTIVE = "active"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class PolicyStatus(StrEnum):
    """Whether organizational policy permits using a provider connection.

    A third, independent axis: a credential can be perfectly valid and the
    provider perfectly healthy while policy still forbids sending data there.
    """

    ALLOWED = "allowed"
    RESTRICTED = "restricted"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    UNKNOWN = "unknown"
