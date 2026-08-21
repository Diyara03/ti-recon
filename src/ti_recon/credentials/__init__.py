"""Per-user provider credential foundation (Task 4).

Provider credentials are held per user, referenced indirectly, and resolved
only under the authenticated user's identity. The secret store implementation
here is in-memory and explicitly **not for production**.
"""

from ti_recon.credentials.enums import AuthType, CredentialStatus, PolicyStatus
from ti_recon.credentials.errors import (
    ConnectionNotFound,
    CredentialError,
    CredentialNotConfigured,
    CredentialUnusable,
    PolicyDenied,
    SecretNotFound,
    SecretStoreError,
)
from ti_recon.credentials.groups import (
    ABUSE_CH_GROUP,
    CREDENTIAL_GROUP_MEMBERS,
    credential_group_for,
    providers_in_group,
)
from ti_recon.credentials.manager import CredentialManager
from ti_recon.credentials.models import (
    CredentialMaterial,
    ProviderConnection,
    SecretRef,
)
from ti_recon.credentials.repository import (
    ConnectionRepository,
    InMemoryConnectionRepository,
)
from ti_recon.credentials.resolver import CredentialResolver
from ti_recon.credentials.secret_store import InMemorySecretStore, SecretStore

__all__ = [
    "ABUSE_CH_GROUP",
    "CREDENTIAL_GROUP_MEMBERS",
    "AuthType",
    "ConnectionNotFound",
    "ConnectionRepository",
    "CredentialError",
    "CredentialManager",
    "CredentialMaterial",
    "CredentialNotConfigured",
    "CredentialResolver",
    "CredentialStatus",
    "CredentialUnusable",
    "InMemoryConnectionRepository",
    "InMemorySecretStore",
    "PolicyDenied",
    "PolicyStatus",
    "ProviderConnection",
    "SecretNotFound",
    "SecretRef",
    "SecretStore",
    "SecretStoreError",
    "credential_group_for",
    "providers_in_group",
]
