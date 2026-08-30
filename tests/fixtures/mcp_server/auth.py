"""Fake remote-auth material, for tests only (Task 22).

A delegate token verifier lives here rather than in ``src`` deliberately. A
permissive verifier reachable from a production composition — one that decodes a
token without proving it, or trusts an issuer claim — is the single change that
would turn the whole isolation boundary into decoration. Keeping every fake on
this side of the tree means there is nothing to reach.

``FakeDelegateVerifier`` stands in for whatever a deployment really uses: a
signed-JWT validator, an RFC 7662 introspection client, or an identity
platform's own. It returns an already-verified :class:`AccessToken`, which is
exactly the contract the strict wrapper composes over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp.server.auth.provider import AccessToken
from pydantic import SecretStr

from ti_recon.mcp_server.auth import RemoteAuthConfig

#: Unmistakable, so a match anywhere in an output cannot be a coincidence.
FAKE_MCP_TOKEN = "SUPER_SECRET_MCP_ACCESS_TOKEN_123"
FAKE_TENANT_SECRET = "SUPER_SECRET_TENANT_DERIVATION_KEY_123"
FAKE_PROVIDER_TOKEN = "SUPER_SECRET_PROVIDER_API_KEY_789"

#: A deliberately identifying subject, so "did the raw subject leak?" is a
#: question with a searchable answer.
FAKE_SUBJECT = "analyst.person@example.invalid"

ISSUER = "https://idp.example.invalid/oauth2"
OTHER_ISSUER = "https://other-idp.example.invalid/oauth2"
RESOURCE = "https://ti-recon.example.invalid/mcp"
CLIENT_ID = "claude-code"


def auth_config(
    *,
    issuer: str = ISSUER,
    resource: str = RESOURCE,
    tenant_key: str = FAKE_TENANT_SECRET,
) -> RemoteAuthConfig:
    """The deployment configuration a remote runtime is built from."""
    return RemoteAuthConfig(issuer=issuer, resource=resource, tenant_key=SecretStr(tenant_key))


def access_token(
    *,
    subject: str | None = FAKE_SUBJECT,
    issuer: str | None = ISSUER,
    resource: str | None = RESOURCE,
    audience: object | None = None,
    client_id: str = CLIENT_ID,
    scopes: list[str] | None = None,
    token: str = FAKE_MCP_TOKEN,
    expires_at: int | None = None,
) -> AccessToken:
    """One already-verified token, shaped however a test needs.

    ``issuer`` and ``audience`` land in ``claims``, which is where the SDK model
    puts everything beyond its own named fields — and is the only place an
    issuer can legitimately come from, since the strict wrapper never reads the
    bearer string.
    """
    claims: dict[str, Any] = {}
    if issuer is not None:
        claims["iss"] = issuer
    if audience is not None:
        claims["aud"] = audience
    return AccessToken(
        token=token,
        client_id=client_id,
        scopes=[] if scopes is None else scopes,
        expires_at=expires_at,
        resource=resource,
        subject=subject,
        claims=claims or None,
    )


@dataclass
class FakeDelegateVerifier:
    """A deployment verifier that has already done its job.

    Returns whatever it was told to return, and records the raw bearer strings
    it was handed — which is how a test proves the strict wrapper never looked
    at one itself.
    """

    result: AccessToken | None
    seen: list[str] = field(default_factory=list)

    async def verify_token(self, token: str) -> AccessToken | None:
        self.seen.append(token)
        return self.result
