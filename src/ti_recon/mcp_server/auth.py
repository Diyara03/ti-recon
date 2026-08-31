"""Validating a remote access token, and turning it into a principal (Task 22).

TI Recon is an OAuth **resource server**. It issues nothing, stores no password
and runs no login page: an organization's own authorization server authenticates
the analyst, and this layer decides whether the token that arrived was issued
*for TI Recon* and *by the expected issuer*, then derives the identity everything
below runs under.

Two verifiers, and why
----------------------

``StrictTokenVerifier`` is a wrapper, not a token parser. The **delegate** — a
deployment's own :class:`~mcp.server.auth.provider.TokenVerifier` — is what
actually proves the token: a signed JWT validated against the authorization
server's keys, an RFC 7662 introspection call, or whatever that deployment's
identity platform supports. Only the delegate knows the token format, so
format-specific rules (RFC 9068 ``typ``, signature algorithms, ``nbf``,
introspection ``active``, revocation) live there and nowhere else.

The wrapper enforces the small set of invariants that hold for *every* format,
because a delegate that forgets one of them must not be able to weaken TI Recon:

* the subject is present and non-empty — there is no principal without one;
* the issuer is exactly the configured one;
* the token names this MCP resource as its audience.

That last check is the one the SDK does not perform. ``BearerAuthBackend`` reads
the header, calls the verifier and checks expiry; nothing in the installed SDK
ever reads ``AccessToken.resource`` or an ``aud`` claim. A resource server that
skipped it would accept any token the identity provider ever issued for any API
— the confused-deputy failure the MCP specification calls out by name.

The wrapper never looks at the bearer string. It is not a JWT parser, does not
base64-decode anything and would accept an entirely opaque token, because
whether the token is readable is the delegate's business.

There is deliberately no permissive default verifier. Nothing in this module
decodes a token without proof, trusts a claim it was handed, or accepts a bearer
string on the strength of its issuer alone, and no development-mode escape hatch
is reachable from a production composition. A fake verifier is a test fixture.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from pydantic import SecretBytes

from ti_recon.mcp_server.principal import RemotePrincipal, derive_tenant_id

__all__ = [
    "MINIMUM_TENANT_KEY_BYTES",
    "RemoteAuthConfig",
    "RemoteAuthenticationError",
    "StrictTokenVerifier",
    "TokenRejection",
    "resolve_remote_principal",
    "validate_access_token",
]

_LOGGER = logging.getLogger("ti_recon.mcp_server")

#: What a caller is told when no validated identity is available.
#:
#: Fixed, and says nothing about the token. Once the HTTP layer exists this case
#: is unreachable — the bearer middleware has already answered 401 — so any
#: detail here would describe deployment internals to somebody who got past
#: nothing.
_UNAUTHENTICATED = "This request is not authenticated."

#: HMAC-SHA-256's full key width. Not a length check on a human string.
MINIMUM_TENANT_KEY_BYTES: Final[int] = 32


class TokenRejection(StrEnum):
    """Why a token was refused. Internal: never rendered to a caller.

    Kept distinct so an operator reading a log can tell a misconfigured audience
    from a misconfigured issuer from a delegate that simply said no. Externally
    all of them are one answer — the token is not valid — because "your token's
    audience was X" tells an attacker what X should have been.
    """

    DELEGATE_REJECTED = "delegate_rejected"
    MISSING_SUBJECT = "missing_subject"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    AUDIENCE_CONFLICT = "audience_conflict"


class RemoteAuthenticationError(RuntimeError):
    """No validated principal is available for this call.

    Fails closed. There is no fallback to the stdio principal, to the OAuth
    ``client_id``, to an anonymous tenant or to a default: remote and stdio are
    separate deployment profiles, and quietly serving one identity's work under
    another's is the failure this whole layer exists to prevent.
    """


@dataclass(frozen=True)
class RemoteAuthConfig:
    """What a remote deployment must state before it can authenticate anybody.

    ``issuer`` and ``resource`` are compared as exact strings — no case folding,
    no default-port elision, no trailing-slash equivalence. OAuth resource and
    issuer identity are defined that way (RFC 8414/9207 use simple string
    comparison), so ``https://x/mcp`` and ``https://x/mcp/`` are two different
    resources and treating them as one would accept a token minted for a
    neighbour.

    ``tenant_key`` is a TI Recon deployment secret and nothing else — not a
    provider API key, not an OAuth access token, not the OAuth client secret. It
    is *decoded key bytes*, at least 32 of them, generated by a cryptographically
    secure source outside this process, and its only use is deriving pseudonymous
    tenant identifiers. It must stay stable for the life of an environment: see
    :mod:`ti_recon.mcp_server.principal`.
    """

    issuer: str
    resource: str
    tenant_key: SecretBytes

    def __post_init__(self) -> None:
        for name in ("issuer", "resource"):
            if not getattr(self, name):
                msg = f"{name} must be a non-empty string"
                raise ValueError(msg)
        if len(self.tenant_key.get_secret_value()) < MINIMUM_TENANT_KEY_BYTES:
            # No unsafe default and no short fallback. A character count would
            # pass a 32-character passphrase, whose real strength is a dictionary
            # away — and every tenant identifier in the deployment, which Task 23
            # will key credential ownership on, rests on this one value.
            msg = f"tenant_key must be at least {MINIMUM_TENANT_KEY_BYTES} bytes"
            raise ValueError(msg)

    def __repr__(self) -> str:
        """Never render the tenant key — not its value, length, prefix or digest."""
        return f"RemoteAuthConfig(issuer={self.issuer!r}, resource={self.resource!r})"


@dataclass(frozen=True)
class StrictTokenVerifier:
    """A deployment's verifier, plus the invariants TI Recon will not do without.

    Composed rather than subclassed so any standards-valid verifier — JWT,
    introspection, or something an identity platform ships itself — can be
    dropped in without inheriting assumptions about token format.
    """

    delegate: TokenVerifier
    config: RemoteAuthConfig

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return the token only if the delegate proved it *and* it is ours.

        ``None`` is the SDK's convention for refusal, and the bearer middleware
        turns it into a 401 with the protected-resource metadata pointer. No
        exception carries token material out of here.
        """
        verified = await self.delegate.verify_token(token)
        if verified is None:
            _LOGGER.info("rejected access token: %s", TokenRejection.DELEGATE_REJECTED.value)
            return None
        rejection = validate_access_token(verified, self.config)
        if rejection is not None:
            _LOGGER.info("rejected access token: %s", rejection.value)
            return None
        return verified


def validate_access_token(token: AccessToken, config: RemoteAuthConfig) -> TokenRejection | None:
    """The format-independent invariants, or the first one that failed.

    Time is deliberately absent. The delegate owns ``nbf``, ``active`` and every
    format-specific freshness rule, and the SDK's bearer backend independently
    refuses an ``expires_at`` in the past — a third clock policy here would be a
    second arbitrary answer to a question already answered twice.
    """
    subject = token.subject
    if not isinstance(subject, str) or not subject:
        return TokenRejection.MISSING_SUBJECT
    claims = token.claims or {}
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or issuer != config.issuer:
        return TokenRejection.ISSUER_MISMATCH
    return _audience_rejection(token, claims.get("aud"), config.resource)


def _audience_rejection(
    token: AccessToken, audience_claim: object, expected: str
) -> TokenRejection | None:
    """Whether this token was issued for *this* resource.

    Two standards-valid representations may carry the answer: the SDK's
    ``AccessToken.resource`` (RFC 8707) and an ``aud`` claim (RFC 9068), which
    may itself be a string or a list. Either establishing the expected resource
    is enough; neither establishing it is a refusal.

    Where both are present and disagree, the token is refused rather than
    resolved in whichever direction happens to be convenient. A verifier whose
    two audience views contradict each other has told us it does not know what
    the token is for, and picking the permissive reading is how a token for a
    neighbouring API gets accepted.
    """
    resource_matches: bool | None = None
    if token.resource is not None:
        resource_matches = token.resource == expected

    audience_matches: bool | None = None
    if audience_claim is not None:
        audiences = _audience_values(audience_claim)
        if audiences is None:
            return TokenRejection.AUDIENCE_MISMATCH
        audience_matches = expected in audiences

    if resource_matches is None and audience_matches is None:
        return TokenRejection.AUDIENCE_MISMATCH
    if (
        resource_matches is not None
        and audience_matches is not None
        and resource_matches != audience_matches
    ):
        return TokenRejection.AUDIENCE_CONFLICT
    if not (resource_matches or audience_matches):
        return TokenRejection.AUDIENCE_MISMATCH
    return None


def _audience_values(claim: object) -> tuple[str, ...] | None:
    """The audiences an ``aud`` claim states, or ``None`` if it states none coherently.

    A string is one audience; a sequence must be entirely strings. Anything else
    — a number, a nested object, a mixed list — is a claim this layer refuses to
    interpret, because guessing what a malformed audience meant is guessing in
    the direction of acceptance.
    """
    if isinstance(claim, str):
        return (claim,)
    if isinstance(claim, Sequence) and not isinstance(claim, str | bytes):
        values = tuple(claim)
        if values and all(isinstance(item, str) for item in values):
            return tuple(str(item) for item in values)
    return None


def resolve_remote_principal(config: RemoteAuthConfig) -> RemotePrincipal:
    """The principal for the request currently being served.

    The token comes from the SDK's request-scoped ``ContextVar``, which the auth
    middleware sets per request and resets afterwards — so identity is bound to
    one request under ``asyncio`` rather than held in a mutable server-wide
    field two concurrent analysts could race over.

    The invariants are re-checked here even though the verifier already applied
    them. It costs a dictionary lookup, and it means a deployment that wired the
    middleware without the strict wrapper fails closed instead of deriving a
    tenant from a token nobody checked was ours.
    """
    token = get_access_token()
    if token is None:
        raise RemoteAuthenticationError(_UNAUTHENTICATED)
    if validate_access_token(token, config) is not None:
        raise RemoteAuthenticationError(_UNAUTHENTICATED)
    claims = token.claims or {}
    return RemotePrincipal(
        tenant_id=derive_tenant_id(
            issuer=str(claims["iss"]),
            subject=str(token.subject),
            tenant_key=config.tenant_key,
        )
    )
