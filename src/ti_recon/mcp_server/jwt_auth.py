"""Verifying a signed JWT access token against a remote JWKS (Task 22).

The first *production-capable* delegate for
:class:`~ti_recon.mcp_server.auth.StrictTokenVerifier`. An authorization server
signs an access token with its private key and publishes the matching public key
at a JWKS endpoint; this fetches that key once, caches it, and thereafter
validates tokens locally.

```
JwtJwksTokenVerifier   proves the token: signature, iss, aud, sub, exp, nbf
        ↓
StrictTokenVerifier    proves it is ours, again
        ↓
MCP bearer middleware  401 / 403, and the request ContextVar
```

Both layers check the issuer and the audience, deliberately. The delegate must
establish them because it is the thing holding the signature; the wrapper checks
them again because it must hold for *any* delegate, including one this repository
did not write.

Vendor-neutral by construction
------------------------------

There is no branch for any identity provider. Configuration is an issuer, a JWKS
URL, an expected resource and an algorithm allowlist — the four things every
OAuth 2.1 authorization server publishes. Auth0 is the first staging server this
repository will point at; it is not an architectural dependency, and a Keycloak,
Entra or Okta tenant issuing compatible JWT access tokens works with the same
code and different configuration.

What is never trusted
---------------------

The token, until its signature verifies. Nothing here decodes a payload and then
decides: the header is read only to learn which key and which algorithm were
*claimed*, both of which are then checked against configuration rather than
obeyed. `alg` must be in the allowlist — the header cannot introduce one. `jku`
and `x5u` are never read at all, so a token cannot point key retrieval anywhere;
the JWKS URL comes from deployment configuration and from nowhere else.

Symmetric algorithms are refused outright. A resource server should verify with
the authorization server's *public* key and never hold its signing secret — and
accepting HS256 beside RS256 is the classic confusion attack, where an RSA public
key everybody can fetch becomes an HMAC secret anybody can sign with.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final
from urllib.parse import urlparse

import httpx
import jwt
from jwt import PyJWK
from mcp.server.auth.provider import AccessToken

__all__ = [
    "DEFAULT_ALGORITHMS",
    "JWKS_MEDIA_TYPES",
    "JwksUnavailableError",
    "JwtJwksTokenVerifier",
    "JwtRejection",
    "JwtVerifierConfig",
    "TokenProfile",
]

_LOGGER = logging.getLogger("ti_recon.mcp_server")

#: Asymmetric only, and only what a deployment explicitly asks for.
#:
#: RS256 is what every mainstream authorization server issues by default. PS256
#: is accepted as configuration because it is strictly better and costs nothing
#: to allow; no symmetric algorithm is offered at all, because a resource server
#: holding a token-signing secret is the wrong shape and because HS256 beside
#: RS256 is the key-confusion attack.
SUPPORTED_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}
)

#: What a deployment gets if it says nothing.
DEFAULT_ALGORITHMS: Final[tuple[str, ...]] = ("RS256",)

#: Content types a JWKS document may legitimately arrive as.
JWKS_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {"application/json", "application/jwk-set+json"}
)

#: RFC 9068 §2.1. Compared case-insensitively, with the optional media-type
#: prefix tolerated, exactly as the RFC directs recipients to.
_RFC9068_TYPES: Final[frozenset[str]] = frozenset({"at+jwt", "application/at+jwt"})

_PLACEHOLDER_TOKEN: Final[str] = "verified-access-token"


class TokenProfile(StrEnum):
    """Which access-token profile the deployment's authorization server issues.

    Two, because there are two answers in the wild and guessing either way breaks
    somebody. RFC 9068 pins a `typ` and a required claim set; plenty of standards-
    valid servers issue JWT access tokens without adopting it, and demanding
    `at+jwt` universally would reject them.
    """

    #: Signature, issuer, audience, subject and expiry. Nothing about `typ`.
    GENERIC_JWT = "generic_jwt"
    #: RFC 9068's mandatory semantics as written: `typ`, plus `client_id`,
    #: `iat` and `jti` alongside the generic requirements.
    RFC9068 = "rfc9068"


class JwtRejection(StrEnum):
    """Why a token was refused. Internal: never rendered to a caller.

    Distinguished so an operator can tell a misconfigured audience from an
    unreachable identity provider from an actual forgery. Externally every one of
    them is the same answer — the token is not valid — because "the issuer should
    have been X" tells an attacker what X is.

    ``JWKS_UNAVAILABLE`` and ``MALFORMED_JWKS`` are the two that are not the
    caller's fault. They are still an authentication failure, because failing
    open is not on the menu.
    """

    MALFORMED_TOKEN = "malformed_token"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    KEY_NOT_FOUND = "key_not_found"
    JWKS_UNAVAILABLE = "jwks_unavailable"
    MALFORMED_JWKS = "malformed_jwks"
    INVALID_SIGNATURE = "invalid_signature"
    ISSUER_MISMATCH = "issuer_mismatch"
    AUDIENCE_MISMATCH = "audience_mismatch"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    MISSING_CLAIM = "missing_claim"
    MISSING_SUBJECT = "missing_subject"
    MALFORMED_SCOPE = "malformed_scope"
    WRONG_TOKEN_TYPE = "wrong_token_type"


class JwksUnavailableError(RuntimeError):
    """The key set could not be loaded. Carries a category, never a response."""

    def __init__(self, reason: JwtRejection) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class JwtVerifierConfig:
    """Everything the delegate needs, and nothing about anybody's identity.

    No provider API key, no OAuth token, no user, no tenant. The four required
    values are the ones an authorization server publishes; the bounds below are
    this repository's own policy about reading an external document.
    """

    #: Exact expected ``iss``. Compared as a string, never normalized: OAuth
    #: issuer identity is exact, so ``https://x`` and ``https://x/`` differ.
    issuer: str
    #: Where the public keys live. **Deployment configuration only** — never a
    #: token header, an incoming ``Host``, an ``iss`` claim or a query parameter.
    jwks_url: str
    #: The canonical MCP resource this server is, required in ``aud``.
    resource: str
    #: Asymmetric algorithms this deployment will accept, in configuration rather
    #: than taken from a token header.
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    profile: TokenProfile = TokenProfile.GENERIC_JWT
    #: Bounded, so an unreachable identity provider cannot hold a request open.
    fetch_timeout_seconds: float = 5.0
    #: The floor between two JWKS fetches. An unknown ``kid`` triggers one
    #: refresh; without a floor, a stream of forged key ids would become a
    #: request amplifier pointed at the identity provider — and since an attacker
    #: can vary the ``kid`` freely, only a *global* floor bounds anything.
    #:
    #: The cost is stated rather than hidden: a key published immediately after a
    #: fetch is picked up on the next fetch the floor allows, so rotation is
    #: visible within this interval rather than instantly. That is the normal
    #: shape — authorization servers publish a new key before they sign with it,
    #: precisely so cached resource servers keep working — and this default is
    #: considerably tighter than PyJWT's own five-minute key cache.
    minimum_refresh_interval_seconds: float = 30.0
    #: Bounds on a document fetched from outside this process.
    max_jwks_bytes: int = 128 * 1024
    max_jwks_keys: int = 32
    #: Tests and local experiments only, to permit an ``http://`` JWKS URL.
    allow_insecure_jwks_url: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        for name in ("issuer", "jwks_url", "resource"):
            if not getattr(self, name):
                msg = f"{name} must be a non-empty string"
                raise ValueError(msg)
        if not self.algorithms:
            msg = "algorithms must not be empty"
            raise ValueError(msg)
        unsupported = sorted(set(self.algorithms) - SUPPORTED_ALGORITHMS)
        if unsupported:
            # Named because this is deployment configuration a human wrote, not
            # anything a caller supplied.
            msg = f"unsupported or non-asymmetric algorithms: {', '.join(unsupported)}"
            raise ValueError(msg)
        parsed = urlparse(self.jwks_url)
        if parsed.scheme != "https" and not self.allow_insecure_jwks_url:
            msg = "jwks_url must use https"
            raise ValueError(msg)
        if not parsed.netloc:
            msg = "jwks_url must name a host"
            raise ValueError(msg)
        for name in ("fetch_timeout_seconds", "minimum_refresh_interval_seconds"):
            if getattr(self, name) <= 0:
                msg = f"{name} must be positive"
                raise ValueError(msg)
        if self.max_jwks_bytes < 1 or self.max_jwks_keys < 1:
            msg = "JWKS bounds must be positive"
            raise ValueError(msg)

    @property
    def required_claims(self) -> tuple[str, ...]:
        """Claims that must be present before a signature is even considered."""
        base = ("iss", "aud", "sub", "exp")
        if self.profile is TokenProfile.RFC9068:
            # RFC 9068 §2.2 makes these mandatory in an access token.
            return (*base, "client_id", "iat", "jti")
        return base


class JwtJwksTokenVerifier:
    """A production delegate: signed JWT in, verified :class:`AccessToken` out.

    Holds one HTTP client and one key cache for the process. Both are created
    lazily — construction contacts nothing, so a server can start and answer
    ``/health`` while its identity provider is briefly unreachable, and
    authentication simply fails closed until keys can be loaded. Deployment
    liveness is not identity-provider reachability.
    """

    def __init__(
        self,
        config: JwtVerifierConfig,
        *,
        client: httpx.AsyncClient | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._client = client
        self._owns_client = client is None
        self._monotonic = monotonic
        self._keys: dict[str, PyJWK] = {}
        self._unkeyed: PyJWK | None = None
        self._lock = asyncio.Lock()
        self._last_fetch: float | None = None

    @property
    def expected_issuer(self) -> str:
        """Read by the remote factory, so one resource cannot advertise another."""
        return self._config.issuer

    @property
    def expected_resource(self) -> str:
        return self._config.resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return a verified token, or ``None`` for every kind of failure.

        ``None`` is the SDK's refusal convention and becomes a 401. No exception
        escapes carrying a claim, a key or a JWKS response, and the raw token is
        never logged — not even at DEBUG.
        """
        try:
            return await self._verify(token)
        except JwksUnavailableError as error:
            _LOGGER.warning("rejected access token: %s", error.reason.value)
            return None
        except _Rejected as error:
            _LOGGER.info("rejected access token: %s", error.reason.value)
            return None

    async def aclose(self) -> None:
        """Release the HTTP client, if this verifier created one."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # -- verification ------------------------------------------------------ #

    async def _verify(self, token: str) -> AccessToken:
        header = _header_of(token)
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in self._config.algorithms:
            # Covers ``alg: none`` and every algorithm the deployment did not
            # ask for, including a symmetric one. The header states a claim; the
            # allowlist decides.
            raise _Rejected(JwtRejection.UNSUPPORTED_ALGORITHM)

        key = await self._key_for(header.get("kid"))
        claims = self._decode(token, key)
        if self._config.profile is TokenProfile.RFC9068:
            # Checked after the signature verified, which is what makes the
            # header trustworthy enough to read for policy. RFC 9068 §2.1
            # directs recipients to compare case-insensitively and to tolerate
            # the media-type prefix.
            declared = header.get("typ")
            if not isinstance(declared, str) or declared.lower() not in _RFC9068_TYPES:
                raise _Rejected(JwtRejection.WRONG_TOKEN_TYPE)
        return self._access_token(claims)

    def _decode(self, token: str, key: PyJWK) -> Mapping[str, Any]:
        """Signature and registered claims, all through the library.

        ``algorithms`` is the configured allowlist rather than the header's
        value, which is what makes algorithm confusion impossible here. Nothing
        is decoded without a signature: there is no ``verify_signature: False``
        path in this module.
        """
        try:
            decoded: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=list(self._config.algorithms),
                audience=self._config.resource,
                issuer=self._config.issuer,
                leeway=0,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": list(self._config.required_claims),
                },
            )
        except jwt.ExpiredSignatureError as error:
            raise _Rejected(JwtRejection.TOKEN_EXPIRED) from error
        except jwt.ImmatureSignatureError as error:
            raise _Rejected(JwtRejection.TOKEN_NOT_YET_VALID) from error
        except jwt.InvalidIssuerError as error:
            raise _Rejected(JwtRejection.ISSUER_MISMATCH) from error
        except jwt.InvalidAudienceError as error:
            raise _Rejected(JwtRejection.AUDIENCE_MISMATCH) from error
        except jwt.MissingRequiredClaimError as error:
            raise _Rejected(JwtRejection.MISSING_CLAIM) from error
        except jwt.InvalidSignatureError as error:
            raise _Rejected(JwtRejection.INVALID_SIGNATURE) from error
        except jwt.InvalidAlgorithmError as error:
            raise _Rejected(JwtRejection.UNSUPPORTED_ALGORITHM) from error
        except jwt.InvalidTokenError as error:
            # The catch-all stays last so the specific categories above keep
            # their meaning; the message is never forwarded.
            raise _Rejected(JwtRejection.MALFORMED_TOKEN) from error
        return decoded

    def _access_token(self, claims: Mapping[str, Any]) -> AccessToken:
        """The narrowest possible representation of a verified principal.

        Four things cross into the request context: the issuer, the subject, the
        granted scopes and the expiry. **Not the raw token** — nothing in the SDK's
        resource-server path reads ``AccessToken.token``, so a placeholder goes
        there and the JWT stops at this function. **Not the decoded payload**
        either: an access token routinely carries a name, an email and an
        organization, and none of that has any business reaching a ContextVar
        that later code can read.
        """
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise _Rejected(JwtRejection.MISSING_SUBJECT)

        expires_at = claims.get("exp")
        if not isinstance(expires_at, int | float):
            raise _Rejected(JwtRejection.MISSING_CLAIM)

        return AccessToken(
            token=_PLACEHOLDER_TOKEN,
            client_id=_client_id_of(claims),
            scopes=list(_scopes_of(claims)),
            expires_at=int(expires_at),
            resource=self._config.resource,
            subject=subject,
            claims={"iss": self._config.issuer},
        )

    # -- keys -------------------------------------------------------------- #

    async def _key_for(self, kid: object) -> PyJWK:
        """The signing key for this ``kid``, fetching at most one refresh.

        A ``kid`` is required whenever the key set holds more than one key: with
        several rotating keys and no hint, picking one would be guessing, and a
        guess that happened to verify would be luck rather than validation.
        """
        if kid is not None and not isinstance(kid, str):
            raise _Rejected(JwtRejection.MALFORMED_TOKEN)

        key = self._cached(kid)
        if key is not None:
            return key
        await self._refresh(kid)
        key = self._cached(kid)
        if key is None:
            raise _Rejected(JwtRejection.KEY_NOT_FOUND)
        return key

    def _cached(self, kid: str | None) -> PyJWK | None:
        if kid is not None:
            return self._keys.get(kid)
        # No `kid` in the header: acceptable only where the set is unambiguous.
        if self._unkeyed is not None:
            return self._unkeyed
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    async def _refresh(self, kid: str | None) -> None:
        """One coordinated fetch, shared by everyone waiting for it.

        Under the lock the cache is re-checked, so a burst of requests carrying a
        newly rotated ``kid`` produces one HTTP call rather than one each. A
        floor between fetches keeps a stream of forged key ids from turning this
        server into an amplifier pointed at the identity provider — after a
        recent attempt, an unknown ``kid`` is simply unknown.
        """
        async with self._lock:
            if self._cached(kid) is not None:
                return
            now = self._monotonic()
            if (
                self._last_fetch is not None
                and now - self._last_fetch < self._config.minimum_refresh_interval_seconds
            ):
                return
            self._last_fetch = now
            document = await self._fetch()
            keyed, unkeyed = _parse_jwks(document, self._config)
            # Replaced atomically, and only once the document parsed: a
            # malformed refresh must not corrupt keys that already work.
            self._keys = keyed
            self._unkeyed = unkeyed

    async def _fetch(self) -> Mapping[str, Any]:
        """Read the configured JWKS URL, and only that.

        No redirects: a JWKS endpoint that moves is a deployment change, not
        something to follow at request time, and following one would let whoever
        controls that hostname point key retrieval elsewhere. Normal system CA
        verification, bounded timeouts, and a size ceiling read before the body
        is parsed.
        """
        client = self._http_client()
        try:
            response = await client.get(
                self._config.jwks_url,
                headers={"accept": "application/json"},
                timeout=self._config.fetch_timeout_seconds,
            )
            response.raise_for_status()
            body = response.content
        except httpx.HTTPError as error:
            # No hostname, no DNS detail, no TLS detail, no traceback.
            _LOGGER.warning("jwks fetch failed: %s", type(error).__name__)
            raise JwksUnavailableError(JwtRejection.JWKS_UNAVAILABLE) from error

        media_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type and media_type not in JWKS_MEDIA_TYPES:
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        if len(body) > self._config.max_jwks_bytes:
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        try:
            document = json.loads(body)
        except ValueError as error:
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS) from error
        if not isinstance(document, dict):
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        return document

    def _http_client(self) -> httpx.AsyncClient:
        """One client for the process, created on first use.

        Not one per token: a client per request leaks connections and makes every
        verification pay a TLS handshake. Deliberately *not* a provider client —
        this is authorization infrastructure, and a provider client's retry,
        quota and metric semantics mean something entirely different.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(self._config.fetch_timeout_seconds),
            )
        return self._client


@dataclass(frozen=True)
class _Rejected(Exception):
    """An internal category. Never carries a claim, a key or a token."""

    reason: JwtRejection


def _header_of(token: str) -> Mapping[str, Any]:
    """The unverified JOSE header, read only to learn what was *claimed*.

    ``jku`` and ``x5u`` are never read. The JWKS URL is deployment configuration,
    so a token cannot point key retrieval at a host of its choosing — the
    server-side request forgery this whole class of bug is made of.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as error:
        raise _Rejected(JwtRejection.MALFORMED_TOKEN) from error
    if not isinstance(header, dict):
        raise _Rejected(JwtRejection.MALFORMED_TOKEN)
    return header


def _scopes_of(claims: Mapping[str, Any]) -> tuple[str, ...]:
    """The granted scopes, from the standard space-delimited ``scope`` claim.

    OAuth 2.1 is the universal input. A provider-specific permissions claim is
    deliberately *not* merged in: two vocabularies quietly unioned is how a
    permission somebody granted in one system becomes a scope in another.

    Absent means none, which is honest and lets the MCP middleware refuse for
    insufficient scope. A malformed value is refused rather than guessed at.
    """
    raw = claims.get("scope")
    if raw is None:
        return ()
    if not isinstance(raw, str):
        raise _Rejected(JwtRejection.MALFORMED_SCOPE)
    seen: dict[str, None] = {}
    for item in raw.split(" "):
        if item:
            seen.setdefault(item, None)
    return tuple(seen)


def _client_id_of(claims: Mapping[str, Any]) -> str:
    """Which OAuth *client* the token was issued to. Never a human identity.

    RFC 9068 names ``client_id``; OIDC-derived tokens often carry ``azp``
    instead, and plenty of generic JWT access tokens carry neither. It is
    informational — the SDK uses it for session ownership — and
    :class:`~ti_recon.mcp_server.principal.RemotePrincipal` continues to derive
    identity from the issuer and subject alone, because a client id names Claude
    Code rather than the person using it.
    """
    for name in ("client_id", "azp"):
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    return "unknown-client"


def _parse_jwks(
    document: Mapping[str, Any], config: JwtVerifierConfig
) -> tuple[dict[str, PyJWK], PyJWK | None]:
    """Turn an external document into usable keys, refusing anything ambiguous.

    Treated as untrusted input throughout: the key count is bounded before any
    key is constructed, unusable entries are skipped rather than fatal, and a
    duplicate ``kid`` refuses the whole document — two keys claiming one
    identifier means the set cannot say which signed anything.
    """
    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
    if len(keys) > config.max_jwks_keys:
        raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)

    keyed: dict[str, PyJWK] = {}
    unkeyed: PyJWK | None = None
    for entry in keys:
        if not isinstance(entry, dict):
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        if entry.get("use") not in (None, "sig"):
            # An encryption key is not a signing key. Skipped rather than
            # refused: a set may legitimately hold both.
            continue
        try:
            key = PyJWK(entry)
        except Exception:
            continue
        kid = entry.get("kid")
        if kid is None:
            unkeyed = key
            continue
        if not isinstance(kid, str) or not kid:
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        if kid in keyed:
            raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
        keyed[kid] = key

    if not keyed and unkeyed is None:
        raise JwksUnavailableError(JwtRejection.MALFORMED_JWKS)
    return keyed, unkeyed
