"""A test authorization server: real RSA keys, real signatures, no network.

Every token these tests use is genuinely signed and genuinely verified. Mocking
`jwt.decode` would prove that a stub returns what it was told to; the whole point
of a signature check is that it cannot be talked into anything, and only real
cryptography can demonstrate that.

Keys are generated per test session rather than committed. A private signing key
in the repository is a key somebody eventually copies into a deployment, however
many times the filename says otherwise — and generating one costs a few hundred
milliseconds once.

The JWKS endpoint is an ``httpx.MockTransport``: in-process, no socket, no DNS,
and injectable so a test can make it fail, rotate, or return nonsense.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISSUER = "https://idp.example.invalid/oauth2"
RESOURCE = "https://mcp.example.invalid/mcp"
JWKS_URL = "https://idp.example.invalid/.well-known/jwks.json"
SCOPE = "ti-recon:investigate"
CLIENT_ID = "claude-code"

#: Deliberately identifying, so "did a claim leak?" has a searchable answer.
SUBJECT = "very.identifying.person@example.invalid"

#: Planted so a match anywhere cannot be a coincidence.
PLANTED_TOKEN_MARKER = "SUPER_SECRET_JWT_ACCESS_TOKEN_123"


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class SigningKey:
    """One RSA key pair, with its public half rendered as a JWK."""

    kid: str
    private: Any
    algorithm: str = "RS256"

    @classmethod
    def generate(cls, kid: str, *, algorithm: str = "RS256") -> SigningKey:
        # 2048 bits: what real authorization servers issue, and fast enough that
        # a test session does not notice.
        return cls(
            kid=kid,
            private=rsa.generate_private_key(public_exponent=65537, key_size=2048),
            algorithm=algorithm,
        )

    def jwk(self, **overrides: Any) -> dict[str, Any]:
        numbers = self.private.public_key().public_numbers()
        document: dict[str, Any] = {
            "kty": "RSA",
            "use": "sig",
            "alg": self.algorithm,
            "kid": self.kid,
            "n": _b64(numbers.n),
            "e": _b64(numbers.e),
        }
        document.update(overrides)
        return {key: value for key, value in document.items() if value is not None}

    def public_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(
        self,
        *,
        headers: dict[str, Any] | None = None,
        algorithm: str | None = None,
        **claims: Any,
    ) -> str:
        """One signed access token, with whatever claims a test needs."""
        payload = default_claims()
        payload.update(claims)
        payload = {key: value for key, value in payload.items() if value is not None}
        header = {"kid": self.kid}
        header.update(headers or {})
        # A `None` means "omit", so a test can produce a header with no `kid` at
        # all rather than one whose `kid` is null — which PyJWT rejects outright.
        header = {key: value for key, value in header.items() if value is not None}
        return jwt.encode(
            payload, self.private, algorithm=algorithm or self.algorithm, headers=header
        )


def default_claims(**overrides: Any) -> dict[str, Any]:
    """A well-formed access token's claims, before a test breaks one."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": SUBJECT,
        "exp": now + 3600,
        "iat": now,
        "nbf": now - 5,
        "scope": SCOPE,
        "client_id": CLIENT_ID,
        "jti": "test-token-id",
        # Identifying material a real IdP routinely includes, so a test can prove
        # none of it survives into the request context.
        "email": SUBJECT,
        "name": "Very Identifying Person",
        "org_id": "org_identifying_example",
    }
    claims.update(overrides)
    return claims


@dataclass
class JwksEndpoint:
    """An in-process JWKS server a test can rotate, break or count.

    Not a real socket: ``httpx.MockTransport`` answers the client directly, so
    the normal suite stays free of DNS and sockets while still exercising the
    real fetch, parse and cache path.
    """

    keys: list[SigningKey] = field(default_factory=list)
    requests: int = 0
    #: Set to return this instead of a well-formed document.
    body: bytes | None = None
    status: int = 200
    content_type: str = "application/json"
    #: Set to make every fetch fail as a connection error would.
    failing: bool = False

    def document(self) -> dict[str, Any]:
        return {"keys": [key.jwk() for key in self.keys]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.failing:
            msg = "connection refused"
            raise httpx.ConnectError(msg, request=request)
        body = self.document() if self.body is None else None
        content = self.body if body is None else json.dumps(body).encode()
        return httpx.Response(
            self.status, content=content, headers={"content-type": self.content_type}
        )

    def client(self) -> httpx.AsyncClient:
        """An HTTP client wired to this endpoint, opening nothing."""
        return httpx.AsyncClient(
            transport=httpx.MockTransport(self.handler), follow_redirects=False
        )


def verifier_config(**overrides: Any) -> Any:
    """The verifier configuration these fixtures are built around."""
    from ti_recon.mcp_server.jwt_auth import JwtVerifierConfig

    settings: dict[str, Any] = {
        "issuer": ISSUER,
        "jwks_url": JWKS_URL,
        "resource": RESOURCE,
    }
    settings.update(overrides)
    return JwtVerifierConfig(**settings)


def generate_ec_key(kid: str) -> SigningKey:
    """An EC key, for the algorithm-allowlist tests."""
    return SigningKey(kid=kid, private=ec.generate_private_key(ec.SECP256R1()), algorithm="ES256")
