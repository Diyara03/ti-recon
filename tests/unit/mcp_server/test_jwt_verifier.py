"""Real signatures, real forgeries (Task 22).

Every token here is genuinely signed with a real RSA key and genuinely verified.
Mocking ``jwt.decode`` would prove a stub returns what it was told; the entire
value of a signature check is that it cannot be talked into anything, and only
real cryptography demonstrates that.

No socket and no DNS: the JWKS endpoint is an ``httpx.MockTransport``, so the
fetch, parse, cache and rotation paths are the shipped ones while the network
guard stays exactly as strict as it is for every other test.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
import warnings
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from fixtures.mcp_server.jwks import (
    CLIENT_ID,
    ISSUER,
    RESOURCE,
    SCOPE,
    SUBJECT,
    JwksEndpoint,
    SigningKey,
    default_claims,
    generate_ec_key,
    sign_raw,
    verifier_config,
)
from ti_recon.mcp_server.jwt_auth import (
    DEFAULT_ALGORITHMS,
    JwtJwksTokenVerifier,
    JwtRejection,
    JwtVerifierConfig,
    TokenProfile,
)

OTHER_ISSUER = "https://other-idp.example.invalid/oauth2"


@pytest.fixture(scope="module")
def signing_key() -> SigningKey:
    """One key for the module: generating RSA keys is the slow part."""
    return SigningKey.generate("primary")


@pytest.fixture(scope="module")
def second_key() -> SigningKey:
    return SigningKey.generate("rotated")


def _verifier(endpoint: JwksEndpoint, **overrides: Any) -> JwtJwksTokenVerifier:
    return JwtJwksTokenVerifier(verifier_config(**overrides), client=endpoint.client())


def _part(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _unsigned(claims: dict[str, Any], *, algorithm: str = "none", kid: str = "primary") -> str:
    """A token nobody signed, assembled by hand."""
    return f"{_part({'alg': algorithm, 'kid': kid})}.{_part(claims)}."


def _hmac_signed(claims: dict[str, Any], *, secret: bytes, kid: str) -> str:
    """The key-confusion forgery, built the way an attacker would.

    Header says HS256; the "secret" is the RSA public key anybody can fetch from
    the JWKS endpoint. A server that accepted HS256 alongside RS256 and took the
    algorithm from the header would verify this happily.
    """
    signing_input = f"{_part({'alg': 'HS256', 'kid': kid})}.{_part(claims)}"
    digest = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(digest).rstrip(b'=').decode()}"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_the_default_algorithm_set_is_asymmetric_and_narrow() -> None:
    assert DEFAULT_ALGORITHMS == ("RS256",)


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": ""},
        {"jwks_url": ""},
        {"resource": ""},
        {"algorithms": ()},
        {"algorithms": ("HS256",)},
        {"algorithms": ("RS256", "HS512")},
        {"algorithms": ("none",)},
        {"jwks_url": "http://idp.example.invalid/jwks"},
        {"jwks_url": "https:///jwks"},
        {"fetch_timeout_seconds": 0},
        {"minimum_refresh_interval_seconds": -1},
        {"max_jwks_keys": 0},
    ],
)
def test_a_verifier_refuses_unsafe_configuration(overrides: dict[str, Any]) -> None:
    """Symmetric algorithms most of all.

    A resource server verifying with HS256 needs the authorization server's
    signing secret, which it should never hold — and HS256 accepted beside RS256
    is the key-confusion attack, where a public key everybody can fetch becomes a
    secret anybody can sign with.
    """
    with pytest.raises(ValueError):
        verifier_config(**overrides)


def test_an_rfc9068_profile_requires_more_claims_than_the_generic_one() -> None:
    generic = verifier_config().required_claims
    strict = verifier_config(profile=TokenProfile.RFC9068).required_claims

    assert set(generic) == {"iss", "aud", "sub", "exp"}
    assert set(strict) == set(generic) | {"client_id", "iat", "jti"}


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_correctly_signed_token_is_accepted(signing_key: SigningKey) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    token = await verifier.verify_token(signing_key.sign())

    assert token is not None
    assert token.subject == SUBJECT
    assert token.scopes == [SCOPE]
    assert token.client_id == CLIENT_ID
    assert token.resource == RESOURCE
    assert token.claims == {"iss": ISSUER}
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_the_raw_token_and_the_identifying_claims_stop_at_the_verifier(
    signing_key: SigningKey,
) -> None:
    """Four values cross into the request context, and no more.

    A real access token routinely carries a name, an email and an organization.
    None has any business reaching a ContextVar later code can read, so the
    verified representation is built rather than copied — and the raw JWT is not
    in it either, because nothing in the SDK's resource-server path reads it.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    raw = signing_key.sign()

    token = await _verifier(endpoint).verify_token(raw)

    assert token is not None
    rendered = token.model_dump_json()
    assert raw not in rendered
    for claim in ("Very Identifying Person", "org_identifying_example"):
        assert claim not in rendered
    # The subject is the one identifying value that must survive — it is what the
    # tenant is derived from — and it goes no further than this object.
    assert token.subject == SUBJECT
    assert set(token.claims or {}) == {"iss"}


@pytest.mark.asyncio
async def test_an_absent_scope_claim_is_no_scopes_rather_than_an_error(
    signing_key: SigningKey,
) -> None:
    """The MCP middleware then refuses for insufficient scope, which is correct."""
    endpoint = JwksEndpoint(keys=[signing_key])

    token = await _verifier(endpoint).verify_token(signing_key.sign(scope=None))

    assert token is not None
    assert token.scopes == []


@pytest.mark.asyncio
async def test_scopes_are_split_deduplicated_and_order_preserved(
    signing_key: SigningKey,
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])

    token = await _verifier(endpoint).verify_token(
        signing_key.sign(scope="  a:read   b:write a:read ")
    )

    assert token is not None
    assert token.scopes == ["a:read", "b:write"]


@pytest.mark.asyncio
async def test_azp_is_accepted_where_client_id_is_absent(signing_key: SigningKey) -> None:
    """OIDC-derived tokens carry ``azp``; RFC 9068 names ``client_id``.

    Informational either way. The tenant is still derived from issuer and
    subject, because a client id names Claude Code rather than a person.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    with_azp = await verifier.verify_token(signing_key.sign(client_id=None, azp="other-client"))
    with_neither = await verifier.verify_token(signing_key.sign(client_id=None))

    assert with_azp is not None and with_azp.client_id == "other-client"
    assert with_neither is not None and with_neither.client_id == "unknown-client"


# --------------------------------------------------------------------------- #
# Tampering
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_modified_payload_is_rejected(signing_key: SigningKey) -> None:
    """The attack this whole layer exists to stop: escalate, do not re-sign."""
    endpoint = JwksEndpoint(keys=[signing_key])
    header, _, signature = signing_key.sign().split(".")
    forged = (
        base64.urlsafe_b64encode(
            json.dumps(default_claims(sub="somebody-else", scope="ti-recon:investigate")).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    assert await _verifier(endpoint).verify_token(f"{header}.{forged}.{signature}") is None


@pytest.mark.asyncio
async def test_a_modified_signature_is_rejected(signing_key: SigningKey) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])
    header, payload, signature = signing_key.sign().split(".")

    assert (
        await _verifier(endpoint).verify_token(f"{header}.{payload}.{signature[:-4]}AAAA") is None
    )


@pytest.mark.asyncio
async def test_a_token_signed_by_an_unknown_key_is_rejected(signing_key: SigningKey) -> None:
    """A well-formed token from the wrong authorization server."""
    stranger = SigningKey.generate("primary")  # same kid, different key material
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(stranger.sign()) is None


@pytest.mark.asyncio
async def test_an_unsigned_token_is_rejected(signing_key: SigningKey) -> None:
    """``alg: none``. Refused at the header, before a key is even looked up."""
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(_unsigned(default_claims())) is None
    assert endpoint.requests == 0


@pytest.mark.asyncio
async def test_an_algorithm_outside_the_allowlist_is_rejected(signing_key: SigningKey) -> None:
    """The header states a claim; configuration decides.

    The same token is refused under the default allowlist and accepted once the
    deployment says RS512 — with the published key declaring RS512 too. A JWK
    carries its own ``alg``, and the library binds the key to it, so a key
    published for RS256 cannot verify an RS512 token however the header is
    labelled. That is a second, independent check, and it is welcome.
    """
    token = signing_key.sign(headers={"alg": "RS512"}, algorithm="RS512")
    endpoint = JwksEndpoint(keys=[signing_key])
    rs512 = JwksEndpoint(keys=[signing_key])
    rs512.body = json.dumps({"keys": [signing_key.jwk(alg="RS512")]}).encode()

    assert await _verifier(endpoint).verify_token(token) is None
    assert await _verifier(rs512, algorithms=("RS512",)).verify_token(token) is not None


@pytest.mark.asyncio
async def test_an_rsa_public_key_cannot_be_used_as_an_hmac_secret(
    signing_key: SigningKey,
) -> None:
    """The classic confusion attack, and it fails twice over.

    HS256 cannot be configured at all, and the header cannot introduce an
    algorithm the deployment did not list — so a token an attacker signed with
    the public key everyone can fetch is refused before any key lookup.
    """
    # Assembled by hand: PyJWT refuses to *encode* HS256 with an asymmetric key,
    # which is a welcome second barrier but not one an attacker is bound by.
    forged = _hmac_signed(default_claims(), secret=signing_key.public_pem(), kid=signing_key.kid)
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(forged) is None
    with pytest.raises(ValueError):
        verifier_config(algorithms=("RS256", "HS256"))


@pytest.mark.asyncio
async def test_a_token_cannot_redirect_key_retrieval(signing_key: SigningKey) -> None:
    """``jku`` and ``x5u`` are never read.

    A token that could name its own key source could name one the attacker
    controls, and then sign itself. Keys come from configuration; the header's
    suggestion is ignored, and the configured endpoint is still the one asked.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    token = signing_key.sign(
        headers={
            "jku": "https://attacker.example.invalid/jwks.json",
            "x5u": "https://attacker.example.invalid/cert.pem",
        }
    )

    assert await _verifier(endpoint).verify_token(token) is not None
    assert endpoint.requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "claims"),
    [
        ("wrong issuer", {"iss": OTHER_ISSUER}),
        ("no issuer", {"iss": None}),
        ("issuer with a trailing slash", {"iss": ISSUER + "/"}),
        ("wrong audience", {"aud": "https://elsewhere.example.invalid/mcp"}),
        ("no audience", {"aud": None}),
        ("audience with a trailing slash", {"aud": RESOURCE + "/"}),
        ("no subject", {"sub": None}),
        ("empty subject", {"sub": ""}),
        ("no expiry", {"exp": None}),
        ("expired", {"exp": int(time.time()) - 1}),
        ("not yet valid", {"nbf": int(time.time()) + 3600}),
        ("malformed scope", {"scope": ["ti-recon:investigate"]}),
    ],
)
async def test_a_token_failing_a_claim_check_is_rejected(
    signing_key: SigningKey, label: str, claims: dict[str, Any]
) -> None:
    del label
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(signing_key.sign(**claims)) is None


@pytest.mark.asyncio
async def test_an_audience_list_containing_this_resource_is_accepted(
    signing_key: SigningKey,
) -> None:
    """A token may legitimately be for several audiences, one of which is us."""
    endpoint = JwksEndpoint(keys=[signing_key])
    token = signing_key.sign(aud=["https://elsewhere.example.invalid/api", RESOURCE])

    assert await _verifier(endpoint).verify_token(token) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformed",
    ["", "not-a-token", "a.b", "a.b.c.d", "....", "eyJhbGciOiJSUzI1NiJ9", "..."],
)
async def test_a_malformed_compact_token_is_rejected(
    signing_key: SigningKey, malformed: str
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(malformed) is None
    assert endpoint.requests == 0


# --------------------------------------------------------------------------- #
# RFC 9068
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_rfc9068_profile_requires_the_access_token_type(
    signing_key: SigningKey,
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint, profile=TokenProfile.RFC9068)

    assert await verifier.verify_token(signing_key.sign(headers={"typ": "at+jwt"})) is not None
    assert await verifier.verify_token(signing_key.sign(headers={"typ": "JWT"})) is None
    assert await verifier.verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_the_rfc9068_type_comparison_tolerates_case_and_the_media_prefix(
    signing_key: SigningKey,
) -> None:
    """RFC 9068 §2.1 directs recipients to do exactly this."""
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint, profile=TokenProfile.RFC9068)

    for declared in ("at+jwt", "AT+JWT", "application/at+jwt", "Application/AT+JWT"):
        assert await verifier.verify_token(signing_key.sign(headers={"typ": declared})) is not None


@pytest.mark.asyncio
async def test_the_generic_profile_does_not_demand_a_token_type(
    signing_key: SigningKey,
) -> None:
    """Plenty of standards-valid servers issue JWT access tokens without it."""
    endpoint = JwksEndpoint(keys=[signing_key])

    assert (
        await _verifier(endpoint).verify_token(signing_key.sign(headers={"typ": "JWT"})) is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["client_id", "iat", "jti"])
async def test_the_rfc9068_profile_requires_its_mandatory_claims(
    signing_key: SigningKey, missing: str
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint, profile=TokenProfile.RFC9068)
    token = signing_key.sign(headers={"typ": "at+jwt"}, **{missing: None})

    assert await verifier.verify_token(token) is None


# --------------------------------------------------------------------------- #
# JWKS documents
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_set_holding_several_keys_selects_by_kid(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key, second_key])
    verifier = _verifier(endpoint)

    assert await verifier.verify_token(signing_key.sign()) is not None
    assert await verifier.verify_token(second_key.sign()) is not None
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_a_header_without_a_kid_works_only_when_the_set_is_unambiguous(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """With several rotating keys and no hint, picking one would be guessing."""
    single = JwksEndpoint(keys=[signing_key])
    several = JwksEndpoint(keys=[signing_key, second_key])
    token = signing_key.sign(headers={"kid": None})

    assert await _verifier(single).verify_token(token) is not None
    assert await _verifier(several).verify_token(token) is None


@pytest.mark.asyncio
async def test_a_duplicate_kid_refuses_the_whole_document(signing_key: SigningKey) -> None:
    """Two keys claiming one identifier means the set cannot say which signed."""
    twin = SigningKey.generate(signing_key.kid)
    endpoint = JwksEndpoint(keys=[signing_key, twin])

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_two_keys_without_a_kid_refuse_the_whole_document() -> None:
    """Absent is an identifier, and two keys cannot share it either.

    A key with no ``kid`` is the key an unkeyed token resolves against, so a set
    holding two of them is the same ambiguity a repeated ``kid`` is — and was
    the one place it was resolved silently instead of refused. Keeping the last
    entry made the answer depend on the order the authorization server happened
    to serialize its document in: a token signed with the *first* key was
    rejected as an unknown key, which reads like an outage rather than a
    malformed key set.

    Not an authentication bypass in either direction — both keys came from the
    configured JWKS over HTTPS — but a security-critical set that cannot say
    which key signed anything must be refused rather than guessed at.
    """
    first = SigningKey.generate("unused-a")
    second = SigningKey.generate("unused-b")
    endpoint = JwksEndpoint()
    endpoint.body = json.dumps({"keys": [first.jwk(kid=None), second.jwk(kid=None)]}).encode()

    verifier = _verifier(endpoint)
    assert await verifier.verify_token(first.sign(headers={"kid": None})) is None
    assert await verifier.verify_token(second.sign(headers={"kid": None})) is None


@pytest.mark.asyncio
async def test_one_key_without_a_kid_still_answers_beside_a_keyed_one(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """The refusal is about *two* unkeyed keys, and nothing narrower works.

    A rotation that publishes a keyed key beside a legacy unkeyed one is
    ordinary, and so is a set holding exactly one unkeyed key. Refusing either
    would deny authentication over a document that says what it means.
    """
    endpoint = JwksEndpoint()
    endpoint.body = json.dumps({"keys": [signing_key.jwk(kid=None), second_key.jwk()]}).encode()

    verifier = _verifier(endpoint)
    assert await verifier.verify_token(signing_key.sign(headers={"kid": None})) is not None
    assert await verifier.verify_token(second_key.sign()) is not None


@pytest.mark.asyncio
async def test_an_unkeyed_encryption_key_is_not_an_unkeyed_conflict(
    signing_key: SigningKey,
) -> None:
    """Eligibility is judged first here too, exactly as it is for a shared ``kid``.

    An encryption key with no ``kid`` is not a candidate, so it cannot collide
    with the signing key that is one — otherwise irrelevant encryption material
    would deny all authentication.
    """
    encryption = SigningKey.generate("unused")
    endpoint = JwksEndpoint()
    endpoint.body = json.dumps(
        {"keys": [encryption.jwk(kid=None, use="enc"), signing_key.jwk(kid=None)]}
    ).encode()

    assert (
        await _verifier(endpoint).verify_token(signing_key.sign(headers={"kid": None})) is not None
    )


@pytest.mark.asyncio
async def test_an_encryption_key_is_skipped_rather_than_fatal(signing_key: SigningKey) -> None:
    """A set may legitimately hold both; only signing keys are candidates."""
    endpoint = JwksEndpoint(keys=[signing_key])
    encryption = SigningKey.generate("encryption")
    endpoint.body = json.dumps({"keys": [encryption.jwk(use="enc"), signing_key.jwk()]}).encode()

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("not json", b"<html>not json</html>"),
        ("not an object", b"[]"),
        ("no keys member", b'{"jwks": []}'),
        ("empty key list", b'{"keys": []}'),
        ("keys not a list", b'{"keys": {}}'),
        ("entry not an object", b'{"keys": ["nope"]}'),
        ("unsupported key type", b'{"keys": [{"kty": "oct", "k": "AAAA", "kid": "x"}]}'),
        ("malformed modulus", b'{"keys": [{"kty": "RSA", "n": "!!", "e": "AQAB", "kid": "x"}]}'),
        ("empty kid", b'{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": ""}]}'),
    ],
)
async def test_a_malformed_jwks_document_authenticates_nobody(
    signing_key: SigningKey, label: str, body: bytes
) -> None:
    del label
    endpoint = JwksEndpoint(keys=[signing_key], body=body)

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_an_oversized_or_overlong_jwks_is_refused(signing_key: SigningKey) -> None:
    """An external document must not be able to allocate arbitrary memory."""
    huge = JwksEndpoint(keys=[signing_key], body=b'{"keys": []}' + b" " * 200_000)
    many = JwksEndpoint(
        keys=[SigningKey(kid=f"k{index}", private=signing_key.private) for index in range(40)]
    )

    assert await _verifier(huge).verify_token(signing_key.sign()) is None
    assert await _verifier(many, max_jwks_keys=32).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_a_wrong_content_type_is_refused(signing_key: SigningKey) -> None:
    endpoint = JwksEndpoint(keys=[signing_key], content_type="text/html")

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_an_error_status_from_the_jwks_endpoint_authenticates_nobody(
    signing_key: SigningKey,
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key], status=500)

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


# --------------------------------------------------------------------------- #
# Caching, rotation and failure
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_keys_are_fetched_once_and_then_reused(signing_key: SigningKey) -> None:
    """A fetch per request would put the identity provider in the hot path."""
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    for _ in range(5):
        assert await verifier.verify_token(signing_key.sign()) is not None

    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_an_unknown_kid_triggers_exactly_one_refresh_that_finds_it(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """Rotation on a cold cache: the unknown key is fetched and the token works."""
    endpoint = JwksEndpoint(keys=[signing_key, second_key])
    verifier = _verifier(endpoint)

    assert await verifier.verify_token(second_key.sign()) is not None
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_rotation_is_picked_up_within_the_refresh_interval(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """The cost of the anti-amplification floor, stated rather than hidden.

    The floor bounds *total* fetches, because an attacker can vary the ``kid``
    freely and a per-kid memory would bound nothing. So a key published after a
    recent fetch is picked up on the next fetch the floor allows — up to
    ``minimum_refresh_interval_seconds`` later, and the default is a good deal
    tighter than PyJWT's own five-minute key cache.

    In practice authorization servers publish a new key well before they start
    signing with it, precisely so cached resource servers keep working.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )

    assert await verifier.verify_token(signing_key.sign()) is not None
    endpoint.keys = [signing_key, second_key]

    # Inside the floor the new key is not yet visible, and no fetch is made.
    assert await verifier.verify_token(second_key.sign()) is None
    assert endpoint.requests == 1

    now[0] += 31.0
    assert await verifier.verify_token(second_key.sign()) is not None
    assert endpoint.requests == 2


@pytest.mark.asyncio
async def test_a_kid_that_is_still_absent_does_not_refetch_immediately(
    signing_key: SigningKey,
) -> None:
    """The anti-amplification floor.

    Without it a stream of forged key ids becomes a request multiplier pointed
    at the identity provider — one inbound request, one outbound fetch, from
    anybody, unauthenticated.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)
    stranger = SigningKey.generate("never-published")

    for _ in range(5):
        assert await verifier.verify_token(stranger.sign()) is None

    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_the_floor_lifts_once_the_interval_has_passed(signing_key: SigningKey) -> None:
    """A real rotation must still be picked up. The clock is injected."""
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(minimum_refresh_interval_seconds=30.0),
        client=endpoint.client(),
        monotonic=lambda: now[0],
    )
    later = SigningKey.generate("published-later")

    assert await verifier.verify_token(later.sign()) is None
    assert endpoint.requests == 1

    endpoint.keys = [signing_key, later]
    assert await verifier.verify_token(later.sign()) is None  # still inside the floor
    assert endpoint.requests == 1

    now[0] += 31.0
    assert await verifier.verify_token(later.sign()) is not None
    assert endpoint.requests == 2


@pytest.mark.asyncio
async def test_concurrent_unknown_kids_share_one_refresh(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """A burst after a rotation is one fetch, not one each."""
    endpoint = JwksEndpoint(keys=[signing_key, second_key])
    verifier = _verifier(endpoint)

    results = await asyncio.gather(*(verifier.verify_token(second_key.sign()) for _ in range(8)))

    assert all(item is not None for item in results)
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_a_malformed_refresh_does_not_corrupt_working_keys(
    signing_key: SigningKey,
) -> None:
    """Keys are replaced only once a document has parsed."""
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    assert await verifier.verify_token(signing_key.sign()) is not None

    endpoint.body = b"<html>the identity provider is having a day</html>"
    stranger = SigningKey.generate("unknown")
    assert await verifier.verify_token(stranger.sign()) is None
    # The key that already worked still does.
    assert await verifier.verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
async def test_an_unreachable_jwks_endpoint_fails_authentication_closed(
    signing_key: SigningKey,
) -> None:
    """No keys, no authentication. Never the other way round."""
    endpoint = JwksEndpoint(keys=[signing_key], failing=True)

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_a_rejection_reveals_nothing_about_the_token_or_the_endpoint(
    signing_key: SigningKey, caplog
) -> None:
    """A category, and not a claim, a key, a hostname or a traceback."""
    caplog.set_level("DEBUG")
    endpoint = JwksEndpoint(keys=[signing_key], failing=True)
    raw = signing_key.sign()

    assert await _verifier(endpoint).verify_token(raw) is None

    logged = caplog.text
    assert JwtRejection.JWKS_UNAVAILABLE.value in logged
    for secret in (raw, SUBJECT, "idp.example.invalid", "Very Identifying Person"):
        assert secret not in logged
    assert "Traceback" not in logged


@pytest.mark.asyncio
async def test_no_raw_token_is_logged_even_at_debug(signing_key: SigningKey, caplog) -> None:
    caplog.set_level("DEBUG")
    endpoint = JwksEndpoint(keys=[signing_key])
    forged = SigningKey.generate("primary").sign()

    verifier = _verifier(endpoint)
    assert await verifier.verify_token(signing_key.sign()) is not None
    assert await verifier.verify_token(forged) is None

    assert forged not in caplog.text
    assert JwtRejection.INVALID_SIGNATURE.value in caplog.text


# --------------------------------------------------------------------------- #
# The HTTP client
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_verifier_builds_one_client_and_closes_only_its_own() -> None:
    """One client for the process; an injected one belongs to whoever injected it."""
    owned = JwtJwksTokenVerifier(verifier_config())
    assert owned._http_client() is owned._http_client()
    await owned.aclose()

    endpoint = JwksEndpoint()
    client = endpoint.client()
    borrowed = JwtJwksTokenVerifier(verifier_config(), client=client)
    await borrowed.aclose()
    assert not client.is_closed
    await client.aclose()


def test_the_client_follows_no_redirects_and_keeps_tls_verification() -> None:
    """A JWKS endpoint that moves is a deployment change, not a runtime hop.

    Following one would let whoever controls that hostname point key retrieval
    somewhere else. TLS verification is the system default and is never relaxed.
    """
    verifier = JwtJwksTokenVerifier(verifier_config())
    client = verifier._http_client()

    assert client.follow_redirects is False
    assert client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"


def test_the_expected_issuer_and_resource_are_exposed_for_the_factory_to_check() -> None:
    """So one deployment cannot advertise one resource and accept another."""
    verifier = JwtJwksTokenVerifier(verifier_config())

    assert verifier.expected_issuer == ISSUER
    assert verifier.expected_resource == RESOURCE


def test_the_config_type_is_frozen_and_hides_nothing_sensitive() -> None:
    config = verifier_config()
    rendered = repr(config)

    assert isinstance(config, JwtVerifierConfig)
    assert "tenant" not in rendered
    assert "allow_insecure_jwks_url" not in rendered


@pytest.mark.asyncio
async def test_an_ec_key_works_where_the_deployment_configures_one() -> None:
    """Vendor-neutral means algorithm-neutral within the asymmetric set."""
    key = generate_ec_key("ec-primary")
    endpoint = JwksEndpoint(keys=[])
    endpoint.body = json.dumps({"keys": [_ec_jwk(key)]}).encode()

    verifier = _verifier(endpoint, algorithms=("ES256",))
    assert await verifier.verify_token(key.sign()) is not None


def _ec_jwk(key: SigningKey) -> dict[str, Any]:
    numbers = key.private.public_key().public_numbers()

    def coordinate(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": key.kid,
        "x": coordinate(numbers.x),
        "y": coordinate(numbers.y),
    }


@pytest.mark.asyncio
async def test_nothing_reaches_a_url_the_deployment_did_not_configure(
    signing_key: SigningKey,
) -> None:
    """Every fetch goes to the configured JWKS URL and nowhere else."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            content=json.dumps({"keys": [signing_key.jwk()]}).encode(),
            headers={"content-type": "application/json"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    verifier = JwtJwksTokenVerifier(verifier_config(), client=client)

    await verifier.verify_token(
        signing_key.sign(headers={"jku": "https://attacker.example.invalid/jwks"})
    )
    await client.aclose()

    assert seen == ["https://idp.example.invalid/.well-known/jwks.json"]


@pytest.mark.asyncio
async def test_a_non_string_kid_in_the_header_is_rejected(signing_key: SigningKey) -> None:
    """A header field is attacker-shaped data until it has been checked."""
    endpoint = JwksEndpoint(keys=[signing_key])
    header = _part({"alg": "RS256", "kid": {"nested": "object"}})
    payload = _part(default_claims())

    assert await _verifier(endpoint).verify_token(f"{header}.{payload}.AAAA") is None
    assert endpoint.requests == 0


@pytest.mark.asyncio
async def test_a_jwks_entry_without_a_kid_is_usable_when_it_is_the_only_one(
    signing_key: SigningKey,
) -> None:
    """Some authorization servers publish a single unlabelled key."""
    endpoint = JwksEndpoint(keys=[signing_key])
    endpoint.body = json.dumps({"keys": [signing_key.jwk(kid=None)]}).encode()

    assert (
        await _verifier(endpoint).verify_token(signing_key.sign(headers={"kid": None})) is not None
    )


def test_no_identity_provider_appears_in_code_rather_than_prose() -> None:
    """Vendor-neutral means no branch, no setting and no string — only a comment.

    The module docstring names Auth0, Keycloak, Entra and Okta as *examples* of
    servers the same code works with, which is the point being made. What must
    not exist is an identifier or a literal that behaves differently for one of
    them.
    """
    import ast
    from pathlib import Path

    vendors = {"auth0", "okta", "keycloak", "cognito", "entra", "azure", "aws"}
    tree = ast.parse(Path("src/ti_recon/mcp_server/jwt_auth.py").read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            assert not any(name in node.value.lower() for name in vendors), node.value
        if isinstance(node, ast.Name | ast.Attribute):
            label = (node.id if isinstance(node, ast.Name) else node.attr).lower()
            assert not any(name in label for name in vendors), label


# --------------------------------------------------------------------------- #
# JWKS freshness and revocation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_revoked_key_stops_being_trusted_once_the_cache_expires(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """The control that makes revocation mean anything.

    Before the cached set had a lifetime, a ``kid`` once seen was trusted for the
    life of the process: an authorization server could retire a compromised key
    and this server would keep accepting freshly forged tokens signed with it
    indefinitely. Token ``exp`` is no help — whoever holds the private key mints
    new ones.

    Remove the expiry check and this test accepts a key a full lifetime after it
    was withdrawn.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )

    assert await verifier.verify_token(signing_key.sign()) is not None

    # The authorization server retires the key.
    endpoint.keys = [second_key]

    # Still inside the freshness window: the cached key is used, deliberately.
    now[0] += 60.0
    assert await verifier.verify_token(signing_key.sign()) is not None
    assert endpoint.requests == 1

    # Past it: the set is discarded, refetched, and the key is simply gone.
    now[0] += 300.0
    assert await verifier.verify_token(signing_key.sign()) is None
    assert endpoint.requests == 2
    assert await verifier.verify_token(second_key.sign()) is not None


@pytest.mark.asyncio
async def test_an_expired_cache_plus_an_outage_authenticates_nobody(
    signing_key: SigningKey,
) -> None:
    """Fail closed, and never renew freshness on a failed attempt.

    Availability is not worth indefinite trust in a key that may have been
    revoked precisely because it was compromised.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )

    assert await verifier.verify_token(signing_key.sign()) is not None

    endpoint.failing = True
    now[0] += 301.0
    assert await verifier.verify_token(signing_key.sign()) is None

    # And it stays closed: a failed fetch starts no new freshness window, so the
    # discarded keys never come back on their own.
    now[0] += 3600.0
    assert await verifier.verify_token(signing_key.sign()) is None

    # Recovery is still subject to the anti-flood floor, so the next attempt
    # comes after it — which is the floor doing its job, not the outage lingering.
    endpoint.failing = False
    now[0] += 31.0
    assert await verifier.verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
async def test_a_malformed_refresh_after_expiry_does_not_restore_stale_keys(
    signing_key: SigningKey,
) -> None:
    """Only a document that parsed creates a new freshness window."""
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )

    assert await verifier.verify_token(signing_key.sign()) is not None
    endpoint.body = b"<html>the identity provider is having a day</html>"
    now[0] += 301.0

    assert await verifier.verify_token(signing_key.sign()) is None
    now[0] += 301.0
    assert await verifier.verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
async def test_a_malformed_refresh_while_still_fresh_leaves_the_cache_intact(
    signing_key: SigningKey,
) -> None:
    """An optional unknown-kid refresh must not destroy keys that work."""
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    assert await verifier.verify_token(signing_key.sign()) is not None
    endpoint.body = b"nonsense"
    stranger = SigningKey.generate("unknown")

    assert await verifier.verify_token(stranger.sign()) is None
    assert await verifier.verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
async def test_many_requests_at_expiry_cause_one_refresh(
    signing_key: SigningKey,
) -> None:
    """No thundering herd, and no split brain.

    Everyone waiting observes the same atomically validated replacement, so
    nobody is served a stale key because they raced.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )

    assert await verifier.verify_token(signing_key.sign()) is not None
    now[0] += 301.0

    results = await asyncio.gather(*(verifier.verify_token(signing_key.sign()) for _ in range(12)))

    assert all(item is not None for item in results)
    assert endpoint.requests == 2


@pytest.mark.asyncio
async def test_a_flood_of_unknown_kids_is_bounded_in_fetches_and_memory(
    signing_key: SigningKey,
) -> None:
    """Attacker-chosen key ids must not become an amplifier or a memory leak.

    No negative cache, no per-kid entry, no per-kid timer: an unknown ``kid`` is
    looked up, missed, and forgotten.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)

    for index in range(64):
        stranger = SigningKey(kid=f"forged-{index}", private=signing_key.private)
        assert await verifier.verify_token(stranger.sign()) is None

    assert endpoint.requests == 1
    assert set(verifier._keys) == {signing_key.kid}


@pytest.mark.asyncio
async def test_a_pre_published_next_key_works_without_a_refresh(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """The normal shape of rotation: publish, then start signing.

    Both keys are already in the cached set, so the switchover costs no fetch.
    """
    endpoint = JwksEndpoint(keys=[signing_key, second_key])
    verifier = _verifier(endpoint)

    assert await verifier.verify_token(signing_key.sign()) is not None
    assert await verifier.verify_token(second_key.sign()) is not None
    assert endpoint.requests == 1


def test_a_lifetime_shorter_than_the_refresh_floor_is_refused() -> None:
    """Otherwise the anti-flood floor could delay repopulating an expired set.

    Failing closed while it did would be safe but needlessly unavailable, and the
    interaction is worth refusing outright rather than reasoning about per
    deployment.
    """
    with pytest.raises(ValueError, match="cache_lifetime_seconds"):
        verifier_config(cache_lifetime_seconds=10.0, minimum_refresh_interval_seconds=30.0)
    with pytest.raises(ValueError, match="cache_lifetime_seconds"):
        verifier_config(cache_lifetime_seconds=0)


# --------------------------------------------------------------------------- #
# JWK metadata
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("signing only", {"key_ops": ["sign"]}),
        ("encryption only", {"key_ops": ["encrypt"]}),
        ("decryption only", {"key_ops": ["decrypt"]}),
        ("empty operations", {"key_ops": []}),
        ("a bare string", {"key_ops": "verify"}),
        ("a non-string member", {"key_ops": ["verify", 7]}),
        ("duplicate operations", {"key_ops": ["verify", "verify"]}),
        ("inconsistent with use", {"use": "enc", "key_ops": ["verify"]}),
        ("use forbids it", {"use": "enc"}),
    ],
)
async def test_a_key_not_published_for_verification_verifies_nothing(
    signing_key: SigningKey, label: str, overrides: dict[str, Any]
) -> None:
    """RFC 7517 §4.3: ``key_ops`` says what a key may do, and ``verify`` is the
    operation signature checking needs.

    A publisher who wrote "signing only" or "encryption only" said so on purpose.
    Before this, ``key_ops`` was not read at all and a key marked ``["sign"]``
    happily verified tokens.
    """
    del label
    endpoint = JwksEndpoint(keys=[signing_key])
    endpoint.body = json.dumps({"keys": [signing_key.jwk(**overrides)]}).encode()

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [{}, {"use": None}, {"key_ops": ["verify"]}, {"use": "sig", "key_ops": ["sign", "verify"]}],
)
async def test_a_key_published_for_verification_is_used(
    signing_key: SigningKey, overrides: dict[str, Any]
) -> None:
    """Absent metadata means unrestricted, which is how most servers publish."""
    endpoint = JwksEndpoint(keys=[signing_key])
    endpoint.body = json.dumps({"keys": [signing_key.jwk(**overrides)]}).encode()

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
async def test_an_ineligible_twin_does_not_create_a_duplicate_kid_conflict(
    signing_key: SigningKey,
) -> None:
    """Filtering happens before uniqueness is judged.

    A set holding an encryption key and a signing key under one ``kid`` is
    ordinary; refusing it would let irrelevant encryption material deny all
    authentication. Two *eligible* keys sharing a ``kid`` is the ambiguity worth
    refusing, and still is.
    """
    encryption = SigningKey.generate(signing_key.kid)
    endpoint = JwksEndpoint(keys=[signing_key])
    endpoint.body = json.dumps({"keys": [encryption.jwk(use="enc"), signing_key.jwk()]}).encode()

    assert await _verifier(endpoint).verify_token(signing_key.sign()) is not None

    ambiguous = JwksEndpoint(keys=[signing_key, SigningKey.generate(signing_key.kid)])
    assert await _verifier(ambiguous).verify_token(signing_key.sign()) is None


# --------------------------------------------------------------------------- #
# Key strength and JOSE headers
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_undersized_rsa_key_verifies_nothing(signing_key: SigningKey) -> None:
    """PyJWT only *warns* about this by default, and a warning is not a control.

    ``enforce_minimum_key_length`` turns NIST SP 800-131A's 2048-bit floor into an
    error. Before it was set, a 1024-bit key authenticated normally with a
    warning nobody would see in production.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        weak = SigningKey(
            kid="weak",
            private=rsa.generate_private_key(public_exponent=65537, key_size=1024),
        )
        endpoint = JwksEndpoint(keys=[weak])
        assert await _verifier(endpoint).verify_token(weak.sign()) is None


@pytest.mark.asyncio
async def test_a_normal_two_thousand_forty_eight_bit_key_still_works(
    signing_key: SigningKey,
) -> None:
    """The floor must not reject what every authorization server actually issues."""
    endpoint = JwksEndpoint(keys=[signing_key])

    assert signing_key.private.key_size == 2048
    assert await _verifier(endpoint).verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "headers"),
    [
        ("unknown extension", {"crit": ["x-unknown"], "x-unknown": "value"}),
        ("empty list", {"crit": []}),
        ("a bare string", {"crit": "x-unknown"}),
        ("duplicates", {"crit": ["x-dup", "x-dup"], "x-dup": 1}),
        ("names an absent header", {"crit": ["x-missing"]}),
    ],
)
async def test_a_critical_header_extension_is_never_silently_ignored(
    signing_key: SigningKey, label: str, headers: dict[str, Any]
) -> None:
    """``crit`` means "reject if you do not understand this".

    PyJWT 2.13 handles it; earlier releases had a flaw here, which is exactly why
    this is pinned rather than assumed — a dependency bump that regressed it
    would fail here rather than in production.
    """
    del label
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(signing_key.sign(headers=headers)) is None


@pytest.mark.asyncio
async def test_a_detached_payload_token_is_not_an_access_token(
    signing_key: SigningKey,
) -> None:
    """``b64: false`` is a JWS signing mode, not an OAuth access token.

    This verifier reads bearer tokens; detached-payload semantics are not
    supported and must not be accepted as if they were.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    header = _part({"alg": "RS256", "kid": signing_key.kid, "b64": False, "crit": ["b64"]})
    payload = _part(default_claims())

    assert await _verifier(endpoint).verify_token(f"{header}.{payload}.AAAA") is None


@pytest.mark.asyncio
async def test_no_header_can_supply_or_locate_verification_material(
    signing_key: SigningKey, second_key: SigningKey
) -> None:
    """``jku``, ``x5u``, ``jwk`` and ``x5c`` are all ignored.

    An embedded key would let a token bring its own; a URL would let it name a
    host the attacker controls. Keys come from configuration, so a token signed
    by the *published* key is accepted while its embedded suggestions are simply
    not looked at — and a token signed by the embedded key is refused.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            content=json.dumps({"keys": [signing_key.jwk()]}).encode(),
            headers={"content-type": "application/json"},
        )

    smuggled = second_key.jwk()
    smuggled["kid"] = signing_key.kid
    headers = {
        "jku": "https://attacker.example.invalid/jwks.json",
        "x5u": "https://attacker.example.invalid/chain.pem",
        "jwk": smuggled,
        "x5c": ["QUFBQQ=="],
    }

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    verifier = JwtJwksTokenVerifier(verifier_config(), client=client)
    honest = await verifier.verify_token(signing_key.sign(headers=headers))
    forged = await verifier.verify_token(
        second_key.sign(headers={**headers, "kid": signing_key.kid})
    )
    await client.aclose()

    assert honest is not None
    assert forged is None
    assert seen == ["https://idp.example.invalid/.well-known/jwks.json"]


@pytest.mark.asyncio
async def test_an_oversized_bearer_is_refused_before_anything_expensive(
    signing_key: SigningKey,
) -> None:
    """An ``Authorization`` header is not bounded by the MCP body limit.

    A megabyte of attacker-chosen header — including its ``kid``, which becomes an
    in-memory lookup — should not reach base64, JSON or a key fetch. The limit is
    never reported: an error naming it would be an oracle for tuning around.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    huge = signing_key.sign(headers={"kid": "z" * 1_000_000})

    assert await _verifier(endpoint).verify_token(huge) is None
    assert endpoint.requests == 0
    assert await _verifier(endpoint).verify_token(signing_key.sign()) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "claims"),
    [
        ("issuer not a string", {"iss": 7}),
        ("subject not a string", {"sub": {"id": "alice"}}),
        ("audience an object", {"aud": {"resource": RESOURCE}}),
        ("audience list with a non-string", {"aud": [RESOURCE, 7]}),
        ("expiry a string", {"exp": "9999999999"}),
        ("expiry a boolean", {"exp": True}),
        ("not-before a string", {"nbf": "0"}),
        ("issued-at an object", {"iat": {"when": 1}}),
        ("scope a list", {"scope": ["a", "b"]}),
        ("scope an object", {"scope": {"a": True}}),
    ],
)
async def test_a_malformed_claim_type_is_refused_rather_than_coerced(
    signing_key: SigningKey, label: str, claims: dict[str, Any]
) -> None:
    """Nothing here turns a wrong type into a right one.

    Signed at the JWS layer, because ``jwt.encode`` refuses to build several of
    these — helpful for honest callers, and no evidence at all about what a
    consumer accepts. Three of these were accepted before this audit: PyJWT
    coerces a string ``exp`` and ``nbf`` through ``int()``, and an object ``iat``
    raised a bare ``TypeError`` that escaped the verifier entirely.
    """
    del label
    endpoint = JwksEndpoint(keys=[signing_key])

    assert await _verifier(endpoint).verify_token(sign_raw(signing_key, **claims)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["client_id", "jti", "iat"])
async def test_rfc9068_mandatory_claims_must_have_the_right_type(
    signing_key: SigningKey, claim: str
) -> None:
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint, profile=TokenProfile.RFC9068)
    token = sign_raw(signing_key, **{claim: {"nested": True}})
    header, payload, signature = token.split(".")
    del header, payload, signature

    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_an_id_token_for_the_oauth_client_cannot_substitute(
    signing_key: SigningKey,
) -> None:
    """Cross-JWT confusion, from the same issuer and the same signing key.

    An ID token is audienced to the OAuth *client*, not to this resource, so it
    fails on audience — and under the RFC 9068 profile on ``typ`` as well.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    id_token = signing_key.sign(headers={"typ": "JWT"}, aud=CLIENT_ID, scope=None, azp=CLIENT_ID)

    assert await _verifier(endpoint).verify_token(id_token) is None
    assert await _verifier(endpoint, profile=TokenProfile.RFC9068).verify_token(id_token) is None


@pytest.mark.asyncio
async def test_expiry_and_not_before_have_no_leeway(signing_key: SigningKey) -> None:
    """``leeway=0``. No clock skew is invented before an interoperability need."""
    endpoint = JwksEndpoint(keys=[signing_key])
    verifier = _verifier(endpoint)
    now = int(time.time())

    assert await verifier.verify_token(signing_key.sign(exp=now - 1)) is None
    assert await verifier.verify_token(signing_key.sign(nbf=now + 60)) is None
    assert await verifier.verify_token(signing_key.sign(nbf=now - 1, exp=now + 60)) is not None
