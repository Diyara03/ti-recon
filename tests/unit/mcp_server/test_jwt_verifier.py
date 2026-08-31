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
from typing import Any

import httpx
import pytest

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
