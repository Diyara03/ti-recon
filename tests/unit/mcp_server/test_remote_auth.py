"""The strict token check and the tenant identity it produces (Task 22).

Two questions, and they are separate on purpose. *Is this token ours?* is answered
by :func:`validate_access_token` over a token a delegate already proved. *Who is
this?* is answered by an HMAC over the validated issuer and subject. Getting the
first wrong accepts a stranger's token; getting the second wrong merges two
analysts into one tenant, or splits one across two.
"""

from __future__ import annotations

import dataclasses

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from pydantic import SecretBytes

from fixtures.mcp_server.auth import (
    CLIENT_ID,
    FAKE_MCP_TOKEN,
    FAKE_SUBJECT,
    FAKE_TENANT_SECRET,
    ISSUER,
    OTHER_ISSUER,
    RESOURCE,
    FakeDelegateVerifier,
    access_token,
    auth_config,
)
from ti_recon.mcp_server.auth import (
    RemoteAuthConfig,
    RemoteAuthenticationError,
    StrictTokenVerifier,
    TokenRejection,
    resolve_remote_principal,
    validate_access_token,
)
from ti_recon.mcp_server.principal import TENANT_ID_PREFIX, derive_tenant_id

CONFIG = auth_config()


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_a_remote_deployment_cannot_be_configured_without_its_three_answers() -> None:
    """No unsafe default, in particular for the tenant key.

    An empty key would make every deployment derive the same tenant ids from the
    same people, which is the same as having no key at all.
    """
    for kwargs in (
        {"issuer": ""},
        {"resource": ""},
        {"tenant_key": b""},
        {"tenant_key": b"too-short"},
    ):
        with pytest.raises(ValueError):
            auth_config(**kwargs)  # type: ignore[arg-type]


def test_the_tenant_key_is_not_rendered_by_repr() -> None:
    """Not the value, and not its length, prefix or digest either."""
    text = repr(CONFIG)

    assert FAKE_TENANT_SECRET.decode() not in text
    assert str(len(FAKE_TENANT_SECRET)) not in text
    assert ISSUER in text and RESOURCE in text


# --------------------------------------------------------------------------- #
# Strict token invariants
# --------------------------------------------------------------------------- #


def test_a_fully_valid_token_is_accepted() -> None:
    assert validate_access_token(access_token(), CONFIG) is None


@pytest.mark.parametrize("subject", [None, ""])
def test_a_token_without_a_subject_names_no_principal(subject: str | None) -> None:
    """There is no identity to derive, so there is nothing to serve."""
    assert (
        validate_access_token(access_token(subject=subject), CONFIG)
        is TokenRejection.MISSING_SUBJECT
    )


@pytest.mark.parametrize("issuer", [None, OTHER_ISSUER, ISSUER + "/", ISSUER.upper()])
def test_only_the_configured_issuer_is_accepted(issuer: str | None) -> None:
    """Exact string comparison, as OAuth issuer identity is defined.

    A trailing slash and a case change are different issuers, not the same one
    written differently — and a resource server that normalised them would
    accept a neighbour's tokens.
    """
    assert (
        validate_access_token(access_token(issuer=issuer), CONFIG) is TokenRejection.ISSUER_MISMATCH
    )


def test_an_issuer_is_never_invented_from_the_bearer_string() -> None:
    """A token carrying no issuer is refused rather than assumed to be ours.

    The wrapper does not read the token, so the only issuer it can trust is one
    a verifier put on the verified representation.
    """
    token = access_token(issuer=None)
    assert token.claims is None or "iss" not in token.claims
    assert validate_access_token(token, CONFIG) is TokenRejection.ISSUER_MISMATCH


# --- audience ------------------------------------------------------------- #


def test_the_resource_field_alone_establishes_the_audience() -> None:
    assert validate_access_token(access_token(audience=None), CONFIG) is None


def test_a_string_aud_claim_alone_establishes_the_audience() -> None:
    assert validate_access_token(access_token(resource=None, audience=RESOURCE), CONFIG) is None


def test_a_list_aud_claim_containing_this_resource_is_accepted() -> None:
    """RFC 9068 permits an array audience; one member being us is enough."""
    audience = ["https://elsewhere.example.invalid/api", RESOURCE]
    assert validate_access_token(access_token(resource=None, audience=audience), CONFIG) is None


def test_a_token_naming_no_audience_at_all_is_refused() -> None:
    """MCP requires the token to have been issued for *this* resource."""
    assert (
        validate_access_token(access_token(resource=None, audience=None), CONFIG)
        is TokenRejection.AUDIENCE_MISMATCH
    )


@pytest.mark.parametrize(
    "audience",
    [
        "https://elsewhere.example.invalid/mcp",
        ["https://elsewhere.example.invalid/mcp"],
        RESOURCE + "/",
        [],
        123,
        {"aud": RESOURCE},
        [RESOURCE, 7],
    ],
)
def test_an_audience_that_is_not_exactly_this_resource_is_refused(audience: object) -> None:
    """Including a trailing slash, and including malformed representations.

    Guessing what a malformed audience meant is guessing in the direction of
    acceptance, so it is not guessed at.
    """
    assert (
        validate_access_token(access_token(resource=None, audience=audience), CONFIG)
        is TokenRejection.AUDIENCE_MISMATCH
    )


def test_two_audience_representations_that_disagree_are_refused() -> None:
    """Not resolved in whichever direction happens to be convenient.

    A verifier whose two audience views contradict each other has said it does
    not know what the token is for, in both directions.
    """
    assert (
        validate_access_token(
            access_token(resource=RESOURCE, audience="https://elsewhere.example.invalid/mcp"),
            CONFIG,
        )
        is TokenRejection.AUDIENCE_CONFLICT
    )
    assert (
        validate_access_token(
            access_token(resource="https://elsewhere.example.invalid/mcp", audience=RESOURCE),
            CONFIG,
        )
        is TokenRejection.AUDIENCE_CONFLICT
    )


def test_two_audience_representations_that_agree_are_accepted() -> None:
    assert validate_access_token(access_token(resource=RESOURCE, audience=RESOURCE), CONFIG) is None


def test_scopes_are_preserved_exactly_and_not_enforced_here() -> None:
    """Scope enforcement is the HTTP middleware's, configured once."""
    token = access_token(scopes=["ti-recon:investigate"])
    assert validate_access_token(token, CONFIG) is None
    assert token.scopes == ["ti-recon:investigate"]


# --------------------------------------------------------------------------- #
# The wrapper over a delegate
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_wrapper_accepts_an_opaque_token_a_delegate_verified() -> None:
    """The generic layer is not accidentally a JWT parser.

    The bearer string here has no dots, no base64 and no structure at all. If the
    delegate proved it, the wrapper's only remaining questions are about the
    verified representation.
    """
    delegate = FakeDelegateVerifier(result=access_token(token="opaque-token-with-no-dots"))
    verifier = StrictTokenVerifier(delegate=delegate, config=CONFIG)

    assert await verifier.verify_token("opaque-token-with-no-dots") is not None
    assert delegate.seen == ["opaque-token-with-no-dots"]


@pytest.mark.asyncio
async def test_a_delegate_refusal_is_final() -> None:
    """The wrapper never second-guesses a rejection by reading the token."""
    delegate = FakeDelegateVerifier(result=None)
    verifier = StrictTokenVerifier(delegate=delegate, config=CONFIG)

    assert await verifier.verify_token(FAKE_MCP_TOKEN) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        access_token(subject=None),
        access_token(issuer=OTHER_ISSUER),
        access_token(resource=None, audience=None),
        access_token(resource=RESOURCE, audience="https://elsewhere.example.invalid/mcp"),
    ],
)
async def test_the_wrapper_refuses_what_the_delegate_let_through(token: object) -> None:
    """A delegate that forgets an invariant must not be able to weaken TI Recon."""
    verifier = StrictTokenVerifier(
        delegate=FakeDelegateVerifier(result=token),  # type: ignore[arg-type]
        config=CONFIG,
    )

    assert await verifier.verify_token(FAKE_MCP_TOKEN) is None


@pytest.mark.asyncio
async def test_a_rejection_reveals_nothing_about_the_token(caplog) -> None:
    """Not the token, not its claims, and not what the audience should have been."""
    caplog.set_level("DEBUG")
    verifier = StrictTokenVerifier(
        delegate=FakeDelegateVerifier(result=access_token(issuer=OTHER_ISSUER)),
        config=CONFIG,
    )

    assert await verifier.verify_token(FAKE_MCP_TOKEN) is None
    logged = caplog.text
    assert TokenRejection.ISSUER_MISMATCH.value in logged
    for secret in (
        FAKE_MCP_TOKEN,
        FAKE_SUBJECT,
        OTHER_ISSUER,
        RESOURCE,
        FAKE_TENANT_SECRET.decode(),
    ):
        assert secret not in logged


# --------------------------------------------------------------------------- #
# Tenant derivation
# --------------------------------------------------------------------------- #


def _tenant(
    *, issuer: str = ISSUER, subject: str = FAKE_SUBJECT, key: bytes = FAKE_TENANT_SECRET
) -> str:
    return derive_tenant_id(issuer=issuer, subject=subject, tenant_key=SecretBytes(key))


def test_the_tenant_id_is_deterministic() -> None:
    """No clock, no randomness, no process-dependent hashing.

    A returning analyst has to find their own credentials and their own cache
    entries, which only works if the identifier is a pure function of its inputs.
    """
    assert _tenant() == _tenant() == _tenant()
    assert _tenant().startswith(TENANT_ID_PREFIX)


def test_the_same_subject_from_two_issuers_is_two_tenants() -> None:
    """Mandatory. ``sub`` is unique only per issuer.

    Two organizations can both have an "alice", and deriving from the subject
    alone would hand one of them the other's credentials.
    """
    assert _tenant(subject="alice") != _tenant(issuer=OTHER_ISSUER, subject="alice")


def test_the_same_issuer_with_two_subjects_is_two_tenants() -> None:
    assert _tenant(subject="alice") != _tenant(subject="bob")


def test_a_different_deployment_key_is_a_different_tenant() -> None:
    """Which is why the key is durable configuration, not a startup nonce."""
    assert _tenant() != _tenant(key=b"a-different-deployment-key-of-adequate-length")


def test_the_encoding_is_unambiguous_across_the_issuer_subject_boundary() -> None:
    """Length-prefixed, so no split of the same characters collides.

    A naive concatenation would make ``iss="https://a" sub="bc"`` and
    ``iss="https://ab" sub="c"`` one identifier.
    """
    assert _tenant(issuer="https://a", subject="bc") != _tenant(issuer="https://ab", subject="c")


def test_nothing_about_the_subject_or_the_key_survives_into_the_tenant_id() -> None:
    """The identifier is the prefix and hex, and nothing else."""
    tenant = _tenant()
    assert FAKE_SUBJECT not in tenant
    assert FAKE_TENANT_SECRET.decode() not in tenant
    assert ISSUER not in tenant
    digest = tenant.removeprefix(TENANT_ID_PREFIX)
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


# --------------------------------------------------------------------------- #
# Resolving the principal of a request
# --------------------------------------------------------------------------- #


def _authenticated(token: object):
    """Bind a token to the current context exactly as the SDK middleware does."""
    return auth_context_var.set(AuthenticatedUser(token))  # type: ignore[arg-type]


def test_a_validated_token_resolves_to_its_tenant() -> None:
    reset = _authenticated(access_token())
    try:
        principal = resolve_remote_principal(CONFIG)
    finally:
        auth_context_var.reset(reset)

    assert principal.tenant_id == _tenant()


def test_two_analysts_sharing_one_oauth_client_are_two_tenants() -> None:
    """The ``client_id`` identifies Claude Code, not the person using it.

    Deriving from it would collapse every analyst in an organization into one
    tenant, sharing credentials, cache and quota.
    """
    tenants = []
    for subject in ("alice", "bob"):
        reset = _authenticated(access_token(subject=subject, client_id=CLIENT_ID))
        try:
            tenants.append(resolve_remote_principal(CONFIG).tenant_id)
        finally:
            auth_context_var.reset(reset)

    assert tenants[0] != tenants[1]


def test_resolution_fails_closed_outside_an_authenticated_request() -> None:
    """No fallback to the stdio principal, the client id, or a default."""
    with pytest.raises(RemoteAuthenticationError):
        resolve_remote_principal(CONFIG)


@pytest.mark.parametrize(
    "token",
    [
        access_token(subject=None),
        access_token(issuer=OTHER_ISSUER),
        access_token(resource=None, audience=None),
    ],
)
def test_an_unvalidated_token_can_never_produce_a_tenant(token: object) -> None:
    """The invariants are re-checked here, so mis-wiring fails closed.

    A deployment that installed the bearer middleware without the strict wrapper
    would otherwise derive a tenant from a token nobody checked was ours.
    """
    reset = _authenticated(token)
    try:
        with pytest.raises(RemoteAuthenticationError):
            resolve_remote_principal(CONFIG)
    finally:
        auth_context_var.reset(reset)


def test_a_refusal_says_nothing_about_the_token() -> None:
    with pytest.raises(RemoteAuthenticationError) as raised:
        resolve_remote_principal(CONFIG)

    message = str(raised.value)
    for secret in (FAKE_MCP_TOKEN, FAKE_SUBJECT, ISSUER, RESOURCE, FAKE_TENANT_SECRET.decode()):
        assert secret not in message


def test_the_config_is_a_value_two_deployments_cannot_share_by_accident() -> None:
    """Frozen, so nothing can retune the issuer or the key after composition."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        CONFIG.issuer = OTHER_ISSUER  # type: ignore[misc]
    assert isinstance(CONFIG, RemoteAuthConfig)
