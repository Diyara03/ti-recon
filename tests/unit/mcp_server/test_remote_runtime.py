"""The whole remote runtime, from a signed JWT to an analyst report (Task 22).

Everything is the shipped code: the ASGI gate, the SDK's bearer middleware, the
JWT/JWKS verifier, the strict wrapper, tenant derivation, the Task 20
application, Task 19 and the four reasoning engines. Only the providers, the
signing keys and the JWKS endpoint are local — and the tokens are genuinely
signed and genuinely verified.

Nothing opens a socket, resolves a name, or contacts an identity provider.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretBytes

from fixtures.investigation.stack import (
    InvestigationStack,
    ScriptedProvider,
    claim_evidence,
    spec,
)
from fixtures.mcp_server.jwks import (
    CLIENT_ID,
    ISSUER,
    JWKS_URL,
    RESOURCE,
    SUBJECT,
    JwksEndpoint,
    SigningKey,
    verifier_config,
)
from fixtures.mcp_server.remote import (
    HOST,
    _lifespan,
    modern_headers,
    modern_request,
    raw,
    result_of,
)
from ti_recon.application.composition import CredentialLoadReport
from ti_recon.application.service import InvestigationApplication
from ti_recon.credentials import AuthType, CredentialStatus
from ti_recon.enums import ProviderCapability
from ti_recon.mcp_server.auth import RemoteAuthConfig
from ti_recon.mcp_server.http import HEALTH_PATH, MCP_PATH, RemoteHttpConfig, build_remote_http_app
from ti_recon.mcp_server.jwt_auth import JwtJwksTokenVerifier
from ti_recon.mcp_server.limits import TenantInvestigationLimiter
from ti_recon.mcp_server.principal import derive_tenant_id
from ti_recon.mcp_server.runtime import McpRuntime, RemotePrincipalSource
from ti_recon.reasoning.claims.models import ClaimSemantic

OBSERVABLE = "1.2.3.4"
TENANT_KEY = b"a-deployment-tenant-derivation-key-of-adequate-length"
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
PROVIDER_KEY = "PROVIDER_KEY_FOR_THIS_TENANT"


@pytest.fixture(scope="module")
def signing_key() -> SigningKey:
    return SigningKey.generate("deployment")


def _config() -> RemoteHttpConfig:
    return RemoteHttpConfig(resource_url=RESOURCE, issuer_url=ISSUER, allowed_hosts=(HOST,))


def _provider() -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "reputation_remote",
            family="fam_remote",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        {OBSERVABLE: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
    )


def _tenant() -> str:
    return derive_tenant_id(issuer=ISSUER, subject=SUBJECT, tenant_key=SecretBytes(TENANT_KEY))


async def _deployment(endpoint: JwksEndpoint, providers: list[ScriptedProvider]) -> Any:
    """The real application, wired to a local JWKS endpoint."""
    config = _config()
    auth = RemoteAuthConfig(issuer=ISSUER, resource=RESOURCE, tenant_key=SecretBytes(TENANT_KEY))
    stack = InvestigationStack(providers=providers)
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        adapters=tuple(providers),
        investigations=TenantInvestigationLimiter(),
    )
    verifier = JwtJwksTokenVerifier(verifier_config(), client=endpoint.client())
    app = build_remote_http_app(runtime, config=config, auth=auth, delegate=verifier)
    return app, stack, verifier


# --------------------------------------------------------------------------- #
# The whole chain
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_signed_token_reaches_a_tool_and_derives_the_right_tenant(
    signing_key: SigningKey,
) -> None:
    """Signature to report, with nothing stubbed in between.

    The token is signed with a real RSA key; the public half is fetched from a
    local JWKS endpoint; the verifier checks the signature and the claims; the
    strict wrapper re-checks issuer and audience; the middleware authenticates;
    the tenant is derived; and the credential resolved for that tenant is the one
    that reaches the provider.
    """
    provider = _provider()
    endpoint = JwksEndpoint(keys=[signing_key])
    app, stack, _verifier = await _deployment(endpoint, [provider])

    async with _lifespan(app):
        await stack.manager.create_connection(
            user_id=_tenant(),
            provider_id="reputation_remote",
            secret=PROVIDER_KEY,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(signing_key.sign()),
            body=json.dumps(
                modern_request(
                    "tools/call",
                    {"name": "investigate_observable", "arguments": {"observable": OBSERVABLE}},
                )
            ),
        )

    assert response.status_code == 200
    report = result_of(response)["structuredContent"]
    assert report["assessment"]["verdict"]
    assert provider.credentials == [PROVIDER_KEY]
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_no_part_of_the_token_survives_into_the_report_or_the_engine(
    signing_key: SigningKey,
) -> None:
    """The JWT, the subject and the identifying claims all stop at the boundary."""
    provider = _provider()
    endpoint = JwksEndpoint(keys=[signing_key])
    app, stack, _ = await _deployment(endpoint, [provider])
    token = signing_key.sign()

    async with _lifespan(app):
        await stack.manager.create_connection(
            user_id=_tenant(),
            provider_id="reputation_remote",
            secret=PROVIDER_KEY,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(token),
            body=json.dumps(
                modern_request(
                    "tools/call",
                    {"name": "investigate_observable", "arguments": {"observable": OBSERVABLE}},
                )
            ),
        )

        keys = list(stack.executor._cache._entries)

    body = response.text
    for secret in (token, SUBJECT, TENANT_KEY.decode(), "Very Identifying Person", PROVIDER_KEY):
        assert secret not in body
    assert keys
    for key in keys:
        assert _tenant() in key
        assert SUBJECT not in key
        assert token not in key


@pytest.mark.asyncio
async def test_a_token_from_the_wrong_signer_reaches_nothing(
    signing_key: SigningKey,
) -> None:
    """A well-formed token the deployment's authorization server did not issue."""
    provider = _provider()
    endpoint = JwksEndpoint(keys=[signing_key])
    app, _, _ = await _deployment(endpoint, [provider])
    stranger = SigningKey.generate("deployment")

    async with _lifespan(app):
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(stranger.sign()),
            body=json.dumps(modern_request("tools/list")),
        )

    assert response.status_code == 401
    assert provider.requests == []


@pytest.mark.asyncio
async def test_a_token_without_the_scope_is_refused_after_verification(
    signing_key: SigningKey,
) -> None:
    """The signature is fine; the grant is not. That is a 403, from the SDK."""
    provider = _provider()
    endpoint = JwksEndpoint(keys=[signing_key])
    app, _, _ = await _deployment(endpoint, [provider])

    async with _lifespan(app):
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(signing_key.sign(scope="something:else")),
            body=json.dumps(modern_request("tools/list")),
        )

    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]
    assert provider.requests == []


# --------------------------------------------------------------------------- #
# The identity provider is not the deployment's liveness
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_health_answers_while_the_identity_provider_is_unreachable(
    signing_key: SigningKey,
) -> None:
    """Mandatory. Deployment liveness is not identity-provider reachability.

    A probe that failed whenever the IdP hiccuped would take a working server out
    of rotation for something it does not need in order to be alive.
    """
    endpoint = JwksEndpoint(keys=[signing_key], failing=True)
    app, _, _ = await _deployment(endpoint, [_provider()])

    async with _lifespan(app):
        health = await raw(
            app, "GET", HEALTH_PATH, headers={"authorization": "Bearer anything-at-all"}
        )
        mcp = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(signing_key.sign()),
            body=json.dumps(modern_request("tools/list")),
        )

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    # Health caused no JWKS traffic at all; the authenticated call tried once and
    # failed closed.
    assert mcp.status_code == 401
    assert endpoint.requests == 1


@pytest.mark.asyncio
async def test_the_metadata_endpoint_answers_while_the_identity_provider_is_unreachable(
    signing_key: SigningKey,
) -> None:
    """Discovery must survive an outage, or a client cannot even learn where to
    authenticate."""
    endpoint = JwksEndpoint(keys=[signing_key], failing=True)
    app, _, _ = await _deployment(endpoint, [_provider()])

    async with _lifespan(app):
        response = await raw(
            app, "GET", METADATA_PATH, headers={"authorization": "Bearer anything-at-all"}
        )

    assert response.status_code == 200
    assert response.json()["resource"] == RESOURCE
    assert response.json()["authorization_servers"] == [ISSUER]
    assert endpoint.requests == 0


@pytest.mark.asyncio
async def test_startup_contacts_no_identity_provider(signing_key: SigningKey) -> None:
    """Construction and lifespan are offline; keys arrive with the first token."""
    endpoint = JwksEndpoint(keys=[signing_key])
    app, _, _ = await _deployment(endpoint, [_provider()])

    async with _lifespan(app):
        assert endpoint.requests == 0
        assert (await raw(app, "GET", HEALTH_PATH)).status_code == 200
        assert endpoint.requests == 0


@pytest.mark.asyncio
async def test_the_lifespan_closes_the_verifiers_http_client() -> None:
    """One client for the process, released once, by the application lifespan."""
    endpoint = JwksEndpoint(keys=[])
    verifier = JwtJwksTokenVerifier(verifier_config())
    config = _config()
    auth = RemoteAuthConfig(issuer=ISSUER, resource=RESOURCE, tenant_key=SecretBytes(TENANT_KEY))
    stack = InvestigationStack(providers=[])
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        investigations=TenantInvestigationLimiter(),
    )
    app = build_remote_http_app(runtime, config=config, auth=auth, delegate=verifier)
    client = verifier._http_client()

    async with _lifespan(app):
        assert not client.is_closed
    assert client.is_closed
    assert endpoint.requests == 0


@pytest.mark.asyncio
async def test_the_factory_refuses_a_verifier_configured_for_another_resource() -> None:
    """Three values naming one resource are three chances for two to drift."""
    stack = InvestigationStack(providers=[])
    auth = RemoteAuthConfig(issuer=ISSUER, resource=RESOURCE, tenant_key=SecretBytes(TENANT_KEY))
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
    )
    for overrides in (
        {"resource": "https://elsewhere.example.invalid/mcp"},
        {"issuer": "https://other-idp.example.invalid"},
    ):
        with pytest.raises(ValueError):
            build_remote_http_app(
                runtime,
                config=_config(),
                auth=auth,
                delegate=JwtJwksTokenVerifier(verifier_config(**overrides)),
            )


def _headers(token: str) -> dict[str, str]:
    headers = modern_headers("tools/call", bearer=token, name="investigate_observable")
    return headers


@pytest.mark.asyncio
async def test_public_routes_answer_while_the_key_cache_is_expired_and_the_idp_is_down(
    signing_key: SigningKey,
) -> None:
    """The worst combination, and the one a probe must survive.

    An expired key cache plus an unreachable identity provider is exactly when a
    deployment is most likely to be restarted by an over-eager health check. So
    liveness and discovery answer, and only authentication fails.
    """
    endpoint = JwksEndpoint(keys=[signing_key])
    now = [1000.0]
    verifier = JwtJwksTokenVerifier(
        verifier_config(), client=endpoint.client(), monotonic=lambda: now[0]
    )
    config = _config()
    auth = RemoteAuthConfig(issuer=ISSUER, resource=RESOURCE, tenant_key=SecretBytes(TENANT_KEY))
    stack = InvestigationStack(providers=[])
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        investigations=TenantInvestigationLimiter(),
    )
    app = build_remote_http_app(runtime, config=config, auth=auth, delegate=verifier)

    async with _lifespan(app):
        # Warm the cache, then let it expire while the endpoint goes away.
        assert (
            await raw(
                app,
                "POST",
                MCP_PATH,
                headers=modern_headers("tools/list", bearer=signing_key.sign()),
                body=json.dumps(modern_request("tools/list")),
            )
        ).status_code == 200
        endpoint.failing = True
        now[0] += 301.0

        before = endpoint.requests
        assert (await raw(app, "GET", HEALTH_PATH)).status_code == 200
        assert (await raw(app, "GET", METADATA_PATH)).status_code == 200
        assert endpoint.requests == before

        assert (
            await raw(
                app,
                "POST",
                MCP_PATH,
                headers=modern_headers("tools/list", bearer=signing_key.sign()),
                body=json.dumps(modern_request("tools/list")),
            )
        ).status_code == 401


@pytest.mark.asyncio
async def test_no_auth_or_key_detail_reaches_the_analyst_contract(
    signing_key: SigningKey,
) -> None:
    """Auth internals are deployment concerns, not analytical output.

    A report that carried the signing ``kid``, the issuer or the OAuth client id
    would be leaking who authenticated and how into something an analyst copies
    into a ticket.
    """
    provider = _provider()
    endpoint = JwksEndpoint(keys=[signing_key])
    app, stack, _ = await _deployment(endpoint, [provider])

    async with _lifespan(app):
        await stack.manager.create_connection(
            user_id=_tenant(),
            provider_id="reputation_remote",
            secret=PROVIDER_KEY,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        report = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(signing_key.sign()),
            body=json.dumps(
                modern_request(
                    "tools/call",
                    {"name": "investigate_observable", "arguments": {"observable": OBSERVABLE}},
                )
            ),
        )
        status = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=modern_headers("tools/call", bearer=signing_key.sign(), name="provider_status"),
            body=json.dumps(
                modern_request("tools/call", {"name": "provider_status", "arguments": {}})
            ),
        )

    for body in (report.text, status.text):
        for leak in (ISSUER, JWKS_URL, signing_key.kid, "at+jwt", "rfc9068", CLIENT_ID):
            assert leak not in body
