"""The authenticated remote HTTP surface (Task 22).

Driven over real HTTP through ``httpx.ASGITransport`` against the real ASGI
application, not through the in-memory ``Client(server)``. That distinction is
the point: the in-memory client bypasses the whole ASGI stack, and therefore
bypasses Host validation, Origin validation and the bearer middleware — which is
most of what a remote deployment's security actually consists of.

Nothing here opens a socket, contacts an identity provider or reaches a provider
API.
"""

from __future__ import annotations

import json

import pytest

from fixtures.investigation.stack import ScriptedProvider, claim_evidence, spec
from fixtures.mcp_server.remote import (
    BROWSER_ORIGIN,
    FAKE_BEARER,
    HOST,
    ISSUER,
    LEGACY_VERSION,
    MODERN_VERSION,
    RESOURCE,
    SCOPE,
    call_modern,
    call_tool,
    http_config,
    initialize_legacy,
    modern_headers,
    modern_request,
    remote_harness,
    result_of,
)
from ti_recon.enums import EvidenceEffect, ProviderCapability, Verdict
from ti_recon.mcp_server.http import (
    HEALTH_PATH,
    MAX_REQUEST_BODY_SIZE,
    MCP_PATH,
    REMOTE_SCOPE,
    RemoteHttpConfig,
)
from ti_recon.reasoning.claims.models import ClaimSemantic

OBSERVABLE = "1.2.3.4"
DIGEST = "b" * 64


def _provider(script: dict[str, object] | None = None) -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "reputation_remote",
            family="fam_remote",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        script
        if script is not None
        else {OBSERVABLE: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Configuration fails closed
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "overrides",
    [
        {"resource_url": ""},
        {"issuer_url": ""},
        {"allowed_hosts": ()},
        {"required_scopes": ()},
        {"allowed_hosts": ("*",)},
        {"allowed_hosts": ("*.example.invalid",)},
        {"allowed_origins": ("*",)},
        {"resource_url": f"http://{HOST}/mcp"},
        {"resource_url": f"https://{HOST}/mcp/"},
        {"resource_url": f"https://{HOST}/"},
        {"resource_url": "https:///mcp"},
        {"max_investigations_per_tenant": 0},
    ],
)
def test_a_remote_deployment_refuses_a_permissive_configuration(overrides: dict) -> None:
    """No permissive production default, anywhere.

    A wildcard host disables DNS-rebinding protection while *appearing* to
    configure it, which is worse than leaving it unconfigured; an ``http://``
    resource makes the token audience something an attacker on the path can
    impersonate; and ``/mcp`` and ``/mcp/`` are two different OAuth resources.
    """
    with pytest.raises(ValueError):
        http_config(**overrides)


def test_an_https_resource_ending_in_mcp_is_accepted() -> None:
    config = http_config()
    assert config.resource_url == RESOURCE
    assert config.required_scopes == (REMOTE_SCOPE,)
    assert config.max_investigations_per_tenant == 1


def test_the_verifier_and_the_published_resource_cannot_drift_apart() -> None:
    """One canonical value, checked rather than trusted.

    Advertising one resource while accepting tokens for another is exactly the
    confused-deputy shape this whole layer exists to prevent, and it is the kind
    of mistake that survives review because both halves look right on their own.
    """
    from fixtures.mcp_server.auth import auth_config
    from ti_recon.mcp_server.http import build_remote_http_app

    runtime_config = http_config()
    for auth in (
        auth_config(issuer=ISSUER, resource="https://elsewhere.example.invalid/mcp"),
        auth_config(issuer="https://other-idp.example.invalid", resource=RESOURCE),
    ):
        with pytest.raises(ValueError):
            build_remote_http_app(
                None,  # type: ignore[arg-type]
                config=runtime_config,
                auth=auth,
                delegate=object(),  # type: ignore[arg-type]
            )


def test_the_body_limit_is_the_sdk_default_rather_than_an_invented_number() -> None:
    """Recorded, not chosen. Task 24 tunes it with the ingress."""
    from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE

    assert MAX_REQUEST_BODY_SIZE == DEFAULT_MAX_REQUEST_BODY_SIZE == 4 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Discovery and the 401
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_unauthenticated_call_is_refused_and_points_at_the_metadata() -> None:
    """The first step of the flow a Claude Code user actually experiences."""
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        response = await client.post(
            MCP_PATH,
            content=json.dumps(modern_request("tools/list")),
            headers=modern_headers("tools/list", bearer=None),
        )

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert (
        f'resource_metadata="https://{HOST}/.well-known/oauth-protected-resource/mcp"' in challenge
    )


@pytest.mark.asyncio
async def test_the_protected_resource_metadata_names_the_resource_and_no_secret() -> None:
    """RFC 9728, served by the SDK from the one configured resource URL.

    Not hand-built: a second copy of this document would be a second place for
    the resource identifier to drift.
    """
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    document = response.json()
    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER]
    assert document["scopes_supported"] == [SCOPE]
    assert document["bearer_methods_supported"] == ["header"]
    body = response.text
    for secret in (FAKE_BEARER, "tenant-v1:", "client_secret"):
        assert secret not in body


@pytest.mark.asyncio
async def test_the_metadata_endpoint_is_reachable_without_a_token() -> None:
    """It has to be. A client reads it *because* it was refused."""
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        assert (await client.get("/.well-known/oauth-protected-resource/mcp")).status_code == 200


@pytest.mark.asyncio
async def test_the_installed_sdk_omits_the_scope_parameter_from_the_401() -> None:
    """Pinning what the SDK actually does, not what the spec prefers.

    2026-07-28 says a server SHOULD include ``scope=`` in the challenge. The
    installed middleware emits it only on the 403 path. Clients have a defined
    fallback — the ``scopes_supported`` in protected-resource metadata, which
    this server does publish — so this is an interoperability note rather than a
    defect, and patching a vendored SDK on a SHOULD would be the larger risk.
    Revisit only if real Claude Code OAuth fails.
    """
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        response = await client.post(
            MCP_PATH,
            content=json.dumps(modern_request("tools/list")),
            headers=modern_headers("tools/list", bearer=None),
        )

    assert "scope=" not in response.headers["www-authenticate"]


# --------------------------------------------------------------------------- #
# Who is refused, and how
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "register"),
    [
        ("unknown bearer", None),
        (
            "wrong issuer",
            {"subject": "alice", "issuer": "https://other-idp.example.invalid/oauth2"},
        ),
        (
            "wrong resource",
            {"subject": "alice", "resource": "https://elsewhere.example.invalid/mcp"},
        ),
        ("no subject", {"subject": None}),
        ("no audience", {"subject": "alice", "resource": None}),
        ("expired", {"subject": "alice", "expires_at": 1}),
    ],
)
async def test_a_token_that_is_not_ours_reaches_no_tool(label: str, register: dict | None) -> None:
    """401, and nothing below it ran.

    The provider was never asked, no credential was resolved, and — for every
    case where the token failed strict validation — no tenant id was ever
    derived, so the limiter has no record of anybody.
    """
    del label
    async with remote_harness([_provider()]) as harness:
        if register is not None:
            harness.directory.add(FAKE_BEARER, **register)
        response = await call_tool(harness, "investigate_observable", {"observable": OBSERVABLE})

        assert response.status_code == 401
        assert harness.stack.providers[0].requests == []
        assert harness.stack.providers[0].credentials == []
        assert harness.limiter.tracked_tenants == 0


@pytest.mark.asyncio
async def test_a_malformed_authorization_header_is_not_even_offered_to_the_verifier() -> None:
    """Only a ``Bearer `` header reaches a verifier at all."""
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        async with harness.client() as client:
            response = await client.post(
                MCP_PATH,
                content=json.dumps(modern_request("tools/list")),
                headers={
                    **modern_headers("tools/list", bearer=None),
                    "authorization": f"Basic {FAKE_BEARER}",
                },
            )

        assert response.status_code == 401
        assert harness.directory.seen == []


@pytest.mark.asyncio
async def test_a_valid_token_without_the_scope_is_refused_before_any_handler() -> None:
    """403 ``insufficient_scope``, from the middleware rather than from a tool.

    Enforced once, at the boundary. A scope check inside each tool would be a
    second policy to keep in step, and the first one anybody forgets to add to a
    new tool.
    """
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice", scopes=["some:other:scope"])
        response = await call_tool(harness, "investigate_observable", {"observable": OBSERVABLE})

        assert response.status_code == 403
        challenge = response.headers["www-authenticate"]
        assert 'error="insufficient_scope"' in challenge
        assert SCOPE in challenge
        assert harness.stack.providers[0].requests == []
        assert harness.limiter.tracked_tenants == 0


@pytest.mark.asyncio
async def test_an_auth_failure_describes_nothing_about_the_token_or_the_caller() -> None:
    """Not the received issuer, audience, subject, client id, bearer or tenant."""
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(
            FAKE_BEARER,
            subject="analyst.person@example.invalid",
            issuer="https://other-idp.example.invalid/oauth2",
        )
        response = await call_tool(harness, "investigate_observable", {"observable": OBSERVABLE})

        seen = response.text + json.dumps(dict(response.headers))
        for secret in (
            FAKE_BEARER,
            "analyst.person@example.invalid",
            "other-idp.example.invalid",
            "claude-code",
            "tenant-v1:",
        ):
            assert secret not in seen


# --------------------------------------------------------------------------- #
# Transport security
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_allowed_host_with_no_origin_proceeds() -> None:
    """The ordinary Claude Code shape: non-browser clients send no Origin."""
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(harness, "tools/list")

    assert response.status_code == 200
    assert "origin" not in {key.lower() for key in response.request.headers}


@pytest.mark.asyncio
async def test_an_untrusted_host_is_refused() -> None:
    """421, and no tool, credential or provider was reached.

    Pinning the installed middleware order rather than the order one would
    assume. Starlette's ``AuthenticationMiddleware`` sits *outside* the route, so
    the bearer is verified before ``TransportSecurityMiddleware`` checks the
    Host — an attacker sending a rebinding request with a stolen token can
    therefore cause one token verification, which for an introspection-based
    delegate is one call to the identity provider, before being refused.

    That is a rate-limiting consideration for the ingress (Task 24), not a
    disclosure: the response is 421, no handler runs, no credential is resolved
    and no provider is contacted. Recorded here so a future change to that order
    is a visible test change rather than a silent one.
    """
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(
            harness, "tools/list", headers={"host": "evil.example.invalid"}
        )

    assert response.status_code == 421
    assert harness.stack.providers[0].requests == []
    assert harness.stack.providers[0].credentials == []
    assert harness.limiter.tracked_tenants == 0


@pytest.mark.asyncio
async def test_an_explicitly_allowed_origin_proceeds() -> None:
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(harness, "tools/list", headers={"origin": BROWSER_ORIGIN})

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_an_untrusted_present_origin_is_refused() -> None:
    """Absent is fine; present-and-unknown is not. Never ``*``."""
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(
            harness, "tools/list", headers={"origin": "https://evil.example.invalid"}
        )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_a_post_without_json_content_type_is_refused() -> None:
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(harness, "tools/list", headers={"content-type": "text/plain"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_a_deployment_with_no_browser_origin_refuses_every_present_origin() -> None:
    """The default. An empty allowlist means no browser, not any browser."""
    config = http_config(allowed_origins=())
    async with remote_harness([_provider()], config=config) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(harness, "tools/list", headers={"origin": BROWSER_ORIGIN})
        assert response.status_code == 403
        assert (await call_modern(harness, "tools/list")).status_code == 200


def test_transport_security_is_always_enabled_and_never_wildcarded() -> None:
    """Never left to the SDK's default.

    The SDK auto-enables DNS-rebinding protection only for a loopback host and
    otherwise falls back to protection *disabled* for backwards compatibility —
    so a production hostname with no settings is silently unprotected.
    """
    settings = http_config().transport_security()

    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == [HOST]
    assert "*" not in settings.allowed_hosts
    assert "*" not in settings.allowed_origins


# --------------------------------------------------------------------------- #
# The remote tool surface
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_remote_surface_is_exactly_two_tools() -> None:
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        listing = result_of(await call_modern(harness, "tools/list"))

    assert sorted(item["name"] for item in listing["tools"]) == [
        "investigate_observable",
        "provider_status",
    ]


@pytest.mark.asyncio
async def test_the_file_tool_is_absent_rather_than_hidden() -> None:
    """A remote path names the *server's* filesystem, not the analyst's.

    Leaving it registered and merely undocumented would still list it and would
    still let a hand-written ``tools/call`` reach a path. It is not registered,
    so the call fails as an unknown tool before anything touches a filesystem.
    """
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        listing = result_of(await call_modern(harness, "tools/list"))
        assert "investigate_file" not in {item["name"] for item in listing["tools"]}

        response = await call_tool(harness, "investigate_file", {"path": "/etc/passwd"})

    assert response.status_code == 200
    body = response.json()
    unknown = json.dumps(body).lower()
    assert "error" in body or body["result"].get("isError") is True
    assert "/etc/passwd" not in unknown or "unknown tool" in unknown


@pytest.mark.asyncio
async def test_the_stdio_surface_still_has_all_three_tools() -> None:
    """The local product is untouched, including the human-approval metadata."""
    from mcp import Client

    from fixtures.mcp_server import scripted_runtime
    from ti_recon.mcp_server.server import FILE_TOOL_META, build_stdio_server

    runtime, _ = await scripted_runtime([_provider()])
    async with Client(build_stdio_server(runtime)) as client:
        tools = (await client.list_tools()).tools

    by_name = {item.name: item for item in tools}
    assert sorted(by_name) == ["investigate_file", "investigate_observable", "provider_status"]
    assert by_name["investigate_file"].meta == FILE_TOOL_META


@pytest.mark.asyncio
async def test_the_remote_resources_are_exactly_the_two_public_schemas() -> None:
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        listing = result_of(await call_modern(harness, "resources/list"))
        read = result_of(
            await call_modern(harness, "resources/read", {"uri": "ti-recon://schema/report"})
        )

    assert sorted(item["uri"] for item in listing["resources"]) == [
        "ti-recon://schema/report",
        "ti-recon://schema/request",
    ]
    document = json.loads(read["contents"][0]["text"])
    assert document["$schema"]


@pytest.mark.asyncio
async def test_resources_need_the_same_token_as_tools() -> None:
    """They travel over the same protected endpoint, so there is one boundary."""
    async with remote_harness([_provider()]) as harness:
        assert (await call_modern(harness, "resources/list", bearer=None)).status_code == 401


@pytest.mark.asyncio
async def test_no_tool_input_accepts_an_identity() -> None:
    """Identity comes from the token or from nowhere.

    A model writes its own arguments, so a ``user_id`` or ``tenant_id`` field
    would be an identity supplied by nobody.
    """
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        listing = result_of(await call_modern(harness, "tools/list"))

    forbidden = {
        "user_id",
        "tenant_id",
        "subject",
        "issuer",
        "client_id",
        "principal",
        "authorization",
        "token",
        "api_key",
        "credential",
        "scope",
        "execution_scope",
    }
    for tool in listing["tools"]:
        assert not forbidden & set(tool["inputSchema"].get("properties", {}))


# --------------------------------------------------------------------------- #
# Both protocol eras, and no sessions
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_modern_request_is_self_contained_and_creates_no_session() -> None:
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_modern(harness, "tools/list")

    assert response.status_code == 200
    assert "mcp-session-id" not in response.headers
    assert response.request.headers["mcp-protocol-version"] == MODERN_VERSION


@pytest.mark.asyncio
async def test_a_handshake_era_client_is_served_without_a_session() -> None:
    """``stateless_http=True`` closes the only remaining server-side session.

    TI Recon needs no sampling, elicitation, subscription or resumable SSE, so
    there is nothing a session would carry — and a session would be
    process-local state a future second worker could not see.
    """
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await initialize_legacy(harness)

    assert response.status_code == 200
    assert "mcp-session-id" not in response.headers
    assert LEGACY_VERSION in response.text


@pytest.mark.asyncio
async def test_the_handshake_era_endpoint_is_protected_too() -> None:
    """Both eras arrive on one path, so both meet the same middleware."""
    async with remote_harness([_provider()]) as harness:
        assert (await initialize_legacy(harness, bearer=None)).status_code == 401


# --------------------------------------------------------------------------- #
# The public surface, audited
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_health_is_public_fixed_and_says_nothing_about_the_deployment() -> None:
    """Liveness only.

    No version, issuer, resource URL, provider count, tenant count, uptime or
    cache state: each is a small gift to somebody deciding whether this host is
    worth attacking, and none of them helps a load balancer.
    """
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        response = await client.get(HEALTH_PATH)

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        # It is liveness, not Task 18's coverage adequacy. One word meaning two
        # things in one system is how somebody acts on the wrong one.
        assert "readiness" not in response.text.lower()
        assert harness.directory.seen == []
        assert harness.stack.providers[0].requests == []


@pytest.mark.asyncio
async def test_health_is_the_only_route_this_repository_adds_unauthenticated() -> None:
    """Everything else on the app is either protected or SDK-required metadata.

    Enumerated from the app's own routing table rather than asserted in prose, so
    a future custom route cannot quietly join the public set.
    """
    async with remote_harness([_provider()]) as harness:
        paths = {getattr(route, "path", None) for route in harness.app.routes}

    assert paths == {
        MCP_PATH,
        HEALTH_PATH,
        "/.well-known/oauth-protected-resource/mcp",
    }


@pytest.mark.asyncio
async def test_no_authorization_server_endpoint_is_served() -> None:
    """TI Recon verifies tokens; it never issues them.

    ``auth_server_provider`` is never supplied, so these routes are absent rather
    than merely unimplemented.
    """
    async with remote_harness([_provider()]) as harness, harness.client() as client:
        for path in (
            "/authorize",
            "/token",
            "/register",
            "/revoke",
            "/login",
            "/.well-known/oauth-authorization-server",
        ):
            assert (await client.get(path)).status_code == 404, path


# --------------------------------------------------------------------------- #
# Analysis travels intact over the wire
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("semantic", "effect", "verdict"),
    [
        (
            ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
            EvidenceEffect.SUPPORTS_MALICIOUS,
            Verdict.MALICIOUS,
        ),
        (ClaimSemantic.MALICIOUS_REPUTATION, EvidenceEffect.SUPPORTS_MALICIOUS, Verdict.SUSPICIOUS),
        (ClaimSemantic.BENIGN_REPUTATION, EvidenceEffect.SUPPORTS_BENIGN, Verdict.LIKELY_BENIGN),
    ],
)
async def test_every_verdict_is_a_successful_tool_call(
    semantic: ClaimSemantic, effect: EvidenceEffect, verdict: Verdict
) -> None:
    """A tool call reports whether the tool worked, never what it found.

    There is no remote-specific verdict logic, and authentication success is
    independent of the analytical conclusion.
    """
    provider = ScriptedProvider(
        spec(
            "reputation_remote",
            family="fam_remote",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        {DIGEST: claim_evidence(semantic, effect=effect)},
    )
    async with remote_harness([provider]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        await harness.stack.manager.create_connection(
            user_id=_tenant("alice"),
            provider_id="reputation_remote",
            secret="fake-remote-key",
            auth_type=__import__("ti_recon.credentials", fromlist=["AuthType"]).AuthType.API_KEY,
        )
        response = await call_tool(
            harness,
            "investigate_observable",
            {"observable": DIGEST, "observable_type": "file_hash"},
        )

    assert response.status_code == 200
    result = result_of(response)
    assert result.get("isError") is not True
    assert result["structuredContent"]["assessment"]["verdict"] == verdict.value


@pytest.mark.asyncio
async def test_an_unanswered_observable_is_inconclusive_and_still_a_success() -> None:
    """Absence is never suspicion, and never an error either."""
    async with remote_harness([_provider(script={})]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_tool(harness, "investigate_observable", {"observable": OBSERVABLE})

    result = result_of(response)
    assert result.get("isError") is not True
    assert result["structuredContent"]["assessment"]["verdict"] == Verdict.INCONCLUSIVE.value


@pytest.mark.asyncio
async def test_an_unparseable_observable_is_a_tool_error_not_an_http_error() -> None:
    """Authentication succeeded; the argument did not. Those are different layers."""
    async with remote_harness([_provider()]) as harness:
        harness.directory.add(FAKE_BEARER, subject="alice")
        response = await call_tool(harness, "investigate_observable", {"observable": "not valid!!"})

    assert response.status_code == 200
    assert result_of(response)["isError"] is True


def _tenant(subject: str) -> str:
    from pydantic import SecretStr

    from fixtures.mcp_server.auth import FAKE_TENANT_SECRET
    from ti_recon.mcp_server.principal import derive_tenant_id

    return derive_tenant_id(
        issuer=ISSUER, subject=subject, tenant_key=SecretStr(FAKE_TENANT_SECRET)
    )


def test_the_config_type_is_frozen() -> None:
    assert isinstance(http_config(), RemoteHttpConfig)
    with pytest.raises(Exception):  # noqa: B017 - dataclasses.FrozenInstanceError
        http_config().resource_url = "https://elsewhere.example.invalid/mcp"  # type: ignore[misc]
