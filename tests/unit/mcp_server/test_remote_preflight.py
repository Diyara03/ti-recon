"""What runs before OAuth, and what never reaches it (Task 22).

Token verification is the most expensive thing in a remote request path: for a
deployment whose delegate introspects, it is a network call to the identity
provider. Everything cheap therefore has to happen first, and the public health
route has to happen *outside* it entirely.

The SDK cannot arrange that on its own. Its
``AuthenticationMiddleware(BearerAuthBackend)`` is Starlette *application*
middleware, so it wraps the whole routing table, while
``TransportSecurityMiddleware`` runs inside the Streamable HTTP transport
handler — after routing and after ``RequireAuthMiddleware``. Measured before the
gate existed:

===================================== ======= ================
request                               status  verifier calls
===================================== ======= ================
bad ``Host`` + invalid bearer         401     1
bad ``Origin`` + invalid bearer       401     1
``text/plain`` POST + invalid bearer  401     1
``GET /health`` + garbage bearer      200     1
metadata + garbage bearer             200     1
===================================== ======= ================

None of those is a disclosure. All of them let unauthenticated traffic drive the
verifier, and the first three never even reached the Host check because the
invalid bearer answered first.

Most of these use a verifier that raises rather than one that counts. A counter
proves a number; a raising verifier proves the code path, and fails with the
reason written on it rather than on an assertion three frames away.
"""

from __future__ import annotations

import json

import pytest

from fixtures.mcp_server.remote import (
    BROWSER_ORIGIN,
    HOST,
    CountingVerifier,
    RefusingVerifier,
    gated_app,
    http_config,
    modern_headers,
    modern_request,
    raw,
    remote_token,
)
from ti_recon.mcp_server.http import HEALTH_PATH, MCP_PATH

#: Planted so a match anywhere in a log, a response or stderr cannot be chance.
PLANTED_BEARER = "SUPER_SECRET_HTTP_BEARER_123"

METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"

BAD_HOST = "definitely-untrusted.example"
BAD_ORIGIN = "https://evil.example.invalid"


def _body() -> str:
    return json.dumps(modern_request("tools/list"))


def _headers(**overrides: str) -> dict[str, str]:
    headers = modern_headers("tools/list", bearer=PLANTED_BEARER)
    headers.update(overrides)
    return headers


# --------------------------------------------------------------------------- #
# The ordering matrix
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "overrides", "status"),
    [
        ("untrusted Host", {"host": BAD_HOST}, 421),
        ("untrusted Origin", {"origin": BAD_ORIGIN}, 403),
        ("wrong content type", {"content-type": "text/plain"}, 400),
    ],
)
async def test_a_transport_rejection_never_reaches_the_verifier(
    label: str, overrides: dict[str, str], status: int
) -> None:
    """The whole point of the gate.

    Each of these carries a bearer, and each used to have it verified before the
    request was refused for a reason that costs nothing to check.
    """
    del label
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(app, "POST", MCP_PATH, headers=_headers(**overrides), body=_body())

    assert response.status_code == status
    assert PLANTED_BEARER not in response.text


@pytest.mark.asyncio
async def test_a_missing_bearer_is_refused_without_a_verification() -> None:
    """No header, nothing to verify. 401 from the SDK, as before."""
    verifier = CountingVerifier()
    async with gated_app(verifier) as app:
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=modern_headers("tools/list", bearer=None),
            body=_body(),
        )

    assert response.status_code == 401
    assert verifier.calls == 0


@pytest.mark.asyncio
async def test_an_invalid_bearer_is_verified_exactly_once() -> None:
    """Once past the cheap checks, the token is the question — and it is asked once."""
    verifier = CountingVerifier(result=None)
    async with gated_app(verifier) as app:
        response = await raw(app, "POST", MCP_PATH, headers=_headers(), body=_body())

    assert response.status_code == 401
    assert verifier.calls == 1


@pytest.mark.asyncio
async def test_a_valid_bearer_without_the_scope_is_verified_once_then_refused() -> None:
    """Scope enforcement is the SDK's, after verification, before the handler."""
    verifier = CountingVerifier(result=remote_token(scopes=["some:other:scope"]))
    async with gated_app(verifier) as app:
        response = await raw(app, "POST", MCP_PATH, headers=_headers(), body=_body())

    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]
    assert verifier.calls == 1


@pytest.mark.asyncio
async def test_a_valid_bearer_with_the_scope_reaches_the_dispatcher() -> None:
    """The complete chain: transport, token, scope, MCP handler."""
    verifier = CountingVerifier(result=remote_token())
    async with gated_app(verifier) as app:
        response = await raw(app, "POST", MCP_PATH, headers=_headers(), body=_body())

    assert response.status_code == 200
    assert verifier.calls == 1
    assert "tools" in response.json()["result"]


@pytest.mark.asyncio
async def test_the_transport_checks_run_in_host_then_origin_then_type_order() -> None:
    """A request wrong in several ways is answered by the cheapest check first."""
    async with gated_app(RefusingVerifier()) as app:
        both = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(host=BAD_HOST, origin=BAD_ORIGIN, **{"content-type": "text/plain"}),
            body=_body(),
        )
        origin_and_type = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=_headers(origin=BAD_ORIGIN, **{"content-type": "text/plain"}),
            body=_body(),
        )

    # Content type is checked before Host and Origin by the SDK's own validator,
    # which is deliberately left as it is rather than re-ordered here: reusing
    # its semantics means reusing all of them.
    assert both.status_code == 400
    assert origin_and_type.status_code == 400


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "headers", "status"),
    [
        ("no authorization", {}, 200),
        ("garbage bearer", {"authorization": f"Bearer {PLANTED_BEARER}"}, 200),
        ("allowed origin", {"origin": BROWSER_ORIGIN}, 200),
        ("untrusted host", {"host": BAD_HOST}, 421),
        ("untrusted origin", {"origin": BAD_ORIGIN}, 403),
    ],
)
async def test_health_never_verifies_a_token(
    label: str, headers: dict[str, str], status: int
) -> None:
    """Public, and outside authentication entirely.

    It was an SDK custom route before, which is documented as unauthenticated —
    but a custom route still sits *behind* the app-level authentication
    middleware, so a bearer sent to it was verified anyway. Served from the gate,
    there is no middleware to sit behind.

    It still respects the transport policy, because the gate applies globally: a
    health probe from an untrusted Host is refused like anything else.
    """
    del label
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(app, "GET", HEALTH_PATH, headers=headers)

    assert response.status_code == status
    assert PLANTED_BEARER not in response.text


@pytest.mark.asyncio
async def test_health_says_one_thing_and_carries_no_json_requirement() -> None:
    """A GET has no content type to be wrong, so none is demanded of it."""
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(app, "GET", HEALTH_PATH, headers={"content-type": "text/plain"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    body = response.text.lower()
    for forbidden in ("readiness", "issuer", "resource", "version", "uptime", "provider"):
        assert forbidden not in body


@pytest.mark.asyncio
async def test_health_refuses_a_write_method() -> None:
    """Liveness is a read. Nothing here changes anything."""
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(app, "POST", HEALTH_PATH, headers={"content-type": "application/json"})

    assert response.status_code == 405
    assert response.headers["allow"] == "GET, HEAD"


@pytest.mark.asyncio
async def test_health_touches_no_credential_store_provider_or_executor() -> None:
    """Proved by there being nothing underneath to touch.

    The gate answers before the SDK application is entered, so the principal
    resolver, the credential repository and the executor are all unreachable —
    and a verifier that raises proves the authentication path was not entered
    either.
    """
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(
            app, "GET", HEALTH_PATH, headers={"authorization": f"Bearer {PLANTED_BEARER}"}
        )

    assert response.status_code == 200
    assert HEALTH_PATH in app.public_paths


# --------------------------------------------------------------------------- #
# RFC 9728 discovery
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "headers", "status"),
    [
        ("no authorization", {}, 200),
        ("garbage bearer", {"authorization": f"Bearer {PLANTED_BEARER}"}, 200),
        ("untrusted host", {"host": BAD_HOST}, 421),
        ("untrusted origin", {"origin": BAD_ORIGIN}, 403),
    ],
)
async def test_the_metadata_endpoint_never_verifies_a_token(
    label: str, headers: dict[str, str], status: int
) -> None:
    """Public discovery, and now verifier-free as well.

    RFC 9728 metadata is unconditionally public — a client reads it precisely
    *because* it was refused — so a bearer sent there is meaningless. The gate
    drops the ``Authorization`` header on that exact path before handing the
    request to the SDK, which is enough to skip verification and changes nothing
    else: the route was unauthenticated either way and still answers with the
    SDK's own document.

    Nothing is copied, rebuilt or re-routed. The metadata stays the SDK's.
    """
    del label
    async with gated_app(RefusingVerifier()) as app:
        response = await raw(app, "GET", METADATA_PATH, headers=headers)

    assert response.status_code == status


@pytest.mark.asyncio
async def test_the_metadata_document_is_unchanged_by_the_header_stripping() -> None:
    """Same four fields, same values, still generated by the SDK."""
    async with gated_app(RefusingVerifier()) as app:
        plain = await raw(app, "GET", METADATA_PATH)
        with_bearer = await raw(
            app, "GET", METADATA_PATH, headers={"authorization": f"Bearer {PLANTED_BEARER}"}
        )

    assert plain.json() == with_bearer.json()
    document = plain.json()
    assert document["resource"] == f"https://{HOST}/mcp"
    assert document["authorization_servers"] == [http_config().issuer_url]
    assert document["scopes_supported"] == ["ti-recon:investigate"]
    assert document["bearer_methods_supported"] == ["header"]


@pytest.mark.asyncio
async def test_stripping_is_scoped_to_the_metadata_path_alone() -> None:
    """It must never widen to a protected path.

    And if it ever did, it fails in the safe direction: a stripped bearer on
    ``/mcp`` becomes a 401, not access. This asserts the bearer still arrives.
    """
    verifier = CountingVerifier(result=remote_token())
    async with gated_app(verifier) as app:
        assert (
            await raw(app, "POST", MCP_PATH, headers=_headers(), body=_body())
        ).status_code == 200
        assert verifier.calls == 1

        await raw(app, "GET", METADATA_PATH, headers={"authorization": f"Bearer {PLANTED_BEARER}"})
        assert verifier.calls == 1


# --------------------------------------------------------------------------- #
# The MCP surface is still protected
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["tools/list", "tools/call", "resources/list", "resources/read"])
async def test_every_mcp_operation_still_requires_a_bearer(method: str) -> None:
    """The hardening must not have made anything public by accident."""
    verifier = CountingVerifier()
    params: dict[str, object] = {}
    if method == "tools/call":
        params = {"name": "provider_status", "arguments": {}}
    elif method == "resources/read":
        params = {"uri": "ti-recon://schema/report"}

    async with gated_app(verifier) as app:
        headers = modern_headers(
            method,
            bearer=None,
            name=params.get("name") or params.get("uri"),  # type: ignore[arg-type]
        )
        response = await raw(
            app,
            "POST",
            MCP_PATH,
            headers=headers,
            body=json.dumps(modern_request(method, params)),
        )

    assert response.status_code == 401
    assert verifier.calls == 0


# --------------------------------------------------------------------------- #
# Defence in depth, and lifespan ownership
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_sdk_transport_check_is_still_enabled_inside_the_mcp_app() -> None:
    """A mistake in the gate must not silently disable the SDK's own protection.

    Proved by driving the *inner* application directly, past the gate: it still
    refuses an untrusted Host, with a token this time because that is the order
    the SDK has. The inner settings are never weakened just because an outer
    check exists.
    """
    import httpx

    verifier = CountingVerifier(result=remote_token())
    async with (
        gated_app(verifier) as app,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app.mcp_app), base_url=f"https://{HOST}"
        ) as client,
    ):
        response = await client.post(MCP_PATH, headers=_headers(host=BAD_HOST), content=_body())

    assert response.status_code == 421


@pytest.mark.asyncio
async def test_one_configuration_drives_both_enforcement_points() -> None:
    """No second policy, and no separately tunable copy.

    The gate builds its validator from the same ``RemoteHttpConfig`` the inner
    transport was given, so a host can never be trusted by one and refused by the
    other.
    """
    config = http_config()
    async with gated_app(RefusingVerifier(), config=config) as app:
        assert app.config is config
        settings = app.config.transport_security()

    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == list(config.allowed_hosts)
    assert settings.allowed_origins == list(config.allowed_origins)


@pytest.mark.asyncio
async def test_the_session_manager_starts_once_for_many_requests() -> None:
    """Lifespan passes through the gate to the application that owns it.

    ``StreamableHTTPSessionManager.run()`` refuses a second call on one instance,
    so a wrapper that started it per request — or started it itself — would fail
    on the second one. Several requests through one lifespan is the proof.
    """
    verifier = CountingVerifier(result=remote_token())
    async with gated_app(verifier) as app:
        for _ in range(3):
            response = await raw(app, "POST", MCP_PATH, headers=_headers(), body=_body())
            assert response.status_code == 200
        assert (await raw(app, "GET", HEALTH_PATH)).status_code == 200

    assert verifier.calls == 3


@pytest.mark.asyncio
async def test_a_request_outside_the_lifespan_is_refused_rather_than_served() -> None:
    """The fixture cannot be what makes these tests pass.

    Without the lifespan the SDK's session manager has no task group, so the
    transport raises. If the gate quietly started one per request this would
    succeed — and every other test in this file would be proving something about
    a fixture rather than about a deployment.
    """
    import httpx

    from fixtures.investigation.stack import InvestigationStack
    from fixtures.mcp_server.auth import auth_config
    from ti_recon.application.composition import CredentialLoadReport
    from ti_recon.application.service import InvestigationApplication
    from ti_recon.mcp_server.http import build_remote_http_app
    from ti_recon.mcp_server.limits import TenantInvestigationLimiter
    from ti_recon.mcp_server.runtime import McpRuntime, RemotePrincipalSource

    config = http_config()
    auth = auth_config(issuer=config.issuer_url, resource=config.resource_url)
    stack = InvestigationStack(providers=[])
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        investigations=TenantInvestigationLimiter(),
    )
    app = build_remote_http_app(
        runtime,
        config=config,
        auth=auth,
        delegate=CountingVerifier(result=remote_token()),
    )

    # Health is answered by the gate, so it works with no lifespan at all.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"https://{HOST}"
    ) as client:
        assert (await client.get(HEALTH_PATH)).status_code == 200
        with pytest.raises(RuntimeError, match="Task group is not initialized"):
            await client.post(MCP_PATH, headers=_headers(), content=_body())


# --------------------------------------------------------------------------- #
# Privacy
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_transport_rejection_names_nothing_configured_or_supplied(caplog) -> None:
    """Not the bearer, and not the allowed host or origin lists either.

    The SDK logs the rejected Host and Origin values, which are attacker-supplied
    and therefore already known to the attacker. What must never appear is what
    *would* have been accepted, or anything about the caller.
    """
    caplog.set_level("DEBUG")
    async with gated_app(RefusingVerifier()) as app:
        host = await raw(app, "POST", MCP_PATH, headers=_headers(host=BAD_HOST), body=_body())
        origin = await raw(app, "POST", MCP_PATH, headers=_headers(origin=BAD_ORIGIN), body=_body())
        bad_type = await raw(
            app, "POST", MCP_PATH, headers=_headers(**{"content-type": "text/plain"}), body=_body()
        )

    seen = "\n".join([host.text, origin.text, bad_type.text, caplog.text])
    assert PLANTED_BEARER not in seen
    assert "ti-recon:investigate" not in seen
    assert BROWSER_ORIGIN not in seen
    # The configured host appears in the request line of a *successful* probe's
    # own Host header, so this checks the rejections specifically.
    assert HOST not in host.text + origin.text + bad_type.text
    # And the messages stay the SDK's, unembellished with what was expected.
    assert host.text == "Invalid Host header"
    assert origin.text == "Invalid Origin header"
    assert bad_type.text == "Invalid Content-Type header"


@pytest.mark.asyncio
async def test_a_transport_rejection_consumes_no_investigation_slot() -> None:
    """The limiter sits after authentication, which sits after the gate."""
    async with gated_app(RefusingVerifier()) as app:
        await raw(app, "POST", MCP_PATH, headers=_headers(host=BAD_HOST), body=_body())
        await raw(app, "POST", MCP_PATH, headers=_headers(origin=BAD_ORIGIN), body=_body())
        await raw(app, "GET", HEALTH_PATH, headers={"authorization": f"Bearer {PLANTED_BEARER}"})

    # Nothing was tracked, because nothing got as far as an investigation.
    assert app.mcp_app is not None
