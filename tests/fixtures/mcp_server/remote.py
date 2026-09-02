"""A real authenticated remote MCP app, over the real engine (Task 22).

Everything below the transport is shipped code: the ASGI application the
deployment would run, the SDK's own bearer middleware, the Task 20 application,
the Task 19 workflow and all four reasoning engines. Only the providers and the
token verifier are fakes.

The verifier fake matters. It stands where a deployment's signed-JWT validator or
RFC 7662 introspection client goes, and it lives here rather than in ``src``
because a permissive verifier reachable from a production composition is the one
change that would turn this entire boundary into decoration.

Requests are driven over HTTP with ``httpx.ASGITransport`` rather than through
the in-memory ``Client(server)``, because the in-memory client bypasses the ASGI
stack — and therefore bypasses Host validation, Origin validation and the bearer
middleware, which are most of what these tests exist to check.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
from mcp.server.auth.provider import AccessToken
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from fixtures.investigation.stack import InvestigationStack, ScriptedProvider
from fixtures.mcp_server.auth import access_token, auth_config
from ti_recon.application.composition import CredentialLoadReport
from ti_recon.application.service import InvestigationApplication
from ti_recon.mcp_server.http import (
    MCP_PATH,
    RemoteHttpApp,
    RemoteHttpConfig,
    build_remote_http_app,
)
from ti_recon.mcp_server.limits import TenantInvestigationLimiter
from ti_recon.mcp_server.runtime import McpRuntime, RemotePrincipalSource
from ti_recon.providers.adapter import ProviderAdapter

#: A bearer planted so a match anywhere in an output cannot be a coincidence.
FAKE_BEARER = "SUPER_SECRET_REMOTE_MCP_TOKEN_123"

HOST = "mcp.example.invalid"
RESOURCE = f"https://{HOST}/mcp"
ISSUER = "https://idp.example.invalid/oauth2"
SCOPE = "ti-recon:investigate"
BROWSER_ORIGIN = "https://console.example.invalid"

MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-06-18"


@dataclass
class TokenDirectory:
    """A fake deployment verifier: bearer string in, verified token out.

    Records every string it was handed, which is how a test proves the strict
    wrapper never read one itself.
    """

    tokens: dict[str, AccessToken] = field(default_factory=dict)
    seen: list[str] = field(default_factory=list)

    async def verify_token(self, token: str) -> AccessToken | None:
        self.seen.append(token)
        return self.tokens.get(token)

    def add(self, bearer: str, **kwargs: Any) -> AccessToken:
        """Register one bearer as resolving to a token with these properties."""
        kwargs.setdefault("issuer", ISSUER)
        kwargs.setdefault("resource", RESOURCE)
        kwargs.setdefault("scopes", [SCOPE])
        kwargs.setdefault("token", bearer)
        issued = access_token(**kwargs)
        self.tokens[bearer] = issued
        return issued


def http_config(**overrides: Any) -> RemoteHttpConfig:
    """The transport configuration a deployment would supply."""
    settings: dict[str, Any] = {
        "resource_url": RESOURCE,
        "issuer_url": ISSUER,
        "allowed_hosts": (HOST,),
        "allowed_origins": (BROWSER_ORIGIN,),
    }
    settings.update(overrides)
    return RemoteHttpConfig(**settings)


@dataclass
class RemoteHarness:
    """One built app, plus what a test needs to interrogate it."""

    app: Any
    stack: InvestigationStack
    runtime: McpRuntime
    directory: TokenDirectory
    config: RemoteHttpConfig

    def client(self) -> httpx.AsyncClient:
        """An HTTP client speaking to the ASGI app, opening no socket."""
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=f"https://{HOST}"
        )

    @property
    def limiter(self) -> TenantInvestigationLimiter:
        assert self.runtime.investigations is not None
        return self.runtime.investigations


@asynccontextmanager
async def remote_harness(
    providers: list[ScriptedProvider],
    *,
    adapters: list[ProviderAdapter] | None = None,
    config: RemoteHttpConfig | None = None,
) -> AsyncIterator[RemoteHarness]:
    """The shipped remote app over scripted providers, with its lifespan running.

    The runtime is assembled directly rather than through ``build_remote_runtime``
    so the providers can be fakes; the credential stores, the executor and the
    limiter are the real ones, and credentials are never loaded from the
    environment here either.

    The lifespan wraps the whole harness rather than each client, because
    Streamable HTTP's session manager refuses to ``run()`` twice on one instance
    — one app, one lifespan, however many requests.
    """
    stack = InvestigationStack(providers=providers)
    settings = http_config() if config is None else config
    auth = auth_config(issuer=settings.issuer_url, resource=settings.resource_url)
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        adapters=tuple(adapters if adapters is not None else providers),
        investigations=TenantInvestigationLimiter(
            max_concurrent=settings.max_investigations_per_tenant
        ),
    )
    directory = TokenDirectory()
    app = build_remote_http_app(runtime, config=settings, auth=auth, delegate=directory)
    harness = RemoteHarness(
        app=app, stack=stack, runtime=runtime, directory=directory, config=settings
    )
    async with _lifespan(app):
        yield harness


@asynccontextmanager
async def _lifespan(app: Any) -> AsyncIterator[None]:
    """Drive the ASGI lifespan protocol around a block.

    Sixteen lines rather than a dependency. The startup message is what enters
    ``StreamableHTTPSessionManager.run()``, which owns the task group every
    request needs.
    """
    receive: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    sent: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def send(message: dict[str, Any]) -> None:
        await sent.put(message)

    task = asyncio.ensure_future(app({"type": "lifespan"}, receive.get, send))
    await receive.put({"type": "lifespan.startup"})
    started = await sent.get()
    assert started["type"] == "lifespan.startup.complete", started
    try:
        yield
    finally:
        await receive.put({"type": "lifespan.shutdown"})
        await sent.get()
        await task


# --------------------------------------------------------------------------- #
# Speaking MCP over HTTP by hand
# --------------------------------------------------------------------------- #


def modern_request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """One self-contained 2026-07-28 request body.

    No ``initialize``, no session id: the envelope carries the protocol version
    and the client capabilities in ``params._meta``, which the server validates
    against the headers before dispatching.
    """
    body_params: dict[str, Any] = dict(params or {})
    body_params["_meta"] = {
        PROTOCOL_VERSION_META_KEY: MODERN_VERSION,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "ti-recon-tests", "version": "0"},
    }
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": body_params}


def modern_headers(
    method: str, *, bearer: str | None = FAKE_BEARER, name: str | None = None
) -> dict[str, str]:
    """The headers a 2026-07-28 request must carry.

    ``Mcp-Method`` and ``Mcp-Name`` are validated against the body, so a gateway
    metering on them cannot be lied to — and a test that sets them wrongly is
    told so rather than quietly served.
    """
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": MODERN_VERSION,
        "mcp-method": method,
    }
    if name is not None:
        headers["mcp-name"] = name
    if bearer is not None:
        headers["authorization"] = f"Bearer {bearer}"
    return headers


async def call_modern(
    harness: RemoteHarness,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    bearer: str | None = FAKE_BEARER,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST one modern MCP request to the real ASGI app."""
    name = None
    if method == "tools/call":
        name = (params or {}).get("name")
    elif method == "resources/read":
        name = (params or {}).get("uri")
    request_headers = modern_headers(method, bearer=bearer, name=name)
    if headers:
        request_headers.update(headers)
    async with harness.client() as client:
        return await client.post(
            MCP_PATH, content=json.dumps(modern_request(method, params)), headers=request_headers
        )


def result_of(response: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC result, insisting the call actually succeeded."""
    body = response.json()
    assert "error" not in body, body
    result: dict[str, Any] = body["result"]
    return result


async def call_tool(
    harness: RemoteHarness,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    bearer: str | None = FAKE_BEARER,
) -> httpx.Response:
    return await call_modern(
        harness,
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        bearer=bearer,
    )


async def initialize_legacy(
    harness: RemoteHarness, *, bearer: str | None = FAKE_BEARER
) -> httpx.Response:
    """A handshake-era ``initialize``, to prove the older wire is also protected."""
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": LEGACY_VERSION,
    }
    if bearer is not None:
        headers["authorization"] = f"Bearer {bearer}"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ti-recon-tests", "version": "0"},
        },
    }
    async with harness.client() as client:
        return await client.post(MCP_PATH, content=json.dumps(body), headers=headers)


@dataclass
class CountingVerifier:
    """Records only *how many times* it was asked, never what it was handed.

    A counter rather than a log of bearer strings, because a fixture that
    accumulated tokens would be the one place in the test suite holding them.
    """

    calls: int = 0
    result: AccessToken | None = None

    async def verify_token(self, token: str) -> AccessToken | None:
        del token
        self.calls += 1
        return self.result


@dataclass
class RefusingVerifier:
    """Fails loudly if it is ever reached.

    Stronger than a counter for the rejection cases: a counter proves a number,
    this proves the code path. If ordering regresses, the test fails inside the
    verifier with the reason written on it rather than on an assertion three
    frames away.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        del token
        msg = "verifier must not be called"
        raise AssertionError(msg)


@asynccontextmanager
async def gated_app(
    delegate: Any, *, config: RemoteHttpConfig | None = None
) -> AsyncIterator[RemoteHttpApp]:
    """The real remote app over a chosen verifier, with its lifespan running.

    No engine underneath: these tests are about what happens *before* a request
    could reach one, so a runtime that would explode if entered is the honest
    stand-in — and proves nothing below the gate ran.
    """
    settings = http_config() if config is None else config
    auth = auth_config(issuer=settings.issuer_url, resource=settings.resource_url)
    stack = InvestigationStack(providers=[])
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(auth),
        adapters=(),
        investigations=TenantInvestigationLimiter(),
    )
    app = build_remote_http_app(runtime, config=settings, auth=auth, delegate=delegate)
    async with _lifespan(app):
        yield app


async def raw(
    app: RemoteHttpApp,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> httpx.Response:
    """One HTTP request against the gate, with the headers exactly as given."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"https://{HOST}"
    ) as client:
        return await client.request(method, path, headers=headers, content=body)


def remote_token(**overrides: Any) -> AccessToken:
    """A verified token for *this* deployment's issuer, resource and scope.

    One helper, so a test cannot accidentally build a token for the auth
    fixture's resource while driving an app configured for a different one — a
    mismatch the strict verifier is right to refuse and which reads as an
    unrelated failure.
    """
    overrides.setdefault("issuer", ISSUER)
    overrides.setdefault("resource", RESOURCE)
    overrides.setdefault("scopes", [SCOPE])
    overrides.setdefault("subject", "alice")
    return access_token(**overrides)
