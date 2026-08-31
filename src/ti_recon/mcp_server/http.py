"""The authenticated remote MCP application (Task 22).

An ASGI app: OAuth-protected Streamable HTTP over the same Task 20 stack the
local server uses, with the identity substrate deciding who each request belongs
to.

```
HTTPS ingress -> ASGI app -> Host/Origin check -> bearer auth
              -> RemotePrincipal -> request-scoped ExecutionContext
              -> Task 20 -> 19 -> 13 -> 6 -> providers
```

A factory, not a process
------------------------

This module builds an application and stops. It deliberately ships **no console
entry point**, because a runnable server needs a real token verifier and
choosing one means choosing an identity platform — and the only verifiers that
could be constructed without one are the three that must never exist: a
static-token verifier, an unsigned-JWT verifier, and a "development" verifier
reachable from production. A deployment injects its own delegate; the next phase
picks one for this repository's own deployment.

Configuration is never inferred
-------------------------------

Not from ``Host``, not from ``X-Forwarded-Host``, ``X-Forwarded-Proto`` or
``Forwarded``, not from ``Origin``, and not from the socket the app happens to be
bound to. The canonical public resource URL, the issuer, the required scope and
the host allowlist are all configured values, so no proxy header can move a
security decision and the app needs to trust none of them. TLS terminates at the
ingress; the internal bind may be plain HTTP, and the public scheme is stated
rather than sniffed.

One process
-----------

Task 6's cache, cooldown, quota and single-flight stores are process-local, and
so is the per-tenant investigation limiter. A second worker would enforce every
one of them a second time independently — four workers would let four analysts'
identical questions become four provider calls and would let one analyst hold
four investigation slots. **Remote deployment is single-worker until Task 24**
gives that state a shared backend. This is a correctness requirement, not a
performance note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlparse

from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from ti_recon.mcp_server.auth import RemoteAuthConfig, StrictTokenVerifier
from ti_recon.mcp_server.runtime import McpRuntime
from ti_recon.mcp_server.server import build_remote_server

__all__ = [
    "HEALTH_PATH",
    "MCP_PATH",
    "REMOTE_SCOPE",
    "REMOTE_SCOPES",
    "RemoteHttpApp",
    "RemoteHttpConfig",
    "build_remote_http_app",
]

#: The one scope a remote caller needs.
#:
#: One scope for the whole resource, on purpose. ``provider_status`` is *less*
#: privileged than an investigation and reveals only the caller's own
#: configuration; splitting them would buy no meaningful least privilege — nobody
#: wants a token that can list their own setup but not use it — while costing a
#: step-up flow and a second consent screen. The vocabulary is versioned here so
#: a later privilege boundary (a write surface, say) can be added beside it
#: rather than by redefining this one.
REMOTE_SCOPE: Final[str] = "ti-recon:investigate"

#: Every scope this resource currently advertises.
REMOTE_SCOPES: Final[tuple[str, ...]] = (REMOTE_SCOPE,)

#: The MCP endpoint path. The canonical resource URL must end with it.
MCP_PATH: Final[str] = "/mcp"

#: Deployment liveness. Public, and says one thing.
HEALTH_PATH: Final[str] = "/health"

#: What the SDK allows a request body to be, recorded rather than chosen.
#:
#: TI Recon's tool requests are a few hundred bytes, so a tighter limit would be
#: an unresearched number invented for appearance. Task 24 tunes the application
#: and the ingress together, where the two can be made to agree.
MAX_REQUEST_BODY_SIZE: Final[int] = DEFAULT_MAX_REQUEST_BODY_SIZE


@dataclass(frozen=True)
class RemoteHttpConfig:
    """What a remote deployment must state before it can serve anybody.

    Small on purpose, and composed rather than merged: the tenant derivation key
    and the expected token issuer/resource already live on
    :class:`~ti_recon.mcp_server.auth.RemoteAuthConfig`, and a second copy would
    be a second thing to keep in step. This carries only what the *transport*
    needs.

    Holds no provider credential, no bearer token and no vendor field.
    """

    #: The exact canonical public MCP resource URL, e.g.
    #: ``https://mcp.example.com/mcp``.
    #:
    #: One value drives the token audience check, ``AuthSettings``, the RFC 9728
    #: metadata and the documentation. Constructing it separately in several
    #: places is how two of them end up disagreeing by a trailing slash, which
    #: OAuth treats as a different resource entirely.
    resource_url: str
    #: The authorization server that issues tokens for this resource.
    issuer_url: str
    #: Exact ``Host`` values this deployment answers to.
    #:
    #: Narrow by default. ``*`` is refused, and a ``host:*`` port wildcard is
    #: accepted only where a deployment genuinely needs arbitrary ports — the
    #: normal case is the one authority the canonical URL already names.
    allowed_hosts: tuple[str, ...]
    #: Browser origins permitted to call this endpoint. Empty by default.
    #:
    #: Claude Code and other non-browser clients send no ``Origin`` at all, which
    #: the transport permits. A *present* origin is checked against this list, so
    #: an empty list means "no browser may call us" rather than "anyone may".
    allowed_origins: tuple[str, ...] = ()
    #: How many investigations one tenant may have running at once.
    max_investigations_per_tenant: int = 1
    #: Scopes required for the whole resource.
    required_scopes: tuple[str, ...] = REMOTE_SCOPES
    #: Set only by tests and local experiments, to permit an ``http://`` resource.
    allow_insecure_resource: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        _require(self.resource_url, "resource_url must be a non-empty string")
        _require(self.issuer_url, "issuer_url must be a non-empty string")
        _require(self.allowed_hosts, "allowed_hosts must not be empty")
        _require(self.required_scopes, "required_scopes must not be empty")
        if self.max_investigations_per_tenant < 1:
            msg = "max_investigations_per_tenant must be at least 1"
            raise ValueError(msg)

        parsed = urlparse(self.resource_url)
        if parsed.scheme != "https" and not self.allow_insecure_resource:
            # OAuth protected-resource metadata and every redirect in the flow
            # are HTTPS-only. An http:// resource identifier would also make the
            # token audience a value an attacker on the path could impersonate.
            msg = "resource_url must use https"
            raise ValueError(msg)
        if parsed.path != MCP_PATH:
            # The canonical contract. `/mcp` and `/mcp/` are different OAuth
            # resources, so this is an equality check rather than a normalization.
            msg = f"resource_url path must be exactly {MCP_PATH!r}"
            raise ValueError(msg)
        if not parsed.netloc:
            msg = "resource_url must name a host"
            raise ValueError(msg)

        for host in self.allowed_hosts:
            _require(host, "allowed_hosts entries must be non-empty")
            if host == "*" or host.startswith("*"):
                # A wildcard host disables DNS-rebinding protection while
                # appearing to configure it, which is worse than not configuring
                # it at all.
                msg = "allowed_hosts must not contain a wildcard"
                raise ValueError(msg)
        for origin in self.allowed_origins:
            _require(origin, "allowed_origins entries must be non-empty")
            if origin == "*" or origin.startswith("*"):
                msg = "allowed_origins must not contain a wildcard"
                raise ValueError(msg)

    @property
    def resource_metadata_url(self) -> str:
        """Where RFC 9728 metadata for this resource is published."""
        return str(build_resource_metadata_url(AnyHttpUrl(self.resource_url)))

    def transport_security(self) -> TransportSecuritySettings:
        """Explicit Host and Origin policy. Never implied by the bind address.

        The SDK auto-enables DNS-rebinding protection *only* for a loopback
        host, and otherwise falls back to protection disabled for backwards
        compatibility — so a production hostname with no settings is silently
        unprotected. Passing this is what closes that.
        """
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(self.allowed_hosts),
            allowed_origins=list(self.allowed_origins),
        )

    def auth_settings(self) -> AuthSettings:
        """Resource-server settings only.

        ``auth_server_provider`` is deliberately never supplied, which is what
        keeps ``/authorize``, ``/token``, ``/register`` and ``/revoke`` off this
        app: TI Recon verifies tokens an external authorization server issued and
        never becomes one.
        """
        return AuthSettings(
            issuer_url=AnyHttpUrl(self.issuer_url),
            resource_server_url=AnyHttpUrl(self.resource_url),
            required_scopes=list(self.required_scopes),
        )


def build_remote_http_app(
    runtime: McpRuntime,
    *,
    config: RemoteHttpConfig,
    auth: RemoteAuthConfig,
    delegate: TokenVerifier,
) -> RemoteHttpApp:
    """The authenticated remote MCP application.

    ``delegate`` is the deployment's own verifier — a signed-JWT validator, an
    RFC 7662 introspection client, whatever its identity platform supports. It is
    required and has no default: the only defaults available would be permissive
    ones.

    The audience the tokens must name is checked against ``auth.resource``, and
    the resource this app publishes is ``config.resource_url``. They must be the
    same string, and this refuses to build if they are not — two values that
    drifted apart would advertise one resource and accept tokens for another.

    Returns the preflight gate wrapping the SDK's application, not the SDK's
    application itself. See :class:`RemoteHttpApp` for why the order has to be
    arranged from outside.
    """
    if auth.resource != config.resource_url:
        msg = "the verifier's expected resource must equal the published resource URL"
        raise ValueError(msg)
    if auth.issuer != config.issuer_url:
        msg = "the verifier's expected issuer must equal the published issuer URL"
        raise ValueError(msg)

    server = build_remote_server(
        runtime,
        auth=config.auth_settings(),
        token_verifier=StrictTokenVerifier(delegate=delegate, config=auth),
    )
    mcp_app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        # Every 2026-07-28 request is self-contained already; this additionally
        # stops a handshake-era client creating a server-side transport session.
        # TI Recon needs no sampling, elicitation, resource subscription or
        # resumable SSE, so there is nothing a session would carry — and a
        # session would be process-local state a future second worker could not
        # see.
        stateless_http=True,
        # Request in, response out. Nothing here streams progress.
        json_response=True,
        max_request_body_size=MAX_REQUEST_BODY_SIZE,
        # Kept, and deliberately not weakened because the gate now checks the
        # same things first. Defence in depth: a mistake in the outer wrapper
        # must not silently disable the SDK's own protection.
        transport_security=config.transport_security(),
    )
    return RemoteHttpApp(mcp_app=mcp_app, config=config)


class RemoteHttpApp:
    """The outermost ASGI application: a preflight gate over the MCP app.

    Why a gate at all
    -----------------

    The SDK composes its Starlette application with
    ``AuthenticationMiddleware(BearerAuthBackend)`` at the *application* level,
    so it wraps the whole routing table — while ``TransportSecurityMiddleware``
    runs *inside* the Streamable HTTP transport handler, which is reached only
    after routing and after ``RequireAuthMiddleware``. Two consequences follow,
    and both were measured rather than assumed:

    * a request with an untrusted ``Host``, an untrusted ``Origin`` or a wrong
      POST content type still had its bearer verified first — so a rebinding
      probe or a content-type typo could drive a verifier that, for an
      introspection-based deployment, makes a network call to the identity
      provider;
    * ``GET /health`` had its bearer verified too, because an app-level
      middleware cannot know that one route was meant to be public.

    Neither is a disclosure — the eventual answers were still ``421``/``403`` and
    a fixed health document — but both let unauthenticated traffic reach the most
    expensive thing in the request path. So the cheap checks are hoisted in front
    of the whole SDK application, where they belong:

    ``Host -> Origin -> content type -> public route -> OAuth -> scope -> tool``.

    What it does not do
    -------------------

    It parses no ``Authorization`` header, reads no bearer, understands no scope,
    builds no ``WWW-Authenticate`` and generates no metadata. OAuth stays entirely
    inside the SDK. This layer decides only whether a request is *eligible* to
    reach the authenticated application.

    It also invents no Host or Origin rules: validation is delegated to the SDK's
    own :class:`~mcp.server.transport_security.TransportSecurityMiddleware`,
    built from the same :class:`RemoteHttpConfig` the inner transport gets. One
    configuration, two enforcement points — never two policies.
    """

    def __init__(self, *, mcp_app: Starlette, config: RemoteHttpConfig) -> None:
        self.mcp_app = mcp_app
        self.config = config
        #: The SDK's own validator, over the same settings the transport holds.
        self._security = TransportSecurityMiddleware(config.transport_security())
        self._metadata_path = urlparse(config.resource_metadata_url).path

    #: Paths this gate answers itself, without entering the SDK application.
    @property
    def public_paths(self) -> tuple[str, ...]:
        return (HEALTH_PATH,)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # Lifespan passes straight through, unexamined. The SDK application
            # owns the Streamable HTTP session manager's lifecycle, and it must
            # start exactly once for the process — not once per request, and not
            # once per wrapper.
            await self.mcp_app(scope, receive, send)
            return

        rejection = await self._preflight(scope, receive)
        if rejection is not None:
            await rejection(scope, receive, send)
            return

        if scope["path"] == HEALTH_PATH:
            await _health(scope, receive, send)
            return

        await self.mcp_app(_without_authorization(scope, self._metadata_path), receive, send)

    async def _preflight(self, scope: Scope, receive: Receive) -> Response | None:
        """The SDK's own Host/Origin/content-type check, run first.

        The content-type rule applies only to a POST at the MCP path, which is
        the one place the SDK itself applies it. ``GET /health`` and the metadata
        endpoint carry no JSON requirement, and inventing one for them would be a
        rule this repository made up.

        The request body is never read here — only headers — so ``receive`` is
        handed onwards untouched and the MCP transport still sees a complete
        request.
        """
        request = Request(scope, receive)
        is_post = scope["method"] == "POST" and scope["path"] == MCP_PATH
        return await self._security.validate_request(request, is_post=is_post)


async def _health(scope: Scope, receive: Receive, send: Send) -> None:
    """Deployment liveness, answered before the SDK application is entered.

    Served by the gate rather than as an SDK custom route, which is the whole
    point: a custom route still sits behind the app-level authentication
    middleware, so a caller sending ``Authorization: Bearer garbage`` to a
    *public* endpoint drove a token verification. Here nothing about
    authentication is reachable — no middleware, no verifier, no principal
    resolver, no credential store, no executor.

    It says nothing about the deployment. No version, no issuer, no resource URL,
    no provider counts, no configured tenants, no uptime, no cache state — each of
    those is a small gift to somebody deciding whether this host is worth
    attacking, and none of them helps a load balancer.

    Deliberately not called *readiness*: Task 18 owns that word for whether the
    intelligence collected was adequate, and one term meaning two things in one
    system is how somebody eventually acts on the wrong one. A deployment
    readiness probe waits for Task 24, where there is a credential backend whose
    reachability would be worth reporting.
    """
    if scope["method"] not in ("GET", "HEAD"):
        await Response(status_code=405, headers={"allow": "GET, HEAD"})(scope, receive, send)
        return
    await JSONResponse({"status": "ok"})(scope, receive, send)


def _without_authorization(scope: Scope, metadata_path: str) -> Scope:
    """Drop the ``Authorization`` header on the public metadata path only.

    RFC 9728 protected-resource metadata is unconditionally public — a client
    reads it precisely *because* it was refused, and no token it holds is
    meaningful there. But the SDK's authentication middleware is app-level, so a
    bearer sent to that route was verified anyway.

    Removing the header is enough to make the SDK skip verification, and it
    changes nothing else: the route is unauthenticated either way and returns the
    same SDK-generated document. Nothing is copied, rebuilt or re-routed — the
    metadata stays the SDK's.

    The path comparison is exact, and it fails in the safe direction: matching
    too broadly would strip a bearer from a *protected* path, which turns into a
    401 rather than into access.
    """
    if scope["path"] != metadata_path:
        return scope
    headers = [(key, value) for key, value in scope["headers"] if key.lower() != b"authorization"]
    return {**scope, "headers": headers}


def _require(value: object, message: str) -> None:
    """Fail closed at construction. There are no permissive production defaults."""
    if not value:
        raise ValueError(message)
