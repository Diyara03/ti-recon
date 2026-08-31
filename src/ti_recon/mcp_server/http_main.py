"""The ``ti-recon-mcp-http`` process (Task 22).

The authenticated remote server, configured from the environment and run as one
ASGI worker. It exists now, and not earlier, because a remote server is only
worth running once a real token verifier can be constructed — and until
:mod:`ti_recon.mcp_server.jwt_auth` there was nothing to construct but a
permissive one.

It is a server, not a command. No login page, no token endpoint, no credential
provisioning, no migrations, no scheduler. It loads configuration, builds the
application, and serves it.

Separate from ``ti-recon-mcp``, which stays local stdio for one analyst.
Overloading one entry point would mean one process with two authentication
models and two tool surfaces.

One worker, deliberately
------------------------

Task 6's cache, cooldown, quota and single-flight stores are process-local, and
so is the per-tenant investigation limiter. A second worker enforces every one of
them a second time independently: four analysts' identical questions become four
calls against a metered API, and one analyst holds four investigation slots. So
there is no ``--workers`` flag and no worker environment variable — the count is
not configurable, and a test asserts it. Multi-worker remote TI Recon is
unsupported until Task 24 gives that state a shared backend.

Configuration is the environment
--------------------------------

Six required variables, all ``TI_RECON``-prefixed. Nothing generic is read: no
bare ``API_KEY``, ``TOKEN`` or ``SECRET``, so a variable meant for something else
can never be picked up as ours. No provider credential is read at all — a
server's environment is global to the server, and every authenticated analyst
would otherwise share one set of keys.

Startup fails before the socket opens if anything is missing or unsafe. A remote
server that started in a degraded, unauthenticated mode would be worse than one
that did not start.

Startup contacts nothing
------------------------

Not even the identity provider. Keys are fetched on the first authenticated
request and cached; until then authentication fails closed. That keeps
``/health`` answering during a brief IdP outage, which is the point of a liveness
probe — deployment liveness is not identity-provider reachability.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from pydantic import SecretStr

from ti_recon import __version__
from ti_recon.mcp_server.auth import RemoteAuthConfig
from ti_recon.mcp_server.http import RemoteHttpApp, RemoteHttpConfig, build_remote_http_app
from ti_recon.mcp_server.jwt_auth import (
    DEFAULT_ALGORITHMS,
    JwtJwksTokenVerifier,
    JwtVerifierConfig,
    TokenProfile,
)
from ti_recon.mcp_server.runtime import build_remote_runtime

__all__ = [
    "ENVIRONMENT",
    "RemoteDeployment",
    "build_remote_application",
    "load_deployment",
    "main",
]

#: Every variable this process reads, and what it means.
#:
#: Documented as data so the failure message can name what was missing without a
#: second list going stale beside it.
ENVIRONMENT: Final[Mapping[str, str]] = {
    "TI_RECON_MCP_RESOURCE_URL": "canonical public MCP resource, e.g. https://mcp.example.com/mcp",
    "TI_RECON_AUTH_ISSUER_URL": "authorization server issuer, exactly as it appears in `iss`",
    "TI_RECON_AUTH_JWKS_URL": "where that server publishes its public signing keys",
    "TI_RECON_TENANT_DERIVATION_KEY": "deployment secret for pseudonymous tenant identity",
    "TI_RECON_MCP_ALLOWED_HOSTS": "comma-separated exact Host values this server answers to",
}

#: Optional, with defaults that suit a container.
_ALLOWED_ORIGINS = "TI_RECON_MCP_ALLOWED_ORIGINS"
_ALGORITHMS = "TI_RECON_AUTH_ALGORITHMS"
_TOKEN_PROFILE = "TI_RECON_AUTH_TOKEN_PROFILE"
_BIND_HOST = "TI_RECON_MCP_BIND_HOST"
_BIND_PORT = "TI_RECON_MCP_BIND_PORT"
_LEVEL = "TI_RECON_LOG_LEVEL"

#: Loopback by default. A container publishes a port; a developer running this by
#: hand should not be exposed to their network because a default said so.
_DEFAULT_BIND_HOST: Final[str] = "127.0.0.1"
_DEFAULT_BIND_PORT: Final[int] = 8000

#: HMAC-SHA-256's block-size-equivalent security floor. A short deployment secret
#: is a guessable one, and every tenant identifier in the deployment depends on it.
MINIMUM_TENANT_KEY_LENGTH: Final[int] = 32


@dataclass(frozen=True)
class RemoteDeployment:
    """One environment's worth of configuration, already validated.

    Composed rather than merged: each piece is the configuration its own layer
    already defines, and the resource URL appears once — in
    :attr:`http.resource_url` — with the other two derived from it, so the three
    values that must agree cannot be typed separately.
    """

    http: RemoteHttpConfig
    auth: RemoteAuthConfig
    verifier: JwtVerifierConfig
    bind_host: str = _DEFAULT_BIND_HOST
    bind_port: int = _DEFAULT_BIND_PORT

    def __repr__(self) -> str:
        """Never render the tenant key, which ``auth`` holds."""
        return (
            f"RemoteDeployment(resource={self.http.resource_url!r}, "
            f"issuer={self.http.issuer_url!r}, bind={self.bind_host}:{self.bind_port})"
        )


def load_deployment(environment: Mapping[str, str] | None = None) -> RemoteDeployment:
    """Read and validate the deployment's configuration, or refuse to start.

    Every failure here happens before a socket is opened. A missing tenant key,
    an ``http://`` resource, a wildcard host, an unsupported algorithm — each is a
    configuration mistake somebody can fix, and none of them is something to
    start up and discover at the first request.
    """
    source = os.environ if environment is None else environment
    missing = sorted(name for name in ENVIRONMENT if not source.get(name, "").strip())
    if missing:
        msg = f"missing required configuration: {', '.join(missing)}"
        raise ValueError(msg)

    resource_url = source["TI_RECON_MCP_RESOURCE_URL"].strip()
    issuer_url = source["TI_RECON_AUTH_ISSUER_URL"].strip()
    jwks_url = source["TI_RECON_AUTH_JWKS_URL"].strip()
    tenant_key = source["TI_RECON_TENANT_DERIVATION_KEY"]

    if len(tenant_key) < MINIMUM_TENANT_KEY_LENGTH:
        # Never generated here. A random key per start would give every analyst a
        # new identity on every restart and orphan whatever Task 23 stored under
        # the old one.
        msg = (
            f"TI_RECON_TENANT_DERIVATION_KEY must be at least "
            f"{MINIMUM_TENANT_KEY_LENGTH} characters"
        )
        raise ValueError(msg)

    http = RemoteHttpConfig(
        resource_url=resource_url,
        issuer_url=issuer_url,
        allowed_hosts=_values(source["TI_RECON_MCP_ALLOWED_HOSTS"]),
        allowed_origins=_values(source.get(_ALLOWED_ORIGINS, "")),
    )
    auth = RemoteAuthConfig(
        issuer=issuer_url, resource=resource_url, tenant_key=SecretStr(tenant_key)
    )
    verifier = JwtVerifierConfig(
        issuer=issuer_url,
        jwks_url=jwks_url,
        resource=resource_url,
        algorithms=_algorithms(source.get(_ALGORITHMS, "")),
        profile=_profile(source.get(_TOKEN_PROFILE, "")),
    )
    return RemoteDeployment(
        http=http,
        auth=auth,
        verifier=verifier,
        bind_host=source.get(_BIND_HOST, "").strip() or _DEFAULT_BIND_HOST,
        bind_port=_port(source.get(_BIND_PORT, "")),
    )


async def build_remote_application(deployment: RemoteDeployment) -> RemoteHttpApp:
    """Compose the application. Contacts nothing.

    Every shipped provider is registered and **no provider credential is read
    from the environment** — that is `load_credentials=False`, and it is the
    difference between a multi-tenant server and one where everybody shares the
    operator's keys.
    """
    runtime = await build_remote_runtime(
        auth=deployment.auth,
        max_investigations_per_tenant=deployment.http.max_investigations_per_tenant,
    )
    return build_remote_http_app(
        runtime,
        config=deployment.http,
        auth=deployment.auth,
        delegate=JwtJwksTokenVerifier(deployment.verifier),
    )


def main(argv: list[str] | None = None) -> int:
    """Serve the authenticated remote MCP application, on one worker."""
    parser = _parser()
    parser.parse_args(argv)
    _configure_logging()

    import asyncio

    import uvicorn

    try:
        deployment = load_deployment()
    except ValueError as error:
        # Reported through the logger rather than printed: stdout belongs to the
        # protocol elsewhere in this package, and one rule about it is easier to
        # keep than two. The message names variables, never values.
        logging.getLogger("ti_recon.mcp_server").error("configuration error: %s", error)
        return 2

    application = asyncio.run(build_remote_application(deployment))
    logging.getLogger("ti_recon.mcp_server").info(
        "serving MCP on %s:%s for %s",
        deployment.bind_host,
        deployment.bind_port,
        deployment.http.resource_url,
    )
    uvicorn.run(
        application,
        host=deployment.bind_host,
        port=deployment.bind_port,
        # Deliberately absent: `workers`. Not a default to override — the option
        # is not offered, because process-local execution state makes a second
        # worker a correctness problem rather than a scaling choice.
        log_level=os.environ.get(_LEVEL, "info").lower(),
        access_log=False,
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    """Two flags, neither of which starts anything.

    Configuration is the environment for a deployed process, so there is nothing
    for flags to do except identify the program — and ``--help`` and ``--version``
    must not read credentials, build an application or reach an identity
    provider.
    """
    parser = argparse.ArgumentParser(
        prog="ti-recon-mcp-http",
        description=(
            "Serve the authenticated remote TI Recon MCP application. "
            "Configured entirely from the environment; runs exactly one worker."
        ),
        epilog="Required: " + ", ".join(sorted(ENVIRONMENT)),
    )
    parser.add_argument("--version", action="version", version=f"ti-recon {__version__}")
    return parser


def _configure_logging() -> None:
    """Container-friendly, and never a decoded token.

    stderr rather than stdout, at a level the deployment chooses. Nothing here
    logs a JWT, a claim, a subject, a tenant id or a provider credential.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    for name in ("ti_recon", "mcp"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(os.environ.get(_LEVEL, "INFO").upper())


def _values(raw: str) -> tuple[str, ...]:
    """A comma-separated list, parsed strictly.

    Explicit values only. A wildcard is refused rather than expanded, because a
    host allowlist containing ``*`` disables DNS-rebinding protection while
    looking configured — and ``RemoteHttpConfig`` refuses one anyway; this just
    fails with a clearer message.
    """
    items = tuple(item.strip() for item in raw.split(",") if item.strip())
    for item in items:
        if "*" in item:
            msg = f"wildcards are not permitted in host or origin configuration: {item!r}"
            raise ValueError(msg)
    return items


def _algorithms(raw: str) -> tuple[str, ...]:
    """The signing algorithms this deployment accepts, or the default."""
    values = tuple(item.strip().upper() for item in raw.split(",") if item.strip())
    return values or DEFAULT_ALGORITHMS


def _profile(raw: str) -> TokenProfile:
    value = raw.strip().lower()
    if not value:
        return TokenProfile.GENERIC_JWT
    try:
        return TokenProfile(value)
    except ValueError as error:
        options = ", ".join(sorted(item.value for item in TokenProfile))
        msg = f"{_TOKEN_PROFILE} must be one of: {options}"
        raise ValueError(msg) from error


def _port(raw: str) -> int:
    value = raw.strip()
    if not value:
        return _DEFAULT_BIND_PORT
    try:
        port = int(value)
    except ValueError as error:
        msg = f"{_BIND_PORT} must be an integer"
        raise ValueError(msg) from error
    if not 1 <= port <= 65535:
        msg = f"{_BIND_PORT} must be between 1 and 65535"
        raise ValueError(msg)
    return port


if __name__ == "__main__":  # pragma: no cover - module execution
    raise SystemExit(main())
