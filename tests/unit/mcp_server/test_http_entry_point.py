"""Configuring and starting the remote process (Task 22).

Startup is where a remote deployment is either safe or quietly not. Everything
here happens before a socket opens: a missing tenant key, an ``http://``
resource, a wildcard host, a symmetric algorithm — each refuses to start rather
than starting in a degraded mode somebody discovers later.

Nothing here runs a server. ``uvicorn.run`` blocks forever by design, so the
tests drive :func:`load_deployment` and :func:`build_remote_application`, which
is everything ``main`` does before it hands over.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ti_recon import __version__
from ti_recon.mcp_server.http import RemoteHttpApp
from ti_recon.mcp_server.http_main import (
    ENVIRONMENT,
    MINIMUM_TENANT_KEY_LENGTH,
    RemoteDeployment,
    build_remote_application,
    load_deployment,
    main,
)
from ti_recon.mcp_server.jwt_auth import TokenProfile

RESOURCE = "https://mcp.example.com/mcp"
ISSUER = "https://idp.example.com/"
JWKS = "https://idp.example.com/.well-known/jwks.json"
TENANT_KEY = "x" * MINIMUM_TENANT_KEY_LENGTH

MODULE = Path("src/ti_recon/mcp_server/http_main.py")


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "TI_RECON_MCP_RESOURCE_URL": RESOURCE,
        "TI_RECON_AUTH_ISSUER_URL": ISSUER,
        "TI_RECON_AUTH_JWKS_URL": JWKS,
        "TI_RECON_TENANT_DERIVATION_KEY": TENANT_KEY,
        "TI_RECON_MCP_ALLOWED_HOSTS": "mcp.example.com",
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value != ""}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_a_complete_environment_produces_one_consistent_deployment() -> None:
    """The resource is stated once and reaches all three configurations.

    Typed separately, three copies of one URL are three chances for two to
    disagree — and a server advertising one resource while accepting tokens for
    another is the confused-deputy shape.
    """
    deployment = load_deployment(_environment())

    assert deployment.http.resource_url == RESOURCE
    assert deployment.auth.resource == RESOURCE
    assert deployment.verifier.resource == RESOURCE
    assert deployment.http.issuer_url == deployment.auth.issuer == deployment.verifier.issuer
    assert deployment.verifier.jwks_url == JWKS
    assert deployment.verifier.algorithms == ("RS256",)
    assert deployment.verifier.profile is TokenProfile.GENERIC_JWT
    assert deployment.http.allowed_hosts == ("mcp.example.com",)
    assert deployment.http.allowed_origins == ()
    assert deployment.bind_host == "127.0.0.1"
    assert deployment.bind_port == 8000


@pytest.mark.parametrize("variable", sorted(ENVIRONMENT))
def test_every_required_variable_is_required(variable: str) -> None:
    """Named in the failure, so an operator is told which one."""
    with pytest.raises(ValueError, match=variable):
        load_deployment(_environment(**{variable: ""}))


def test_a_short_tenant_derivation_key_refuses_to_start() -> None:
    """And it is never generated here.

    A random key per start would give every analyst a new identity on every
    restart, orphaning whatever Task 23 stored under the old one.
    """
    with pytest.raises(ValueError, match="TI_RECON_TENANT_DERIVATION_KEY"):
        load_deployment(_environment(TI_RECON_TENANT_DERIVATION_KEY="too-short"))

    assert load_deployment(_environment()) is not None


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("insecure resource", {"TI_RECON_MCP_RESOURCE_URL": "http://mcp.example.com/mcp"}),
        ("wrong resource path", {"TI_RECON_MCP_RESOURCE_URL": "https://mcp.example.com/"}),
        ("trailing slash", {"TI_RECON_MCP_RESOURCE_URL": "https://mcp.example.com/mcp/"}),
        ("insecure jwks", {"TI_RECON_AUTH_JWKS_URL": "http://idp.example.com/jwks"}),
        ("wildcard host", {"TI_RECON_MCP_ALLOWED_HOSTS": "*"}),
        ("wildcard subdomain", {"TI_RECON_MCP_ALLOWED_HOSTS": "*.example.com"}),
        ("wildcard origin", {"TI_RECON_MCP_ALLOWED_ORIGINS": "*"}),
        ("symmetric algorithm", {"TI_RECON_AUTH_ALGORITHMS": "HS256"}),
        ("unsigned algorithm", {"TI_RECON_AUTH_ALGORITHMS": "none"}),
        ("unknown profile", {"TI_RECON_AUTH_TOKEN_PROFILE": "whatever"}),
        ("bad port", {"TI_RECON_MCP_BIND_PORT": "0"}),
        ("non-numeric port", {"TI_RECON_MCP_BIND_PORT": "http"}),
    ],
)
def test_an_unsafe_configuration_refuses_to_start(label: str, overrides: dict[str, str]) -> None:
    """Before the socket, every time. A degraded remote server is worse than none."""
    del label
    with pytest.raises(ValueError):
        load_deployment(_environment(**overrides))


def test_optional_settings_are_parsed_explicitly() -> None:
    deployment = load_deployment(
        _environment(
            TI_RECON_MCP_ALLOWED_ORIGINS="https://a.example.com, https://b.example.com",
            TI_RECON_AUTH_ALGORITHMS="rs256, ps256",
            TI_RECON_AUTH_TOKEN_PROFILE="rfc9068",
            TI_RECON_MCP_BIND_HOST="0.0.0.0",
            TI_RECON_MCP_BIND_PORT="9000",
        )
    )

    assert deployment.http.allowed_origins == ("https://a.example.com", "https://b.example.com")
    assert deployment.verifier.algorithms == ("RS256", "PS256")
    assert deployment.verifier.profile is TokenProfile.RFC9068
    assert deployment.bind_host == "0.0.0.0"
    assert deployment.bind_port == 9000


def test_the_internal_bind_is_not_the_public_resource() -> None:
    """Two different things, and only one of them is the OAuth audience.

    A container binds ``0.0.0.0:8000`` behind an ingress that terminates TLS at
    ``https://mcp.example.com/mcp``. Using the bind address as the resource would
    make the audience something no client could name.
    """
    deployment = load_deployment(
        _environment(TI_RECON_MCP_BIND_HOST="0.0.0.0", TI_RECON_MCP_BIND_PORT="8000")
    )

    assert deployment.bind_host == "0.0.0.0"
    assert deployment.http.resource_url == RESOURCE
    assert deployment.auth.resource == RESOURCE


def test_no_provider_credential_variable_is_read() -> None:
    """A server's environment is global to the server.

    Reading provider keys here would hand every authenticated analyst the same
    ones. Nothing generic is read either — no bare ``API_KEY``, ``TOKEN`` or
    ``SECRET`` — so a variable meant for something else cannot be picked up.
    """
    from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT

    source = MODULE.read_text(encoding="utf-8")
    for variable in CREDENTIAL_ENVIRONMENT.values():
        assert variable not in source
    for name in ENVIRONMENT:
        assert name.startswith("TI_RECON_")

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in {"API_KEY", "TOKEN", "SECRET", "PASSWORD"}


def test_the_deployment_never_renders_the_tenant_key() -> None:
    rendered = repr(load_deployment(_environment()))

    assert TENANT_KEY not in rendered
    assert str(len(TENANT_KEY)) not in rendered
    assert RESOURCE in rendered


# --------------------------------------------------------------------------- #
# Composition
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_building_the_application_contacts_nothing(monkeypatch) -> None:
    """Not the identity provider, and not a provider API.

    Keys arrive with the first authenticated request. That is what lets
    ``/health`` answer during a brief IdP outage, which is the whole point of a
    liveness probe.
    """
    from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT

    for variable in CREDENTIAL_ENVIRONMENT.values():
        monkeypatch.setenv(variable, f"FAKE-{variable}")

    deployment = load_deployment(_environment())
    application = await build_remote_application(deployment)

    assert isinstance(application, RemoteHttpApp)
    assert application.config.resource_url == RESOURCE


@pytest.mark.asyncio
async def test_the_remote_application_loads_no_environment_provider_credential(
    monkeypatch,
) -> None:
    """The regression that matters most about a multi-tenant server."""
    from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT

    for variable in CREDENTIAL_ENVIRONMENT.values():
        monkeypatch.setenv(variable, f"FAKE-{variable}")

    application = await build_remote_application(load_deployment(_environment()))

    # No route, no tool and no tenant can see a credential nobody stored.
    assert application.public_paths == ("/health",)


# --------------------------------------------------------------------------- #
# The command
# --------------------------------------------------------------------------- #


def test_version_and_help_start_nothing(capsys) -> None:
    """Neither reads a credential, builds an application or fetches a key."""
    for flag in ("--version", "--help"):
        with pytest.raises(SystemExit) as raised:
            main([flag])
        assert raised.value.code == 0

    captured = capsys.readouterr().out
    assert __version__ in captured or "ti-recon-mcp-http" in captured


def test_a_broken_configuration_exits_without_serving(monkeypatch, capsys) -> None:
    """A nonzero exit and a message naming variables, never values.

    Read from stderr rather than ``caplog``: the entry point owns logging for its
    own process and sets ``propagate = False``, which is exactly what keeps a
    container's log readable — and what detaches it from the root handler.
    """
    monkeypatch.delenv("TI_RECON_MCP_RESOURCE_URL", raising=False)
    monkeypatch.setenv("TI_RECON_TENANT_DERIVATION_KEY", TENANT_KEY)

    assert main([]) == 2

    reported = capsys.readouterr().err
    assert "TI_RECON_MCP_RESOURCE_URL" in reported
    assert TENANT_KEY not in reported


def test_the_entry_point_is_separate_from_the_stdio_one() -> None:
    """Overloading one command would mean two authentication models in one."""
    manifest = Path("pyproject.toml").read_text(encoding="utf-8")

    assert 'ti-recon-mcp = "ti_recon.mcp_server.main:main"' in manifest
    assert 'ti-recon-mcp-http = "ti_recon.mcp_server.http_main:main"' in manifest


def test_the_process_cannot_be_asked_for_more_than_one_worker() -> None:
    """A correctness constraint, not a tuning knob.

    Task 6's cache, cooldown, quota and single-flight stores are process-local,
    and so is the tenant limiter; a second worker enforces each of them a second
    time independently. Read from the AST, because the module docstring explains
    the policy at length and should.
    """
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                assert keyword.arg != "workers"
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in {"--workers", "workers", "WEB_CONCURRENCY"}


def test_the_deployment_type_is_frozen() -> None:
    deployment = load_deployment(_environment())

    assert isinstance(deployment, RemoteDeployment)
    with pytest.raises(Exception):  # noqa: B017 - dataclasses.FrozenInstanceError
        deployment.bind_port = 1  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Static security
# --------------------------------------------------------------------------- #


def _auth_sources() -> list[tuple[Path, ast.Module]]:
    root = Path("src/ti_recon/mcp_server")
    return [
        (path, ast.parse(path.read_text(encoding="utf-8")))
        for path in (root / "jwt_auth.py", root / "http_main.py", root / "http.py")
    ]


def test_no_production_module_disables_a_verification() -> None:
    """Signature checking, TLS verification and the algorithm allowlist.

    Each of these is one keyword away from silently accepting anything, and each
    of them is the kind of thing somebody adds while debugging.
    """
    unsafe = {"verify_signature": False, "verify": False, "verify_aud": False, "verify_iss": False}
    for path, tree in _auth_sources():
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value in unsafe
                        and isinstance(value, ast.Constant)
                    ):
                        assert value.value is not False, f"{path}: {key.value}=False"
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg in {"verify", "follow_redirects"} and isinstance(
                        keyword.value, ast.Constant
                    ):
                        expected = keyword.arg != "follow_redirects"
                        assert keyword.value.value is expected, f"{path}: {keyword.arg}"


def test_no_symmetric_algorithm_is_reachable() -> None:
    """Not in the supported set, not as a default, not as a fallback."""
    from ti_recon.mcp_server.jwt_auth import DEFAULT_ALGORITHMS, SUPPORTED_ALGORITHMS

    for name in SUPPORTED_ALGORITHMS | set(DEFAULT_ALGORITHMS):
        assert not name.startswith("HS"), name
        assert name.lower() != "none", name
    assert SUPPORTED_ALGORITHMS


def test_no_key_url_is_ever_taken_from_a_token() -> None:
    """``jku`` and ``x5u`` are not read anywhere in production source."""
    root = Path("src/ti_recon")
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in {"jku", "x5u"}, path
