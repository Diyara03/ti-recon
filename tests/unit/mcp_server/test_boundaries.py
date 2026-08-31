"""What the server may not do, and may not leak (Task 21).

The transport is the outermost surface: everything the engine holds passes
through it on the way to a model, and a model will act on whatever it reads. So
these tests cover the three ways that goes wrong — a secret escaping, a
diagnostic reaching the network, and this layer growing an opinion of its own.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import io
import json
import logging
from pathlib import Path

import pytest
from mcp import Client

from fixtures.investigation import claim_evidence, spec
from fixtures.investigation.stack import FAKE_SECRET_MARKER, ScriptedProvider
from fixtures.mcp_server import FAKE_ABUSE_KEY, FAKE_VT_KEY, scripted_server
from ti_recon.application.composition import CredentialLoadReport
from ti_recon.application.models import ObservableInputType
from ti_recon.correlation.policy import PivotMode
from ti_recon.credentials import InMemoryConnectionRepository
from ti_recon.enums import InvestigationDepth, ProviderCapability
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.runtime import (
    STDIO_PRINCIPAL,
    FixedPrincipal,
    McpRuntime,
    build_stdio_runtime,
)
from ti_recon.mcp_server.server import (
    REPORT_SCHEMA_URI,
    REQUEST_SCHEMA_URI,
    build_mcp_server,
)
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.reasoning.claims.models import ClaimSemantic

MCP_PACKAGE = Path("src/ti_recon/mcp_server")
REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64

#: A secret planted where only a badly behaved dependency would put one.
EXCEPTION_SECRET = "SUPER_SECRET_MCP_EXCEPTION_123"


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_no_secret_appears_anywhere_a_client_can_read() -> None:
    """Every surface at once: listings, schemas, results and content.

    The fixture credential is stored through the real mechanism, so this is the
    path a deployment actually takes rather than a handcrafted object.
    """
    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    server, _ = await scripted_server(
        [provider], adapters=build_default_adapters(), configured_groups=frozenset({"abuse_ch"})
    )

    async with Client(server) as client:
        surfaces = [
            json.dumps(
                [item.model_dump(mode="json") for item in (await client.list_tools()).tools]
            ),
            json.dumps(
                [item.model_dump(mode="json") for item in (await client.list_resources()).resources]
            ),
            (await client.read_resource(REPORT_SCHEMA_URI)).contents[0].text or "",
            (await client.read_resource(REQUEST_SCHEMA_URI)).contents[0].text or "",
        ]
        status = await client.call_tool("provider_status", {})
        good = await client.call_tool(
            "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
        )
        bad = await client.call_tool("investigate_observable", {"observable": "not valid!!"})

    for result in (status, good, bad):
        surfaces.append(json.dumps(result.structured_content))
        surfaces.append(" ".join(item.text or "" for item in result.content))

    blob = "\n".join(surfaces)
    for secret in (FAKE_VT_KEY, FAKE_ABUSE_KEY, FAKE_SECRET_MARKER):
        assert secret not in blob, secret


@pytest.mark.asyncio
async def test_an_unexpected_exception_leaks_neither_message_nor_traceback() -> None:
    """The failure this sanitisation exists for.

    Left to escape, the SDK returns a generic message *but logs the whole
    traceback at ERROR* — and a dependency can put a credential or a raw
    provider payload in an exception string. Converting it here keeps the type
    (safe, useful) and discards the message (neither).
    """

    class _Exploding:
        async def investigate(self, request: object, context: object) -> object:
            msg = f"provider replied with {EXCEPTION_SECRET}"
            raise RuntimeError(msg)

    runtime = McpRuntime(
        application=_Exploding(),  # type: ignore[arg-type]
        credentials=CredentialLoadReport(),
        connections=InMemoryConnectionRepository(),
        principals=FixedPrincipal(STDIO_PRINCIPAL),
    )
    captured = io.StringIO()
    handler = logging.StreamHandler(captured)
    for name in ("ti_recon", "mcp"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        async with Client(build_mcp_server(runtime)) as client:
            result = await client.call_tool("investigate_observable", {"observable": "8.8.8.8"})

    seen = "\n".join(
        [
            json.dumps(result.structured_content),
            " ".join(item.text or "" for item in result.content),
            captured.getvalue(),
            stderr.getvalue(),
        ]
    )

    assert result.is_error is True
    assert EXCEPTION_SECRET not in seen
    assert "Traceback" not in seen
    # The model is told something true and useless to an attacker.
    assert "internal application error" in " ".join(item.text or "" for item in result.content)
    # The type is logged, because that is diagnosable and carries no payload.
    assert "RuntimeError" in captured.getvalue()


@pytest.mark.asyncio
async def test_cancellation_does_not_become_a_result() -> None:
    """A caller going away is not an analytical outcome.

    ``CancelledError`` is a ``BaseException``, so the broad handler that
    sanitises unexpected failures does not catch it — and no partial or
    inconclusive report is returned in its place.
    """
    gate = asyncio.Event()

    class _Blocking:
        async def investigate(self, request: object, context: object) -> object:
            await gate.wait()
            raise AssertionError("should never be reached")

    runtime = McpRuntime(
        application=_Blocking(),  # type: ignore[arg-type]
        credentials=CredentialLoadReport(),
        connections=InMemoryConnectionRepository(),
        principals=FixedPrincipal(STDIO_PRINCIPAL),
    )
    task = asyncio.ensure_future(
        tools.investigate_observable(
            runtime,
            observable="8.8.8.8",
            observable_type=ObservableInputType.AUTO,
            depth=InvestigationDepth.STANDARD,
            pivot_mode=PivotMode.RECOMMEND,
            allow_remote_pivot_lookup=False,
        )
    )
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelled()


# --------------------------------------------------------------------------- #
# Zero network
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_building_a_server_and_listing_it_opens_nothing(monkeypatch) -> None:
    """Startup and diagnostics are offline, with nine real providers registered.

    Adapters create their clients lazily and no credential is validated, so a
    server starts on a machine with no keys and a host can discover it without
    anything leaving the machine.
    """
    from fixtures.network import install_network_guard

    install_network_guard(monkeypatch)

    runtime = await build_stdio_runtime()
    server = build_mcp_server(runtime)

    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        resources = (await client.list_resources()).resources
        status = await client.call_tool("provider_status", {})
        schema = await client.read_resource(REPORT_SCHEMA_URI)

    assert {item.name for item in tools}
    assert resources
    assert status.is_error is False
    assert status.structured_content["total"] == len(build_default_adapters())
    assert json.loads(schema.contents[0].text or "{}")


@pytest.mark.asyncio
async def test_provider_status_describes_the_runtime_catalogue() -> None:
    """One list, so a source reported configured is genuinely available.

    Two lists — one to display, one to execute — would eventually disagree, and
    the disagreement would look like a provider that silently never ran.
    """
    runtime = await build_stdio_runtime()

    async with Client(build_mcp_server(runtime)) as client:
        result = await client.call_tool("provider_status", {})

    listed = {item["provider_id"] for item in result.structured_content["providers"]}
    assert listed == {item.descriptor.provider_id for item in runtime.adapters}
    assert listed == {item.descriptor.provider_id for item in build_default_adapters()}


@pytest.mark.asyncio
async def test_provider_status_says_configured_and_never_validated() -> None:
    """The field is named for what it knows.

    ``configured`` means this principal has the credential stored. Calling it
    ``verified`` or ``healthy`` would claim something only a network call could
    establish — which this tool must never make.
    """
    runtime = await build_stdio_runtime()

    async with Client(build_mcp_server(runtime)) as client:
        result = await client.call_tool("provider_status", {})

    document = json.dumps(result.structured_content).lower()
    for forbidden in ("authenticated", "verified", "healthy", "valid"):
        assert forbidden not in document, forbidden
    for item in result.structured_content["providers"]:
        assert isinstance(item["configured"], bool)


# --------------------------------------------------------------------------- #
# Static boundaries
# --------------------------------------------------------------------------- #


def _sources() -> list[tuple[Path, str]]:
    return [(path, path.read_text(encoding="utf-8")) for path in sorted(MCP_PACKAGE.rglob("*.py"))]


def test_the_server_imports_no_provider_adapter_or_transport() -> None:
    """Execution belongs to Task 13 and Task 6.

    ``runtime.py`` may import the *catalogue*, which is a composition root. No
    module here may import an individual adapter, an HTTP client or a socket.
    """
    for path, source in _sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in {"socket", "httpx", "ssl", "requests"}, path.name
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in {"socket", "httpx", "ssl", "requests"}, path.name
                assert not node.module.startswith("ti_recon.providers.") or node.module.endswith(
                    (".catalog", ".adapter")
                ), f"{path.name} imports {node.module}"


def test_the_server_reimplements_no_reasoning_policy() -> None:
    """It consumes decisions; it does not make them.

    Importing a policy module would be the first step towards a second opinion
    that could disagree with the engine's — and a model would have no way to
    tell which half was wrong.
    """
    for path, source in _sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.endswith(".policy") or node.module.endswith(
                    ("correlation.policy",)
                ), f"{path.name} imports {node.module}"


def test_the_server_never_calls_an_adapter_or_the_executor() -> None:
    """Every provider call goes Task 20 -> 19 -> 13 -> 6."""
    for path, source in _sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {
                    "lookup",
                    "batch_lookup",
                    "active_action",
                    "execute",
                }, f"{path.name}: .{node.attr}()"


def test_nothing_prints_to_stdout() -> None:
    """stdout belongs to the protocol.

    One stray line corrupts the JSON-RPC stream and a host simply fails to
    connect, with no clue why.
    """
    for path, source in _sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "print", f"{path.name} calls print()"
        assert "sys.stdout" not in source, f"{path.name} touches sys.stdout"


def test_the_reusable_factory_does_not_reconfigure_logging() -> None:
    """Only the process entry point owns logging.

    A library that reconfigured the package logger would silently replace an
    embedding application's handlers — the lesson Task 20 already learned once.
    """
    for path, source in _sources():
        if path.name == "main.py":
            continue
        assert "basicConfig" not in source, path.name
        assert ".handlers =" not in source, path.name


# --------------------------------------------------------------------------- #
# The access token stops at the MCP boundary
# --------------------------------------------------------------------------- #

#: Every package the engine is made of. None of them may learn that OAuth
#: exists: the MCP layer converts a validated token into one opaque string, and
#: that string is the whole vocabulary below it.
_ENGINE_PACKAGES = (
    "application",
    "investigation",
    "planning",
    "correlation",
    "execution",
    "credentials",
    "providers",
    "reasoning",
    "reporting",
    "cli",
)

#: Symbols that only exist because a request was authenticated over HTTP.
_AUTH_SYMBOLS = frozenset(
    {
        "AccessToken",
        "AuthenticatedUser",
        "AuthSettings",
        "TokenVerifier",
        "auth_context_var",
        "get_access_token",
        "principal_components",
        "authorization_context",
    }
)


def _engine_sources() -> list[tuple[Path, str]]:
    root = MCP_PACKAGE.parent
    return [
        (path, path.read_text(encoding="utf-8"))
        for package in _ENGINE_PACKAGES
        for path in sorted((root / package).rglob("*.py"))
    ]


def test_the_engine_imports_nothing_from_the_mcp_sdk() -> None:
    """The token that authorizes an analyst must never reach a provider.

    Structural rather than procedural: a provider adapter can only forward an
    MCP access token if something below this boundary can *reach* one, and the
    only way to reach one is to import the SDK. Nothing below does, so a
    passthrough would have to add an import first — and this test is what
    notices.
    """
    for path, source in _engine_sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "mcp" and not alias.name.startswith("mcp."), (
                        f"{path} imports {alias.name}"
                    )
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module != "mcp" and not node.module.startswith("mcp."), (
                    f"{path} imports from {node.module}"
                )


def test_no_engine_module_names_an_authentication_symbol() -> None:
    """Not by import, and not by attribute either.

    Catches the shape an import ban misses: reaching a contextvar through a
    module object somebody passed in.
    """
    for path, source in _engine_sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    assert alias.name not in _AUTH_SYMBOLS, f"{path} imports {alias.name}"
            if isinstance(node, ast.Name):
                assert node.id not in _AUTH_SYMBOLS, f"{path} names {node.id}"
            if isinstance(node, ast.Attribute):
                assert node.attr not in _AUTH_SYMBOLS, f"{path} reads .{node.attr}"


def test_nothing_below_the_boundary_can_read_an_inbound_request_header() -> None:
    """The two directions are different, and only one is forbidden.

    A provider config naming ``Authorization`` is *TI Recon's* key going out to
    a provider — expected, and where the outbound credential belongs. Reading an
    *inbound* header is the direction that could reach the analyst's token, and
    it needs the ASGI/HTTP server machinery to do it. Nothing below the MCP
    layer imports any, so there is no inbound request to read a header from.
    """
    forbidden = ("starlette", "uvicorn", "fastapi", "asgiref")
    for path, source in _engine_sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            for name in names:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_the_remote_composition_never_loads_environment_credentials() -> None:
    """A server's environment is global to the server.

    Read from the module's AST rather than from a comment: the remote builder
    must pass ``load_credentials=False``, and nothing here may call the
    environment loader.
    """
    source = (MCP_PACKAGE / "runtime.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    remote = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "build_remote_runtime"
    )
    keywords = {
        keyword.arg: keyword.value
        for node in ast.walk(remote)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
    }
    loaded = keywords.get("load_credentials")
    assert isinstance(loaded, ast.Constant) and loaded.value is False

    for path, text in _sources():
        assert "load_environment_credentials" not in text, path.name


# --------------------------------------------------------------------------- #
# HTTP stops at the MCP boundary too
# --------------------------------------------------------------------------- #


def test_the_engine_imports_no_http_server_machinery() -> None:
    """Extends the token ban to the transport that carries one.

    ``application/``, ``execution/``, ``credentials/``, ``providers/`` and
    ``reasoning/`` must not learn that HTTP serving exists. ``providers/`` is an
    HTTP *client* of third parties and imports ``httpx`` legitimately; what none
    of them may import is a server framework, which is the only way to reach an
    inbound request, a header, or ``AuthSettings``.
    """
    forbidden = ("starlette", "uvicorn", "fastapi", "asgiref", "hypercorn")
    for path, source in _engine_sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            for name in names:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_no_engine_module_names_an_http_auth_symbol() -> None:
    """``AuthSettings``, ``Request`` and the transport knobs stay above the line."""
    symbols = frozenset(
        {
            "AuthSettings",
            "TransportSecuritySettings",
            "RemoteHttpConfig",
            "StrictTokenVerifier",
            "RemotePrincipal",
            "build_remote_http_app",
            "streamable_http_app",
        }
    )
    for path, source in _engine_sources():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    assert alias.name not in symbols, f"{path} imports {alias.name}"
            if isinstance(node, ast.Name):
                assert node.id not in symbols, f"{path} names {node.id}"


def test_the_remote_builder_never_registers_the_file_tool() -> None:
    """Read from the AST, so "hidden from the docs" cannot pass for "absent".

    ``build_remote_server`` must pass ``local_file_tool=False``, and the file
    tool's registration must live behind that flag rather than beside it.
    """
    source = (MCP_PACKAGE / "server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    remote = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "build_remote_server"
    )
    flags = {
        keyword.arg: keyword.value
        for node in ast.walk(remote)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
    }
    value = flags.get("local_file_tool")
    assert isinstance(value, ast.Constant) and value.value is False

    register = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_register_tools"
    )
    guarded = [
        node
        for node in ast.walk(register)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "local_file_tool"
    ]
    assert guarded, "the file tool must be registered behind the profile flag"


def test_the_remote_modules_name_no_provider() -> None:
    """Which source answers a question stays Task 13's ranked decision.

    The transport layer must not be able to express a preference, so no module
    added for HTTP may import an adapter or name one.
    """
    for name in ("http.py", "limits.py", "auth.py", "principal.py"):
        source = (MCP_PACKAGE / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("ti_recon.providers."), f"{name}: {node.module}"
        for provider in ("virustotal", "urlscan", "greynoise", "censys", "abuse", "gti"):
            assert provider not in source.lower().replace("provider", ""), f"{name}: {provider}"


def test_no_permissive_token_verifier_ships() -> None:
    """A development verifier reachable from production would end this boundary.

    The one implementation in ``src`` is the strict wrapper, and it composes over
    an injected delegate it has no default for.
    """
    for path, source in _sources():
        lowered = source.lower()
        for banned in ("unsafetokenverifier", "developmentverifier", "insecuretokenverifier"):
            assert banned not in lowered.replace(" ", ""), f"{path.name}: {banned}"

    tree = ast.parse((MCP_PACKAGE / "http.py").read_text(encoding="utf-8"))
    factory = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "build_remote_http_app"
    )
    delegate = next(item for item in factory.args.kwonlyargs if item.arg == "delegate")
    index = factory.args.kwonlyargs.index(delegate)
    assert factory.args.kw_defaults[index] is None, "delegate must have no default"


def test_no_remote_console_script_is_published() -> None:
    """Running a remote server needs a real verifier, and that needs an IdP.

    Shipping an entry point today would mean shipping something for it to
    construct, and the only candidates are the three verifiers that must never
    exist. The next phase adds both together.
    """
    manifest = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "ti-recon-mcp-http" not in manifest
    assert "uvicorn" not in manifest
    for path, source in _sources():
        assert "--workers" not in source, path.name


def test_nothing_below_the_boundary_imports_the_http_gate() -> None:
    """The preflight gate is transport composition and stays above the engine.

    It knows HTTP and configuration; it must never learn that providers,
    executors or reasoning exist, and nothing in the engine may reach up to it.
    """
    for path, source in _engine_sources():
        assert "RemoteHttpApp" not in source, path
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "mcp_server" not in node.module, f"{path} imports {node.module}"


def test_the_http_gate_knows_only_transport_configuration() -> None:
    """No adapter, no executor, no credential loader, no reasoning engine."""
    tree = ast.parse((MCP_PACKAGE / "http.py").read_text(encoding="utf-8"))
    forbidden = (
        "ti_recon.providers",
        "ti_recon.execution",
        "ti_recon.reasoning",
        "ti_recon.planning",
        "ti_recon.correlation",
        "ti_recon.investigation",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith(forbidden), node.module
    for name in ("ProviderExecutor", "CredentialResolver", "load_environment_credentials"):
        assert name not in (MCP_PACKAGE / "http.py").read_text(encoding="utf-8"), name


def test_no_sdk_class_is_monkeypatched_or_reached_into_privately() -> None:
    """Ordering is arranged by ASGI composition, not by rewriting the SDK.

    A global replacement of ``BearerAuthBackend`` or a patched
    ``AuthenticationMiddleware`` would work in tests and be invisible to anybody
    reading the deployment.
    """
    tree = ast.parse((MCP_PACKAGE / "http.py").read_text(encoding="utf-8"))
    # Symbols, not prose: the module's docstring explains the SDK's composition
    # at length, and it should. What matters is what the code touches.
    symbols = frozenset({"BearerAuthBackend", "AuthenticationMiddleware", "setattr"})
    privates = frozenset(
        {"_lowlevel_server", "_session_manager", "_custom_starlette_routes", "__dict__"}
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name not in symbols, alias.name
        if isinstance(node, ast.Name):
            assert node.id not in symbols, node.id
        if isinstance(node, ast.Attribute):
            assert node.attr not in symbols | privates, node.attr


def test_the_gate_adds_no_security_configuration_flag() -> None:
    """These are mandatory semantics, not options somebody can turn off."""
    source = (MCP_PACKAGE / "http.py").read_text(encoding="utf-8")
    for banned in (
        "pre_auth_enabled",
        "health_skip_auth",
        "bypass_verifier",
        "pre_auth_allowed_hosts",
        "mcp_allowed_hosts",
        "skip_transport_security",
    ):
        assert banned not in source, banned
