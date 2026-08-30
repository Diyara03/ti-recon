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
from ti_recon.enums import InvestigationDepth, ProviderCapability
from ti_recon.execution.models import ExecutionContext
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.runtime import McpRuntime, build_stdio_runtime
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
        context=ExecutionContext(authenticated_user_id="mcp-stdio-local"),
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
        context=ExecutionContext(authenticated_user_id="mcp-stdio-local"),
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

    ``configured`` means the credential was present at startup. Calling it
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
