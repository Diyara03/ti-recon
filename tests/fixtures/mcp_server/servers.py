"""A real MCP server over a real engine with scripted providers (Task 21).

Everything below the transport is the shipped code: the Task 20 application, the
Task 19 workflow and all four reasoning engines. Only the providers are fakes,
so a test can state "this source says this" and then assert what the *real*
chain concluded, delivered through the *real* protocol.

Faking the application instead would prove only that a value can be copied
across a tool boundary.
"""

from __future__ import annotations

from fixtures.investigation.stack import InvestigationStack, ScriptedProvider
from ti_recon.application.composition import CredentialLoadReport
from ti_recon.application.service import InvestigationApplication
from ti_recon.execution.models import ExecutionContext
from ti_recon.mcp_server.runtime import STDIO_PRINCIPAL, McpRuntime
from ti_recon.mcp_server.server import build_mcp_server
from ti_recon.providers.adapter import ProviderAdapter

#: Unmistakable, so a match anywhere in an output cannot be a coincidence.
FAKE_VT_KEY = "SUPER_SECRET_MCP_KEY_123"
FAKE_ABUSE_KEY = "SUPER_SECRET_ABUSE_MCP_456"


async def scripted_runtime(
    providers: list[ScriptedProvider],
    *,
    adapters: list[ProviderAdapter] | None = None,
    configured_groups: frozenset[str] = frozenset(),
) -> tuple[McpRuntime, InvestigationStack]:
    """A runtime whose application is the real one, over scripted providers.

    The stack is returned too, so a test can ask what a provider was actually
    asked — the only way to prove that a pivot did or did not disclose anything.
    """
    stack = InvestigationStack(providers=providers)
    await stack.add_credentials(user_id=STDIO_PRINCIPAL)
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(configured_groups=configured_groups),
        context=ExecutionContext(authenticated_user_id=STDIO_PRINCIPAL),
        adapters=tuple(adapters or []),
    )
    return runtime, stack


async def scripted_server(providers: list[ScriptedProvider], **kwargs: object):
    """The same, already wrapped in an MCP server."""
    runtime, stack = await scripted_runtime(providers, **kwargs)  # type: ignore[arg-type]
    return build_mcp_server(runtime), stack
