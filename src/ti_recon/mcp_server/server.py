"""The MCP server, built from the Task 20 boundary (Task 21).

Three tools and two schema resources over
:class:`~ti_recon.application.service.InvestigationApplication`. The server adds
capability and nothing else: it performs no analysis, selects no provider,
accepts no credential and cannot reach an adapter — every investigation goes
Task 20 → 19 → 13 → 6 → provider, exactly as a CLI invocation does.

Structured output
-----------------

The investigation tools are annotated ``-> AnalystInvestigationReport``, and the
SDK derives the output schema and the ``structured_content`` from that model. So
Task 20 remains the single definition of what a report is: there is no MCP
report type to drift from it, and no hand-maintained schema to forget to update.

A factory, not a process
------------------------

``build_mcp_server`` returns the server object. A test connects to it in
process with ``Client(server)`` — no subprocess, no port — and the entry point
is the only thing that turns one into a running process.
"""

from __future__ import annotations

import json
from typing import Annotated

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from ti_recon import __version__
from ti_recon.application.models import ObservableInputType
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.models import ProviderStatusReport
from ti_recon.mcp_server.runtime import McpRuntime
from ti_recon.reporting.models import AnalystInvestigationReport
from ti_recon.reporting.schema import report_json_schema, request_json_schema

__all__ = [
    "REPORT_SCHEMA_URI",
    "REQUEST_SCHEMA_URI",
    "SERVER_INSTRUCTIONS",
    "SERVER_NAME",
    "build_mcp_server",
]

SERVER_NAME = "ti-recon"

REQUEST_SCHEMA_URI = "ti-recon://schema/request"
REPORT_SCHEMA_URI = "ti-recon://schema/report"

#: JSON Schema documents, not arbitrary JSON. Both are Draft 2020-12.
_SCHEMA_MIME = "application/schema+json"

#: What a client is told about this server, kept short.
#:
#: Discovery terms first, then the two things a caller gets wrong without being
#: told: providers are chosen automatically and are not votes, and a local
#: transport does not make the *investigation* local. Detailed analyst procedure
#: belongs in a Skill, not here.
SERVER_INSTRUCTIONS = """\
TI Recon performs passive external threat-intelligence investigation of URLs, \
domains, IP addresses, file hashes and user-selected local files.

Use its tools for a deterministic assessment, the confidence that assessment is \
correct, how adequate the intelligence coverage was, the supporting and opposing \
evidence, alternative explanations for a detection, and related observables.

Provider selection is automatic and cannot be influenced from a tool call. \
Sources are provenance, never votes: the engine does not count who agreed.

Running over a local transport does not make collection local. Investigating an \
observable may send it to configured external intelligence providers.\
"""


def build_mcp_server(runtime: McpRuntime) -> MCPServer:
    """One server bound to one runtime.

    The runtime is captured rather than rebuilt per call: reassembling the
    application for every tool invocation would re-read credentials, re-register
    every adapter and discard the execution caches between two questions in one
    conversation.
    """
    server: MCPServer = MCPServer(
        SERVER_NAME,
        title="TI Recon",
        version=__version__,
        instructions=SERVER_INSTRUCTIONS,
    )
    _register_tools(server, runtime)
    _register_resources(server)
    return server


def _register_tools(server: MCPServer, runtime: McpRuntime) -> None:
    """The whole public surface: three tools, no more.

    No provider-specific tool exists, because which source answers a question is
    Task 13's ranked decision and exposing one would make results depend on what
    a model happened to pick.
    """

    @server.tool(
        title="Investigate an observable",
        annotations=ToolAnnotations(
            # It reads intelligence and changes nothing. `open_world_hint`
            # because it reaches external services whose answers are outside
            # this system. The destructive and idempotent hints are meaningful
            # for tools that write, so they are deliberately left unset.
            read_only_hint=True,
            open_world_hint=True,
        ),
    )
    async def investigate_observable(
        observable: Annotated[
            str,
            Field(
                description=(
                    "The thing to investigate: a URL, a domain, an IPv4 or IPv6 "
                    "address, or an MD5/SHA-1/SHA-256 hash."
                )
            ),
        ],
        observable_type: Annotated[
            ObservableInputType,
            Field(
                description=(
                    "Leave as auto except where the input is genuinely ambiguous "
                    "and you know which reading is meant."
                )
            ),
        ] = ObservableInputType.AUTO,
        depth: Annotated[
            InvestigationDepth,
            Field(
                description=(
                    "How much collection to buy. quick is minimal and fast; "
                    "standard is the normal default; deep collects more broadly "
                    "and may consume more provider quota."
                )
            ),
        ] = InvestigationDepth.STANDARD,
        pivot_mode: Annotated[
            PivotMode,
            Field(
                description=(
                    "What to do with related observables the investigation "
                    "discovers. none ignores them; recommend records and shows "
                    "them without querying them; enrich permits bounded "
                    "enrichment of them. This does not affect the observable you "
                    "submitted, which may be sent to external providers in every "
                    "mode."
                )
            ),
        ] = PivotMode.RECOMMEND,
        allow_remote_pivot_lookup: Annotated[
            bool,
            Field(
                description=(
                    "Effective only with pivot_mode=enrich. Permits eligible "
                    "related observables to be sent to configured external "
                    "providers, disclosing things the analyst did not submit and "
                    "consuming additional quota. Off unless explicitly asked for."
                )
            ),
        ] = False,
    ) -> AnalystInvestigationReport:
        """Passive threat-intelligence investigation of one observable.

        Returns a deterministic assessment, the confidence that the assessment is
        correct, how adequate the intelligence coverage was, the supporting and
        opposing evidence, alternative explanations and related observables.
        Provider selection is automatic. May contact configured external
        intelligence providers.
        """
        return await tools.investigate_observable(
            runtime,
            observable=observable,
            observable_type=observable_type,
            depth=depth,
            pivot_mode=pivot_mode,
            allow_remote_pivot_lookup=allow_remote_pivot_lookup,
        )

    @server.tool(
        title="Investigate a local file",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
    )
    async def investigate_file(
        path: Annotated[
            str,
            Field(
                description=(
                    "Path to a regular local file the user has chosen. Special "
                    "files such as pipes and devices are refused."
                )
            ),
        ],
        depth: Annotated[
            InvestigationDepth, Field(description="See investigate_observable.")
        ] = InvestigationDepth.STANDARD,
        pivot_mode: Annotated[
            PivotMode, Field(description="See investigate_observable.")
        ] = PivotMode.RECOMMEND,
        allow_remote_pivot_lookup: Annotated[
            bool, Field(description="See investigate_observable.")
        ] = False,
    ) -> AnalystInvestigationReport:
        """Hashes the file locally with SHA-256 and investigates the hash.

        The file itself is never uploaded and never submitted for detonation;
        its bytes do not leave this machine. Only the hash, and any related
        observables you explicitly permit, may be sent to configured external
        intelligence providers, which are selected automatically.
        """
        return await tools.investigate_file(
            runtime,
            path=path,
            depth=depth,
            pivot_mode=pivot_mode,
            allow_remote_pivot_lookup=allow_remote_pivot_lookup,
        )

    @server.tool(
        title="Check intelligence source setup",
        annotations=ToolAnnotations(
            # Nothing outside this process is consulted, so the world it reads
            # is closed.
            read_only_hint=True,
            open_world_hint=False,
        ),
    )
    async def provider_status() -> ProviderStatusReport:
        """Which intelligence sources this installation can use, and what they cover.

        Makes no provider requests at all. "Configured" means the required
        credentials were present at startup — not that they are valid, that
        authentication would succeed, or that quota remains.
        """
        return tools.provider_status(runtime)


def _register_resources(server: MCPServer) -> None:
    """The two public contracts, served from Task 20's own generators.

    Nothing internal is exposed: not the investigation result, not planner
    state, not the graph, not a provider payload, not configuration. A consumer
    integrating against this server gets the schemas it validates against and
    nothing it should not be depending on.
    """

    @server.resource(
        REQUEST_SCHEMA_URI,
        name="analyst-investigation-request-schema",
        title="Investigation request schema",
        description="JSON Schema for the investigation request this server accepts.",
        mime_type=_SCHEMA_MIME,
    )
    def request_schema() -> str:
        return _dump(request_json_schema())

    @server.resource(
        REPORT_SCHEMA_URI,
        name="analyst-investigation-report-schema",
        title="Analyst report schema",
        description="JSON Schema for the analyst report the investigation tools return.",
        mime_type=_SCHEMA_MIME,
    )
    def report_schema() -> str:
        return _dump(report_json_schema())


def _dump(document: dict[str, object]) -> str:
    """Deterministic bytes, so two reads compare equal."""
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False)
