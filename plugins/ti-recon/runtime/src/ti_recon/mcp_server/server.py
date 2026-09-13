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
from enum import StrEnum
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations
from pydantic import Field

from ti_recon import __version__
from ti_recon.application.models import ObservableInputType
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.investigation.models import InvestigationObjective
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.models import ProviderStatusReport
from ti_recon.mcp_server.runtime import McpRuntime
from ti_recon.reporting.models import AnalystInvestigationReport
from ti_recon.reporting.schema import report_json_schema, request_json_schema

__all__ = [
    "FILE_TOOL_META",
    "PLUGIN_INSTRUCTIONS",
    "REMOTE_INSTRUCTIONS",
    "REPORT_SCHEMA_URI",
    "REQUEST_SCHEMA_URI",
    "SERVER_INSTRUCTIONS",
    "SERVER_NAME",
    "STDIO_INSTRUCTIONS",
    "LocalCredentialSetup",
    "build_mcp_server",
    "build_remote_server",
    "build_stdio_server",
]


class LocalCredentialSetup(StrEnum):
    """How a credential comes to exist for a *local* stdio server.

    The stdio profile always reads credentials from its own process environment,
    read once at startup. What differs is who put them there, and therefore what
    an analyst has to do to add one — which is the one thing a client must be
    told accurately, because left unsaid it fills the gap with the model it
    already knows and sends somebody to set an environment variable the plugin
    will overwrite.

    * ``ENVIRONMENT`` — the analyst owns the process and its environment: a
      repository checkout, a CLI installation, a hand-written ``.mcp.json``.
    * ``CLAUDE_PLUGIN`` — Claude Code started the server from the TI Recon
      plugin and populated the environment from the plugin's configuration,
      which is where a credential is entered and where it is stored.

    Neither value reaches the engine: it selects instruction text and nothing
    else. Credential resolution is identical in both cases.
    """

    ENVIRONMENT = "environment"
    CLAUDE_PLUGIN = "claude-plugin"


SERVER_NAME = "ti-recon"

REQUEST_SCHEMA_URI = "ti-recon://schema/request"
REPORT_SCHEMA_URI = "ti-recon://schema/report"

#: JSON Schema documents, not arbitrary JSON. Both are Draft 2020-12.
_SCHEMA_MIME = "application/schema+json"

#: Ask the host to obtain human approval every time the file tool runs.
#:
#: An Anthropic extension key, carried in the tool's ``_meta``. Claude Code
#: 2.1.199 and later reads it and prompts on every call — including where an
#: allow rule would otherwise match, which is the point: a standing "yes" to
#: investigating observables should not become a standing "yes" to reading
#: files off somebody's disk.
#:
#: **Defence in depth, and advisory.** A host that does not know the key ignores
#: it, so this is never the boundary that matters most. Those are: the user
#: chooses the file, Task 20 refuses anything that is not a regular file, the
#: bytes are hashed locally and never sent, and the Skill may not go looking for
#: files on its own. This only adds a human beat in the hosts that support it.
#:
#: Deliberately *not* an input field. A ``user_confirmed`` argument would be set
#: by the model, which is not consent from anybody.
FILE_TOOL_META: dict[str, Any] = {"anthropic/requiresUserInteraction": True}

#: What a client is told about this server, kept short.
#:
#: Discovery terms first, then the handful of things a caller gets wrong without
#: being told. Every rule here is one whose loss produces a *confidently wrong*
#: answer rather than a vague one — "inconclusive" read as clean, a source that
#: was never asked read as one that found nothing, a confidence band read as a
#: probability of compromise.
#:
#: **This is the cross-client contract and it may not depend on a Skill.** A
#: project Skill is a filesystem artifact of one repository; an ordinary client
#: that merely connects this server receives these instructions, the tool
#: descriptions and the output schemas, and nothing else. Whatever a reader must
#: not get wrong has to be reachable from those three. A Skill may organise,
#: illustrate and extend — it may not be what makes the contract correct.
#:
#: Still deliberately short. Detailed analyst procedure belongs in a Skill and in
#: the schema field descriptions, which carry the per-field vocabulary; a
#: handbook here would compete with both and go stale.
#:
#: **Short has a number.** Claude Code 2.1.259 truncates a server's instructions
#: to 2048 characters and logs it only at debug level, so every profile — this
#: core plus its deployment addendum — must fit inside that, or the sentence
#: that differs by deployment is exactly the one cut off. The addenda are the
#: last thing in each profile because the shared rules matter to every client;
#: a test holds each complete profile under the limit.
SERVER_INSTRUCTIONS = """\
TI Recon performs passive external threat-intelligence investigation of URLs, \
domains, IP addresses, file hashes and user-selected local files. A local \
transport does not make collection local: an observable may be sent to \
configured external providers.

Provider selection is automatic and cannot be influenced from a tool call. \
Sources are provenance, never votes: the engine does not count who agreed, so \
never justify a verdict by a count of sources. Datasets from one organisation \
share a source family and are one origin.

Reporting the result, in plain language before internal identifiers:
- INCONCLUSIVE means the engine cannot justify either direction. It never means \
clean, safe or not malicious.
- not_configured means a source was NOT checked: no usable credential is \
available for the caller. no_data means it was checked and held nothing \
applicable, which is not evidence of safety.
- Confidence is confidence that the assessment is correct, not a probability \
that the observable is malicious, and not a severity.
- Coverage (the readiness fields) is evidence adequacy, never permission to \
block, allow, remediate or close anything.
- source_checks is the authority for what was actually consulted; a shipped or \
configured source was not thereby asked.
- A related observable with assessed=false is a relationship, not an indicator.
- Anything from your own knowledge must be labelled as yours and never be \
presented as TI Recon evidence, coverage or provenance.\
"""

#: The local profile's addendum: credential setup is a real local step here.
#:
#: True over stdio and only over stdio. One process serves the one analyst who
#: started it, from that machine's environment, read once — so "configure it and
#: reconnect" is accurate advice rather than a guess.
STDIO_INSTRUCTIONS = f"""\
{SERVER_INSTRUCTIONS}

This server runs locally for one analyst. Provider credentials are configured on \
this machine through the documented environment variables and read once at \
startup, so a newly added one appears after the server is restarted or \
reconnected. Never ask anyone to paste a provider API key into the conversation: \
credentials are never tool arguments and never belong in a transcript.\
"""

#: The plugin profile's addendum: the credential step is the plugin's own.
#:
#: Still local stdio — one process, one analyst, environment read once — but
#: the environment was populated by Claude Code from the plugin's configuration,
#: so that is where a credential is added. Telling this caller to export a
#: variable would be wrong twice: the plugin's mapping overwrites whatever the
#: shell exported, and the key would land in a shell profile rather than in the
#: host's secure storage.
PLUGIN_INSTRUCTIONS = f"""\
{SERVER_INSTRUCTIONS}

This server runs locally for one analyst, started by the TI Recon Claude Code \
plugin. Provider credentials are entered in the plugin's configuration (/plugin, \
TI Recon, Configure), stored by Claude Code and read once at startup, so a new \
one appears after a reconnect or a session restart. \
Never advise setting an environment variable or editing a file: the plugin's \
configuration is the only place read. Never ask anyone to paste a provider API \
key into the conversation: credentials are never tool arguments and never belong \
in a transcript.\
"""

#: The hosted profile's addendum: there is no credential onboarding to point at.
#:
#: The correction this exists for. Absent an explicit statement, a client fills
#: the gap with the local model it knows — "add the key to the server's
#: environment and reconnect" — which for a hosted deployment is advice to edit
#: somebody else's server, and would be wrong even if the caller could. A remote
#: caller's provider credentials are per-analyst and reach the engine through the
#: credential layer; the authenticated path that fills it is later work, and this
#: says so rather than implying either that it exists or that a local workaround
#: does.
REMOTE_INSTRUCTIONS = f"""\
{SERVER_INSTRUCTIONS}

This server is hosted and serves many analysts, each with their own \
authenticated session. Where a source reports not_configured, say it was not \
checked because no credential is available for this account, and stop there: do \
not tell the caller to configure a credential locally, set a server environment \
variable or reconnect. Self-service provider credential setup is not available \
in this version. Never ask anyone to paste a provider API key into the \
conversation, a tool argument, a prompt or a request header: a secret sent that \
way lands in a transcript.\
"""


def build_mcp_server(
    runtime: McpRuntime,
    *,
    auth: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
    local_file_tool: bool = True,
    instructions: str = SERVER_INSTRUCTIONS,
    hosted: bool = False,
    credential_setup: LocalCredentialSetup = LocalCredentialSetup.ENVIRONMENT,
) -> MCPServer:
    """One server bound to one runtime.

    The runtime is captured rather than rebuilt per call: reassembling the
    application for every tool invocation would re-read credentials, re-register
    every adapter and discard the execution caches between two questions in one
    conversation.

    ``local_file_tool`` is the deployment profile, and the only difference
    between the two surfaces. A file path means something on the machine the
    server runs on, which over stdio is the analyst's own and over HTTP is
    somebody else's — see :func:`build_remote_server`.

    ``auth`` and ``token_verifier`` are what turn the HTTP app this server can
    produce into a protected resource. They are inert over stdio, where the
    specification says credentials come from the environment instead.

    ``instructions`` and ``hosted`` carry the one semantic difference between the
    profiles that a *client* can see. How a provider credential comes to exist is
    genuinely different in the two deployments, and a server that stays silent
    about it gets described by the local model every client already knows — "put
    the key in the environment and reconnect" — which is wrong, and unactionable,
    for somebody talking to a server they do not run.

    ``credential_setup`` refines the local case the same way: it says *where* an
    analyst adds a credential, and is ignored when ``hosted`` because a hosted
    caller has nowhere to add one.
    """
    server: MCPServer = MCPServer(
        SERVER_NAME,
        title="TI Recon",
        version=__version__,
        instructions=instructions,
        auth=auth,
        token_verifier=token_verifier,
    )
    _register_tools(
        server,
        runtime,
        local_file_tool=local_file_tool,
        hosted=hosted,
        credential_setup=credential_setup,
    )
    _register_resources(server)
    return server


def build_stdio_server(
    runtime: McpRuntime,
    *,
    credential_setup: LocalCredentialSetup = LocalCredentialSetup.ENVIRONMENT,
) -> MCPServer:
    """The local profile: three tools, one analyst, no authorization.

    The tool surface is the Task 21 one, unchanged. ``credential_setup`` selects
    which true sentence describes how a credential is configured for *this*
    process — the environment the analyst owns, or the plugin configuration
    Claude Code owns — and changes nothing else.
    """
    instructions = (
        PLUGIN_INSTRUCTIONS
        if credential_setup is LocalCredentialSetup.CLAUDE_PLUGIN
        else STDIO_INSTRUCTIONS
    )
    return build_mcp_server(
        runtime,
        local_file_tool=True,
        instructions=instructions,
        hosted=False,
        credential_setup=credential_setup,
    )


def build_remote_server(
    runtime: McpRuntime, *, auth: AuthSettings, token_verifier: TokenVerifier
) -> MCPServer:
    """The authenticated profile: two tools, many analysts, bearer-protected.

    ``investigate_file`` is **absent**, not hidden. Its ``path`` argument names a
    file on the machine running the server; over stdio that is the analyst's own
    workstation, and over HTTP it is somebody else's server — so the tool would
    stop being file analysis and become an authenticated arbitrary-read
    primitive. Leaving it registered and undocumented would still put it in
    ``tools/list`` and still make a hand-written ``tools/call`` reach a path.
    """
    return build_mcp_server(
        runtime,
        auth=auth,
        token_verifier=token_verifier,
        local_file_tool=False,
        instructions=REMOTE_INSTRUCTIONS,
        hosted=True,
    )


def _register_tools(
    server: MCPServer,
    runtime: McpRuntime,
    *,
    local_file_tool: bool,
    hosted: bool,
    credential_setup: LocalCredentialSetup,
) -> None:
    """The public surface: at most three tools, and never a fourth.

    No provider-specific tool exists, because which source answers a question is
    Task 13's ranked decision and exposing one would make results depend on what
    a model happened to pick. No credential tool exists either: a secret in a
    tool argument is a secret in a conversation transcript.
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
        objective: Annotated[
            InvestigationObjective,
            Field(
                description=(
                    "What the collection stops on. triage (default) stops when "
                    "coverage is adequate for triage. corroborate spends at most "
                    "one extra round after that, seeking an adverse search from a "
                    "source family independent of the assessment's basis, if one "
                    "is eligible and the budget permits -- use it only when the "
                    "user asks to confirm, corroborate or check with another "
                    "source. It adds no depth, names no provider and never "
                    "guarantees a second source exists; a verdict alone is never "
                    "a reason to choose it."
                )
            ),
        ] = InvestigationObjective.TRIAGE,
    ) -> AnalystInvestigationReport:
        """Passive threat-intelligence investigation of one observable.

        Returns a deterministic assessment, the confidence that the assessment is
        correct, how adequate the intelligence coverage was, the supporting and
        opposing evidence, alternative explanations and related observables.

        Disclosure: the submitted observable may be sent to external
        intelligence providers configured for the caller. Provider selection is
        automatic and cannot be requested or influenced from this call, and no
        credential is ever an argument to it.

        Reading the result: `assessment_basis` is why the verdict was reached and
        `opposing_evidence` is what argued against it — keep them apart.
        `source_checks` is the only authority for which sources were actually
        consulted. `confidence` is confidence the assessment is correct, not a
        probability of maliciousness; the readiness fields describe how adequate
        the collection was, and never whether to act. Every field's exact meaning
        is in this tool's output schema.

        Anything you add from your own knowledge rather than from this report is
        yours, not TI Recon's. Label it as your own, and never present it as TI
        Recon evidence, coverage or provenance, or fold it into the assessment
        basis — a reader has to be able to tell which statements the engine
        stands behind.
        """
        return await tools.investigate_observable(
            runtime,
            observable=observable,
            observable_type=observable_type,
            depth=depth,
            pivot_mode=pivot_mode,
            allow_remote_pivot_lookup=allow_remote_pivot_lookup,
            objective=objective,
        )

    if local_file_tool:
        _register_file_tool(server, runtime)

    @server.tool(
        title="Check intelligence source setup",
        description=_provider_status_description(hosted=hosted, credential_setup=credential_setup),
        annotations=ToolAnnotations(
            # Nothing outside this process is consulted, so the world it reads
            # is closed.
            read_only_hint=True,
            open_world_hint=False,
        ),
    )
    async def provider_status() -> ProviderStatusReport:
        """See ``_provider_status_description``; the description parameter wins."""
        return await tools.provider_status(runtime)


def _provider_status_description(
    *, hosted: bool, credential_setup: LocalCredentialSetup = LocalCredentialSetup.ENVIRONMENT
) -> str:
    """What the setup diagnostic is, and what a caller may not conclude from it.

    Split by profile for one reason: the last sentence. "Configure it locally and
    reconnect" is accurate for the process an analyst started on their own
    machine and is nonsense addressed to a hosted deployment, where the caller
    has no server to edit and no restart to perform. Saying nothing is not
    neutral — a client with no statement supplies the local one. And the local
    one has two shapes: the environment the analyst owns, or the plugin
    configuration Claude Code owns and the analyst edits through the host.
    """
    shared = (
        "Which intelligence sources this installation ships, what they cover, "
        "and whether YOU have the configuration each one needs.\n\n"
        "Contacts nothing: no provider request, no network call, no credential "
        "validation. 'configured' means the credential is stored for your "
        "account — not that it is valid, that authentication would succeed, "
        "that an entitlement covers the operation, that quota remains, or that "
        "the source is healthy.\n\n"
        "This describes the installation, never what an investigation did. A "
        "source listed here was not thereby queried: what was actually "
        "consulted is the 'source_checks' section of an investigation report."
    )
    if hosted:
        return (
            f"{shared}\n\n"
            "This deployment is hosted. Self-service provider credential setup "
            "is not available in this version, so do not advise configuring a "
            "credential locally, editing a server environment variable or "
            "reconnecting. Never ask for a provider API key in the "
            "conversation: this tool accepts no credential and no other tool "
            "here does either."
        )
    if credential_setup is LocalCredentialSetup.CLAUDE_PLUGIN:
        return (
            f"{shared}\n\n"
            "This server is local to one analyst and was started by the TI Recon "
            "Claude Code plugin. Provider credentials are entered in the plugin's "
            "configuration (the /plugin menu, TI Recon, Configure), are stored by "
            "Claude Code and are read once at startup, so a newly added one "
            "appears after the server is reconnected or the session is "
            "restarted. Do not advise setting an environment variable or editing "
            "a file. Never ask for a provider API key in the conversation: this "
            "tool accepts no credential and no other tool here does either."
        )
    return (
        f"{shared}\n\n"
        "This server is local to one analyst. Provider credentials come from "
        "this machine's documented environment variables and are read once at "
        "startup, so a newly added one appears after a restart or reconnect. "
        "Never ask for a provider API key in the conversation: this tool "
        "accepts no credential and no other tool here does either."
    )


def _register_file_tool(server: MCPServer, runtime: McpRuntime) -> None:
    """The local-only tool, registered by the stdio profile alone.

    Kept as one implementation shared with :mod:`ti_recon.mcp_server.tools`; the
    deployment profile decides whether it is *registered*, which is what keeps it
    out of ``tools/list`` and out of the tool manager rather than merely out of
    the documentation.
    """

    @server.tool(
        title="Investigate a local file",
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
        meta=FILE_TOOL_META,
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
