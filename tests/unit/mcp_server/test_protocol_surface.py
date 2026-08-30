"""What a client sees, and what it must never see (Task 21).

The protocol surface is a contract in its own right: a model discovers tools
from names, descriptions and schemas, and a field appearing there is a field a
model will try to use. So these tests are as much about what is *absent* — a
provider choice, a credential, an active operation — as about what works.
"""

from __future__ import annotations

import json

import pytest
from mcp import Client

from fixtures.investigation import claim_evidence, spec
from fixtures.investigation.stack import ScriptedProvider
from fixtures.mcp_server import scripted_server
from ti_recon.enums import ProviderCapability
from ti_recon.mcp_server.server import (
    REPORT_SCHEMA_URI,
    REQUEST_SCHEMA_URI,
    SERVER_INSTRUCTIONS,
)
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.models import AnalystInvestigationReport
from ti_recon.reporting.schema import report_json_schema, request_json_schema

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64

#: The whole public surface. A fourth tool appearing here is a design decision,
#: not an accident, so the set is asserted exactly.
EXPECTED_TOOLS = {"investigate_observable", "investigate_file", "provider_status"}

INVESTIGATION_TOOLS = ("investigate_observable", "investigate_file")


async def _server():
    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    server, stack = await scripted_server([provider])
    return server, stack


@pytest.mark.asyncio
async def test_the_tool_surface_is_exactly_three_tools() -> None:
    """No provider-specific tool, and nothing registered by accident.

    A `query_virustotal` tool would put provider selection in the model's hands,
    which is Task 13's ranked decision and stays reproducible only while it is.
    """
    server, _ = await _server()

    async with Client(server) as client:
        names = {item.name for item in (await client.list_tools()).tools}

    assert names == EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_the_investigation_tools_declare_a_structured_output_schema() -> None:
    """The schema is derived from the Task 20 model, not written here.

    That is what keeps one definition of a report: there is no MCP report type
    to drift, and no hand-maintained schema to forget to update.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for name in INVESTIGATION_TOOLS:
        schema = tools[name].output_schema
        assert schema is not None, name
        # The sections a consumer integrates against.
        properties = set(schema.get("properties", {}))
        assert {
            "schema_version",
            "target",
            "assessment",
            "readiness",
            "assessment_basis",
            "opposing_evidence",
            "alternative_explanations",
            "coverage",
            "gaps",
            "related_observables",
            "source_checks",
            "investigation",
            "versions",
        } <= properties, name


@pytest.mark.asyncio
async def test_the_output_schema_matches_the_task_20_model() -> None:
    """Semantically the same document, allowing for SDK wrapping."""
    server, _ = await _server()
    canonical = report_json_schema()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}
    exposed = tools["investigate_observable"].output_schema or {}

    assert set(exposed.get("properties", {})) == set(canonical["properties"])
    assert set(exposed.get("required", [])) == set(canonical.get("required", []))


@pytest.mark.asyncio
async def test_the_input_schema_carries_the_task_20_defaults() -> None:
    """Defaults are the request model's, so a bare call behaves like a bare CLI run.

    A model reading the schema must see the same conservative defaults: normal
    depth, related observables recorded rather than queried, and no external
    disclosure of anything the analyst did not submit.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}
    properties = (tools["investigate_observable"].input_schema)["properties"]

    assert properties["observable_type"]["default"] == "auto"
    assert properties["depth"]["default"] == "standard"
    assert properties["pivot_mode"]["default"] == "recommend"
    assert properties["allow_remote_pivot_lookup"]["default"] is False
    assert "observable" in tools["investigate_observable"].input_schema["required"]


@pytest.mark.asyncio
async def test_the_annotations_are_read_only_and_nothing_more() -> None:
    """Hints that describe the tool, not hints filled in for completeness.

    ``destructive`` and ``idempotent`` are meaningful for tools that write.
    Setting them on a read-only tool says nothing and invites a reader to think
    it was considered.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for name in INVESTIGATION_TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.read_only_hint is True
        # Reaches external intelligence services.
        assert annotations.open_world_hint is True
        assert annotations.destructive_hint is None
        assert annotations.idempotent_hint is None

    status = tools["provider_status"].annotations
    assert status is not None
    assert status.read_only_hint is True
    # Consults nothing outside this process.
    assert status.open_world_hint is False


# --------------------------------------------------------------------------- #
# What must never be in the input surface
# --------------------------------------------------------------------------- #


def _field_names(schema: dict[str, object]) -> set[str]:
    """Every property name in an input schema, at any depth.

    Names rather than the whole document: a *description* explaining that
    providers are chosen automatically, or that a file is not submitted, is the
    tool telling the truth about itself. What must not exist is a field a model
    could fill in.
    """
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                found.update(str(key).lower() for key in properties)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    return found


def _enum_values(schema: dict[str, object]) -> set[str]:
    """Every accepted enum value, so a provider id cannot arrive as one."""
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            values = node.get("enum")
            if isinstance(values, list):
                found.update(str(item).lower() for item in values)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    return found


@pytest.mark.asyncio
async def test_no_investigation_input_can_name_a_provider() -> None:
    """Provider selection stays Task 13's.

    ``provider_status`` *output* naturally names providers — that is provenance.
    An investigation *input* naming one would let results depend on what a model
    happened to pick.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for name in INVESTIGATION_TOOLS:
        schema = tools[name].input_schema
        surface = _field_names(schema) | _enum_values(schema)
        for forbidden in (
            "provider",
            "providers",
            "preferred_provider",
            "skip_provider",
            "virustotal",
            "gti",
            "greynoise",
            "urlscan",
            "threatfox",
            "urlhaus",
            "malwarebazaar",
            "censys",
            "hybrid_analysis",
        ):
            assert not any(forbidden in item for item in surface), f"{name}: {forbidden}"


@pytest.mark.asyncio
async def test_no_input_can_carry_a_credential() -> None:
    """A secret must not be something a model can pass.

    Credentials are resolved per user by the credential layer. A field here
    would put one in a conversation transcript.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for tool in tools.values():
        surface = _field_names(tool.input_schema) | _enum_values(tool.input_schema)
        for forbidden in (
            "api_key",
            "apikey",
            "token",
            "credential",
            "auth_key",
            "authorization",
            "password",
            "secret",
        ):
            assert not any(forbidden in item for item in surface), f"{tool.name}: {forbidden}"


@pytest.mark.asyncio
async def test_no_input_can_request_an_active_operation() -> None:
    """Task 21 is passive investigation. Nothing submits, detonates or downloads."""
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for tool in tools.values():
        surface = _field_names(tool.input_schema) | _enum_values(tool.input_schema)
        for forbidden in (
            "submit",
            "detonate",
            "rescan",
            "upload",
            "download",
            "fetch_payload",
            "active_scan",
        ):
            assert not any(forbidden in item for item in surface), f"{tool.name}: {forbidden}"


@pytest.mark.asyncio
async def test_no_input_can_choose_the_principal() -> None:
    """Identity is the process's, never the caller's.

    A model-supplied user id would let one conversation read another's cached
    results and spend their quota — which is exactly what the execution scope
    exists to prevent.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    for tool in tools.values():
        surface = _field_names(tool.input_schema)
        for forbidden in ("user_id", "authenticated_user", "execution_scope", "principal"):
            assert not any(forbidden in item for item in surface), f"{tool.name}: {forbidden}"


# --------------------------------------------------------------------------- #
# Resources
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_only_the_two_public_schemas_are_exposed() -> None:
    """No internal result, planner state, graph dump or configuration."""
    server, _ = await _server()

    async with Client(server) as client:
        uris = {str(item.uri) for item in (await client.list_resources()).resources}

    assert uris == {REQUEST_SCHEMA_URI, REPORT_SCHEMA_URI}


@pytest.mark.asyncio
async def test_the_schema_resources_serve_task_20s_own_documents() -> None:
    """Read back and compared against the generators, not against a copy."""
    server, _ = await _server()

    async with Client(server) as client:
        report = await client.read_resource(REPORT_SCHEMA_URI)
        request = await client.read_resource(REQUEST_SCHEMA_URI)

    served_report = json.loads(report.contents[0].text)
    served_request = json.loads(request.contents[0].text)

    assert served_report == report_json_schema()
    assert served_request == request_json_schema()
    assert served_report["$schema"].startswith("https://json-schema.org/draft/")
    assert AnalystInvestigationReport.__name__ in served_report["title"]


@pytest.mark.asyncio
async def test_the_server_instructions_stay_short_and_say_the_two_hard_parts() -> None:
    """Discovery terms first; the two things a caller gets wrong without being told.

    Detailed analyst procedure belongs in a Skill. A large instruction block
    would compete with it and go stale.
    """
    assert len(SERVER_INSTRUCTIONS.encode()) < 2048
    lowered = SERVER_INSTRUCTIONS.lower()
    assert "provider selection is automatic" in lowered
    assert "never votes" in lowered
    # Local transport is not offline collection.
    assert "does not make collection local" in lowered


# --------------------------------------------------------------------------- #
# Human approval for local file access
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_only_the_file_tool_asks_the_host_for_human_approval() -> None:
    """Reading a file off somebody's disk deserves its own beat.

    Claude Code reads this key and prompts on every call, including where an
    allow rule would otherwise match — which is exactly the case worth
    protecting: a standing yes to investigating observables must not become a
    standing yes to opening local files.

    The other two tools do not carry it, because asking for approval where none
    is warranted trains a user to click through the ones that are.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}

    assert tools["investigate_file"].meta == {"anthropic/requiresUserInteraction": True}
    assert tools["investigate_observable"].meta is None
    assert tools["provider_status"].meta is None


@pytest.mark.asyncio
async def test_the_approval_key_reaches_the_wire_as_meta() -> None:
    """It has to survive serialization to do anything.

    A host reads ``_meta`` off the tool description; a key that only existed on
    the Python object would be advisory to nobody.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}
    wire = tools["investigate_file"].model_dump(mode="json", by_alias=True)

    assert wire["_meta"] == {"anthropic/requiresUserInteraction": True}


@pytest.mark.asyncio
async def test_consent_is_never_something_the_model_can_assert() -> None:
    """No ``user_confirmed`` argument, because the model would set it.

    Human approval belongs to the host, which can actually ask a human.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}
    surface = _field_names(tools["investigate_file"].input_schema)

    for forbidden in ("confirm", "consent", "approved", "acknowledged"):
        assert not any(forbidden in item for item in surface), forbidden


@pytest.mark.asyncio
async def test_the_metadata_changed_nothing_else_about_the_tool() -> None:
    """Annotations, schemas and the description are untouched.

    A permission hint must not quietly alter the contract a consumer already
    integrated against.
    """
    server, _ = await _server()

    async with Client(server) as client:
        tools = {item.name: item for item in (await client.list_tools()).tools}
    tool = tools["investigate_file"]

    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is True
    assert set(tool.input_schema["properties"]) == {
        "path",
        "depth",
        "pivot_mode",
        "allow_remote_pivot_lookup",
    }
    assert tool.output_schema == tools["investigate_observable"].output_schema
    # The wording that carries the real boundary is still there.
    description = (tool.description or "").lower()
    assert "locally" in description
    assert "not uploaded" in description or "never uploaded" in description
    assert "detonation" in description
