"""The path a plugin option takes to the credential resolver, and nowhere else.

Proved twice. In process, through the same composition function the server
calls, so the assertion is about the *existing* credential layer: the option
lands in the connection repository under the group the repository already
defines, the resolver hands it back, and an omitted option leaves its group
unconfigured. Then out of process, against the installed ``ti-recon-mcp`` entry
point started exactly as the plugin starts it — a fresh interpreter, the
plugin's environment mapping, MCP over stdio — so the proof covers the process
boundary the host actually crosses.

Nothing is investigated: ``provider_status`` contacts no provider, and it is
what shows whether a credential is stored. The sentinels are fake, unmistakable,
and asserted absent from every surface a model, a log or a person could read.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client

from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT, build_default_application
from ti_recon.credentials import (
    CredentialNotConfigured,
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.mcp_server.runtime import STDIO_PRINCIPAL, build_stdio_runtime
from ti_recon.mcp_server.server import LocalCredentialSetup, build_stdio_server
from ti_recon.providers.catalog import build_default_adapters

from .support import PLUGIN_SKILL, host_environment

#: Fake. Unmistakable, so a match in any output cannot be a coincidence.
SENTINEL_VT = "PLUGIN_SENTINEL_VIRUSTOTAL_KEY_7f3a"
SENTINEL_CENSYS = "PLUGIN_SENTINEL_CENSYS_PAT_9c1d"
SENTINEL_ORG = "PLUGIN_SENTINEL_CENSYS_ORG_0042"
SENTINELS = (SENTINEL_VT, SENTINEL_CENSYS, SENTINEL_ORG)

#: What the analyst entered. Everything else is left empty on purpose.
CONFIGURED = {
    "virustotal_api_key": SENTINEL_VT,
    "censys_pat": SENTINEL_CENSYS,
    "censys_organization_id": SENTINEL_ORG,
}

CONFIGURED_GROUPS = frozenset({"virustotal", "censys"})


def _credentialled_groups() -> set[str]:
    return {
        adapter.descriptor.credential_group
        for adapter in build_default_adapters()
        if adapter.descriptor.requires_credentials
    }


def _skill_corpus() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(PLUGIN_SKILL.rglob("*.md"))
    )


# --------------------------------------------------------------------------- #
# In process: the existing credential layer
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_configured_option_reaches_the_existing_resolver_by_group() -> None:
    """Through ``build_default_application`` — the server's own composition."""
    secrets, connections = InMemorySecretStore(), InMemoryConnectionRepository()

    _, report = await build_default_application(
        user_id=STDIO_PRINCIPAL,
        environment=host_environment(CONFIGURED),
        secrets=secrets,
        connections=connections,
    )
    assert report.configured_groups == CONFIGURED_GROUPS

    resolver = CredentialResolver(secrets, connections)
    material = await resolver.resolve(authenticated_user_id=STDIO_PRINCIPAL, provider_id="gti")
    assert material.credential_group == "virustotal"
    assert material.reveal() == SENTINEL_VT

    censys = await resolver.resolve_connection(
        authenticated_user_id=STDIO_PRINCIPAL, provider_id="censys"
    )
    assert censys is not None
    # The non-secret option lands where the deployment model keeps it.
    assert censys.metadata == {"organization_id": SENTINEL_ORG}


@pytest.mark.asyncio
async def test_an_omitted_option_leaves_its_group_not_configured() -> None:
    """The host substitutes the empty string, and an empty value is no credential.

    No boundary change was needed for that: the loader already skips a blank
    variable. This pins the property the plugin relies on.
    """
    secrets, connections = InMemorySecretStore(), InMemoryConnectionRepository()
    await build_default_application(
        user_id=STDIO_PRINCIPAL,
        environment=host_environment(CONFIGURED),
        secrets=secrets,
        connections=connections,
    )
    resolver = CredentialResolver(secrets, connections)

    for group in sorted(_credentialled_groups() - CONFIGURED_GROUPS):
        assert await connections.find_by_group(STDIO_PRINCIPAL, group) is None, group
    with pytest.raises(CredentialNotConfigured):
        await resolver.resolve(authenticated_user_id=STDIO_PRINCIPAL, provider_id="urlscan")
    assert not await resolver.has_credential(
        authenticated_user_id=STDIO_PRINCIPAL, provider_id="threatfox"
    )
    assert len(secrets) == len(CONFIGURED_GROUPS), "no empty secret was stored"


@pytest.mark.asyncio
async def test_the_environment_mapping_covers_every_group_and_nothing_else() -> None:
    """The plugin feeds exactly the variables the loader reads, by group."""
    environment = host_environment(CONFIGURED)
    for group in _credentialled_groups():
        assert CREDENTIAL_ENVIRONMENT[group] in environment, group
    credential_variables = set(CREDENTIAL_ENVIRONMENT.values())
    assert credential_variables <= set(environment)


# --------------------------------------------------------------------------- #
# In process: the MCP surface the plugin serves
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_provider_status_reports_configured_per_group_and_leaks_nothing(
    monkeypatch, caplog
) -> None:
    """The real stdio runtime builder, reading the environment the host set."""
    for variable in CREDENTIAL_ENVIRONMENT.values():
        monkeypatch.delenv(variable, raising=False)
    for variable, value in host_environment(CONFIGURED).items():
        monkeypatch.setenv(variable, value)
    caplog.set_level(logging.DEBUG, logger="ti_recon")

    runtime = await build_stdio_runtime()
    assert runtime.credentials.configured_groups == CONFIGURED_GROUPS
    server = build_stdio_server(runtime, credential_setup=LocalCredentialSetup.CLAUDE_PLUGIN)

    async with Client(server) as client:
        instructions = client.instructions or ""
        listing = [item.model_dump(mode="json") for item in (await client.list_tools()).tools]
        status = await client.call_tool("provider_status", {})

    assert {item["name"] for item in listing} == {
        "investigate_observable",
        "investigate_file",
        "provider_status",
    }
    configured = {
        item["provider_id"]: item["configured"] for item in status.structured_content["providers"]
    }
    assert configured["gti"] is True
    assert configured["censys"] is True
    assert configured["misp_warninglists"] is True, "credential-free is always configured"
    for provider in ("urlscan", "greynoise", "hybrid_analysis", "threatfox", "urlhaus"):
        assert configured[provider] is False, provider

    surfaces = "\n".join(
        [
            instructions,
            json.dumps(listing),
            json.dumps(status.structured_content),
            " ".join(item.text or "" for item in status.content),
            caplog.text,
            _skill_corpus(),
        ]
    )
    for sentinel in SENTINELS:
        assert sentinel not in surfaces, sentinel


# --------------------------------------------------------------------------- #
# Out of process: the installed entry point, started as the plugin starts it
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_server_process_receives_the_plugin_environment(tmp_path: Path) -> None:
    """A fresh interpreter, the plugin's mapping, MCP over stdio.

    The command is the console entry point's own function, so this is the
    process a host starts. Its stderr is captured to a file and searched, with
    logging at DEBUG, because a log line is the leak this layer would be most
    likely to produce.
    """
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in set(CREDENTIAL_ENVIRONMENT.values()) | {"CENSYS_ORGANIZATION_ID"}
    }
    environment.update(host_environment(CONFIGURED))
    environment["TI_RECON_LOG_LEVEL"] = "DEBUG"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from ti_recon.mcp_server.main import main; main()"],
        env=environment,
    )
    stderr_path = tmp_path / "server-stderr.txt"

    with stderr_path.open("w", encoding="utf-8") as stderr:
        async with Client(stdio_client(parameters, errlog=stderr)) as client:
            instructions = client.instructions or ""
            tools = {item.name: item for item in (await client.list_tools()).tools}
            status = await client.call_tool("provider_status", {})

    assert "plugin" in instructions.lower()
    assert set(tools) == {"investigate_observable", "investigate_file", "provider_status"}
    assert tools["investigate_file"].meta == {"anthropic/requiresUserInteraction": True}
    configured = {
        item["provider_id"]: item["configured"] for item in status.structured_content["providers"]
    }
    assert configured["gti"] is True
    assert configured["urlscan"] is False

    captured = stderr_path.read_text(encoding="utf-8")
    everything = "\n".join(
        [instructions, json.dumps(status.structured_content), captured]
        + [json.dumps(item.model_dump(mode="json")) for item in tools.values()]
    )
    for sentinel in SENTINELS:
        assert sentinel not in everything, sentinel
