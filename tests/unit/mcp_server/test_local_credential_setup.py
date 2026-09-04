"""The two local credential-setup profiles, and the process switch between them.

A local stdio server always reads credentials from its own environment. What
differs is who put them there — the analyst, or Claude Code from the plugin's
configuration — and therefore what an analyst has to do to add one. That
sentence is the only thing the profile changes: same tools, same resolution,
same everything else, asserted here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp import Client

from ti_recon.application.composition import CredentialLoadReport
from ti_recon.credentials import InMemoryConnectionRepository
from ti_recon.mcp_server import main as entry_point
from ti_recon.mcp_server.runtime import STDIO_PRINCIPAL, FixedPrincipal, McpRuntime
from ti_recon.mcp_server.server import (
    PLUGIN_INSTRUCTIONS,
    REMOTE_INSTRUCTIONS,
    SERVER_INSTRUCTIONS,
    STDIO_INSTRUCTIONS,
    LocalCredentialSetup,
    build_stdio_server,
)

SRC = Path("src/ti_recon")


def _runtime() -> McpRuntime:
    return McpRuntime(
        application=object(),  # type: ignore[arg-type]
        credentials=CredentialLoadReport(),
        connections=InMemoryConnectionRepository(),
        principals=FixedPrincipal(STDIO_PRINCIPAL),
    )


async def _surface(setup: LocalCredentialSetup) -> tuple[str, dict[str, str], set[str]]:
    server = build_stdio_server(_runtime(), credential_setup=setup)
    async with Client(server) as client:
        instructions = client.instructions or ""
        tools = (await client.list_tools()).tools
    descriptions = {item.name: (item.description or "").lower() for item in tools}
    return instructions.lower(), descriptions, {item.name for item in tools}


@pytest.mark.asyncio
async def test_the_plugin_profile_states_the_plugin_setup_step() -> None:
    """A plugin user pointed at an environment variable would set one the
    plugin overwrites."""
    instructions, descriptions, _ = await _surface(LocalCredentialSetup.CLAUDE_PLUGIN)

    for text in (instructions, descriptions["provider_status"]):
        assert "plugin's configuration" in text
        assert "/plugin" in text
        # The environment profile's advice, absent — not merely the words.
        assert "documented environment variables" not in text
        assert "come from this machine" not in text
        assert "reconnect" in text
        assert "never ask" in text
        assert "not available in this version" not in text


@pytest.mark.asyncio
async def test_the_environment_profile_is_unchanged() -> None:
    instructions, descriptions, _ = await _surface(LocalCredentialSetup.ENVIRONMENT)

    assert instructions == STDIO_INSTRUCTIONS.lower()
    assert "environment variables" in descriptions["provider_status"]
    assert "plugin" not in descriptions["provider_status"]


@pytest.mark.asyncio
async def test_the_default_is_the_environment_profile() -> None:
    server = build_stdio_server(_runtime())
    async with Client(server) as client:
        assert client.instructions == STDIO_INSTRUCTIONS


@pytest.mark.asyncio
@pytest.mark.parametrize("setup", list(LocalCredentialSetup))
async def test_both_local_profiles_share_the_core_and_the_tool_surface(setup) -> None:
    instructions, _, names = await _surface(setup)
    assert SERVER_INSTRUCTIONS.lower() in instructions
    assert names == {"investigate_observable", "investigate_file", "provider_status"}


def test_the_plugin_instructions_are_the_stdio_ones_with_a_different_setup_step() -> None:
    assert PLUGIN_INSTRUCTIONS.startswith(SERVER_INSTRUCTIONS)
    assert STDIO_INSTRUCTIONS.startswith(SERVER_INSTRUCTIONS)
    assert PLUGIN_INSTRUCTIONS != STDIO_INSTRUCTIONS


def test_the_profile_never_reaches_credential_resolution() -> None:
    """It selects text. Resolution is identical, and nothing below reads it."""
    for path in sorted(SRC.rglob("*.py")):
        if "mcp_server" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert "LocalCredentialSetup" not in text, path
        assert entry_point.CREDENTIAL_SETUP_ENV not in text, path


# --------------------------------------------------------------------------- #
# The process switch
# --------------------------------------------------------------------------- #


def test_an_absent_switch_means_the_environment_profile(monkeypatch) -> None:
    monkeypatch.delenv(entry_point.CREDENTIAL_SETUP_ENV, raising=False)
    assert entry_point._credential_setup() is LocalCredentialSetup.ENVIRONMENT
    monkeypatch.setenv(entry_point.CREDENTIAL_SETUP_ENV, "   ")
    assert entry_point._credential_setup() is LocalCredentialSetup.ENVIRONMENT


def test_the_plugin_sets_the_switch_to_the_plugin_profile(monkeypatch) -> None:
    monkeypatch.setenv(entry_point.CREDENTIAL_SETUP_ENV, "claude-plugin")
    assert entry_point._credential_setup() is LocalCredentialSetup.CLAUDE_PLUGIN


def test_an_unrecognised_switch_refuses_to_start_without_echoing_it(monkeypatch, capsys) -> None:
    """Fail closed before the transport opens, on stderr, naming the variable."""
    monkeypatch.setenv(entry_point.CREDENTIAL_SETUP_ENV, "BOGUS_PROFILE_VALUE")
    with pytest.raises(SystemExit) as raised:
        entry_point._credential_setup()
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert entry_point.CREDENTIAL_SETUP_ENV in captured.err
    assert "claude-plugin" in captured.err
    assert "BOGUS_PROFILE_VALUE" not in captured.err


# --------------------------------------------------------------------------- #
# The host's instruction budget
# --------------------------------------------------------------------------- #


#: Measured, not documented: Claude Code 2.1.259 logs "Server instructions
#: truncated from N to 2048 chars" at debug level and keeps the first 2048.
CLAUDE_CODE_INSTRUCTION_LIMIT = 2048


@pytest.mark.parametrize(
    "instructions",
    [STDIO_INSTRUCTIONS, PLUGIN_INSTRUCTIONS, REMOTE_INSTRUCTIONS],
    ids=["stdio", "plugin", "remote"],
)
def test_every_profile_fits_the_hosts_instruction_limit(instructions: str) -> None:
    """The deployment addendum is last, so it is what a truncation would cut.

    Found by the plugin host proof: the plugin profile's setup sentence never
    reached the model, and neither did the stdio or hosted one — each profile
    was over the limit by exactly its addendum.
    """
    assert len(instructions) <= CLAUDE_CODE_INSTRUCTION_LIMIT, len(instructions)
    assert len(instructions.encode()) <= CLAUDE_CODE_INSTRUCTION_LIMIT
