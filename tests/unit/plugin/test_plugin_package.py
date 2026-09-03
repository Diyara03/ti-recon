"""The Claude Code plugin as a distribution artifact (Task 23, Phase 1).

The plugin is a *packaging* of things the repository already has — the local
MCP server and the analyst Skill — plus the declaration of how an analyst's
provider credentials reach that server. So what a test can hold is structural:
the manifest the host reads, the credential mapping it substitutes, the Skill
copy it carries, and the absence of anything that must not be in a distributed
directory. Prose is not asserted; the distinctions are.

Where a check needs the real host, it runs ``claude plugin validate`` and skips
where the CLI is not installed. The interactive proof — the plugin loaded with
``--plugin-dir`` and driven through a session — is recorded in
``docs/claude-plugin.md`` rather than automated, because it needs a model.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from ti_recon import __version__
from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT
from ti_recon.credentials import ABUSE_CH_GROUP, providers_in_group
from ti_recon.mcp_server.main import CREDENTIAL_SETUP_ENV
from ti_recon.mcp_server.server import LocalCredentialSetup
from ti_recon.providers.catalog import build_default_adapters

from .support import (
    CANONICAL_SKILL,
    LAUNCHER,
    MANIFEST,
    MCP_CONFIG,
    PLUGIN,
    PLUGIN_SKILL,
    ROOT,
    SERVER_NAME,
    env_mapping,
    load_tool,
    manifest,
    mcp_config,
    option_for,
    plugin_files,
    server_config,
)

#: The manifest fields Claude Code 2.1.259 documents. Anything else is a typo
#: the host would only warn about.
KNOWN_MANIFEST_FIELDS = {
    "name",
    "displayName",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "metadata",
    "defaultEnabled",
    "skills",
    "commands",
    "agents",
    "hooks",
    "mcpServers",
    "lspServers",
    "outputStyles",
    "userConfig",
    "experimental",
}

#: The ``userConfig`` schema fields the host documents.
KNOWN_OPTION_FIELDS = {
    "type",
    "title",
    "description",
    "sensitive",
    "required",
    "default",
    "multiple",
    "min",
    "max",
}

#: The one non-secret option, and the variable it feeds.
NON_SECRET_OPTIONS = {"censys_organization_id": "CENSYS_ORGANIZATION_ID"}


def _credentialled_groups() -> set[str]:
    return {
        adapter.descriptor.credential_group
        for adapter in build_default_adapters()
        if adapter.descriptor.requires_credentials
    }


# --------------------------------------------------------------------------- #
# Layout the host depends on
# --------------------------------------------------------------------------- #


def test_the_manifest_lives_where_the_host_looks_and_holds_only_itself() -> None:
    """``.claude-plugin/`` is for the manifest; components live beside it."""
    assert MANIFEST.is_file()
    assert [path.name for path in (PLUGIN / ".claude-plugin").iterdir()] == ["plugin.json"]
    assert (PLUGIN_SKILL / "SKILL.md").is_file()
    assert MCP_CONFIG.is_file()


def test_the_manifest_names_the_plugin_and_uses_only_documented_fields() -> None:
    data = manifest()
    assert data["name"] == "ti-recon"
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", data["name"])
    assert data["version"] == __version__, "the plugin version tracks the package version"
    assert data["description"]
    unknown = set(data) - KNOWN_MANIFEST_FIELDS
    assert unknown == set(), unknown


def test_components_are_discovered_from_default_locations() -> None:
    """No path overrides: the layout *is* the default, so nothing can point elsewhere."""
    data = manifest()
    for field in ("skills", "commands", "agents", "hooks", "mcpServers", "lspServers"):
        assert field not in data, field
    assert not (PLUGIN / "hooks").exists()
    assert not (PLUGIN / "agents").exists()
    assert not (PLUGIN / "commands").exists()


# --------------------------------------------------------------------------- #
# The credential mapping
# --------------------------------------------------------------------------- #


def test_every_credentialled_group_has_exactly_one_sensitive_optional_option() -> None:
    """One option per *group*, so the analyst is asked for a shared key once.

    Derived from the shipped adapters and the repository's own variable names:
    the plugin restates neither, it maps onto them.
    """
    options = manifest()["userConfig"]
    by_variable = env_mapping()

    for group in sorted(_credentialled_groups()):
        variable = CREDENTIAL_ENVIRONMENT[group]
        assert variable in by_variable, f"{group}: no plugin option feeds {variable}"
        option = options[by_variable[variable]]
        assert option["type"] == "string", group
        assert option.get("sensitive") is True, f"{group}: credential must be sensitive"
        assert option.get("required", False) is False, f"{group}: credentials are optional"
        assert "default" not in option, f"{group}: a credential has no default"
        feeders = [name for name, opt in by_variable.items() if name == variable]
        assert len(feeders) == 1, f"{group}: {variable} fed by more than one option"


def test_the_shared_abusech_key_is_asked_for_once_and_named_for_all_three() -> None:
    variable = CREDENTIAL_ENVIRONMENT[ABUSE_CH_GROUP]
    feeders = [option for var, option in env_mapping().items() if var == variable]
    assert len(feeders) == 1
    description = manifest()["userConfig"][feeders[0]]["description"].lower()
    for provider in providers_in_group(ABUSE_CH_GROUP):
        assert provider in description, provider


def test_non_secret_configuration_is_not_marked_sensitive() -> None:
    """Secure storage is a shared, bounded budget; only secrets belong there."""
    options = manifest()["userConfig"]
    mapping = env_mapping()
    for name, variable in NON_SECRET_OPTIONS.items():
        assert mapping[variable] == name
        assert options[name].get("sensitive", False) is False, name
        assert options[name].get("required", False) is False, name


def test_every_option_is_consumed_and_every_substitution_is_declared() -> None:
    """A declared option nothing reads is a prompt for nothing; an undeclared
    reference substitutes to nothing."""
    declared = set(manifest()["userConfig"])
    referenced = set(env_mapping().values())
    assert declared == referenced


def test_each_option_uses_only_documented_schema_fields() -> None:
    for name, option in manifest()["userConfig"].items():
        unknown = set(option) - KNOWN_OPTION_FIELDS
        assert unknown == set(), f"{name}: {unknown}"
        for required in ("type", "title", "description"):
            assert option.get(required), f"{name}: {required}"


def test_the_sensitive_footprint_stays_small() -> None:
    """Secure storage is ~2 KB shared with OAuth tokens.

    The count is what this layer controls: one sensitive option per credential
    group, no more. Value lengths are the providers' and are estimated in
    ``docs/claude-plugin.md``.
    """
    sensitive = [n for n, o in manifest()["userConfig"].items() if o.get("sensitive")]
    assert len(sensitive) == len(_credentialled_groups())


# --------------------------------------------------------------------------- #
# The MCP server declaration
# --------------------------------------------------------------------------- #


def test_the_plugin_declares_one_stdio_server_started_from_the_bundled_launcher() -> None:
    servers = mcp_config()["mcpServers"]
    assert list(servers) == [SERVER_NAME]
    server = server_config()
    assert server["command"] == "${CLAUDE_PLUGIN_ROOT}/bin/ti-recon-mcp"
    assert "url" not in server, "the plugin is local stdio, never HTTP"
    assert "args" not in server or server["args"] == []


def test_the_server_is_told_its_credentials_came_from_the_plugin() -> None:
    """So the client hears the plugin setup step and not the environment one."""
    env = server_config()["env"]
    assert env[CREDENTIAL_SETUP_ENV] == LocalCredentialSetup.CLAUDE_PLUGIN.value


def test_options_travel_only_through_the_environment() -> None:
    """Never a command-line argument: those are visible in a process listing."""
    server = server_config()
    assert option_for(server["command"]) is None
    for arg in server.get("args", []):
        assert "${user_config" not in arg, arg


def test_the_environment_names_only_variables_the_repository_documents() -> None:
    documented = {
        line.split("=", 1)[0].strip()
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    for variable in server_config()["env"]:
        assert variable in documented, variable


# --------------------------------------------------------------------------- #
# What must not be in the plugin
# --------------------------------------------------------------------------- #


def test_no_sensitive_value_is_ever_substituted_into_skill_content() -> None:
    """The host substitutes non-sensitive ``${user_config.*}`` into Skills.

    So the only safe reference count in Skill content is zero — a future edit
    that pasted one in would put a value into model context.
    """
    for path, text in plugin_files().items():
        if path.suffix == ".md":
            assert "${user_config" not in text, path


def test_no_distribution_file_holds_a_secret_shaped_value() -> None:
    for path, text in plugin_files().items():
        for pattern in (
            r"api[_-]?key\s*[=:]\s*\S{8,}",
            r"auth[_-]?key\s*[=:]\s*\S{8,}",
            r"token\s*[=:]\s*\S{8,}",
            r"\b[A-Fa-f0-9]{64}\b",
        ):
            assert not re.search(pattern, text, re.IGNORECASE), f"{path}: {pattern}"
    for name, option in manifest()["userConfig"].items():
        assert "default" not in option or not option.get("sensitive"), name


def test_the_committed_plugin_references_no_checkout_and_no_absolute_path() -> None:
    """Installed elsewhere, an absolute path points at nothing or at the wrong thing."""
    build = load_tool("build_dev_plugin")
    for path, text in plugin_files().items():
        for forbidden in ("/home/", "/Users/", "/tmp/", "C:\\", ".venv", build.MARKER):
            assert forbidden not in text, f"{path}: {forbidden}"
    assert not (PLUGIN / "NON_DISTRIBUTABLE").exists()


def test_the_plugin_references_no_remote_authentication() -> None:
    """The plugin is the local, single-analyst path. Task 22 is a different surface."""
    forbidden = (
        "jwt",
        "jwks",
        "oauth",
        "auth0",
        "http_main",
        "ti-recon-mcp-http",
        "token_verifier",
        "tokenverifier",
        "tenant-v1",
        "resource server",
        "onrender",
    )
    for path, text in plugin_files().items():
        lowered = text.lower()
        for term in forbidden:
            assert term not in lowered, f"{path}: {term}"


def test_the_core_knows_nothing_about_the_plugin() -> None:
    """Distribution sits above the engine; nothing in the package reads it.

    The one plugin-aware value in ``src`` is the credential-setup profile the
    MCP entry point reads to choose instruction text, and that stays in
    ``mcp_server``.
    """
    for path in sorted((ROOT / "src" / "ti_recon").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "user_config", "plugins/"):
            assert forbidden not in text, f"{path}: {forbidden}"
        if "mcp_server" not in path.parts:
            assert "claude-plugin" not in text, path
            assert "LocalCredentialSetup" not in text, path


# --------------------------------------------------------------------------- #
# The launcher
# --------------------------------------------------------------------------- #


def _run_launcher(
    root: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ.get("PATH", "")}
    if env:
        environment.update(env)
    return subprocess.run(
        ["sh", str(root / "bin" / "ti-recon-mcp")],
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_the_launcher_is_executable_and_fails_closed_with_a_clean_stdout(tmp_path) -> None:
    """No bundled runtime means no server — and nothing on the protocol stream."""
    assert LAUNCHER.stat().st_mode & stat.S_IXUSR
    result = _run_launcher(PLUGIN, env={"CLAUDE_PLUGIN_ROOT": str(tmp_path)})
    assert result.returncode == 1
    assert result.stdout == b"", "stdout belongs to MCP; a message there corrupts the stream"
    assert b"runtime" in result.stderr


def test_the_launcher_finds_its_root_without_the_host_variable(tmp_path) -> None:
    copy = tmp_path / "ti-recon"
    shutil.copytree(PLUGIN, copy)
    result = _run_launcher(copy)
    assert result.returncode == 1
    assert result.stdout == b""


def test_the_launcher_runs_only_a_runtime_bundled_under_the_plugin_root(tmp_path) -> None:
    """One location, no override: a runtime that is present is exec'd; nothing
    else is searched."""
    bundled = tmp_path / "runtime" / "bin" / "ti-recon-mcp"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("#!/bin/sh\nprintf 'BUNDLED-RUNTIME-STARTED'\n", encoding="utf-8")
    bundled.chmod(0o755)

    result = _run_launcher(PLUGIN, env={"CLAUDE_PLUGIN_ROOT": str(tmp_path)})

    assert result.returncode == 0
    assert result.stdout == b"BUNDLED-RUNTIME-STARTED"

    text = LAUNCHER.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert code.count("exec ") == 1
    assert "runtime/bin/ti-recon-mcp" in code
    # No development escape hatch: nothing but the plugin root decides the target.
    for forbidden in ("TI_RECON_MCP", "$PATH", "command -v", "which ", "python", "uv "):
        assert forbidden not in code, forbidden


# --------------------------------------------------------------------------- #
# The Skill copy
# --------------------------------------------------------------------------- #


def test_the_plugin_skill_is_byte_identical_to_the_canonical_skill() -> None:
    """One source. The copy exists because the plugin cache cannot follow a
    symlink; it is regenerated, never edited."""
    sync = load_tool("sync_plugin_skill")
    assert sync.SOURCE == CANONICAL_SKILL
    assert sync.TARGET == PLUGIN_SKILL
    assert sync.differences() == []


def test_the_sync_tool_reports_drift_and_repairs_it(tmp_path) -> None:
    sync = load_tool("sync_plugin_skill")
    source = tmp_path / "source"
    target = tmp_path / "target"
    shutil.copytree(CANONICAL_SKILL, source)
    shutil.copytree(CANONICAL_SKILL, target)
    (target / "SKILL.md").write_text("edited in the wrong place\n", encoding="utf-8")
    (target / "stray.md").write_text("should not exist\n", encoding="utf-8")
    (source / "references" / "new.md").write_text("added at the source\n", encoding="utf-8")

    problems = sync.differences(source, target)
    assert any("differs: SKILL.md" in p for p in problems)
    assert any("stray.md" in p for p in problems)
    assert any("missing from plugin: references/new.md" in p for p in problems)

    sync.write(source, target)
    assert sync.differences(source, target) == []


def test_the_plugin_skill_keeps_the_structure_the_host_needs() -> None:
    skill = (PLUGIN_SKILL / "SKILL.md").read_text(encoding="utf-8")
    header = re.match(r"^---\n(.*?)\n---\n", skill, re.DOTALL)
    assert header
    assert "name: ti-recon-analyst" in header.group(1)
    assert "allowed-tools" not in header.group(1)
    for name in set(re.findall(r"references/([a-z-]+\.md)", skill)):
        assert (PLUGIN_SKILL / "references" / name).is_file(), name


# --------------------------------------------------------------------------- #
# The developer proof is a different artifact
# --------------------------------------------------------------------------- #


def test_the_dev_build_is_marked_non_distributable_everywhere(tmp_path) -> None:
    build = load_tool("build_dev_plugin")
    fake_server = tmp_path / "checkout" / ".venv" / "bin" / "ti-recon-mcp"
    fake_server.parent.mkdir(parents=True)
    fake_server.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    out = build.build(tmp_path / "out" / "ti-recon", server=fake_server)

    assert (out / "NON_DISTRIBUTABLE").is_file()
    assert build.MARKER in (out / "NON_DISTRIBUTABLE").read_text(encoding="utf-8")
    generated = json.loads((out / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert generated["description"].startswith(build.MARKER)
    assert generated["name"] == "ti-recon", "same namespace as the real plugin"
    launcher = (out / "bin" / "ti-recon-mcp").read_text(encoding="utf-8")
    assert build.MARKER in launcher
    assert str(fake_server) in launcher
    # Everything else is the committed plugin, unchanged.
    assert (out / ".mcp.json").read_bytes() == MCP_CONFIG.read_bytes()
    sync = load_tool("sync_plugin_skill")
    assert sync.differences(PLUGIN_SKILL, out / "skills" / "ti-recon-analyst") == []


def test_the_dev_build_refuses_to_run_without_a_development_server(tmp_path) -> None:
    build = load_tool("build_dev_plugin")
    with pytest.raises(FileNotFoundError):
        build.build(tmp_path / "out", server=tmp_path / "missing")


# --------------------------------------------------------------------------- #
# The real host, where it is installed
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_claude_code_validates_the_plugin_strictly() -> None:
    """The host's own validator, in the mode CI would run it."""
    result = subprocess.run(
        ["claude", "plugin", "validate", "--strict", "--json", str(PLUGIN)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
