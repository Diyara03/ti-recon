"""The Claude Code plugin as a distribution artifact (Task 23).

The plugin is a *packaging* of things the repository already has — the local
MCP server, as a bundled copy of the project, and the analyst Skill — plus the
declaration of how the host starts the server and how an analyst's provider
credentials reach it. So what a test can hold is structural: the manifest the
host reads, the ``uv`` invocation it spawns, the credential mapping it
substitutes, the two copies it carries, and the absence of anything that must
not be in a distributed directory. Prose is not asserted; the distinctions are.

Where a check needs the real host, it runs ``claude plugin validate`` and skips
where the CLI is not installed. Provisioning and running the bundled runtime is
``test_runtime_provisioning.py``'s job.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
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
    DATA_PLACEHOLDER,
    MANIFEST,
    MCP_CONFIG,
    PLUGIN,
    PLUGIN_SKILL,
    ROOT,
    ROOT_PLACEHOLDER,
    RUNTIME,
    SERVER_NAME,
    env_mapping,
    every_entry,
    integration_files,
    load_tool,
    manifest,
    mcp_config,
    option_for,
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

#: Top-level directories organization-distributed plugins may not contain.
REJECTED_TOP_LEVEL = {"bin"}


def _credentialled_groups() -> set[str]:
    return {
        adapter.descriptor.credential_group
        for adapter in build_default_adapters()
        if adapter.descriptor.requires_credentials
    }


def _runtime_pyproject() -> dict[str, object]:
    with (RUNTIME / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


# --------------------------------------------------------------------------- #
# Layout the host depends on
# --------------------------------------------------------------------------- #


def test_the_manifest_lives_where_the_host_looks_and_holds_only_itself() -> None:
    """``.claude-plugin/`` is for the manifest; components live beside it."""
    assert MANIFEST.is_file()
    assert [path.name for path in (PLUGIN / ".claude-plugin").iterdir()] == ["plugin.json"]
    assert (PLUGIN_SKILL / "SKILL.md").is_file()
    assert MCP_CONFIG.is_file()
    assert (RUNTIME / "pyproject.toml").is_file()


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
    for name in ("hooks", "agents", "commands", "scripts"):
        assert not (PLUGIN / name).exists(), f"{name}/ exists but nothing needs it"


def test_the_plugin_has_no_top_level_directory_enterprise_distribution_rejects() -> None:
    """Organization-distributed plugins are rejected with a top-level ``bin/``."""
    top_level = {path.name for path in PLUGIN.iterdir()}
    assert top_level & REJECTED_TOP_LEVEL == set(), top_level & REJECTED_TOP_LEVEL


def test_nothing_in_the_plugin_is_a_symlink() -> None:
    """The plugin cache copies files; a link out of the tree copies nothing."""
    links = [path for path in every_entry() if path.is_symlink()]
    assert links == [], links


def test_no_placeholder_path_escapes_the_plugin_root() -> None:
    """Every ``${CLAUDE_PLUGIN_ROOT}`` reference names something inside the plugin."""
    server = server_config()
    for part in [server["command"], *server.get("args", []), *server["env"].values()]:
        if ROOT_PLACEHOLDER not in part:
            continue
        relative = part.split(ROOT_PLACEHOLDER, 1)[1].lstrip("/")
        assert ".." not in Path(relative).parts, part
        assert (PLUGIN / relative).exists(), f"{part} names nothing in the plugin"
    for path, text in integration_files().items():
        assert "../" not in text, f"{path}: repository-relative reference"


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
    """Sensitive plugin storage is a shared, bounded budget; only secrets belong there."""
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
    """Sensitive plugin storage is ~2 KB shared with the host's own tokens.

    The count is what this layer controls: one sensitive option per credential
    group, no more. Value lengths are the providers' and are estimated in
    ``docs/claude-plugin.md``.
    """
    sensitive = [n for n, o in manifest()["userConfig"].items() if o.get("sensitive")]
    assert len(sensitive) == len(_credentialled_groups())


# --------------------------------------------------------------------------- #
# The MCP server declaration: what the host spawns
# --------------------------------------------------------------------------- #


def test_the_plugin_declares_one_stdio_server_started_directly_through_uv() -> None:
    """A bare executable name, resolved on PATH, on every platform. No shell."""
    servers = mcp_config()["mcpServers"]
    assert list(servers) == [SERVER_NAME]
    server = server_config()
    assert server["command"] == "uv"
    assert "url" not in server, "the plugin is local stdio, never HTTP"
    assert server["args"][0] == "run"
    assert server["args"][-1] == "ti-recon-mcp"


def test_the_server_command_is_a_console_script_the_bundled_project_defines() -> None:
    scripts = _runtime_pyproject()["project"]["scripts"]  # type: ignore[index]
    assert server_config()["args"][-1] in scripts


def test_uv_is_pointed_at_the_bundled_project_and_nowhere_else() -> None:
    """``--project`` names the runtime under the plugin root, so the working
    directory — wherever the analyst started Claude Code — plays no part."""
    args = server_config()["args"]
    assert "--project" in args
    assert args[args.index("--project") + 1] == f"{ROOT_PLACEHOLDER}/runtime"
    assert "--directory" not in args


def test_the_invocation_is_locked_lean_and_reads_no_environment_file() -> None:
    """Exact lock, no dev extras, a real install, and no ``.env`` from the cwd."""
    args = server_config()["args"]
    for flag in ("--locked", "--no-dev", "--no-editable", "--no-env-file"):
        assert flag in args, flag
    assert "--frozen" not in args, "--locked also refuses a lock that disagrees with pyproject"


def test_the_python_request_is_deterministic_and_agrees_everywhere() -> None:
    """One series, derived from ``requires-python`` and stated three times identically."""
    sync = load_tool("sync_plugin_runtime")
    series = sync.python_series()
    args = server_config()["args"]
    assert "--python" in args
    assert args[args.index("--python") + 1] == series
    assert (RUNTIME / ".python-version").read_text(encoding="utf-8").strip() == series
    assert series == "3.12"


def test_runtime_state_lives_under_plugin_data_and_code_under_plugin_root() -> None:
    """The root is replaced on every plugin update; the data directory survives it."""
    server = server_config()
    environment = server["env"]
    assert environment["UV_PROJECT_ENVIRONMENT"].startswith(f"{DATA_PLACEHOLDER}/")
    assert ".." not in environment["UV_PROJECT_ENVIRONMENT"]
    for part in server["args"]:
        assert DATA_PLACEHOLDER not in part, "mutable state is never an argument"
    for value in environment.values():
        assert ROOT_PLACEHOLDER not in value, "nothing under the versioned root is mutable"


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


def test_the_environment_names_only_variables_the_repository_documents_or_uv_defines() -> None:
    documented = {
        line.split("=", 1)[0].strip()
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    for variable in server_config()["env"]:
        assert variable in documented or variable.startswith("UV_"), variable


# --------------------------------------------------------------------------- #
# What must not be in the plugin
# --------------------------------------------------------------------------- #


def test_no_sensitive_value_is_ever_substituted_into_skill_content() -> None:
    """The host substitutes non-sensitive ``${user_config.*}`` into Skills.

    So the only safe reference count in Skill content is zero — a future edit
    that pasted one in would put a value into model context.
    """
    for path in PLUGIN_SKILL.rglob("*.md"):
        assert "${user_config" not in path.read_text(encoding="utf-8"), path


def test_no_integration_file_holds_a_secret_shaped_value() -> None:
    for path, text in integration_files().items():
        for pattern in (
            r"api[_-]?key\s*[=:]\s*\S{8,}",
            r"auth[_-]?key\s*[=:]\s*\S{8,}",
            r"token\s*[=:]\s*\S{8,}",
            r"\b[A-Fa-f0-9]{64}\b",
        ):
            assert not re.search(pattern, text, re.IGNORECASE), f"{path}: {pattern}"
    for name, option in manifest()["userConfig"].items():
        assert "default" not in option or not option.get("sensitive"), name


def test_the_plugin_references_no_checkout_home_directory_or_virtual_environment() -> None:
    """Installed elsewhere, an absolute path points at nothing or at the wrong thing."""
    for path, text in integration_files().items():
        for forbidden in ("/home/", "/Users/", "/tmp/", "C:\\", ".venv", "~/ti-recon"):
            assert forbidden not in text, f"{path}: {forbidden}"


def test_the_integration_references_no_remote_authentication() -> None:
    """The plugin is the local, single-analyst path; the bundled runtime still
    *contains* the remote surface, unchanged, but nothing here starts it."""
    forbidden = (
        "jwt",
        "jwks",
        "oauth",
        "auth0",
        "http_main",
        "ti-recon-mcp-http",
        "token_verifier",
        "tenant-v1",
        "resource server",
        "onrender",
    )
    for path, text in integration_files().items():
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
# The two copies: Skill and runtime
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


def test_the_bundled_runtime_is_byte_identical_to_the_repository_manifest() -> None:
    """The project, its lock, its package and nothing else — regenerated, never edited."""
    sync = load_tool("sync_plugin_runtime")
    assert sync.TARGET == RUNTIME
    assert sync.differences() == []


def test_the_runtime_manifest_carries_only_what_a_build_needs() -> None:
    """Tests, tools, docs, the Skill, environment files and caches stay out."""
    sync = load_tool("sync_plugin_runtime")
    assert set(sync.FILES) == {"pyproject.toml", "uv.lock", "README.md"}
    assert set(sync.DIRECTORIES) == {"src/ti_recon"}
    names = {path.relative_to(RUNTIME).as_posix() for path in RUNTIME.rglob("*") if path.is_file()}
    for forbidden in (
        "tests/",
        "tools/",
        "docs/",
        ".claude/",
        ".env",
        ".git/",
        "__pycache__",
        ".pyc",
    ):
        assert not any(forbidden in name for name in names), forbidden
    assert ".python-version" in names


def test_the_runtime_sync_tool_reports_drift_and_repairs_it(tmp_path) -> None:
    sync = load_tool("sync_plugin_runtime")
    root = tmp_path / "repo"
    (root / "src" / "ti_recon").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\nrequires-python = ">=3.12"\n', encoding="utf-8"
    )
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    (root / "src" / "ti_recon" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    (root / "src" / "ti_recon" / "__pycache__").mkdir()
    (root / "src" / "ti_recon" / "__pycache__" / "a.pyc").write_bytes(b"\x00")
    target = tmp_path / "runtime"

    assert sync.differences(root, target), "an absent copy is drift"
    sync.write(root, target)
    assert sync.differences(root, target) == []
    assert not (target / "src" / "ti_recon" / "__pycache__").exists()
    assert (target / ".python-version").read_text(encoding="utf-8") == "3.12\n"

    (root / "src" / "ti_recon" / "__init__.py").write_text("x = 2\n", encoding="utf-8")
    (target / "stray.txt").write_text("edited in the wrong place\n", encoding="utf-8")
    problems = sync.differences(root, target)
    assert any("differs: src/ti_recon/__init__.py" in p for p in problems)
    assert any("not part of the runtime manifest: stray.txt" in p for p in problems)
    sync.write(root, target)
    assert sync.differences(root, target) == []


def test_the_runtime_project_metadata_is_the_repositorys_own() -> None:
    project = _runtime_pyproject()["project"]  # type: ignore[index]
    assert project["name"] == "ti-recon"  # type: ignore[index]
    assert project["version"] == __version__  # type: ignore[index]
    assert (RUNTIME / "uv.lock").read_bytes() == (ROOT / "uv.lock").read_bytes()


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_the_runtime_lock_matches_its_project() -> None:
    """``--locked`` at startup would refuse a stale lock; catch it here first."""
    result = subprocess.run(
        ["uv", "lock", "--check", "--offline", "--project", str(RUNTIME)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr


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


def test_the_runtime_copy_is_not_published_inside_the_package_sdist() -> None:
    """The package's own archive must not carry a second copy of itself."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        exclude = tomllib.load(handle)["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]
    assert "plugins/" in exclude


def test_no_leftover_developer_artifacts_from_the_proof_phase() -> None:
    """The shell launcher and the generated developer copy were Phase 1 only."""
    assert not (ROOT / "tools" / "build_dev_plugin.py").exists()
    assert not (PLUGIN / "NON_DISTRIBUTABLE").exists()
    assert json.dumps(manifest()).count("NON-DISTRIBUTABLE") == 0
