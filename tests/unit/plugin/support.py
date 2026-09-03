"""Shared paths and readers for the plugin tests.

The plugin is JSON, Markdown and one shell script, so every test reads files.
These helpers keep the paths in one place and give the tests one reading of
how the host substitutes ``${user_config.KEY}`` — measured against Claude Code
2.1.259 with a throwaway probe plugin: a *set* option becomes its value and an
*unset* option becomes the empty string, never a literal placeholder and never
a refusal to start the server.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / "plugins" / "ti-recon"
MANIFEST = PLUGIN / ".claude-plugin" / "plugin.json"
MCP_CONFIG = PLUGIN / ".mcp.json"
LAUNCHER = PLUGIN / "bin" / "ti-recon-mcp"
PLUGIN_SKILL = PLUGIN / "skills" / "ti-recon-analyst"
CANONICAL_SKILL = ROOT / ".claude" / "skills" / "ti-recon-analyst"
TOOLS = ROOT / "tools"

#: The name of the one MCP server the plugin declares.
SERVER_NAME = "ti-recon"

_OPTION_REFERENCE = re.compile(r"^\$\{user_config\.([A-Za-z_][A-Za-z0-9_]*)\}$")


def manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def mcp_config() -> dict[str, Any]:
    return json.loads(MCP_CONFIG.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def server_config() -> dict[str, Any]:
    servers = mcp_config()["mcpServers"]
    return servers[SERVER_NAME]  # type: ignore[no-any-return]


def option_for(value: str) -> str | None:
    """The user-config key a ``.mcp.json`` env value refers to, if it does."""
    match = _OPTION_REFERENCE.match(value)
    return None if match is None else match.group(1)


def env_mapping() -> dict[str, str]:
    """Environment variable -> user-config key, for every substituted entry."""
    mapping: dict[str, str] = {}
    for variable, value in server_config()["env"].items():
        option = option_for(value)
        if option is not None:
            mapping[variable] = option
    return mapping


def host_environment(configured: dict[str, str]) -> dict[str, str]:
    """What the host hands the server process, given which options are set.

    Literal entries pass through unchanged. A substituted entry becomes the
    option's value where the analyst set one and the empty string where they
    did not, which is the measured host behaviour.
    """
    environment: dict[str, str] = {}
    for variable, value in server_config()["env"].items():
        option = option_for(value)
        environment[variable] = value if option is None else configured.get(option, "")
    return environment


def plugin_files() -> dict[Path, str]:
    """Every text file the committed plugin ships, decoded."""
    files: dict[Path, str] = {}
    for path in sorted(PLUGIN.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            files[path] = path.read_text(encoding="utf-8")
    return files


def load_tool(name: str) -> ModuleType:
    """Import an operator script from ``tools/`` by file, without a package."""
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
