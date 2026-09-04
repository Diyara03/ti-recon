"""Shared paths and readers for the plugin tests.

The plugin is JSON, Markdown and a copy of the Python project, so every test
reads files. These helpers keep the paths in one place and give the tests one
reading of how the host substitutes the plugin's placeholders — measured
against Claude Code 2.1.259 with a throwaway probe plugin:

* ``${user_config.KEY}``: a *set* option becomes its value and an *unset* one
  becomes the empty string, never a literal placeholder and never a refusal to
  start the server;
* ``${CLAUDE_PLUGIN_ROOT}`` and ``${CLAUDE_PLUGIN_DATA}``: replaced with
  absolute paths, in ``command``, ``args`` and ``env`` alike.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / "plugins" / "ti-recon"
MANIFEST = PLUGIN / ".claude-plugin" / "plugin.json"
MCP_CONFIG = PLUGIN / ".mcp.json"
PLUGIN_SKILL = PLUGIN / "skills" / "ti-recon-analyst"
RUNTIME = PLUGIN / "runtime"
CANONICAL_SKILL = ROOT / ".claude" / "skills" / "ti-recon-analyst"
TOOLS = ROOT / "tools"

#: The name of the one MCP server the plugin declares.
SERVER_NAME = "ti-recon"

#: The host placeholders the plugin may use.
ROOT_PLACEHOLDER = "${CLAUDE_PLUGIN_ROOT}"
DATA_PLACEHOLDER = "${CLAUDE_PLUGIN_DATA}"

#: Files that are the plugin's own *integration* — as opposed to the bundled
#: runtime, which is a byte-identical copy of the repository and is covered by
#: the repository's own tests.
INTEGRATION_FILES: tuple[Path, ...] = (MANIFEST, MCP_CONFIG, PLUGIN / "README.md")

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


def _substitute(value: str, *, plugin_root: Path, plugin_data: Path) -> str:
    return value.replace(ROOT_PLACEHOLDER, str(plugin_root)).replace(
        DATA_PLACEHOLDER, str(plugin_data)
    )


def host_environment(
    configured: dict[str, str],
    *,
    plugin_root: Path = PLUGIN,
    plugin_data: Path | None = None,
) -> dict[str, str]:
    """The ``env`` block as the host hands it to the server process.

    Literal entries pass through with the path placeholders replaced. A
    substituted option becomes its value where the analyst set one and the
    empty string where they did not, which is the measured host behaviour.
    """
    data = plugin_data if plugin_data is not None else plugin_root / "_data"
    environment: dict[str, str] = {}
    for variable, value in server_config()["env"].items():
        option = option_for(value)
        if option is None:
            environment[variable] = _substitute(value, plugin_root=plugin_root, plugin_data=data)
        else:
            environment[variable] = configured.get(option, "")
    return environment


def host_command(*, plugin_root: Path = PLUGIN, plugin_data: Path) -> list[str]:
    """``command`` plus ``args`` as the host would spawn them."""
    server = server_config()
    parts = [server["command"], *server.get("args", [])]
    return [_substitute(part, plugin_root=plugin_root, plugin_data=plugin_data) for part in parts]


def sanitized_environment() -> dict[str, str]:
    """The developer's environment with everything that could leak the checkout
    or a real credential removed.

    Keeps ``PATH`` and ``HOME`` so ``uv`` and its caches are found, exactly as
    on an analyst workstation. Drops the active virtual environment, any
    ``PYTHONPATH``, every documented credential variable and any ``uv`` project
    override, so that whatever the subprocess imports is what the plugin's own
    runtime provided.
    """
    from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT

    dropped = set(CREDENTIAL_ENVIRONMENT.values()) | {
        "CENSYS_ORGANIZATION_ID",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
        "UV_PROJECT",
        "UV_PYTHON",
        "TI_RECON_CREDENTIAL_SETUP",
        "TI_RECON_LOG_LEVEL",
    }
    return {key: value for key, value in os.environ.items() if key not in dropped}


def integration_files() -> dict[Path, str]:
    """The plugin's own files, decoded: manifest, server declaration, README, Skill."""
    files: dict[Path, str] = {path: path.read_text(encoding="utf-8") for path in INTEGRATION_FILES}
    for path in sorted(PLUGIN_SKILL.rglob("*.md")):
        files[path] = path.read_text(encoding="utf-8")
    return files


def every_entry() -> list[Path]:
    """Every file and directory under the plugin, symlinks included and not followed."""
    return sorted(path for path in PLUGIN.rglob("*") if "__pycache__" not in path.parts)


def load_tool(name: str) -> ModuleType:
    """Import an operator script from ``tools/`` by file, without a package."""
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
