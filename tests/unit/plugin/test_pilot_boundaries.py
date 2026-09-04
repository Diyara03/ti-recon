"""Pilot boundaries: the marketplace, the platforms, the index policy, and
what an update must and must not change (Task 23, Phase 3).

Everything here is static or offline. The lock is read as data, the
marketplace manifest is checked structurally and by the host's validator where
it is installed, and the update behaviour is exercised through the real ``uv``
against a copy of the bundled runtime under a *new* root path with the *same*
data directory — which is exactly what a plugin update looks like to the host.
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

from .support import PLUGIN, ROOT, RUNTIME, host_command, host_environment, sanitized_environment

MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"

#: The platforms the pilot intends to support, as uv target triples and as the
#: wheel-tag fragments a cp312-compatible wheel for each must carry.
TARGETS: dict[str, re.Pattern[str]] = {
    "x86_64-pc-windows-msvc": re.compile(r"win_amd64"),
    "aarch64-apple-darwin": re.compile(r"macosx_[0-9_]+_(arm64|universal2)"),
    "x86_64-apple-darwin": re.compile(r"macosx_[0-9_]+_(x86_64|universal2)"),
    "x86_64-unknown-linux-gnu": re.compile(r"manylinux[_0-9]*_x86_64"),
}

#: Distributions with no wheel for a target, each with the reason it is
#: tolerated. A new entry here is a decision, never an accident: the test
#: fails for any distribution not listed.
KNOWN_GAPS: dict[tuple[str, str], str] = {
    ("cryptography", "x86_64-apple-darwin"): (
        "cryptography >= 49 publishes no macOS x86-64 wheel. It is required by "
        "the MCP SDK itself (mcp -> pyjwt[crypto] -> cryptography), not only by "
        "TI Recon's remote extra, so the dependency split cannot remove it. "
        "Decision pending: a marker-scoped constraint to the last x86-64 "
        "release (48.0.1, which carries published advisories) or excluding "
        "Intel Macs from the pilot. See docs/claude-plugin.md."
    ),
}

_CPYTHON_312 = re.compile(r"-(cp312|py3|py2\.py3)-|-abi3-")


def _lock() -> dict[str, object]:
    with (RUNTIME / "uv.lock").open("rb") as handle:
        return tomllib.load(handle)


def _local_closure_names() -> set[str]:
    """What the local runtime installs: the lock without dev or extras.

    Asked of ``uv`` itself, offline, so the set is the one ``uv run --locked
    --no-dev`` will materialise rather than a re-implementation of marker and
    extra resolution. Development tools (mypy, ruff, pytest) are in the lock
    and are not part of the plugin's runtime.
    """
    if shutil.which("uv") is None:
        pytest.skip("uv not installed")
    result = subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-hashes",
            "--no-emit-project",
            "--offline",
            "--project",
            str(RUNTIME),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    names: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "-")):
            names.add(re.split(r"[=<>!;\[ ]", line)[0].lower())
    assert names, "uv export produced no requirements"
    return names


def _local_packages() -> list[dict[str, object]]:
    """Lock entries for the local runtime's closure, from the lock the plugin ships."""
    names = _local_closure_names()
    packages = [pkg for pkg in _lock()["package"] if pkg["name"] in names]  # type: ignore[index]
    assert {pkg["name"] for pkg in packages} == names, "lock and export disagree"
    return packages


# --------------------------------------------------------------------------- #
# Platforms
# --------------------------------------------------------------------------- #


def test_every_native_distribution_has_a_wheel_for_every_pilot_platform() -> None:
    """No Rust, no Xcode, no MSVC on an analyst workstation: wheels or nothing."""
    gaps: dict[tuple[str, str], list[str]] = {}
    for pkg in _local_packages():
        wheels = [w["url"].rsplit("/", 1)[-1] for w in pkg.get("wheels", [])]  # type: ignore[union-attr]
        if not wheels or all(w.endswith("-none-any.whl") for w in wheels):
            continue
        for target, tag in TARGETS.items():
            if pkg["name"] == "pywin32" and "windows" not in target:
                continue  # Windows-only by marker, as intended
            usable = [w for w in wheels if tag.search(w) and _CPYTHON_312.search(w)]
            if not usable:
                gaps[(str(pkg["name"]), target)] = wheels
    unexplained = {key: value for key, value in gaps.items() if key not in KNOWN_GAPS}
    assert unexplained == {}, unexplained
    # And every tolerated gap still exists: a gap that closed should be removed.
    for key in KNOWN_GAPS:
        assert key in gaps, f"{key} no longer lacks a wheel; delete it from KNOWN_GAPS"


def test_no_local_package_is_sdist_only() -> None:
    """A source-only distribution would need a compiler on the workstation."""
    sdist_only = [pkg["name"] for pkg in _local_packages() if not pkg.get("wheels")]
    assert sdist_only == []


def test_the_remote_only_packages_arrive_through_the_sdk_and_are_recorded() -> None:
    """Measured, not assumed: the MCP SDK requires them, so they stay."""
    by_name = {pkg["name"]: pkg for pkg in _lock()["package"]}  # type: ignore[index]
    mcp_deps = {dep["name"] for dep in by_name["mcp"]["dependencies"]}  # type: ignore[index]
    assert {"pyjwt", "uvicorn", "starlette"} <= mcp_deps
    assert "cryptography" in by_name
    ti_recon = by_name["ti-recon"]
    core = {dep["name"] for dep in ti_recon["dependencies"]}  # type: ignore[index]
    assert core.isdisjoint({"pyjwt", "uvicorn", "starlette", "cryptography"})


# --------------------------------------------------------------------------- #
# Package-index policy
# --------------------------------------------------------------------------- #


def test_the_lock_names_only_the_public_index_and_carries_no_credential() -> None:
    lock_text = (RUNTIME / "uv.lock").read_text(encoding="utf-8")
    urls = set(re.findall(r"https?://[^\s\"']+", lock_text))
    hosts = {re.match(r"https?://([^/]+)", url).group(1) for url in urls}  # type: ignore[union-attr]
    assert hosts <= {"pypi.org", "files.pythonhosted.org"}, hosts
    for url in urls:
        assert "@" not in url.split("//", 1)[1].split("/", 1)[0], f"credential in URL: {url}"
    assert "index-url" not in lock_text.lower() or "pypi.org" in lock_text


def test_the_plugin_sets_no_index_and_no_index_credential() -> None:
    """The workstation's uv settings are the enterprise control point."""
    server = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"][
        "ti-recon"
    ]
    for variable in server["env"]:
        assert not variable.startswith(("UV_INDEX", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX")), variable
        assert "KEYRING" not in variable and "NETRC" not in variable, variable
    pyproject = (RUNTIME / "pyproject.toml").read_text(encoding="utf-8")
    assert "index-url" not in pyproject
    assert "[[tool.uv.index]]" not in pyproject
    assert "://" not in pyproject.split("[tool.uv]")[-1] if "[tool.uv]" in pyproject else True


# --------------------------------------------------------------------------- #
# The pilot marketplace
# --------------------------------------------------------------------------- #


def test_the_marketplace_lists_the_plugin_at_the_package_version() -> None:
    data = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", data["name"])
    assert data["owner"]["name"]
    assert data["description"]
    entries = {entry["name"]: entry for entry in data["plugins"]}
    assert list(entries) == ["ti-recon"]
    entry = entries["ti-recon"]
    assert entry["source"] == "./plugins/ti-recon"
    assert entry["version"] == __version__
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == entry["version"]
    assert not entry["version"].startswith("1."), "pilot releases stay below 1.0"


def test_the_marketplace_names_no_hostname_and_no_credential() -> None:
    text = MARKETPLACE.read_text(encoding="utf-8")
    assert "://" not in text
    assert "@" not in text
    for reserved in ("claude-plugins-official", "anthropic", "claude-code-plugins"):
        assert reserved not in json.loads(text)["name"]


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_claude_code_validates_the_pilot_marketplace_strictly() -> None:
    result = subprocess.run(
        ["claude", "plugin", "validate", "--strict", "--json", str(ROOT)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# Updates: new root, same data
# --------------------------------------------------------------------------- #


pytestmark_uv = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")


def _run(root: Path, workdir: Path, environment: dict[str, str], *program: str):
    command = host_command(plugin_root=root, plugin_data=workdir / "data")[:-1]
    return subprocess.run(
        [*command, *program],
        cwd=workdir,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytestmark_uv
def test_a_plugin_update_replaces_the_code_and_keeps_the_data_directory(tmp_path) -> None:
    """Version A under one root, version B under another, one data directory.

    The host installs each plugin version into its own directory and keeps
    ``${CLAUDE_PLUGIN_DATA}`` across versions. So an update is: a new
    ``CLAUDE_PLUGIN_ROOT``, the same environment path. The environment must
    then run version B's code and never version A's.
    """
    workdir = tmp_path / "workstation"
    workdir.mkdir()
    data = workdir / "data"
    version_a = tmp_path / "cache" / "0.1.0"
    version_b = tmp_path / "cache" / "0.1.0-next"
    for root in (version_a, version_b):
        shutil.copytree(PLUGIN, root, ignore=shutil.ignore_patterns("__pycache__"))
    marker = version_b / "runtime" / "src" / "ti_recon" / "__init__.py"
    marker.write_text(
        marker.read_text(encoding="utf-8") + '\nPLUGIN_UPDATE_MARKER = "version-b"\n',
        encoding="utf-8",
    )
    environment = sanitized_environment()
    environment.update(host_environment({}, plugin_root=version_a, plugin_data=data))
    environment["UV_OFFLINE"] = "1"
    probe = "import ti_recon; print(getattr(ti_recon, 'PLUGIN_UPDATE_MARKER', 'version-a'))"

    first = _run(version_a, workdir, environment, "python", "-c", probe)
    if first.returncode != 0:
        pytest.skip(f"offline provisioning unavailable here: {first.stderr.strip()[-300:]}")
    assert first.stdout.strip() == "version-a"
    env_dir = data / "runtime-env"
    interpreter_before = (env_dir / "pyvenv.cfg").read_text(encoding="utf-8")

    environment.update(host_environment({}, plugin_root=version_b, plugin_data=data))
    second = _run(version_b, workdir, environment, "python", "-c", probe)

    assert second.returncode == 0, second.stderr
    assert second.stdout.strip() == "version-b", "stale code stayed active after the update"
    assert (env_dir / "pyvenv.cfg").read_text(encoding="utf-8") == interpreter_before
    assert "Creating virtual environment" not in second.stderr, "the data directory was reused"
    # And nothing under either versioned root was written to.
    for root in (version_a, version_b):
        assert not (root / "runtime" / ".venv").exists()


@pytestmark_uv
def test_a_lock_that_disagrees_with_its_project_is_refused_rather_than_installed(tmp_path) -> None:
    """``--locked`` at work: a half-updated runtime never starts stale."""
    workdir = tmp_path / "workstation"
    workdir.mkdir()
    root = tmp_path / "cache" / "broken"
    shutil.copytree(PLUGIN, root, ignore=shutil.ignore_patterns("__pycache__"))
    pyproject = root / "runtime" / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace('version = "0.1.0"', 'version = "9.9.9"', 1),
        encoding="utf-8",
    )
    environment = sanitized_environment()
    environment.update(host_environment({}, plugin_root=root, plugin_data=workdir / "data"))
    environment["UV_OFFLINE"] = "1"

    result = _run(root, workdir, environment, "python", "-c", "print('must not run')")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "lock" in result.stderr.lower()
