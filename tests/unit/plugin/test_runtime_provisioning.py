"""The bundled runtime, provisioned and run exactly as the host does it.

Every test here spawns ``uv`` with the command and environment the plugin's
``.mcp.json`` declares, after the substitutions the host performs, from a
working directory outside the repository and with an environment scrubbed of
the developer's virtual environment, ``PYTHONPATH`` and every credential
variable. What the subprocess imports is therefore what the plugin's own
runtime provided, or the test fails.

``uv`` runs ``--offline``: the suite must never reach a package index, and a
developer's cache already holds everything the lock names. Where it does not —
a cold cache on a fresh machine — provisioning is skipped with the reason,
never faked.

Nothing is investigated. ``provider_status`` contacts no provider, and it is
what shows whether a credential is stored. The sentinels are fake.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client

from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT

from .support import PLUGIN, ROOT, RUNTIME, host_command, host_environment, sanitized_environment

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")

#: Fake. Unmistakable, so a match in any output cannot be a coincidence.
SENTINEL_VT = "PLUGIN_SENTINEL_VIRUSTOTAL_KEY_7f3a"
SENTINEL_CENSYS = "PLUGIN_SENTINEL_CENSYS_PAT_9c1d"
SENTINEL_ORG = "PLUGIN_SENTINEL_CENSYS_ORG_0042"
SENTINEL_DOTENV = "PLUGIN_SENTINEL_FROM_DOTENV_FILE"
SENTINELS = (SENTINEL_VT, SENTINEL_CENSYS, SENTINEL_ORG, SENTINEL_DOTENV)

CONFIGURED = {
    "virustotal_api_key": SENTINEL_VT,
    "censys_pat": SENTINEL_CENSYS,
    "censys_organization_id": SENTINEL_ORG,
}

ALL_TOOLS = {"investigate_observable", "investigate_file", "provider_status"}

#: A Python one-liner that reports where the interpreter and the package are.
_WHERE = (
    "import json, sys, ti_recon; "
    "print(json.dumps({'executable': sys.executable, 'package': ti_recon.__file__, "
    "'path': sys.path, 'version': sys.version.split()[0]}))"
)


@dataclass(frozen=True)
class Provisioned:
    """One provisioned runtime environment and how long the first run took."""

    workdir: Path
    data: Path
    environment: dict[str, str]
    first_run_seconds: float
    first_stdout: str


def _base_environment(data: Path, configured: dict[str, str] | None = None) -> dict[str, str]:
    environment = sanitized_environment()
    environment.update(host_environment(configured or {}, plugin_root=PLUGIN, plugin_data=data))
    environment["UV_OFFLINE"] = "1"
    return environment


def _run(
    workdir: Path, environment: dict[str, str], *program: str, timeout: float = 300
) -> subprocess.CompletedProcess[str]:
    """The plugin's own ``uv run`` prefix with ``program`` in place of the server."""
    command = host_command(plugin_root=PLUGIN, plugin_data=workdir / "data")
    prefix = command[:-1]  # everything but ``ti-recon-mcp``
    return subprocess.run(
        [*prefix, *program],
        cwd=workdir,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def provisioned(tmp_path_factory) -> Provisioned:
    """First run: an absent environment, created offline from the developer cache."""
    workdir = tmp_path_factory.mktemp("outside-the-repository")
    data = workdir / "data"
    environment = _base_environment(data)
    started = time.perf_counter()
    result = _run(workdir, environment, "python", "-c", _WHERE)
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        pytest.skip(f"offline provisioning unavailable here: {result.stderr.strip()[-400:]}")
    return Provisioned(workdir, data, environment, elapsed, result.stdout)


# --------------------------------------------------------------------------- #
# First run, warm run
# --------------------------------------------------------------------------- #


def test_the_first_run_creates_the_environment_under_plugin_data(provisioned) -> None:
    where = json.loads(provisioned.first_stdout)
    env_dir = provisioned.data / "runtime-env"
    assert env_dir.is_dir()
    assert Path(where["executable"]).is_relative_to(env_dir)
    assert Path(where["package"]).is_relative_to(env_dir)
    assert where["version"].startswith("3.12.")


def test_nothing_the_runtime_imports_comes_from_the_repository(provisioned) -> None:
    """The strong independence check: no path leads back to this checkout."""
    where = json.loads(provisioned.first_stdout)
    checkout = str(ROOT)
    assert checkout not in where["executable"]
    assert checkout not in where["package"]
    offenders = [entry for entry in where["path"] if entry and checkout in entry]
    assert offenders == [], offenders
    # And the interpreter is not the developer's virtual environment either.
    assert str(ROOT / ".venv") not in where["executable"]


def test_the_package_is_installed_not_linked(provisioned) -> None:
    """``--no-editable``: a real copy in site-packages, no ``.pth`` to the source."""
    site = provisioned.data / "runtime-env" / "lib"
    pth_files = [path for path in site.rglob("*.pth") if "ti_recon" in path.read_text()]
    assert pth_files == [], pth_files
    assert any(path.name == "ti_recon" for path in site.rglob("ti_recon"))


def test_stdout_carries_only_the_program_output(provisioned) -> None:
    """``uv``'s own provisioning messages go to stderr; stdout is the protocol."""
    lines = provisioned.first_stdout.strip().splitlines()
    assert len(lines) == 1
    json.loads(lines[0])


def test_the_warm_run_reuses_the_environment(provisioned) -> None:
    before = sorted(p.name for p in (provisioned.data / "runtime-env" / "lib").rglob("*.dist-info"))
    started = time.perf_counter()
    result = _run(provisioned.workdir, provisioned.environment, "python", "-c", _WHERE)
    elapsed = time.perf_counter() - started
    assert result.returncode == 0, result.stderr
    after = sorted(p.name for p in (provisioned.data / "runtime-env" / "lib").rglob("*.dist-info"))
    assert before == after
    assert "Installed" not in result.stderr, "a warm run must not reinstall"
    # Not compared against the first run: with a warm uv cache the first run
    # hard-links wheels in tens of milliseconds, so both are process-startup
    # noise. What matters is that nothing was installed and it stays fast.
    assert elapsed < 30


def test_the_plugin_root_is_never_written_to(provisioned) -> None:
    """The versioned root is immutable; every run leaves it byte-identical."""
    snapshot = {
        p.relative_to(RUNTIME).as_posix(): p.stat().st_size
        for p in RUNTIME.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    result = _run(provisioned.workdir, provisioned.environment, "python", "-c", "pass")
    assert result.returncode == 0, result.stderr
    after = {
        p.relative_to(RUNTIME).as_posix(): p.stat().st_size
        for p in RUNTIME.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    assert snapshot == after
    assert not (RUNTIME / ".venv").exists()


# --------------------------------------------------------------------------- #
# Concurrency and damage
# --------------------------------------------------------------------------- #


def test_two_sessions_provisioning_at_once_do_not_corrupt_the_environment(
    provisioned, tmp_path
) -> None:
    """Two Claude sessions can start TI Recon simultaneously on a fresh machine."""
    workdir = tmp_path / "two-sessions"
    workdir.mkdir()
    environment = _base_environment(workdir / "data")
    command = host_command(plugin_root=PLUGIN, plugin_data=workdir / "data")[:-1]
    program = ["python", "-c", "import ti_recon; print('started')"]
    processes = [
        subprocess.Popen(
            [*command, *program],
            cwd=workdir,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    outputs = [process.communicate(timeout=300) for process in processes]
    for process, (out, err) in zip(processes, outputs, strict=True):
        assert process.returncode == 0, err
        assert out.strip() == "started"
    check = _run(workdir, environment, "python", "-c", "import ti_recon.mcp_server.server")
    assert check.returncode == 0, check.stderr


def test_a_damaged_interpreter_link_is_repaired_on_the_next_start(provisioned, tmp_path) -> None:
    """Repair, not brick: a half-written environment does not lock an analyst out."""
    workdir = tmp_path / "damaged"
    workdir.mkdir()
    environment = _base_environment(workdir / "data")
    first = _run(workdir, environment, "python", "-c", "pass")
    assert first.returncode == 0, first.stderr
    env_dir = workdir / "data" / "runtime-env"
    for name in ("python", "python3", "python.exe"):
        for path in env_dir.rglob(name):
            path.unlink()
    (env_dir / "pyvenv.cfg").write_text("", encoding="utf-8")

    second = _run(workdir, environment, "python", "-c", "import ti_recon; print('repaired')")

    assert second.returncode == 0, second.stderr
    assert second.stdout.strip() == "repaired"


def test_an_environment_path_that_is_not_a_directory_fails_closed(provisioned, tmp_path) -> None:
    """A clear startup failure on stderr, nothing on stdout, no half-start."""
    workdir = tmp_path / "blocked"
    workdir.mkdir()
    (workdir / "data").mkdir()
    (workdir / "data" / "runtime-env").write_text("not a directory", encoding="utf-8")
    environment = _base_environment(workdir / "data")

    result = _run(workdir, environment, "python", "-c", "print('must not run')")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "runtime-env" in result.stderr
    for sentinel in SENTINELS:
        assert sentinel not in result.stderr


# --------------------------------------------------------------------------- #
# The server itself, over stdio, through uv
# --------------------------------------------------------------------------- #


async def _serve(
    workdir: Path, environment: dict[str, str], stderr_path: Path
) -> tuple[str, dict[str, object], dict[str, bool]]:
    command = host_command(plugin_root=PLUGIN, plugin_data=workdir / "data")
    parameters = StdioServerParameters(
        command=command[0], args=command[1:], env=environment, cwd=str(workdir)
    )
    with stderr_path.open("w", encoding="utf-8") as stderr:
        async with Client(stdio_client(parameters, errlog=stderr)) as client:
            instructions = client.instructions or ""
            tools = {
                item.name: item.model_dump(mode="json")
                for item in (await client.list_tools()).tools
            }
            status = await client.call_tool("provider_status", {})
    configured = {
        item["provider_id"]: item["configured"] for item in status.structured_content["providers"]
    }
    return instructions, tools, configured


@pytest.mark.asyncio
async def test_the_server_starts_through_uv_with_the_plugin_environment(
    provisioned, tmp_path
) -> None:
    """All three tools, the file tool's approval metadata, the plugin profile,
    configured credentials by group, and no sentinel on any surface."""
    environment = _base_environment(provisioned.data, CONFIGURED)
    environment["TI_RECON_LOG_LEVEL"] = "DEBUG"
    stderr_path = tmp_path / "server-stderr.txt"

    instructions, tools, configured = await _serve(provisioned.workdir, environment, stderr_path)

    assert set(tools) == ALL_TOOLS
    assert tools["investigate_file"]["meta"] == {"anthropic/requiresUserInteraction": True}
    assert "plugin" in instructions.lower()
    assert configured["gti"] is True
    assert configured["censys"] is True
    assert configured["misp_warninglists"] is True
    for provider in ("urlscan", "greynoise", "hybrid_analysis", "threatfox", "urlhaus"):
        assert configured[provider] is False, provider

    everything = "\n".join(
        [instructions, json.dumps(tools), json.dumps(configured), stderr_path.read_text()]
    )
    for sentinel in SENTINELS:
        assert sentinel not in everything, sentinel


@pytest.mark.asyncio
async def test_the_server_starts_with_no_credentials_and_ignores_a_dotenv_in_the_cwd(
    provisioned, tmp_path
) -> None:
    """Zero keys is a valid installation, and the working directory cannot add one."""
    workdir = tmp_path / "analyst-project"
    workdir.mkdir()
    (workdir / ".env").write_text(
        f"VIRUSTOTAL_API_KEY={SENTINEL_DOTENV}\nURLSCAN_API_KEY={SENTINEL_DOTENV}\n",
        encoding="utf-8",
    )
    environment = _base_environment(provisioned.data)
    # Run from the new working directory but against the already provisioned data.
    environment["UV_PROJECT_ENVIRONMENT"] = str(provisioned.data / "runtime-env")
    stderr_path = tmp_path / "server-stderr.txt"

    instructions, tools, configured = await _serve(workdir, environment, stderr_path)

    assert set(tools) == ALL_TOOLS
    assert [name for name, flag in sorted(configured.items()) if flag] == ["misp_warninglists"]
    for variable in CREDENTIAL_ENVIRONMENT.values():
        assert environment.get(variable, "") == ""
    everything = "\n".join([instructions, json.dumps(tools), stderr_path.read_text()])
    assert SENTINEL_DOTENV not in everything


def test_a_missing_dependency_source_fails_closed_before_the_server_starts(tmp_path) -> None:
    """Fresh machine, no cache, no index reachable: a clear stderr failure,
    nothing on stdout, and no half-provisioned start."""
    workdir = tmp_path / "no-index"
    workdir.mkdir()
    environment = _base_environment(workdir / "data")
    environment["UV_CACHE_DIR"] = str(tmp_path / "empty-cache")
    result = _run(workdir, environment, "python", "-c", "print('must not run')")
    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr.strip()
    for sentinel in SENTINELS:
        assert sentinel not in result.stderr


def test_an_unobtainable_python_fails_closed_before_the_server_starts(tmp_path) -> None:
    """No interpreter of the requested series and downloads forbidden."""
    workdir = tmp_path / "no-python"
    workdir.mkdir()
    environment = _base_environment(workdir / "data")
    environment["UV_PYTHON_INSTALL_DIR"] = str(tmp_path / "no-managed-pythons")
    environment["UV_PYTHON_PREFERENCE"] = "only-managed"
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    result = _run(workdir, environment, "python", "-c", "print('must not run')")
    assert result.returncode != 0
    assert result.stdout == ""
    assert "python" in result.stderr.lower()
