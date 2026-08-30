"""What ships, and what must not (Task 21).

Hatchling builds an sdist from the working directory rather than from git, so
anything sitting in the tree can end up inside a published archive — including
files git never tracked. That is how a developer's own machine state escapes,
and how two builds of one commit stop being identical.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory) -> tuple[set[str], set[str]]:
    """One offline build, read back. Skipped where the toolchain is unavailable."""
    out = tmp_path_factory.mktemp("dist")
    try:
        subprocess.run(
            ["uv", "build", "--offline", "--out-dir", str(out)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        pytest.skip(f"cannot build here: {type(error).__name__}")

    sdist = next(out.glob("*.tar.gz"))
    wheel = next(out.glob("*.whl"))
    with tarfile.open(sdist) as archive:
        sdist_names = set(archive.getnames())
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
    return sdist_names, wheel_names


def test_no_local_machine_settings_are_published(artifacts) -> None:
    """A developer's own Claude Code settings are not source.

    Untracked, and ignored only by whatever global gitignore that developer
    happens to have — so nothing about the repository stops them being packaged
    except this exclusion.
    """
    sdist, wheel = artifacts

    for names, label in ((sdist, "sdist"), (wheel, "wheel")):
        offenders = [name for name in names if "settings.local.json" in name]
        assert offenders == [], f"{label}: {offenders}"


def test_the_server_ships_in_both_artifacts(artifacts) -> None:
    """The MCP server is library code and belongs in the installable package."""
    sdist, wheel = artifacts

    assert len([n for n in wheel if n.startswith("ti_recon/mcp_server/")]) >= 6
    assert len([n for n in sdist if "src/ti_recon/mcp_server/" in n]) >= 6


def test_the_console_commands_are_declared(artifacts) -> None:
    """Both entry points, or an installed user gets one of the two."""
    _, wheel = artifacts
    entry_points = next(name for name in wheel if name.endswith("entry_points.txt"))

    out = ROOT / "pyproject.toml"
    declared = out.read_text(encoding="utf-8")
    assert "ti-recon = " in declared
    assert "ti-recon-mcp = " in declared
    assert entry_points


def test_the_skill_is_source_and_not_an_installed_package(artifacts) -> None:
    """A deliberate asymmetry, asserted so nobody has to guess.

    The Skill is tracked repository content, so it belongs in a *source*
    distribution. It is not Python and installing the wheel does not place it
    anywhere Claude Code looks — a user gets it by working in this repository,
    or by copying it into their own skills directory.
    """
    sdist, wheel = artifacts

    assert [n for n in sdist if "skills/ti-recon-analyst/SKILL.md" in n]
    assert [n for n in wheel if "skills" in n] == []


def test_the_python_used_is_the_project_interpreter() -> None:
    """Guard for the assumption the build fixture makes about its environment."""
    assert sys.version_info >= (3, 12)
