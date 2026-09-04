"""Keep the plugin's bundled TI Recon runtime identical to the repository's.

Why a copy exists at all
------------------------

An installed Claude Code plugin is copied into the host's plugin cache and may
reference nothing outside its own directory. So the plugin has to *carry* the
TI Recon project the local MCP server runs from: the package source, the
project metadata and the exact dependency lock. The repository stays the
canonical source — its tests, its history and its release process live there —
and the copy under ``plugins/ti-recon/runtime/`` is regenerated, never edited.

What is copied, exactly
-----------------------

The smallest set a ``uv``-provisioned environment needs to build and run the
``ti-recon-mcp`` entry point, and nothing else:

* ``pyproject.toml`` — the project, its dependencies, its console scripts and
  the build backend. Copied verbatim: a transformed copy would be a second
  project definition that could drift in ways a byte comparison would miss.
* ``uv.lock`` — the exact, cross-platform dependency resolution.
* ``README.md`` — named by ``pyproject.toml``'s ``readme``; the build backend
  refuses to build without it.
* ``src/ti_recon/`` — the package, including its packaged data (the pinned
  MISP warninglist snapshot), minus byte-code caches.
* ``.python-version`` — generated, pinning the interpreter *series* the
  plugin asks ``uv`` for. It is derived from ``requires-python`` rather than
  written by hand, so the two cannot disagree.

Not copied: tests, tools, docs, the Skill, any environment file, any cache or
build artifact, and anything that is not in the manifest above. The manifest
is explicit so that an unrelated repository change never obliges a resync, and
a test asserts the copy contains nothing the manifest does not name.

Two modes, no third
-------------------

``--check`` reports whether the copy is byte-identical to what the manifest
would produce and exits nonzero if not; a unit test runs the same comparison
so drift fails the suite. ``--write`` regenerates the copy.

Usage
-----

.. code-block:: bash

    uv run python tools/sync_plugin_runtime.py --check
    uv run python tools/sync_plugin_runtime.py --write
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Where the copy lives inside the plugin.
TARGET = ROOT / "plugins" / "ti-recon" / "runtime"

#: Repository files copied verbatim to the same relative path.
FILES: tuple[str, ...] = ("pyproject.toml", "uv.lock", "README.md")

#: Repository directories copied whole, minus ``EXCLUDED_DIR_NAMES``.
DIRECTORIES: tuple[str, ...] = ("src/ti_recon",)

#: Directory names never copied and never counted, wherever they appear: byte
#: code, and the caches a tool run over the repository may drop beside a
#: ``pyproject.toml`` it finds.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {"__pycache__", ".ruff_cache", ".mypy_cache", ".pytest_cache", ".venv"}
)

#: File suffixes never copied.
EXCLUDED_SUFFIXES: frozenset[str] = frozenset({".pyc", ".pyo"})

#: The generated interpreter pin.
PYTHON_VERSION_FILE = ".python-version"

_MINIMUM_PYTHON = re.compile(r">=\s*(\d+)\.(\d+)")


def python_series(pyproject: Path = ROOT / "pyproject.toml") -> str:
    """The ``MAJOR.MINOR`` series ``requires-python`` starts at.

    ``requires-python`` is a lower bound; the plugin asks ``uv`` for exactly
    that series so every analyst gets the interpreter line the repository is
    tested on rather than whatever newest CPython happens to be installed.
    """
    with pyproject.open("rb") as handle:
        requires = tomllib.load(handle)["project"]["requires-python"]
    match = _MINIMUM_PYTHON.search(requires)
    if match is None:
        msg = f"cannot derive a Python series from requires-python {requires!r}"
        raise ValueError(msg)
    return f"{match.group(1)}.{match.group(2)}"


def _tree(directory: Path, base: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(base)
        if any(part in EXCLUDED_DIR_NAMES for part in relative.parts):
            continue
        if path.is_file() and path.suffix not in EXCLUDED_SUFFIXES:
            files[relative.as_posix()] = path.read_bytes()
    return files


def expected(root: Path = ROOT) -> dict[str, bytes]:
    """Every file the runtime copy must hold, keyed by relative POSIX path."""
    files: dict[str, bytes] = {}
    for name in FILES:
        files[name] = (root / name).read_bytes()
    for name in DIRECTORIES:
        files.update(_tree(root / name, root))
    files[PYTHON_VERSION_FILE] = f"{python_series(root / 'pyproject.toml')}\n".encode()
    return files


def actual(target: Path = TARGET) -> dict[str, bytes]:
    """Every file the copy currently holds."""
    if not target.is_dir():
        return {}
    return _tree(target, target)


def differences(root: Path = ROOT, target: Path = TARGET) -> list[str]:
    """Relative paths that differ, are missing, or are extra in the copy."""
    want = expected(root)
    have = actual(target)
    problems: list[str] = []
    for name in sorted(set(want) | set(have)):
        if name not in have:
            problems.append(f"missing from plugin runtime: {name}")
        elif name not in want:
            problems.append(f"not part of the runtime manifest: {name}")
        elif want[name] != have[name]:
            problems.append(f"differs: {name}")
    return problems


def write(root: Path = ROOT, target: Path = TARGET) -> None:
    """Regenerate the copy from the manifest, removing anything else."""
    files = expected(root)
    if target.exists():
        shutil.rmtree(target)
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift; exit 1 if any")
    mode.add_argument("--write", action="store_true", help="regenerate the plugin runtime")
    args = parser.parse_args(argv)

    if args.write:
        write()
        print(f"plugin runtime regenerated at {TARGET.relative_to(ROOT)}")
        return 0

    problems = differences()
    if problems:
        print("plugin runtime has drifted from the repository:", file=sys.stderr)
        for problem in problems[:40]:
            print(f"  {problem}", file=sys.stderr)
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more", file=sys.stderr)
        print("run: uv run python tools/sync_plugin_runtime.py --write", file=sys.stderr)
        return 1
    print("plugin runtime is identical to the repository source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
