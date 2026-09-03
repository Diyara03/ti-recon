"""Keep the plugin's copy of the analyst Skill identical to the repository's.

Why a copy exists at all
------------------------

Claude Code copies an installed plugin into its own cache and loads components
from inside that directory only, so the plugin has to *carry* the Skill. The
repository's project Skill under ``.claude/skills/ti-recon-analyst/`` is what a
session working in this checkout gets, and it stays the **canonical source**:
its tests, its docs and its history live there. A symlink would not survive the
plugin cache or a checkout on a platform without symlink support, so the plugin
holds a real copy — and this script is the only way that copy is meant to change.

Two modes, no third
-------------------

``--check`` reports whether the copy is byte-identical to the source, file for
file, and exits nonzero if not. A unit test runs the same comparison, so drift
fails the suite. ``--write`` makes the copy identical, creating, replacing and
deleting files as needed. Nothing is transformed on the way: the plugin's Skill
is the repository's Skill, not a derived rendering that could drift in a way a
byte comparison would not notice.

Usage
-----

.. code-block:: bash

    uv run python tools/sync_plugin_skill.py --check
    uv run python tools/sync_plugin_skill.py --write
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The canonical Skill: the repository's project Skill.
SOURCE = ROOT / ".claude" / "skills" / "ti-recon-analyst"

#: The plugin's packaged copy.
TARGET = ROOT / "plugins" / "ti-recon" / "skills" / "ti-recon-analyst"


def _files(directory: Path) -> dict[str, bytes]:
    """Every regular file under ``directory``, keyed by its relative POSIX path."""
    if not directory.is_dir():
        return {}
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


def differences(source: Path = SOURCE, target: Path = TARGET) -> list[str]:
    """Relative paths whose bytes differ, are missing, or are extra in the copy."""
    expected = _files(source)
    actual = _files(target)
    problems: list[str] = []
    for name in sorted(set(expected) | set(actual)):
        if name not in actual:
            problems.append(f"missing from plugin: {name}")
        elif name not in expected:
            problems.append(f"not in the canonical Skill: {name}")
        elif expected[name] != actual[name]:
            problems.append(f"differs: {name}")
    return problems


def write(source: Path = SOURCE, target: Path = TARGET) -> None:
    """Make ``target`` a byte-identical copy of ``source``."""
    if not source.is_dir():
        msg = f"canonical Skill directory not found: {source}"
        raise FileNotFoundError(msg)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift; exit 1 if any")
    mode.add_argument("--write", action="store_true", help="make the plugin copy identical")
    args = parser.parse_args(argv)

    if args.write:
        write()
        print(f"plugin Skill synchronised from {SOURCE.relative_to(ROOT)}")
        return 0

    problems = differences()
    if problems:
        print("plugin Skill has drifted from the canonical Skill:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print("run: uv run python tools/sync_plugin_skill.py --write", file=sys.stderr)
        return 1
    print("plugin Skill is identical to the canonical Skill")
    return 0


if __name__ == "__main__":
    sys.exit(main())
