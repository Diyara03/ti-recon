"""The snapshot must be found the same way everywhere (Task 11 packaging).

Task 11 promises a pinned snapshot that ships with TI Recon and works offline
with no configuration. That promise held in a source checkout and quietly failed
once installed: the default was ``Path(__file__).parents[3].parent / "data" /
"misp_warninglists"``, which resolved to ``<venv>/lib/python3.12/data/…`` in a
wheel — a directory that never existed, because the wheel packaged ``src/ti_recon``
only.

The dataset now lives inside the package and is located with
``importlib.resources``, so the import system answers the question instead of
directory arithmetic. These tests pin the parts of that which can regress
silently: where the default resolves, that an operator's path still wins, that a
bad explicit path fails rather than falling back, and that the built artifacts
actually carry the bytes.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

import ti_recon
from ti_recon.providers.misp_warninglists import (
    DEFAULT_SNAPSHOT_ROOT,
    MispWarningListsConfig,
    load_snapshot,
)
from ti_recon.providers.misp_warninglists.snapshot import SnapshotError

#: The pinned dataset's identity. Packaging must move bytes, never rewrite them.
EXPECTED_FINGERPRINT = "b5ab02ed5b3d369b9c788876b7f17ef0cd259e51840fa4d06913d7d8baae09a7"
EXPECTED_LIST_COUNT = 135
EXPECTED_ENTRY_COUNT = 428971
EXPECTED_FILE_COUNT = 136  # manifest.json plus one file per list

# Deliberately *not* skipped when the snapshot is missing. Elsewhere in the Task 11
# suite a skip guard is right: those tests need the dataset's content and have
# nothing to say without it. Here the presence of the dataset at the default
# location is the assertion, so skipping when it is absent would turn the exact
# regression these tests exist to catch into a green run. Reverting the fix makes
# this file fail, which is the only useful behaviour.

REPO_ROOT = Path(__file__).resolve().parents[4]
DIST = REPO_ROOT / "dist"


def _tree_hash(root: Path) -> str:
    """A stable hash of a snapshot directory's relative paths and bytes."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Where the default comes from
# --------------------------------------------------------------------------- #


def test_the_default_snapshot_lives_inside_the_installed_package() -> None:
    """The invariant that makes a wheel work: it is package data, not repo data.

    Anything outside the package directory is unreachable once installed, so
    asserting containment here is asserting that an installed deployment can find
    its own dataset.
    """
    package_root = Path(ti_recon.__file__).resolve().parent

    assert DEFAULT_SNAPSHOT_ROOT.is_dir()
    assert package_root in DEFAULT_SNAPSHOT_ROOT.parents
    assert DEFAULT_SNAPSHOT_ROOT.parts[-2:] == ("data", "misp_warninglists")


def test_the_default_tracks_the_package_wherever_it_is_installed() -> None:
    """Behavioural, not textual: the default *is* the package-relative location.

    ``parents[N]`` walking from the module file is what let a checkout and a wheel
    disagree — it produced ``<repo>/data`` in one and ``<venv>/lib/python3.12/data``
    in the other. Asserting the default equals the package's own ``data``
    directory pins the fix without caring how it is computed, so a future
    refactor is free as long as it keeps answering correctly.
    """
    package_root = Path(ti_recon.__file__).resolve().parent

    assert DEFAULT_SNAPSHOT_ROOT == package_root / "data" / "misp_warninglists"
    # The old answer, explicitly excluded: a sibling of the package directory.
    assert DEFAULT_SNAPSHOT_ROOT != package_root.parent / "data" / "misp_warninglists"


def test_the_packaged_snapshot_keeps_its_exact_identity() -> None:
    """Moving the dataset must not have reformatted a single byte.

    The fingerprint is cache identity for Task 6 and provenance for Task 15, so a
    packaging change that regenerated the files would invalidate stored results
    while looking like a no-op.
    """
    manifest = json.loads((DEFAULT_SNAPSHOT_ROOT / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["dataset_fingerprint"] == EXPECTED_FINGERPRINT
    assert manifest["list_count"] == EXPECTED_LIST_COUNT
    assert manifest["entry_count"] == EXPECTED_ENTRY_COUNT
    assert manifest["license"] == "CC0-1.0"
    assert sum(1 for path in DEFAULT_SNAPSHOT_ROOT.rglob("*") if path.is_file()) == (
        EXPECTED_FILE_COUNT
    )


# --------------------------------------------------------------------------- #
# Precedence
# --------------------------------------------------------------------------- #


def test_an_operator_path_overrides_the_packaged_default(tmp_path: Path) -> None:
    """The bundled snapshot is a floor, not a ceiling.

    A deployment tracking a newer upstream snapshot must not be forced onto the
    baseline that happened to ship with the release.
    """
    external = tmp_path / "external"
    external.mkdir()
    (external / "manifest.json").write_text("{}", encoding="utf-8")

    config = MispWarningListsConfig(snapshot_root=external)

    assert config.snapshot_root == external.resolve()
    assert config.snapshot_root != DEFAULT_SNAPSHOT_ROOT


def test_the_default_is_used_when_no_path_is_configured() -> None:
    """No configuration required: that is the whole point of shipping it."""
    assert MispWarningListsConfig().snapshot_root == DEFAULT_SNAPSHOT_ROOT


def test_a_missing_explicit_path_fails_instead_of_falling_back(tmp_path: Path) -> None:
    """An operator who configured a path gets that path's answer, or an error.

    Silently substituting the packaged baseline would be worse than failing: the
    deployment would believe it was consulting a dataset it had chosen, and the
    substitution would be invisible in the result.
    """
    missing = tmp_path / "not_here"
    config = MispWarningListsConfig(snapshot_root=missing)

    assert config.snapshot_root == missing.resolve()
    assert config.snapshot_root != DEFAULT_SNAPSHOT_ROOT
    with pytest.raises(SnapshotError):
        load_snapshot(config.snapshot_root)


def test_the_update_tool_refuses_to_rewrite_an_installed_snapshot() -> None:
    """The packaged copy is an immutable baseline.

    Rewriting it in place would edit an installed distribution behind the
    installer's back, leave the wheel's RECORD hashes wrong, and vanish on the
    next reinstall — while looking like a successful refresh to whoever ran it.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_update_tool", REPO_ROOT / "tools" / "update_misp_warninglists.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module._is_installed_location(Path("/x/lib/python3.12/site-packages/ti_recon/data"))
    assert module._is_installed_location(Path("/usr/lib/python3/dist-packages/ti_recon/data"))
    assert not module._is_installed_location(REPO_ROOT / "src" / "ti_recon" / "data")


# --------------------------------------------------------------------------- #
# The built artifacts
# --------------------------------------------------------------------------- #

WHEEL = next(DIST.glob("*.whl"), None) if DIST.is_dir() else None
SDIST = next(DIST.glob("*.tar.gz"), None) if DIST.is_dir() else None

needs_artifacts = pytest.mark.skipif(
    WHEEL is None or SDIST is None,
    reason="no built distributions in dist/; run `uv build --offline`",
)


@needs_artifacts
def test_the_wheel_carries_the_snapshot_byte_for_byte() -> None:
    """The bug was that it did not.

    Hashing the members as stored proves the wheel holds the same dataset the
    source tree does — not merely a directory of the right shape.
    """
    assert WHEEL is not None
    prefix = "ti_recon/data/misp_warninglists/"
    with zipfile.ZipFile(WHEEL) as archive:
        members = sorted(
            n for n in archive.namelist() if n.startswith(prefix) and not n.endswith("/")
        )
        assert len(members) == EXPECTED_FILE_COUNT
        assert f"{prefix}manifest.json" in members

        digest = hashlib.sha256()
        for name in members:
            digest.update(name[len(prefix) :].encode("utf-8"))
            digest.update(archive.read(name))
    assert digest.hexdigest() == _tree_hash(DEFAULT_SNAPSHOT_ROOT)


@needs_artifacts
def test_the_sdist_carries_the_snapshot_too() -> None:
    """So that sdist -> wheel -> install keeps the data."""
    assert SDIST is not None
    with tarfile.open(SDIST) as archive:
        names = archive.getnames()
    members = [n for n in names if "/src/ti_recon/data/misp_warninglists/" in n]

    assert len(members) == EXPECTED_FILE_COUNT
    assert any(n.endswith("/src/ti_recon/data/misp_warninglists/manifest.json") for n in names)
