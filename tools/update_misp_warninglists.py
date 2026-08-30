"""Build a pinned MISP warninglist snapshot from a local upstream checkout.

An **explicit operator action**, deliberately separate from enrichment. Nothing
in the provider can invoke this, and a lookup never refreshes anything: a
provider that updated itself mid-investigation would make its answers depend on
when they were asked.

Usage
-----

.. code-block:: bash

    git clone --depth 1 https://github.com/MISP/misp-warninglists /tmp/mwl
    uv run python tools/update_misp_warninglists.py \\
        --source-dir /tmp/mwl \\
        --output-dir src/ti_recon/data/misp_warninglists

Acquisition is yours, parsing is this tool's. That split is the security boundary:
this script takes a directory, never a URL, so there is no origin to point
somewhere else, no credential to leak and no download to validate. If you want
the fetch automated, automate the ``git clone`` in your own pipeline against the
official repository and hand the result here.

What it does
------------

Validate the checkout's shape, read every list, refuse anything that is not the
official schema, bound the snapshot by entry count, write compact per-list files
plus a manifest recording provenance and checksums, and swap the result into
place atomically. A half-written snapshot never becomes the live one.

Bounding at build time
----------------------

``--max-list-entries`` (default 100,000) keeps the shipped dataset small enough
to live in a repository: the upstream tree is 157 MB pretty-printed and 133 MB
compact, of which 20 lists are 4.9 million of the 5.2 million entries. Bounded,
it is 6.7 MB. Every omission is recorded in the manifest with a reason, so a
lookup can say what it never had rather than implying it checked everything.
Pass ``--max-list-entries 0`` for an unbounded snapshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
#: The snapshot inside this checkout's ``src`` tree -- the development copy, and
#: the one that becomes the packaged baseline when a distribution is built.
_SOURCE_SNAPSHOT_ROOT: Final[Path] = _REPO_ROOT / "src" / "ti_recon" / "data" / "misp_warninglists"
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from ti_recon import __version__  # noqa: E402
from ti_recon.providers.misp_warninglists.models import (  # noqa: E402
    ListOmissionReason,
    LoadDiagnostics,
    RawWarningList,
    SnapshotListRecord,
    SnapshotManifest,
)
from ti_recon.providers.misp_warninglists.profile import (  # noqa: E402
    DEFAULT_MAX_LIST_ENTRIES,
)
from ti_recon.providers.misp_warninglists.snapshot import (  # noqa: E402
    LISTS_DIRNAME,
    MANIFEST_FILENAME,
    slug_is_safe,
)

#: The only repository this tool describes itself as having read. Recorded in the
#: manifest; not used to fetch anything.
UPSTREAM_REPOSITORY: Final[str] = "https://github.com/MISP/misp-warninglists"

REASON_OVERSIZED: Final[str] = "oversized_at_build"
REASON_INVALID: Final[str] = "schema_invalid"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--source-dir",
        required=True,
        type=Path,
        help="a local checkout of MISP/misp-warninglists",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_SOURCE_SNAPSHOT_ROOT,
        help="where the snapshot is written (replaced atomically)",
    )
    parser.add_argument(
        "--max-list-entries",
        type=int,
        default=DEFAULT_MAX_LIST_ENTRIES,
        help="omit lists larger than this; 0 for no bound",
    )
    args = parser.parse_args(argv)

    output = args.output_dir.expanduser().resolve()
    if _is_installed_location(output):
        print(
            f"error: refusing to write into an installed package at {output}. "
            "The packaged snapshot is an immutable baseline; build a new snapshot "
            "into a source checkout or an external directory and point "
            "MispWarningListsConfig.snapshot_root at it instead.",
            file=sys.stderr,
        )
        return 2

    source = args.source_dir.expanduser().resolve()
    lists_dir = source / "lists"
    schema_path = source / "schema.json"
    if not lists_dir.is_dir() or not schema_path.is_file():
        print(
            f"error: {source} does not look like a misp-warninglists checkout "
            f"(expected lists/ and schema.json)",
            file=sys.stderr,
        )
        return 2

    limit = args.max_list_entries or None
    schema_fingerprint = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    commit, committed_at = _describe_checkout(source)

    records: list[SnapshotListRecord] = []
    omitted: list[ListOmissionReason] = []
    payloads: dict[str, bytes] = {}
    diagnostics = LoadDiagnostics()
    total_entries = 0

    for directory in sorted(lists_dir.iterdir()):
        list_file = directory / "list.json"
        if not list_file.is_file():
            continue
        slug = directory.name
        if not slug_is_safe(slug):
            omitted.append(
                ListOmissionReason(slug=slug[:200], reason=REASON_INVALID, entry_count=0)
            )
            diagnostics = diagnostics.merge(
                LoadDiagnostics(malformed_list_count=1, notes=(f"{slug[:60]}: unsafe slug",))
            )
            continue
        try:
            raw = RawWarningList.model_validate_json(list_file.read_bytes())
        except ValueError:
            omitted.append(ListOmissionReason(slug=slug, reason=REASON_INVALID, entry_count=0))
            diagnostics = diagnostics.merge(
                LoadDiagnostics(malformed_list_count=1, notes=(f"{slug}: schema invalid",))
            )
            continue

        if limit is not None and len(raw.list) > limit:
            omitted.append(
                ListOmissionReason(
                    slug=slug,
                    reason=REASON_OVERSIZED,
                    entry_count=len(raw.list),
                    detail=f"more than {limit} entries",
                )
            )
            continue

        body = _canonical_json(raw)
        payloads[slug] = body
        records.append(
            SnapshotListRecord(
                slug=slug,
                name=raw.name,
                version=raw.version,
                matcher=raw.type,
                entry_count=len(raw.list),
                matching_attributes=raw.matching_attributes,
                sha256=hashlib.sha256(body).hexdigest(),
            )
        )
        total_entries += len(raw.list)

    records.sort(key=lambda item: item.slug)
    omitted.sort(key=lambda item: item.slug)
    manifest = SnapshotManifest(
        upstream_repository=UPSTREAM_REPOSITORY,
        upstream_commit=commit,
        upstream_committed_at=committed_at,
        generated_at=datetime.now(UTC),
        generator=f"tools/update_misp_warninglists.py ti-recon/{__version__}",
        schema_fingerprint=schema_fingerprint,
        dataset_fingerprint=_dataset_fingerprint(records),
        list_count=len(records),
        entry_count=total_entries,
        lists=tuple(records),
        omitted=tuple(omitted),
        diagnostics=diagnostics,
    )

    _write_atomically(output, manifest, payloads)
    print(
        f"wrote {len(records)} lists / {total_entries:,} entries to {output}\n"
        f"  upstream commit    : {commit}\n"
        f"  dataset fingerprint: {manifest.dataset_fingerprint}\n"
        f"  omitted at build   : {len(omitted)} lists"
    )
    return 0


def _canonical_json(raw: RawWarningList) -> bytes:
    """Serialize one list deterministically.

    Sorted keys, no whitespace, and entries in upstream order. Determinism is
    what makes the dataset fingerprint meaningful: the same checkout must produce
    byte-identical files on any machine, or a rebuild would look like new data.
    """
    payload: dict[str, Any] = {
        "name": raw.name,
        "version": raw.version,
        "description": raw.description,
        "type": raw.type,
        "list": list(raw.list),
    }
    if raw.matching_attributes is not None:
        payload["matching_attributes"] = list(raw.matching_attributes)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _dataset_fingerprint(records: list[SnapshotListRecord]) -> str:
    """A digest over what the snapshot actually contains.

    Computed from the stored files rather than from the source tree, so it
    changes exactly when the data this package will read changes — which is what
    lets it discriminate a cache entry.
    """
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: item.slug):
        digest.update(f"{record.slug}:{record.sha256}\n".encode())
    return digest.hexdigest()


def _is_installed_location(path: Path) -> bool:
    """Whether this path lives inside an installed distribution.

    The packaged snapshot is read-only application data. Rewriting it in place
    would edit an installed distribution behind pip's back, leave the wheel's
    RECORD hashes wrong, and be silently discarded on the next reinstall -- while
    looking, to whoever ran it, exactly like a successful refresh.

    The development copy under a source checkout's ``src`` tree is a different
    thing and stays writable: that is where a new pinned baseline is prepared.
    """
    parts = set(path.parts)
    return bool(parts & {"site-packages", "dist-packages"})


def _describe_checkout(source: Path) -> tuple[str, datetime | None]:
    """Read the checkout's commit, or fall back to an explicit unknown.

    ``git`` is invoked here, in an operator tool, and nowhere near a lookup. It
    is called with a fixed argument list and no shell.
    """
    try:
        commit = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
        stamp = subprocess.run(
            ["git", "-C", str(source), "log", "-1", "--format=%cI"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "0" * 40, None
    committed_at = None
    try:
        committed_at = datetime.fromisoformat(stamp).astimezone(UTC)
    except ValueError:
        committed_at = None
    return (commit or "0" * 40), committed_at


def _write_atomically(output: Path, manifest: SnapshotManifest, payloads: dict[str, bytes]) -> None:
    """Build the snapshot beside its destination, then swap it in.

    A snapshot is read by a running process, so it is never edited in place: the
    new tree is written to a sibling directory, and only a validated, complete
    tree replaces the live one. An interrupted build leaves the previous snapshot
    exactly as it was.
    """
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f"{output.name}.incoming"
    previous = output.parent / f"{output.name}.previous"
    if staging.exists():
        shutil.rmtree(staging)
    (staging / LISTS_DIRNAME).mkdir(parents=True)

    for slug, body in payloads.items():
        (staging / LISTS_DIRNAME / f"{slug}.json").write_bytes(body)
    (staging / MANIFEST_FILENAME).write_bytes(
        json.dumps(
            manifest.model_dump(mode="json", exclude_none=True),
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )

    if previous.exists():
        shutil.rmtree(previous)
    if output.exists():
        output.rename(previous)
    staging.rename(output)
    if previous.exists():
        shutil.rmtree(previous)


if __name__ == "__main__":
    raise SystemExit(main())
