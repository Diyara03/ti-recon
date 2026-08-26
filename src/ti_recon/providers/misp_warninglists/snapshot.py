"""Reading a pinned warninglist snapshot off local disk (Task 11).

A snapshot is a directory:

.. code-block:: text

    <root>/
      manifest.json        provenance, per-list metadata, omissions, diagnostics
      lists/<slug>.json    one upstream list, compact, exactly the raw schema

Everything this module does is local. There is no client, no URL, no host and no
socket — refreshing a snapshot is an operator action performed by
``tools/update_misp_warninglists.py``, never something a lookup can trigger. A
provider that could update itself during enrichment would make every answer
depend on when it was asked.

Reading untrusted-ish files carefully
-------------------------------------

A snapshot directory is operator-supplied, which is not the same as trusted: it
may have been built by an older tool, copied over a network share, or edited by
hand. So slugs are pattern-checked before they touch a path, resolved paths must
stay inside the root, file sizes are bounded before being read, and checksums are
verified against the manifest. A tampered or truncated snapshot is refused rather
than half-loaded.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from ti_recon.models.base import utc_now
from ti_recon.providers.misp_warninglists.models import (
    RawWarningList,
    SnapshotListRecord,
    SnapshotManifest,
)

__all__ = [
    "LISTS_DIRNAME",
    "MANIFEST_FILENAME",
    "MAX_LIST_FILE_BYTES",
    "MAX_MANIFEST_BYTES",
    "SLUG_PATTERN",
    "SnapshotError",
    "WarningListSnapshot",
    "load_snapshot",
    "slug_is_safe",
]

MANIFEST_FILENAME: Final[str] = "manifest.json"
LISTS_DIRNAME: Final[str] = "lists"

#: A slug names a file, so it is validated before it is ever joined to a path.
#: No separators, no dots, no traversal — the shape upstream directory names
#: already have.
SLUG_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,120}\Z")

#: Read bounds. The pinned snapshot's largest retained file is a few megabytes;
#: these are generous ceilings that still stop a corrupt file from being loaded
#: into memory before anyone looks at it.
MAX_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_LIST_FILE_BYTES: Final[int] = 64 * 1024 * 1024


class SnapshotError(RuntimeError):
    """A snapshot could not be read, or could not be trusted."""


def slug_is_safe(slug: str) -> bool:
    """Whether ``slug`` may be used to build a path.

    Rejects traversal, separators and a leading dot outright rather than
    sanitizing: a slug that needed cleaning is a slug this snapshot did not
    write, and guessing what it meant is how a path escapes a root.
    """
    if not SLUG_PATTERN.fullmatch(slug):
        return False
    return ".." not in slug


class WarningListSnapshot:
    """A verified snapshot directory, read one list at a time.

    Deliberately lazy. The manifest carries every list's matcher type and entry
    count, so a profile decides what to load *before* anything is parsed — which
    is what keeps a bounded profile from paying the cost of the lists it
    excludes.
    """

    def __init__(self, root: Path, manifest: SnapshotManifest) -> None:
        self._root = root
        self._manifest = manifest

    @property
    def root(self) -> Path:
        return self._root

    @property
    def manifest(self) -> SnapshotManifest:
        return self._manifest

    def age(self) -> timedelta:
        """How long ago this snapshot was generated."""
        return utc_now() - self._manifest.generated_at

    def is_stale(self, threshold: timedelta) -> bool:
        """Whether the snapshot is older than ``threshold``.

        A stale snapshot is reported, never refreshed: the only correct response
        to old data during a lookup is to say it is old.
        """
        return self.age() > threshold

    def list_path(self, slug: str) -> Path:
        """The path holding ``slug``'s list, verified to stay inside the root."""
        if not slug_is_safe(slug):
            msg = f"unsafe warninglist slug: {slug!r}"
            raise SnapshotError(msg)
        lists_root = (self._root / LISTS_DIRNAME).resolve()
        candidate = (lists_root / f"{slug}.json").resolve()
        # Belt and braces. The slug pattern already forbids separators, but the
        # containment check is what holds if that pattern is ever loosened, and
        # it also catches a symlink pointing out of the tree.
        if not candidate.is_relative_to(lists_root):
            msg = f"warninglist path escapes the snapshot root: {slug!r}"
            raise SnapshotError(msg)
        return candidate

    def read_list(self, record: SnapshotListRecord) -> RawWarningList:
        """Read and verify one list.

        The checksum is verified before the JSON is parsed as a warninglist, so
        a modified file is refused as a snapshot problem rather than surfacing
        later as a strange match.
        """
        path = self.list_path(record.slug)
        raw = _read_bounded(path, MAX_LIST_FILE_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != record.sha256:
            msg = f"checksum mismatch for warninglist {record.slug!r}"
            raise SnapshotError(msg)
        try:
            payload: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            msg = f"warninglist {record.slug!r} is not valid JSON"
            raise SnapshotError(msg) from exc
        if not isinstance(payload, dict):
            msg = f"warninglist {record.slug!r} is not a JSON object"
            raise SnapshotError(msg)
        return RawWarningList.model_validate(payload)

    def __repr__(self) -> str:
        return (
            f"<WarningListSnapshot commit={self._manifest.upstream_commit[:12]} "
            f"lists={self._manifest.list_count} entries={self._manifest.entry_count}>"
        )


def load_snapshot(root: Path) -> WarningListSnapshot:
    """Read and validate the manifest at ``root``.

    Raises :class:`SnapshotError` for anything that makes the snapshot unusable —
    an absent directory, an unreadable or oversized manifest, a manifest that is
    not this format version. Those are provider *errors*, not empty results: an
    analyst must never be told "no warninglist matched" by a provider that could
    not read its dataset.
    """
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        msg = f"warninglist snapshot directory not found: {resolved}"
        raise SnapshotError(msg)
    manifest_path = resolved / MANIFEST_FILENAME
    if not manifest_path.is_file():
        msg = f"warninglist snapshot has no {MANIFEST_FILENAME}"
        raise SnapshotError(msg)

    raw = _read_bounded(manifest_path, MAX_MANIFEST_BYTES)
    try:
        payload: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        msg = "warninglist manifest is not valid JSON"
        raise SnapshotError(msg) from exc
    if not isinstance(payload, dict):
        msg = "warninglist manifest is not a JSON object"
        raise SnapshotError(msg)
    try:
        manifest = SnapshotManifest.model_validate(payload)
    except ValueError as exc:
        # Deliberately not echoing the validation detail: it can quote manifest
        # content, and a snapshot problem needs a stable message rather than a
        # variable one.
        msg = "warninglist manifest failed validation"
        raise SnapshotError(msg) from exc
    if manifest.snapshot_format != 1:
        msg = f"unsupported warninglist snapshot format: {manifest.snapshot_format}"
        raise SnapshotError(msg)
    return WarningListSnapshot(resolved, manifest)


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read a file, refusing one larger than ``limit``.

    The size is checked before the read so an implausible file is never brought
    into memory at all.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        msg = f"cannot read {path.name}"
        raise SnapshotError(msg) from exc
    if size > limit:
        msg = f"{path.name} is larger than this loader will read"
        raise SnapshotError(msg)
    try:
        return path.read_bytes()
    except OSError as exc:
        msg = f"cannot read {path.name}"
        raise SnapshotError(msg) from exc
