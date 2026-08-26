"""Synthetic warninglist snapshots for tests.

Deliberately synthetic rather than a copy of the shipped dataset. A matcher test
should fail because the matcher is wrong, not because upstream re-ranked a
domain — so semantics are pinned against fixtures built here, and a separate
small suite checks the real snapshot still contains the values those fixtures
model.
"""

from fixtures.warninglists.builder import (
    SnapshotBuilder,
    build_snapshot,
    realistic_lists,
)

__all__ = ["SnapshotBuilder", "build_snapshot", "realistic_lists"]
