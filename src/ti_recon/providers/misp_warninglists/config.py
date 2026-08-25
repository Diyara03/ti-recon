"""How to reach the local warninglist dataset (Task 11).

Notice what is not here: no host, no base URL, no timeout, no auth placement, no
credential field of any kind. This provider has no transport, so a configuration
object for it is a path, a freshness threshold and some bounds.

That absence is the point of the whole task. A false-positive-context source that
needed a MISP server, an API key and network reachability would be unavailable
exactly when an analyst most wants it — during triage, offline, on a laptop.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Final

from pydantic import Field, field_validator

from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "DEFAULT_SNAPSHOT_ROOT",
    "DEFAULT_STALE_AFTER_DAYS",
    "MispWarningListsConfig",
]


def _default_snapshot_root() -> Path:
    """The snapshot shipped with the repository.

    Resolved from this module's own location rather than from the working
    directory, so a lookup finds the dataset regardless of where the process was
    started.
    """
    return Path(__file__).resolve().parents[3].parent / "data" / "misp_warninglists"


DEFAULT_SNAPSHOT_ROOT: Final[Path] = _default_snapshot_root()

#: When a snapshot starts being reported as stale. Upstream moves daily, so a
#: month-old dataset is still useful and worth flagging rather than refusing:
#: RFC1918 has not changed, but this month's scanner ranges may have.
DEFAULT_STALE_AFTER_DAYS: Final[int] = 30


class MispWarningListsConfig(FrozenTiReconModel):
    """Where the dataset is, how old is too old, and how much detail to keep."""

    snapshot_root: Path = DEFAULT_SNAPSHOT_ROOT

    #: Operator-configurable. Exceeding it marks coverage stale; it never fails a
    #: lookup and never triggers a refresh.
    stale_after: timedelta = timedelta(days=DEFAULT_STALE_AFTER_DAYS)

    #: Hard ceiling on match records in one result, above every depth bound.
    max_match_records: int = Field(default=100, ge=1, le=500)

    @field_validator("snapshot_root")
    @classmethod
    def _validate_root(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            # Relative roots resolve against the process's working directory,
            # which is not a property of the deployment. Made absolute here so
            # the path recorded in a diagnostic is the path that was read.
            expanded = expanded.resolve()
        return expanded

    @field_validator("stale_after")
    @classmethod
    def _validate_stale_after(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0):
            msg = "stale_after must be positive"
            raise ValueError(msg)
        return value
