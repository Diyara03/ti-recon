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
from importlib import resources
from pathlib import Path
from typing import Final

from pydantic import Field, field_validator

from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "DEFAULT_SNAPSHOT_ROOT",
    "DEFAULT_STALE_AFTER_DAYS",
    "MispWarningListsConfig",
]


#: Where the pinned snapshot lives inside the ``ti_recon`` package.
_PACKAGED_SNAPSHOT_SUBPATH: Final[tuple[str, ...]] = ("data", "misp_warninglists")


def _default_snapshot_root() -> Path:
    """The pinned snapshot shipped inside the installed package.

    Resolved as a **package resource**, not from the repository layout. An
    earlier version walked ``Path(__file__).parents[3].parent``, which found
    ``<repo>/data/misp_warninglists`` in a checkout and, once installed, pointed
    at ``<venv>/lib/python3.12/data/misp_warninglists`` — a directory that has
    never existed. The source tree and the wheel therefore had different default
    behaviour, which is the one thing a default must not have.

    ``importlib.resources`` asks the import system where the package actually is,
    so a checkout, an editable install and an installed wheel all answer
    correctly without anyone counting directory levels.

    The loader needs a real directory: it resolves paths, checks containment,
    stats sizes and reads individual lists rather than holding 9 MB in memory. A
    wheel installs unpacked, so that holds. A zip-imported deployment cannot
    offer one, and rather than silently materialising the dataset to a temporary
    directory this returns the traversable's path so the loader reports a
    missing snapshot in its own vocabulary.
    """
    resource = resources.files("ti_recon").joinpath(*_PACKAGED_SNAPSHOT_SUBPATH)
    if isinstance(resource, Path):
        return resource
    return Path(str(resource))


DEFAULT_SNAPSHOT_ROOT: Final[Path] = _default_snapshot_root()

#: When a snapshot starts being reported as stale. Upstream moves daily, so a
#: month-old dataset is still useful and worth flagging rather than refusing:
#: RFC1918 has not changed, but this month's scanner ranges may have.
DEFAULT_STALE_AFTER_DAYS: Final[int] = 30


class MispWarningListsConfig(FrozenTiReconModel):
    """Where the dataset is, how old is too old, and how much detail to keep."""

    #: Defaults to the snapshot packaged inside ``ti_recon``. An operator may
    #: point this at a newer external snapshot; an explicit path always wins, and
    #: a bad one is reported rather than quietly replaced by the packaged
    #: baseline. The packaged copy is immutable read-only application data.
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
