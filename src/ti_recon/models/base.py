"""Shared model plumbing: base classes, identifiers and UTC timestamps."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

__all__ = [
    "FrozenTiReconModel",
    "Identifier",
    "TiReconModel",
    "UtcDatetime",
    "new_id",
    "utc_now",
]


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def new_id() -> str:
    """Return a fresh opaque identifier."""
    return str(uuid4())


def _require_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware ones to UTC.

    Naive timestamps are rejected rather than assumed to be UTC: threat
    intelligence timestamps arrive from many providers in many zones, and
    silently guessing produces evidence that is quietly wrong about
    first/last-seen ordering.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        msg = "timestamp must be timezone-aware"
        raise ValueError(msg)
    return value.astimezone(UTC)


#: A timezone-aware timestamp, always normalized to UTC.
UtcDatetime = Annotated[datetime, AfterValidator(_require_utc)]

#: A non-empty opaque identifier.
Identifier = Annotated[str, Field(min_length=1, max_length=200)]


class TiReconModel(BaseModel):
    """Base class for mutable TI Recon models."""

    # Strings are deliberately *not* auto-stripped: models record provenance,
    # so a stored value must be exactly what was recorded. Callers normalize
    # explicitly where normalization is meaningful.
    #
    # ``hide_input_in_errors`` matters for security, not tidiness: by default
    # pydantic embeds the rejected input in the ValidationError message, so a
    # field that happens to hold credential material would leak it into any log
    # that captures the exception.
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        hide_input_in_errors=True,
    )


class FrozenTiReconModel(TiReconModel):
    """Base class for models that must not change after construction.

    Used for provider facts. Evidence records what a provider said at a point
    in time; engine interpretation is expressed in separate models rather than
    by editing the fact.
    """

    model_config = ConfigDict(frozen=True)
