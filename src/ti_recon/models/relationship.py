"""Relationships between intelligence objects (Task 3)."""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import RelationshipType
from ti_recon.models.base import Identifier, TiReconModel, UtcDatetime, new_id

__all__ = ["Relationship"]


class Relationship(TiReconModel):
    """A directed link between two objects, always backed by evidence.

    ``evidence_refs`` must be non-empty. A relationship with no evidence behind
    it is an assertion TI Recon cannot explain, and unexplainable links are how
    pivot graphs turn into guesswork.
    """

    id: Identifier = Field(default_factory=new_id)
    source_object_id: Identifier
    relationship_type: RelationshipType
    target_object_id: Identifier
    first_seen: UtcDatetime | None = None
    last_seen: UtcDatetime | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    evidence_refs: tuple[Identifier, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_relationship(self) -> Relationship:
        if self.source_object_id == self.target_object_id:
            msg = "a relationship must connect two different objects"
            raise ValueError(msg)
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.last_seen < self.first_seen
        ):
            msg = "last_seen must not precede first_seen"
            raise ValueError(msg)
        return self
