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

    #: ``True`` when the provider *watched this happen* — a sandbox execution, a
    #: live page load — rather than holding a record that it once did.
    #:
    #: Deliberately separate from the evidence's :class:`EvidenceClass`, because
    #: the two answer different questions. The class says what *kind of claim* the
    #: evidence is: a sandbox's contacted domain is ``CONTEXT`` because it accuses
    #: nobody — a detonating sample also reaches CRLs, CDNs and time servers. This
    #: flag says how the provider came to know, and a watched connection is a
    #: stronger basis than a passive-DNS row whatever the claim's kind. Collapsing
    #: them made every sandbox observation read as a database lookup.
    #:
    #: A boolean rather than a tri-state: the third basis a correlation layer
    #: distinguishes is TI Recon's own derivation, which no provider can claim, so
    #: a provider-facing enum would carry a member nobody may set. The default is
    #: the conservative one, so a provider that says nothing is never overstated.
    directly_observed: bool = False

    #: The provider's own name for this link, before it was mapped to the
    #: canonical vocabulary — ``contacted_domains``, ``payloads``, ``resolutions``.
    #:
    #: Kept because the mapping is a judgement someone will eventually want to
    #: argue with. Nine provider vocabularies collapse into thirteen canonical
    #: types, and without the original name a wrong mapping is invisible: the
    #: relationship simply looks like something the provider said. It is also what
    #: lets one provider assert two genuinely different links between the same
    #: pair of objects without them deduplicating into one.
    raw_relationship_type: str | None = Field(default=None, max_length=128)

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
