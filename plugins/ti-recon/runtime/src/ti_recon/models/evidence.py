"""Evidence models (Task 3).

``Evidence`` is the most important entity in TI Recon. One instance is **one
factual claim or observation** — never a whole provider response. A single
VirusTotal report typically yields several pieces of evidence (a detection
aggregate, a resolution observation, a submission-name observation), each with
its own class, scope and provenance.

Evidence is a record of what a provider said. It is frozen: engine
interpretation is expressed in ``AssessmentContribution``, never by editing the
fact.
"""

from __future__ import annotations

import re
from typing import Any, Final

from pydantic import Field, field_validator, model_validator

from ti_recon.enums import (
    ConflictSeverity,
    ConflictStatus,
    ConflictType,
    EvidenceClass,
    EvidenceEffect,
    InformationCredibilityGrade,
    MatchScope,
    ProviderOperation,
    SourceReliabilityGrade,
)
from ti_recon.models.base import (
    FrozenTiReconModel,
    Identifier,
    TiReconModel,
    UtcDatetime,
    new_id,
    utc_now,
)
from ti_recon.security import reject_credential_like_keys

__all__ = ["Evidence", "EvidenceConflict", "RawEvidenceReference"]

#: Claim types are an open vocabulary — every provider surfaces claims nobody
#: anticipated — but the format is fixed so claims stay groupable and greppable.
CLAIM_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")


class RawEvidenceReference(FrozenTiReconModel):
    """A pointer to a stored raw provider response.

    The raw payload itself is intentionally *not* held here. Keeping only a
    reference means normalized evidence can be passed around, logged and
    serialized without dragging an unaudited provider payload — which may echo
    request headers — along with it.
    """

    id: Identifier = Field(default_factory=new_id)
    investigation_id: Identifier
    provider: str = Field(min_length=1, max_length=64)
    operation: ProviderOperation
    storage_key: str = Field(min_length=1, max_length=512)
    content_type: str = Field(default="application/json", max_length=128)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    retrieved_at: UtcDatetime = Field(default_factory=utc_now)
    redacted: bool = Field(
        default=True,
        description="Whether request/auth material was stripped before storage.",
    )


class Evidence(FrozenTiReconModel):
    """A single factual claim made by a provider about one object.

    Provenance is mandatory. ``transport_provider`` is whose API was called;
    ``origin_provider`` is who produced the data. They differ whenever a
    provider relays third-party intelligence, and keeping them apart is what
    stops relayed data from being counted as independent confirmation.

    The three confidence signals are deliberately separate and are never
    combined here:

    * ``provider_confidence`` — what the provider itself asserts;
    * ``source_reliability`` — how dependable that source has proven to be;
    * ``information_credibility`` — how credible this particular claim is.

    Final investigation confidence is a fourth, distinct number computed by the
    assessment layer.
    """

    id: Identifier = Field(default_factory=new_id)
    investigation_id: Identifier
    subject_object_id: Identifier

    evidence_class: EvidenceClass
    claim_type: str = Field(min_length=1, max_length=128)
    effect: EvidenceEffect

    transport_provider: str = Field(min_length=1, max_length=64)
    origin_provider: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)

    provider_confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    source_reliability: SourceReliabilityGrade | None = None
    information_credibility: InformationCredibilityGrade | None = None

    match_scope: MatchScope = MatchScope.UNKNOWN

    first_seen: UtcDatetime | None = None
    last_seen: UtcDatetime | None = None
    observed_at: UtcDatetime | None = None
    retrieved_at: UtcDatetime = Field(default_factory=utc_now)

    lineage_group_id: str = Field(default="", max_length=200)
    upstream_evidence_refs: tuple[Identifier, ...] = ()

    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_reference_id: Identifier | None = None

    @field_validator("claim_type")
    @classmethod
    def _validate_claim_type(cls, value: str) -> str:
        if not CLAIM_TYPE_PATTERN.fullmatch(value):
            msg = "claim_type must be lowercase alphanumeric segments separated by '.', '_' or '-'"
            raise ValueError(msg)
        return value

    @field_validator("attributes")
    @classmethod
    def _reject_credential_material(cls, value: dict[str, Any]) -> dict[str, Any]:
        reject_credential_like_keys(value, where="Evidence.attributes")
        return value

    @model_validator(mode="after")
    def _validate_evidence(self) -> Evidence:
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.last_seen < self.first_seen
        ):
            msg = "last_seen must not precede first_seen"
            raise ValueError(msg)
        if self.evidence_class is EvidenceClass.CONTEXT and self.effect is not (
            EvidenceEffect.CONTEXT_ONLY
        ):
            msg = "context evidence must have effect context_only"
            raise ValueError(msg)
        if not self.lineage_group_id:
            # Default lineage grouping is conservative: evidence originating
            # from the same source is assumed non-independent unless an adapter
            # states a narrower group.
            object.__setattr__(
                self,
                "lineage_group_id",
                f"{self.source_family}:{self.origin_provider}",
            )
        return self

    @property
    def is_relayed(self) -> bool:
        """Whether this evidence reached us through a third party."""
        return self.transport_provider != self.origin_provider

    def shares_lineage_with(self, other: Evidence) -> bool:
        """Whether two pieces of evidence must not be treated as independent."""
        return self.lineage_group_id == other.lineage_group_id


class EvidenceConflict(TiReconModel):
    """Two pieces of evidence that cannot both be straightforwardly true.

    Conflicts are recorded rather than silently resolved: an unresolved conflict
    is itself information, and hiding it would make a confident-looking verdict
    out of a genuinely murky picture.
    """

    id: Identifier = Field(default_factory=new_id)
    investigation_id: Identifier
    evidence_a_id: Identifier
    evidence_b_id: Identifier
    conflict_type: ConflictType
    severity: ConflictSeverity
    status: ConflictStatus = ConflictStatus.OPEN
    resolution_note: str | None = Field(default=None, max_length=2000)
    detected_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_conflict(self) -> EvidenceConflict:
        if self.evidence_a_id == self.evidence_b_id:
            msg = "a conflict must reference two different pieces of evidence"
            raise ValueError(msg)
        if self.status is ConflictStatus.RESOLVED and not self.resolution_note:
            msg = "a resolved conflict must record how it was resolved"
            raise ValueError(msg)
        return self
