"""Provider result envelope (Task 5).

The envelope is the single shape every adapter returns. It carries normalized
Task 3 models — never a raw provider payload, and never a credential.

It also deliberately carries no verdict, risk score or confidence: an adapter
reports what its provider said, and nothing about an adapter's data should be
able to short-circuit the assessment layer.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import (
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.base import (
    FrozenTiReconModel,
    Identifier,
    UtcDatetime,
    utc_now,
)
from ti_recon.models.evidence import Evidence, RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.investigation import ProviderRun
from ti_recon.models.relationship import Relationship
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = ["CacheabilityHint", "NormalizedPayload", "ProviderResultEnvelope", "RateLimitSnapshot"]


class RateLimitSnapshot(FrozenTiReconModel):
    """What a provider said about rate limits on this response.

    Every field is nullable because most providers expose some of this and no
    provider exposes all of it. A snapshot with everything ``None`` is a valid,
    honest answer — better than inventing numbers a scheduler would trust.
    """

    operation: str | None = Field(default=None, max_length=64)
    limit: int | None = Field(default=None, ge=0)
    remaining: int | None = Field(default=None, ge=0)
    reset_at: UtcDatetime | None = None
    scope: str | None = Field(default=None, max_length=64)

    @property
    def is_empty(self) -> bool:
        """Whether the provider told us nothing about its limits."""
        return (
            self.limit is None
            and self.remaining is None
            and self.reset_at is None
            and self.scope is None
        )


class CacheabilityHint(FrozenTiReconModel):
    """Whether and for how long this result may be reused.

    Only metadata: the cache itself is Task 6. Recording the hint now means
    adapters do not have to be revisited when caching lands.
    """

    cacheable: bool = True
    ttl_seconds: int | None = Field(default=None, ge=0, le=60 * 60 * 24 * 30)
    cache_key_hint: str | None = Field(default=None, max_length=256)
    revalidate_after: UtcDatetime | None = None

    @model_validator(mode="after")
    def _validate_hint(self) -> CacheabilityHint:
        if not self.cacheable and (self.ttl_seconds or self.revalidate_after):
            msg = "an uncacheable result must not carry cache lifetimes"
            raise ValueError(msg)
        return self


class NormalizedPayload(FrozenTiReconModel):
    """The Task 3 models an adapter extracted from one provider response.

    Returned by ``ProviderAdapter.normalize`` and embedded in the envelope, so
    normalization is independently testable against a stored fixture without
    performing any I/O.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_payload(self) -> NormalizedPayload:
        _reject_credential_like_warnings(self.warnings)
        _require_relationship_evidence(self.relationships)
        return self


class ProviderResultEnvelope(FrozenTiReconModel):
    """Everything one provider operation produced."""

    provider: str = Field(min_length=1, max_length=64)
    operation: ProviderOperation
    status: ProviderRunStatus
    retrieved_at: UtcDatetime = Field(default_factory=utc_now)
    api_version: str | None = Field(default=None, max_length=32)
    adapter_version: str = Field(min_length=1, max_length=32)

    cacheability: CacheabilityHint = CacheabilityHint()
    rate_limit: RateLimitSnapshot | None = None

    raw_reference: RawEvidenceReference | None = None

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()

    error_category: ProviderErrorCategory | None = None
    error_message: str | None = Field(default=None, max_length=500)
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_envelope(self) -> ProviderResultEnvelope:
        if self.status is ProviderRunStatus.SUCCESS and self.error_category is not None:
            msg = "a successful result must not carry an error category"
            raise ValueError(msg)
        if self.status is ProviderRunStatus.ERROR and self.error_category is None:
            msg = "a failed result must carry a normalized error category"
            raise ValueError(msg)
        for evidence in self.evidence:
            if evidence.transport_provider != self.provider:
                msg = "every piece of evidence must record this provider as its transport_provider"
                raise ValueError(msg)
        _reject_credential_like_warnings(self.warnings)
        if self.error_message and SENSITIVE_KEY_PATTERN.search(self.error_message):
            msg = "error_message must not mention credential material"
            raise ValueError(msg)
        _require_relationship_evidence(self.relationships)
        return self

    @classmethod
    def from_payload(
        cls,
        *,
        provider: str,
        operation: ProviderOperation,
        status: ProviderRunStatus,
        adapter_version: str,
        payload: NormalizedPayload,
        api_version: str | None = None,
        raw_reference: RawEvidenceReference | None = None,
        cacheability: CacheabilityHint | None = None,
        rate_limit: RateLimitSnapshot | None = None,
    ) -> ProviderResultEnvelope:
        """Build an envelope around a normalized payload."""
        return cls(
            provider=provider,
            operation=operation,
            status=status,
            adapter_version=adapter_version,
            api_version=api_version,
            cacheability=cacheability or CacheabilityHint(),
            rate_limit=rate_limit,
            raw_reference=raw_reference,
            evidence=payload.evidence,
            objects=payload.objects,
            relationships=payload.relationships,
            warnings=payload.warnings,
        )

    def to_provider_run(
        self,
        *,
        investigation_id: Identifier,
        capability: ProviderCapability,
        started_at: UtcDatetime | None = None,
        cache_hit: bool = False,
    ) -> ProviderRun:
        """Record this result as a Task 3 :class:`ProviderRun`."""
        return ProviderRun(
            investigation_id=investigation_id,
            provider=self.provider,
            capability=capability,
            operation=self.operation,
            status=self.status,
            cache_hit=cache_hit,
            started_at=started_at or self.retrieved_at,
            completed_at=self.retrieved_at,
            api_version=self.api_version,
            adapter_version=self.adapter_version,
            error_code=self.error_category,
            raw_reference_id=self.raw_reference.id if self.raw_reference else None,
        )

    @property
    def has_data(self) -> bool:
        """Whether this result contributed anything to the investigation."""
        return bool(self.evidence or self.objects or self.relationships)


def _reject_credential_like_warnings(warnings: tuple[str, ...]) -> None:
    for warning in warnings:
        if SENSITIVE_KEY_PATTERN.search(warning):
            msg = "warnings must not mention credential material"
            raise ValueError(msg)


def _require_relationship_evidence(relationships: tuple[Relationship, ...]) -> None:
    for relationship in relationships:
        if not relationship.evidence_refs:  # pragma: no cover - Relationship enforces this
            msg = "every relationship must reference at least one piece of evidence"
            raise ValueError(msg)
