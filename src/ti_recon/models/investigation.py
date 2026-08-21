"""Investigation and provider-run models (Task 3).

Neither model refers to Claude or MCP. An investigation is a backend concept
that must be usable from a library, CLI or HTTP API with no LLM in the loop.
"""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from ti_recon.enums import (
    ActivityMode,
    InvestigationDepth,
    InvestigationStatus,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.base import Identifier, TiReconModel, UtcDatetime, new_id, utc_now

__all__ = ["Investigation", "ProviderRun"]


class Investigation(TiReconModel):
    """One enrichment run over one primary observable.

    ``requested_capabilities`` records the intelligence the investigation asked
    for, not the providers it happened to call. Coverage is reported against
    this list, so a thin result is distinguishable from a clean one.
    """

    id: Identifier = Field(default_factory=new_id)
    primary_object_id: Identifier
    original_input: str = Field(min_length=1, max_length=4096)
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    activity_mode: ActivityMode = ActivityMode.PASSIVE
    status: InvestigationStatus = InvestigationStatus.PENDING
    requested_capabilities: list[ProviderCapability] = Field(default_factory=list)
    started_at: UtcDatetime = Field(default_factory=utc_now)
    completed_at: UtcDatetime | None = None
    engine_version: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=64)

    @field_validator("requested_capabilities")
    @classmethod
    def _deduplicate_capabilities(cls, value: list[ProviderCapability]) -> list[ProviderCapability]:
        """Deduplicate and order capabilities so runs are reproducible."""
        return sorted(set(value), key=lambda capability: capability.value)

    @model_validator(mode="after")
    def _validate_timeline(self) -> Investigation:
        if self.completed_at is not None and self.completed_at < self.started_at:
            msg = "completed_at must not precede started_at"
            raise ValueError(msg)
        return self


class ProviderRun(TiReconModel):
    """One provider operation performed for an investigation.

    ``status`` is the outcome of *this call*. It is deliberately not a statement
    about the provider's health or about whether the credential used is valid;
    those are tracked separately so a single failed lookup cannot be mistaken
    for a broken integration.
    """

    id: Identifier = Field(default_factory=new_id)
    investigation_id: Identifier
    provider: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability
    operation: ProviderOperation
    status: ProviderRunStatus
    cache_hit: bool = False
    started_at: UtcDatetime = Field(default_factory=utc_now)
    completed_at: UtcDatetime | None = None
    api_version: str | None = Field(default=None, max_length=64)
    adapter_version: str | None = Field(default=None, max_length=64)
    error_code: ProviderErrorCategory | None = None
    raw_reference_id: Identifier | None = None

    @model_validator(mode="after")
    def _validate_run(self) -> ProviderRun:
        if self.completed_at is not None and self.completed_at < self.started_at:
            msg = "completed_at must not precede started_at"
            raise ValueError(msg)
        if self.status is ProviderRunStatus.SUCCESS and self.error_code is not None:
            msg = "a successful run must not carry an error_code"
            raise ValueError(msg)
        if self.status is ProviderRunStatus.ERROR and self.error_code is None:
            msg = "a failed run must carry a normalized error_code"
            raise ValueError(msg)
        return self

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration, or ``None`` while the run is still open."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()
