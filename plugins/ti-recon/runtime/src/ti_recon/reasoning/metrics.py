"""Qualification metrics (Task 15).

Counts and enum members. No field can hold an observable, a node key, a
warninglist slug, an investigation id or a user — this layer sees everything the
providers returned, so a label carrying the IOC would turn a metrics pipeline
into a record of every value every analyst has ever looked at, with a retention
story nobody agreed to.

``cues_by_type`` is keyed by enum member value, which is a closed vocabulary of
fifteen strings. Nothing else is dimensioned.

Nothing is load-bearing: the default sink discards, and no rule reads a metric
back.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "InMemoryQualificationMetricsSink",
    "NoOpQualificationMetricsSink",
    "QualificationMetric",
    "QualificationMetricsSink",
]


class QualificationMetric(FrozenTiReconModel):
    """One qualification run, once it finished."""

    provider_results: int = Field(default=0, ge=0)
    evidence_items: int = Field(default=0, ge=0)
    temporal_facts: int = Field(default=0, ge=0)
    temporal_issues: int = Field(default=0, ge=0)
    context_signals: int = Field(default=0, ge=0)
    interpretation_cues: int = Field(default=0, ge=0)
    #: Cue type value -> count. Bounded: the keys are enum members.
    cues_by_type: dict[str, int] = Field(default_factory=dict)
    providers_without_qualifier: int = Field(default=0, ge=0)
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class QualificationMetricsSink:
    """Where qualification metrics go. Synchronous, like every other sink here."""

    def record_qualification(self, metric: QualificationMetric) -> None:  # pragma: no cover
        raise NotImplementedError


class NoOpQualificationMetricsSink(QualificationMetricsSink):
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_qualification(self, metric: QualificationMetric) -> None:
        return None


class InMemoryQualificationMetricsSink(QualificationMetricsSink):
    """Bounded in-memory buffer. **NOT FOR PRODUCTION** — process-local."""

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.records: deque[QualificationMetric] = deque(maxlen=max_records)

    def record_qualification(self, metric: QualificationMetric) -> None:
        self.records.append(metric)

    def __repr__(self) -> str:
        return f"<InMemoryQualificationMetricsSink records={len(self.records)}>"
