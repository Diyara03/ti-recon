"""Alternative-explanation reasoning metrics (Task 16).

Counts and closed enum vocabularies. Nothing here can hold an observable, a
node key, a warninglist slug, an investigation id or a user: this layer sees
every claim every provider made about whatever an analyst typed, so a label
carrying the IOC would turn a metrics pipeline into a record of everything
anybody has ever looked at, with a retention story nobody agreed to.

``findings_by_role`` and ``findings_by_reason`` are keyed by enum member value --
seven and fifteen possible keys respectively, both fixed in the policy module.

Nothing is load-bearing: the default sink discards, and no rule reads a metric
back.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "InMemoryReasoningMetricsSink",
    "NoOpReasoningMetricsSink",
    "ReasoningMetric",
    "ReasoningMetricsSink",
]


class ReasoningMetric(FrozenTiReconModel):
    """One reasoning run, once it finished."""

    evidence_examined: int = Field(default=0, ge=0)
    directional_evidence_examined: int = Field(default=0, ge=0)
    reasoning_findings: int = Field(default=0, ge=0)
    #: Role value -> count. Seven possible keys.
    findings_by_role: dict[str, int] = Field(default_factory=dict)
    #: Reason value -> count. Fifteen possible keys.
    findings_by_reason: dict[str, int] = Field(default_factory=dict)
    rules_matched: int = Field(default=0, ge=0)
    #: The number that matters operationally: claims nothing accounted for.
    directional_evidence_without_explanations: int = Field(default=0, ge=0)
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class ReasoningMetricsSink:
    """Where reasoning metrics go. Synchronous, like every other sink here."""

    def record_reasoning(self, metric: ReasoningMetric) -> None:  # pragma: no cover
        raise NotImplementedError


class NoOpReasoningMetricsSink(ReasoningMetricsSink):
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_reasoning(self, metric: ReasoningMetric) -> None:
        return None


class InMemoryReasoningMetricsSink(ReasoningMetricsSink):
    """Bounded in-memory buffer. **NOT FOR PRODUCTION** -- process-local."""

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.records: deque[ReasoningMetric] = deque(maxlen=max_records)

    def record_reasoning(self, metric: ReasoningMetric) -> None:
        self.records.append(metric)

    def __repr__(self) -> str:
        return f"<InMemoryReasoningMetricsSink records={len(self.records)}>"
