"""Investigation metrics (Task 19).

Counts and closed vocabularies. This layer sees the whole investigation, so a
label carrying the observable, the user or the investigation id would turn a
metrics pipeline into a record of everything anybody has ever looked up. Provider
ids are excluded for the same reason they are excluded from workflow policy: the
workflow does not reason about them.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "InMemoryInvestigationMetricsSink",
    "InvestigationMetric",
    "InvestigationMetricsSink",
    "NoOpInvestigationMetricsSink",
]


class InvestigationMetric(FrozenTiReconModel):
    """One finished investigation."""

    workflow_stop_reason: str = Field(min_length=1, max_length=48)
    final_verdict: str = Field(min_length=1, max_length=32)
    final_confidence: str = Field(min_length=1, max_length=32)
    final_readiness_status: str = Field(min_length=1, max_length=32)
    requested_depth: str = Field(min_length=1, max_length=16)
    rounds: int = Field(default=1, ge=1)
    continuation_attempted: bool = False
    continuation_progressed: bool = False
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class InvestigationMetricsSink:
    """Where investigation metrics go, if anywhere."""

    def record(self, metric: InvestigationMetric) -> None:  # pragma: no cover
        raise NotImplementedError


class NoOpInvestigationMetricsSink(InvestigationMetricsSink):
    """The default. Observability is opt-in."""

    def record(self, metric: InvestigationMetric) -> None:
        return None


class InMemoryInvestigationMetricsSink(InvestigationMetricsSink):
    """A bounded ring buffer, for tests and local inspection."""

    def __init__(self, capacity: int = 64) -> None:
        self._metrics: deque[InvestigationMetric] = deque(maxlen=capacity)

    def record(self, metric: InvestigationMetric) -> None:
        self._metrics.append(metric)

    @property
    def metrics(self) -> tuple[InvestigationMetric, ...]:
        return tuple(self._metrics)
