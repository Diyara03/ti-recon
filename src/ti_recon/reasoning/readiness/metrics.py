"""Readiness metrics (Task 18).

Counts and closed vocabularies only. This layer sees the whole investigation, so
a label carrying the observable, the hash, the URL, the user or the investigation
id would turn a metrics pipeline into a log of everything anybody has ever looked
up. Provider ids are excluded for the same reason they are excluded from policy:
they are not the unit readiness reasons about.

Nothing is load-bearing -- the default sink discards, and no rule reads a metric
back.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "InMemoryReadinessMetricsSink",
    "NoOpReadinessMetricsSink",
    "ReadinessMetric",
    "ReadinessMetricsSink",
]


class ReadinessMetric(FrozenTiReconModel):
    """One readiness run, once it finished."""

    readiness_status: str = Field(min_length=1, max_length=32)
    coverage_adequacy: str = Field(min_length=1, max_length=32)
    continuation_state: str = Field(min_length=1, max_length=32)
    purpose: str = Field(min_length=1, max_length=32)
    requested_depth: str = Field(min_length=1, max_length=16)
    verdict: str = Field(min_length=1, max_length=32)
    requirements_total: int = Field(default=0, ge=0)
    requirements_satisfied: int = Field(default=0, ge=0)
    material_gaps: int = Field(default=0, ge=0)
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class ReadinessMetricsSink:
    """Where readiness metrics go, if anywhere."""

    def record(self, metric: ReadinessMetric) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class NoOpReadinessMetricsSink(ReadinessMetricsSink):
    """The default. Observability is opt-in."""

    def record(self, metric: ReadinessMetric) -> None:
        return None


class InMemoryReadinessMetricsSink(ReadinessMetricsSink):
    """A bounded ring buffer, for tests and local inspection."""

    def __init__(self, capacity: int = 128) -> None:
        self._metrics: deque[ReadinessMetric] = deque(maxlen=capacity)

    def record(self, metric: ReadinessMetric) -> None:
        self._metrics.append(metric)

    @property
    def metrics(self) -> tuple[ReadinessMetric, ...]:
        return tuple(self._metrics)
