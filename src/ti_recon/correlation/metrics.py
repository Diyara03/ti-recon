"""Correlation metrics (Task 14).

Counts and enum members only. There is no field that can hold an observable, a
node key, an investigation id or a user: a metric labelled with the IOC would turn
a metrics pipeline into a record of everything every analyst has looked at, with a
retention story nobody agreed to — and this layer sees more observables than any
other, because it sees everything the providers returned as well.

Nothing is load-bearing: the default sink discards, and no decision reads a metric
back.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "CorrelationMetric",
    "CorrelationMetricsSink",
    "InMemoryCorrelationMetricsSink",
    "NoOpCorrelationMetricsSink",
]


class CorrelationMetric(FrozenTiReconModel):
    """One correlated investigation, once it finished."""

    depth: InvestigationDepth
    pivot_mode: PivotMode
    graph_nodes: int = Field(ge=0)
    graph_edges: int = Field(ge=0)
    assertions: int = Field(ge=0)
    #: Repeat renderings of one provider's claim that did not inflate an edge.
    assertions_deduplicated: int = Field(default=0, ge=0)
    identity_merges: int = Field(default=0, ge=0)
    #: Merges refused because a stronger hash disagreed.
    identity_conflicts: int = Field(default=0, ge=0)
    pivot_candidates: int = Field(default=0, ge=0)
    pivots_enriched: int = Field(default=0, ge=0)
    #: Skip reason value -> count. Bounded: the keys are enum members.
    pivots_skipped_by_reason: dict[str, int] = Field(default_factory=dict)
    cycles_prevented: int = Field(default=0, ge=0)
    graph_truncated: bool = False
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class CorrelationMetricsSink:
    """Where correlation metrics go. Synchronous, like every other sink here."""

    def record_correlation(self, metric: CorrelationMetric) -> None:  # pragma: no cover
        raise NotImplementedError


class NoOpCorrelationMetricsSink(CorrelationMetricsSink):
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_correlation(self, metric: CorrelationMetric) -> None:
        return None


class InMemoryCorrelationMetricsSink(CorrelationMetricsSink):
    """Bounded in-memory buffer. **NOT FOR PRODUCTION** — process-local."""

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.records: deque[CorrelationMetric] = deque(maxlen=max_records)

    def record_correlation(self, metric: CorrelationMetric) -> None:
        self.records.append(metric)

    def __repr__(self) -> str:
        return f"<InMemoryCorrelationMetricsSink records={len(self.records)}>"
