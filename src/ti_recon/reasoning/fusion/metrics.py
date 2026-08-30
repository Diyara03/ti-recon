"""Fusion metrics (Task 17).

Counts and closed vocabularies. Nothing here can hold an observable, a hash, a
URL, a user, an investigation id or a provider string: this layer sees every
claim every provider made about whatever an analyst typed, so a label carrying
the IOC would turn a metrics pipeline into a record of everything anybody has
ever investigated.

``verdict``, ``confidence``, ``verdict_rule`` and ``confidence_rule`` are all
closed sets fixed in the policy module -- four verdicts, four bands, eight
verdict rules, seven confidence rules.

Nothing is load-bearing: the default sink discards, and no rule reads a metric
back.
"""

from __future__ import annotations

from collections import deque

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "FusionMetric",
    "FusionMetricsSink",
    "InMemoryFusionMetricsSink",
    "NoOpFusionMetricsSink",
]


class FusionMetric(FrozenTiReconModel):
    """One fusion run, once it finished."""

    verdict: str = Field(min_length=1, max_length=32)
    confidence: str = Field(min_length=1, max_length=32)
    verdict_rule: str = Field(min_length=1, max_length=128)
    confidence_rule: str = Field(min_length=1, max_length=128)
    claims_normalized: int = Field(default=0, ge=0)
    claims_unclassified: int = Field(default=0, ge=0)
    conflicts: int = Field(default=0, ge=0)
    #: The operational number: malicious support nothing accounted for.
    unexplained_directional_claims: int = Field(default=0, ge=0)
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class FusionMetricsSink:
    """Where fusion metrics go. Synchronous, like every other sink here."""

    def record_fusion(self, metric: FusionMetric) -> None:  # pragma: no cover
        raise NotImplementedError


class NoOpFusionMetricsSink(FusionMetricsSink):
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_fusion(self, metric: FusionMetric) -> None:
        return None


class InMemoryFusionMetricsSink(FusionMetricsSink):
    """Bounded in-memory buffer. **NOT FOR PRODUCTION** -- process-local."""

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.records: deque[FusionMetric] = deque(maxlen=max_records)

    def record_fusion(self, metric: FusionMetric) -> None:
        self.records.append(metric)

    def __repr__(self) -> str:
        return f"<InMemoryFusionMetricsSink records={len(self.records)}>"
