"""Planning metrics (Task 13).

Observability for *decisions*, alongside Task 6's observability for executions.
The two answer different questions: Task 6 says how a provider call went, this
says why it was made — or why something else was not.

Low cardinality, by construction
--------------------------------

Every field is an enum member, a bounded provider id, a small integer or a
boolean. There is **no observable value** anywhere and no free text: labelling a
metric with the IOC would turn a metrics pipeline into a log of everything every
analyst has looked at, with a retention story nobody agreed to. The object type
is recorded instead, which is what an aggregate actually wants.

There is also nothing here a credential could reach. Planning never sees one.

What a planning metric is for
-----------------------------

Three questions this makes answerable and reasoning about them impossible
without: are plans stopping because they got what they needed or because
something was blocked; is a provider being skipped so consistently that its
profile or entitlement is wrong; and is a depth's budget actually being spent, or
is enrichment quietly stopping short of it.

None of it is load-bearing. The default sink discards, and no decision reads a
metric back.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Protocol, runtime_checkable

from pydantic import Field

from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now
from ti_recon.planning.models import (
    CallCostClass,
    NoveltyClass,
    ProviderLocality,
    SelectionReason,
    SkipReason,
    StopReason,
)

__all__ = [
    "InMemoryPlanningMetricsSink",
    "NoOpPlanningMetricsSink",
    "PlanningMetricsSink",
    "PlanningRunMetric",
    "ProviderSelectionMetric",
    "ProviderSkipMetric",
]


class ProviderSelectionMetric(FrozenTiReconModel):
    """One provider chosen for one capability."""

    provider_id: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability
    object_type: IntelObjectType
    depth: InvestigationDepth
    locality: ProviderLocality
    cost_class: CallCostClass
    novelty: NoveltyClass
    reason: SelectionReason
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class ProviderSkipMetric(FrozenTiReconModel):
    """One provider passed over, and the reason code.

    Aggregated, this is the most useful thing here: a provider skipped for
    ``BLOCKED`` all week is an entitlement problem, and one skipped for
    ``UNSUPPORTED_OBSERVABLE`` all week is a catalogue gap. Both look like
    silence without a counter.

    ``SkippedCandidate.detail`` is deliberately *not* carried: it is short free
    text meant for a human reading one trace, and free text is what makes a
    metric label unbounded.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    #: Absent when the skip was not about a provider at all — a goal that is not
    #: yet active is recorded without one.
    capability: ProviderCapability | None = None
    object_type: IntelObjectType
    depth: InvestigationDepth
    reason: SkipReason
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


class PlanningRunMetric(FrozenTiReconModel):
    """One enrichment run, once it stopped."""

    object_type: IntelObjectType
    depth: InvestigationDepth
    stop_reason: StopReason
    rounds: int = Field(ge=0)
    providers_called: int = Field(ge=0)
    remote_runs_used: int = Field(ge=0)
    high_cost_runs_used: int = Field(ge=0)
    remote_budget: int = Field(ge=0)
    cache_hits: int = Field(ge=0)
    #: Whether a REQUIRED capability finished the run uncovered. The single most
    #: important planning signal: a run that stopped tidily without answering the
    #: question it existed to answer.
    required_capability_uncovered: bool = False
    recorded_at: UtcDatetime = Field(default_factory=utc_now)


@runtime_checkable
class PlanningMetricsSink(Protocol):
    """Where planning metrics go.

    Synchronous, like the execution sink: the orchestrator emits between provider
    calls, and a sink that awaited would put a metrics backend's latency into an
    enrichment run. A sink needing I/O should enqueue and drain elsewhere.
    """

    def record_selection(self, metric: ProviderSelectionMetric) -> None:
        """Record one selected provider."""
        ...

    def record_skip(self, metric: ProviderSkipMetric) -> None:
        """Record one skipped candidate."""
        ...

    def record_run(self, metric: PlanningRunMetric) -> None:
        """Record one completed planning run."""
        ...


class NoOpPlanningMetricsSink:
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_selection(self, metric: ProviderSelectionMetric) -> None:
        return None

    def record_skip(self, metric: ProviderSkipMetric) -> None:
        return None

    def record_run(self, metric: PlanningRunMetric) -> None:
        return None


class InMemoryPlanningMetricsSink:
    """Keeps recent planning metrics in bounded buffers.

    **NOT FOR PRODUCTION.** Process-local, unaggregated, dropped on restart. It
    exists so tests can assert what was emitted and so local development can see
    what the planner decided.
    """

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.selections: deque[ProviderSelectionMetric] = deque(maxlen=max_records)
        self.skips: deque[ProviderSkipMetric] = deque(maxlen=max_records)
        self.runs: deque[PlanningRunMetric] = deque(maxlen=max_records)

    def record_selection(self, metric: ProviderSelectionMetric) -> None:
        self.selections.append(metric)

    def record_skip(self, metric: ProviderSkipMetric) -> None:
        self.skips.append(metric)

    def record_run(self, metric: PlanningRunMetric) -> None:
        self.runs.append(metric)

    # -- read helpers for tests and local inspection -----------------------

    def skips_by_reason(self) -> Counter[SkipReason]:
        return Counter(metric.reason for metric in self.skips)

    def selections_by_provider(self) -> Counter[str]:
        return Counter(metric.provider_id for metric in self.selections)

    def stops_by_reason(self) -> Counter[StopReason]:
        return Counter(metric.stop_reason for metric in self.runs)

    def clear(self) -> None:
        self.selections.clear()
        self.skips.clear()
        self.runs.clear()

    def __repr__(self) -> str:
        return (
            f"<InMemoryPlanningMetricsSink runs={len(self.runs)} "
            f"selections={len(self.selections)} skips={len(self.skips)}>"
        )
