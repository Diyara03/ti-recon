"""Execution metrics (Task 6).

Observability hooks with no monitoring dependency: a sink protocol and two
implementations, one that discards and one that keeps records in memory for
tests and local development. Exporting to a real backend is a later concern and
slots in behind the same protocol.

What is deliberately **not** collected
--------------------------------------

No credential material, no raw provider response, and **no observable value**.
The last one is the easy mistake: it would be convenient to label a metric with
the IOC, and it would quietly turn a metrics pipeline into a log of everything
every analyst has ever investigated — a sensitive dataset with a different
retention story from the metric counts around it. There is therefore no field
that can hold one. The object *type* is recorded instead, which is what you
actually want to aggregate by.

User identity is opt-in. When enabled, an opaque digest of the execution scope
is recorded rather than the identity itself, and the executor has to be asked
for it explicitly.
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Protocol, runtime_checkable

from pydantic import Field

from ti_recon.enums import (
    IntelObjectType,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now

__all__ = [
    "ExecutionMetric",
    "ExecutionMetricsSink",
    "InMemoryExecutionMetricsSink",
    "NoOpExecutionMetricsSink",
    "ProviderAttemptMetric",
    "scope_digest",
]


def scope_digest(scope_identity: str) -> str:
    """A short, opaque, stable digest of an execution scope.

    Lets one scope's executions be correlated with each other without recording
    who they belong to. Short on purpose: it is a grouping key, not an
    identifier to be reversed.
    """
    return hashlib.sha256(scope_identity.encode("utf-8")).hexdigest()[:16]


class ProviderAttemptMetric(FrozenTiReconModel):
    """One physical call to a provider.

    Separate from :class:`ExecutionMetric` because one logical request can make
    several attempts, and conflating them makes a retry rate impossible to
    measure — three attempts would look like three requests.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    operation: ProviderOperation
    attempt: int = Field(ge=1)
    duration_ms: float = Field(ge=0.0)
    error_category: ProviderErrorCategory | None = None
    retried: bool = False
    recorded_at: UtcDatetime = Field(default_factory=utc_now)

    @property
    def succeeded(self) -> bool:
        return self.error_category is None


class ExecutionMetric(FrozenTiReconModel):
    """One logical provider execution, however many attempts it took."""

    provider_id: str = Field(min_length=1, max_length=64)
    operation: ProviderOperation
    status: ProviderRunStatus
    object_type: IntelObjectType
    duration_ms: float = Field(ge=0.0)
    attempts: int = Field(default=0, ge=0)
    cache_hit: bool = False
    coalesced: bool = False
    cooldown_applied: bool = False
    error_category: ProviderErrorCategory | None = None
    #: Opaque scope grouping key. Populated only when the executor is explicitly
    #: configured to emit it.
    scope_digest: str | None = Field(default=None, max_length=32)
    recorded_at: UtcDatetime = Field(default_factory=utc_now)

    @property
    def retry_count(self) -> int:
        """Attempts beyond the first."""
        return max(0, self.attempts - 1)

    @property
    def called_provider(self) -> bool:
        """Whether this execution cost a real provider request."""
        return self.attempts > 0


@runtime_checkable
class ExecutionMetricsSink(Protocol):
    """Where execution metrics go.

    Both methods are synchronous: the executor emits from its hot path, and a
    sink that awaited would let a metrics backend's latency become a provider
    call's latency. A sink needing I/O should enqueue and drain elsewhere.
    """

    def record_execution(self, metric: ExecutionMetric) -> None:
        """Record one logical execution."""
        ...

    def record_attempt(self, metric: ProviderAttemptMetric) -> None:
        """Record one physical provider attempt."""
        ...


class NoOpExecutionMetricsSink:
    """Discards everything. The default, so metrics are never load-bearing."""

    def record_execution(self, metric: ExecutionMetric) -> None:
        return None

    def record_attempt(self, metric: ProviderAttemptMetric) -> None:
        return None


class InMemoryExecutionMetricsSink:
    """Keeps recent metrics in a bounded buffer.

    **NOT FOR PRODUCTION.** Process-local, unaggregated, and dropped on
    restart. It exists so tests can assert what was emitted and so local
    development can see it.
    """

    is_production_ready: bool = False

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            msg = "max_records must be at least 1"
            raise ValueError(msg)
        self.executions: deque[ExecutionMetric] = deque(maxlen=max_records)
        self.attempts: deque[ProviderAttemptMetric] = deque(maxlen=max_records)

    def record_execution(self, metric: ExecutionMetric) -> None:
        self.executions.append(metric)

    def record_attempt(self, metric: ProviderAttemptMetric) -> None:
        self.attempts.append(metric)

    # -- read helpers for tests and local inspection -----------------------

    def count_by_status(self, status: ProviderRunStatus) -> int:
        return sum(1 for metric in self.executions if metric.status is status)

    @property
    def cache_hits(self) -> int:
        return sum(1 for metric in self.executions if metric.cache_hit)

    @property
    def coalesced(self) -> int:
        return sum(1 for metric in self.executions if metric.coalesced)

    @property
    def cooldowns_applied(self) -> int:
        return sum(1 for metric in self.executions if metric.cooldown_applied)

    @property
    def total_attempts(self) -> int:
        return sum(metric.attempts for metric in self.executions)

    @property
    def total_retries(self) -> int:
        return sum(metric.retry_count for metric in self.executions)

    def clear(self) -> None:
        self.executions.clear()
        self.attempts.clear()

    def __len__(self) -> int:
        return len(self.executions)

    def __repr__(self) -> str:
        return (
            f"<InMemoryExecutionMetricsSink executions={len(self.executions)} "
            f"attempts={len(self.attempts)}>"
        )
