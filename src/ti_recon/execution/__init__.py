"""Provider execution controls (Task 6).

The shared execution layer every provider adapter runs behind: caching, retry
and backoff, rate-limit and quota tracking, cooldowns, bounded concurrency and
in-flight request coalescing.

This layer decides *how* to call a selected provider safely. It never decides
which provider to call (a later task), and it never decides anything about
maliciousness — no verdict, risk score or confidence is computed here.

All coordination state is in-memory and single-process: this is a development
foundation, not distributed coordination. The protocols are the seams that
Redis-backed implementations will slot into later.
"""

from ti_recon.execution.cache import (
    CacheKey,
    InMemoryProviderCache,
    ProviderCache,
    build_cache_key,
)
from ti_recon.execution.clock import (
    AsyncioSleeper,
    Clock,
    FixedJitter,
    JitterSource,
    ManualClock,
    NoJitter,
    RandomJitter,
    RecordingSleeper,
    Sleeper,
    SystemClock,
)
from ti_recon.execution.models import CacheScope, CooldownReason, ExecutionScope
from ti_recon.execution.policy import CACHEABLE_STATUSES, CachePolicy

__all__ = [
    "CACHEABLE_STATUSES",
    "AsyncioSleeper",
    "CacheKey",
    "CachePolicy",
    "CacheScope",
    "Clock",
    "CooldownReason",
    "ExecutionScope",
    "FixedJitter",
    "InMemoryProviderCache",
    "JitterSource",
    "ManualClock",
    "NoJitter",
    "ProviderCache",
    "RandomJitter",
    "RecordingSleeper",
    "Sleeper",
    "SystemClock",
    "build_cache_key",
]
