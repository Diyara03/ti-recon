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
from ti_recon.execution.coordination import (
    DEFAULT_MAX_CONCURRENCY,
    ConcurrencyLimiter,
    SingleFlight,
)
from ti_recon.execution.executor import (
    ExecutionConfigurationError,
    ProviderExecutor,
)
from ti_recon.execution.limits import (
    MAX_COOLDOWN_SECONDS,
    CooldownEntry,
    CooldownStore,
    InMemoryCooldownStore,
    InMemoryQuotaStore,
    QuotaStore,
    cooldown_from_quota,
    cooldown_from_rate_limit,
    make_cooldown,
    make_credential_cooldown,
)
from ti_recon.execution.metrics import (
    ExecutionMetric,
    ExecutionMetricsSink,
    InMemoryExecutionMetricsSink,
    NoOpExecutionMetricsSink,
    ProviderAttemptMetric,
    scope_digest,
)
from ti_recon.execution.models import (
    CacheScope,
    CooldownReason,
    ExecutionContext,
    ExecutionScope,
    ProviderExecutionOutcome,
)
from ti_recon.execution.policy import (
    CACHEABLE_STATUSES,
    CachePolicy,
    ProviderExecutionPolicy,
    ProviderPolicyRegistry,
)
from ti_recon.execution.retry import (
    AUTOMATICALLY_RETRYABLE_CATEGORIES,
    CONDITIONALLY_RETRYABLE_CATEGORIES,
    NEVER_RETRYABLE_CATEGORIES,
    RetryDecision,
    RetryOutcome,
    RetryPolicy,
    compute_backoff,
    decide_retry,
)

__all__ = [
    "AUTOMATICALLY_RETRYABLE_CATEGORIES",
    "CACHEABLE_STATUSES",
    "CONDITIONALLY_RETRYABLE_CATEGORIES",
    "DEFAULT_MAX_CONCURRENCY",
    "MAX_COOLDOWN_SECONDS",
    "NEVER_RETRYABLE_CATEGORIES",
    "AsyncioSleeper",
    "CacheKey",
    "CachePolicy",
    "CacheScope",
    "Clock",
    "ConcurrencyLimiter",
    "CooldownEntry",
    "CooldownReason",
    "CooldownStore",
    "ExecutionConfigurationError",
    "ExecutionContext",
    "ExecutionMetric",
    "ExecutionMetricsSink",
    "ExecutionScope",
    "FixedJitter",
    "InMemoryCooldownStore",
    "InMemoryExecutionMetricsSink",
    "InMemoryProviderCache",
    "InMemoryQuotaStore",
    "JitterSource",
    "ManualClock",
    "NoJitter",
    "NoOpExecutionMetricsSink",
    "ProviderAttemptMetric",
    "ProviderCache",
    "ProviderExecutionOutcome",
    "ProviderExecutionPolicy",
    "ProviderExecutor",
    "ProviderPolicyRegistry",
    "QuotaStore",
    "RandomJitter",
    "RecordingSleeper",
    "RetryDecision",
    "RetryOutcome",
    "RetryPolicy",
    "SingleFlight",
    "Sleeper",
    "SystemClock",
    "build_cache_key",
    "compute_backoff",
    "cooldown_from_quota",
    "cooldown_from_rate_limit",
    "decide_retry",
    "make_cooldown",
    "make_credential_cooldown",
    "scope_digest",
]
