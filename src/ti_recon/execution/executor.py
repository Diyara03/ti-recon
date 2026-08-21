"""Bounded provider executor (Task 6).

Ties Task 4 credentials, Task 5 adapters and the Task 6 execution controls into
one reusable path. It answers *how* to call a provider safely; it never decides
**which** provider to call — that is the query planner, a later task — and it
never decides anything about maliciousness.

Execution order
---------------

::

    validate support
    resolve connection metadata (no secret read)
    cooldown check          -> short-circuit, no provider call
    quota pre-check         -> short-circuit, no provider call
    cache lookup            -> short-circuit, no provider call
    single-flight
      concurrency slot
        cache re-check      (a queued duplicate may find a leader's result)
        resolve credential  (just-in-time, only now)
        attempt loop with retry/backoff
      record rate-limit / quota state, apply cooldowns
      cache eligible result
    ProviderExecutionOutcome

Two orderings are deliberate and worth stating:

* **Single-flight wraps the concurrency limiter, not the other way round.** If
  followers waited *inside* a slot, a ``max_concurrency`` of 1 with two
  identical requests would serialize into two real provider calls — the exact
  duplication coalescing exists to prevent. Outside, followers hold no slot and
  the limiter still bounds the only thing worth bounding: real calls.
* **The credential is resolved last.** A request served from cache, blocked by
  a cooldown, or coalesced onto somebody else's call never causes a secret to be
  read out of the store at all.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime

from ti_recon.credentials.models import CredentialMaterial, ProviderConnection
from ti_recon.credentials.resolver import CredentialResolver
from ti_recon.enums import (
    ActivityMode,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.cache import CacheKey, ProviderCache, build_cache_key
from ti_recon.execution.clock import (
    AsyncioSleeper,
    Clock,
    JitterSource,
    RandomJitter,
    Sleeper,
    SystemClock,
)
from ti_recon.execution.coordination import ConcurrencyLimiter, SingleFlight
from ti_recon.execution.limits import (
    CooldownEntry,
    CooldownStore,
    QuotaStore,
    cooldown_from_quota,
    cooldown_from_rate_limit,
    make_cooldown,
)
from ti_recon.execution.metrics import (
    ExecutionMetric,
    ExecutionMetricsSink,
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
from ti_recon.execution.policy import ProviderExecutionPolicy, ProviderPolicyRegistry
from ti_recon.execution.retry import RetryDecision, decide_retry
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import (
    ProviderError,
    ProviderSchemaError,
    provider_error_for,
)
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import ProviderResultEnvelope, RateLimitSnapshot
from ti_recon.security import SENSITIVE_KEY_PATTERN, redact_sensitive_text

__all__ = ["ExecutionConfigurationError", "ProviderExecutor"]

_logger = logging.getLogger(__name__)

#: Substituted when a provider's own message cannot be made safe to record.
_WITHHELD_MESSAGE = "provider detail withheld as unsafe to record"

#: Operations this executor performs. The others on the adapter contract either
#: take a different shape (batch takes a sequence) or are lifecycle calls that
#: no investigation routes through here.
_DISPATCHABLE_OPERATIONS = frozenset(
    {
        ProviderOperation.LOOKUP,
        ProviderOperation.PIVOT,
        ProviderOperation.ACTIVE_ACTION,
    }
)


class ExecutionConfigurationError(Exception):
    """The executor was asked to run an unsafe configuration.

    Raised rather than silently corrected: a policy that would share one user's
    credentialed results with everybody is a mistake to surface, not to work
    around.
    """


@dataclass(slots=True)
class _Attempt:
    """What the provider-calling section produced."""

    envelope: ProviderResultEnvelope | None = None
    error: ProviderError | None = None
    attempts: int = 0
    cache_hit: bool = False
    cooldown: CooldownEntry | None = None
    quota: ProviderQuotaSnapshot | None = None


@dataclass(slots=True)
class _Timing:
    started_at: datetime
    monotonic_start: float


class ProviderExecutor:
    """Executes one provider operation under the full set of controls.

    Every collaborator is injectable, and the time-dependent ones
    (clock, sleeper, jitter) exist so the whole path is testable without
    waiting. Defaults are the real implementations.
    """

    def __init__(
        self,
        *,
        credential_resolver: CredentialResolver,
        cache: ProviderCache | None = None,
        quota_store: QuotaStore | None = None,
        cooldown_store: CooldownStore | None = None,
        limiter: ConcurrencyLimiter | None = None,
        single_flight: SingleFlight | None = None,
        policies: ProviderPolicyRegistry | None = None,
        metrics: ExecutionMetricsSink | None = None,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
        jitter: JitterSource | None = None,
        emit_scope_digest: bool = False,
    ) -> None:
        # Every default uses an explicit ``is None`` test rather than ``or``.
        # Several of these collaborators define ``__len__`` — an empty registry
        # or cache is falsy — so ``x or Default()`` would silently throw away an
        # injected-but-empty collaborator and quietly ignore its configuration.
        self._resolver = credential_resolver
        self._cache = cache
        self._quota_store = quota_store
        self._cooldown_store = cooldown_store
        self._limiter = ConcurrencyLimiter() if limiter is None else limiter
        self._single_flight = SingleFlight() if single_flight is None else single_flight
        self._policies = ProviderPolicyRegistry() if policies is None else policies
        self._clock = SystemClock() if clock is None else clock
        self._sleeper = AsyncioSleeper() if sleeper is None else sleeper
        self._jitter = RandomJitter() if jitter is None else jitter
        self._metrics = NoOpExecutionMetricsSink() if metrics is None else metrics
        # Opt-in: recording even an opaque per-user grouping key is a collection
        # decision, so it is made by whoever builds the executor.
        self._emit_scope_digest = emit_scope_digest

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    async def execute(
        self,
        adapter: ProviderAdapter,
        request: ProviderRequest,
        context: ExecutionContext,
    ) -> ProviderExecutionOutcome:
        """Execute one provider operation and report how it went."""
        descriptor = adapter.descriptor
        policy = self._policies.get(descriptor.provider_id)
        timing = _Timing(started_at=self._clock.now(), monotonic_start=self._clock.monotonic())

        unsupported = _unsupported_reason(descriptor, request)
        if unsupported is not None:
            return self._finish(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope_identity=_provisional_identity(descriptor, context),
                status=ProviderRunStatus.NOT_SUPPORTED,
                error_category=ProviderErrorCategory.INVALID_REQUEST,
                error_message=unsupported,
            )

        connection = await self._resolve_connection(descriptor, context)
        if descriptor.requires_credentials and (connection is None or not connection.is_usable):
            # Reported, not raised: an unconfigured provider is a coverage gap
            # for this investigation, never a failure of it.
            return self._finish(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope_identity=_provisional_identity(descriptor, context),
                status=ProviderRunStatus.NOT_CONFIGURED,
                error_message="no usable provider connection for this user",
            )

        scope = self._build_scope(descriptor, context, connection, policy)
        operation = request.operation.value

        blocked = await self._active_cooldown(scope, operation)
        if blocked is not None:
            return self._cooldown_outcome(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope=scope,
                entry=blocked,
            )

        exhausted = await self._exhausted_quota(scope, policy)
        if exhausted is not None:
            entry = cooldown_from_quota(
                exhausted,
                scope=scope,
                now=self._clock.now(),
                default_seconds=policy.quota_cooldown_seconds,
            )
            if entry is not None:
                await self._store_cooldown(entry)
            return self._finish(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope_identity=scope.identity,
                status=ProviderRunStatus.QUOTA_EXCEEDED,
                error_category=ProviderErrorCategory.QUOTA_EXCEEDED,
                error_message="known quota exhausted; provider not called",
                cooldown=entry,
                quota=exhausted,
            )

        key = build_cache_key(scope=scope, descriptor=descriptor, request=request)
        # Resolved once, here: a cache is in play only if one was injected *and*
        # this request is eligible. Keeping it in a local means no code below has
        # to re-check both conditions.
        cache = self._cache if policy.cache.is_request_cacheable(request) else None
        cache_key = key if cache is not None else None

        if cache is not None and cache_key is not None:
            cached = await cache.get(cache_key)
            if cached is not None:
                return self._cached_outcome(
                    descriptor=descriptor,
                    request=request,
                    context=context,
                    timing=timing,
                    scope=scope,
                    envelope=cached,
                    coalesced=False,
                )

        async def perform() -> _Attempt:
            async with self._limiter.acquire(scope.identity):
                # Re-checked *after* acquiring the slot, because waiting in the
                # queue is exactly the window in which a leader finishes and
                # fills the cache. Checking before the slot would leave that
                # window open and turn queued duplicates into real calls.
                if cache is not None and cache_key is not None:
                    again = await cache.get(cache_key)
                    if again is not None:
                        return _Attempt(envelope=again, cache_hit=True)
                return await self._run_attempts(
                    adapter=adapter,
                    request=request,
                    context=context,
                    scope=scope,
                    policy=policy,
                    connection=connection,
                    cache=cache,
                    cache_key=cache_key,
                )

        if _coalescing_allowed(policy, request):
            attempt, coalesced = await self._single_flight.run(key.storage_key, perform)
        else:
            attempt, coalesced = await perform(), False

        if attempt.cache_hit and attempt.envelope is not None:
            return self._cached_outcome(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope=scope,
                envelope=attempt.envelope,
                coalesced=coalesced,
            )

        return self._attempt_outcome(
            descriptor=descriptor,
            request=request,
            context=context,
            timing=timing,
            scope=scope,
            attempt=attempt,
            coalesced=coalesced,
        )

    # ------------------------------------------------------------------ #
    # The provider-calling section
    # ------------------------------------------------------------------ #

    async def _run_attempts(
        self,
        *,
        adapter: ProviderAdapter,
        request: ProviderRequest,
        context: ExecutionContext,
        scope: ExecutionScope,
        policy: ProviderExecutionPolicy,
        connection: ProviderConnection | None,
        cache: ProviderCache | None,
        cache_key: CacheKey | None,
    ) -> _Attempt:
        descriptor = adapter.descriptor
        credential = await self._resolve_credential(descriptor, context, connection)
        attempts = 0

        while True:
            attempts += 1
            attempt_start = self._clock.monotonic()
            try:
                envelope = await self._call_adapter(adapter, request, credential)
            except ProviderError as error:
                decision = decide_retry(
                    error=error,
                    attempt=attempts,
                    policy=policy.retry,
                    activity_mode=request.activity_mode,
                    now=self._clock.now(),
                    jitter=self._jitter,
                )
                cooldown = await self._apply_decision_cooldown(
                    scope=scope, request=request, error=error, decision=decision
                )
                self._record_attempt(
                    descriptor=descriptor,
                    request=request,
                    attempt=attempts,
                    started=attempt_start,
                    error_category=error.category,
                    retried=decision.should_retry,
                )
                if decision.should_retry:
                    _log_retry(descriptor, request, attempts, decision.delay_seconds)
                    await self._sleeper.sleep(decision.delay_seconds)
                    continue
                return _Attempt(error=error, attempts=attempts, cooldown=cooldown)

            self._record_attempt(
                descriptor=descriptor,
                request=request,
                attempt=attempts,
                started=attempt_start,
                error_category=None,
                retried=False,
            )
            cooldown, quota = await self._record_provider_state(
                scope=scope, request=request, envelope=envelope, policy=policy
            )
            await self._store_result(cache, cache_key, envelope, request, policy)
            return _Attempt(envelope=envelope, attempts=attempts, cooldown=cooldown, quota=quota)

    async def _call_adapter(
        self,
        adapter: ProviderAdapter,
        request: ProviderRequest,
        credential: CredentialMaterial | None,
    ) -> ProviderResultEnvelope:
        """Dispatch to the adapter, normalizing any non-provider exception.

        An adapter may raise something that is not a ``ProviderError``; that is
        exactly what ``classify_error`` exists for, so the executor never has to
        interpret a provider's own exception types.
        """
        descriptor = adapter.descriptor
        handler = self._operation_handler(adapter, request.operation)
        try:
            envelope = await handler(request, credential)
        except ProviderError:
            raise
        except Exception as raw:
            category = adapter.classify_error(raw)
            raise provider_error_for(
                category,
                descriptor.provider_id,
                message=type(raw).__name__,
                operation=request.operation.value,
            ) from raw

        if envelope.provider != descriptor.provider_id:
            # An adapter attributing its result to another provider would
            # corrupt evidence provenance, so it is a schema failure.
            raise ProviderSchemaError(
                descriptor.provider_id,
                message="adapter returned a result attributed to another provider",
                operation=request.operation.value,
            )
        return envelope

    def _operation_handler(
        self, adapter: ProviderAdapter, operation: ProviderOperation
    ) -> Callable[[ProviderRequest, CredentialMaterial | None], Awaitable[ProviderResultEnvelope]]:
        match operation:
            case ProviderOperation.LOOKUP:
                return adapter.lookup
            case ProviderOperation.PIVOT:
                return adapter.pivot
            case ProviderOperation.ACTIVE_ACTION:
                return adapter.active_action
            case _:  # pragma: no cover - guarded by _unsupported_reason
                msg = f"operation {operation.value!r} is not dispatchable"
                raise ExecutionConfigurationError(msg)

    # ------------------------------------------------------------------ #
    # Collaborator access
    # ------------------------------------------------------------------ #

    async def _resolve_connection(
        self, descriptor: ProviderDescriptor, context: ExecutionContext
    ) -> ProviderConnection | None:
        return await self._resolver.resolve_connection(
            authenticated_user_id=context.authenticated_user_id,
            provider_id=descriptor.provider_id,
            credential_group=context.credential_group or descriptor.credential_group,
        )

    async def _resolve_credential(
        self,
        descriptor: ProviderDescriptor,
        context: ExecutionContext,
        connection: ProviderConnection | None,
    ) -> CredentialMaterial | None:
        """Read the secret, and only now.

        Reached only when a provider call is genuinely about to happen.
        """
        if not descriptor.requires_credentials or connection is None:
            return None
        return await self._resolver.resolve(
            authenticated_user_id=context.authenticated_user_id,
            provider_id=descriptor.provider_id,
            credential_group=connection.credential_group,
        )

    def _build_scope(
        self,
        descriptor: ProviderDescriptor,
        context: ExecutionContext,
        connection: ProviderConnection | None,
        policy: ProviderExecutionPolicy,
    ) -> ExecutionScope:
        if policy.cache.scope is CacheScope.GLOBAL:
            if descriptor.requires_credentials:
                msg = (
                    f"provider {descriptor.provider_id!r} requires a credential, so its "
                    "results must not be shared in a global scope"
                )
                raise ExecutionConfigurationError(msg)
            return ExecutionScope.global_for_provider(provider_id=descriptor.provider_id)
        return ExecutionScope.for_user(
            provider_id=descriptor.provider_id,
            user_id=context.authenticated_user_id,
            provider_connection_id=connection.id if connection else None,
        )

    async def _active_cooldown(self, scope: ExecutionScope, operation: str) -> CooldownEntry | None:
        if self._cooldown_store is None:
            return None
        return await self._cooldown_store.active(scope_identity=scope.identity, operation=operation)

    async def _store_cooldown(self, entry: CooldownEntry) -> None:
        if self._cooldown_store is not None:
            await self._cooldown_store.set(entry)

    async def _exhausted_quota(
        self, scope: ExecutionScope, policy: ProviderExecutionPolicy
    ) -> ProviderQuotaSnapshot | None:
        if self._quota_store is None or not policy.quota_precheck:
            return None
        snapshot = await self._quota_store.get(scope.identity)
        if snapshot is None or not snapshot.is_exhausted:
            return None
        return snapshot

    async def _store_result(
        self,
        cache: ProviderCache | None,
        cache_key: CacheKey | None,
        envelope: ProviderResultEnvelope,
        request: ProviderRequest,
        policy: ProviderExecutionPolicy,
    ) -> None:
        if cache is None or cache_key is None:
            return
        ttl = policy.cache.ttl_for(envelope, request)
        if ttl is not None:
            await cache.set(cache_key, envelope, ttl)

    async def _record_provider_state(
        self,
        *,
        scope: ExecutionScope,
        request: ProviderRequest,
        envelope: ProviderResultEnvelope,
        policy: ProviderExecutionPolicy,
    ) -> tuple[CooldownEntry | None, ProviderQuotaSnapshot | None]:
        """Record what the response revealed about limits, and act on it."""
        now = self._clock.now()
        applied: CooldownEntry | None = None

        if envelope.rate_limit is not None:
            entry = cooldown_from_rate_limit(
                envelope.rate_limit,
                scope=scope,
                now=now,
                operation=request.operation.value,
                default_seconds=policy.rate_limit_cooldown_seconds,
            )
            if entry is not None:
                await self._store_cooldown(entry)
                applied = entry

        quota = envelope.quota
        if quota is not None and self._quota_store is not None:
            await self._quota_store.put(scope.identity, quota)
        if quota is not None:
            entry = cooldown_from_quota(
                quota,
                scope=scope,
                now=now,
                default_seconds=policy.quota_cooldown_seconds,
            )
            if entry is not None:
                await self._store_cooldown(entry)
                # A provider-wide quota block outranks an operation-scoped one.
                applied = entry
        return applied, quota

    async def _apply_decision_cooldown(
        self,
        *,
        scope: ExecutionScope,
        request: ProviderRequest,
        error: ProviderError,
        decision: RetryDecision,
    ) -> CooldownEntry | None:
        """Store the cooldown a retry decision asked for, if any."""
        if decision.cooldown_reason is None or decision.cooldown_seconds is None:
            return None
        entry = make_cooldown(
            scope=scope,
            reason=decision.cooldown_reason,
            seconds=decision.cooldown_seconds,
            now=self._clock.now(),
            # A rate limit belongs to the action that hit it; anything else
            # (quota spent, provider down) applies to the whole integration.
            operation=(
                request.operation.value
                if decision.cooldown_reason is CooldownReason.RATE_LIMIT
                else None
            ),
            detail=error.category.value,
        )
        await self._store_cooldown(entry)
        return entry

    def _record_attempt(
        self,
        *,
        descriptor: ProviderDescriptor,
        request: ProviderRequest,
        attempt: int,
        started: float,
        error_category: ProviderErrorCategory | None,
        retried: bool,
    ) -> None:
        self._metrics.record_attempt(
            ProviderAttemptMetric(
                provider_id=descriptor.provider_id,
                operation=request.operation,
                attempt=attempt,
                duration_ms=max(0.0, (self._clock.monotonic() - started) * 1000.0),
                error_category=error_category,
                retried=retried,
            )
        )

    # ------------------------------------------------------------------ #
    # Outcome construction
    # ------------------------------------------------------------------ #

    def _cached_outcome(
        self,
        *,
        descriptor: ProviderDescriptor,
        request: ProviderRequest,
        context: ExecutionContext,
        timing: _Timing,
        scope: ExecutionScope,
        envelope: ProviderResultEnvelope,
        coalesced: bool,
    ) -> ProviderExecutionOutcome:
        return self._finish(
            descriptor=descriptor,
            request=request,
            context=context,
            timing=timing,
            scope_identity=scope.identity,
            status=envelope.status,
            result=envelope,
            cache_hit=True,
            coalesced=coalesced,
            rate_limit=envelope.rate_limit,
        )

    def _cooldown_outcome(
        self,
        *,
        descriptor: ProviderDescriptor,
        request: ProviderRequest,
        context: ExecutionContext,
        timing: _Timing,
        scope: ExecutionScope,
        entry: CooldownEntry,
    ) -> ProviderExecutionOutcome:
        status = _COOLDOWN_STATUS[entry.reason]
        return self._finish(
            descriptor=descriptor,
            request=request,
            context=context,
            timing=timing,
            scope_identity=scope.identity,
            status=status,
            error_category=_COOLDOWN_ERROR_CATEGORY[entry.reason],
            error_message=f"cooldown active ({entry.reason.value}); provider not called",
            cooldown=entry,
        )

    def _attempt_outcome(
        self,
        *,
        descriptor: ProviderDescriptor,
        request: ProviderRequest,
        context: ExecutionContext,
        timing: _Timing,
        scope: ExecutionScope,
        attempt: _Attempt,
        coalesced: bool,
    ) -> ProviderExecutionOutcome:
        if attempt.envelope is not None:
            return self._finish(
                descriptor=descriptor,
                request=request,
                context=context,
                timing=timing,
                scope_identity=scope.identity,
                status=attempt.envelope.status,
                result=attempt.envelope,
                error_category=attempt.envelope.error_category,
                error_message=attempt.envelope.error_message,
                attempts=attempt.attempts,
                coalesced=coalesced,
                cooldown=attempt.cooldown,
                rate_limit=attempt.envelope.rate_limit,
                quota=attempt.quota,
            )

        error = attempt.error
        if error is None:  # pragma: no cover - one of the two is always set
            msg = "an attempt must produce either a result or an error"
            raise ExecutionConfigurationError(msg)
        return self._finish(
            descriptor=descriptor,
            request=request,
            context=context,
            timing=timing,
            scope_identity=scope.identity,
            status=error.run_status,
            error_category=error.category,
            error_message=_safe_message(str(error)),
            attempts=attempt.attempts,
            coalesced=coalesced,
            cooldown=attempt.cooldown,
        )

    def _finish(
        self,
        *,
        descriptor: ProviderDescriptor,
        request: ProviderRequest,
        context: ExecutionContext,
        timing: _Timing,
        scope_identity: str,
        status: ProviderRunStatus,
        result: ProviderResultEnvelope | None = None,
        error_category: ProviderErrorCategory | None = None,
        error_message: str | None = None,
        attempts: int = 0,
        cache_hit: bool = False,
        coalesced: bool = False,
        cooldown: CooldownEntry | None = None,
        rate_limit: RateLimitSnapshot | None = None,
        quota: ProviderQuotaSnapshot | None = None,
    ) -> ProviderExecutionOutcome:
        completed_at = self._clock.now()
        duration_ms = max(0.0, (self._clock.monotonic() - timing.monotonic_start) * 1000.0)
        # Every outcome path funnels through here, so one metric per logical
        # execution is emitted exactly once — including the paths that never
        # called the provider, which are the ones worth counting.
        self._metrics.record_execution(
            ExecutionMetric(
                provider_id=descriptor.provider_id,
                operation=request.operation,
                status=status,
                # The object *type*, never its value: a metrics pipeline must not
                # become a log of everything anyone has investigated.
                object_type=request.intel_object.object_type,
                duration_ms=duration_ms,
                attempts=attempts,
                cache_hit=cache_hit,
                coalesced=coalesced,
                cooldown_applied=cooldown is not None,
                error_category=error_category,
                scope_digest=(scope_digest(scope_identity) if self._emit_scope_digest else None),
            )
        )
        return ProviderExecutionOutcome(
            provider_id=descriptor.provider_id,
            operation=request.operation,
            status=status,
            request_id=context.request_id,
            scope_identity=scope_identity,
            result=result,
            error_category=error_category,
            error_message=_safe_message(error_message),
            attempts=attempts,
            cache_hit=cache_hit,
            coalesced=coalesced,
            started_at=timing.started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            cooldown_applied=cooldown is not None,
            cooldown_until=cooldown.until if cooldown else None,
            cooldown_reason=cooldown.reason if cooldown else None,
            rate_limit_snapshot=rate_limit,
            quota_snapshot=quota,
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_COOLDOWN_STATUS: dict[CooldownReason, ProviderRunStatus] = {
    CooldownReason.RATE_LIMIT: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    CooldownReason.QUOTA_EXHAUSTED: ProviderRunStatus.QUOTA_EXCEEDED,
    CooldownReason.TRANSIENT_FAILURES: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    CooldownReason.PROVIDER_UNAVAILABLE: ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
}

_COOLDOWN_ERROR_CATEGORY: dict[CooldownReason, ProviderErrorCategory] = {
    CooldownReason.RATE_LIMIT: ProviderErrorCategory.RATE_LIMITED,
    CooldownReason.QUOTA_EXHAUSTED: ProviderErrorCategory.QUOTA_EXCEEDED,
    CooldownReason.TRANSIENT_FAILURES: ProviderErrorCategory.TRANSIENT_ERROR,
    CooldownReason.PROVIDER_UNAVAILABLE: ProviderErrorCategory.PROVIDER_UNAVAILABLE,
}


def _unsupported_reason(descriptor: ProviderDescriptor, request: ProviderRequest) -> str | None:
    """Why this adapter cannot serve this request, or ``None`` if it can.

    Messages name the object *type*, never its value: an outcome is logged and
    serialized, and the observable under investigation does not need to travel
    with a configuration complaint.
    """
    if request.operation not in _DISPATCHABLE_OPERATIONS:
        return f"operation {request.operation.value} is not executed by this layer"
    if request.intel_object.object_type not in descriptor.supported_object_types:
        return f"provider does not support {request.intel_object.object_type.value}"
    if not (request.requested_capabilities & descriptor.capabilities):
        return "provider offers none of the requested capabilities"
    is_active = (
        request.activity_mode is ActivityMode.ACTIVE
        or request.operation is ProviderOperation.ACTIVE_ACTION
    )
    if is_active and not descriptor.supports_active:
        return "provider does not support active operations"
    if not is_active and not descriptor.supports_passive:
        return "provider does not support passive operations"
    return None


def _coalescing_allowed(policy: ProviderExecutionPolicy, request: ProviderRequest) -> bool:
    """Whether identical concurrent copies of this request may share one call.

    Never for active operations: two callers asking to submit a file both want
    a submission to happen, and silently serving one submission to both would
    be the wrong answer, not an optimization.
    """
    if not policy.coalesce_requests:
        return False
    return (
        request.activity_mode is ActivityMode.PASSIVE
        and request.operation is not ProviderOperation.ACTIVE_ACTION
    )


def _provisional_identity(descriptor: ProviderDescriptor, context: ExecutionContext) -> str:
    """A scope identity for outcomes produced before a connection is known."""
    return ExecutionScope.for_user(
        provider_id=descriptor.provider_id, user_id=context.authenticated_user_id
    ).identity


def _safe_message(text: str | None) -> str | None:
    """Redact a message, or withhold it entirely if it still looks unsafe.

    The redactor is best-effort; this fallback is the guarantee. A message that
    still resembles credential material after redaction is dropped rather than
    recorded, because a diagnostic string is never worth the risk.
    """
    if not text:
        return None
    redacted = redact_sensitive_text(text)
    if SENSITIVE_KEY_PATTERN.search(redacted):
        return _WITHHELD_MESSAGE
    return redacted


def _log_retry(
    descriptor: ProviderDescriptor,
    request: ProviderRequest,
    attempt: int,
    delay_seconds: float,
) -> None:
    """Log a retry with safe fields only: no observable value, no credential."""
    _logger.info(
        "retrying provider attempt",
        extra={
            "provider": descriptor.provider_id,
            "operation": request.operation.value,
            "object_type": request.intel_object.object_type.value,
            "attempt": attempt,
            "delay_seconds": round(delay_seconds, 3),
        },
    )
