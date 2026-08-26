# TI Recon — Provider Execution Controls

> Task 6. Describes `src/ti_recon/execution/`.
>
> This layer decides **how** to call a selected provider safely. It does not
> decide **which** provider to call — that is the query planner, a later task —
> and it decides nothing about maliciousness: no verdict, risk score or
> confidence is computed here.
>
> **All execution state is in-memory and single-process.** This is a development
> foundation, not distributed coordination. See §11.

## 1. Where this sits

```
        Query planner                     FUTURE — chooses the provider
             |
        ProviderExecutor                  this layer
             |
   cooldown / quota / cache / limits / single-flight / retry
             |
        ProviderAdapter                   Task 5 contract
             |
        External provider
```

Nothing below the executor knows the controls exist: an adapter is called
exactly as the Task 5 contract describes, and receives no extra parameters.

## 2. Execution flow

```
 1. validate the request against the adapter's descriptor
 2. resolve connection metadata            (no secret read)
 3. cooldown check          -> short-circuit, provider not called
 4. quota pre-check         -> short-circuit, provider not called
 5. cache lookup            -> short-circuit, provider not called
 6. single-flight
 7.   concurrency slot
 8.     cache re-check      (a queued duplicate may find a leader's result)
 9.     resolve credential  (just-in-time — only now)
10.     attempt loop with retry / backoff
11.   record rate-limit and quota state, apply cooldowns
12.   cache the result if eligible
13. emit metrics
14. return ProviderExecutionOutcome
```

Two orderings are deliberate rather than incidental.

**Single-flight wraps the concurrency limiter, not the reverse.** If followers
waited *inside* a slot, a `max_concurrency` of 1 with two identical requests
would serialize into two real provider calls — the exact duplication coalescing
exists to prevent. Outside, followers hold no slot, and the limiter still bounds
the only thing worth bounding: real calls.

**The cache is re-checked after acquiring the slot, not before.** Waiting in the
concurrency queue is precisely the window in which a leader finishes and fills
the cache; checking before the slot would leave that window open and turn queued
duplicates into real calls.

**The credential is resolved last.** A request served from cache, blocked by a
cooldown, or coalesced onto somebody else's call never causes a secret to be
read out of the store at all.

## 3. Isolation

Every control is keyed by `ExecutionScope`:

```python
ExecutionScope.for_user(
    provider_id=...,
    user_id=...,  # from verified request identity
    provider_connection_id=...,  # which credential the work uses
)
```

Its `identity` — `user|<user>|<provider>|<connection>` — is the partition key
for the cache, quota state, cooldowns, concurrency slots and coalescing. One
scope can never read, block or consume another's.

`provider_connection_id` is preferred over `user_id` alone: it identifies the
specific credential, so rotating a key or adding a second connection does not
silently reuse results fetched under the old one.

The scope model has **no field that could hold credential material**, which is
asserted structurally rather than by pattern-matching a string.

It also records the `credential_group` the work draws its secret from. That field
is *not* part of `identity` — it partitions nothing — and exists only for
`credential_identity`, the separate key used by the one control that belongs to a
credential rather than to a provider. See §8.2.

## 4. Cache

`ProviderCache` protocol; `InMemoryProviderCache` is the only implementation.

### 4.1 Scope

`CacheScope.USER` is the default and the only scope enabled unless a provider
policy says otherwise. A provider result is obtained with one analyst's
credential, against their quota, and may reflect what their plan is entitled to
see — serving it to somebody else is both a data-sharing and an entitlement
problem.

`CacheScope.GLOBAL` exists for sources whose answer genuinely cannot vary by
caller (a local warning list). Requesting it for a provider that
`requires_credentials` raises `ExecutionConfigurationError` rather than being
silently downgraded: sharing credentialed results with everybody is a
misconfiguration to surface, not to work around.

### 4.2 Key

Built from request semantics, identifiers and version strings:

```
cache scope · scope identity · provider · operation · observable canonical key
capabilities (sorted) · depth · activity mode · max_results · max_pages
api_version · adapter_version · dataset_version
```

Then SHA-256'd, and stored under `v1|<scope identity>|<digest>` so the store is
visibly partitioned by scope.

Two deliberate exclusions:

- **`investigation_id`.** The same analyst asking about the same observable
  twenty minutes later, in a different investigation, is asking the same
  question. Including it would make the cache almost never hit.
- **Anything secret.** The inputs are identifiers, request options and version
  strings; there is no field on any of them that could carry credential
  material.

`api_version` and `adapter_version` are included so that upgrading an adapter,
or a provider moving to a new API version, does not serve results parsed by the
old code.

`dataset_version` extends the same rule to a provider that answers from a
**pinned local dataset**. Refreshing the data would otherwise leave every cached
answer describing a dataset that no longer exists — a problem no remote provider
has, since its data version is whatever its API returned. It is `None` for every
provider without local data, so their keys are unchanged.

MISP Warning Lists sets it to `<profile fingerprint>:<dataset fingerprint>`, and
both halves matter: the snapshot alone would serve one profile's answers to
another, the profile alone would serve yesterday's data after a refresh. The
executor knows none of that — it hashes a string a descriptor supplied, which is
what keeps the mechanism generic rather than a special case.

### 4.3 Policy

| Status | Default |
|--------|---------|
| `SUCCESS` | cached for `success_ttl_seconds` (1 h) |
| `NO_DATA` | cached for `no_data_ttl_seconds` (5 min) |
| `PARTIAL` | **not cached** (`partial_ttl_seconds=None`) |
| `NOT_CONFIGURED`, `NOT_SUPPORTED`, `PLAN_LIMITED`, `QUOTA_EXCEEDED`, `TEMPORARILY_UNAVAILABLE`, `ERROR` | never cached |
| active operations | never cached unless `cache_active_operations` |

The reasoning behind the three interesting ones:

- **Negative caching is short.** "This provider has never seen it" is the answer
  most likely to change soon — it is exactly what changes when an indicator is
  first reported. A long negative TTL would hide the report that matters.
- **`PARTIAL` is not cached.** A partial result usually reflects what a
  subscription is entitled to return; caching a truncated answer risks it later
  being mistaken for a complete one. A policy may opt in with a short TTL.
- **Failures are never cached.** Caching a transient outage would turn it into a
  persistent one.

A provider's own `CacheabilityHint` may **shorten** a TTL or veto caching
entirely, but never extend it past policy.

### 4.4 Correctness details

- **Monotonic expiry.** TTLs are computed from monotonic time, so a host clock
  correction cannot resurrect an expired entry or expire a fresh one.
- **Deep copies in and out.** An envelope is frozen, but the `attributes` dict
  inside a piece of evidence is not; a caller that mutated it would silently
  corrupt what every later reader sees.
- **Bounded.** LRU eviction at `max_entries`, so a long-running process cannot
  grow without limit.

## 5. Retry and backoff

Decisions are made from **normalized error categories**, never from HTTP status
codes. Interpreting a provider's conventions is the adapter's job
(`ProviderAdapter.classify_error`); by the time an error reaches this layer it
is already a category, so there is no `if status_code == 403` anywhere here.

### 5.1 Matrix

| Categories | Behaviour |
|------------|-----------|
| `TRANSIENT_ERROR`, `PROVIDER_UNAVAILABLE` | retry with exponential backoff |
| `RATE_LIMITED` | retry inline **only** if the reset is known and close; otherwise cooldown |
| `QUOTA_EXCEEDED` | never retry; provider-wide cooldown |
| `AUTHENTICATION_ERROR`, `PERMISSION_ERROR`, `PLAN_LIMITED`, `NOT_FOUND`, `INVALID_REQUEST`, `PARTIAL_RESULT`, `SCHEMA_ERROR` | never retry |
| `UNKNOWN_ERROR` | never retry unless `retry_unknown_errors` |

The sets are defined so that `NEVER_RETRYABLE` is derived by subtraction. They
therefore always partition the category vocabulary, and a newly added category
is "never retryable" until somebody deliberately classifies it — rather than
silently falling through an `if` chain. A test also asserts the union of the
retryable sets still equals Task 5's `RETRYABLE_ERROR_CATEGORIES`, so the two
layers cannot drift apart on what "transient" means.

The narrowness is the point: retrying a rejected key burns quota and can trip a
provider's abuse protection, retrying quota exhaustion turns one refusal into a
loop of refusals, and a `PARTIAL_RESULT` is a completed answer rather than a
failure to repeat.

### 5.2 `RATE_LIMITED` vs `QUOTA_EXCEEDED`

Kept strictly separate, because the right response differs:

- **rate limited** — short-term throttling. If the provider said when the limit
  lifts and that is within `max_inline_wait_seconds` (default 5 s), the attempt
  waits and retries.
- **quota exhausted** — an entitlement for a period is spent. No amount of
  waiting inside one investigation fixes that, so it never retries.

A rate limit whose reset is far away does **not** block the request: the
provider goes on cooldown and the investigation reports reduced coverage.
Nobody should watch a spinner because a quota window resets in forty minutes.

A `429` with no reset hint also becomes a cooldown. With nothing to wait for,
hammering the endpoint to discover the answer is the wrong behaviour.

### 5.3 Backoff

`base_delay · 2^(attempt-1)`, capped at `max_delay`, plus jitter bounded by
`jitter_ratio`. The cap is applied **after** jitter, so the configured maximum
is a real ceiling rather than one jitter can exceed. Jitter exists so a fleet of
workers that failed together does not retry in lockstep and recreate the spike.

Defaults: `max_attempts=3`, `base_delay=0.5 s`, `max_delay=8 s`,
`jitter_ratio=0.25`. All configuration, not provider guidance.

### 5.4 Active operations

Never retried automatically, whatever the category. Two callers asking to
submit a file both want a submission to happen, and submitting or detonating
something twice is not a safe default. A provider-specific idempotency design
could change that later, per provider.

### 5.5 No retry dependency

Implemented with the standard library. The whole decision is a pure function
over a category, an attempt number and a policy; Tenacity or similar would add
dependency surface without removing any of the domain logic that actually
matters here.

## 6. Rate limits

`RateLimitSnapshot` (Task 5) gained `RateLimitWindow` rather than being
replaced, so nothing that already produced one breaks.

```python
RateLimitSnapshot(
    operation="search",
    windows=(
        RateLimitWindow(window_name="minute", limit=60, remaining=0, reset_after_seconds=20),
        RateLimitWindow(window_name="hour", limit=1000, remaining=880),
        RateLimitWindow(window_name="day", limit=10_000, remaining=4200),
    ),
)
```

Providers throttle over several windows at once, often per action. A single
`provider.remaining_requests` would collapse them and lose the only useful
fact: *which* window is exhausted and when it refills. Window names are
provider-defined — nothing assumes minute/hour/day.

Every measurement is optional, and an unknown `remaining` is **not** treated as
exhaustion: refusing to call a provider that told us nothing is worse than
trying. `longest_reset_delay` returns the longest wait among exhausted windows,
because a request needs every one of them refilled before it can succeed.

## 7. Quota

`ProviderQuotaSnapshot` holds named `QuotaBucket`s over `MINUTE`, `HOUR`,
`DAY`, `MONTH` or `CUSTOM` periods, scoped to a user and connection — quota
belongs to whoever's key is being spent.

```python
ProviderQuotaSnapshot(
    provider_id=...,
    user_id=...,
    buckets=(
        QuotaBucket(name="api_requests_hourly", period=QuotaPeriod.HOUR, allowed=1000, used=250),
        QuotaBucket(name="api_requests_daily", period=QuotaPeriod.DAY, allowed=20_000, used=9_000),
        QuotaBucket(
            name="api_requests_monthly", period=QuotaPeriod.MONTH, allowed=500_000, used=12_000
        ),
    ),
)
```

- `remaining` is derived when a provider reports allowance and usage instead, so
  callers need not know which shape they got.
- **Any** exhausted bucket blocks the credential: a spent daily allowance is not
  rescued by the monthly one having room.
- `CUSTOM` exists because provider periods are not ours to enumerate.

An adapter reports a snapshot on `ProviderResultEnvelope.quota`; the executor
stores it and pre-checks it on the next request, so a spent allowance costs no
further requests to rediscover. **No quota API is called by this task** — that
arrives with each real integration.

Stored snapshots expire (`ttl_seconds`, default 5 min). Stale quota data is
worse than none: acting on hour-old exhaustion would keep a provider switched
off long after it refilled.

## 8. Cooldowns

A cooldown is a decision not to call something for a while, because we already
know the answer would be a refusal.

| Reason | Scope | Typical trigger |
|--------|-------|-----------------|
| `RATE_LIMIT` | the operation | 429, or an exhausted window on a successful response |
| `QUOTA_EXHAUSTED` | the whole provider | spent account allowance |
| `TRANSIENT_FAILURES` | the whole provider | retries exhausted against a flaky provider |
| `PROVIDER_UNAVAILABLE` | the whole provider | retries exhausted against a provider that looks down |
| `PROVIDER_DIRECTED` | the **credential** | an adapter recognized a provider condition a category cannot express |

**Per-operation by default is load-bearing.** Providers commonly limit one
action far more tightly than the rest — a cheap search endpoint throttled while
a retrieve endpoint has plenty of room. Blocking a whole integration for that
throws away coverage we still have. Account-level quota, by contrast, applies to
everything that credential could do, so those cooldowns are provider-wide.

Lookup considers both the operation-specific and the provider-wide entry, and
the longest-lasting block wins. A new, shorter cooldown cannot shorten one
already active: newer information should not be able to un-learn a limit we
have already been told about.

Durations are capped (6 h). A provider reporting a reset a week away is far more
likely misreporting than right, and honouring it literally would silently remove
an integration for a week.

When a cooldown is active the provider is **not called**; the outcome reports
`cooldown_applied`, `cooldown_reason` and `cooldown_until`. Nothing ever sleeps
until a long reset.

### 8.1 Adapter-supplied credential cooldowns

Four of the five reasons above are derived here, from things this layer can see:
a status category, a rate-limit window, a quota bucket, an exhausted retry
budget. `PROVIDER_DIRECTED` is the one an **adapter** asks for.

It exists because a category is sometimes too coarse to carry the decision.
`PERMISSION_ERROR` covers two very different situations:

* *this call* is not permitted — one endpoint outside the plan, while everything
  else on the same key works. Cooling down here would silence a working
  integration, so it must not happen.
* *this credential* is not permitted — the provider has refused the account
  outright, and every call it makes from now on will be refused too.

Only the provider package can tell those apart, because telling them apart means
reading a provider's own vocabulary — which this layer is forbidden to learn
(invariant 11). So the adapter decides, and says so by attaching a hint to the
error it raises:

```python
provider_error_for(
    ProviderErrorCategory.PERMISSION_ERROR,
    provider_id,
    credential_cooldown_hint_seconds=...,
)
```

The hint is a **duration, never a reason**. Passing a reason would mean this
module growing a vocabulary of provider conditions; passing a number means it
learns nothing. The category the adapter reported travels on the entry's
`detail`, so the outcome is still diagnosable.

Three properties keep this from becoming a back door:

* **Nothing gets one without asking.** No category earns this cooldown by
  default. An error with no hint behaves exactly as it did before.
* **It is a request, not a command.** `RetryPolicy.max_credential_cooldown_seconds`
  (default 6 h) is the operator's ceiling on how long *any* adapter may silence a
  credential for, and the store's absolute cap applies after that.
* **It never makes a failure retryable.** The hint is only read on the path that
  has already decided to stop.

`QUOTA_EXCEEDED` and `RATE_LIMITED` are handled before the hint is consulted, so
a hint cannot displace a cooldown derived from what the provider actually
reported.

### 8.2 The credential scope

A `PROVIDER_DIRECTED` cooldown is keyed to the *credential* rather than to one
provider, via `ExecutionScope.credential_identity`:

```
user|<user>|group:<credential group>|<connection>
```

A separate key space from `identity`, and never a substitute for it. Almost
everything an execution control does is per-provider: one provider being
throttled says nothing about the next one, even on the same key. This exists for
the narrow condition that is genuinely about the secret rather than the endpoint.

It matters wherever providers share a credential. The three abuse.ch platforms
draw on one `Auth-Key`, so a ThreatFox `user_blacklisted` means the *key* is
blocked — and continuing to call URLhaus and MalwareBazaar with it would keep
producing refusals. One entry suppresses all three.

The credential group is recorded on the scope but deliberately **left out of
`identity`**, so sharing a credential never means sharing a cache entry, a quota
bucket or a concurrency slot. Isolation is unchanged: the credential identity is
built from the analyst's id, their credential group and their connection id, so
one analyst's block can never silence another's key.

When no credential group is known the identity is `None`, and the executor falls
back to an ordinary provider-scoped cooldown. The pause still happens; it simply
covers less. Skipping it would be the wrong failure mode.

## 9. Concurrency and coalescing

### 9.1 Bounded concurrency

`ConcurrencyLimiter` bounds in-flight calls per scope. Default 4 — configuration,
not provider guidance; no provider documents that number.

Gates are created on demand and dropped once nobody holds or awaits them, so a
process that has served a million scopes does not retain a million semaphores.
The holder count includes *waiting* tasks precisely so a gate is never discarded
while a task still holds a slot, which would hand the next arrival a fresh
semaphore and quietly exceed the limit.

### 9.2 Single-flight

Identical concurrent requests collapse into one provider call; the rest await
the same result and are reported as `coalesced`, so a saved request is visible
rather than invisible.

The identity is the same recipe as the cache key, so coalescing inherits the
same isolation: different users, connections, observables, operations or
request options never merge. **Active operations are never coalesced** — two
callers asking for a submission each want one to happen.

Failure and cancellation propagate to every waiter and always clear the
registry, so a failed leader cannot wedge the key for later callers.

Both get-or-create paths use no lock: there is no `await` between the lookup and
the insert, so asyncio cannot interleave another task there, and a lock would
add contention without adding safety.

## 10. Executor

```python
executor = ProviderExecutor(
    credential_resolver=resolver,  # required
    cache=...,
    quota_store=...,
    cooldown_store=...,  # all optional
    limiter=...,
    single_flight=...,
    policies=...,
    metrics=...,
    clock=...,
    sleeper=...,
    jitter=...,
    emit_scope_digest=False,
)

outcome = await executor.execute(adapter, request, context)
```

`ExecutionContext` carries identity only: `authenticated_user_id` (which must
come from verified request identity, never from a caller-supplied argument or an
MCP tool parameter), `request_id`, and an optional credential-group override.

The provider and connection are deliberately *not* context fields: the provider
comes from the adapter's own descriptor and the connection is discovered by
resolving this user's credential metadata. Accepting either from a caller would
allow one to be paired with a mismatched identity.

### 10.1 Credential handling

`CredentialResolver.resolve_connection` returns connection metadata **without
touching the secret**, which is what lets cache and quota scoping be established
before deciding whether a call is needed. `resolve` — the one that reads the
secret — is called only once a provider request is genuinely about to happen.

The credential never reaches the outcome, the cache, the metrics, the logs or an
exception. There is no field for it on any of them.

### 10.2 Statuses

Task 3/5 enums are reused rather than duplicated. `ProviderRunStatus` values the
executor produces:

| Status | When |
|--------|------|
| `SUCCESS` / `NO_DATA` / `PARTIAL` | as the adapter reported |
| `NOT_CONFIGURED` | no usable connection for this user; provider not called |
| `NOT_SUPPORTED` | descriptor cannot serve this object type / capability / mode |
| `PLAN_LIMITED` | normalized `PLAN_LIMITED` |
| `QUOTA_EXCEEDED` | quota exhausted, or a quota cooldown is active |
| `TEMPORARILY_UNAVAILABLE` | rate limited, provider down, or a cooldown is active — including a credential a provider has refused (§8.1) |
| `ERROR` | anything else, with a normalized category |

`NOT_CONFIGURED` is reported, not raised: an unconfigured provider is a coverage
gap for an investigation, never a failure of it.

**`NO_DATA` is not benign.** This layer has no notion of benign, and a test
asserts the outcome carries no verdict, risk or confidence field at all.

**`PARTIAL` survives.** Its evidence is preserved and it is never retried,
because partial data usually reflects a subscription's entitlements rather than
a failure.

### 10.3 `ProviderExecutionOutcome`

Kept separate from `ProviderResultEnvelope`. The envelope is what the provider
said; the outcome is what *we* did to obtain it — attempts, cache hit, coalesced,
cooldown, duration. Merging them would mean rewriting a provider fact every time
execution mechanics changed.

Consequently a cache hit keeps the envelope's original `retrieved_at` untouched
while reporting current execution timings. `to_provider_run(...)` bridges an
outcome into the Task 3 `ProviderRun` record.

### 10.4 Error text

Provider messages are passed through `redact_sensitive_text`, which replaces
whole `key=value` assignments rather than just values — leaving `api_key=` behind
would still look like a credential to every downstream guard. If a message still
resembles credential material after redaction it is **withheld entirely**: the
redactor is best-effort, and a diagnostic string is never worth the risk.

## 11. Metrics

`ExecutionMetricsSink` with `NoOpExecutionMetricsSink` (the default, so metrics
are never load-bearing) and `InMemoryExecutionMetricsSink` (tests and local
development only).

Logical executions and physical attempts are recorded separately:
`ExecutionMetric` per `execute()` call, `ProviderAttemptMetric` per provider
call. Conflating them would make a retry rate impossible to measure — three
attempts would look like three requests.

Recorded: provider, operation, status, object **type**, duration, attempts,
cache hit, coalesced, cooldown applied, error category.

Not recorded, and with no field able to hold it: credential material, raw
provider responses, and **the observable value**. That last one is the easy
mistake — labelling a metric with the IOC would quietly turn a metrics pipeline
into a log of everything every analyst has ever investigated, a sensitive
dataset with a completely different retention story from the counts around it.
The object *type* is recorded instead, which is what you want to aggregate by
anyway.

User identity is opt-in: with `emit_scope_digest=True` an opaque 16-character
digest of the scope is recorded, which allows correlation without recording who.

Both sink methods are synchronous. The executor emits from its hot path, and a
sink that awaited would let a metrics backend's latency become a provider call's
latency; a sink needing I/O should enqueue and drain elsewhere.

## 12. All state is in-memory and single-process

`InMemoryProviderCache`, `InMemoryQuotaStore`, `InMemoryCooldownStore`,
`InMemoryExecutionMetricsSink`, `ConcurrencyLimiter` and `SingleFlight` are all
process-local. Each is labelled `NOT FOR PRODUCTION` and exposes
`is_production_ready = False`.

Concretely, with N worker processes:

- each worker has its own cache, so a result is fetched up to N times;
- each worker discovers a throttled provider independently;
- effective provider concurrency is `max_concurrency × N`;
- coalescing only collapses duplicates within one process;
- all of it is lost on restart.

This is deliberately **not** pretending to be distributed coordination. The
protocols — `ProviderCache`, `QuotaStore`, `CooldownStore`,
`ExecutionMetricsSink` — are the seams that Redis-backed implementations will
slot into without the executor changing.

## 13. Testability

Time, sleeping and jitter are injected (`Clock`, `Sleeper`, `JitterSource`).
Production wires `SystemClock` / `AsyncioSleeper` / `RandomJitter`; tests wire
`ManualClock` / `RecordingSleeper` / `FixedJitter` and run instantly. No test in
this package sleeps, waits for a cooldown, or reads the wall clock, and the
concurrency tests wrap their awaits in `asyncio.timeout` so a deadlock fails in
a second instead of hanging CI.

## 14. Explicitly not implemented

Task 6 deliberately excludes:

```
Redis                     PostgreSQL              production secret vault
distributed locks         distributed semaphores  shared rate-limit state
real quota API calls      provider selection      query planning
```

and every remaining provider integration — SecurityTrails, AbuseIPDB, Shodan,
IPinfo — along with evidence fusion, verdict scoring, MCP, the Claude Skill and
any web UI. Google Threat Intelligence (Task 7), urlscan.io
(Task 8), GreyNoise and Censys (Task 9), and the three abuse.ch platforms
ThreatFox, URLhaus and MalwareBazaar (Task 10) and MISP Warning Lists (Task 11)
all run behind these controls today.

Task 11 is the first **credential-free, local** provider, and it needed almost
nothing from this layer. `requires_credentials = False` was already supported
generically: the executor skips the `NOT_CONFIGURED` gate, never touches the
secret store, permits a shared cache scope only for providers in that position,
and — since a credential-scoped cooldown needs a credential group it will not
have — cannot put one on cooldown either. No provider-name branch was added.

The one addition it did need is `ProviderDescriptor.dataset_version`, described in
§4.2: a provider answering from a pinned local dataset has a cache-correctness
problem no remote provider has, because refreshing the data invalidates every
answer derived from it.

The abuse.ch three are worth a note here, because they are the first providers to
share a credential. Task 6 resolves by the descriptor's credential group, so one
stored Auth-Key serves all three with no execution-layer change at all — and
sharing a credential never means sharing execution state: cache entries, quotas
and cooldowns are keyed by `ExecutionScope`, which includes the provider id. A
ThreatFox throttle does not stop URLhaus being asked. All three run at
`max_concurrency = 1`, because abuse.ch is a free service with published fair-use
limits and parallelism there is not TI Recon's to take.

The fake adapters in `tests/fixtures/execution_adapters.py` are shaped after
*categories* of provider behaviour (a quota-metered aggregator, a provider with
per-action limits, a provider returning subscription-limited partial data) so
these controls can be tested against realistic shapes. They contain no vendor
API details — no hosts, endpoints, payload schemas or header names — and perform
no I/O.
