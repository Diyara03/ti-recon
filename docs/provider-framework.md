# TI Recon — Provider Integration Framework

> Task 5. Describes `src/ti_recon/providers/`.
>
> This document describes the provider-neutral contracts, the registry and the
> shared transport. Seven providers now implement them: Google Threat
> Intelligence (Task 7, see [providers/gti.md](providers/gti.md)), urlscan.io
> (Task 8, see [providers/urlscan.md](providers/urlscan.md)), GreyNoise and
> Censys (Task 9, see [providers/greynoise.md](providers/greynoise.md) and
> [providers/censys.md](providers/censys.md)), and the three abuse.ch platforms
> ThreatFox, URLhaus and MalwareBazaar (Task 10, see
> [providers/threatfox.md](providers/threatfox.md),
> [providers/urlhaus.md](providers/urlhaus.md) and
> [providers/malwarebazaar.md](providers/malwarebazaar.md)) — three adapters
> sharing one credential group and one source family.
>
> Covers capabilities, descriptor, request, result envelope, error taxonomy,
> the adapter contract, the registry and the shared HTTP transport.

## 1. Why the framework looks like this

Three requirements shape every type in this package:

1. **Every provider is optional.** The engine asks for a *capability*, and the
   registry answers with whichever configured providers can serve it. A missing
   provider degrades coverage; it never breaks an investigation.
2. **Adapters report, they do not conclude.** An adapter normalizes and
   classifies. It has no way to express a verdict, risk score or confidence —
   there is no such field on the result envelope and no such method on the
   contract.
3. **Credentials never travel with a request.** `ProviderRequest` has no
   credential field, so it can be logged, cached and attached to an exception
   without carrying a secret.

## 2. Capabilities

`ProviderCapability` (defined in `ti_recon.enums`, re-exported from
`ti_recon.providers`):

```
REPUTATION                 aggregated multi-vendor reputation
MALWARE_INTELLIGENCE       malware family / campaign association
WEB_BEHAVIOR               page behavior, redirects, resources
SCANNER_CONTEXT            internet-scanner / background-noise classification
NETWORK_OWNERSHIP          ASN, organization, geolocation
CURRENT_INFRASTRUCTURE     currently observable hosting / services
HISTORICAL_INFRASTRUCTURE  passive DNS, historical hosting
CERTIFICATE_CONTEXT        TLS certificate observations
RELATIONSHIPS              pivots and related objects
FALSE_POSITIVE_CONTEXT     benign-infrastructure / warning-list context
BATCH_LOOKUP               several observables in one request
ACTIVE_SCAN                new interaction with the target (gated, unimplemented)
```

`ACTIVE_CAPABILITIES` names the subset that requires `ActivityMode.ACTIVE` and
explicit user approval.

`ProviderHealth` — `available`, `degraded`, `unavailable`, `unknown` — is a
fourth status axis, independent of credential status, policy status and the
status of any individual run. A provider can be `available` while a user's key
is revoked, and `unavailable` while every key is valid. A test asserts no model
carries two of these axes at once.

## 3. `ProviderDescriptor`

A provider's self-declaration. The registry matches on this, which is what keeps
vendor names out of engine code.

| Field | Notes |
|-------|-------|
| `provider_id` | `^[a-z][a-z0-9_]*$` |
| `display_name` | analyst-facing |
| `adapter_version` | our code version |
| `api_version` | the provider's API version |
| `source_family` | upstream-origin grouping; feeds evidence lineage |
| `credential_group` | defaults to `provider_id` |
| `supported_object_types` | non-empty |
| `capabilities` | non-empty |
| `supports_passive` / `supports_active` / `supports_batch` | |
| `requires_credentials` | some providers need none |

Consistency is enforced rather than trusted:

- declaring `ACTIVE_SCAN` requires `supports_active`, and vice versa;
- `supports_batch` must agree with the `BATCH_LOOKUP` capability;
- a provider must support passive or active operations.

`source_family` matters for correctness, not bookkeeping: two providers in the
same family agreeing is much weaker evidence than two independent families
agreeing, and `AssessmentContribution.independence_factor` is what consumes it.

## 4. `ProviderRequest`

`investigation_id`, `intel_object`, `operation`, `requested_capabilities`,
`depth`, `activity_mode`, `max_results`, `max_pages`.

Frozen, and with **no credential field** — a test asserts no field name matches
the credential-key pattern, and `extra="forbid"` means one cannot be smuggled in.

`activity_mode` is the user's consent boundary, so it is enforced here: a
`PASSIVE` request may not carry an `ACTIVE_ACTION` operation or request
`ACTIVE_SCAN`. If it could, consent would be bypassable by whoever constructed
the request.

## 5. `ProviderResultEnvelope`

The single shape every adapter returns.

| Group | Fields |
|-------|--------|
| identity | `provider`, `operation`, `status`, `retrieved_at` |
| versions | `api_version`, `adapter_version` |
| caching | `cacheability` (`CacheabilityHint`) |
| limits | `rate_limit` (`RateLimitSnapshot \| None`) |
| raw | `raw_reference` (`RawEvidenceReference \| None`) |
| normalized output | `evidence`, `objects`, `relationships` |
| problems | `error_category`, `error_message`, `warnings` |

Enforced invariants:

- a `SUCCESS` result may not carry an error category; an `ERROR` result must;
- every piece of evidence must name this envelope's provider as its
  `transport_provider` (an adapter cannot attribute evidence to someone else);
- `warnings` and `error_message` may not mention credential material;
- relationships must reference evidence.

There is deliberately **no** `verdict`, `risk_score`, `confidence` or `score`
field, and no `assess`/`decide` method on the contract. Tests assert both.

`RateLimitSnapshot` has `operation`, `limit`, `remaining`, `reset_at`, `scope` —
all nullable, because most providers expose only some of this and some expose
none. An all-`None` snapshot is an honest answer; invented numbers would be
trusted by a scheduler.

`CacheabilityHint` records `cacheable`, `ttl_seconds`, `cache_key_hint`,
`revalidate_after`. Metadata only — the cache itself is Task 6. Recording the
hint now means adapters need not be revisited when caching lands.

Two helpers keep the boundary to Task 3 explicit:
`ProviderResultEnvelope.from_payload(...)` builds an envelope around a
`NormalizedPayload`, and `.to_provider_run(...)` converts a result into the Task
3 `ProviderRun` record.

## 6. Error taxonomy

`ProviderErrorCategory` (in `ti_recon.enums`):

```
AUTHENTICATION_ERROR   PERMISSION_ERROR   PLAN_LIMITED
RATE_LIMITED           QUOTA_EXCEEDED     NOT_FOUND
INVALID_REQUEST        PARTIAL_RESULT     TRANSIENT_ERROR
PROVIDER_UNAVAILABLE   SCHEMA_ERROR       UNKNOWN_ERROR
```

Each has an exception class deriving from `ProviderError`, which exposes:

- `run_status` — how the failure is recorded on a `ProviderRun`. Notably
  `NOT_FOUND` maps to `NO_DATA`: "the provider has never seen this" is a
  finding, not a failure.
- `is_retryable` — whether retrying could plausibly help. The retry engine is
  Task 6; recording the nature of each failure now means nothing has to guess
  later. `SCHEMA_ERROR` is deliberately not retryable — a schema change needs a
  code fix.

No provider-specific HTTP mapping is implemented; each adapter will map its own
vendor's conventions in `classify_error`.

Error messages must be safe to log. Adapters must not build messages from raw
response bodies or request headers.

### `UnsupportedProviderOperation`

Optional operations raise this typed error, never `NotImplementedError`. A
provider not offering batch lookup is an ordinary runtime fact the engine must
route around, not a bug to crash on. Its `run_status` is `NOT_SUPPORTED` and it
is never retryable.

## 7. `ProviderAdapter`

```python
class ProviderAdapter(ABC):
    @property
    @abstractmethod
    def descriptor(self) -> ProviderDescriptor: ...

    def supports(self, object_type, capability) -> bool: ...
    def assert_supports(self, object_type, capability) -> None: ...

    @abstractmethod
    async def validate_credentials(self, credential) -> CredentialValidation: ...
    @abstractmethod
    async def discover_capabilities(self, credential) -> CapabilityDiscovery: ...
    @abstractmethod
    async def lookup(self, request, credential) -> ProviderResultEnvelope: ...

    async def batch_lookup(self, requests, credential):
        raise UnsupportedProviderOperation(...)

    async def pivot(self, request, credential):
        raise UnsupportedProviderOperation(...)

    async def active_action(self, request, credential):
        raise UnsupportedProviderOperation(...)

    @abstractmethod
    def normalize(self, request, payload, *, raw_reference=None) -> NormalizedPayload: ...
    @abstractmethod
    def classify_error(self, error) -> ProviderErrorCategory: ...

    def parse_rate_limits(self, headers) -> RateLimitSnapshot | None:
        return None

    async def health(self, credential=None) -> ProviderHealthReport: ...
```

Supporting result types:

- `CredentialValidation` — reports a `CredentialStatus`, the same vocabulary the
  credential layer stores, so a validation result can be recorded without
  translation.
- `CapabilityDiscovery` — what *this account's plan* actually allows, as opposed
  to what the integration can do. The difference is why a free-tier key produces
  a reported coverage gap rather than a silent empty result.
- `ProviderHealthReport` — availability, independent of any credential.

Two defaults are deliberate:

- `parse_rate_limits` returns `None`. Guessing limits from headers a provider
  does not send would hand a scheduler numbers it should not trust.
- `health` returns `UNKNOWN`, not `AVAILABLE`. An adapter that has not checked
  should not claim its provider is up.

`normalize` and `classify_error` are synchronous and pure, so normalization can
be tested against a stored response fixture with no I/O.

## 8. Contract invariants (all tested)

```
all provider I/O is async

no credential appears in ProviderRequest

no secret appears in ProviderResultEnvelope

provenance is mandatory on every piece of evidence

transport_provider and origin_provider may differ

adapters return normalized Task 3 models, not provider payloads

unsupported operations raise UnsupportedProviderOperation, not
NotImplementedError

a provider adapter never decides a verdict
```

Google Threat Intelligence is held to every one of these invariants by the same
reusable suite the fakes are, which is what makes it a provider rather than a
special case. Its one documented deviation — using the official `vt-py` SDK
instead of the shared transport — is contained to a single module so no SDK type
crosses into the core.

`tests/fixtures/fake_providers.py` holds four fake adapters used throughout the
test suite. They perform no network I/O and contain no vendor API details — no
hosts, endpoints, payload schemas or header names. Each is shaped after a
*category* of provider so capability overlap can be tested realistically without
naming a vendor:

| Fake | Shaped like | Notable trait |
|------|-------------|---------------|
| `FakeScannerProvider` | scanner / background-noise | IPs only; context-class evidence |
| `FakeAggregatorProvider` | multi-vendor aggregator | all object types; batch; relays third-party data |
| `FakeWarningListProvider` | curated known-good list | requires no credential |
| `FakeMinimalProvider` | smallest legal adapter | proves the optional parts are optional |

`FakeAggregatorProvider` exists mainly to exercise lineage: it emits one piece
of evidence with `transport_provider=fake_aggregator` and
`origin_provider=fake_scanner`, landing in the same lineage group as the scanner's
own evidence — so querying both cannot inflate confidence.


## 9. `ProviderRegistry`

The registry is what makes "which vendor do I call?" an unaskable question. The
engine describes what it needs; the registry answers with whichever registered
providers can serve it.

```python
registry = ProviderRegistry(adapters)

registry.register(adapter)               # DuplicateProviderId on collision
registry.unregister(provider_id)         # UnknownProvider if absent
registry.get(provider_id)                # UnknownProvider if absent
registry.list_all()                      # ordered by provider_id
registry.descriptors()                   # safe to expose; no credential state
registry.find_by_object_type(object_type)
registry.find_by_capability(capability)
registry.find_compatible(object_type, capability, *, activity_mode, requires_credentials)
registry.capabilities_for_object_type(object_type)
```

Properties, all tested:

- **Duplicate provider ids are rejected, not overwritten.** Silently replacing
  an integration would make evidence provenance ambiguous, since
  `transport_provider` is just the provider id. A rejected duplicate leaves the
  original in place.
- **Deterministic ordering.** Every listing is sorted by `provider_id`, so
  results do not depend on registration order and investigations stay
  reproducible and diffable.
- **No credentials.** The registry holds adapters and descriptors only. No
  method name matches the credential-key pattern, and serialized descriptors
  contain no credential state.
- **Several providers may serve one capability**, and providers may require no
  credential at all (`requires_credentials=False`).
- **No vendor branching.** A test greps the registry source for vendor names and
  fails if any appears. Registering a brand-new provider requires no registry
  change.
- **No scoring or prioritization.** `find_compatible` returns every match.
  Choosing which to call, in what order, at what cost is a later task; a test
  asserts there is no `rank`/`score`/`prioritize`/`select` method, so a policy
  cannot quietly accrete inside a lookup table.

`activity_mode` (default `PASSIVE`) is a filter rather than a hint: a passive
investigation must never be handed an adapter that can only act, and an active
request must not be served by a passive-only adapter.

`capabilities_for_object_type` exists for coverage reporting — it is what lets an
investigation distinguish "no provider could serve that capability for this
object type" from "providers were tried and found nothing".

Worked example — the canonical match:

```
need: ipv4-addr + SCANNER_CONTEXT

FakeScannerProvider     (ipv4/ipv6, SCANNER_CONTEXT)    -> match
FakeAggregatorProvider  (all types, REPUTATION)         -> no match
```


## 10. `ProviderHttpClient`

One client per provider, pinned to that provider's API base URL.

```python
config = TransportConfig(
    provider_id="example_provider",
    base_url="https://api.example-provider.test/v1/",
    timeouts=TransportTimeouts(connect=5.0, read=20.0, write=10.0, pool=5.0),
    auth=AuthConfig(placement=AuthPlacement.HEADER, header_name="X-Api-Key"),
)

async with ProviderHttpClient(config) as client:
    response = await client.get("ip/198.51.100.7", credential=credential)
```

Provided:

- persistent connection pooling for the client's lifetime;
- explicit connect, read, write and pool timeouts, none of which may be zero or
  negative — a missing read timeout is how one slow provider stalls every worker;
- TLS verification always on, with **no configuration path to disable it** (a
  test asserts `verify` appears in neither `TransportConfig` nor the constructor
  signature);
- `https`-only base URLs, with a trailing slash added if absent — a base URL
  without one silently drops its last path segment when joined;
- a versioned `User-Agent` (`ti-recon/<version>`) so providers can attribute and
  rate-limit our traffic;
- clean async shutdown via `aclose()` or `async with`, idempotent, with use after
  close raising `ProviderTransportClosed`.

Redirects are **not** followed: a redirect is a provider-controlled way to move a
request to another host.

### 10.1 The SSRF boundary

TI Recon investigates suspicious URLs. If any function accepted a full URL, then
sooner or later an analyst-submitted URL would reach it — and TI Recon would be
fetching attacker-controlled infrastructure from its own network, with its own
IP, on behalf of whoever submitted the URL. A suspicious URL must be handed to a
provider API built to visit it (a URL scanner), never followed directly.

So the boundary is structural, not a rule to remember:

```
known configured provider base URL  +  relative provider API path
```

- The base URL is fixed at construction.
- `path` is always relative. A leading `/` is accepted and treated as relative to
  the base URL.
- Refused with `ProviderTransportSecurityError`: absolute URLs (`https://…`),
  scheme-relative `//host`, `..` traversal, any path that resolves outside the
  base URL, backslashes, whitespace and control characters (CR/LF in a path is a
  request-splitting attempt).
- Only `GET`, `POST` and `HEAD` are permitted.
- A response whose host is not the configured host is refused — defence in depth
  against a proxy or misconfiguration answering from elsewhere.

There is deliberately **no** `fetch_arbitrary_url`, `fetch`, `open_url` or
`browse`, and no method takes a `url` parameter. Tests assert all of this,
including the concrete attack: handing the client the URL under investigation.

### 10.2 Credential handling

`AuthConfig` says *where* a credential goes (header or query parameter, with an
optional scheme such as `Bearer`). `AuthConfig.for_auth_type(...)` gives a
conventional placement for each `AuthType`; an adapter overrides it when its
provider differs.

The credential is attached at the last possible moment, in one method. A test
asserts `reveal()` appears exactly once in the transport module — adapters never
touch the raw value.

An adapter that tries to pass a credential in as a plain header
(`Authorization`, `X-Apikey`, `Auth-Key`, `Cookie`, …) is refused: credentials
arrive as a `CredentialMaterial`, not as strings in a header dict. The same
rejection applies to `TransportConfig.default_headers`.

### 10.3 Logging

An allow-list, emitted as structured `extra` fields:

```
provider   http_method   provider_path   operation   status_code   latency_ms
```

Never logged: headers, cookies, request or response bodies, and **the query
string**. That last exclusion matters — some providers accept credentials as
query parameters, so logging query strings would leak keys for exactly those
providers. A test passes `params={"apikey": ...}` and asserts the value never
reaches the log.

### 10.4 Typed errors

| Condition | Raised | Retryable |
|-----------|--------|-----------|
| would leave the base URL / illegal path / method | `ProviderTransportSecurityError` | no |
| used after close | `ProviderTransportClosed` | no |
| timeout | `ProviderTimeoutError` | yes |
| connection failure | `ProviderUnavailableError` | yes |

HTTP status codes are **not** interpreted here. A 429 or 403 is returned to the
adapter, which maps its own provider's conventions in `classify_error`.

## 11. Execution controls (Task 6)

`ProviderHttpClient` performs exactly one HTTP attempt per call, and an adapter
interprets exactly one response. Everything around that — caching, retry and
backoff, rate-limit and quota tracking, cooldowns, bounded concurrency,
request coalescing — lives in `ti_recon.execution` and is documented in
[provider-execution.md](provider-execution.md).

The seams this framework left for it are the ones that layer now uses:
`CacheabilityHint` on every envelope, `RateLimitSnapshot` (extended in Task 6
with per-window `RateLimitWindow` entries) from `parse_rate_limits`, the
optional `quota` snapshot on an envelope, `ProviderError.is_retryable` and its
`reset_at` / `retry_after_seconds` metadata, and `ProviderRun.cache_hit`.

An adapter needs no awareness of any of it: the executor calls
`lookup` / `pivot` / `active_action` exactly as this contract describes.

Still **not implemented**: Redis or any distributed coordination, shared
rate-limit state across workers, and real quota API calls.
