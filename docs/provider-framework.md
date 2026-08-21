# TI Recon — Provider Integration Framework

> Task 5. Describes `src/ti_recon/providers/`.
>
> **No real provider integration exists.** This document describes contracts,
> a registry and a transport. There is no VirusTotal, urlscan, GreyNoise,
> Censys, ThreatFox, URLhaus or MalwareBazaar adapter in this repository.
>
> **Coverage at this commit:** capabilities, descriptor, request, result
> envelope, error taxonomy and the adapter contract. The registry and the HTTP
> transport land in the following commits of this series and are documented
> then.

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

    async def batch_lookup(self, requests, credential): raise UnsupportedProviderOperation(...)
    async def pivot(self, request, credential):        raise UnsupportedProviderOperation(...)
    async def active_action(self, request, credential): raise UnsupportedProviderOperation(...)

    @abstractmethod
    def normalize(self, request, payload, *, raw_reference=None) -> NormalizedPayload: ...
    @abstractmethod
    def classify_error(self, error) -> ProviderErrorCategory: ...

    def parse_rate_limits(self, headers) -> RateLimitSnapshot | None: return None
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
