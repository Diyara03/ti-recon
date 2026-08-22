# TI Recon — Platform Architecture Foundation

> Task 2. Component architecture and the invariants that hold it together.
> Every component is marked **implemented** or **future**. Future components are
> not in this repository.

## 1. Layer diagram

```
        Analyst
           |
  Claude + TI Analyst Skill        FUTURE — separate component, not in this repo
           |                       owns workflow narration + presentation
        MCP layer                  FUTURE — exposes TI Recon capabilities as tools
           |
  ============================ repository boundary ============================
           |
     TI Recon backend
           |
     Capability Planner            FUTURE — object type + depth -> capability set
           |
     Provider Registry             IMPLEMENTED — capability/object-type lookup
           |
     Provider Executor             IMPLEMENTED — cache, retry, quota, cooldown,
           |                                     concurrency, single-flight
           |
     Provider Adapters             CONTRACT IMPLEMENTED — GTI is the first
           |  (via Provider HTTP Transport — IMPLEMENTED)
           |  (auth via Credential Resolver — IMPLEMENTED)
           |
     Normalized Evidence           MODELS IMPLEMENTED — Task 3
           |
     Lineage / Correlation         MODELS IMPLEMENTED, engine FUTURE
           |
     Evidence Fusion               FUTURE — weighting, independence, decay
           |
     Assessment                    MODELS IMPLEMENTED, scoring engine FUTURE
```

## 2. The Claude boundary

The core TI engine is **independent of Claude**. Nothing under `src/ti_recon`
imports, mentions or assumes an LLM, and no model carries a Claude/MCP field.

- The **Claude TI Analyst Skill** will own workflow choices and how findings are
  presented to a human.
- The **MCP layer** will expose TI Recon operations as tools.
- **TI Recon** owns normalization, provider access, evidence, lineage and
  assessment.

Consequence: TI Recon must be independently usable and testable — via a future
HTTP API, CLI or library — with no LLM in the loop. Neither the Skill nor MCP is
implemented.

Corollary for credentials: because MCP arguments and Claude prompts are outside
the trust boundary, credentials must never travel through them. Credentials are
resolved server-side from the authenticated user identity.

## 3. Capability-based provider access

The engine asks **"what intelligence capability do I need?"**, never
**"which vendor must I call?"**.

```python
registry.find_compatible(
    object_type=IntelObjectType.IPV4_ADDR,
    capability=ProviderCapability.SCANNER_CONTEXT,
)
```

Capabilities (`ProviderCapability`):

```
REPUTATION                 aggregated multi-vendor reputation
MALWARE_INTELLIGENCE       malware family / campaign association
WEB_BEHAVIOR               page behavior, redirects, resources
SCANNER_CONTEXT            internet-scanner / background-noise classification
NETWORK_OWNERSHIP          ASN, organization, geolocation
CURRENT_INFRASTRUCTURE     currently observable hosting / services
HISTORICAL_INFRASTRUCTURE  passive DNS, historical hosting
CERTIFICATE_CONTEXT        TLS certificate observations
RELATIONSHIPS             pivots and related objects
FALSE_POSITIVE_CONTEXT     benign-infrastructure / warning-list context
BATCH_LOOKUP               multiple observables in one request
ACTIVE_SCAN                new interaction with the target (future, gated)
```

This yields three properties:

1. **Every provider is optional.** A missing or unconfigured provider degrades
   coverage; it never breaks an investigation.
2. **No vendor-specific branching.** Registry and engine code contains no
   `if provider_id == "virustotal"`.
3. **Substitutability.** Several providers may serve one capability; adding a
   provider is registration, not an engine change.

Provider *selection* among candidates (scoring, prioritization, cost) is a later
task. The registry returns all compatible providers in deterministic order.

## 4. Evidence, not votes

TI Recon must never implement:

```
3 providers say malicious, 2 say benign  ->  malicious
```

Providers contribute **evidence**, and evidence types are not interchangeable:

- a ThreatFox exact malware-sample association is a curated threat assertion
  about a specific artifact;
- a Censys open-port observation is a neutral infrastructure fact;
- a GreyNoise "benign scanner" classification is false-positive context;
- a VirusTotal detection count is an aggregation of *other* vendors' opinions —
  one aggregated source, not N independent sources.

Evidence classes (`EvidenceClass`):

```
DIRECT_OBSERVATION          the provider itself observed this
CURATED_THREAT_ASSERTION    a curated feed asserts a threat association
AGGREGATED_REPUTATION       an aggregation of third-party opinions
CONTEXT                     neutral context, no directional meaning alone
RELATIONSHIP                a link between two objects
```

Evidence effect (`EvidenceEffect`) is directional but not a score:

```
SUPPORTS_MALICIOUS   SUPPORTS_BENIGN   CONTEXT_ONLY
```

## 5. Facts, interpretation, assessment

Three layers, never merged:

| Layer | Model | Owner | Mutability |
|-------|-------|-------|------------|
| Provider fact | `Evidence` (+ `RawEvidenceReference`) | provider adapter | immutable input |
| Interpretation | `AssessmentContribution` | fusion engine (future) | derived, recomputable |
| Conclusion | `Assessment` | assessment engine (future) | derived, versioned |

An engine interpretation must never overwrite a provider fact. If TI Recon
concludes a GreyNoise "benign" classification should be discounted, that
discount lives in the contribution's factors and reason codes — the evidence
still says what the provider said.

`AssessmentContribution` separates `base_strength` from the modifiers applied to
it (`freshness_factor`, `independence_factor`, `specificity_factor`,
`false_positive_factor`) and the resulting `effective_contribution`, so a verdict
can be explained factor by factor.

## 6. Source lineage

Every `Evidence` records:

```
transport_provider   the provider whose API we actually called
origin_provider      the provider that originally produced the data
source_family        the intelligence family/upstream grouping
lineage_group_id     evidence sharing a lineage group is NOT independent
```

Worked example — a Censys response containing GreyNoise-derived data:

```
transport_provider = censys
origin_provider    = greynoise
```

Without this, querying both Censys and GreyNoise would look like two independent
confirmations of one fact and would inflate confidence. Lineage grouping is what
makes `independence_factor` computable later. The correlation engine that
consumes lineage is a future task; the mandatory fields exist now.

## 7. Passive by default

`ActivityMode.PASSIVE` is the default at every layer. Active operations
(submission, rescan, sandbox) are a separate adapter method
(`active_action`), gated on `descriptor.supports_active`, and are not
implemented. `ProviderAdapter.active_action` raises
`UnsupportedProviderOperation` by default.

## 8. Security boundaries

- **Credential boundary.** Credentials never enter `ProviderRequest`, provider
  results, logs, exceptions or serialized models. They are resolved from the
  authenticated user id inside the backend and applied by the transport.
- **Tenant boundary.** Credential lookups are keyed by
  `(authenticated_user_id, provider_id | credential_group)`. There is no API
  that accepts an arbitrary user id from an untrusted caller.
- **SSRF boundary.** `ProviderHttpClient` is constructed with one provider base
  URL and accepts only relative paths. Absolute URLs, scheme changes and
  host changes raise `ProviderTransportSecurityError`. There is deliberately no
  general-purpose fetch function anywhere in the codebase, so a submitted IOC
  URL cannot be turned into an outbound request to that URL.
- **Log boundary.** Transport logging is an allow-list: provider, method,
  path, status, latency, request id. Headers, cookies, bodies and query strings
  are not logged.

## 9. Repository module map

```
src/ti_recon/
  enums.py            shared vocabularies
  security.py         credential-key guards shared by models and transport
  versions.py         ENGINE_VERSION / POLICY_VERSION audit stamps
  models/
    base.py           TiReconModel base, utc_now
    intel_object.py   IntelObject (Observables and derived objects)
    investigation.py  Investigation, ProviderRun
    evidence.py       Evidence, RawEvidenceReference, EvidenceConflict
    relationship.py   Relationship + relationship vocabulary
    coverage.py       CoverageItem
    assessment.py     Assessment, AssessmentContribution
  normalization/
    errors.py         NormalizationError
    observables.py    normalize_observable + per-type normalizers
  credentials/
    enums.py          AuthType, CredentialStatus, PolicyStatus
    errors.py         credential-layer errors (no secrets in messages)
    groups.py         credential groups (e.g. shared abuse.ch Auth-Key)
    models.py         SecretRef, ProviderConnection, CredentialMaterial
    secret_store.py   SecretStore protocol, InMemorySecretStore
    repository.py     ConnectionRepository protocol, in-memory implementation
    manager.py        CredentialManager (lifecycle)
    resolver.py       CredentialResolver (user-scoped resolution)
  providers/
    capabilities.py   ProviderCapability, ProviderHealth
    descriptor.py     ProviderDescriptor
    request.py        ProviderRequest
    result.py         ProviderResultEnvelope, RateLimitSnapshot/Window
    quota.py          ProviderQuotaSnapshot, QuotaBucket, QuotaPeriod
    errors.py         ProviderErrorCategory, ProviderError hierarchy
    adapter.py        ProviderAdapter ABC
    registry.py       ProviderRegistry
    transport.py      ProviderHttpClient (+ TransportConfig)
  providers/gti/
    client.py         the only vt.Client user; GTIObject / descriptors
    config.py         x-tool, agent, host, timeouts (no credential)
    errors.py         GTI error codes -> normalized categories
    quota.py          overall_quotas -> ProviderQuotaSnapshot
    policy.py         collection routing, excluded attributes, cache TTLs
    relationships.py  verified relationship table, depth profiles, limits
    normalizer.py     GTI objects -> Task 3 evidence/objects/relationships
    adapter.py        GTIAdapter
  execution/
    clock.py          Clock / Sleeper / JitterSource injection seams
    models.py         ExecutionScope, ExecutionContext, outcome, CacheScope
    cache.py          ProviderCache protocol, key builder, in-memory cache
    policy.py         CachePolicy, ProviderExecutionPolicy + registry
    retry.py          RetryPolicy, retry matrix, exponential backoff
    limits.py         quota + cooldown stores, cooldown derivation
    coordination.py   ConcurrencyLimiter, SingleFlight
    metrics.py        ExecutionMetricsSink + no-op / in-memory sinks
    executor.py       ProviderExecutor
```

## 10. Provider execution (Task 6)

Between the future planner and each adapter sits `ProviderExecutor`, which runs
a *selected* provider under caching, retry/backoff, rate-limit and quota
tracking, cooldowns, bounded concurrency and in-flight request coalescing. It
decides how to call a provider safely and never what to call or what a result
means. Every control is keyed by an `ExecutionScope` built from the analyst's
identity and credential connection, so no state is shared between users.

All of that state is in-memory and single-process — a development foundation.
The protocols are the seams distributed implementations will slot into.

Full detail: [provider-execution.md](provider-execution.md).

## 11. Providers

One provider is integrated: **Google Threat Intelligence**, reading GTI /
VirusTotal API v3 with each analyst's own VirusTotal API key. It is passive
enrichment only and supplies evidence rather than conclusions.

It reaches the engine entirely through the Task 5 contract — the registry finds
it by capability with no vendor branch, and it passes the same reusable adapter
contract suite as the test fakes. The one deviation from the framework is
documented and contained: GTI uses the official `vt-py` SDK rather than the
shared HTTP transport, and that SDK is imported by exactly one module so its
types never reach the core.

Full detail: [providers/gti.md](providers/gti.md).

Note the data-use boundary recorded there: GTI content must not be exposed to
Claude, MCP or any AI layer before the applicable provider terms are reviewed.

## 12. Deferred architecture (Task 9+)

Documented so the shape is known; not implemented:

- Distributed execution state: Redis-backed cache, quota and cooldown stores,
  shared rate-limit state and cross-worker concurrency limits.
- Further provider adapters (GreyNoise, Censys, abuse.ch, warning lists)
  alongside GTI and urlscan.
- Capability planner, provider selection and adaptive enrichment (widen
  capabilities when evidence is thin).
- Lineage-aware correlation, evidence fusion and verdict scoring.
- Persistence (PostgreSQL), raw-response object storage, a durable backend for
  the artifact store (Task 8 ships an in-memory one), production secret vault.
- MCP server, Claude connector, TI Analyst Skill, web frontend.
- Active operations and sandbox integration.
