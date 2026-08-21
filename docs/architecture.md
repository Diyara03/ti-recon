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
     Provider Adapters             CONTRACT IMPLEMENTED — no real adapters yet
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
    result.py         ProviderResultEnvelope, RateLimitSnapshot, cacheability
    errors.py         ProviderErrorCategory, ProviderError hierarchy
    adapter.py        ProviderAdapter ABC
    registry.py       ProviderRegistry
    transport.py      ProviderHttpClient (+ TransportConfig)
```

## 10. Deferred architecture (Task 6+)

Documented so the shape is known; not implemented:

- **Task 6** — response caching (Redis), retry engine with exponential backoff
  and jitter, coordinated 429 handling, quota counters, provider cooldown,
  shared rate-limit state across workers.
- Capability planner and adaptive enrichment (widen capabilities when evidence
  is thin).
- Lineage-aware correlation, evidence fusion and verdict scoring.
- Persistence (PostgreSQL), raw-response object storage, production secret vault.
- MCP server, Claude connector, TI Analyst Skill, web frontend.
- Active operations and sandbox integration.
