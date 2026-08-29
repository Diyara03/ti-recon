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
     Enrichment Planner            IMPLEMENTED — Task 13. capability goals,
           |                                     source-family coverage, budgets,
           |                                     deterministic ranking, stop rules
           |
     Enrichment Orchestrator       IMPLEMENTED — Task 13. plan -> execute ->
           |                                     observe -> re-plan, sequential
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
     Correlation Engine            IMPLEMENTED — Task 14. exact identity,
           |                                     assertion edges, lineage
           |
     Investigation Graph           IMPLEMENTED — Task 14. nodes + edges +
           |                                     assertions, per investigation
           |
     Pivot Candidate Engine        IMPLEMENTED — Task 14. bounded, explicit,
           |                                     one hop; executes via Task 13
           |
     Temporal + Context            IMPLEMENTED — Task 15. typed instants,
     Qualification                                explicit as_of, source
           |                                      lifecycle, context signals,
           |                                      interpretation cues
           |
           |   +-- TemporalFact          what kind of time this is
           |   +-- SourceLifecycleState  what the source says is true now
           |   +-- ContextSignal         structured context, never a direction
           |   +-- sandbox quality       how informative a negative run was
           |   +-- InterpretationCue     named cautions, with their derivation
           +-- TemporalIssue         time that cannot be read literally
           |
     False-Positive /              IMPLEMENTED — Task 16. scoped alternative
     Alternative-Explanation                     explanations and limitations
     Reasoning
           |
           |   +-- ALTERNATIVE_EXPLANATION    context may explain a detection
           |   +-- INTERPRETATION_LIMITATION  true, but read too broadly
           |   +-- ANALYSIS_QUALITY_LIMITATION how much a negative can carry
           |   +-- ATTRIBUTION_CAUTION        what happened vs who owns it
           |   +-- TEMPORAL_RELEVANCE         history vs current state
           |   +-- SOURCE_DEPENDENCE          not independent corroboration
           +-- UNRESOLVED_TENSION         opposing facts, left unresolved
           |
     Claim Semantics               IMPLEMENTED — Task 17A. provider-neutral
           |                                      propositions; provider-owned
           |                                      translation
           |
     Independence /                IMPLEMENTED — Task 17B. originating source
     Corroboration                                family; compatible propositions
           |
     Explanation-Aware Fusion      IMPLEMENTED — Task 17C. Task 16 EXPLAINS links
           |                                      only; deterministic rules
           |
     Assessment + Confidence       IMPLEMENTED — Task 17D. verdict and confidence
           |                                      decided separately; no score
           |
     Decision Readiness            FUTURE — Task 18. is the assessment sufficient
           |                                for a particular decision?
           |
     Interface / MCP / Skill       FUTURE
```

Task 17 is the first layer allowed to conclude, and the last one that concludes
anything about the *observable* alone. It produces a verdict and a confidence
band and deliberately no action: whether to block, quarantine or close depends on
the environment and the asset, and a MALICIOUS verdict on shared or compromised
infrastructure can make blocking actively harmful.

Task 3's `Assessment` model remains the untouched Task 3 placeholder. It requires
a `risk_score` Task 17 must not produce, and its `AssessmentContribution` is built
on `base_strength` times multiplicative dampening factors — the arithmetic fusion
model Tasks 15 and 16 spent two tasks refusing. Task 17 owns `FusionAssessment`
and reuses Task 3's `Verdict` enum, which was always the right part.

Task 16 is **not** fusion either. It says which evidence context legitimately
explains and which it does not, and hands both sets on: it never selects the
final side of a disagreement, and every alternative explanation it produces
carries an explicit statement that it does not establish the object is benign.

Task 15 is **not** fusion. It hands the layers below it structured facts saying
what happened, when the source actually says it happened, what kind of timestamp
that is, what current state the source reports, which contextual caveats apply,
what scope they apply to, how informative a sandbox result was, and whether two
sources are dependent — without deciding the case.

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

The registry returns all compatible providers in deterministic order and ranks
nothing. Choosing between them is Task 13's job, and it is a separate layer on
purpose: the registry answers "who *could* answer this?", the planner answers
"who should we ask next, and is another answer worth buying?".

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
  providers/urlscan/
    client.py         read-only urlscan client (no submission method exists)
    config.py         host, timeouts, artifact byte ceilings (no credential)
    descriptor.py     provider identity and declared capabilities
    errors.py         urlscan statuses -> normalized categories
    quota.py          per-action allowances + per-window rate limits
    search.py         allow-listed query building, bounded candidate selection
    normalizer.py     scan results -> evidence, with verdict lineage separated
    observations.py   redirects, contacted infrastructure, served-body digests
    forensics.py      static extraction from stored artifacts (no execution)
    policy.py         the WEB_FORENSICS gate, search windows, cache TTLs
    adapter.py        UrlscanAdapter
  providers/greynoise/
    client.py         two read-only v3 endpoints; no GNQL, no v2
    config.py         host, `key` header placement, timeouts (no credential)
    descriptor.py     provider identity; IPv4 only, nothing active
    errors.py         GreyNoise statuses -> normalized categories
    access.py         full vs Community access, resolved and remembered per key
    metering.py       response rate-limit headers -> RateLimitSnapshot
    normalizer.py     classification, BSI, tags, CVEs, sensor detail, ownership
    policy.py         access mode, per-depth detail, cache TTLs
    adapter.py        GreyNoiseAdapter
  providers/censys/
    client.py         four reads (two metered, two free); no search, no rescan
    config.py         host, bearer placement, schema Accept headers
    descriptor.py     provider identity; no REPUTATION capability
    errors.py         Censys statuses -> categories, credits vs rate limits
    assets.py         observable -> deterministic host / web-property identity
    credits.py        zero-cost balance -> ProviderQuotaSnapshot (a wallet)
    organizations.py  per-connection organization id resolution
    normalizer.py     exposure, ownership, DNS, certificates, vulnerabilities
    policy.py         per-depth bounds, conservative concurrency, cache TTLs
    adapter.py        CensysAdapter
  providers/abusech/
    family.py         shared source family, credential group, relay origins
    values.py         bounded readers for provider-supplied values
    config.py         the three fixed origins, Auth-Key header placement
    errors.py         `query_status` bodies -> normalized categories
    client.py         POST transport (form or JSON), frozen query allow-list
    evidence.py       shared normalization context, relayed-summary builder
    policy.py         per-depth bounds, concurrency 1, execution policy builder
  providers/threatfox/
    client.py         two reads: search_ioc, search_hash
    config.py         host and descriptor wiring (no credential)
    descriptor.py     provider identity; IPv4/domain/URL/file, nothing active
    matching.py       local re-validation of loose matches, by parsing only
    normalizer.py     one IOC assertion, family objects, coverage + horizon
    policy.py         per-depth bounds, cache TTLs
    adapter.py        ThreatFoxAdapter
  providers/urlhaus/
    client.py         three path-routed reads: url, host, payload
    config.py         host and descriptor wiring (no credential)
    descriptor.py     provider identity; no web-behaviour capability
    normalizer.py     exact-URL vs host association, payload provenance, relays
    policy.py         per-depth bounds, cache TTLs
    adapter.py        UrlhausAdapter
  providers/malwarebazaar/
    client.py         one read: get_info (no download, no upload)
    config.py         host and descriptor wiring (no credential)
    descriptor.py     provider identity; files only, no FILE_BEHAVIOR
    normalizer.py     one sample assertion, signing, YARA, vendor names only
    policy.py         durable-result TTL, per-depth bounds
    adapter.py        MalwareBazaarAdapter
  providers/misp_warninglists/
    models.py         raw upstream schema, snapshot manifest, diagnostics
    snapshot.py       local snapshot reader: path safety, checksums, staleness
    profile.py        include/exclude, entry ceiling, profile fingerprint
    candidates.py     observable -> MISP attribute candidates (matching_attributes)
    matchers.py       string/substring/hostname/cidr; regex recognized, not run
    loader.py         compiled in-memory index + applicability-aware diagnostics
    config.py         snapshot root, stale threshold (no host, no credential)
    descriptor.py     credential-free, FALSE_POSITIVE_CONTEXT, dataset_version
    normalizer.py     one context finding + coverage; every hit CONTEXT_ONLY
    policy.py         depth presentation bounds, execution policy
    adapter.py        MispWarningListsAdapter
  sandbox/
    models.py         provider-neutral dynamic-analysis vocabulary
    selection.py      bounded deterministic representative-report choice
    bounds.py         per-depth presentation caps with hard ceilings
  providers/hybrid_analysis/
    config.py         host, api-key header, User-Agent (no credential field)
    descriptor.py     FILE_BEHAVIOR, files only, nothing active
    errors.py         statuses + quota prose -> categories; 410 as a state
    client.py         three GETs behind a frozen path allow-list
    models.py         Falcon Sandbox JSON -> neutral models; privacy exclusions
    normalizer.py     one sample finding + bounded behaviour + coverage
    policy.py         request budget per depth, cache TTLs, concurrency 1
    adapter.py        HybridAnalysisAdapter
  artifacts/
    models.py         ArtifactScope, ArtifactKind, StoredArtifact
    store.py          bounded, user-isolated artifact store (in-memory)
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
  planning/
    models.py         locality, cost, novelty, budgets, decisions, result
    goals.py          CapabilityGoal, GoalActivation, depth ordering
    policy.py         per-depth budgets, goal templates, profile registry
    state.py          coverage per capability and source family, blocking
    ranking.py        RANKING_FACTORS + lexicographic candidate key
    planner.py        AdaptiveEnrichmentPlanner (no I/O, deterministic)
    orchestrator.py   AdaptiveEnrichmentOrchestrator (plan -> execute -> observe)
    metrics.py        PlanningMetricsSink + no-op / in-memory sinks
    catalog.py        the only module here that may name a provider
  correlation/
    models.py         nodes, edges, assertions, issues, limits, truncation
    identity.py       canonical node keys + conservative file-hash resolver
    relationships.py  canonical vocabulary, orientation, pivot safety classes
    graph.py          InvestigationGraph (dicts + adjacency, bounded)
    engine.py         CorrelationEngine.ingest(provider result)
    policy.py         pivot modes, global budgets, depth downshift, hop limit
    pivots.py         PivotCandidate + lexicographic ranking + privacy rules
    orchestrator.py   root -> correlate -> bounded pivots via Task 13
    results.py        CorrelatedEnrichmentResult, PivotRun
    metrics.py        CorrelationMetricsSink + no-op / in-memory sinks
```

## 10. Provider execution (Task 6)

Between the planner and each adapter sits `ProviderExecutor`, which runs
a *selected* provider under caching, retry/backoff, rate-limit and quota
tracking, cooldowns, bounded concurrency and in-flight request coalescing. It
decides how to call a provider safely and never what to call or what a result
means. Every control is keyed by an `ExecutionScope` built from the analyst's
identity and credential connection, so no state is shared between users.

All of that state is in-memory and single-process — a development foundation.
The protocols are the seams distributed implementations will slot into.

Full detail: [provider-execution.md](provider-execution.md).

## 11. Providers

Nine providers are integrated, each answering a different question and all of
them passive:

| Provider | Question it answers | Detail |
|---|---|---|
| Google Threat Intelligence | what does the industry know about this artifact? | [providers/gti.md](providers/gti.md) |
| urlscan.io | what did a browser see when it visited this page? | [providers/urlscan.md](providers/urlscan.md) |
| GreyNoise | what does this address *do* on the internet? | [providers/greynoise.md](providers/greynoise.md) |
| Censys | what is *exposed on* this asset? | [providers/censys.md](providers/censys.md) |
| ThreatFox | is this a current, family-attributed indicator? | [providers/threatfox.md](providers/threatfox.md) |
| URLhaus | has this URL been seen distributing malware? | [providers/urlhaus.md](providers/urlhaus.md) |
| MalwareBazaar | is this file a known, vetted malware sample? | [providers/malwarebazaar.md](providers/malwarebazaar.md) |
| MISP Warning Lists | is there local context that should change how I read the rest? | [providers/misp-warninglists.md](providers/misp-warninglists.md) |
| Hybrid Analysis | what did this sample *do* when it was run, and where? | [providers/hybrid-analysis.md](providers/hybrid-analysis.md) |

Every one of them reaches the engine entirely through the Task 5 contract: the
registry finds it by capability with no vendor branch, and each passes the same
reusable adapter contract suite as the test fakes. Every one runs behind the
Task 6 executor, with no provider-shaped branch anywhere in that layer.

Some supply an assessment and some deliberately do not. GTI reports provider
verdicts and aggregated reputation; GreyNoise reports one scanner classification;
the three abuse.ch platforms each report one curated assertion per response.
urlscan's browser observations and Censys's exposure findings are context — an
open port or a served certificate says what a thing *is*, not whether it is
hostile — and the model enforces that rather than trusting each package to
remember it.

The three abuse.ch providers are one ecosystem, and the framework has to show it:
they share the `abuse_ch` credential group, so one stored Auth-Key serves all
three, and they share one `source_family`, so a future fusion layer can see that
two of them agreeing is not two independent corroborations. Each keeps its own
`lineage_group_id` so their claims remain distinguishable inside that family, and
anything they relay from elsewhere keeps its real origin — a VirusTotal ratio
relayed through URLhaus carries the same family a direct GTI result carries,
precisely so the two can never be counted twice.

MISP Warning Lists is the first provider with no transport at all. It reads a
pinned local dataset, needs no credential, and cannot make a request — which the
framework already accommodated: `requires_credentials = False` was supported
generically, so a local provider needed no execution change beyond one
provider-neutral cache-key field (`dataset_version`, so refreshing a dataset
invalidates answers derived from the old one).

It is also the only provider that never expresses an opinion. Every finding it
produces is `CONTEXT_ONLY`, because a warninglist match explains other evidence
rather than contradicting it: a cloud range hosts attacks, a popular domain has a
malicious path on it, and an EICAR hash is a test artifact. Deciding what a
malicious verdict plus shared-infrastructure context adds up to is false-positive
reasoning and belongs to the fusion layer.

Task 12 adds a layer rather than just a provider. `sandbox/` is the
provider-neutral vocabulary for dynamic analysis — sample, report, environment and
analysis quality as three separate identities — so a second sandbox writes a
reader and a descriptor instead of a data model. Two rules in it are worth
repeating here because they are false-positive rules rather than plumbing: **no
sandbox verdict maps to `SUPPORTS_BENIGN`**, because a sample may sit still for a
dozen reasons that say nothing about its intent; and **several reports from one
provider are one source**, because a well-studied hash must not outvote
independent intelligence by having been run more often. Report divergence across
environments is preserved rather than resolved.

The one deviation from the framework is documented and contained: GTI uses the
official `vt-py` SDK rather than the shared HTTP transport, and that SDK is
imported by exactly one module so its types never reach the core. Every other
remote provider uses the shared, host-pinned transport.

Note the data-use boundary recorded in the GTI document: GTI content must not be
exposed to Claude, MCP or any AI layer before the applicable provider terms are
reviewed.

## 12. Adaptive enrichment planning (Task 13)

The layer that decides **what to ask next**, sitting above the executor and below
the future fusion engine.

`AdaptiveEnrichmentPlanner` turns an observable, a depth and any explicitly
requested capabilities into one decision at a time: this provider, for this
capability, or stop with this reason. `AdaptiveEnrichmentOrchestrator` executes
each decision through Task 6, folds the outcome back into planning state, and
plans again — sequentially, so an answer can change what is worth asking next.

Four properties carry the design:

- **Capabilities, not vendors.** Goals name a `ProviderCapability`, never a
  provider. Exactly one module in `planning/` may name a provider — `catalog.py`,
  the shipped registry — and a test reads the AST of every other one to prove it.
- **Coverage per source family.** Three abuse.ch platforms answering is one family
  covered, and one sandbox's four environment reports are one family too. Novelty
  ranks a new *kind* of answer above a new family above the same family again.
- **Budgets charged on real calls.** `2/4/6` remote runs for QUICK/STANDARD/DEEP,
  charged on `ProviderExecutionOutcome.called_provider`. A cache hit, a coalesced
  request, an unconfigured credential and a local provider all cost nothing, which
  is what makes cache-first ranking safe.
- **Deterministic lexicographic ranking.** `RANKING_FACTORS` is the order, as
  data. No weighted score, because there is no evidence for any such constant and
  a made-up one cannot be explained to an analyst.
- **One provider answering several active goals is one call.** The capabilities a
  provider is currently an eligible candidate for travel in a single request, so a
  provider is never asked four times for one document. Elevated-cost capabilities
  are excluded from a bundle, and `capability_invariant_response` is what tells
  the planner whether asking again later is incremental work or a duplicate.

Two boundaries are structural rather than conventional. `EnrichmentPlanningRequest`
refuses a non-passive mode or a non-`LOOKUP` operation at construction, so no plan
that submits or detonates can be built; and a run enriches the requested
observable only, because recursive pivoting needs judgement and limits it does not
have.

Nothing here produces a verdict, a risk score or a confidence, and no
`StopReason` means the answer is known — `GOALS_SATISFIED` says the requested
coverage was *collected*. `NO_DATA` covers a source and never the observable, and
false-positive context never substitutes for threat intelligence.

Full detail: [planning/adaptive-enrichment.md](planning/adaptive-enrichment.md).

## 13. Correlation and controlled pivots (Task 14)

Above the planner and below the future fusion engine: what everything that came
back actually adds up to, structurally.

`CorrelationEngine` folds each provider result into an `InvestigationGraph` — in
memory, scoped to one user and one investigation, and never shared, because a
common correlation store would make one analyst's pivots visible in another's work
and leak *who is looking at what*. There is no graph database: the queries are
"neighbours" and "one hop", which a dict answers, and persistence can later be
PostgreSQL without changing any semantics here.

Four rules carry it:

- **Exact identity.** Nodes key on the Task 3 canonical key. Records merge when
  they are the same object — never on a shared ASN, /24, certificate issuer,
  malware family or fuzzy hash. Files use a conservative resolver: a shared
  SHA-256 merges, a weaker digest merges only when nothing stronger disagrees, and
  a contradicting stronger digest refuses the merge and files an issue.
- **Edges aggregate assertions.** Two providers claiming one relationship is one
  edge with two `RelationshipAssertion`s, each keeping transport, origin, source
  family, lineage, the provider's own field name and its own times. The edge key
  carries no provider, which is what makes them meet; inverse provider semantics
  are flipped onto one canonical orientation.
- **Derived is not observed.** The URL → host relationship TI Recon parses for
  itself is `ENGINE_DERIVED`, names no provider and no source family, and never
  counts as somebody having observed anything.
- **No inference.** A→B plus B→C never yields A→C, two samples contacting one
  address are not related, and no edge is ever created from a label.

Pivoting is a separate decision from discovery. `PivotMode` defaults to building
and recommending; remote enrichment needs both the root's `allow_remote_lookup`
and an explicit `allow_remote_pivot_lookup`, is capped per depth across the whole
session (0/0, 2/3, 5/8 targets/remote runs), runs one depth down, and stops one hop
from the root. Non-global addresses and URLs carrying userinfo or credential-shaped
parameters are graphed and never disclosed. Every pivot goes back through Task 13 —
Task 14 selects no providers, holds no credentials and performs no network access
of any kind.

Nothing here produces a verdict, confidence or risk score. A warninglist match
explains a node; it never deletes an edge.

Full detail: [correlation/investigation-graph.md](correlation/investigation-graph.md)
and [correlation/controlled-pivots.md](correlation/controlled-pivots.md).

## 14. Deferred architecture (Task 15+)

Documented so the shape is known; not implemented:

- Distributed execution state: Redis-backed cache, quota and cooldown stores,
  shared rate-limit state and cross-worker concurrency limits.
- Further provider adapters (SecurityTrails, AbuseIPDB, Shodan, IPinfo) alongside
  the nine integrated ones, and a MISP *instance* integration — which would share
  `source_family = "misp"` with the warninglists so it cannot read as an
  independent second source.
- A second sandbox provider (CAPE, Triage, ANY.RUN). The Task 12 framework is
  provider-neutral so one can be added without touching passive evidence
  semantics, and each would carry its own `source_family` — two independent
  sandboxes agreeing is genuine corroboration.
- Hunting and query interfaces the current adapters deliberately omit: GreyNoise
  GNQL, Censys CenQL search, ThreatFox family/tag queries, URLhaus feeds,
  MalwareBazaar YARA and certificate hunting, and every historical-timeline
  endpoint. These belong with the query planner rather than with a per-observable
  lookup.
- Evidence fusion and verdict scoring. Task 13 chose what to ask, Task 14
  recorded what came back and how it connects; deciding what the answers *mean* is
  the next layer, and it is the only one that may weigh a source, resolve a
  conflict or apply decay.
- Freshness and false-positive reasoning over the graph. Task 14 preserves
  per-assertion times and warninglist context without interpreting either — no
  age thresholds, no "still active", no benign verdict.
- Inference and similarity: transitive rules, ssdeep/TLSH/imphash clustering,
  CIDR and ASN grouping. If TI Recon ever infers, it will label inferred
  relationships as inferred, the way OpenCTI does, so an analyst can tell an
  observation from a conclusion.
- Multi-hop pivoting and a persistent, cross-investigation graph. Task 14 is one
  hop and one investigation.
- Planning *waves*: the orchestrator is sequential so each answer can inform the
  next decision. Bounded parallelism within one round is possible later, with
  real latency numbers rather than an assumption.
- Persistence (PostgreSQL), raw-response object storage, a durable backend for
  the artifact store (Task 8 ships an in-memory one), production secret vault.
- MCP server, Claude connector, TI Analyst Skill, web frontend.
- **Active** sandboxing. Task 12 implements the passive half of that
  distinction: Hybrid Analysis reads detonations that already happened and
  declares `FILE_BEHAVIOR`, which MalwareBazaar deliberately does not because
  relaying somebody else's sandbox output is not observing behaviour. Submission
  and detonation remain unimplemented and unstubbed — they need explicit analyst
  approval, a privacy warning about whichever platform receives the file, an
  entitlement check and environment selection, and inactive submission code is
  submission code waiting for someone to call it.
