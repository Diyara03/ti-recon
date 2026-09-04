# CLAUDE.md — TI Recon

Guidance for Claude Code sessions working in this repository.

## Purpose

TI Recon is an external **Threat Intelligence enrichment and analysis platform**.
An analyst submits an observable (IP, domain, URL, file hash); TI Recon queries
external TI providers, normalizes what they return into **evidence**, tracks
where each piece of evidence actually came from, and will eventually produce an
explainable assessment.

Target end-state pipeline:

```
Analyst -> Claude + TI Analyst Skill -> MCP -> TI Recon backend
       -> external providers -> normalized evidence
       -> correlation -> risk + confidence + coverage -> explainable verdict
```

## Current implementation boundary

Implemented (Jira Tasks 1-19):

- Task 1 — product scope + investigation workflow foundation (docs, enums)
- Task 2 — architecture foundation (docs, module boundaries)
- Task 3 — common TI data model (`models/`, `normalization/`)
- Task 4 — per-user provider credential foundation (`credentials/`)
- Task 5 — provider integration framework (`providers/`)
- Task 6 — provider execution controls (`execution/`): cache, retry/backoff,
  quota + cooldown, bounded concurrency, single-flight, executor, metrics
- Task 7 — Google Threat Intelligence (`providers/gti/`): the first live
  provider. Passive enrichment for IP/domain/URL/hash using each analyst's own
  VirusTotal API key, via the official `vt-py` SDK.
- Task 8 — urlscan.io (`providers/urlscan/`) plus a generic bounded artifact
  store (`artifacts/`): passive web intelligence from urlscan's historical
  scans, and — only on an explicit `WEB_FORENSICS` request at DEEP depth —
  retrieval and *static* analysis of stored screenshots, DOM snapshots and
  response bodies.
- Task 9 — GreyNoise (`providers/greynoise/`) and Censys (`providers/censys/`):
  passive internet-scanning context for IPv4, with per-credential resolution of
  full-context vs Community access; and passive exposure/infrastructure context
  for addresses and HTTP(S) URLs, by deterministic asset identity only.
- Task 10 — the three abuse.ch platforms, sharing `providers/abusech/`:
  ThreatFox (`providers/threatfox/`) for current family-attributed IOCs with
  loose address matches re-validated locally; URLhaus (`providers/urlhaus/`) for
  malware-distribution URLs, keeping exact-URL and host-level claims distinct;
  MalwareBazaar (`providers/malwarebazaar/`) for vetted samples by hash. One
  `abuse_ch` credential group, one `abuse_ch` source family, per-platform
  lineage groups, and every relayed third-party finding attributed to its real
  origin.
- Task 11 — MISP Warning Lists (`providers/misp_warninglists/`): **local,
  zero-network false-positive and infrastructure context** from a pinned CC0
  snapshot of the community dataset. No MISP server, no API key, no transport,
  no credential. Every hit is `CONTEXT_ONLY`; `matching_attributes` gates every
  list; a URL's host stays visibly separate from the URL; profiles bound the
  dataset and every omission is reported.

- Task 12 — sandbox intelligence framework (`sandbox/`) plus Hybrid Analysis
  (`providers/hybrid_analysis/`): the first **dynamic-analysis** source, behind a
  provider-neutral vocabulary for sample/report/environment. Strictly passive —
  it finds detonations that already happened, and nothing submits, detonates or
  downloads. One directional finding per sample; no verdict maps to
  `SUPPORTS_BENIGN`; report divergence across environments is preserved.

- Task 13 — adaptive enrichment planner and orchestrator (`planning/`): decides
  **what to ask next**. Capability goals per observable type per depth, coverage
  tracked per *source family*, per-depth budgets charged on
  `called_provider`, deterministic lexicographic ranking, activation rules for
  expensive follow-ups, and operational stop reasons only. The orchestrator loops
  plan -> execute (Task 6) -> observe -> re-plan, sequentially, over the requested
  observable alone. Not the fusion layer: no verdict, risk score or confidence.

- Task 14 — correlation graph, relationship lineage and controlled pivots
  (`correlation/`): assembles what providers returned into one investigation
  graph. Exact identity only (a conservative file-hash resolver, conflicts
  refused and reported), semantic edges that aggregate `RelationshipAssertion`s
  keeping transport/origin/family/lineage, canonical orientation so inverse
  provider semantics meet, one `ENGINE_DERIVED` structural relationship
  (URL → host, parsed), per-assertion times, and bounded pivot selection whose
  execution goes back through Task 13. No verdict, no inference, no similarity.

- Task 15 — temporal evidence qualification and context reasoning
  (`reasoning/`): says **what a finding means in time and context**, never what
  the case is. Typed instants (`TemporalFactKind`) so a scan time can never
  become an observation, an explicit timezone-aware `as_of` with no wall clock
  anywhere, exact ages and no decay model, source-stated lifecycle,
  `ContextSignal`s from a versioned exact-slug warninglist mapping plus provider
  facts, `InterpretationCue`s from data-driven rules over structured inputs, and
  two temporal issues. Provider field semantics stay in each provider's own
  `qualification.py`; the evaluator names no vendor. No verdict, no confidence,
  no risk score, no evidence weight, no false-positive flag, no network.

- Task 16 — deterministic false-positive and alternative-explanation reasoning
  (`reasoning/false_positive/`): asks whether Task 15's context legitimately
  **explains a specific piece of evidence**, and what the explanation does not
  cover. Seven roles, seven dimensions, fifteen reason codes and fifteen
  versioned rules; typed `FindingLink`s so every finding names what it concerns;
  content-derived finding ids; explicit `DoesNotEstablish` boundaries. Only two
  context types can explain an object and only at exact scope. No verdict, no
  confidence, no false-positive boolean, no provider names anywhere, no network.

- Task 17 — provider-neutral claim semantics, evidence fusion and final
  assessment (`reasoning/claims/`, `reasoning/fusion/`): the first layer allowed
  to reach a verdict. Twelve `ClaimSemantic`s translated by provider-owned
  modules, so a scanner classification and a C2 indicator are different
  propositions — the Task 16 deferral, resolved. Independence by originating
  source family, corroboration only across compatible propositions, Task 16
  `EXPLAINS` links the only thing that removes support, eight verdict rules and
  seven confidence rules. No score, no weight, no probability, no risk number, no
  provider votes, no action recommendation, no network.

- Task 18 — assessment readiness and coverage adequacy (`reasoning/readiness/`):
  asks whether the *collection* behind Task 17's assessment was adequate for
  external-TI analyst triage, and what is still missing. Two orthogonal axes
  (`CoverageAdequacy`, `ContinuationState`) with a derived `ReadinessStatus`;
  completion separated from informational yield so `NO_DATA` can never be
  confused with `NOT_RUN`; requirements taken from Task 13's own capability
  goals; materiality judged from Task 17's verdict rule. No verdict change, no
  confidence change, no enrichment, no score, no severity, no action.

- Task 19 — end-to-end investigation orchestration (`investigation/`): composes
  Tasks 13-18 into one bounded, reproducible workflow. Collect through Task 13
  and Task 14, analyse through Tasks 15-18, and continue only when Task 18 says
  coverage is inadequate *and* a path remains. Budgets, depth, pivot mode and the
  set of calls already made are investigation-wide; continuation directives name
  capabilities and Task 13 chooses the provider. No transport, no persistence, no
  action.

- Task 20 — stable analyst output contract and CLI (`application/`,
  `reporting/`, `cli/`): the first application-facing interface. A public
  request that names an observable and two ceilings, a versioned
  `AnalystInvestigationReport` derived deterministically from
  `InvestigationResult`, deterministic text and JSON renderings, a generated
  JSON Schema, and a `ti-recon` console command over the same service a future
  MCP server will call. Presentation only: it selects, orders, labels and
  bounds what Tasks 13-19 decided, and decides nothing itself.

- Task 21 — local MCP server (`mcp_server/`) and the analyst Skill
  (`.claude/skills/ti-recon-analyst/`): the Task 20 application over the Model
  Context Protocol, stdio only. Three tools (`investigate_observable`,
  `investigate_file`, `provider_status`), the analyst report as structured
  output derived from the Task 20 model, and the two public schemas as
  resources. Capability only: no reasoning, no provider selection, no credential
  input, no active operation.

- Task 22 — the authenticated remote MCP surface (`mcp_server/`), complete and
  merged; an optional deployment path beside the primary local one.
  TI Recon is an OAuth **resource server**: a deployment's own `TokenVerifier`
  proves a token and `StrictTokenVerifier` enforces the invariants the SDK does
  not — non-empty subject, exact issuer, and an audience naming this MCP
  resource. Identity below the boundary is one pseudonymous `tenant-v1:` HMAC
  over the validated issuer and subject; `ExecutionContext` is request-scoped and
  `provider_status` principal-scoped, over one shared application.
  `build_remote_http_app` produces an OAuth-protected Streamable HTTP ASGI app
  behind a `RemoteHttpApp` preflight gate — Host, Origin and POST content type
  are checked, and `/health` answered, before the SDK's authentication
  middleware is entered — with `stateless_http`, a two-tool surface without
  `investigate_file`, both schema resources and one concurrent investigation per
  tenant. `JwtJwksTokenVerifier` is the production delegate — asymmetric
  signature verification against an authorization server's published JWKS, exact
  issuer and audience, bounded and cached key retrieval — and
  `ti-recon-mcp-http` runs the whole thing on one worker from
  `TI_RECON`-prefixed environment configuration. **Nothing is deployed and no
  identity provider has been contacted**; a staging OAuth acceptance test is the
  next phase.

- Task 23 (in progress) — the local Claude Code plugin (`plugins/ti-recon/`).
  The primary usage model is Claude Enterprise → Claude Code on each analyst
  workstation → the plugin → the local stdio `ti-recon-mcp` → that analyst's
  own provider credentials, with **no shared deployment**. Phase 1 proved the
  host mechanics; Phase 2 made the plugin self-contained: `.mcp.json` starts
  the server directly through `uv run --project ${CLAUDE_PLUGIN_ROOT}/runtime
  --locked --no-dev --no-editable --no-env-file --python 3.12 ti-recon-mcp`,
  with the environment under `${CLAUDE_PLUGIN_DATA}/runtime-env`
  (`UV_PROJECT_ENVIRONMENT`). `runtime/` is a byte-identical, generated copy of
  the project — `pyproject.toml`, `uv.lock`, `README.md`, `src/ti_recon/` and a
  derived `.python-version` — kept by `tools/sync_plugin_runtime.py`; the Skill
  copy is kept by `tools/sync_plugin_skill.py`. `userConfig` declares one
  optional `sensitive` option per credential group plus the non-secret Censys
  organization id, substituted by the host into the server's environment where
  the existing loader already reads them; `TI_RECON_CREDENTIAL_SETUP` selects a
  `LocalCredentialSetup` so the server states the plugin's setup step. The only
  workstation prerequisites are Claude Code and `uv`. Proved installed from a
  disposable local marketplace on Linux x86-64; Windows and macOS are resolved
  statically only. The internal marketplace, an Enterprise pilot and the
  `ti-recon[remote]` dependency split are later phases. See
  `docs/claude-plugin.md`.

**GTI, urlscan, GreyNoise, Censys, ThreatFox, URLhaus, MalwareBazaar, MISP
Warning Lists and Hybrid Analysis are the only providers.** Task 13 chooses what
to ask, Task 14 assembles what came back, Task 15 says what each finding means in
time and context, Task 16 says which findings context explains, and Task 17
decides what assessment is justified — while deciding nothing about what to *do*
about it.

**Not implemented — do not add without an explicit request:**

- Any other provider API integration (SecurityTrails, AbuseIPDB, Shodan, IPinfo)
- Any MISP *instance* integration: events, attributes, galaxies, taxonomies,
  sightings, the MISP REST API, PyMISP. Task 11 reads a local warninglist
  snapshot and nothing else; a future instance provider shares
  `source_family = "misp"` so it cannot read as a second independent source
- Regex matching of warninglists, and any claim of PCRE compatibility; automatic
  warninglist dataset refresh from a lookup or at startup
- Any **active** sandbox operation: file or URL submission, detonation, rescan,
  quick scan, `overview/{sha256}/refresh`, and every download (sample, dropped
  file, PCAP, memory dump, screenshot, report archive). Task 12 implements the
  passive half only. Do not add inactive submission code "for later": a future
  active path needs explicit analyst approval, a privacy warning about a
  community platform that may retain and redistribute what it receives, an
  entitlement check and environment selection.
- Hybrid Analysis host/domain/URL search, YARA hunting, advanced search, feeds,
  file collections, `GET /overview/*`, and the deprecated `POST /search/hash`
  and `POST /report/summary`
- A second sandbox provider (CAPE, Triage, ANY.RUN). `sandbox/` is
  provider-neutral so one can be added without changing passive evidence
  semantics, but each would carry its own `source_family`.
- MalwareBazaar still relays sandbox output and therefore deliberately does
  *not* declare `FILE_BEHAVIOR` — relaying is not observing. Hybrid Analysis is
  the direct integration that capability was reserved for.
- Any abuse.ch write or bulk operation: `submit_ioc`, URL submission, rescan,
  `get_file`, `upload`, `update`, `add_comment`, `get_recent`, every feed, and
  ThreatFox/MalwareBazaar tag, family, signature, YARA and certificate hunting
- GreyNoise GNQL and every hunting, timeline, bulk-lookup, feed, PCAP or session
  endpoint; every deprecated GreyNoise v2 endpoint
- Censys CenQL and `POST /v3/global/search/query`, historical timelines,
  `at_time` enumeration, collections, Adversary Investigation, live rescan and
  live discovery
- GTI Intelligence Search, Threat Profiles, Threat Lists, IOC Streams, DTM, ASM
- Any active GTI operation: submission, rescan, sandbox detonation, downloads
- Any active urlscan operation: scan submission (`POST /api/v1/scan`), rescan,
  live scan, liveshot, sample download (`/downloads/`), visibility changes,
  deletion, saved searches, incidents
- urlscan paging beyond the first search page, Brand/Kit monitoring, hostname
  and similarity APIs
- Evidence fusion, conflict resolution, decay and verdict scoring. Tasks 13-15
  stop at coverage, correlation and qualification; weighing sources belongs to
  the next layer, the only one allowed to weigh a source or resolve a conflict
- Any universal decay model — `score *= exp(-age)`, `decay_score`,
  `evidence_weight`, `confidence -= N`, "older than 30 days is stale". A phishing
  URL, a malware hash, a cloud address, a scanner range, a certificate and a
  sandbox report do not share a lifetime, and MISP itself maintains separate
  decay models per use case. Task 15 preserves exact ages and source-managed
  lifecycle; numerical weighting is deferred
- Organisational readiness profiles beyond external-TI analyst triage. Task 18
  answers for one purpose only; readiness for containment, alert closure or
  incident declaration depends on asset criticality, business impact, user
  context, internal telemetry and incident policy that TI Recon has no access to
- REST API, web or desktop UI, streaming progress, HTML/PDF/Markdown export, and
  any LLM-written analyst narrative. Task 20 adds a CLI and a transport-neutral
  application service; Task 21 consumes that service rather than parsing its text
- Persistence, cross-process resume, job queues and durable idempotency. Task 19
  continues *within one invocation* and claims nothing beyond it
- Any remediation or containment action: blocking, quarantine, isolation, alert
  suppression, ticket closure, allowlisting. A MALICIOUS verdict on shared or
  compromised infrastructure can make blocking actively harmful, and Task 17
  assesses the observable rather than prescribing what to do
- Any numerical fusion: `malicious_score`, `benign_score`, `risk_score`,
  `probability`, `evidence_weight`, a weighted sum, Bayesian or Dempster-Shafer
  combination. There is no calibration data behind any coefficient, so a formula
  would manufacture precision that cannot be explained or defended
- A graph-derived malicious claim. Controlled one-hop promotion (a root file
  dropping a known-malware child) was designed and deferred: the shipped
  relationship vocabulary cannot cleanly separate a dropped artifact from a
  contacted host, and a wrong promotion rule would attribute a child's verdict to
  its parent. `resolves-to` must never propagate maliciousness at all
- Admiralty source-reliability and information-credibility weighting. The fields
  exist on `Evidence` and no provider populates them, so v1 fusion leaves them
  unused rather than inventing per-provider ratings
- A false-positive *rule* based on a low AV detection count, a valid code
  signature, or popularity. None of the three is evidence a detection was wrong,
  and the repository preserves no structured goodware indicator that would make a
  low count meaningful. Regression tests assert each explains nothing
- A Task 16 alternative explanation from scanner context. Scanner context could
  explain a scanning-reputation claim, but a scanner classification and a
  botnet-C2 indicator are both `CURATED_THREAT_ASSERTION` + `SUPPORTS_MALICIOUS`,
  and the only field separating them is a provider-prefixed `claim_type` the
  generic engine may not read. Deferred pending a generic claim-kind seam
- Re-enrichment triggered from a qualification. "This evidence is old" must not
  become an automatic provider call: Task 15 performs zero I/O, and orchestrating
  a refresh is a caller's decision made with Task 13
- Semantic categories for warninglists taken from any *other* MISP project or
  runtime database. The pinned CC0 schema has no authoritative category field;
  TI Recon's mapping is engine policy, versioned, keyed on exact slugs
- Regex, substring or name-based classification of warninglists, provider
  descriptions, tags or any provider prose anywhere in `reasoning/`
- Any graph database (Neo4j, JanusGraph, ArangoDB, RedisGraph) or a global,
  cross-investigation, cross-user intelligence graph. The graph is in-memory and
  scoped to one investigation
- Transitive or rule-based inference in the graph, similarity/fuzzy correlation
  (ssdeep, TLSH, imphash, CIDR, ASN clustering), freshness or false-positive
  reasoning, threat-actor attribution and campaign clustering
- Automatic pivot enrichment beyond one hop, or any pivot that resolves DNS,
  fetches a URL, opens a socket or downloads a file
- Any planner-side retry, waiting or transport. Task 6 owns retry, backoff,
  cooldown and cache; a planner-side retry would multiply a policy it cannot see
- Recursive enrichment of related objects inside a *Task 13* plan. A plan enriches
  the requested observable only; pivoting is Task 14's, is explicit, and is
  bounded by a shared budget and one hop
- Parallel provider fan-out inside one planning round ("waves"). The orchestrator
  is sequential so each answer can inform the next decision; changing that needs
  real latency data, not an assumption
- Any LLM, Claude call or external ranking service inside the planner. AI clients
  will call TI Recon; AI must not choose which intelligence sources TI Recon
  queries internally
- A `StopReason`, `SkipReason` or `SelectionReason` that asserts knowledge —
  `CONFIDENCE_HIGH_ENOUGH`, `VERDICT_CONFIRMED`, `DEFINITELY_MALICIOUS`,
  `DEFINITELY_BENIGN`. Every reason is operational
- A weighted provider score (`priority * 0.4 - cost * 0.2`, ...). Ranking is
  lexicographic over `RANKING_FACTORS` and stays that way
- Provider names anywhere under `planning/` except `catalog.py`
- Redis or any distributed coordination: every execution store, and the artifact
  store, is in-memory and single-process
- PostgreSQL, production secret vault, Kafka, Celery, Neo4j
- Claude connector, web frontend
- Active actions: URL/file submission, rescan, sandboxing, sample download
- A `--workers` option, `WEB_CONCURRENCY`, a second ASGI server, a `/ready`
  route, and any deployed service. Remote TI Recon is single-worker until Task 24
  gives Task 6's process-local state a shared backend
- A vendor-specific `TokenVerifier` (Entra, Auth0, Okta, Keycloak, Cognito) or a
  vendor settings class. `JwtJwksTokenVerifier` is configured with an issuer, a
  JWKS URL, a resource and an algorithm allowlist, and contains no provider name
- An RFC 7662 introspection verifier, OIDC discovery, and a permissive or
  "development" verifier of any kind. The delegate seam stays open for a future
  introspection implementation; what must never exist is a static-token verifier,
  an unsigned-JWT verifier, or anything reachable from production that decodes
  without proving a signature
- Any authorization server inside TI Recon: a user/password database, a login
  page, password reset, MFA, client registration (DCR or CIMD), token issuance.
  TI Recon verifies tokens an external IdP issued and never becomes a login
  system. The code stays vendor-neutral: no IdP is named as a requirement
- Persistent or encrypted credential storage, an out-of-band provisioning API,
  rotation, revocation and audit events. Those are Task 23, and none of them is
  ever an MCP tool — `set_api_key` would put a provider secret through a model
  prompt, into tool arguments and into a conversation transcript
- Tenant-key rotation or migration, and any second identity scheme beside
  `tenant-v1:`
- A `ti-recon[remote]` extra, an internal plugin marketplace, a release tag
  flow, a self-contained signed executable, and any plugin hook, agent,
  command or launcher script. The plugin starts the server through `uv`
  directly; a shell launcher would need a shell, and a top-level `bin/` is
  rejected by organization-managed distribution
- A plugin-specific credential store, loader or repository; a `set_api_key`
  tool; any `${user_config.*}` reference in Skill content; any runtime state
  written under `${CLAUDE_PLUGIN_ROOT}`; any `.env` read by the plugin's server

## Architectural invariants

1. **Core engine is Claude-independent.** Nothing under `src/ti_recon` may
   import or assume Claude, MCP, or any LLM. The Skill and MCP layer sit
   *above* TI Recon and are separate future components.
2. **Provider independence.** Every provider is optional. Code asks
   "what intelligence *capability* do I need?" — never "which vendor must I
   call?". No vendor-specific `if` statements in engine or registry code.
3. **Evidence, not votes.** Never count providers ("3 malicious vs 2 benign").
   Providers contribute evidence of differing class, specificity and strength.
4. **Facts vs interpretation vs assessment are separate layers.** Provider
   observations (`Evidence`) are immutable inputs; engine interpretation lives
   in `AssessmentContribution`; the conclusion lives in `Assessment`. Engine
   interpretation must never overwrite a provider fact.
5. **Source lineage is mandatory.** Every `Evidence` carries
   `transport_provider`, `origin_provider`, `source_family` and a
   `lineage_group_id`. If Censys relays GreyNoise-derived data, transport is
   `censys` and origin is `greynoise` — so it is never mistaken for
   independent confirmation.
6. **Passive by default.** `ActivityMode.PASSIVE` is the default. Active
   operations are a separate, explicitly-approved path and are not implemented.
7. **Confidence signals stay separate.** `provider_confidence`,
   `source_reliability` (Admiralty A-F) and `information_credibility` (1-6) are
   never collapsed into one number at the evidence layer.
8. **Adapters never decide verdicts.** A provider adapter normalizes and
   classifies; it must not emit a verdict or risk score.
9. **Unsupported operations are explicit.** Optional adapter operations raise
   `UnsupportedProviderOperation`, never bare `NotImplementedError`.
10. **Execution decides how, not what.** `execution/` runs a *selected*
    provider safely. It never chooses a provider (planner, later task) and never
    computes a verdict, risk score or confidence.
11. **Execution reacts to normalized categories, not HTTP.** Retry, cooldown and
    quota decisions read `ProviderErrorCategory`. No `if status_code == 403`
    outside an adapter. Where a category is too coarse — a credential a provider
    has refused outright is a `PERMISSION_ERROR`, and so is one unentitled
    endpoint — the adapter supplies a *duration*
    (`credential_cooldown_hint_seconds`), never a reason. A provider condition
    named to `execution/` would be a vocabulary it must not learn.
12. **Execution state is user-isolated by construction.** Cache, quota,
    cooldowns, concurrency slots and request coalescing are all keyed by
    `ExecutionScope`, whose identity is built from ids only.
13. **A provider SDK stays inside its own package.** `vt-py` is imported only by
    `providers/gti/` — the client for `vt.Client`/`vt.Object`/`vt.url_id`, and
    `errors.py` for the `APIError` type alone. Its types never reach the
    normalizer, the adapter or the core. Any future SDK exception must be
    equally contained.
14. **`UNDETECTED` is not benign, and engine counts are not votes.** A provider
    reporting "nothing flagged it" is context, never evidence of safety, and an
    aggregate of other vendors' opinions is one source rather than many. A
    provider's own roll-up over its sub-verdicts (urlscan's `verdicts.overall`)
    is not normalized either — emitting it alongside its components counts one
    opinion twice.
15. **Expensive, content-pulling operations need an explicit request.** Web
    forensics runs only when the depth is `DEEP` *and* `WEB_FORENSICS` was
    requested, checked in one place. Neither half alone is consent.
16. **Retrieved content is never executed and never parsed for its secrets.**
    Static analysis only — no `eval`, no renderer, no subprocess. Credentials
    found inside page content are recorded by type and count; the value is
    discarded where it is matched.
17. **A provider gets one opinion per response, not one per field.** GreyNoise's
    scanner classification is its assessment; its tags, CVE associations, sensor
    detail and Business Services Intelligence are context, and every one of them
    shares a lineage group with the classification. Censys produces no
    assessment at all — exposure is not an accusation, so every piece of Censys
    evidence is `CONTEXT_ONLY`, and most is `EvidenceClass.CONTEXT` so the model
    refuses to attach a direction.
18. **`suspicious` is not `malicious`, and absence is not benign.** A coarse
    `EvidenceEffect` records direction rather than strength, so a provider's raw
    wording is always preserved alongside it. `noise: false`, `riot: false`,
    `found: false`, a 404 and "Censys has never scanned this" are coverage facts:
    an address that has not touched a sensor fleet, or an asset a scanner has not
    reached, is not thereby safe.
19. **An entitlement is discovered from a response, never inferred from a status
    code.** A `401` is a rejected credential and must never be reinterpreted as a
    free-tier plan, or a revoked key looks like a working one. Only a `403` may
    earn a single fallback attempt, and only a real answer to that attempt sets a
    remembered access level — which is scoped per user and connection, like every
    other execution store.
20. **Depth never buys more provider requests than the question needs.** For
    providers answering one observable with one deterministic read, depth selects
    an endpoint variant and how much of the *already-returned* document is
    normalized. It never adds a request, widens a search, or changes which way
    evidence points.
21. **A cost-metered provider is asked about identities it can derive, never
    about guesses.** A Censys web property is `hostname:port`; a bare domain
    names no port, so it is reported `NOT_SUPPORTED` rather than answered by
    querying two ports and presenting that as domain coverage.
22. **One ecosystem is one source family.** ThreatFox, URLhaus and MalwareBazaar
    are three datasets run by one organization and share `source_family =
    "abuse_ch"`, so two of them agreeing can never read as two independent
    corroborations. Each keeps its own `lineage_group_id` so their claims stay
    distinguishable within that family.
23. **A relayed finding keeps the origin *and the family* of whoever produced
    it.** A VirusTotal ratio relayed through URLhaus carries
    `origin_provider = "virustotal"` and the same `source_family` a direct GTI
    result carries, precisely so relayed and direct cannot be counted twice. An
    aggregate of other people's opinions — a blocklist sweep, a `vendor_intel`
    block — is *one* record naming who had something, never one per contributor,
    and always `EvidenceClass.CONTEXT` so the model refuses it a direction.
24. **A loose match from a provider we do not control is re-validated locally, by
    parsing.** ThreatFox stores addresses as `ip:port`, so a bare address must be
    searched loosely — and a loose search returns `11.2.3.45:443` for `1.2.3.4`.
    The host part is parsed off and compared for *equality*; containment is never
    a match, and what was discarded is published in the coverage evidence.
    `providers/threatfox/matching.py` contains no `in`, no `startswith`/`find`/
    `search`, and no regex, and a test asserts that.
25. **Where an API's parameters travel in a body, passivity is a property of an
    allow-list, not of the HTTP verb.** The abuse.ch APIs are read by POST —
    ThreatFox with a JSON body, URLhaus and MalwareBazaar with form data — so
    "this integration never calls `post`" is unavailable as a proof and must not
    be claimed. The encoding is fixed per platform on the shared client and
    every safety check runs before it is chosen, so JSON is a serialization
    choice rather than a second route in. Each client hands the shared transport
    a frozen set of permitted queries or paths, checked before a request is
    built: `submit_ioc`, `get_file`, `upload`, `add_comment` and every feed are
    unreachable rather than merely unused.
26. **Provider-relayed and community-authored text never becomes evidence.**
    MalwareBazaar comments contribute a count, never their text; an archive
    password, uploader identity and uploader country are not stored at all;
    `vendor_intel` values — which can be entire HTML reports — are never read,
    only their keys. `EXCLUDED_FIELDS` is data with a reason per field so a test
    can assert it.
27. **Presence in a sample archive is provenance, not a direction.** A URLhaus
    payload record says a tracked URL served this file, which a URL that now
    serves an installer or an error page also does; it stays `CONTEXT_ONLY` even
    when a family signature is present. And an expiring feed's silence is a
    coverage fact: ThreatFox drops IOCs after ~6 months, so a miss means "nothing
    unexpired matched" and records that horizon explicitly.
28. **A warninglist match is context, never a verdict — in either direction.**
    Every MISP warninglist hit is `EvidenceClass.CONTEXT` with
    `EvidenceEffect.CONTEXT_ONLY`. Never `SUPPORTS_BENIGN` and never
    `SUPPORTS_MALICIOUS`: a cloud range hosts attacks, a CDN serves malware, a
    popular domain has a malicious path on it, an EICAR hash is a test artifact
    rather than an ordinary benign file, and a warninglist can be stale. A clean
    lookup means "no selected list in this snapshot matched" and nothing else —
    the record says `means_benign: false` rather than leaving it to be inferred.
    What a malicious verdict plus shared-infrastructure context adds up to is
    false-positive reasoning and belongs to the fusion layer.
29. **`matching_attributes` is authoritative, and candidates are never
    fabricated.** An observable is turned into the MISP attribute values it
    legitimately *is*, and a list is offered only the candidates whose attribute
    type it declares — a hostname list is never asked about an MD5. No
    `domain|ip` for a bare domain, no `ip-src|port` for a portless address, no
    `filename|md5` without a real filename. An absent `matching_attributes`
    means ALL. Every hash a file carries is checked, because a local lookup
    spends nothing and the false-positive lists differ in which they hold.
30. **A URL's host is not the URL.** A derived hostname candidate is
    `MatchScope.SAME_HOST`, tagged `url_host`, and flagged
    `host_component_only`; the full URL is `EXACT_OBSERVABLE`. The host is
    *parsed*, never searched for, so a path or query string cannot masquerade as
    one. Losing that distinction is how a living-off-trusted-sites payload gets
    waved through.
31. **Upstream data is honoured, not repaired.** A leading dot in a `hostname`
    entry means "subdomains only" and is preserved; the same dot in an exact
    `string` list can never match a canonical domain and is counted
    `unmatchable` rather than rewritten. Malformed CIDRs and blank entries are
    skipped and diagnosed. One bad list costs one list, never the dataset.
32. **A local dataset is pinned, provenanced, packaged, and refreshed only by an
    operator.** The snapshot lives inside the package at
    `src/ti_recon/data/misp_warninglists` and is resolved with
    `importlib.resources`, never from repository layout — a default derived from
    `parents[N]` gave a checkout and an installed wheel different behaviour, and
    the wheel's default pointed at a directory that never existed. The packaged
    copy is an immutable baseline; `update_misp_warninglists.py` refuses to write
    into `site-packages`, and an operator's explicit `snapshot_root` always wins.
    No lookup may fetch, clone, resolve or update anything; refresh is
    `tools/update_misp_warninglists.py` against a *local checkout*, never a URL,
    and it swaps atomically. Coverage carries the upstream commit, the dataset
    and profile fingerprints, and both kinds of omission — lists the snapshot
    never had and lists the profile excluded — so no result can imply "all MISP
    warninglists checked".
33. **Depth never changes which warninglists are checked.** Unlike a metered
    remote provider there is nothing to spend, so every depth searches the same
    lists and depth bounds only how many match records are rendered. Coverage
    that varied by depth would mean an analyst had to know which depth ran to
    know what "no match" covered.

34. **A sandbox report is an observation, not a verdict — and a sandbox that saw
    nothing did not see safety.** No entry in `SANDBOX_VERDICT_EFFECT` maps to
    `SUPPORTS_BENIGN`: `malicious` and `suspicious` point at malicious, while
    `no specific threat`, `no verdict` and `whitelisted` are `CONTEXT_ONLY`. A
    sample may sit still because the OS was wrong, it wanted a click, its C2 was
    down, it was geofenced, or it noticed it was being watched — so a
    non-detection must never earn exoneration. `SandboxAnalysisQuality` (state,
    runtime, process and connection totals, network mode, warnings,
    `observed_execution`) is what lets a later layer tell "nothing happened" from
    "nothing could have happened".
35. **Report state is not report verdict.** A run that errored has no
    behavioural content, so only *completed* runs contribute a verdict or become
    selection candidates — providers do emit `malicious` on failed reports, and
    letting one through turns an infrastructure failure into an opinion.
36. **Several reports from one sandbox are one source.** A hash detonated on
    Windows 7, 10 and 11 is one provider observing one sample; it becomes one
    directional finding sharing a sample-level lineage group, with behaviour
    records `CONTEXT_ONLY` even when full of malicious signatures. Hundreds of
    signatures and dozens of ATT&CK techniques from one run are bounded
    attributes, never findings. `source_family` is per sandbox, not a generic
    `"sandbox"`: two *independent* sandboxes agreeing is real corroboration.
37. **Report divergence is preserved, not resolved.** Malicious on Windows 11
    beside nothing on Windows 7 is environment-dependent malware describing
    itself, recorded as `verdicts_by_environment` and `divergent_verdicts`.
    `EvidenceConflict` relates two *pieces of evidence* and therefore does not
    fit a provider that deliberately emits one.
38. **Depth may buy requests only where the provider policy says so, and never
    unboundedly.** Hybrid Analysis is the one provider whose depth changes the
    physical request count — 1/2/3 for QUICK/STANDARD/DEEP — capped by
    `MAX_SUMMARIES_PER_LOOKUP`. Which reports are read is deterministic
    (strongest completed verdict, then a *contrasting* one) and recency is never
    claimed, because a hash search carries no analysis timestamp.

39. **The planner asks what is missing, never who has not been called.** A goal
    names a `ProviderCapability`; a provider being added, removed, renamed,
    unconfigured or denied changes who answers it and never whether the goal
    exists. `catalog.py` is the only module under `planning/` that may name a
    provider, and a test reads the AST of every other one to prove it. A goal no
    registered provider can serve for this observable is dropped rather than
    carried, because a permanently unsatisfiable goal reports a catalogue blind
    spot as a provider failure.

40. **Coverage is counted per source family, and satisfaction is not knowledge.**
    Three abuse.ch platforms answering is one family; one provider's twenty
    evidence records are one family; one sandbox's four environment reports are
    one family. Every `StopReason` is operational, `GOALS_SATISFIED` means the
    requested coverage was *collected*, and there is deliberately no reason
    meaning "confident enough". `NO_DATA` covers a source and never the
    observable, `PARTIAL` satisfies no family target, and false-positive context
    never substitutes for threat intelligence — a warninglist match explains
    evidence rather than replacing the need for any.

41. **Locality is declared, never inferred from credentials.** A credential-free
    HTTP API still discloses the observable to a third party, so
    `requires_credentials == False` must never be read as `LOCAL`.
    `allow_remote_lookup = False` is a disclosure control rather than a cost
    control, and a run under it stops with `REMOTE_LOOKUPS_DISABLED` rather than
    implying it finished.

42. **The remote budget is charged on `called_provider`, not on decisions.** A
    cache hit, a coalesced request, a cooldown short-circuit, an unconfigured
    credential and every local provider cost nothing — which is what makes
    cache-first ranking safe. A caller may lower a budget and never raise it;
    `max_remote_provider_runs` is reduction-only. `elevated_cost_capabilities`
    exists because one cost class per provider cannot describe a provider that is
    cheap for a summary and expensive for retrieved content.

43. **Ranking is lexicographic over `RANKING_FACTORS` and never a weighted
    score.** There is no evidence for any such constant, and a made-up one looks
    principled, cannot be explained to an analyst, and shifts unpredictably when a
    provider is added. Every decision must be explainable by naming the first
    factor that separated two candidates, and identical inputs must produce
    identical plans regardless of registration order.

44. **The planner selects and observes; Task 6 executes.** No I/O, no credential
    resolution, no cache read, no adapter client and no retry — a planner-side
    retry would silently multiply a policy it cannot see, so a provider that
    returned a blocking category is simply not chosen again for that run. Nothing
    under `planning/` may import `httpx`, the credential layer or `SecretStr`.

45. **One provider answering several active goals is one call.** A provider that
    serves four active capabilities is asked once, for all four: a request per
    capability spends a budget unit and a real API call per goal and returns the
    same document each time, and Task 6 cannot absorb it because
    `requested_capabilities` is part of the cache key. Only *current candidates*
    are bundled, so a bundle can never widen depth or activate a waiting goal, and
    an `elevated_cost_capabilities` member is never bundled — it must win a
    decision of its own, or a bundle becomes a way to spend the high-cost budget
    and to reach web forensics without an explicit request.
    `capability_invariant_response` is the provider's own statement that one read
    returns its whole document; it alone lets coverage be credited for a
    capability the request did not name, and where it is `False` — GTI, urlscan,
    whose responses are shaped by the requested set — a later call for another
    capability is genuine incremental work and is charged as such.

46. **An automatic plan is passive, and covers one observable.**
    `EnrichmentPlanningRequest` refuses a non-passive mode or a non-`LOOKUP`
    operation at construction, so no plan that submits, detonates or rescans can
    be built; a test additionally asserts every `ProviderOperation` and
    `ActivityMode` name written anywhere in the package is the passive one. A run
    enriches the requested observable only — the related objects providers return
    are never planned. And no LLM is in the loop: AI clients will call TI Recon,
    but must not choose which intelligence sources it queries internally, or
    provider selection stops being reproducible.

47. **Correlation merges exact observable identity, never similarity.** A shared
    ASN, /24, certificate issuer, page title, favicon, ssdeep, TLSH, imphash,
    malware family, YARA rule or tag is an analytic signal and none of them is
    identity. A file merges on a shared SHA-256; on a shared SHA-1 or MD5 only
    when nothing stronger disagrees, recorded as a weaker basis; and a
    contradicting stronger digest refuses the merge and files a
    `FILE_HASH_CONFLICT` rather than fusing two samples and cross-attributing
    their behaviour. A held digest is never overwritten.

48. **A graph edge aggregates assertions, and every assertion keeps its
    provenance.** Two providers claiming one relationship is one edge with two
    `RelationshipAssertion`s; the edge key carries no provider, which is what
    makes them meet. Assertion deduplication is by
    `(basis, source_family, lineage_group_id, origin_provider, raw type)`, so one
    provider rendering the same claim in evidence, related objects and a summary
    is one assertion rather than three corroborations — while two genuinely
    different claims about the same pair both survive. `raw_relationship_type` is
    kept because the canonical mapping is a judgement someone will want to argue
    with.

49. **Same-family assertions never become independent sources.** ThreatFox and
    URLhaus agreeing is `('abuse_ch',)`. `asserting_source_families` is
    informational, is never turned into a number, and is deliberately excluded
    from pivot ranking — ranking on it is the first step to "two providers agreed,
    therefore malicious". A relayed finding keeps the origin that produced it.

50. **Engine-derived edges are never provider evidence.** The URL → host
    relationship is parsed from the authority the URL already carries, never
    searched for and never resolved. It is `ENGINE_DERIVED`, names no provider and
    no source family — validated, not merely documented — and shares one edge with
    any provider asserting the same thing without contributing to the family
    count. **How a relationship was learned is orthogonal to what kind of claim it
    is**: a sandbox's contacted domain is `EvidenceClass.CONTEXT` with
    `CONTEXT_ONLY` effect *and* something the sandbox watched, so a provider says
    so via `Relationship.directly_observed` and correlation reads that field
    generically — never by branching on a provider id. Either that flag or
    `EvidenceClass.DIRECT_OBSERVATION` earns `PROVIDER_OBSERVED`; silence leaves
    `PROVIDER_REPORTED`, so nothing is ever overstated. Marking a link observed
    changes no class, effect, direction, safety class or ranking: observation basis
    is provenance, not significance.

51. **Correlation performs no inference.** A→B and B→C never yields A→C; two
    samples contacting one address are not related; a domain does not inherit its
    address's certificate. No edge is ever created from a label — family, tag, AV
    verdict, YARA rule, country, ASN owner, warninglist name. Times live on
    assertions, and an edge's bounds are display-only: a 2019 and a 2026
    observation are two observations, not a seven-year association.

52. **Pivot discovery is not pivot execution.** Learning that a sample contacted a
    domain creates graph knowledge and authorises nothing. `PivotMode` defaults to
    building and recommending, an object returned with no usable relationship is
    marked unlinked and never auto-pivoted, and no `related-to` is invented to make
    the graph connected — a fabricated edge would become the justification for
    querying third parties about it.

53. **Remote pivot enrichment is explicit and doubly gated.** It requires both the
    root's `allow_remote_lookup` and `allow_remote_pivot_lookup`, which defaults to
    `False`; Task 14 can never re-enable what the root disabled. Following a lead
    the provider chose is a wider disclosure than looking up what the analyst
    typed, and one flag would make that escalation invisible.

54. **Private and sensitive targets are never disclosed automatically.**
    Non-global addresses (RFC1918, loopback, link-local, multicast, reserved,
    unspecified, documentation) and URLs carrying userinfo or a credential-shaped
    query *name* are graphed, recommended and never sent — the relationship is
    kept, because not disclosing is not deleting. Only the parameter name is read,
    never its value, and stripping the query to query "the same URL" is refused:
    that is a different observable.

55. **Automatic pivot enrichment is one hop, bounded by a shared budget.**
    `MAX_AUTOMATIC_PIVOT_HOP = 1`; hop-2 objects are graphed and never queried,
    appearing as candidates with `HOP_LIMIT`. Targets and remote runs are capped
    per depth (0/0, 2/3, 5/8) across the *whole session*, handed to each Task 13
    run as a reduction rather than watched afterwards, charged from Task 13's own
    remote-run figure so cache hits, cooldowns, unconfigured credentials and local
    providers cost nothing. Pivots run one depth below the root, and a target is
    marked enriched before ingestion so a cycle cannot queue it twice.

56. **Task 13 remains the only provider-selection engine.** Task 14 selects no
    provider, resolves no credential and calls no adapter; a pivot is a canonical
    observable handed to the planner. Correlation modules perform zero network
    access — no DNS, no HTTP, no socket, no download — and a test reads their AST
    to prove it.

57. **The graph is investigation knowledge, not a global store.** It is in-memory,
    scoped to one user and one investigation, and never shared: two analysts
    investigating one observable build the same canonical keys and two separate
    graphs, because sharing would leak who is looking at what. There is no graph
    database, and correlation produces no verdict, risk score or confidence — a
    warninglist match explains a node and never deletes an edge.

58. **Query time is never observation time, and analysis time is not activity
    time.** A lookup on a date does not make an indicator active on that date, and
    no instant is ever manufactured from a request, cache, enrichment or Task 13
    execution time. `last_analysis_date` is when VirusTotal *scanned*;
    `task.time` is when a browser *visited*; `analysis_start_time` is when a
    sandbox *detonated*. Each carries its own `TemporalFactKind` plus the
    provider's own field name, because collapsing them into one `last_seen` turns
    "we rescanned it yesterday" into "it attacked somebody yesterday".

59. **Temporal reasoning always uses an explicit timezone-aware `as_of`.** It is a
    required argument, a naive value is refused rather than assumed, nothing under
    `reasoning/` reads a wall clock, and an extractor is handed no clock at all.
    Identical inputs at one `as_of` serialize byte-identically, so a stored
    qualification stays re-derivable and a diff between two runs means something.

60. **There is no universal decay model, and no invented freshness label.** Age is
    exact and unlabelled — no `fresh`, no `stale`, no `old`, no half-life. A
    phishing URL, a malware SHA-256, a cloud address, a scanner range, a
    certificate and a sandbox report age nothing alike, and one number would be
    wrong for most of them while looking principled. Where a *source* defines a
    lifecycle its word is carried; where it does not, a later layer gets the
    number.

61. **A source's own lifecycle outranks any generic rule, and a returned record
    is not a heartbeat.** ThreatFox's six-month API horizon is
    `WITHIN_SOURCE_API_HORIZON`, never `ACTIVE_NOW` — which does not exist. A
    ThreatFox miss is compatible with never-listed, expired and reported an hour
    ago, so an absence produces no times, no lifecycle and no "expired".

62. **URLhaus `offline` does not erase historical malicious evidence.** A URL that
    distributed malware in March and stopped in April distributed malware. The
    evidence keeps `SUPPORTS_MALICIOUS` untouched; what is added beside it is
    `INACTIVE_BY_SOURCE`, `LAST_ONLINE_AT` and a
    `HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE` cue. `date_added` is a dataset time
    and `last_online` is an observation, and merging them would make a long-dead
    URL look recently active on every re-import.

63. **A file hash does not expire.** MalwareBazaar's first/last seen carry no
    lifecycle, because none is stated. Cryptographic file identity does not change
    tenant the way a cloud address does: a sample last seen in 2023 is not expired,
    not inactive and not benign.

64. **Warninglist and Business Services context never means safe.** Every
    warninglist signal is context; GreyNoise BSI is common business-service
    infrastructure and explicitly not an allow list. There is no
    `ContextSignalType`, `SourceLifecycleState` or `InterpretationCueType`
    containing *safe*, *trusted*, *benign* or *allow*, and a test asserts it. A
    cloud range hosts attacks, a CDN serves malware, and an EICAR hash is a test
    artifact rather than an ordinary benign file.

65. **Host-level context never clears an exact URL.** A warninglist match on a
    URL's host is `SAME_HOST`, `host_component_only`, and raises
    `HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL`. Losing that distinction is how every
    living-off-trusted-sites payload gets waved through.

66. **Sandbox negatives are qualified by execution quality, and never become
    benign.** Task 12's `observed_execution` is authoritative and Task 15 invents
    no threshold of its own: a completed non-directional run that observed nothing
    is `SANDBOX_LOW_EXECUTION`, one that did execute is
    `SANDBOX_MEANINGFUL_EXECUTION`, and an errored or queued run produces neither.
    Divergence across environments is preserved as `SANDBOX_DIVERGENCE`, never
    voted on, averaged or converted to a confidence.

67. **`PROVIDER_OBSERVED` describes provenance, not maliciousness.** It says a
    provider watched a link happen. It is exposed to later reasoning as
    epistemic quality and is never mapped toward a verdict about either endpoint.

68. **A relayed finding is not independent corroboration.** Detected generically
    from `transport_provider != origin_provider` — two model fields, so the rule
    holds for a provider that does not exist yet. Task 15 records the dependence
    and whether the same family also answered directly; it computes no source
    weighting, because that is the fusion layer's.

69. **Task 15 never mutates a provider fact.** `EvidenceEffect`, `EvidenceClass`,
    `source_family`, `lineage_group_id`, `origin_provider`, `transport_provider`,
    `MatchScope`, `Relationship`, `RelationBasis` and every graph edge are
    read-only. Provider evidence is never upgraded or downgraded: context is
    added *beside* a finding, never applied *to* it.

70. **Task 15 produces no verdict, confidence, score, weight or false-positive
    flag.** No `Assessment`, no `Verdict`, no `risk_score`, no `malicious_score`,
    no `decay_score`, no `evidence_weight`, no `is_false_positive`. Enforced at
    field-name level across every model and by an AST guard that the package never
    imports the assessment layer; structured detail rejects conclusion-shaped keys
    at construction.

71. **Context never propagates transitively.** A→B and B→C never gives C's context
    to A. There is exactly one edge-scoped rule — a contact with a public resolver
    — and it reads one edge and stops. A chain of ordinary-looking links is how an
    unremarkable-looking conclusion gets built out of nothing.

72. **Nothing infers meaning from prose.** No rule reads a description, a provider
    name, a tag, a warninglist title or any free text; every rule keys on an enum
    member, a boolean, a lifecycle state or an exact slug. Provider-authored text
    is attacker-influenced in several places, so a string saying "ignore previous
    instructions" is inert because no string is consulted. No regex classification,
    no `eval`, no dynamic import, no LLM.

73. **Provider time-field semantics stay provider-owned, and the evaluator names
    no vendor.** Each integration exposes one pure `qualification.qualify`;
    `reasoning/catalog.py` is the only module under `reasoning/` that may name a
    provider, and a test reads the AST *and the string literals* of every other one
    to prove it. A provider with no extractor is named in coverage rather than
    silently skipped, and the warninglist slug mapping is versioned and validated
    against the shipped snapshot so a refresh cannot change a meaning in silence.

74. **Task 15 performs no provider call and no network access.** No HTTP, DNS,
    socket, credential, cache, Task 13 enrichment or Task 14 pivot — it reasons
    over data already in hand, so a stored result can be requalified years later
    with the network unplugged. "This evidence is old" is never a trigger for a
    lookup.

75. **A false positive is a property of a detection, not of an IOC.** There is no
    `is_false_positive` on an address, a URL or a file — those would clear every
    claim about the object at once. Every Task 16 finding names the evidence or
    relationship it concerns through a typed `FindingLink`, and a finding with no
    links is refused at construction.

76. **Context alone is never an alternative explanation.** A warninglist hit on a
    value nobody has accused of anything is context: there is nothing to explain,
    and inventing an explanation would manufacture doubt about a finding nobody
    made. Every explaining rule first requires directional evidence or an explicit
    relationship whose significance is in question.

77. **Explaining, limiting and cautioning are different jobs.** Shared hosting
    affects attribution, current inactivity affects activity, a relayed finding
    affects independence, and a sandbox that ran nothing affects analysis quality.
    None of those is a candidate false positive. Only `ALTERNATIVE_EXPLANATION`
    means "this may explain the detection", and only two context types —
    `TEST_ARTIFACT` and `EMPTY_ARTIFACT` — can reach it for an object.

78. **Host-level context never explains an exact artifact.** A popular-domain or
    cloud-range match on a URL's host produces `INTERPRETATION_LIMITATION` with
    `HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL`, and the malicious evidence stays in
    the unexplained set. Even a normally-explaining signal is refused at host
    scope, checked as a field comparison rather than assumed.

79. **Compromised infrastructure does not invalidate malicious activity, and
    shared infrastructure does not make it safe.** Both produce
    `ATTRIBUTION_CAUTION`: the owner may be a victim, and a block has bystanders.
    Neither is a reason to doubt the activity happened, and filing either as a
    potential false positive would be the most consequential mistake this layer
    could make.

80. **Public-service context explains a relationship, never an object.** A public
    resolver or business service explains the *contact* at edge scope; the
    relationship stays `PROVIDER_OBSERVED`, `explained_evidence_ids` stays empty,
    and every such finding carries `DoesNotEstablish.OBJECT_BENIGN`. The
    business-service rule additionally declines when somebody has made a
    directional claim about the endpoint itself.

81. **An object-nature explanation never covers directly-observed behaviour.**
    "It is a test artifact" accounts for a scanner flagging it and accounts for
    nothing a sandbox watched the file do; that evidence is linked `OPPOSES`
    rather than folded in. `EvidenceClass.DIRECT_OBSERVATION` is the generic
    discriminator, so no provider is named.

82. **Low AV detection counts, code signatures and popularity are not
    false-positive rules.** TI Recon counts no vendor votes; a signature
    establishes a publisher rather than benign behaviour, and signing keys get
    stolen; popularity describes hosting. Each has a regression test asserting it
    explains nothing on its own.

83. **Task 16 produces no verdict, confidence, score, weight or false-positive
    flag,** and never mutates a Task 15 or Task 3 fact. Enforced at field-name
    level, by an AST guard that the package never imports the assessment layer,
    and by a test asserting the graph, the evidence and the qualification are
    byte-identical afterwards.

84. **The Task 16 engine names no provider at all.** Unlike `planning/` and
    `reasoning/`, there is no composition-root exception: it consumes Task 15's
    generic vocabulary, so no module has a reason to know a provider exists.
    `rules.py` may not even read `claim_type`, because every claim type in the
    repository is provider-prefixed — which is also why the scanner explanation is
    deferred rather than guessed.

85. **Nothing in Task 16 reads prose, a clock or the network.** Rules key on enum
    members, booleans and exact ids; `as_of` is carried through from Task 15; and
    a test rewrites every provider-supplied string, including one reading "ignore
    previous instructions", asserting byte-identical output.

86. **Fusion reasons over semantic claims, never over provider names.** A
    `NormalizedClaim` says what proposition a piece of evidence supports;
    `reasoning/claims/registry.py` is the only module in either new package that
    may name a provider, and a test reads the AST and string literals of every
    other one. Generic modules may not even read `claim_type`, because every
    claim type in the repository is provider-prefixed.

87. **Every directional provider claim is intentionally mapped or explicitly
    unclassified.** A regression drives the real adapters over the real fixtures
    and fails if a shipped provider produces `UNCLASSIFIED_DIRECTIONAL`, so a new
    directional claim type forces a decision rather than silently weakening a
    finding. An unclassified claim stays visible and can never be decisive.

88. **A claim semantic is not a verdict.** `C2_ASSOCIATION` says a source claims
    command and control; `SCANNER_ACTIVITY` says a sensor network classified
    scanning behaviour, which is not benign. The semantic names the dimension,
    `EvidenceEffect` names the direction, and fusion policy decides what either
    is worth.

89. **Providers are never counted, and dependence is a connected component.**
    Three kinds of provenance each make two claims dependent — the same
    `source_family`, the same `origin_provider`, the same `lineage_group_id` —
    and claims are unioned over all three, so dependence composes: sharing a
    family with one claim and an origin with another makes all three one origin.
    Partitioning on any single key loses the other two edges, and both ways of
    getting that wrong have already happened here. Keying on lineage split one
    family into several apparent origins, because Task 3 defaults
    `lineage_group_id` to `"{family}:{origin}"`; keying on family alone then read
    a relay whose transport belongs to a *different* family, but which names the
    same origin, as two independent confirmations and escalated the verdict.
    Three abuse.ch datasets answering is one origin. The verdict's corroboration
    test and the confidence band both count components, never families. Nothing
    is discarded: only the ability to corroborate collapses. Task 16's
    `DEPENDENT_WITH` link is deliberately not a fourth edge: it is unary, naming
    the relayed record alone, and the dependence it states is the
    `origin_provider` and `source_family` of that same record — already edges
    here, so the two layers agree without fusion reading the finding.

90. **Corroboration requires compatible propositions, stated in a versioned
    table.** `SCANNER_ACTIVITY` is compatible with nothing but itself, and
    `AGGREGATED_REPUTATION` with nothing at all including itself — one source
    relaying forty opinions is one source. No compatibility is inferred from enum
    names.

91. **Only a Task 16 `ALTERNATIVE_EXPLANATION` with an `EXPLAINS` link to
    evidence removes support.** An attribution caution, a temporal note, an
    analysis-quality limitation, a scope limitation and a source-dependence
    finding all qualify evidence without explaining it. Treating any as an
    explanation would clear real malicious evidence behind a verdict that looked
    thoroughly reasoned.

92. **Explained is not false.** An explained claim is retained in full; the trace
    says the verdict did not rest on it, never that the source was wrong.

93. **Specificity decides, not popularity, and only two semantics decide
    alone.** `MALWARE_SAMPLE_IDENTITY` and `MALWARE_DISTRIBUTION` — specific
    claims about the exact object that a repository publishes after vetting.
    One curated repository holding this exact sample reaches MALICIOUS alone;
    one generic reputation claim reaches SUSPICIOUS. Demanding a second provider
    before believing a specific fact would be treating specificity as if it were
    a vote. A sandbox classification is deliberately *not* decisive whatever its
    evidence class: nothing in a claim distinguishes a sandbox that watched a
    sample act from a boolean saying one did, and the only claim the old
    `DIRECT_OBSERVATION` promotion reached was a contributing-factor flag with no
    report, environment or execution quality — outranking a full report that
    had all three. Task 12 required execution quality to read a sandbox negative;
    a positive carries a verdict alone only once an equivalent claim-level signal
    exists.

93a. **Corroboration requires the same subject *and* the same scope.** Scope is
    part of the proposition key, so the same-proposition path matches it; the
    cross-proposition path must check it explicitly, or a host-level reputation
    completes a MALICIOUS verdict about an exact URL out of a statement nobody
    made about the URL. This is the mirror of "host context never clears an exact
    URL" — host-level evidence may neither condemn nor absolve an exact artifact.

93b. **The verdict is about the target, and only the target.** Only claims whose
    subject is the assessment's `target_key` may decide it. A decisive claim
    about an object reached on a pivot is knowledge about *that* object; letting
    it vote here is the graph-derived promotion Task 14 deferred, arriving
    through claim indexing rather than through an edge, and would attribute a
    pivot's verdict to whatever the analyst typed. Pivot claims stay in the
    claims, propositions, contributions and coverage — they simply do not vote.
    **Unknown is not root.** A claim's `subject_object_id` resolves to the root
    object's own id, to any other object the run saw, or to nothing — and the
    third is `unresolved-subject:<id>`, never the root. `build` indexes the root
    by id, so a legitimate root claim resolves explicitly even though ThreatFox,
    URLhaus and Hybrid Analysis list only *discovered* objects in `objects`; the
    old fallback therefore only ever fired on an id nothing could account for,
    letting a malformed or misrouted claim condemn or clear whatever the analyst
    had typed. An unresolved claim is retained, reported as
    `UNRESOLVED_CLAIM_SUBJECT`, and excluded from verdict, confidence and
    corroboration.

94. **SUSPICIOUS means affirmative concern; INCONCLUSIVE means the engine cannot
    justify either direction.** Missing data, `NO_DATA`, a provider failure and a
    sandbox that ran nothing are never reasons for concern, and reporting them as
    suspicion would flood an analyst with alarm generated by absence.

94a. **Benign is not undetected, and no count is an assertion.** GTI's
    `VERDICT_BENIGN` is a stated determination and becomes `BENIGN_REPUTATION`;
    `VERDICT_UNDETECTED` and `VERDICT_UNKNOWN` are `CONTEXT_ONLY` and become no
    claim at all, because "nothing flagged it" is also true of every threat
    nobody has caught yet. `SEVERITY_NONE`, a zero threat score and
    `last_analysis_stats` are statistics about who looked, never a determination.
    v1 policy: an explicit unopposed `VERDICT_BENIGN` about the exact object
    reaches LIKELY_BENIGN; nothing derived from engine counts ever does.

94b. **A contributor's confidence is not TI Recon's.** ThreatFox carries a
    per-IOC `confidence_level` (0-100, default 50). It is preserved verbatim as
    provider data, reaches no claim and maps to no band — there is no calibration
    behind a threshold like "≥ 75 is decisive". This v1 policy treats an exact,
    unexpired `payload_delivery` record as sufficient malicious evidence because
    ThreatFox vets submissions, not because of any confidence value; a regression
    asserts 0, 50, 75 and 100 produce identical assessments.

95. **Context, absence and non-claims can never reach LIKELY_BENIGN.** Not a
    warninglist hit, business-service context, shared hosting, a scanner
    classification, an offline URL, an absence of detections, `NO_DATA`, a
    sandbox that observed no execution, a low detection count or a valid code
    signature. Two paths reach it: a genuine directional benign assertion with
    nothing against it, or every malicious claim specifically explained with none
    left over.

96. **A conflict is preserved, never cancelled.** Same subject, same semantic,
    same scope, opposite directions. Nothing balances or picks a winner: real
    surviving support yields SUSPICIOUS with the disagreement recorded and
    confidence capped, and two weak claims disagreeing yield INCONCLUSIVE.

97. **There is no numerical fusion anywhere.** No score, weight, probability or
    risk number, and a test asserts the policy and confidence modules contain no
    multiplication, division or exponentiation. There is no calibration data
    behind any coefficient, so a formula would manufacture precision nobody can
    defend.

98. **Verdict and confidence are separate decisions from different inputs.**
    Confidence answers "is this assessment correct?", never "how malicious is
    this?". MALICIOUS at MEDIUM is ordinary. Caps lower a band by name —
    unresolved conflict, unclassified basis, sandbox divergence, stale supporting
    context, wholly weak support — and nothing is subtracted. Only the canonical STIX
    values 15/50/85 are ever produced. Determinism is run-scoped: `claim_id` and
    `assessment_id` incorporate `Evidence.id`, so re-running fusion over stored
    evidence reproduces them exactly while a fresh collection of the same
    intelligence does not — the cross-run identity is the proposition
    (`subject + semantic + scope`). `FUSION_POLICY_VERSION` 1.0.0 is the first
    finalized policy; once a version has shipped or assessments are persisted
    under it, any behavioural change to claim mapping, claim strength,
    compatibility, independence, verdict rules or confidence rules requires an
    explicit review and bump, because the version is what distinguishes the
    resulting assessment identity.
    `FusionAssessment` is the authoritative
    assessment from Task 17 onward; Task 3's `Assessment` is legacy, retained for
    backward compatibility, and a boundary test asserts `claims/` and `fusion/`
    never import it — that model requires a `risk_score` this layer refuses to
    invent.

99. **Every confidence cap is scoped to the decision, and confidence is not
    coverage.** A cap must bear on the claims the verdict rested on: the finding
    links to basis evidence, the conflict is about a proposition in the basis,
    the partial envelope is the one that produced a basis claim, every basis
    claim is weak. So an unrelated stale warninglist, a divergent sandbox
    detonation of another object, a disputed reputation on a pivot and an
    optional provider returning `NO_DATA` all leave an independent assessment
    untouched — they are recorded in coverage, where they belong. A partial
    provider result caps nothing at all: the repository knows only that an
    *envelope* was incomplete, which does not say whether the basis claim itself
    is, and a provider that returned its verdict-bearing fact in full while an
    optional lookup failed has told us nothing less correct. Partiality stays on
    the claim, on its contribution and in coverage; a future *claim-level*
    completeness signal would be a different condition needing its own id and a
    deliberate decision. A run-wide read
    is a bug in *both* directions, and both have happened: the conflict cap
    lowered a band over a disagreement about a different object, and the
    weak-support cap was suppressed by a non-weak claim about a different object,
    handing the root a higher band than its own support earned. `_caps()` is
    therefore handed the basis, the conflicts and the reasoning result and not
    the full claim set. Whether coverage is *sufficient to act on* is Task 18's
    question; MALICIOUS at HIGH with incomplete coverage is a valid statement.
    `INCONCLUSIVE` keeps two distinct rules for `UNSPECIFIED`, because nothing
    being said and sources contradicting each other are opposite situations.

100. **Every verdict names its rule and its contributions.** Each claim gets a
     contribution — including the explained ones and the dependent duplicates —
     carrying a role, a disposition and stable reason codes. A trace listing only
     what supported the verdict would be an argument rather than a record.

101. **Task 17 performs no network access and recommends no action.** No HTTP,
     DNS, socket, provider call, credential or clock; `as_of` comes from Task 15.
     MALICIOUS does not mean block — shared and compromised infrastructure make
     that genuinely difficult, and it belongs to a layer that knows the
     environment.

102. **Readiness never changes the assessment.** Task 18 may say
     READY_WITH_LIMITATIONS about a MALICIOUS/HIGH result whose sandbox coverage
     was unavailable, and the verdict, confidence, rules, claims, contributions
     and conflicts stay byte-identical — a test serializes the `FusionResult`
     before and after and compares. Confidence in *correctness* is not collection
     completeness, and an incomplete investigation does not make a correct
     assessment less correct. This is the Task 17 partial-envelope lesson applied
     from outside: coverage states are surfaced here, never charged to confidence.

102a. **A refusal is not a partial answer, and independence is Task 17's.**
     `PLAN_LIMITED` reaches an attempt only through Task 6's error path, where
     the envelope is `None`, so nothing was retrieved: it is `BLOCKED` with its
     own gap type, not partial coverage. `PARTIAL` genuinely has two shapes —
     reduced evidence, or an adapter that could not build an envelope at all —
     so completion is refined by whether the attempt produced anything rather
     than read from the status alone. And the benign challenge resolves the
     basis's component through `independence_groups`, never a family comparison:
     a relaying transport carries a different family while reporting the same
     origin, so a family-only test lets one origin challenge itself. Where a
     `NO_DATA` check has no claim to group on, family separation is the
     strongest available test and is documented as weaker than claim-level
     precision rather than presented as equivalent.

102c. **One call can answer several capabilities, and coverage says which.**
     Task 13 bundles compatible goals into one request and records a single
     attempt carrying the call's *primary* capability, crediting everything the
     response answered in the `CoverageItem`s. Readiness reads both — attempts
     for what executed and why anything failed, coverage for what was answered —
     and takes the better. An attempts-only ledger reports a bundled capability
     as never attempted and demands a call the planner deliberately avoided.
     Evidence for one capability never establishes another, and the crediting
     comes from Task 13's per-capability statement rather than from evidence
     sharing an envelope.

102e. **Yield belongs to the capability that produced it.** `InformationYield`
     comes only from attempts keyed to the capability, so a secondary bundled
     capability never inherits the primary's `DIRECTIONAL` — a context
     requirement that did would look like a search that happened. Task 13 records outcomes per *call*, so where one response
     answered two capabilities the repository cannot say which returned data,
     context or nothing; that state is named `UNATTRIBUTED` rather than reported
     as `NONE`, which would assert nothing came back, or `NO_DATA`, which would
     assert the source held nothing — both claims about content the record
     cannot support. It is a retention limit, never satisfies a need for
     directional information, creates no evidence, and is counted as itself
     rather than folded into `checks_no_data`. An adverse search
     bundled as a secondary is still found, through
     `PlanningDecision.call.answered_capabilities` plus its `source_family` —
     never through a coverage item, which records candidacy rather than who
     answered.

102d. **The benign challenge must be independent *and* relevant.** Independence
     alone is not enough: the challenging check has to be an adverse search, from
     the small explicit set `REPUTATION` / `MALWARE_INTELLIGENCE` /
     `THREAT_ASSOCIATIONS`. Infrastructure exposure, certificate, scanner and
     business-service context searched for nothing adverse however independent
     they are, and `FILE_BEHAVIOR` is excluded because watching a sample run is
     a different question from searching what is known about it. Mixed material
     gaps resolve addressable-first, so a blocker never stops a run that still
     has useful work in front of it, and it stays reported in `gaps`.

102b. **Capability absence is a catalogue fact; execution history outranks it.**
     `providers_considered` is built by walking the registry and asking each
     descriptor what it supports, before budget, credentials, activation or
     depth — so an empty set describes the catalogue, not the run. A recorded
     budget skip proves a candidate existed, so it is `BUDGET_LIMITED` rather
     than "no source exists". Materiality binds to Task 17's `VERDICT_RULES` by
     imported identity, never by prefix or substring, and an unrecognised rule
     is treated as a weak basis so relevant requirements stay material.

103. **`NO_DATA` is checked-with-no-data, and is never benign evidence.** A source
     that answered "nothing known" completed its check; a source nobody configured
     did not. Collapsing the two lets an unattempted check masquerade as an
     exhausted one. Neither is evidence of safety, so adding a completed `NO_DATA`
     improves coverage and moves no verdict. Every `ProviderRunStatus` is mapped
     in `STATUS_COMPLETION` with no default branch.

104. **A provider failure matters only when it blocks a material requirement.**
     Readiness aggregates at the capability, never the provider: if one source is
     unconfigured, one is out of quota and a third answered, the requirement is
     satisfied and both failures stay in the trace. There is no provider
     percentage, success ratio or vote count anywhere — a static test asserts it.
     Cache hits and coalesced results are valid coverage, and a credential-free
     local source covers without any remote cost.

105. **Requested depth bounds expectation, and an inactive goal is not a gap.**
     Requirements come from Task 13's `goals_for`, so a DEEP-only capability is
     simply absent from a QUICK run rather than missing from it, and a conditional
     goal whose trigger never fired is read from the planner's recorded skip
     reason rather than re-derived. Planner budget exhaustion is an operational
     fact, never proof that coverage was adequate — and `EXHAUSTED` is not
     `ADEQUATE`: asking everything available and learning nothing is a finished
     search with an open question, which is why INCONCLUSIVE can never be READY.

106. **`LIKELY_BENIGN` readiness is deliberately asymmetric.** A malicious
     finding is self-limiting; a benign finding is an absence, and an absence is
     only as good as the search behind it. A benign verdict resting on one
     unopposed assertion needs an *independent* adverse search — independence by
     Task 17's provenance grouping, never a provider count — before it is fully
     ready. That search may return `NO_DATA`: somebody looked, and no benign
     evidence was created. The explained-benign route needs no separate
     challenge, having already accounted for adverse evidence individually.

107. **Stale context and sandbox quality stay scoped.** A stale dataset limits
     only the requirement whose supporting data was stale, never an unrelated
     exact malware-sample identification; a completed sandbox run that observed no
     execution is limited behavioural *coverage* and says nothing about direction.
     An unresolved claim subject prevents a silent full READY, because evidence
     nobody can attribute may still be relevant.

108. **Task 18 performs no enrichment and recommends no action.** No HTTP, DNS,
     socket, provider call, planner run or clock — `evaluated_at` comes from
     Task 15, and identical inputs answer identically forever. No score,
     percentage, risk number, severity, priority, incident declaration or
     remediation. v1 answers one purpose, external-TI analyst triage, because
     readiness for containment or alert closure depends on organisational context
     this engine does not have. `READINESS_POLICY_VERSION` is versioned and
     travels with the Task 15/16/17 versions on every result.

109. **Task 19 composes Tasks 13-18 and reimplements none of them.** No
     maliciousness rule, no coverage judgement, no provider selection. Every
     provider call goes through Task 13 to Task 6, which is where the cache,
     cooldown, quota, retry, execution scope and budget accounting live; a direct
     adapter call would bypass all six, and an AST test asserts none exists. The
     generic workflow names no provider in an import or a string literal —
     `composition.py` is the only exception, and it reuses the existing planning,
     qualifier and claim-translator catalogues rather than assembling a second
     list that would silently drift.

110. **Task 18 is the only automatic continuation trigger.** Readiness must say
     both `NEEDS_MORE_DATA` and `MORE_DATA_AVAILABLE`. A suspicious verdict, an
     inconclusive one, a failed provider and a missing sandbox are none of them
     reasons to keep querying — readiness has already weighed each against what
     the assessment rests on. `READY` and `READY_WITH_LIMITATIONS` are terminal
     even with optional provider failures recorded, and `BLOCKED` and `EXHAUSTED`
     are terminal for the current run.

111. **Ceilings are the caller's and never rise.** Depth never escalates, pivot
     mode never escalates, and budgets never reset: Task 13's state carries the
     spend and the calls already made, so a continuation sees only what remains.
     Cache hits, coalesced results and local credential-free sources are valid
     coverage at zero remote cost, so the workflow does not stop when the remote
     allowance empties — it hands the remaining state to Task 13 and lets its
     locality policy decide. Task 14's pivot budget and one-hop limit are
     investigation-wide, and a target enriched in one round is not enriched again
     in the next.

111a. **A logical call is a provider *and* a question.** What carries between
     rounds is `(provider_id, capability)`, so a source that answered a
     reputation lookup stays eligible for the behaviour lookup it has genuinely
     not answered — excluding it by provider id would turn one answered question
     into a permanently unanswerable one. Where a provider declares
     `capability_invariant_response`, Task 13 credits everything the one document
     answered and the second call never happens; where it does not, the second
     call is real incremental work. A whole provider is set aside only for the
     failures Task 13 already treats as provider-wide — a refused credential, a
     spent quota, an unreachable endpoint — and never because it answered
     `NO_DATA`. The planner's attempt `sequence` continues across rounds, which
     is what makes it an identity rather than a position: the round merge is
     keyed on it, an identical record deduplicates, and two different records
     sharing one sequence raise rather than overwrite.

111b. **Root and pivot spend two allowances, and each call is charged once.**
     `EnrichmentBudget` bounds provider runs about the submitted observable and
     carries in the planning state; `PivotBudget` bounds targets and runs about
     things the root merely touched and carries in the `CorrelationSession`. A
     pivot receives the remaining pivot allowance as a Task 13 reduction and
     plans from its own state — carrying the root's spend into it would charge
     one call to two budgets, and carrying the root's focus would let readiness
     decide what a pivot may ask. Both are charged on `called_provider`, so a
     cached, coalesced or local pivot is free, and neither can rise: the
     investigation's maximum remote disclosure is the sum of two reduction-only
     limits. Every outcome either produces — root and pivot alike — is recorded
     on the session and reaches Tasks 15-18. A pivot result that reached the
     graph but not the reasoning stages would leave the picture looking complete
     while the evidence behind half of it had never been qualified, explained or
     assessed; that the claim then declines to vote on the root's verdict is
     Task 17's rule, and it needs the claim to exist in order to decline it.

111c. **A continuation narrows the planning space and never widens it.** The
     capabilities Task 13 admitted for this root at this depth are frozen from
     the first round — read from its own coverage items rather than from a
     second copy of the depth table — and a readiness need naming anything
     outside them produces no directive. `requested_capabilities` is not a
     filter: Task 13 turns every member into a `REQUIRED`, `IMMEDIATE` goal
     whatever the template said, so a continuation adding its directives there
     would create a goal the depth never admitted, activate a conditional goal
     whose trigger had not fired, and promote an optional goal to required —
     turning QUICK into DEEP one capability at a time. The planning request is
     therefore identical every round and narrowing happens only through focus.
     Three categories stay distinct: admissible and active may be targeted;
     admissible but unactivated is left to Task 13's activation rule; outside
     the requested depth is never planned. Where no admissible capability can
     address a material need the run stops with `NO_ACTIONABLE_CONTINUATION`,
     because deciding an investigation should have been deeper is the caller's.

111d. **The envelope freezes which capabilities, never how much coverage.**
     Task 13's goal states the family target worth buying by default; Task 18
     can hold a requirement that target satisfies numerically and not in
     substance — a benign assessment on one origin needs an *independent* look,
     and one family answering is exactly what met the base goal. A directive
     therefore carries a typed `ContinuationNeed`: `MISSING_COVERAGE` is
     ordinary planning, and `ADDITIONAL_COVERAGE` raises that capability's
     family target to `covered + 1` for one round, reusing the breadth concept
     the goal already has rather than adding a second notion of sufficiency. It
     adds no capability, activates no goal, clears no coverage and names no
     provider; Task 13 still ranks, still refuses an attempted call, still
     honours a blocked provider and an excluded family, and still has to afford
     it. Without the request the effective target is the goal's own, so an
     ordinary Task 13 caller is unaffected. So
     `continuation capabilities ⊆ initial admissible capabilities` holds while
     `continuation source coverage ⊇ first-round source coverage` is allowed —
     and a breadth need is expressed against the adverse-search capabilities
     *this depth admits*, taken from Task 18's own published set, never against
     the representative capability it happened to name. This is not provider
     voting: Task 18 said a check was missing, Task 17 still decides what the
     answer means, and the second source may return nothing, context, agreement,
     contradiction or a relay of the first one's origin.

112. **Pre-call family separation is a planning hint, not proof of
     independence.** A benign-challenge directive carries the families already
     known to share the benign basis's origin so the planner can prefer another,
     but a source that looks unrelated may relay the very origin it was meant to
     challenge. Task 17 regroups from the returned provenance and Task 18 reports
     the challenge still missing; the workflow never declares the answer
     independent because it picked a different family. The hint belongs to the
     need that asked for independence and to no other: whether a sandbox shares
     an origin with something that called the file benign has no bearing on what
     the sandbox watched it do, and attaching the families to every directive
     would record a constraint nobody asked for. The hint is *enforced*, not
     merely recorded: it reaches Task 13 as `excluded_source_families`, a
     capability-to-families mapping checked before cost and budget, because a
     dependent source that wins the ranking spends the allowance the requirement
     was released for and leaves the independent candidate unaffordable. A
     different provider id in the same family is not independent information,
     and a family barred from one capability answers every other exactly as
     before.

113. **New evidence recomputes everything.** Tasks 15-18 re-run over the
     accumulated state rather than patching an old conclusion, using one instant
     per pass so the four results are internally consistent. Readiness may get
     *worse* after genuinely conflicting evidence, and that outcome is preserved:
     Task 18's monotonicity concerns a fixed requirement with no new adverse
     information, not a promise that investigations only improve.

114. **Provider failures are analytical inputs; structural faults are errors.**
     An unconfigured, rate-limited, unavailable or erroring source continues the
     run and reaches Task 18 as coverage. Stages describing different observables
     or a merge conflict between rounds raise, because returning INCONCLUSIVE
     would dress a software fault as a conclusion. Cancellation propagates
     untouched rather than becoming a provider failure.

115. **Run state never outlives its run, and nothing is persisted.** The graph,
     outcomes, planner memory, pivot set and round history live in a per-run
     object, so two investigations through one orchestrator share nothing and a
     long-lived service cannot accumulate one enormous investigation. The
     execution scope reaches every call in every round unchanged. Task 19 writes
     nothing, resumes nothing across invocations, and claims no durable
     idempotency. It produces no risk, severity, priority, incident declaration or
     remediation, and `INVESTIGATION_WORKFLOW_VERSION` versions its composition
     semantics.

116. **Task 20 presents Tasks 13-19 and reinterprets none of them.** The report
     builder selects, orders, labels and bounds; it decides no verdict, no
     confidence, no readiness, no independence and no explanation. Every value
     is copied from the layer that owns it, because a presentation layer that
     re-derived one would eventually disagree with the engine and an analyst
     would have no way to tell which half was wrong. `reporting/` imports no
     `.policy` module and a test asserts it.

117. **`AnalystInvestigationReport` is the supported public contract;
     `InvestigationResult` stays internal.** The internal result carries planner
     decisions, graph structure and every engine's counters — unbounded,
     coupled to seven layers, and changing whenever any of them is refactored.
     `ANALYST_REPORT_SCHEMA_VERSION` is versioned separately from the workflow
     and policy versions it reports, because a fusion policy bump should not
     oblige every consumer to re-integrate. The full result stays reachable
     through the application service for anyone debugging a disagreement.

118. **Report generation is pure and performs no I/O.** No clock — the instant
     is Task 19's `evaluated_at` — no network, no filesystem, no randomness, and
     `report_id` is derived from the schema version and the result id rather
     than generated. The same result always produces the same report and the
     same bytes. `assessment_id` and the claim and evidence ids remain
     run-scoped exactly as the engine defines them.

119. **A related observable is a relationship, never an indicator.** A contacted
     host, a resolved address and a dropped file are things a source connected
     to the root; `assessed` says whether Task 17 separately reached a verdict
     about the object, and where it did not, none is implied. `PROVIDER_OBSERVED`
     and `PROVIDER_REPORTED` stay distinct — watching a connection happen is
     different knowledge from hearing about it, and neither is an accusation.
     Labelling these as IOCs is how a public resolver reaches a blocklist.

120. **The coverage vocabulary survives presentation intact.** `NO_DATA` is a
     completed check and never benign — it is equally true of every threat
     nobody has caught. `NOT_ATTEMPTED` is not `NO_DATA`. `UNATTRIBUTED` is
     neither: one call answered two capabilities and the record cannot say which
     returned what. An alternative explanation covers the evidence Task 16
     linked it to and never the investigation, and a historical detection never
     renders as current activity.

121. **The text renderer neutralises terminal injection; JSON does not need
     to.** Provider labels, tags and the observable itself are
     attacker-influenceable, and a value carrying CR or an ANSI sequence could
     forge report lines an analyst would read as the engine's own words.
     Control characters are replaced visibly, ordinary Unicode is preserved and
     every field is bounded — for display only. JSON keeps the canonical values,
     because it has structural escaping and no cursor to move.

122. **JSON stdout is exactly one document, and diagnostics never reach it.**
     Logging is configured by the process entry point rather than by the
     library seam, so an embedding application's handlers are never silently
     replaced. A closed pipe is an ordinary event, not a traceback.

123. **CLI exit status describes the process, never the verdict.** A completed
     investigation exits 0 whether it reached MALICIOUS, SUSPICIOUS,
     INCONCLUSIVE or LIKELY_BENIGN, and whether readiness was READY or
     UNRESOLVED. Input and structural failures exit nonzero and emit no report:
     a software fault must never be dressed as an analytical conclusion.

124. **Credentials are never CLI arguments, and never reach output.** A secret
     on a command line lands in shell history and the process list. Resolution
     stays per user in the credential layer, no report or log carries a
     credential value or a credential-shaped field name, and the provider
     diagnostic reports only whether one is *required*.

125. **The interface layer never selects a provider and never assesses.** No
     provider flag, no provider name outside the two composition roots
     (`providers/catalog.py` and `application/composition.py`), no adapter
     call, no socket. Ranking is Task 13's and stays reproducible only while it
     is. The application service is transport-neutral, so the CLI is one caller
     among several and a future MCP layer consumes the same contract rather
     than parsing text.

125a. **One catalogue, registered whole, contacting nothing.**
     `providers/catalog.py` is the authoritative adapter list and a test
     asserts it names exactly the providers `planning/catalog.py` can plan, so
     neither can drift. `build_default_application` wires it once for every
     interface: a second assembly point would eventually investigate
     differently. Adapters build with no arguments and create their clients
     lazily, so composing the catalogue, listing it and generating a schema are
     all offline — the first packet leaves when Task 13 selects a provider and
     Task 6 executes it.

125b. **A missing credential removes nothing.** Every shipped provider is
     registered whether or not a key exists, and reports `NOT_CONFIGURED` when
     selected. Dropping it from the catalogue instead would report "the analyst
     has not set this up" as "no source implements this", and Task 18 decides
     materiality from exactly that difference. Secrets load from the variable
     names `.env.example` documents into the ordinary per-user store, one
     connection per credential *group* — which is what keeps one abuse.ch key
     serving three adapters and stores it once. `configured` is a boolean:
     never a value, a prefix, a length or a digest.

125c. **Opposition is not basis.** Task 17 can reach a verdict while recording
     claims that pushed the other way. They appear in their own section under
     their own heading, because under one heading meaning "why" a benign
     assertion reads as a reason the object was called malicious. Every item
     carries its Task 17 role in either section, and Task 17's contributions
     and dispositions are never altered.

125d. **A local file is hashed, and only if it is a file.** Regular files only,
     checked against the resolved target before the open: a FIFO blocks until
     somebody writes to it and a character device can be endless, so either
     would hang the command with no output. A symlink to a real file is
     followed deliberately; a symlink to a pipe is refused. Hashing is
     streamed, and the only thing that leaves the machine is a digest.

125e. **Remote pivot enrichment needs its own yes, in public too.** Task 14
     gates it on `pivot_mode == ENRICH` *and* `allow_remote_pivot_lookup`, so
     the public request exposes both — a request offering only the mode
     promised a disclosure it could not perform, and enriched pivots through
     local providers while a caller believed otherwise. The permission is
     refused outside `ENRICH` rather than ignored, defaults off for every
     existing caller, and changes only *who may be asked*: budgets, the one-hop
     limit, the privacy refusals and Task 13's selection are untouched. The
     report records it beside the mode, because the two together are what
     decided whether anything about a related observable left the machine.

125f. **A human label must not say more than the engine did.** The text
     renderer prints `Confidence: Medium` and not `Medium (50)` — an integer
     beside a verdict reads as "50% likely malicious", which is a different
     claim from confidence that the *assessment* is correct, and no calibration
     exists behind either. It prints `TI coverage:` and not `Readiness:`,
     because READY means the collection was adequate for triage and never ready
     to close, block or declare. Both are presentation: `confidence_stix` and
     the readiness field names are unchanged in the JSON contract.

127. **Task 21 exposes capability and adds no reasoning.** The MCP tools build
     a Task 20 request, call the Task 20 application and return the Task 20
     report. `mcp_server/` imports no adapter, no HTTP client and no reasoning
     policy, calls no adapter or executor, and a test reads its AST to prove
     it. The investigation tools are annotated `-> AnalystInvestigationReport`,
     so the SDK derives the output schema from the Task 20 model and there is
     no second report type to drift.

128. **A tool call reports whether the tool worked, never what it found.**
     MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, INCONCLUSIVE and an UNRESOLVED
     readiness are all `is_error=False`; so is a run where a provider was
     unconfigured, throttled or broken, because Task 19 still produced a report
     and Task 18 recorded what that cost. Only a failure the caller could act on
     — an unparseable observable, a non-regular file, a permission that cannot
     apply — is an error, and it carries a plain message.

129. **An unexpected exception's text never reaches a client or a log.** A
     dependency can put a credential or a raw provider payload in one, and the
     SDK logs an escaping exception's whole traceback at ERROR. The tools
     convert it to a fixed message and log the type alone. `CancelledError` is a
     `BaseException` and is deliberately untouched: cancellation propagates and
     never becomes a partial or inconclusive result.

130. **The MCP principal is the process's, never the caller's.** One stdio
     server serves one analyst, under a reserved local name rather than the
     operating-system account — that identity reaches cache keys and metrics.
     No tool input may carry a user id, an execution scope, a credential, a
     provider preference or an active operation, and a test asserts each
     against the published input schemas. stdout carries the protocol and
     nothing else; logging is configured by the entry point, never by the
     reusable factory.

131. **Reading a local file needs a human, where the host can ask one.**
     `investigate_file` carries `anthropic/requiresUserInteraction` in its
     tool `_meta`, so Claude Code prompts on every call even when an allow rule
     would match — a standing yes to investigating observables must not become
     a standing yes to opening files. It is advisory and host-specific: a client
     that does not know the key ignores it, which is why the real boundaries
     stay elsewhere — the user selects the file, Task 20 accepts only a regular
     file, the bytes are hashed locally and never sent, and an agent may not
     browse for samples. Consent is never an input field: a model sets its own
     arguments, so `user_confirmed` would be consent from nobody. A future Skill
     must not pre-approve these tools with `allowed-tools`.

132. **The Skill presents; it never recalculates.** It drives the MCP tools and
     never the CLI or a provider API, and it decides no verdict, confidence,
     independence, explanation applicability, readiness or provider choice —
     all of those arrive in the Task 20 report. It carries no `allowed-tools`
     grant: permission belongs to the user's configuration, and a grant here
     would undercut the human approval Claude Code requires for local files.

133. **Detail is free; collection is not.** Explaining a result already in the
     conversation must never cause a new tool call, however thorough the request
     — "explain this thoroughly" re-reads, it does not re-run. Broader
     collection (Deep, pivot enrichment, external pivot enrichment) is
     user-directed: a suspicious verdict never escalates depth on the model's
     initiative, and an ambiguous "more" gets one clarifying question rather
     than a guess. Defaults stay STANDARD, RECOMMEND, external pivot off.

134. **Disclosure needs intent, and files need selection.** External pivot
     enrichment is enabled only on unambiguous intent, never silently.
     `investigate_file` runs only for a file the user supplied, attached or
     named — no browsing, no enumerating, no reading `.env`, and "check my
     machine" is not a selection. A provider credential is never pasted into a
     conversation, a tool argument, a prompt or a header, in any deployment.
     *How* one comes to exist is deployment-specific and stated rather than
     assumed — see 164; over stdio it is a local step read once at startup, so a
     new credential appears after a restart or reconnect.

135. **The Skill inherits every vocabulary rule the engine enforces.** Sources
     are provenance and never votes, so no tally is ever produced. `NO_DATA` is
     checked-and-nothing-found, never clean. `UNATTRIBUTED` is not `NO_DATA`.
     `NOT_CONFIGURED` is a configuration fact about the caller's own account —
     a check that never ran — and not a provider being offline. A
     related observable is a relationship, not an indicator. TI coverage is not
     permission to act, and confidence is not a probability of maliciousness.
     The Skill states the assessment and makes no organisational remediation
     decision.

126. **Task 20 recommends no action.** The report states an assessment; it never
     says to block, quarantine, isolate, allowlist, suppress, close an alert or
     declare an incident. Those decisions need asset criticality, business
     impact and incident policy this engine has no access to.

136. **The OAuth access token stops at the `mcp_server/` boundary.** It
     authorizes an analyst to call TI Recon; a provider credential authenticates
     TI Recon to a provider, and neither may become the other. `RemotePrincipal`
     carries one field, so the token, the raw issuer, the raw subject, the
     `client_id` and the claims all end where it was built. No module in
     `application/`, `investigation/`, `planning/`, `correlation/`, `execution/`,
     `credentials/`, `providers/`, `reasoning/`, `reporting/` or `cli/` imports
     the MCP SDK, names an authentication symbol, or imports ASGI machinery that
     could read an inbound header — a passthrough would have to add an import,
     and an AST test is what notices.

137. **The tenant is the validated issuer *and* subject, never the client id.**
     `sub` is unique only per issuer, so two organizations' `alice` are two
     tenants; the OAuth `client_id` identifies Claude Code rather than the person
     using it, and deriving from it would collapse every analyst in an
     organization into one. The derivation is HMAC-SHA-256 under a deployment
     key over a domain-separated, length-framed encoding — keyed rather than a
     plain digest, because a subject is routinely an email or an employee number
     and an unkeyed digest of one is a dictionary attack away from recovery.
     Nothing is case-folded, trimmed or URL-normalized: those semantics are the
     IdP's. Call the result *pseudonymous*, never anonymous or irreversible.

138. **Only a delegate-verified token may become a tenant, and the wrapper is
     not a parser.** `StrictTokenVerifier` never reads the bearer string, so an
     opaque token an introspection endpoint proved is as acceptable as a JWT.
     Format-specific rules — signature, `active`, `nbf`, RFC 9068 `typ`,
     revocation — belong to the delegate; the wrapper enforces a non-empty
     subject, an exact issuer and an audience naming this resource, because the
     installed SDK checks none of the three. Two audience representations that
     disagree are refused rather than resolved conveniently. A permissive or
     development-mode verifier must never be reachable from a production
     composition; fakes live under `tests/`.

139. **The tenant key is durable deployment configuration, and is never
     rendered.** Not a provider key, not an access token, not the OAuth client
     secret. It has no default, an empty one is refused, and it must stay stable
     for an environment's life — Task 23 will key credential ownership on the
     identifiers it produces, so rotating it would orphan every stored
     credential. Never logged, serialized or included in an exception; not its
     value, and not its length, prefix or digest either.

140. **One shared application is safe only because identity is request-scoped.**
     Both profiles share one `InvestigationApplication`, one `ProviderExecutor`
     and one set of Task 6 stores; every tool invocation builds a fresh
     `ExecutionContext` whose principal comes from a `PrincipalSource`. Isolation
     lives in the *key*, which Task 6 already derives from
     `authenticated_user_id` for cache, cooldown, quota, concurrency and
     single-flight. An application per user would discard the cache for no gain;
     a server-wide `current_user` would be a race. The request id is fresh per
     call, never observable-derived, never caller-supplied, and appears in
     neither the internal result nor the public report.

141. **A remote runtime never reads the process environment for provider
     credentials.** A server's environment is global to the server: loading it
     would hand every authenticated analyst the same keys, spend one quota on
     everybody's behalf, share one abuse.ch fair-use block between strangers and
     use a provider account under terms nobody agreed to. `build_remote_runtime`
     passes `load_credentials=False`; stdio keeps its one-analyst startup load.
     An organization-wide shared credential is a deliberate deployment mode,
     never an implicit default.

142. **`provider_status` configuration is principal-scoped, and authentication
     is not configuration.** `configured` means *this* caller has the credential
     stored — read from the shared connection repository by user and group, one
     authoritative path, never a startup snapshot answering "the server has a
     key". Catalogue facts stay shared; `configured` stays a boolean, never a
     value, prefix, length, digest, connection id or secret reference. A fully
     authenticated analyst with no provider credentials gets a valid report with
     `NOT_CONFIGURED` coverage — a missing provider key is never an
     authorization failure.

143. **The remote surface never exposes `investigate_file`, and absence is not
     concealment.** A `path` names a file on the machine running the server:
     over stdio the analyst's own, over HTTP somebody else's — where the tool
     stops being file analysis and becomes an authenticated arbitrary-read
     primitive. It is not *registered* by the remote profile, so it is missing
     from `tools/list`, from the tool manager and from every callable name, and a
     hand-written `tools/call` fails as an unknown tool before a path is touched.
     Leaving it registered and undocumented would satisfy none of that. Stdio
     keeps all three tools and the `anthropic/requiresUserInteraction` metadata
     unchanged; a remote analyst hashes locally and submits the SHA-256. Both
     profiles share one implementation — the deployment profile is an assembly
     concern, never a second tool.

144. **One canonical resource URL, or the app refuses to build.** The same exact
     string is the audience `StrictTokenVerifier` requires, `AuthSettings`'
     `resource_server_url`, the RFC 9728 metadata `resource` and the `resource`
     a client sends; `build_remote_http_app` compares them rather than trusting
     them, because advertising one resource while accepting tokens for another
     is the confused-deputy shape and both halves look right alone. `/mcp` and
     `/mcp/` stay two resources. Construction also refuses an empty issuer or
     resource, a non-HTTPS resource, a path other than `/mcp`, an empty host
     allowlist, a wildcard host or origin and a missing delegate: there are no
     permissive production defaults.

145. **Transport security is stated, never implied, and nothing is derived from a
     request header.** `TransportSecuritySettings` is always passed with
     rebinding protection on and exact hosts, because the SDK auto-enables it
     only for a loopback host and otherwise falls back to protection *disabled* —
     a production hostname with no settings is silently unprotected. A wildcard
     host is refused outright: it disables the protection while appearing to
     configure it. An absent `Origin` is allowed, which is the ordinary
     non-browser client; a *present* unlisted one is `403`, and the allowlist is
     empty by default. `Host`, `X-Forwarded-*`, `Forwarded` and `Origin` are
     never read for the canonical resource, the issuer, the audience or the host
     policy — all four are configuration, so no proxy header can move a security
     decision and no proxy middleware is needed. TLS terminates at the ingress.

146. **Authorization happens before tools, once, at the boundary.** One scope,
     `ti-recon:investigate`, for the whole resource: `provider_status` is *less*
     privileged than an investigation and reveals only the caller's own setup, so
     a second scope buys no least privilege while costing a step-up flow. No tool
     contains a scope check — a second policy is the one somebody forgets to add
     to a new tool. TI Recon serves no `/authorize`, `/token`, `/register`,
     `/revoke` or `/login`: `auth_server_provider` is never supplied, so they are
     absent rather than unimplemented, and client registration (DCR or CIMD)
     belongs to the external authorization server. An auth failure names no
     received issuer, audience, subject, client id, bearer or tenant.

147. **A remote investigation is one per tenant per process, refused rather than
     queued.** An authenticated caller can open unlimited concurrent HTTP
     requests, and Task 13 bounds only the work *inside* one investigation. A
     caller told "try again" still has a working service; one behind an unbounded
     backlog has a slow one and a server holding memory for requests nobody
     awaits. The slot releases on completion, error **and cancellation** — a
     client going away mid-investigation is ordinary, and a leaked slot locks an
     analyst out for the process's life. `provider_status` never takes one: it
     contacts nothing, and blocking it removes the diagnostic exactly when
     somebody is working out why their investigation is stuck. The key is the
     pseudonymous tenant id alone, entries drop when a tenant goes idle, and
     Task 6's provider concurrency is untouched. Local stdio has no limiter.

148. **Remote deployment is single-worker, as a correctness requirement.**
     Task 6's cache, cooldown, quota and single-flight stores are process-local
     and so is the tenant limiter, so four workers would enforce each of them
     four times independently — four analysts' identical questions becoming four
     calls against a metered API, and one analyst holding four investigation
     slots. `stateless_http=True` removes the last server-side session so no
     sticky routing is needed, but shared execution state is Task 24's and until
     it exists a deployer runs exactly one worker.

149. **`/health` is public, verifier-free and says one thing.** Answered by the
     preflight gate *before* the SDK application is entered — an SDK custom route
     is unauthenticated but still sits behind the app-level authentication
     middleware, so a bearer sent to it was verified anyway. From the gate there
     is no middleware to sit behind: no `BearerAuthBackend`, no verifier, no
     principal resolver, no credential store, no executor, and the test uses a
     verifier that *raises* rather than one that counts. It still obeys the
     transport policy, carries no JSON requirement on a `GET`, and reveals no
     version, issuer, resource URL, provider count, tenant count, uptime or cache
     state. It is not called *readiness* — Task 18 owns that word for coverage
     adequacy, and one term meaning two things is how somebody acts on the wrong
     one. Tests enumerate both routing tables so a future route cannot quietly
     join the public set.

150. **Cheap transport checks run before token verification, and the order is
     TI Recon's to arrange.** The SDK installs `AuthenticationMiddleware` at the
     *application* level while `TransportSecurityMiddleware` runs inside the
     Streamable HTTP handler, so an untrusted `Host`, an untrusted `Origin` and a
     wrong POST content type each had their bearer verified first — and answered
     `401` rather than `421`/`403`, because the token was consulted before the
     host was. Verification is the most expensive thing in the path; for an
     introspection delegate it is a network call to the identity provider, so
     unauthenticated traffic must not be able to drive it. `RemoteHttpApp` hoists
     the checks in front of the whole SDK application:
     `Host -> Origin -> content type -> public route -> OAuth -> scope -> tool`.

151. **The gate reuses the SDK's transport semantics and reimplements no OAuth.**
     It delegates to the SDK's own `TransportSecurityMiddleware` rather than
     carrying a second wildcard parser, and both enforcement points are built
     from the same `RemoteHttpConfig` — one configuration, never two policies,
     and no `pre_auth_*` or `*_skip_auth` flag, because these are mandatory
     semantics rather than options. The inner check stays enabled as defence in
     depth, so a mistake in the gate cannot silently disable the SDK's; a test
     drives the inner application directly to prove it still refuses. The gate
     parses no `Authorization` header, reads no bearer, understands no scope,
     builds no `WWW-Authenticate` and generates no metadata: it decides only
     whether a request is *eligible* to reach the authenticated application.

152. **Public metadata stays the SDK's, and the bearer is dropped rather than
     verified.** RFC 9728 metadata is unconditionally public — a client reads it
     because it was refused — so a token sent there is meaningless, and the gate
     removes the header on that exact path instead of letting the SDK verify one.
     Nothing is copied, rebuilt or re-routed; the document is byte-identical with
     and without a bearer. The path match is exact and fails safe: matching too
     broadly would strip a bearer from a protected path, which becomes a `401`
     rather than access. TI Recon builds no OAuth document of its own.

154. **The production verifier trusts a token only after its signature, and never
     a key URL the token names.** `alg` comes from the configured allowlist, so
     `alg: none` and every unlisted algorithm are refused before a key is looked
     up; `jku` and `x5u` are never read, so a token cannot point key retrieval at
     a host it controls. Asymmetric only — HS256 is not configurable at all,
     because a resource server should verify with the authorization server's
     *public* key and never hold its signing secret, and HS256 beside RS256 is
     the key-confusion attack. Issuer and audience are exact; a token may carry
     other audiences as long as ours is among them. No JWT library option that
     skips a verification appears anywhere in production source, and a static
     test reads the AST to keep it that way.

155. **Only four values cross from a verified token into the request context.**
     Issuer, subject, scopes, expiry. Not the raw JWT — nothing in the SDK's
     resource-server path reads `AccessToken.token`, so a placeholder goes there
     — and not the decoded payload, because an access token routinely carries a
     name, an email and an organization that have no business in a ContextVar
     later code can read. Scopes come from the standard space-delimited `scope`
     claim alone; a provider-specific permissions claim is never merged in.
     `client_id`/`azp` names the OAuth *client* and is never human identity.

156. **Key retrieval is bounded, cached, coordinated and fails closed.** Only the
     configured `jwks_url`, redirects disabled, system CA verification, bounded
     timeout, response-size ceiling, key-count limit and content-type check — an
     external document must not be able to allocate arbitrary memory or move the
     endpoint. An unknown `kid` triggers one refresh that concurrent requests
     share, behind a floor that stops forged key ids amplifying requests at the
     identity provider; the cost is that rotation is visible within that interval
     rather than instantly, which is why authorization servers publish a key
     before signing with it. A malformed refresh never replaces working keys, and
     an unreachable JWKS endpoint authenticates nobody.

157. **Startup contacts no identity provider, and neither do the public routes.**
     Keys arrive with the first authenticated request, so `/health` and the RFC
     9728 metadata endpoint keep answering during an IdP outage while
     authentication fails closed. Deployment liveness is not identity-provider
     reachability, and a probe that failed on an IdP hiccup would take a working
     server out of rotation for something it does not need to be alive.

158. **The remote process fails closed before it listens.** A missing or short
     tenant derivation key, an `http://` resource, a path other than `/mcp`, a
     wildcard host or origin, a symmetric algorithm — each refuses to start
     rather than starting degraded. The tenant key is never generated at startup:
     a fresh one would give every analyst a new identity on every restart and
     orphan whatever Task 23 stored. Configuration is `TI_RECON`-prefixed
     environment only; nothing generic is read, and no provider credential is
     read at all. The public resource URL and the internal bind are separate, and
     the OAuth audience is always the former.

159. **A cached JWKS set has a finite life, and an expired one is discarded.**
     Revocation only means something if a key stops being accepted: an
     authorization server that retires a compromised key removes it from the
     document, and a resource server trusting an already-known `kid` forever
     would keep accepting freshly forged tokens for the life of the process —
     token `exp` is no help, because whoever holds the private key mints new
     ones. The set is *dropped* at expiry rather than refreshed-before-use, so
     there is no branch anywhere that can serve a stale key when a refresh fails.
     An expired cache plus an unreachable identity provider **fails closed**,
     with no grace period; only a document that fetched *and* parsed starts a new
     freshness window. Lifetime and the anti-flood floor are two controls for two
     threats and never one timestamp, and a lifetime shorter than the floor is
     refused at construction.

160. **A JWK that was not published for verification never verifies.** `use` other
     than `sig`, or a `key_ops` that omits `verify`, means the publisher said so
     on purpose (RFC 7517 §4.3); an empty, duplicated, non-list or non-string
     `key_ops` is a JWK this layer will not interpret, and an uninterpretable key
     is not one to verify with. Eligibility is decided *before* uniqueness, so an
     encryption key sharing a `kid` with a signing key is ordinary rather than an
     ambiguity — two *eligible* keys sharing one is the ambiguity, and still
     refuses the document.

161. **Library defaults are not security controls.** PyJWT only *warns* about an
     RSA modulus below NIST SP 800-131A's 2048-bit floor unless
     `enforce_minimum_key_length` is set, and it coerces a string `exp` or `nbf`
     through `int()`; an object `iat` raises a bare `TypeError` that would escape
     the verifier entirely. Each is checked explicitly, and the dependency floor
     excludes releases missing the `crit` handling this layer depends on. Where
     PyJWT refuses to *encode* something malformed, that is never evidence the
     consumer rejects it — an attacker is not constrained by our encoder, so
     adversarial tokens are built at the JWS layer.

162. **The tenant derivation key is decoded key material, not a passphrase.**
     base64url, at least 32 decoded bytes, generated by something
     cryptographically secure outside this process, and strictly decoded — the
     variable is named `..._B64` because an operator reading a bare "key" will
     reasonably type a memorable string, and HMAC-SHA-256 takes a key. A
     character count would have passed one. It is never generated at startup and
     never stretched, and changing it changes every tenant identifier — which,
     after Task 23, disconnects analysts from their stored provider credentials.

163. **The interpretive contract travels with the protocol, never with a Skill.**
     `.claude/skills/ti-recon-analyst/` is a filesystem artifact of this
     repository; a client that merely connects the server — Claude Web through
     the hosted connector — receives the server `instructions`, the tool
     `description`s and the report's `outputSchema`, and nothing else. So every
     rule whose loss produces a *confidently wrong* answer lives in those three:
     `INCONCLUSIVE` is not clean, `not_configured` is a check that never ran
     rather than one that found nothing, `no_data` is not safety, a `cache_hit`
     is a completed check that made no request, `configured` is not validated,
     confidence is not a probability of maliciousness, readiness is not
     permission to act, `source_checks` is the authority for what was consulted,
     `assessed=false` is a relationship rather than an indicator, and a client's
     own knowledge must be labelled as its own rather than presented as TI Recon
     evidence. Field `description`s are contract, not decoration — they are the
     only per-value vocabulary an MCP client has. The Skill reinforces, organises
     and illustrates; if deleting it would make MCP-only interpretation wrong or
     ambiguous, the *contract* is incomplete. A test asserts the whole of it over
     a live protocol session and opens no Skill file.

164. **Provider credential setup is deployment-specific, and stated rather than
     implied.** "Configure it locally and reconnect" is true over stdio, where
     the analyst owns the process and the environment it reads once at startup.
     It is nonsense addressed to a hosted caller, who has no server to edit and
     no process to restart — and left unsaid, a client supplies exactly that
     local model from general knowledge, which is what happened in live use. So
     `STDIO_INSTRUCTIONS` keeps the local advice and `REMOTE_INSTRUCTIONS` says
     the check did not happen, that self-service provider credential setup is not
     available in this version, and that no provider API key may reach a
     conversation, a tool argument, a prompt or a header. Neither promises
     Task 23. The analyst *report* carries no setup advice at all, in either
     deployment, because one rendering serves both.

165. **A plain sentence precedes every internal identifier, and replaces none.**
     The text renderer prints the machine verdict and coverage value *and* a
     fixed sentence saying what each claims, keyed on the enum value so a verdict
     without one is impossible, and glosses the three run statuses a reader turns
     into reassurance or into an outage. Restatement, never derivation: no
     ranking, no weighing, nothing the layer that owns the decision did not
     already say. Dropping the machine value in favour of prose would make the
     text disagree with the JSON about what the engine concluded, which is worse
     than the ambiguity it fixes.

166. **A plugin option reaches the engine only as an environment variable the
     loader already reads, and a secret never reaches model context.** The
     path is plugin configuration → Claude Code sensitive plugin storage →
     `${user_config.KEY}` substituted into `.mcp.json` `env` → the server
     process environment, read once → `load_environment_credentials` → the
     per-user store → `CredentialResolver` → `_apply_auth`. It never passes
     through Skill content (no `${user_config.*}` there, and the host refuses
     sensitive ones anyway), a prompt, a tool argument, `instructions`, a tool
     description, a report, a log, stderr or an exception. A test drives the
     real server — in process and as the installed subprocess with stderr
     captured at `DEBUG` — with sentinel credentials and searches every surface.
     The plugin is a distribution layer: nothing under `src/ti_recon` reads
     `CLAUDE_PLUGIN_*`, `user_config` or a plugin path.

167. **One credential system, keyed by group, every credential optional.** The
     plugin declares exactly one `sensitive` option per credential group the
     shipped adapters draw from — derived, not restated, so a new credentialled
     provider fails the suite until the plugin offers it — and asks for the
     abuse.ch key once. No option is `required` and none has a `default`: an
     analyst with one key, or none, gets a server that starts and reports the
     rest `not_configured`. An unset option substitutes to the empty string,
     which the loader already treats as absent, so no boundary change was
     needed and no plugin-specific store, loader or repository exists.

168. **The setup step a client is told is the one that applies, and it fits the
     host.** `TI_RECON_CREDENTIAL_SETUP` selects `LocalCredentialSetup`:
     `environment` (default, unchanged) or `claude-plugin`, whose instructions
     and `provider_status` description say a credential is entered in the
     plugin's configuration and never advise an environment variable the
     plugin's mapping would overwrite. An unrecognised value refuses to start,
     on stderr, without echoing it. Claude Code truncates `instructions` to
     2048 characters, and the deployment sentence is last in every profile, so
     each complete profile is held under that limit by a test.

169. **The plugin starts the server through `uv` directly, from an immutable
     root into a persistent data directory.** `.mcp.json` runs `uv run
     --project ${CLAUDE_PLUGIN_ROOT}/runtime --locked --no-dev --no-editable
     --no-env-file --python 3.12 ti-recon-mcp` with
     `UV_PROJECT_ENVIRONMENT=${CLAUDE_PLUGIN_DATA}/runtime-env`: no shell, no
     launcher, no top-level `bin/`, no working-directory dependency, no
     `.env`, an exact lock that refuses a disagreeing `pyproject.toml`, a real
     install rather than a link to the source, and a deterministic interpreter
     series `uv` provisions if the workstation has none. Code lives under the
     versioned root and is never written to; state lives under the data
     directory, survives plugin updates, and holds no credential — those stay
     in the host's sensitive plugin storage. Concurrent first starts are safe
     (`uv` locks the environment); a damaged interpreter or metadata is
     repaired on the next start; an environment path that is not a directory
     fails closed on stderr with nothing on stdout. Tests run every one of
     those through the real `uv` from outside the repository with a scrubbed
     environment and assert no imported path leads back to the checkout.

170. **The Skill and the runtime each have one canonical source.**
     `.claude/skills/ti-recon-analyst/` and the repository project are
     canonical; the plugin's copies are byte-identical, regenerated by
     `tools/sync_plugin_skill.py` and `tools/sync_plugin_runtime.py` from an
     explicit manifest, never edited, never symlinks, and a test fails on
     drift in either direction. The runtime manifest is `pyproject.toml`,
     `uv.lock`, `README.md`, `src/ti_recon/` and a `.python-version` derived
     from `requires-python` — nothing else, so an unrelated repository change
     never obliges a resync and nothing a build does not need ships.

153. **The gate is a raw ASGI wrapper, and lifespan ownership does not move.**
     Not a `Mount`: lifespan events pass through unexamined to the SDK
     application, which keeps owning the Streamable HTTP session manager —
     `run()` refuses a second call on one instance, so it must start exactly once
     per process, never per request and never in a wrapper. A test builds the app
     with no lifespan at all and asserts `/mcp` raises while `/health` still
     answers, so no other test in that file can be passing because a fixture
     started something a real ASGI server would not.


## Security rules

- **No secrets in the repo.** `.env` is git-ignored; `.env.example` holds
  variable names only, never values.
- Provider credentials must never appear in Claude prompts, the Skill, MCP
  arguments, git, logs, exceptions, or serialized provider results.
- `ProviderConnection` stores a `secret_reference`, never the secret. Secret
  material lives in `SecretStr` and is verified absent from `repr()`, `str()`,
  `model_dump()`, JSON dumps, and exception text by tests.
- `ProviderRequest` carries **no** credentials. Auth is applied inside the
  transport layer at request time.
- **Cross-user isolation.** Credential resolution is always scoped by
  `authenticated_user_id` + provider/credential group. A caller can never
  resolve another user's secret. Covered by explicit tests.
- **No direct IOC fetching.** There is deliberately no
  `fetch_arbitrary_url(...)`. `ProviderHttpClient` is pinned to one configured
  provider base URL and accepts only relative paths; cross-host requests raise
  `ProviderTransportSecurityError`. Suspicious URLs are investigated *through*
  provider APIs (e.g. urlscan), never by TI Recon browsing them.
- Logging allow-list: provider, method, path/operation, status, latency,
  request id. Never log Authorization / `x-apikey` / `API-Key` / `Auth-Key` /
  cookies / secrets / sensitive query strings.
- **Artifact paths are derived, never provider text.** A storage key is
  `sha256(user|investigation)[:32]/<kind>/<content sha256>`; a provider-supplied
  filename, URL, domain or scan title never influences a path, and the model
  rejects a key it did not derive.
- **urlscan search queries are composed, never accepted as text.** Fields come
  from a `StrEnum` allow-list and values must match the shape their field holds,
  so a value cannot become query syntax.
- **urlscan results are user-scoped in the cache.** An authenticated search can
  return unlisted or team-private scans; `CacheScope.GLOBAL` is never enabled.
- **A digest is modelled as what it identifies.** A Censys certificate
  fingerprint becomes an `x509-certificate` object and a body hash stays a pivot
  string; neither becomes a `file`. A TI Recon `file` hash is never reinterpreted
  as a certificate fingerprint, even though both are 64 hex characters.
- **Provider-authored text is never stored.** Censys service banners, HTTP
  bodies, headers and HTML titles are all present in a response and none are
  read; GreyNoise user-agent strings are not stored either. What is kept is the
  shape of the observation — port, protocol, product, digest — under an explicit
  per-block allow-list with every list capped and truncation recorded.
- **Credits and rate limits are different resources.** A Censys `429` is a
  throttle that lifts by itself; a `402` or a zero balance is a spent wallet that
  no wait refills. A balance reading with no readable counter produces an *empty*
  quota snapshot, never a zero bucket: not knowing means Task 6 may try, while
  zero stops the provider being called at all.
- **A provider with no zero-cost allowance endpoint gets no quota snapshot.**
  GreyNoise's results carry a `RateLimitSnapshot` when the response said
  something measurable and nothing otherwise. Inventing an allowance would let
  the quota pre-check disable a working provider without ever calling it.
- **A Censys organization id is per-connection, non-secret configuration.** It
  lives in `ProviderConnection.metadata`, is resolved by user *and* connection so
  one analyst can never read another's balance, and is shape-checked before it
  reaches a path.
- **GTI's quota endpoint puts the API key in its path.** Never build, return,
  log, cache or attach that path to an error. Failures report
  "GTI quota lookup failed" plus a normalized category only.
- **A credential shared between providers is still per-user, and one
  provider's refusal never invalidates it.** One `abuse_ch` Auth-Key serves
  ThreatFox, URLhaus and MalwareBazaar; resolution is scoped by
  `authenticated_user_id` plus group, and `user_blacklisted` — abuse.ch's
  fair-use block — is a `PERMISSION_ERROR` that leaves the credential
  `ACTIVE`. Only a rejected key marks it invalid. The API documentation states
  no duration for a block, so the abuse.ch layer asks Task 6 for a configurable
  6-hour credential cooldown rather than modelling a ban length it cannot know.
- **Where parameters travel in the request body, the credential must not.** The
  Auth-Key is written only to the `Auth-Key` header, never to a form field, path
  or query string: a request log that captures bodies would keep it otherwise.
  The shared transport is the only thing that reads the secret, and tests assert
  the key is absent from every body, URL, log record and cache key.
- **A provider response is data, never navigation.** TI Recon never contacts a
  URL URLhaus reports, never downloads a MalwareBazaar sample and never uploads
  one. `ALLOWED_QUERIES` / `ALLOWED_PATHS` make those unreachable rather than
  merely unused, and no rate limit is ever evaded by rotating keys, switching
  accounts or scraping a web interface.
- **A local dataset is read with the care given to untrusted input.** A snapshot
  directory is operator-supplied, not trusted: slugs are pattern-checked before
  they touch a path, resolved paths must stay inside the snapshot root (which
  also catches a symlink out of the tree), file sizes are bounded before the
  read, and per-list checksums are verified before a file is parsed. A manifest
  that fails validation reports a stable message rather than echoing content.
  Diagnostics are counts and short reasons — never raw list contents, which
  would make a log a dataset leak.
- **No warninglist regex is ever executed.** Upstream patterns are PHP
  `preg_match` with delimiters and flags Python does not have, and the pinned
  snapshot's two regex lists target email and phone attributes TI Recon cannot
  produce. Patterns are recognized and counted, never compiled and never run, so
  there is no catastrophic-backtracking hang to have. If a future snapshot adds
  an *applicable* regex list, the lookup reports `PARTIAL` rather than skipping
  it silently.
- **Nothing is ever submitted to or downloaded from a sandbox.** The Hybrid
  Analysis client can issue exactly three `GET`s, checked against a frozen
  `ALLOWED_PATHS` before a request is built: submission, detonation, quick scan,
  `overview/*/refresh` and every artifact download are unreachable rather than
  merely unused. A provider-returned report URL, domain, host or file path is
  data and must never become an HTTP destination.
- **A sandbox report carries other people's submission metadata, and it is never
  read.** `document_password`, `comment`, `environment_variable`,
  `custom_commandline` and `custom_system_date_time` belong to whoever uploaded
  the sample — possibly years ago, possibly another organization's incident — and
  `EXCLUDED_DETONATION_FIELDS` is data with a reason per field so a test asserts
  it. Only the execution context that bears on analysis quality is kept. Process
  `icon` (base64) is never read either.
- **Observed process command lines are untrusted text, not instructions.** They
  are bounded, stripped of control characters, and never executed, interpolated
  into a shell, or allowed to choose an endpoint, a file or a destination. The
  same holds for signature descriptions, file names and provider warnings.
- **A response that returns your own credential is read by allow-list.** Hybrid
  Analysis's `/key/current` body contains the API key; the reader builds a
  two-field dictionary rather than filtering a copy, so the key is never picked
  up, and the endpoint is never called before a lookup.
- **Relayed AV and machine-learning output is not adopted.** GTI already provides
  direct reputation; counting Hybrid Analysis, its relayed VirusTotal figure and
  a direct GTI result as three sources is exactly the inflation the lineage rules
  prevent.
- **The two-source-address-per-hour limit is respected, not circumvented.** One
  Hybrid Analysis key may use the API from at most two IP addresses per hour. No
  egress rotation, no key rotation, no multiple accounts; a scaled deployment
  needs stable centralized egress.
- **A qualification carries no secret, because qualification cannot reach one.**
  `reasoning/` imports no credential module, no secret store and no HTTP client,
  and never mentions `SecretStr`; a test asserts it. Signals and cues name
  providers, source families and lineage groups — never credentials, connection
  ids or tokens — and structured detail accepts only short scalars, so a provider
  payload cannot ride into a cue. Qualification metrics are counts and enum
  members with no field that can hold an observable, a warninglist slug, a node
  key, an investigation id or a user, which matters here because this layer sees
  everything every provider returned.
- **Alternative-explanation reasoning carries no secret, because it cannot reach
  one.** `reasoning/false_positive/` imports no credential module, no secret
  store and no HTTP client, and never mentions `SecretStr`; a test asserts it.
  Findings reference evidence ids, Task 15 refs and canonical node keys — never
  credentials, connection ids or tokens — and its metrics are counts plus two
  closed enum vocabularies with no field that can hold an observable, a user or
  an investigation id.
- **An assessment carries no secret, because fusion cannot reach one.**
  `reasoning/claims/` and `reasoning/fusion/` import no credential module, no
  secret store and no HTTP client, and never mention `SecretStr`; a test asserts
  it. Claims reference evidence ids and canonical keys, never credentials or
  tokens, and fusion metrics are counts plus four closed vocabularies with no
  field that can hold an observable, a hash, a URL, a user or an investigation id.
- **A correlation graph carries no secret, because correlation cannot reach one.**
  `correlation/` imports no credential module, no secret store and no HTTP client,
  and never mentions `SecretStr`; a test asserts it. Node occurrences and
  assertions name providers and source families — never credentials, connection
  ids or tokens — and correlation metrics are counts and enum members with no
  field that can hold an observable, a node key, an investigation id or a user.
- **A planning trace carries no secret, because planning cannot reach one.**
  `planning/` imports no secret store, no `SecretStr` and no HTTP client, and a
  test asserts it. Planning metrics are enum members, bounded provider ids, small
  integers and bools — no observable value and no free text, so a metrics pipeline
  can never become a log of everything every analyst has investigated.
- **GTI data is provider-policy-sensitive.** Do not expose raw or normalized GTI
  content to Claude, MCP or any AI layer before the applicable Google Threat
  Intelligence data-use terms have been reviewed. See `docs/providers/gti.md`.
- **An MCP access token is never a provider credential.** It authorizes an
  analyst to call TI Recon and must never be forwarded to GTI, VirusTotal,
  urlscan, GreyNoise, Censys, abuse.ch, Hybrid Analysis or anything else — they
  are different credentials from different trust domains. The only path to a
  provider secret is `CredentialResolver` -> `CredentialMaterial` -> the
  transport's `_apply_auth`, and nothing below `mcp_server/` can reach an access
  token at all. A runtime regression drives the real seam with a planted token
  and asserts it reaches no provider request, report, result, log or exception.
- **A rejected transport request never reaches the token verifier.** An
  untrusted `Host` or `Origin`, a wrong POST content type and every request to
  `/health` are answered before the SDK's authentication middleware is entered.
  Verification is the one step that may make a network call to an identity
  provider, so unauthenticated traffic must not be able to drive it — and the
  tests prove it with a verifier that raises rather than a counter.
- **A raw subject never travels below the MCP layer, and neither does a raw
  issuer.** What crosses is a keyed `tenant-v1:` HMAC, so a subject that is an
  email address or an employee number never reaches a cache key, a cooldown key,
  a quota key, a metric or a credential record. The tenant key itself is a
  deployment secret held in `SecretStr`, absent from `repr`, never serialized,
  and never logged — not as a value, a length, a prefix or a digest.

## Commands

```bash
uv sync --all-extras          # install dev environment
uv run ruff format .          # format
uv run ruff check .           # lint
uv run mypy src               # type check (strict)
uv run pytest -q              # tests
uv run pytest -q --cov=ti_recon --cov-report=term-missing
```

## Directory responsibilities

```
src/ti_recon/
  enums.py           shared vocabularies (object types, verdicts, statuses, grades)
  models/            Task 3 data model: intel objects, investigation, evidence,
                     relationships, coverage, assessment
  normalization/     observable parsing/normalization (defanging, IDNA, hashes).
                     Pure functions, no network, no DNS resolution.
  credentials/       Task 4: per-user provider connections, secret store
                     abstraction, credential manager + user-scoped resolver
  providers/         Task 5: capabilities, descriptor, request/result envelope,
                     quota models, normalized errors, adapter contract,
                     registry, HTTP transport
  providers/gti/     Task 7: Google Threat Intelligence. client (the only
                     vt.Client user), config/x-tool, errors, quota, policy,
                     relationships, normalizer, adapter
  providers/urlscan/ Task 8: urlscan.io. client (read-only by construction),
                     config, descriptor, errors, quota, search (query building +
                     bounded candidate selection), normalizer, observations,
                     forensics (static extraction), policy (forensics gate),
                     adapter
  providers/greynoise/ Task 9: GreyNoise. client (two v3 reads, read-only by
                     construction), config, descriptor, errors, access (full vs
                     Community, per credential), metering, normalizer, policy,
                     adapter
  providers/censys/  Task 9: Censys Platform. client (four reads, no search),
                     config, descriptor, errors, assets (deterministic asset
                     identity), credits (zero-cost balance), organizations
                     (per-connection id), normalizer, policy, adapter
  providers/abusech/ Task 10: what the three abuse.ch platforms share. family
                     (source family, credential group, relay origins), values
                     (bounded readers), config (three fixed origins, Auth-Key
                     header), errors (`query_status` -> categories), client
                     (POST transport, form or JSON per platform, gated by a
                     frozen query allow-list), evidence (context +
                     relayed-summary builder), policy
  providers/threatfox/ Task 10: ThreatFox. client (search_ioc, search_hash),
                     config, descriptor, matching (loose matches re-validated by
                     parsing only), normalizer, policy, adapter
  providers/urlhaus/ Task 10: URLhaus. client (three path-routed reads), config,
                     descriptor, normalizer (exact URL vs host association,
                     payload provenance, relays), policy, adapter
  providers/malwarebazaar/ Task 10: MalwareBazaar. client (one read; no
                     download, no upload), config, descriptor, normalizer (one
                     assertion, signing, YARA, vendor names only), policy,
                     adapter
  providers/misp_warninglists/ Task 11: MISP Warning Lists. models (raw upstream
                     schema, manifest, diagnostics), snapshot (local reader: path
                     safety, checksums, staleness), profile (include/exclude,
                     entry ceiling, fingerprint), candidates (observable -> MISP
                     attributes), matchers (string/substring/hostname/cidr;
                     regex recognized, never run), loader (compiled index),
                     config (no host, no credential), descriptor, normalizer,
                     policy, adapter
  sandbox/           Task 12: provider-neutral dynamic analysis. models (sample /
                     report / environment / quality vocabulary; no verdict maps
                     to SUPPORTS_BENIGN), selection (bounded deterministic
                     representative choice), bounds (per-depth caps)
  providers/hybrid_analysis/ Task 12: Hybrid Analysis (Falcon Sandbox). config
                     (api-key header, User-Agent), descriptor (FILE_BEHAVIOR,
                     files only), errors (statuses + quota prose; 410 as a
                     state), client (three GETs behind a frozen path
                     allow-list), models (raw -> neutral; privacy exclusions),
                     normalizer, policy (request budget per depth), adapter
  artifacts/         Task 8: bounded, user-isolated, provider-neutral storage
                     for retrieved screenshots, DOM snapshots and response
                     bodies
  execution/         Task 6: clock/sleeper/jitter seams, cache, retry+backoff,
                     quota + cooldown stores (provider-scoped, plus a
                     credential-scoped key for a refused credential),
                     concurrency + single-flight, policy, bounded executor,
                     metrics
  correlation/       Task 14: investigation graph and controlled pivots. models
                     (nodes, edges, assertions, issues, limits), identity (exact
                     keys + conservative file-hash resolver), relationships
                     (canonical vocabulary, orientation, pivot safety), graph
                     (dicts + adjacency, bounded, deterministic), engine
                     (ingest provider results), policy (modes, budgets, hop),
                     pivots (candidates + lexicographic ranking), orchestrator
                     (root -> correlate -> pivot via Task 13), results, metrics
  reasoning/         Task 15: temporal + context qualification. models (typed
                     instants, lifecycle, signals, cues, issues), temporal
                     (deterministic ageing against an explicit as_of), extraction
                     (the provider contract; no clock), policy (versioned exact
                     warninglist slug map, clock-skew tolerance), context
                     (relayed-source dependence), cues (data-driven rules; one
                     edge-scoped rule), engine (vendor-neutral composition),
                     results, metrics, catalog (the only module here that may
                     name a provider)
  reasoning/claims/    Task 17A: provider-neutral claim semantics. models
                     (ClaimSemantic, NormalizedClaim, ClaimPropositionKey,
                     assertion strength), translation (the provider contract),
                     policy (versioned compatibility table), registry (the only
                     module in the claim and fusion packages that may name a
                     provider)
  reasoning/fusion/  Task 17B-D: independence, corroboration and assessment.
                     models (confidence bands, dispositions, decision roles,
                     contributions, the assessment), independence (grouping by
                     originating family), dispositions (reading Task 16 exactly),
                     policy (decisive/weak semantics, verdict and confidence rule
                     ids, caps), confidence (bands and caps, decided separately
                     from the verdict), engine, results, metrics
  application/       Task 20: the transport-neutral public boundary. models
                     (AnalystInvestigationRequest, observable input types),
                     service (input -> Task 19 -> report; local file hashing),
                     composition (the default application: every shipped
                     provider, the execution stores, credential loading)
  providers/catalog.py
                     Task 20: the authoritative shipped-adapter list, the
                     counterpart to planning/catalog.py
  reporting/         Task 20: the analyst output contract. models (versioned
                     report, bounded sections), builder (projection, never
                     analysis), text (deterministic rendering, terminal-injection
                     safety), schema (generated, dialect read from Pydantic)
  mcp_server/        Tasks 21-22: the MCP server, the remote identity boundary
                     and the authenticated HTTP surface. models (the
                     configuration diagnostic, the only contract this layer
                     owns), runtime (one shared application, request-scoped
                     identity, the stdio and remote composition roots), auth (the
                     strict resource-server token check and the principal
                     resolver), principal (RemotePrincipal and the keyed tenant
                     derivation), limits (one investigation per tenant), tools
                     (the three implementations and the error policy), server
                     (the two deployment profiles, annotations and resources),
                     http (the preflight gate, the ASGI app, its fail-closed
                     configuration and /health), jwt_auth (the production
                     JWT/JWKS verifier, vendor-neutral), http_main (the
                     single-worker remote process and its environment
                     configuration), main (stdio process)
  cli/               Task 20: the `ti-recon` command. parser (argparse; no
                     credential or provider flags), main (streams, exit codes),
                     runtime (the one composition root a local invocation uses)
plugins/ti-recon/    Task 23: the Claude Code plugin. .claude-plugin/plugin.json
                     (manifest, userConfig), .mcp.json (the stdio server started
                     through uv, and its environment mapping), runtime/ (a
                     generated byte-identical copy of the project: pyproject,
                     lock, README, src/ti_recon, .python-version),
                     skills/ti-recon-analyst (byte-identical copy of the
                     project Skill). Never edited by hand: see tools/
  investigation/     Task 19: end-to-end orchestration. models (request, round,
                     stop reasons, directives, workflow version), analysis (the
                     one Task 15-18 pass), continuation (readiness -> capability
                     directives), merge (deterministic multi-round enrichment
                     view), engine (the loop), results, metrics, composition (the
                     only module here that may name a provider)
  reasoning/readiness/  Task 18: assessment readiness and coverage adequacy.
                     models (two axes, completion vs yield, requirements, gaps,
                     information needs), policy (versioned materiality, basis
                     strength, status derivation), coverage (the capability
                     ledger; every ProviderRunStatus mapped on purpose),
                     requirements (derived from Task 13 goals, never restated),
                     gaps, engine, results, metrics
  reasoning/false_positive/
                     Task 16: alternative-explanation reasoning. models (roles,
                     dimensions, reason codes, typed links, does-not-establish
                     boundaries, content-derived ids), policy (versioned rule
                     ids, reason semantics, boundaries, message templates),
                     index (read-only lookups over evidence, signals, cues,
                     temporal facts and graph edges), rules (fifteen
                     deterministic rules), engine, results, metrics
  planning/          Task 13: adaptive enrichment planning. models (locality,
                     cost class, novelty, budgets, decisions, result), goals
                     (capability goals + activation), policy (per-depth budgets,
                     goal templates, profile registry), state (coverage per
                     capability and source family), ranking (RANKING_FACTORS,
                     lexicographic key), planner (no I/O, deterministic),
                     orchestrator (plan -> execute -> observe), metrics,
                     catalog (the only module here that may name a provider)
  providers/*/claim_semantics.py
                     Task 17A: each provider's pure translation of its own
                     directional evidence into generic propositions. Structured
                     field knowledge — ThreatFox's threat_type, GTI's verdict
                     vocabulary, a sandbox's verdict — lives here and nowhere else
  providers/*/qualification.py
                     Task 15: each provider's pure translation of its own
                     already-normalized result into the generic temporal and
                     context vocabulary. Provider field-name knowledge lives
                     here and nowhere else
  security.py        credential-key guards and text redaction
  versions.py        ENGINE_VERSION / POLICY_VERSION audit stamps
tests/unit/          unit + contract tests
tests/fixtures/      model-only and fake-adapter fixtures (no network)
src/ti_recon/data/   Task 11: the pinned MISP warninglist snapshot (manifest +
                     per-list files), packaged as application data and resolved
                     with importlib.resources so a checkout, an editable install
                     and an installed wheel all find it. Refreshed only by
                     tools/, never at runtime; the packaged copy is an immutable
                     baseline and `snapshot_root` overrides it
tools/               operator scripts. update_misp_warninglists.py (Task 11:
                     build a snapshot from a local checkout; the only code that
                     runs git), measure_misp_warninglists.py (footprint report),
                     sync_plugin_skill.py and sync_plugin_runtime.py (Task 23:
                     keep the plugin's Skill and runtime copies identical to
                     the repository; --check fails the suite on drift)
docs/                scope, architecture, data model, credentials, provider
                     framework, provider execution, artifacts, sandbox, mcp,
                     remote-mcp, claude-plugin,
                     providers/gti, providers/urlscan, providers/greynoise,
                     providers/censys, providers/threatfox, providers/urlhaus,
                     providers/malwarebazaar, providers/misp-warninglists,
                     providers/hybrid-analysis,
                     planning/adaptive-enrichment,
                     correlation/investigation-graph,
                     correlation/controlled-pivots,
                     reasoning/temporal-evidence,
                     reasoning/context-qualification,
                     reasoning/false-positive-reasoning,
                     reasoning/claim-semantics,
                     reasoning/evidence-fusion
```

## Conventions

- Python 3.12+, Pydantic v2, `httpx`, strict `mypy`, Ruff (line length 100).
- All provider I/O is `async`.
- Timestamps are timezone-aware UTC (`datetime.now(UTC)`); helper:
  `ti_recon.models.base.utc_now`.
- Enums are `str`-valued with STIX-friendly serialized names
  (`ipv4-addr`, `domain-name`, `file`, ...).
- Time, sleeping and jitter are injected in `execution/` (`Clock`, `Sleeper`,
  `JitterSource`). Never call `datetime.now()` or `asyncio.sleep()` directly
  there — tests must stay instant.
- Prefer `x if y is None else y` over `y or x` for optional collaborators:
  several define `__len__`, so an empty one is falsy and `or` silently discards
  it along with its configuration.
- File hashes are **properties of a `file` object**, not object types of
  their own.
- Findings TI Recon derives itself from raw content (a form posting off-origin,
  a masked input) are recorded as `CONTEXT_ONLY` observations. Turning them into
  a direction is engine interpretation and belongs to the assessment layer.
- A provider adapter reports and classifies. It never assigns an Admiralty grade
  (`source_reliability`, `information_credibility`) — those are TI Recon policy —
  and never emits a verdict, risk score or confidence.
- Docs must describe what exists. Never document planned work as done.
