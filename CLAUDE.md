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

Implemented (Jira Tasks 1-17):

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
- Decision readiness and coverage adequacy (Task 18). Task 17 says what
  assessment is justified; whether it is *sufficient* for a particular
  operational decision is a separate question that depends on the environment
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
- MCP server, Claude connector, Claude Skill, web frontend
- Active actions: URL/file submission, rescan, sandboxing, sample download

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
32. **A local dataset is pinned, provenanced and refreshed only by an operator.**
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
data/                Task 11: the pinned MISP warninglist snapshot (manifest +
                     per-list files). Refreshed only by tools/, never at runtime
tools/               Task 11: operator scripts. update_misp_warninglists.py
                     (build a snapshot from a local checkout; the only code that
                     runs git), measure_misp_warninglists.py (footprint report)
docs/                scope, architecture, data model, credentials, provider
                     framework, provider execution, artifacts, sandbox,
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
