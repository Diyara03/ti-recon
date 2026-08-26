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

Implemented (Jira Tasks 1-12):

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

**GTI, urlscan, GreyNoise, Censys, ThreatFox, URLhaus, MalwareBazaar, MISP
Warning Lists and Hybrid Analysis are the only providers.** Evidence fusion is
not implemented, so there is still no multi-provider verdict.

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
- Query/capability planner, provider selection, adaptive enrichment, evidence
  fusion, verdict scoring
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
                     providers/hybrid-analysis
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
