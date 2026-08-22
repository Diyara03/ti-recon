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

Implemented (Jira Tasks 1-7):

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

**GTI is the only provider.** Other providers and evidence fusion are not
implemented, so there is still no multi-provider verdict.

**Not implemented — do not add without an explicit request:**

- Any other provider API integration (urlscan, GreyNoise, Censys, ThreatFox,
  URLhaus, MalwareBazaar, SecurityTrails, AbuseIPDB, Shodan, IPinfo)
- GTI Intelligence Search, Threat Profiles, Threat Lists, IOC Streams, DTM, ASM
- Any active GTI operation: submission, rescan, sandbox detonation, downloads
- Query/capability planner, provider selection, adaptive enrichment, evidence
  fusion, verdict scoring
- Redis or any distributed coordination: every execution store is in-memory and
  single-process
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
    outside an adapter.
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
    aggregate of other vendors' opinions is one source rather than many.

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
- **GTI's quota endpoint puts the API key in its path.** Never build, return,
  log, cache or attach that path to an error. Failures report
  "GTI quota lookup failed" plus a normalized category only.
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
  execution/         Task 6: clock/sleeper/jitter seams, cache, retry+backoff,
                     quota + cooldown stores, concurrency + single-flight,
                     policy, bounded executor, metrics
  security.py        credential-key guards and text redaction
  versions.py        ENGINE_VERSION / POLICY_VERSION audit stamps
tests/unit/          unit + contract tests
tests/fixtures/      model-only and fake-adapter fixtures (no network)
docs/                scope, architecture, data model, credentials, provider
                     framework, provider execution, providers/gti
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
- A provider adapter reports and classifies. It never assigns an Admiralty grade
  (`source_reliability`, `information_credibility`) — those are TI Recon policy —
  and never emits a verdict, risk score or confidence.
- Docs must describe what exists. Never document planned work as done.
