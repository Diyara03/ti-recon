# TI Recon

TI Recon is an external **Threat Intelligence enrichment and analysis platform**.
An analyst submits an observable — an IP address, domain, URL or file hash — and
TI Recon queries external threat-intelligence providers, normalizes their
responses into structured **evidence** with full source provenance, and will
eventually produce an explainable, auditable assessment.

## Current development state

This repository currently contains the foundation plus its first provider
(Jira Tasks 1-7):

| Task | Scope | State |
|------|-------|-------|
| 1 | Product scope + investigation workflow foundation | Implemented (docs + vocabularies) |
| 2 | Platform architecture foundation | Implemented (docs + module boundaries) |
| 3 | Common TI data model | Implemented |
| 4 | Per-user provider credential foundation | Implemented (in-memory store only) |
| 5 | Provider integration framework | Implemented (contract, registry, transport) |
| 6 | Provider execution controls | Implemented (in-memory, single-process) |
| 7 | Google Threat Intelligence integration | Implemented (passive enrichment) |

**One provider is integrated.** Google Threat Intelligence performs passive
enrichment using each analyst's own VirusTotal API key. There is no urlscan,
GreyNoise, Censys, ThreatFox, URLhaus or MalwareBazaar client yet, and there is
no query planner, no provider selection, no evidence fusion, no verdict scoring,
no MCP server and no Claude Skill. Those are later Jira tasks.

Task 6 added the execution layer every adapter runs behind — caching, retry and
backoff, rate-limit and quota tracking, cooldowns, bounded concurrency and
request coalescing. All of its state is **in-memory and single-process**: a
development foundation, not distributed coordination.

### Providers

| Provider | Status | Supported | Not yet |
|----------|--------|-----------|---------|
| Google Threat Intelligence | Implemented | IP / domain / URL / hash passive enrichment, GTI assessment, threat severity, aggregated reputation, quota awareness, bounded relationships, selected threat associations, deep file behaviour | Intelligence Search, active scanning, sample submission, sample downloads |

GTI supplies **evidence**, not verdicts. Weighing it against other providers and
reaching a conclusion is the future evidence-fusion layer's job, and no such
layer exists yet. See [docs/providers/gti.md](docs/providers/gti.md).

## Architecture (high level)

```
Analyst
   |
Claude + TI Analyst Skill        (future, not in this repo)
   |
MCP connector                    (future, not in this repo)
   |
TI Recon backend                 <-- this repository
   |-- capability planner         (future)
   |-- provider registry          implemented
   |-- provider adapters          contract implemented; GTI is the first
   |-- provider HTTP transport    implemented (SSRF-bounded)
   |-- provider executor          implemented (cache, retry, quota, cooldown,
   |                                           concurrency, single-flight)
   |-- normalized evidence        implemented (Task 3 models)
   |-- lineage / correlation      models implemented, engine future
   |-- evidence fusion            (future)
   `-- assessment                 models implemented, scoring engine future
```

Design principles that shape every layer:

- **Provider independence** — the engine asks for a *capability*
  (`REPUTATION`, `SCANNER_CONTEXT`, `MALWARE_INTELLIGENCE`, ...), never for a
  specific vendor. Every provider is optional.
- **Evidence, not votes** — providers contribute evidence of differing class and
  specificity; TI Recon will never tally "N malicious vs M benign".
- **Facts vs interpretation** — provider observations, engine interpretation and
  the final assessment are three separate model layers.
- **Source lineage** — every piece of evidence records both the provider that
  *transported* it and the provider that *originated* it, so relayed data is
  never mistaken for independent confirmation.
- **Passive by default** — active actions (submission, rescan, sandboxing) are a
  separate future path requiring explicit approval.
- **No direct IOC fetching** — TI Recon never browses a submitted URL. The HTTP
  transport can only talk to a configured provider API host.
- **Execution decides how, not what** — the executor runs a *selected* provider
  safely under caching, retry, quota and concurrency controls. Choosing which
  provider to call is a later task, and nothing in this layer computes a verdict.
- **Per-user execution isolation** — cache entries, quota state, cooldowns,
  concurrency slots and request coalescing are all keyed by the analyst's
  credential, never shared between users.

See [docs/architecture.md](docs/architecture.md) for detail.

## Supported observable types (V1 scope)

```
IPv4    IPv6    Domain    URL    MD5    SHA1    SHA256
```

Submitted concrete artifacts are modelled as **Observables** (STIX-style
`ipv4-addr`, `domain-name`, `url`, `file`), not STIX Indicators. File hashes are
properties of a `file` object rather than object types of their own.

Full in/out-of-scope list: [docs/scope.md](docs/scope.md).

## Installation (development)

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-extras
```

Without `uv`:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Running checks

```bash
uv run ruff format .
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run pytest -q --cov=ti_recon --cov-report=term-missing
```

All tests pass with high statement coverage of `src/ti_recon`.

## Configuration

Copy `.env.example` to `.env` (git-ignored) for local development. `.env.example`
contains variable **names only** — never commit credential values.

In production, provider credentials are held per user by the credential layer
(`src/ti_recon/credentials`), not in process environment variables. See
[docs/credential-management.md](docs/credential-management.md).

## Current limitations

- **One provider only.** Google Threat Intelligence is integrated; every other
  provider named above is a later task.
- **No provider selection.** The registry returns every compatible provider;
  nothing ranks or chooses between them.
- **GTI is passive only.** No submission, rescanning, downloads, sandbox
  detonation or Intelligence Search.
- **Secret storage is in-memory only.** `InMemorySecretStore` is explicitly
  labelled *not for production*: it is process-local, unencrypted and lost on
  restart. No Vault/AWS/Azure/GCP backend is implemented.
- **No persistence.** Nothing is stored in a database; models are in-memory only.
- **No verdict engine.** `Assessment` / `AssessmentContribution` models exist,
  but nothing computes a verdict, risk score or confidence.
- **All execution state is in-memory and single-process.** With N workers each
  has its own cache, each discovers a throttled provider independently, and
  effective provider concurrency is `max_concurrency x N`. No Redis or other
  shared store is implemented.
- **No real quota API calls.** The quota models and stores exist; nothing
  queries a provider for its quota.
- **No batch, pivot or active operations against a real provider.** The
  contract declares them and the default implementations raise
  `UnsupportedProviderOperation`; only test fakes implement batch lookup.
- Normalization is purely syntactic — no DNS resolution, no WHOIS, no network I/O.

## Documentation

- [docs/scope.md](docs/scope.md) — product scope, verdict vocabulary, depths, modes
- [docs/architecture.md](docs/architecture.md) — component architecture
- [docs/data-model.md](docs/data-model.md) — Task 3 data model and normalization
- [docs/credential-management.md](docs/credential-management.md) — Task 4 credentials
- [docs/provider-framework.md](docs/provider-framework.md) — Task 5 provider framework
- [docs/provider-execution.md](docs/provider-execution.md) — Task 6 execution controls
- [docs/providers/gti.md](docs/providers/gti.md) — Task 7 Google Threat Intelligence
