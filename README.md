# TI Recon

TI Recon is an external **Threat Intelligence enrichment and analysis platform**.
An analyst submits an observable — an IP address, domain, URL or file hash — and
TI Recon queries external threat-intelligence providers, normalizes their
responses into structured **evidence** with full source provenance, and will
eventually produce an explainable, auditable assessment.

## Current development state

This repository currently contains the foundation plus its first nine providers
(Jira Tasks 1-12):

| Task | Scope | State |
|------|-------|-------|
| 1 | Product scope + investigation workflow foundation | Implemented (docs + vocabularies) |
| 2 | Platform architecture foundation | Implemented (docs + module boundaries) |
| 3 | Common TI data model | Implemented |
| 4 | Per-user provider credential foundation | Implemented (in-memory store only) |
| 5 | Provider integration framework | Implemented (contract, registry, transport) |
| 6 | Provider execution controls | Implemented (in-memory, single-process) |
| 7 | Google Threat Intelligence integration | Implemented (passive enrichment) |
| 8 | urlscan.io integration + web forensics | Implemented (passive enrichment; forensics on explicit request) |
| 9 | GreyNoise + Censys integration | Implemented (passive enrichment) |
| 10 | abuse.ch: ThreatFox + URLhaus + MalwareBazaar | Implemented (passive enrichment) |
| 11 | MISP Warning Lists | Implemented (local, zero-network false-positive context) |
| 12 | Sandbox framework + Hybrid Analysis | Implemented (passive historical reports only) |

**Seven providers are integrated**, all passive, each answering a different
question. Google Threat Intelligence enriches with each analyst's own VirusTotal
API key. urlscan supplies passive web intelligence — what its browsers observed
when they visited a page — and, only when explicitly asked, static forensic
analysis of the page artifacts it already stored. GreyNoise says what an address
*does* on the internet: whether it is background scanning noise, and whose.
Censys says what is *exposed on* an asset: which ports answer, what software is
visible, which certificate is served. The three abuse.ch platforms answer from
community and curated datasets: ThreatFox for current family-attributed
indicators, URLhaus for malware-distribution URLs, MalwareBazaar for vetted
samples.

The three abuse.ch providers share **one** credential group and **one** source
family, so an analyst stores one Auth-Key and a future fusion layer can see that
two of them agreeing is one ecosystem agreeing with itself.

MISP Warning Lists is different in kind from the other seven, and deliberately
so. It needs **no server, no API key and no network**: it matches an observable
against a pinned local snapshot of the community warninglist dataset, so the
capability is available during offline triage. It is also the only provider that
never expresses an opinion — every finding it produces is context, and a clean
lookup means "nothing in the configured lists matched" rather than anything about
safety.

Task 12 adds the first **dynamic-analysis** source, behind a provider-neutral
sandbox framework. Hybrid Analysis answers what a sample *did* when somebody ran
it — in which environment, and how informative that run was. It is strictly
passive: it searches for detonations that already happened and never starts one,
because uploading a customer's file to a community platform whose terms allow
retention and redistribution is a decision a human makes with a warning in front
of them.

There is no SecurityTrails, AbuseIPDB, Shodan or IPinfo client yet, no *active*
sandboxing, and there is no query planner, no provider selection, no evidence
fusion, no verdict scoring, no MCP server and no Claude Skill. Those are later
Jira tasks.

Task 6 added the execution layer every adapter runs behind — caching, retry and
backoff, rate-limit and quota tracking, cooldowns, bounded concurrency and
request coalescing. All of its state is **in-memory and single-process**: a
development foundation, not distributed coordination.

### Providers

| Provider | Status | Supported | Not yet |
|----------|--------|-----------|---------|
| Google Threat Intelligence | Implemented | IP / domain / URL / hash passive enrichment, GTI assessment, threat severity, aggregated reputation, quota awareness, bounded relationships, selected threat associations, deep file behaviour | Intelligence Search, active scanning, sample submission, sample downloads |
| urlscan.io | Implemented | historical scan discovery bounded by the account's own searchable range, stored scan results, verdicts with separated lineage, redirect chains, contacted infrastructure, served-body digests, quota awareness, and — on explicit request at DEEP depth — stored screenshot / DOM / response-body retrieval with static forensic extraction and kit fingerprints | scan submission, rescan, live scan, sample downloads, visibility changes, deletion, saved searches, incidents |
| GreyNoise | Implemented | IPv4 scanner classification with its raw wording preserved, Business Services Intelligence as context, aggregated tags, CVE-activity association, sensor detail at DEEP depth, network ownership and pivots, and per-credential resolution of full-context vs Community access | GNQL and all hunting, timelines, bulk lookup, feeds, PCAP, deprecated v2 endpoints, IPv6/domain/URL/hash observables |
| Censys | Implemented | direct host and web-property reads by deterministic asset identity, exposed services and software, DNS and reverse DNS, served certificates as `x509-certificate` pivots, labels, vulnerability context, and credit-balance awareness from the zero-cost account endpoints | CenQL and general search, historical timelines, `at_time`, collections, Adversary Investigation, live rescan/discovery, bare domains, file hashes, any body retrieval |
| ThreatFox (abuse.ch) | Implemented | current family-attributed IOC search for IPv4, domain, URL and MD5/SHA-256, with `ip:port` records re-validated locally by parsing, the malware family as a linked object, and the six-month API horizon recorded in coverage | indicator submission, the recent feed, malware-family / tag / reporter queries, every bulk or hunting query, IPv6, SHA-1-only files |
| URLhaus (abuse.ch) | Implemented | exact malware-distribution URL records kept distinct from host-level associations, `url_status` and takedown-report context, served-payload provenance and fingerprints, bounded URL pivots, and relayed VirusTotal / blocklist findings attributed to their real origin | URL submission, rescan, live scan, `/downloads/` sample retrieval, all feeds, Brand/Kit monitoring, the hostname and similarity APIs |
| MalwareBazaar (abuse.ch) | Implemented | vetted sample records by MD5 / SHA-1 / SHA-256, family signature, fingerprint pivots (imphash, TLSH, telfhash, gimphash, ssdeep, icon dhash), code signing with CSCB status and a linked `x509-certificate`, bounded YARA and document context, and relayed vendor names only | sample download and upload, record updates, comments, the recent feed, tag / signature / YARA / certificate hunting, any dynamic analysis |
| Hybrid Analysis (Falcon Sandbox) | Implemented | passive historical sandbox reports for file hashes: the report index (environments, states, verdicts) plus bounded behaviour from at most two representative report summaries — processes, network observations, dropped files, signatures, MITRE techniques, certificates and analysis-quality context, with report divergence across environments preserved | any submission or detonation, sample / PCAP / memory / screenshot / dropped-file download, quick scan, overview refresh, host / domain / URL search, YARA hunting, feeds |
| MISP Warning Lists | Implemented | local, zero-network false-positive and infrastructure context for addresses, domains, URLs and file hashes from a pinned CC0 snapshot of the community dataset — private and special-use ranges, public resolvers, scanners, cloud/CDN ranges, dynamic DNS, living-off-trusted-sites hosts, popular domains, known-good and test-artifact hashes — gated by `matching_attributes`, with a URL's host kept visibly separate from the URL | any MISP instance or REST API integration, regex matching, automatic dataset refresh, non-TI-Recon attribute families |

All nine supply **evidence**, not verdicts. Weighing providers against each other
and reaching a conclusion is the future evidence-fusion layer's job, and no such
layer exists yet. See [docs/providers/gti.md](docs/providers/gti.md),
[docs/providers/urlscan.md](docs/providers/urlscan.md),
[docs/providers/greynoise.md](docs/providers/greynoise.md),
[docs/providers/censys.md](docs/providers/censys.md),
[docs/providers/threatfox.md](docs/providers/threatfox.md),
[docs/providers/urlhaus.md](docs/providers/urlhaus.md),
[docs/providers/malwarebazaar.md](docs/providers/malwarebazaar.md) and
[docs/providers/misp-warninglists.md](docs/providers/misp-warninglists.md) and
[docs/providers/hybrid-analysis.md](docs/providers/hybrid-analysis.md).

Two of them are deliberately *not* reputation sources. Censys answers "what is
exposed here" and every piece of evidence it produces is context: an open RDP
port is a risk to its owner, not evidence its owner is an attacker. GreyNoise
does produce one assessment — its scanner classification — and nothing else it
reports carries a direction, because a provider gets one opinion per response
rather than one per field.

The abuse.ch providers add the relay problem in its sharpest form. All three
carry other people's findings — URLhaus relays VirusTotal ratios and URL
blocklists, MalwareBazaar relays a dozen sandbox vendors — and none of it becomes
an abuse.ch corroboration. A relayed VirusTotal count carries VirusTotal's origin
*and the same source family a direct Google Threat Intelligence result carries*,
so the two can never be counted as independent. MalwareBazaar's `vendor_intel`
becomes one direction-free record naming which vendors had something, because
eight relayed verdicts becoming eight votes would credit providers TI Recon never
queried. Nothing downloads a sample, submits an indicator or requests a rescan,
and a malicious URL in a provider response is data — never a request target.

urlscan has two deliberately separate modes. Ordinary enrichment never retrieves
a DOM, a screenshot or a response body; deep forensic retrieval happens only when
a caller asks for `WEB_FORENSICS` at DEEP depth, and stays passive — everything it
reads is content urlscan already stored.

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
   |-- provider adapters          contract implemented; GTI, urlscan,
   |                               GreyNoise, Censys, ThreatFox, URLhaus,
   |                               MalwareBazaar, MISP Warning Lists (local),
   |                               Hybrid Analysis (passive sandbox)
   |-- sandbox framework          implemented (provider-neutral dynamic analysis)
   |-- provider HTTP transport    implemented (SSRF-bounded)
   |-- provider executor          implemented (cache, retry, quota, cooldown,
   |                                           concurrency, single-flight)
   |-- provider artifacts         implemented (bounded, user-isolated, in-memory)
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

- **Nine providers only.** Google Threat Intelligence, urlscan.io, GreyNoise,
  Censys, ThreatFox, URLhaus, MalwareBazaar, MISP Warning Lists and Hybrid
  Analysis are integrated; every other provider named above is a later task.
- **Sandboxing is passive only.** Hybrid Analysis finds detonations that already
  happened; nothing submits, detonates or downloads. A sandbox result that
  observed nothing is never benign evidence — it is context about one execution
  in one environment, and the analysis-quality record is what makes it
  interpretable.
- **The warninglist dataset is a pinned snapshot, refreshed by hand.** Nothing
  updates it automatically, and a lookup never fetches anything. Its default
  profile deliberately excludes the million-entry popularity rankings, and every
  omission is reported in coverage — no result claims to have checked lists it
  never had.
- **No provider selection.** The registry returns every compatible provider;
  nothing ranks or chooses between them.
- **Every provider is passive only.** No submission, rescanning, live scanning,
  downloads, uploads, sandbox detonation, Intelligence Search, GNQL hunting,
  CenQL search or abuse.ch write query.
- **Coverage is deliberately narrow where it cannot be deterministic.** GreyNoise
  answers for IPv4 only; Censys answers for addresses and HTTP(S) URLs but not
  bare domains, because a web property needs a port and guessing two would
  present two ports as domain coverage. MalwareBazaar answers for files only, and
  ThreatFox and URLhaus decline a file identified solely by SHA-1 rather than
  search under a key their APIs cannot use. All of these report `NOT_SUPPORTED`
  rather than an empty answer.
- **ThreatFox answers only about the recent past.** Its API drops IOCs after
  roughly six months, so a miss means "nothing unexpired matched" — recorded
  explicitly in the coverage evidence, never as an absence of history.
- **Artifact storage is in-memory only.** Retrieved page artifacts are bounded
  and user-isolated but process-local and lost on restart.
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
- [docs/providers/urlscan.md](docs/providers/urlscan.md) — Task 8 urlscan.io and web forensics
- [docs/providers/greynoise.md](docs/providers/greynoise.md) — Task 9 GreyNoise
- [docs/providers/censys.md](docs/providers/censys.md) — Task 9 Censys
- [docs/providers/threatfox.md](docs/providers/threatfox.md) — Task 10 ThreatFox
- [docs/providers/urlhaus.md](docs/providers/urlhaus.md) — Task 10 URLhaus
- [docs/providers/malwarebazaar.md](docs/providers/malwarebazaar.md) — Task 10 MalwareBazaar
- [docs/providers/misp-warninglists.md](docs/providers/misp-warninglists.md) — Task 11 MISP Warning Lists
- [docs/sandbox.md](docs/sandbox.md) — Task 12 provider-neutral sandbox framework
- [docs/providers/hybrid-analysis.md](docs/providers/hybrid-analysis.md) — Task 12 Hybrid Analysis
- [docs/artifacts.md](docs/artifacts.md) — Task 8 bounded provider artifact storage
