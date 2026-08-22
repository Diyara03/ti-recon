# urlscan.io

> Task 8. Describes `src/ti_recon/providers/urlscan/` and the artifact
> subsystem it uses (`src/ti_recon/artifacts/`, documented in
> [../artifacts.md](../artifacts.md)).
>
> Everything here is **passive**: no submission, no rescanning, no live scan,
> no visibility changes, no deletion, no sample downloads.

## 1. What this provider is, and is not

urlscan is TI Recon's source of **passive web intelligence**: what urlscan's
browsers observed when they visited a page. Nobody else in the provider set
reports that first-hand, which is why the integration exists.

It is **one evidence provider**. Nothing in this package computes a verdict, a
risk score or a confidence value; what it produces is evidence for a fusion
layer that does not exist yet.

Two modes, and only one of them can happen without being asked for:

| Mode | When | What it does |
|---|---|---|
| **Enrichment** | every lookup | bounded historical search → bounded stored scan results → normalized evidence, objects and relationships |
| **Web forensics** | DEEP depth **and** `WEB_FORENSICS` requested | additionally retrieves stored screenshot, DOM and a few stored response bodies, analyses them statically, and stores them as artifacts |

Enrichment never retrieves a DOM, a screenshot or a response body. A routine SOC
lookup therefore costs a search plus a small number of result reads.

## 2. Credentials

| | |
|---|---|
| `provider_id` | `urlscan` |
| `display_name` | urlscan.io |
| `credential_group` | `urlscan` |
| `source_family` | `urlscan` |
| `api_version` | `v1` |
| auth | `API-Key` request header |

The key is resolved per user by the Task 4 layer and applied by the shared
transport at request time. It never appears in a URL, a query string, a path, a
cache key, a metric, a log line, an error message, an artifact or a serialized
result — each of those routes has a test.

`UrlscanConfig` holds no secret at all, so a configuration object is safe to log
and compare.

## 3. Endpoints used, and endpoints that do not exist here

Used, all `GET`:

| Path | Purpose |
|---|---|
| `user/quotas/` | credential validation, health, allowance discovery |
| `api/v1/search/` | historical scan discovery |
| `api/v1/result/{uuid}/` | one stored scan result |
| `screenshots/{uuid}.png` | stored screenshot (forensics only) |
| `dom/{uuid}/` | stored DOM snapshot (forensics only) |
| `responses/{sha256}/` | stored response body (forensics only) |

Never reached, and with no code path that could reach them: `POST
/api/v1/scan`, any live-scan endpoint, rescan, `/downloads/{hash}`, visibility
changes, deletion, saved searches and incidents. `adapter.active_action()`
raises `UnsupportedProviderOperation`, and a lookup in `ActivityMode.ACTIVE` is
refused as well, so a caller bypassing the executor cannot turn this into an
active integration. Tests register routes for `POST /api/v1/scan` and
`/downloads/` and assert they stay uncalled during a full forensic run.

### The client is read-only by construction

`UrlscanClient` is a protocol with six reads and a close. There is no submission
method to call, the concrete client never invokes `post`, and a test walks the
module's AST to confirm that no write verb and no write endpoint appear in its
code. Passivity is structural rather than a rule to remember.

## 4. Query construction and injection

urlscan's Search API takes an ElasticSearch query-string expression, which makes
passing analyst input through a query-injection vulnerability: a value with a
quote in it could close its term and append conditions of its own.

So a query is never accepted as text. It is composed from:

* an **allow-listed field** — `UrlscanSearchField` is a `StrEnum`, so a field
  that is not listed cannot be expressed at all;
* a **value validated against the shape that field can hold**.

The defense works by exclusion rather than by blocking syntax. An IP must parse,
a domain must be label characters, an ASN must be `AS<digits>`, a hash must be
64 hex digits — none of those shapes can express a quote, a wildcard, a regular
expression, a range, a boolean or a second field, so there is no list of
dangerous characters to keep current. URL values are the exception, because a
URL legitimately contains that punctuation; they are escaped and quoted.

Boolean structure and the date bound are built by TI Recon and cannot be
supplied by a caller.

### Observable → search fields

| Observable | Fields searched |
|---|---|
| IPv4 / IPv6 | `page.ip`, `ip` |
| domain | `page.domain`, `domain` |
| URL | `page.url`, `task.url` |
| file (SHA-256) | `hash` |
| file (MD5 / SHA-1) | **none** — reported as a coverage gap |

urlscan indexes response bodies by SHA-256 only. An MD5 or SHA-1 produces no
search at all and a `URLSCAN_OBSERVABLE_NOT_SEARCHABLE` warning with `NO_DATA`,
rather than an empty result — reporting a gap as "nothing found" would turn
missing coverage into a false absence of evidence.

## 5. Depth and bounds

Depth is the analyst's cost signal, so it decides how much history is read.

| Depth | Page size | Scans retrieved | Per-domain cap | Time bound |
|---|---|---|---|---|
| QUICK | 10 | 1 | 1 | last 90 days |
| STANDARD | 50 | 3 | 2 | last year |
| DEEP | 100 | 8 | 3 | none |

Selection spends that budget deliberately: newest first, because a page's
current behaviour matters more than last year's, with a per-domain cap so fifty
scans of one popular site cannot crowd out the single scan that shows the
observable somewhere else. Budget the cap leaves unspent is filled rather than
wasted. All of it is overridable through `UrlscanLookupPolicy.search_limits`.

Other bounds:

| Thing | Cap |
|---|---|
| contacted domains / IPs / ASNs per scan | 50 / 50 / 20 |
| served body digests per scan | 20 |
| redirect hops recorded | 20 |
| categories / brands / tags | 20 / 10 / 20 |
| screenshot / DOM / response body bytes | 5 MB / 2 MB / 1 MB |
| response bodies retrieved per forensic run | 5 |
| bytes of an artifact scanned by extraction | 512 KB |
| extracted values per category | 20 |

Whenever a cap bites, the evidence records it (`truncated`, `scan_truncated`).
A truncated list must never read as a complete one.

## 6. Evidence produced

| Claim type | Class | Effect | Origin |
|---|---|---|---|
| `urlscan_verdict` | curated threat assertion | malicious if flagged, else context | `urlscan` |
| `urlscan_engine_aggregate` | aggregated reputation | malicious if any engine flagged, else context | `url_scanning_engines` (relayed) |
| `urlscan_community_votes` | aggregated reputation | malicious if any malicious vote, else context | `urlscan_community` (relayed) |
| `urlscan_scan_observation` | direct observation | context | `urlscan` |
| `urlscan_page_context` | context | context | `urlscan` |
| `urlscan_redirect_chain` | direct observation | context | `urlscan` |
| `urlscan_contacted_infrastructure` | direct observation | context | `urlscan` |
| `urlscan_served_bodies` | direct observation | context | `urlscan` |
| `urlscan_traffic_summary` | context | context | `urlscan` |
| `urlscan_stored_artifact` | context | context | `urlscan` |
| `urlscan_page_forensics` | direct observation | context | `urlscan` |
| `urlscan_response_forensics` | direct observation | context | `urlscan` |
| `urlscan_page_fingerprints` | context | context | `urlscan` |

Adapters never assign `source_reliability` or `information_credibility` —
Admiralty grading is TI Recon policy — and never emit a verdict, risk score or
confidence.

### Lineage: what urlscan saw vs what urlscan repeats

urlscan reports four verdicts. Its own is first-hand, so transport and origin
match and `is_relayed` is false. The engine aggregate is **not** urlscan's
opinion: it is third-party blocklist and scanner results that urlscan repeats,
so its origin is `url_scanning_engines` and its family is
`multi_engine_aggregate` rather than `urlscan`. Without that split, urlscan's
verdict and a relayed Safe Browsing hit would look like two independent sources
agreeing. The aggregate family is deliberately shared with any future provider
relaying overlapping blocklists, since those are not independent of each other
either.

`verdicts.overall` is **not** normalized. It is urlscan's roll-up of the other
three, and emitting it as well would count one provider's opinion twice inside a
single response.

### Direction is asymmetric

* `malicious: true` supports malicious; `malicious: false` supports nothing —
  "our heuristics did not fire" is equally true of every kit deployed this
  morning.
* Zero of ninety engines flagging is not evidence of safety. For most engines it
  means "not in my database".
* Benign community votes carry no direction. TI Recon requires an observation or
  an authority to support benign, never a show of hands.
* Hosting facts (ASN, country, TLS issuer) are context only. Letting "hosted in
  country X" nudge a verdict is how a country becomes a proxy for guilt.

### Match scope

| Submitted | Scan relationship | Scope |
|---|---|---|
| URL | this scan's page or task URL | `EXACT_OBSERVABLE` |
| URL | another URL on the same host | `SAME_HOST` |
| domain | the page's own domain | `SAME_HOST` |
| domain | a subdomain of it | `PARENT_DOMAIN` |
| domain | merely contacted by the page | `CLUSTER` |
| IP | the page's own address | `SAME_IP` |
| IP | merely contacted | `CLUSTER` |
| file | a body the page served | `SAME_HOST` |

## 7. Objects and relationships

| Relationship | From | To |
|---|---|---|
| `redirects-to` | URL | URL |
| `contacts` | page URL | domain |
| `resolves-to` | page URL | IP |
| `belongs-to-asn` | page URL | autonomous system |
| `downloads` | page URL | file (SHA-256 of a served body) |

Every relationship carries the evidence that explains it. Provider-supplied
values are validated by the same normalizer that validates analyst input — a
hostname urlscan reports is not more trustworthy than one a user typed — and
anything that fails validation is dropped rather than turned into an object.

## 8. Web forensics

### The gate

Forensics runs only when **both** of these are true, checked in one place
(`forensics_requested`):

1. `request.depth is InvestigationDepth.DEEP` — the analyst accepted the cost;
2. `ProviderCapability.WEB_FORENSICS in request.requested_capabilities` — the
   analyst asked for *this*, not for "everything urlscan has".

Neither half alone opens it. An operator's `allow_web_forensics=False` overrides
both and is reported by `discover_capabilities`, so a deployment that switches
forensics off produces an honest coverage gap rather than a silently missing
answer. When the gate refuses a request that asked for forensics, the envelope
carries `URLSCAN_WEB_FORENSICS_NOT_PERFORMED`.

Only the newest selected scan is captured: artifacts are large, and a forensic
question is almost always about the current state of a page.

Forensics remains passive. Everything it reads is content urlscan already
stored; nothing causes a new visit to anybody's site.

### Static analysis only

Nothing executes, renders, evaluates or interprets retrieved content. There is
no `eval`, no `exec`, no browser, no HTML renderer, no dynamic import and no
subprocess anywhere in `forensics.py`; a test asserts this against the module's
AST. Extraction is pattern-matching over a bounded prefix of the artifact, and
the text is discarded afterwards.

Extracted, as facts with no direction: form actions and which of them leave the
page's origin, script and iframe sources, input names, whether any input is
masked, meta-refresh targets, referenced hosts, and the page title. Concluding
*phishing* from those facts is the assessment layer's job — an adapter that
assigned a direction here would be promoting its own inference to a provider
fact.

### Secrets are detected, never kept

A phishing kit's exfiltration code contains live credentials. Detecting one is a
real finding; keeping it would make TI Recon a place credentials accumulate.

Recognized, by **type and count only**:

`telegram.bot-token`, `telegram.bot-endpoint`, `discord.webhook`, `google.api`,
`json.jwt`, `mailgun.api-key`, `square.access-token`, `authorization.api`.

The matched value is discarded where it is found. It never reaches evidence, an
artifact's metadata, an error, a metric, a log line, a test snapshot or a
fingerprint.

One naming note: the masked-input flag is `has_masked_input`, not
`has_password_input`, because the evidence layer refuses any attribute key that
looks like credential material. That guard caught the original name, and the
guard is worth more than the nicer word.

### Fingerprints

Computed over **structure**, never over content that could carry a secret:

| Fingerprint | Over |
|---|---|
| `dom_structure` | the sequence of element names |
| `form_targets` | the sorted set of form actions |
| `script_set` | the sorted set of script sources |

A kit deployed a hundred times has the same three digests every time, which is
how the hundredth deployment is recognized as the first. Response bodies are not
fingerprinted here: their own SHA-256 is a better identity.

## 9. Artifact storage

Retrieved artifacts go into the generic, bounded, user-isolated store described
in [../artifacts.md](../artifacts.md). Storage keys are derived from a hashed
scope, the artifact kind and the content digest, so no provider-supplied
filename, URL, domain or scan title ever influences a path. A budget refusal
drops the artifact without failing the lookup: real findings are not traded for
a screenshot.

## 10. Quota, rate limits and errors

`/user/quotas/` reports an allowance per action. Only the **read** actions gate
execution:

| Bucket prefix | Gating |
|---|---|
| `search_*`, `retrieve_*` | yes |
| `public_*`, `private_*`, `unlisted_*`, `livescan_*`, … | no |

TI Recon never scans, and `ProviderQuotaSnapshot.is_exhausted` is true if any
bucket is spent — so a spent scanning allowance would otherwise switch urlscan
off over something no lookup consumes. The non-gating buckets are still parsed
and returned, so nothing is silently discarded.

`X-Rate-Limit-*` headers on each response become a `RateLimitSnapshot`. When
urlscan names the action it metered, the window carries that name so a search
limit is never read as a retrieval limit. If urlscan says nothing measurable, no
snapshot is produced at all.

Status mapping:

| Status | Category | Note |
|---|---|---|
| 401 | `AUTHENTICATION_ERROR` | the only thing that marks a key invalid |
| 403 | `PERMISSION_ERROR` | also what a scan private to another team returns |
| 404 / 410 | `NOT_FOUND` → `NO_DATA` | "urlscan has never seen this" is a finding |
| 400 / 422 / 431 | `INVALID_REQUEST` | |
| 429, minute/hour window | `RATE_LIMITED` | retryable |
| 429, day/month window | `QUOTA_EXCEEDED` | not something to wait for |
| 408 / 500 | `TRANSIENT_ERROR` | |
| 502 / 503 / 504 | `PROVIDER_UNAVAILABLE` | |

Provider messages are redacted, length-bounded, and dropped entirely if they
still contain a long opaque token — urlscan quotes submitted URLs, and a
submitted URL can carry a token in its query string.

## 11. Caching and isolation

Cache scope is `USER` and nothing enables `GLOBAL`. An authenticated urlscan
search can return unlisted and team-private scans visible only to one analyst's
key; serving those from a shared cache would hand one analyst another's private
scans. Successes keep for an hour, `NO_DATA` for five minutes — the moment
somebody scans a domain, "never scanned" stops being true — and `PARTIAL`
results are not cached at all, so a truncated answer is never mistaken later for
a complete one.

## 12. Transport and the host boundary

The shared `ProviderHttpClient` is pinned to `https://urlscan.io`, accepts only
relative paths, permits only GET/POST/HEAD, cannot have TLS disabled, and does
not follow redirects.

urlscan does redirect some artifact URLs legitimately, so the client follows a
bounded number of hops **within urlscan.io only**. A `Location` pointing
anywhere else raises rather than being followed: the next request would carry
the analyst's key.

Every identifier is validated before it reaches a path — a scan id must be a
UUID, a stored body must be addressed by its SHA-256 — so a hostile value from a
search result cannot become part of a URL.

Artifact bodies are read through a streaming, byte-capped request that stops
reading past the ceiling, because artifact size is chosen by whoever is being
investigated.

## 13. What is never persisted

Present in a result document, and deliberately never read: request and response
headers, cookies and `Set-Cookie` values, POST bodies, `localStorage` and
`sessionStorage` contents, full console output and browser messages. They carry
session material belonging to whoever ran the scan, and a stored header turns an
investigation record into a credential leak. Only the shape of the traffic —
which host, which status, which digest — is normalized.

## 14. Configuration

```bash
URLSCAN_API_KEY=            # local development only; production keys live in
                            # the per-user credential store
RUN_URLSCAN_LIVE_TESTS=1    # enables tests/live/test_urlscan_live.py
```

Live tests are off unless both variables are set, so a default `pytest` run, CI
and pre-commit never contact urlscan. They assert structure and provenance,
never today's verdict, and they never scan.

## 15. Not implemented

Submission, rescan, live scan, liveshot, sample download, visibility changes,
deletion, saved searches, incidents, Brand/Kit monitoring, hostname/similarity
APIs, paging beyond the first search page, and any use of urlscan Pro-only
endpoints. Evidence fusion, provider selection and verdict scoring remain future
tasks: urlscan supplies evidence, and nothing weighs it yet.
