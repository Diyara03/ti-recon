# URLhaus

Task 10. `src/ti_recon/providers/urlhaus/`

URLhaus is abuse.ch's **malware-distribution URL tracker**. It watches URLs that
serve malware, records what they served, and keeps watching after they go
offline. It is TI Recon's source of URL-level malware-delivery intelligence.

It answers a question the other providers answer badly: *has this exact URL been
seen distributing malware, and if so, what did it deliver?*

---

## 1. What this provider is, and is not

**It is** a first-hand tracker with a payload archive. URLhaus does not merely
list URLs — it records the files those URLs served, so a URL lookup can carry the
hashes of what actually came down the wire.

**It is not** a scanner, a submission endpoint or a browser. This integration
performs one read per lookup against one of three endpoints. It cannot submit a
URL, request a rescan, download a stored payload, fetch a feed, or use the
Brand/Kit monitoring, hostname or similarity APIs. URLhaus offers those; none of
them exist here.

**Above all: TI Recon never contacts a URL URLhaus reports.** A malicious URL in
a provider response is *data*. Investigating a suspicious URL happens *through*
provider APIs, never by TI Recon fetching it.

---

## 2. Credentials

An **abuse.ch Auth-Key**, stored per analyst by the Task 4 credential layer and
**shared with ThreatFox and MalwareBazaar**.

| | |
|---|---|
| Auth type | `AuthType.AUTH_KEY` |
| Header | `Auth-Key` |
| Credential group | `abuse_ch` — shared with `threatfox` and `malwarebazaar` |
| Placement | Header only, applied by the shared transport at request time |

The Auth-Key never appears in a path, a query string, a **form field**, a cache
key, an error message or a log line. See
[threatfox.md](threatfox.md) §2 for why the form-field exclusion is stated
separately for these three providers.

**Validation costs one host lookup**, against `192.0.2.1` — RFC 5737 TEST-NET-1,
reserved for documentation, never routed, never anybody's observable. A "no
results" is success. Only a rejected key marks the credential invalid, because
one key serves three platforms.

---

## 3. Endpoints used, and endpoints that do not exist here

| Purpose | Path |
|---|---|
| One exact URL | `POST /v1/url/` |
| Everything URLhaus knows about a host | `POST /v1/host/` |
| One collected payload, by digest | `POST /v1/payload/` |

`ALLOWED_PATHS` is a frozen set of exactly those three. Absent, with no code path
to reach them: `POST /api/v1/urls/` and every other submission route, rescan,
live scan, `/downloads/` sample retrieval, the CSV and JSON feeds, the recent
lists, Brand/Kit monitoring, the hostname and similarity APIs, visibility changes
and deletion.

### POST is not a write

URLhaus takes its parameters in a form body, so every lookup is an HTTP POST, and
the "never calls `post`" argument used by the other integrations is unavailable —
see [threatfox.md](threatfox.md) §3. Passivity here is a property of
`ALLOWED_PATHS`: the client routes by path rather than by a `query` field, the
three permitted paths are frozen, and a test asserts that none of them contains
`download`, `submit`, `feed` or `rescan`.

### Path safety

The client is pinned to `https://urlhaus-api.abuse.ch`. A path that would leave
that origin raises `ProviderTransportSecurityError`; a host carrying userinfo is
refused at configuration time. A URL returned by URLhaus never becomes a request
target, and a test asserts that a lookup returning `http://malware.example/...`
contacts nothing but `abuse.ch`.

---

## 4. Exact URL versus host association

This is the distinction that matters most in reading URLhaus evidence, and the
integration keeps the two claims structurally separate.

**An exact URL match** (`/v1/url/`) is a statement about *this resource*:
URLhaus tracked `http://host/path/loader.exe` itself. Scope
`EXACT_OBSERVABLE`.

**A host association** (`/v1/host/`) is a statement about *the host*: URLhaus has
tracked some number of malware URLs on it. Scope `SAME_HOST`. That is a genuinely
weaker claim, and it has to stay weaker — shared hosting, a compromised CMS and a
CDN edge all produce host-level hits that say very little about any particular
path on them.

Which endpoint is used is decided by the observable, not by depth:

| Observable | Endpoint | Scope |
|---|---|---|
| URL | `/v1/url/` | `EXACT_OBSERVABLE` |
| Domain | `/v1/host/` | `SAME_HOST` |
| IPv4 address | `/v1/host/` | `SAME_HOST` |
| File (SHA-256 or MD5) | `/v1/payload/` | `EXACT_OBSERVABLE` |

**A missed URL is never retried as a host lookup.** The temptation is obvious —
the URL was not tracked, so ask about its host and return *something*. That would
silently substitute a weaker claim for the one that was requested, and answer a
question nobody asked. A test asserts the second request does not happen.

Files are looked up by SHA-256 if present, otherwise MD5 — the two digests
URLhaus indexes payloads by. A **SHA-1-only file is `NOT_SUPPORTED`**: asking
under a key the API cannot use would produce a meaningless "no results".

---

## 5. Offline is not benign

URLhaus keeps records after a URL stops responding, and `url_status` says which
state it is in. `offline` is preserved as an attribute and **changes nothing about
the direction of the evidence**.

A URL that distributed Dridex last week and 404s today distributed Dridex. The
campaign happened; the infrastructure was taken down or moved. Downgrading that
evidence because a fetch would now fail would systematically discount every
successful takedown in the dataset.

`larted` — abuse.ch's flag for "reported to the hosting provider" — is preserved
as `reported_for_takedown` for the same reason: it is process context, not a
verdict adjustment.

---

## 6. Payload presence is context, never a direction

`/v1/payload/` says that URLhaus **collected this file from a URL it was
monitoring**. That is provenance, and it is `EvidenceClass.DIRECT_OBSERVATION`
with `EvidenceEffect.CONTEXT_ONLY` — always, including when a family signature is
present.

The reason is URLhaus's own: it collects whatever a tracked URL served. A URL
that distributed malware last week may serve an installer, an error page, a
redirect or an unrelated file today, and URLhaus's own FAQ warns that its payload
records include false positives for exactly this reason. "Was downloaded from a
URL URLhaus watches" is a statement about where bytes were found, not about what
they do.

A signature *is* preserved when URLhaus has one, because it is the most useful
pivot on the record. Turning it into a direction here would be an adapter
deciding maliciousness on a field it cannot verify — and a future fusion layer
weighing it against MalwareBazaar, GTI and sandbox behaviour is exactly where
that decision belongs.

Fingerprints (`imphash`, `ssdeep`, `tlsh`) and the file type are kept as pivots.

---

## 7. Depth

Depth selects how much of the **already-returned** response is normalized. It
never adds a request and never widens a search.

| Depth | Related URLs | Nested detail | Relayed context |
|---|---|---|---|
| `QUICK` | 10 | none | no |
| `STANDARD` | 25 | 10 | yes |
| `DEEP` | 50 | 25 | yes |

A host with 4,000 tracked URLs yields one finding with a bounded sample of URL
objects, plus `provider_total`, `normalized_count` and `truncated` so the
truncation is visible rather than silent.

---

## 8. Evidence produced

| Claim type | Class | Effect | Notes |
|---|---|---|---|
| `urlhaus_malware_url` | `CURATED_THREAT_ASSERTION` | `SUPPORTS_MALICIOUS` | This exact URL was tracked |
| `urlhaus_host_malware_association` | `CURATED_THREAT_ASSERTION` | `SUPPORTS_MALICIOUS` at `SAME_HOST` | The host has tracked URLs |
| `urlhaus_payload_record` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` | Provenance — see §6 |
| `urlhaus_relayed_virustotal` | `CONTEXT` | `CONTEXT_ONLY` | Somebody else's finding — see §9 |
| `urlhaus_relayed_blocklists` | `CONTEXT` | `CONTEXT_ONLY` | Somebody else's finding — see §9 |
| `urlhaus_not_tracked` | `CONTEXT` | `CONTEXT_ONLY` | URLhaus looked and had nothing |

**One opinion per response.** A host with 400 tracked URLs is one URLhaus finding,
not 400. The URLs become bounded objects with `hosts` relationships, and served
payloads become `downloads` relationships.

### Lineage

| | |
|---|---|
| `transport_provider` | `urlhaus` |
| `origin_provider` | `urlhaus` for its own records |
| `source_family` | `abuse_ch` — shared with ThreatFox and MalwareBazaar |
| `lineage_group_id` | `abuse_ch:urlhaus` |

---

## 9. Relayed findings keep somebody else's provenance

A URLhaus response carries other people's work, and none of it becomes a URLhaus
finding.

**VirusTotal.** A payload record often includes a VirusTotal detection ratio.
That relay is normalized with `origin_provider = "virustotal"` and
`source_family = "google_ti"` — deliberately the *same family a direct Google
Threat Intelligence result carries*, so a relayed ratio and a direct GTI lookup
can never be counted as two independent corroborations. A test asserts the two
constants are equal, because if they ever drift apart that inflation returns
silently. The VirusTotal *link* is not stored.

**URL blocklists.** Spamhaus DBL, SURBL and the rest arrive as a set of statuses.
They become **one** record attributed to `url_blocklists` /
`multi_blocklist_aggregate`, listing only the lists that actually flagged the
host. An aggregate of other people's opinions is one source, not several — and a
host that is on no list produces no record at all rather than a benign vote.

Both are `EvidenceClass.CONTEXT`, which the Task 3 model forces to
`CONTEXT_ONLY`: the direction ban is enforced by the data model, not by adapter
discipline. Neither is read at `QUICK` depth.

---

## 10. Absence and unsupported

`no_results` is `ProviderRunStatus.NO_DATA` with one `CONTEXT_ONLY`
`urlhaus_not_tracked` observation carrying `tracked: False`. URLhaus tracks what
somebody reported; an absence is true of every URL nobody has reported yet, and
of every campaign younger than its first report.

An IPv6 address, or a file identified only by SHA-1, is
`ProviderRunStatus.NOT_SUPPORTED` with **no request at all**.

---

## 11. Errors, caching and isolation

Outcomes arrive in the body: `no_results`, `invalid_url`, `no_api_key` and
`user_blacklisted` all come back as HTTP 200, so the adapter checks
`query_status` before reading the payload.

| Body status | Category |
|---|---|
| `no_results`, `url_not_found` | `NOT_FOUND` → `NO_DATA` |
| `no_api_key`, `invalid_api_key` | `AUTHENTICATION_ERROR` |
| `user_blacklisted` | `PERMISSION_ERROR` |
| `invalid_url`, `invalid_host`, `invalid_md5`, `invalid_sha256` | `INVALID_REQUEST` |
| `rate_limited` | `RATE_LIMITED` |

`user_blacklisted` keeps its `PERMISSION_ERROR` category and additionally puts
the **shared abuse.ch credential** on a 6-hour cooldown, because repeating a call
that abuse.ch has already refused is the behaviour that earned the refusal. A
ThreatFox or MalwareBazaar blacklist suppresses URLhaus too — it is the same
Auth-Key. See [malwarebazaar.md](malwarebazaar.md) §11 and
[../provider-execution.md](../provider-execution.md) §8.1.

| Setting | Value |
|---|---|
| Cache scope | `CacheScope.USER` — never `GLOBAL` |
| Success TTL | 1800 s |
| No-data TTL | 300 s |
| Max concurrency | **1** |
| Request coalescing | on |

`GLOBAL` caching is never enabled. Concurrency stays at one because abuse.ch is
free and fair-use metered.

---

## 12. Not implemented

* URL submission, rescan and live scan
* `/downloads/` sample retrieval — nothing is downloaded, ever
* Every feed, recent list and bulk export
* Brand/Kit monitoring, the hostname API, the similarity API
* Visibility changes, deletion, saved searches
* Paging beyond the single response a lookup returns

## 13. Licensing

URLhaus data is offered by abuse.ch under its own terms, with commercial use
requiring a separate arrangement. What TI Recon stores is described in §8;
whether a given deployment's use is permitted is a question for whoever operates
it. Review <https://urlhaus.abuse.ch/api/> and the abuse.ch terms before using
this provider in a commercial context.

## 14. Live tests

Off by default. Enable with `RUN_ABUSECH_LIVE_TESTS=1` and `ABUSECH_AUTH_KEY`.
See [malwarebazaar.md](malwarebazaar.md) §12 for the shared request accounting.
