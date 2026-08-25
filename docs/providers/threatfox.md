# ThreatFox

Task 10. `src/ti_recon/providers/threatfox/`

ThreatFox is abuse.ch's **community IOC exchange**. Researchers and vendors
contribute indicators — C2 addresses, malware distribution URLs, payload hashes —
each tagged with the malware family it belongs to and a confidence level. It is
TI Recon's first source of *current, family-attributed* indicators.

The word doing the work is **current**. ThreatFox is a live IOC feed with a short
memory, not an archive, and that shapes almost every decision in this
integration.

---

## 1. What this provider is, and is not

**It is** a curated indicator database with attribution. A ThreatFox hit does not
merely say "this looks bad" — it says which malware family the indicator belongs
to, who reported it, when it was first and last seen, and how confident the
reporter was.

**It is not** an archive, and it is not a hunting interface. This integration
performs one search per lookup. It cannot query by malware family, by tag, by
reporter or by time window; it cannot pull the recent-additions feed; it cannot
submit an indicator. ThreatFox offers all of those, and none of them exist here.

**It answers for IPv4, domains, URLs and file hashes.** IPv6 is reported
`NOT_SUPPORTED`, and so is a file identified only by SHA-1 — see §4 and §9.

---

## 2. Credentials

An **abuse.ch Auth-Key**, stored per analyst by the Task 4 credential layer and
**shared with URLhaus and MalwareBazaar**.

| | |
|---|---|
| Auth type | `AuthType.AUTH_KEY` |
| Header | `Auth-Key` |
| Credential group | `abuse_ch` — shared with `urlhaus` and `malwarebazaar` |
| Placement | Header only, applied by the shared transport at request time |

The credential group is the point: an analyst stores one abuse.ch key and all
three providers can use it. Task 4 resolves by group, so no per-provider
configuration exists and no provider can reach another user's key.

The Auth-Key never appears in a path, a query string, a **form field**, a cache
key, an error message or a log line. The form-field exclusion is specific to
these three providers: their parameters travel in a POST body, so a careless
implementation could put the credential beside them, where any request log that
captures bodies would keep it. The shared transport is the only thing that reads
the secret, and it only ever writes it to a header.

**Validation costs one search.** ThreatFox has no zero-cost status endpoint, so
the credential check asks `search_ioc` about `192.0.2.1` — RFC 5737 TEST-NET-1,
reserved for documentation, never routed, and therefore never anybody's
observable. A "no result" is success: the key was accepted and ThreatFox looked.

Only a **rejected key** marks the credential invalid. That matters more here than
elsewhere, because one key serves three platforms: reporting `user_blacklisted`
as a bad credential would make an analyst replace a key that was never the
problem.

---

## 3. Endpoints used, and endpoints that do not exist here

| Operation | Query | Purpose |
|---|---|---|
| `search_ioc` | `POST /api/v1/` | Search for an address, domain or URL |
| `search_hash` | `POST /api/v1/` | Search for a file hash |

Absent, with no code path to reach them: `submit_ioc`, `get_iocs` (the recent
feed), `malware_info`, `tag_info`, `malwarebazaar` cross-queries, `taginfo`,
`threat_types`, and every bulk or hunting query.

### POST is not a write

ThreatFox takes its parameters in a form body, so every lookup is an HTTP POST.
The proof used for GTI, urlscan, GreyNoise and Censys — *this integration never
calls `post`* — is unavailable here, and would be misleading if it were used.

Passivity is instead enforced where it actually lives: in **which query values
may be sent**. `ThreatFoxHttpClient` hands the shared transport a frozen
`ALLOWED_QUERIES = {"search_ioc", "search_hash"}`, and a form naming anything
else is refused *before a request is built*. `submit_ioc` is not disabled — it is
unreachable. Tests assert the set directly, and assert the refusal with nothing
mocked, so a form that escaped the gate would hit the network and fail loudly.

### Path safety

The client is pinned to `https://threatfox-api.abuse.ch` and sends only the
relative path `api/v1/`. A path that would leave that origin raises
`ProviderTransportSecurityError`; a host carrying userinfo is refused at
configuration time. There is no `fetch_arbitrary_url`, and an indicator returned
by ThreatFox is data — never a request target.

---

## 4. The address problem, and why it is the interesting one

ThreatFox stores address intelligence as **`ip:port`**, because a C2 is a service
rather than a machine. An exact search for a bare address therefore finds
nothing, so the address lookup — and only the address lookup — asks for a **loose
match**.

A loose match on a provider TI Recon does not control is a substring search. Ask
about `1.2.3.4` and a record for `11.2.3.45:443` can come back. So every returned
record is **re-validated locally** before it may become evidence:

* the record's `ioc` is **parsed**, not searched: `split_host_port` separates a
  trailing numeric port from the host part;
* the host part must be **equal** to the observable, never contain it;
* a record that fails is discarded, and the count of discards is published in the
  coverage evidence rather than dropped quietly.

`src/ti_recon/providers/threatfox/matching.py` is the gate, and a structural test
asserts that the module contains no `in` / `not in` operator, no `startswith`,
`find`, `search` or `index` call, and no regular-expression literal. The rule it
encodes is that a match is decided by parsing, never by looking for one string
inside another.

Domains match case-insensitively; URLs match **exactly and case-sensitively**,
because a path is case-significant and a "close enough" URL match is a different
resource. A file matches on any digest the record carries.

### Digests

`search_hash` accepts MD5 and SHA-256. The strongest available digest is used,
**once** — a file carrying both still costs one request, because two would double
the cost of one lookup against a fair-use-metered service for an identical
answer. A file identified **only by SHA-1** is `NOT_SUPPORTED`: asking under a key
the API cannot use would produce a confident "not found" that means nothing.

---

## 5. The six-month horizon

**ThreatFox drops IOCs from its API after roughly six months.** This is the single
most important fact about reading its answers, and it is recorded in the evidence
rather than left in documentation.

A miss means *"nothing unexpired matched"*. It does not mean "this was never
malicious", and it certainly does not mean "this is safe". An address that ran a
Dridex C2 last year is absent from ThreatFox today and absent for the same reason
a never-seen address is: the API only holds the recent past.

So every ThreatFox coverage record carries:

| Attribute | Meaning |
|---|---|
| `current_api_only` | `True` — this answer describes the live API, not history |
| `expiration_horizon_months` | `6` (`IOC_EXPIRY_HORIZON_MONTHS`) |
| `provider_records` | How many records the response contained |
| `matched_records` | How many survived local validation |
| `discarded_non_matching` | How many were substring noise (see §4) |

A miss is `ProviderRunStatus.NO_DATA` with one `CONTEXT_ONLY`
`threatfox_no_current_record` observation. It is never `SUCCESS`, and it never
carries a direction.

---

## 6. Depth

Depth selects how much of the **already-returned** response is normalized. It
never adds a request, never widens a search and never changes which way evidence
points.

| Depth | Related items | Nested detail |
|---|---|---|
| `QUICK` | 10 | none |
| `STANDARD` | 25 | 10 |
| `DEEP` | 50 | 25 |

There is no depth at which a second query is issued, and a test asserts one call
per lookup at every depth.

---

## 7. Evidence produced

| Claim type | Class | Effect | Notes |
|---|---|---|---|
| `threatfox_ioc` | `CURATED_THREAT_ASSERTION` | `SUPPORTS_MALICIOUS` | One assertion per lookup, carrying the highest confidence among validated records |
| `threatfox_hash_association` | `CURATED_THREAT_ASSERTION` | `SUPPORTS_MALICIOUS` | A sample ThreatFox associates with C2 infrastructure |
| `threatfox_coverage` | `CONTEXT` | `CONTEXT_ONLY` | The horizon, the counts, the discards |
| `threatfox_no_current_record` | `CONTEXT` | `CONTEXT_ONLY` | Nothing unexpired matched |

**One opinion per response, not one per record.** Five ThreatFox records naming
the same address are five reporters inside one platform, not five providers
agreeing. They become one claim; the malware family becomes an object with an
`associated-with-malware` relationship, and the sample digests become pivots.

`provider_confidence` is the highest confidence among the records that *survived
validation* — not among all records returned. A discarded substring record's
confidence of 100 never becomes the claim's confidence.

`is_compromised` is preserved as a record attribute. It matters: a compromised
legitimate host and a purpose-built C2 are both malicious infrastructure but call
for very different responses, and that distinction belongs in the evidence rather
than in a verdict the adapter is not allowed to reach.

### Lineage

| | |
|---|---|
| `transport_provider` | `threatfox` |
| `origin_provider` | `threatfox` for its own records |
| `source_family` | `abuse_ch` — shared with URLhaus and MalwareBazaar |
| `lineage_group_id` | `abuse_ch:threatfox` |

The shared family is deliberate. ThreatFox and URLhaus agreeing is one ecosystem
agreeing with itself; the distinct lineage group keeps their claims
distinguishable within it.

### Match scope

| Observable | Scope |
|---|---|
| Exact `ioc` match | `EXACT_OBSERVABLE` |
| Address matched inside an `ip:port` record | `SAME_IP` |
| Domain matched as a host | `SAME_HOST` |

A `SAME_IP` match is a narrower statement than an exact one: ThreatFox saw a C2
on a port of this address, which is not the same as "this address is a C2".

---

## 8. Unsupported is not the same as empty

An IPv6 address, or a file identified only by SHA-1, produces
`ProviderRunStatus.NOT_SUPPORTED` with a `THREATFOX_OBSERVABLE_NOT_SUPPORTED`
warning and **no request at all**. A blind spot must never arrive at the engine
looking like a clean result.

---

## 9. Errors, caching and isolation

Outcomes arrive in the body, not in the HTTP status: `no_result`, `illegal_hash`,
`no_api_key` and `user_blacklisted` all come back as HTTP 200. The adapter
therefore checks `query_status` **before** reading the payload — reading the
empty `data` list first is exactly how a rejected credential becomes "this
indicator is clean".

| Body status | Category |
|---|---|
| `no_result` | `NOT_FOUND` → `NO_DATA` |
| `no_api_key`, `invalid_api_key` | `AUTHENTICATION_ERROR` |
| `user_blacklisted` | `PERMISSION_ERROR` |
| `illegal_search_term`, `illegal_hash`, `invalid_hash` | `INVALID_REQUEST` |
| `rate_limited` | `RATE_LIMITED` |

`user_blacklisted` is abuse.ch's fair-use response: the account has been blocked.
It is a permission fact, not a bad key — see §2 — and it puts the shared
credential on a cooldown, because repeating the call is the behaviour that earned
the block. See [malwarebazaar.md](malwarebazaar.md) §11.

| Setting | Value |
|---|---|
| Cache scope | `CacheScope.USER` — never `GLOBAL` |
| Success TTL | 1800 s |
| No-data TTL | 300 s |
| Max concurrency | **1** |
| Request coalescing | on |

Concurrency stays at one because abuse.ch is free and fair-use metered.
Parallelism here is not a performance win TI Recon is entitled to take.

No quota snapshot is invented. ThreatFox publishes no allowance counter, and
fabricating one would let Task 6's quota pre-check disable a working provider
without ever calling it.

---

## 10. Not implemented

* `submit_ioc` — TI Recon does not publish customer indicators
* The recent-additions feed, and every bulk or hunting query
* Malware-family, tag, reporter and threat-type queries
* Anything that downloads a sample
* Paging beyond the single response a search returns

## 11. Licensing

ThreatFox data is offered by abuse.ch for **non-commercial use** under its own
terms, with commercial use requiring a separate arrangement. TI Recon's
integration reads the API as an authenticated client and stores what §7
describes; whether a given deployment's use is permitted is a question for
whoever operates it, not something an adapter can settle. Review
<https://threatfox.abuse.ch/faq/> and the abuse.ch terms before using this
provider in a commercial context.

## 12. Live tests

Off by default. Enable with `RUN_ABUSECH_LIVE_TESTS=1` and `ABUSECH_AUTH_KEY`.

A full abuse.ch live run performs **exactly one physical request per platform —
three in total** — issued once by a shared helper and read by every assertion.
The count is enforced statically by `tests/unit/test_live_smoke_cost.py`, not by
a comment or by test ordering. See [malwarebazaar.md](malwarebazaar.md) §12 for
the accounting in full.
