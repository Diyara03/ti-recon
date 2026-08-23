# GreyNoise

Task 9. `src/ti_recon/providers/greynoise/`

GreyNoise is TI Recon's source of **internet-scanning context**. It runs a sensor
network that records who is spraying the internet, and answers one question
nobody else answers as well: *is this address background noise, and if so,
whose?*

That question is worth a provider on its own. A large share of the addresses that
turn up in a SOC alert are mass scanners, and knowing which ones are is the
difference between an investigation and a shrug.

---

## 1. What this provider is, and is not

**It is** a first-hand observer. GreyNoise owns its sensors, so its
classification, its tags, its CVE associations and its Business Services
Intelligence are all things it saw or curated itself. Origin equals transport for
every one of them.

**It is not** a general reputation service, and it is not a hunting interface.
This integration reads two endpoints about one address. It cannot run a GNQL
query, walk a timeline, fetch a feed, retrieve a PCAP or look up anything in
bulk — GreyNoise offers all of those, and none of them exist here.

**It answers for IPv4 only.** Every other observable type is reported as
`NOT_SUPPORTED`, never as a lookup that found nothing. See §9.

---

## 2. Credentials

A GreyNoise API key, stored per analyst by the Task 4 credential layer.

| | |
|---|---|
| Auth type | `AuthType.API_KEY` |
| Header | `key` — not `Authorization`, not `X-Api-Key` |
| Credential group | `greynoise` |
| Placement | Header only, applied by the shared transport at request time |

The key never appears in a path, a query string, a cache key, an error message
or a log line. `GreyNoiseConfig` has no field for it, so a configuration object
is safe to log and serialize.

Validation reads `/v3/community/{ip}` for **192.0.2.1** — RFC 5737 TEST-NET-1,
reserved for documentation and never routed. GreyNoise has no zero-cost endpoint
for checking a key, so validation has to look *something* up; looking up a
reserved address means the check reveals nothing about any investigation and
cannot be mistaken for enrichment. A `404` is the expected answer and proves the
key was accepted, because a rejected key answers `401`.

---

## 3. Endpoints used, and endpoints that do not exist here

Used:

| Endpoint | Purpose |
|---|---|
| `GET /v3/ip/{ip}` | full IP context — classification, tags, CVEs, sensor metadata, BSI |
| `GET /v3/ip/{ip}?quick=true` | the reduced form of the same document |
| `GET /v3/community/{ip}` | the Community view: a handful of fields, far wider availability |

Deliberately absent, with no code path — not even an unused one:

- GNQL / any query or hunting endpoint
- timeline endpoints
- bulk or multi-IP lookup
- feeds, PCAP, session data
- every deprecated **v2** endpoint (`/v2/noise/context`, `/v2/riot`, …)

### The client is read-only by construction

`GreyNoiseClient` is a `Protocol` with exactly three members —
`get_ip_context`, `get_community`, `aclose` — and `GreyNoiseHttpClient` is
asserted at type-check time to satisfy it. Adding a hunting method would mean
changing the protocol, which is the point of having one. Tests also parse the
client module and assert that no `post` call, no `gnql` literal and no `/v2/`
literal appears in it.

### Path safety

The only path parameter is an address. It is parsed with `ipaddress.IPv4Address`
and **re-rendered from the parsed object** before interpolation, so what reaches
the URL came out of the parser rather than from the caller. A value that is not
an IPv4 address cannot become part of a path at all.

---

## 4. Access levels: which door a credential may use

GreyNoise exposes the same address through two doors, and which one a key may use
depends on that account's subscription. TI Recon cannot know it in advance, so
`ti_recon/providers/greynoise/access.py` resolves it *once* per credential and
remembers the answer.

Getting this wrong is expensive in two opposite directions:

- **Probing every lookup wastes the analyst's allowance.** A Community-only key
  that tried the paid endpoint before every lookup would spend half its requests
  on `403`s.
- **Guessing from a status code corrupts the answer.** A `401` means the key is
  wrong. Reading it as "this must be a Community account" and quietly
  downgrading would make a revoked key look like a working free one, and the
  analyst would never be told to fix it.

So the rule is:

| Response to the full context | What happens |
|---|---|
| `200` | full access confirmed and remembered |
| `206` | partial document accepted; run reported `PARTIAL` |
| `404` | the endpoint answered — full access confirmed, absence is the finding |
| `401` | **raised untouched.** Never probed, nothing remembered |
| `403` (or a plan limit) | exactly one Community attempt, if the operator left it enabled |
| anything else | raised |

A Community call that succeeds *or* returns a legitimate `404` proves Community
access works, and that level is remembered. Only a real response ever sets a
level; a status code alone never does.

### Modes and levels are different vocabularies

`GreyNoiseAccessMode` is configuration — `AUTO` (default), `FULL`, `COMMUNITY` —
and is the same for everyone. `GreyNoiseAccessLevel` is a per-credential
*observation*: `FULL` or `COMMUNITY`, and nothing else. A pinned `FULL` mode
produces honest permission errors rather than a silent downgrade, which is what
an operator who pinned it asked for; a pinned `COMMUNITY` never touches the paid
endpoint.

### Isolation

The access store is keyed by the Task 6 `ExecutionScope` identity — user plus
provider connection, built from identifiers only. One analyst's entitlement never
decides another's lookup, and rotating a key does not inherit the old key's
level. Levels expire after a bounded TTL (one hour by default) so an upgraded
subscription starts producing full context within the hour rather than at the
next restart. In-memory and single-process, like every other execution store
here.

---

## 5. Depth

A GreyNoise lookup is a single GET. Depth therefore does **not** buy more
requests, more history or a wider search — there is no query to page through at
any depth. What depth changes is which endpoint variant is asked for and how much
of the *already-returned* document is normalized:

| Depth | Endpoint | Normalized |
|---|---|---|
| `QUICK` | `/v3/ip/{ip}?quick=true` | classification, business-services context |
| `STANDARD` | `/v3/ip/{ip}` | the above plus tags, CVE associations, network ownership |
| `DEEP` | `/v3/ip/{ip}` | the above plus sensor detail — ports, requested paths, client fingerprints |

A Community-only credential reads `/v3/community/{ip}` at every depth; there is
nothing else for it to read.

Nothing about a deeper lookup makes an address look more malicious. Depth changes
how much context is recorded, never which way the evidence points, and that is
asserted directly in the tests.

The `?quick=true` choice is a *depth* decision, not an entitlement one: a
full-access key at `QUICK` depth uses it deliberately.

---

## 6. Evidence produced

| Claim type | Class | Effect |
|---|---|---|
| `greynoise_classification` | `CURATED_THREAT_ASSERTION` | per §7 |
| `greynoise_business_service` | `CONTEXT` | `CONTEXT_ONLY` |
| `greynoise_scanner_observation` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `greynoise_network_context` | `CONTEXT` | `CONTEXT_ONLY` |
| `greynoise_tags` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `greynoise_cve_activity` | `CONTEXT` | `CONTEXT_ONLY` |
| `greynoise_not_observed` | `CONTEXT` | `CONTEXT_ONLY` |
| `greynoise_coverage` | `CONTEXT` | `CONTEXT_ONLY` |

**The classification is the only piece that points anywhere.** A provider gets
one opinion per response, not one per field. Tags, CVE associations, sensor
detail and BSI all describe *what was observed* rather than *what GreyNoise
concluded*, so they are context — otherwise a well-tagged address could outvote
three independent providers.

Several of them are `EvidenceClass.CONTEXT` rather than merely carrying a context
effect. That is structural: the Task 3 model *forbids* context-class evidence
from carrying a direction, so the guarantee does not depend on this package
remembering it.

### Lineage: one provider, one source

Everything shares one lineage group, `greynoise:greynoise`. A classification, a
Mirai tag and a Log4Shell CVE association on one address are one source saying
three things, and a fusion layer must never read them as three sources agreeing.
Nothing here is marked relayed, because GreyNoise relays nobody — if a future
GreyNoise field turns out to repeat a third party's data, that field must get its
own origin before it becomes evidence.

### Match scope

Always `EXACT_OBSERVABLE`. GreyNoise is asked about one address and answers about
that address; nothing is inferred from a neighbour or a shared network.

---

## 7. Classification mapping

GreyNoise's scanner classification is preserved verbatim in
`raw_classification`, and mapped onto TI Recon's direction vocabulary:

| GreyNoise | `EvidenceEffect` | Why |
|---|---|---|
| `malicious` | `SUPPORTS_MALICIOUS` | |
| `suspicious` | `SUPPORTS_MALICIOUS` | the current vocabulary records *direction*, not strength |
| `benign` | `SUPPORTS_BENIGN` | an assertion that this is a known-good scanner, not an absence |
| `unknown` | `CONTEXT_ONLY` | |
| anything unrecognized | `CONTEXT_ONLY` | a changed vocabulary is data, not a licence to guess |
| absent | no evidence | |

**`suspicious` is not `malicious`.** The two share a direction because
`EvidenceEffect` is coarse — it says which way a claim points, not how hard it
pushes. That is *not* a claim that GreyNoise called the address malicious. The
raw word always travels with the evidence, precisely so that no presentation
layer has to reconstruct it, and rendering "suspicious" as "malicious" is a bug.

`benign` points toward benign because it is GreyNoise *asserting* that the
traffic comes from a scanner it has identified as legitimate — Shodan's crawler,
a research scanner. That is an assertion. It is not the same thing as an absence,
which is §8.

---

## 8. Absence is a coverage fact, never a benign verdict

`noise: false`, `riot: false`, `found: false` and a `404` all mean the same
thing: GreyNoise has no record. That is worth writing down — it is exactly what
changes when an address starts scanning — and it is emphatically **not** evidence
of safety.

An address GreyNoise has not seen is one that has not touched its sensors. That
is true of every attacker who only ever hits one target, and of every phishing
host that never scans anything. Turning absence into "likely benign" would make
the most targeted attacker look cleaner than a noisy mass scanner, which is
exactly backwards.

So a `404` produces a `NO_DATA` run carrying `greynoise_not_observed`, and a
document that says `found: false` produces the same record alongside whatever
else parsed.

---

## 9. Unsupported is not the same as empty

| Observable | Outcome |
|---|---|
| IPv4 | supported |
| IPv6 | `NOT_SUPPORTED` |
| domain | `NOT_SUPPORTED` |
| URL | `NOT_SUPPORTED` |
| file hash (MD5 / SHA-1 / SHA-256) | `NOT_SUPPORTED` |

The descriptor declares IPv4 alone, so the Task 6 executor short-circuits every
other type before a credential is even resolved: no request is made, and the
outcome is `NOT_SUPPORTED` with a readable reason rather than `NO_DATA`.

The distinction is load-bearing for the future coverage layer. "GreyNoise cannot
be asked about a domain" and "GreyNoise has never seen this address" are
different statements, and collapsing them would let a blind spot read as a clean
result. An unsupported run is also never cached — nothing was asked, so there is
no answer to keep.

IPv6 is absent because it is unimplemented, not because the address family is
uninteresting. Declaring coverage we do not have would turn a blind spot into a
silent empty answer.

---

## 10. Business Services Intelligence

GreyNoise's BSI (formerly RIOT) identifies **common business services** an
analyst is likely to see in an alert: a public resolver, a mail relay, a CDN
edge. What is kept:

`found`, `name`, `category`, `description`, `explanation`, `reference`,
`trust_level`, `trust_level_meaning`, `last_updated`.

**It is always `CONTEXT_ONLY`, at every trust level, including level 1.**

Three reasons:

1. GreyNoise's own framing is triage context, not a general allow-list.
2. The scanner classification already carries GreyNoise's assessment. Emitting a
   trusted BSI record as benign *evidence* would count one provider's view twice
   inside a single response — the exact vote-counting TI Recon exists to avoid.
3. Level 3 explicitly covers dynamic and cloud-hosted address space that anybody
   can rent and run a workload in.

The trust level is preserved so a future fusion layer can weigh it properly:

| Level | Meaning |
|---|---|
| 1 | service ownership is reasonably trustworthy |
| 2 | common infrastructure that may also carry arbitrary customer activity |
| 3 | dynamic or cloud-hosted address space; not allow-list material |

---

## 11. Tags, CVEs and sensor detail

**Tags aggregate into exactly one observation.** Never one piece of evidence per
tag: "SSH Bruteforcer" and "Mirai" on one address are one source describing one
behaviour twice. Tag names, categories and intentions are kept, each bounded and
de-duplicated. A tag whose intention is `malicious` still does not create a
direction — the classification already carries GreyNoise's opinion, once.

**A CVE association is an observation about traffic.** GreyNoise saying an address
is associated with CVE-2021-44228 means its sensors saw that address probing for
it. It does **not** mean any target was compromised, that an exploit succeeded,
that the address hosts malware, or that the address is itself vulnerable — a
scanner probing for Log4Shell is not a Log4Shell victim. CVE evidence is
`EvidenceClass.CONTEXT`, so the model refuses to let it carry a direction, and it
records `association: observed_scanning_activity` so the claim states its own
scope. Only well-formed CVE identifiers are kept.

**Sensor detail is bounded and DEEP-only.** Ports (40), requested paths (25, each
length-bounded), JA3/JA4/HASSH fingerprints (10 each). User-agent strings are
deliberately **not** stored: attacker-chosen text with no analytical value the
paths do not already provide.

`spoofable` deserves its own note. GreyNoise reporting that an address's traffic
could have been spoofed is a reason to trust the *attribution* less, not a reason
to trust the address more. It is recorded as the fact it is.

---

## 12. Objects and relationships

Two pivots come out of the network context, each referencing the evidence that
justifies it:

- the **ASN** that announces the address → `belongs-to-asn` from the address;
- the **reverse-DNS name** → `resolves-to` *pointing at* the address.

The direction of the second one matters: reverse DNS says "this address answers
to this name", and recording it backwards would make the pivot graph lie.

Both values are validated by the same normalizer that validates analyst input. A
PTR record is chosen by whoever owns the address block, so it is no more
trustworthy than something a user typed; anything the normalizer rejects is
dropped rather than kept.

Stable facts are attached to the submitted object under a `greynoise` namespace —
classification, ASN, organization, country, rDNS, last seen. Judgements stay in
evidence, where they have a provenance and a moment of observation that a
property cannot carry.

---

## 13. Errors, metering and quota

Error mapping lives in `errors.py`, the only module in the package that knows
what an HTTP status means:

| Status | Category | Run status |
|---|---|---|
| 401 | `AUTHENTICATION_ERROR` | `ERROR` |
| 403 | `PERMISSION_ERROR` | `ERROR` |
| 404 | `NOT_FOUND` | `NO_DATA` |
| 400 / 422 | `INVALID_REQUEST` | `ERROR` |
| 408 / 500 | `TRANSIENT_ERROR` | `TEMPORARILY_UNAVAILABLE` |
| 502 / 503 / 504 | `PROVIDER_UNAVAILABLE` | `TEMPORARILY_UNAVAILABLE` |
| 429 | `RATE_LIMITED`, or `QUOTA_EXCEEDED` if `Retry-After` > 1 hour | see §14 |

**403 alone is not evidence of a plan tier.** GreyNoise answers `403` for both
"this key may not use this endpoint" and "your plan does not include this data",
so the honest normalization is the narrower one. Only a *subsequent successful
Community call* turns that into a statement about entitlement, and that inference
lives in `access.py` rather than here.

**429 has no scope header**, so the length of the wait is the only available
signal. Above an hour it is reported as an exhausted allowance — something the
execution layer records and routes around — rather than a pause worth scheduling.
With no `Retry-After` at all, the benign reading wins and the failure stays
retryable.

**There is deliberately no quota snapshot.** GreyNoise has no zero-cost allowance
endpoint that this integration reads, and manufacturing one from a lookup
response would give the Task 6 quota pre-check numbers that look authoritative
and are not — the pre-check would switch a working provider off without ever
calling it. What a result carries instead is a `RateLimitSnapshot`, built from
whatever `X-RateLimit-*` or `Retry-After` headers the response happened to send,
and `None` when it said nothing measurable.

Provider text is never trusted verbatim. A message is kept only if it survives
redaction and contains no long opaque token; the `provider_error_code` is the
status code and nothing else.

Only a rejected key is ever marked `INVALID`. A permission refusal, a plan limit,
an exhausted allowance and a throttled window all mean the key is fine and
something else is in the way — marking any of them invalid would disable a
perfectly good Community key the moment it touched a paid endpoint.

---

## 14. Caching and isolation

`build_greynoise_execution_policy()` returns a Task 6 policy:

| | |
|---|---|
| Cache scope | `USER` — never `GLOBAL` |
| Success TTL | 1 hour |
| `NO_DATA` TTL | 5 minutes |
| `PARTIAL` TTL | not cached |
| Concurrency | 4 (tunable) |

The scope is the part that is not tunable in spirit. Two GreyNoise accounts do
not see the same document for the same address — a Community key gets a handful
of fields where a full key gets the tags, the CVEs and the sensor detail — so
serving one analyst's answer to another would hand out data the second analyst's
plan does not include, and would just as easily hand a full-tier analyst a
Community-shaped answer.

A **Community answer is still a success**, and therefore cacheable. It is
complete for what Community is; the coverage gap is recorded as a warning
(`GREYNOISE_COMMUNITY_ACCESS_ONLY`) and in the coverage evidence rather than by
downgrading the run. Reporting it as `PARTIAL` would leave every free-tier lookup
uncached, and every free-tier analyst paying for the same answer twice.

Only a document GreyNoise itself trimmed (`206`), or a block that would not
parse, makes a run `PARTIAL` — and a partial result is never cached, so a
truncated answer cannot later be mistaken for a complete one.

---

## 15. Configuration

`GreyNoiseConfig`: `host` (pinned to `https://api.greynoise.io`), `user_agent`,
`timeout_seconds`.

`GreyNoiseLookupPolicy`: `access_mode`, `access_ttl_seconds`,
`allow_community_probe`, `depth_detail`.

The host must be `https`, must be an origin with no path, query or fragment, and
is not configurable from a request. The user agent is rejected if it is blank,
carries control characters, or contains credential-like text.

---

## 16. Not implemented

- GNQL and every hunting or query endpoint
- timeline and historical enumeration
- bulk / multi-IP lookup
- feeds, PCAP, session data
- every deprecated v2 endpoint
- IPv6, domains, URLs, file hashes
- any active operation — GreyNoise has none this integration could perform, and
  `supports_active` is `False` with no code path to turn on

Live tests are off by default: `RUN_GREYNOISE_LIVE_TESTS=1` plus
`GREYNOISE_API_KEY`.
