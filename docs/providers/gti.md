# Google Threat Intelligence

> Task 7. Describes `src/ti_recon/providers/gti/`.
>
> The first real provider integration. Everything here is **passive**: no
> submission, no rescanning, no downloads, no sandbox detonation.

## 1. What this provider is, and is not

GTI is **one evidence provider**. It supplies high-quality, curated evidence
about an observable; it is not TI Recon's authority on anything. Nothing in this
package computes a verdict, a risk score or a confidence value.

The eventual picture is:

```
GTI + urlscan + GreyNoise + Censys + ThreatFox + MISP Warning Lists
                          |
                    evidence fusion
                          |
                    TI Recon verdict
```

Task 7 delivers the first of those inputs.

## 2. Credentials

The credential is the analyst's **existing VirusTotal API key**. No separate
`GTI_API_KEY` secret type exists, and none should: GTI is a VirusTotal-keyed
product, and asking for the same secret twice under two brand names is a worse
experience with no security benefit.

| | |
|---|---|
| `provider_id` | `gti` |
| `display_name` | Google Threat Intelligence |
| `credential_group` | `virustotal` |
| `source_family` | `google_ti` |
| `api_version` | `v3` |

The credential group means a future VirusTotal-branded adapter reuses the same
stored secret rather than prompting for it again.

Credentials are resolved per user by the Task 4 layer, and a client is created
per call from that credential and closed when the call ends. Nothing is shared
or cached by API key: a shared client is a shared credential, and per-user
isolation is far easier to guarantee when there is nothing to share.

### Enterprise-first, degrading gracefully

The design assumes a VirusTotal Enterprise / GTI-enabled key is the normal
configuration. It does not assume every key has every entitlement.

A refusal on an Enterprise-gated operation becomes `PLAN_LIMITED` **for that
operation only**. The primary lookup keeps working, the relationships that are
permitted still come back, and the credential is never marked invalid. Disabling
a working Enterprise key because one relationship was unavailable would be worse
than the restriction itself.

## 3. The vt-py exception

Task 5 provides a shared, SSRF-bounded `ProviderHttpClient`, and every other
provider is expected to use it. GTI is an approved exception: the official
`vt-py` SDK already encodes v3's object, relationship, pagination and
URL-identifier semantics, and reimplementing that against a generic transport
would mean maintaining a second, worse copy of Google's API.

The exception is deliberately narrow:

- `client.py` is the only module that uses the vt-py *client*: `vt.Client`,
  `vt.Object` and `vt.url_id` appear there and nowhere else. (`errors.py` also
  imports `vt.error.APIError`, purely to recognize it in an `isinstance` check.)
  Everything above works with `GTIObject` and `GTIRelationshipDescriptor`, so
  vt-py's types never reach the normalizer or the core — and the normalizer is
  testable from JSON fixtures with vt-py absent.
- Task 6 still owns retry, backoff, caching, cooldown, concurrency and quota
  state. This client never sleeps and never retries; a test proves a failing
  call is attempted exactly once.
- vt-py's scan, upload and download methods are never called. `FORBIDDEN_VT_METHODS`
  names them and a test asserts none appears in the package.
- TLS verification is neither passed nor exposed, so it cannot be turned off.
- `trust_env=False`, so ambient proxy settings cannot redirect provider traffic.

## 4. `x-tool`

Every GTI request carries an `x-tool` header identifying the integration to
Google. It is **not a secret** — it identifies the tool the way a User-Agent
identifies a browser — and is kept conceptually separate from the agent string,
which identifies the client library.

```
GTI_X_TOOL=diyara03.ti-recon.0.1     # recommended shape: organization.product.major.minor
```

The default is derived from the package version so it cannot drift out of sync
with a release. Validation rejects blank values and control characters — a
newline in a header value is header injection, not a formatting preference — but
is otherwise permissive, because Google's guidance may change and
over-validating a free-form identifier would turn their documentation update
into our outage.

`x-apikey` is never set by TI Recon. vt-py owns authentication, and it applies
user headers *after* its own, so a credential smuggled through configuration
would silently override the real one. A credential-shaped `GTI_X_TOOL` is
refused for the same reason.

## 5. Supported observables

| Input | GTI collection | Identifier used |
|-------|----------------|-----------------|
| IPv4 | `ip_addresses` | the address |
| IPv6 | `ip_addresses` | the address |
| Domain | `domains` | the normalized domain |
| URL | `urls` | `vt.url_id(url)` |
| MD5 / SHA-1 / SHA-256 | `files` | the strongest known hash |

All three hash lengths resolve to one `file` object, as the Task 3 model
requires. A file is looked up by its strongest known hash, because a SHA-256
identifies a sample unambiguously where an MD5 can collide.

**A suspicious URL is never fetched.** It is turned into GTI's opaque base64
identifier before any path is built, so the URL under investigation is only ever
the object being asked about — it never becomes part of a request TI Recon
issues. Paths are assembled from a fixed set of four collection names plus a
validated identifier, and anything containing a scheme, a slash, a traversal
segment or whitespace is refused.

## 6. Response efficiency

`last_analysis_results` — the per-engine breakdown — is excluded from every
lookup. TI Recon normalizes the aggregate and deliberately never treats
individual engines as independent providers, so fetching dozens of per-vendor
verdicts would cost bandwidth for data we must not use that way.

Nothing else is excluded. Trimming further would be guessing at which fields are
unnecessary, and a wrongly excluded attribute is a silent gap in evidence.
`gti_assessment`, `gti_confidence_score`, `last_analysis_stats` and the core
metadata are always requested.

## 7. `gti_assessment`

The GTI assessment becomes one first-class piece of evidence:

```
evidence_class : CURATED_THREAT_ASSERTION
claim_type     : gti_assessment
attributes     : verdict, severity, threat_score, description,
                 gti_confidence_score, unmapped_contributing_factors
```

It is a curated assertion — GTI's own judgement — whatever the verdict, so the
class is constant and only the effect carries direction.

### Verdict mapping

| GTI verdict | Effect | Why |
|-------------|--------|-----|
| `VERDICT_MALICIOUS` | `SUPPORTS_MALICIOUS` | |
| `VERDICT_SUSPICIOUS` | `SUPPORTS_MALICIOUS` | Same direction; the raw verdict is preserved so fusion can weigh it less heavily |
| `VERDICT_BENIGN` | `SUPPORTS_BENIGN` | |
| `VERDICT_UNDETECTED` | `CONTEXT_ONLY` | **Not benign** |
| `VERDICT_UNKNOWN` | `CONTEXT_ONLY` | |
| anything new | `CONTEXT_ONLY` | A future verdict name must not inherit a direction |

**`UNDETECTED` is not `BENIGN`.** It means nothing flagged the object, which is
equally true of every threat nobody has caught yet. Treating it as evidence of
safety is how a fresh sample gets waved through. A test asserts `VERDICT_BENIGN`
is the only verdict that ever produces `SUPPORTS_BENIGN`, so a later edit cannot
quietly change this.

### `threat_score` is not a risk score

`threat_score` is preserved verbatim in the attributes and **never** converted
into TI Recon's `risk_score`. They are different quantities, on different scales,
owned by different layers.

### Confidence

`gti_confidence_score` becomes `Evidence.provider_confidence` (the provider's own
assertion) and is also kept raw in the attributes for traceability. It never
touches `Assessment.confidence`, which belongs to the future assessment engine.

### Admiralty grades are not assigned

`source_reliability` and `information_credibility` are left unset. Both are
Admiralty grades owned by **TI Recon policy**, and an adapter inventing one would
be asserting an analytic judgement it has no basis for. The fusion layer assigns
them later.

### Contributing factors

Recognized factors become their own evidence through a controlled table
(`CONTRIBUTING_FACTORS`). Nothing iterates the block and invents a claim per key:
GTI adds factors over time, and an unrecognized boolean turned into directional
evidence would be a guess with real consequences.

- A **falsy** factor produces nothing — `"mandiant_association_report": false`
  means there is no association, and emitting evidence for it would invert the
  provider's meaning.
- **Unrecognized** factor names are recorded on the parent assessment under
  `unmapped_contributing_factors`, so adding one later is a table entry rather
  than an archaeology exercise.
- **Score** factors stay on the parent: a number is not a claim with a direction.

Every factor points at its parent assessment through `upstream_evidence_refs`.

## 8. Aggregated reputation

`last_analysis_stats` becomes **exactly one** piece of evidence:

```
evidence_class : AGGREGATED_REPUTATION
claim_type     : gti_analysis_stats
attributes     : malicious, suspicious, harmless, undetected, timeout,
                 failure, type-unsupported, engines_total, reputation
```

Never one per engine. A multi-engine roll-up is a *single source* that happens to
summarize many opinions, and splitting it would let one provider masquerade as
dozens of independent confirmations.

The direction is deliberately asymmetric:

- any engine flagging malicious or suspicious → `SUPPORTS_MALICIOUS`;
- **nothing** produces `SUPPORTS_BENIGN`. Not "60 undetected", and not "60
  harmless" either, since for most engines that only means "not in my database".

No ratio, no threshold, no score. The counters travel in the attributes so the
fusion layer can weigh them with context this layer does not have.

## 9. Relationships

### Depth profiles

| Depth | Behaviour |
|-------|-----------|
| `QUICK` | Primary object only. Relationships GTI already inlined are still normalized, because they cost no additional call. |
| `STANDARD` | A small verified allow-list per object type; threat collections as descriptors. |
| `DEEP` | Selected additional relationships, plus expansion of threat collections into named objects. |

Verified per-type sets:

```
file      STANDARD  contacted_domains, contacted_ips, contacted_urls,
                    malware_families, associations
domain/ip STANDARD  resolutions, communicating_files, associations
url       STANDARD  downloaded_files, communicating_files, redirecting_urls,
                    associations
```

DEEP adds `dropped_files`, `embedded_domains`, `itw_urls`, `referrer_files`,
`contacted_*` for URLs, and the threat relationships `related_threat_actors`,
`related_reports`, `campaigns`.

Never requested: `votes`, `comments`, `screenshots`, `graphs`, `behaviours`,
`similar_files`, `submissions`, `analyses`. A test enforces this.

### Limits

Three independent caps, all TI Recon safety defaults rather than GTI API limits,
and all configurable:

| | STANDARD | DEEP |
|---|---|---|
| relationship types | 5 | 10 |
| results per relationship | 5 | 10 |
| total related objects | 15 | 40 |
| full threat objects per relationship | 3 | 5 |

`ProviderRequest.max_results` only ever *narrows*: a request asking for more than
the depth allows does not get to raise a safety cap. Pagination is never
followed — one page per relationship — and the running total stops the walk early
rather than trimming afterwards, so a cap prevents calls instead of discarding
their results.

### Descriptor-first

A relationship descriptor carries a type and an id, and for most targets that is
the whole identity: a domain descriptor's id is the domain, a file's is its hash.
Those are fetched as descriptors.

Two shapes are the documented exception, because their identity lives in an
attribute:

- a **URL** descriptor's id is GTI's opaque base64 identifier;
- a **resolution** object's id concatenates an address and a hostname.

If a URL still cannot be recovered, the target is counted and skipped rather than
invented — putting an opaque identifier in as if it were a URL would fabricate an
observable.

### Direction

Relationships are directed by meaning, not by GTI's naming.
`communicating_files` on a domain means "that file contacted this domain", so the
related file is the source. DNS resolution is always domain-to-address, so the
direction depends on which end the investigation started from.

### Evidence

Every relationship carries its own evidence, because "this file contacted that
domain" is a distinct claim a later layer must be able to weigh or discount on
its own. That evidence is `CONTEXT_ONLY`: a connection is a behavioural fact, not
an accusation, and treating every observed connection as incriminating is how
legitimate CDN traffic becomes a verdict.

### Capability gating

Relationships are only requested when the caller asked for the matching
capability. A reputation lookup requests none; a threat-attribution lookup skips
infrastructure. Neither quietly spends an analyst's quota on a pivot graph.

| Relationship group | Capability |
|---|---|
| infrastructure and behaviour | `RELATIONSHIPS` |
| `malware_families` | `MALWARE_INTELLIGENCE` |
| `associations`, actors, reports, campaigns | `THREAT_ASSOCIATIONS` |
| sandbox behaviour summary | `FILE_BEHAVIOR` |

## 10. Threat associations

Curated attribution becomes association claims:

```
evidence_class : CURATED_THREAT_ASSERTION
claim_type     : gti.threat_association.<relationship>
effect         : SUPPORTS_MALICIOUS
attributes     : gti_collection_id, gti_collection_type, name | name_available
```

**Names are never invented.** A collection descriptor's id is an internal
identifier, and turning `collection--1a2b3c` into an actor called "1a2b3c" would
put a fabricated actor into the graph. Without a name the association is still
recorded, with `name_available: false` so a reader can tell "GTI did not name it"
from "nobody looked".

**Task 3's model is not extended for one provider.** Only malware families become
objects, because Task 3 already models malware; actors, campaigns and reports
stay association claims carrying their collection type and id. Adding three
first-class object types to hold a GTI identifier would be a data-model decision
made for one integration's convenience, and it loses nothing an analyst needs to
keep them as claims. Full threat-object modelling belongs to a later task.

## 11. File behaviour (DEEP only)

Sandbox behaviour requires three conditions at once: the observable is a **file**,
the investigation is **DEEP**, and **`FILE_BEHAVIOR`** was requested. Detonation
data is the most expensive and most entitlement-sensitive thing GTI offers, so it
is never pulled speculatively.

Only the aggregated `behaviour_summary` is read. Individual sandbox reports are
numerous, heavily duplicated, and not what an analyst reads.

What is normalized:

```
dns_lookups        -> domain objects, CONTACTS
ip_traffic         -> address objects, CONTACTS
http_conversations -> url objects, CONTACTS
files_dropped      -> file objects, DROPS
tags / verdicts / calls_highlighted -> one bounded context claim
```

Behaviour evidence is `DIRECT_OBSERVATION` — something genuinely watched it
happen — but stays `CONTEXT_ONLY`. Contacting a domain during detonation is a
fact about behaviour; deciding what it means about the sample belongs to fusion.
A test asserts behaviour alone produces no malicious-leaning evidence.

## 12. Quota

Quota is read from `/users/{apikey}/overall_quotas` and mapped onto the generic
Task 6 `ProviderQuotaSnapshot`:

```
api_requests_hourly   -> QuotaPeriod.HOUR
api_requests_daily    -> QuotaPeriod.DAY
api_requests_monthly  -> QuotaPeriod.MONTH
```

### Only API-request buckets gate execution

The response also reports allowances for features TI Recon does not use, and
`ProviderQuotaSnapshot.is_exhausted` is true if *any* bucket is spent. Putting a
spent `intelligence_searches_monthly` into the snapshot would therefore switch
GTI off entirely over an allowance no lookup consumes. Only `api_requests_*`
buckets go into the gating snapshot; the rest are still parsed and returned
alongside it, so nothing is silently discarded.

### The API key is in that path

**The quota endpoint's path contains the API key.** It is therefore built only
inside the client, used once, and never stored, returned, logged, cached, or
attached to an error. A failure logs `GTI quota lookup failed` plus a normalized
category and error code — never the path. Tests assert the key, `/users/` and
`overall_quotas` are all absent from logs, metrics, outcomes, raw references and
cache keys.

### Caching

Quota is **not** requested before every lookup. Rather than adding a second
cache, the adapter is handed Task 6's own `QuotaStore` and rebuilds the
executor's scope key from ids, so both sides address the same entry and agree on
freshness. The default TTL is 5 minutes and is configurable. A failed refresh is
swallowed: quota is useful context, and losing it must not turn a successful IOC
lookup into a failed one.

## 13. Credential validation

Validation reuses the quota endpoint — the cheapest authenticated call available,
touching no IOC and consuming no lookup allowance.

| Outcome | Status | Why |
|---------|--------|-----|
| quota returns | `ACTIVE` | |
| `WrongCredentials` / `AuthenticationRequired` / `UserNotActive` | `INVALID` | The only thing that invalidates a key |
| `ForbiddenError` | `UNKNOWN` | Usually "this key may not do this one thing" |
| `QuotaExceeded` | `ACTIVE` | An allowance belongs to an account; an unknown key could not have spent one |
| transient / rate-limited / unknown | `UNKNOWN` | A provider outage must never invalidate every analyst's key |

Capability discovery costs **no API call**. Probing each capability would spend a
request and still be a guess, since entitlement differs per object type and per
relationship. What a key may actually do is discovered at request time, where a
refusal becomes `PLAN_LIMITED` for that one operation.

## 14. Errors

vt-py's `APIError.code` values map onto Task 5 categories:

| GTI code | Category |
|----------|----------|
| `AuthenticationRequiredError`, `WrongCredentialsError`, `UserNotActiveError` | `AUTHENTICATION_ERROR` |
| `ForbiddenError` | `PERMISSION_ERROR`, or `PLAN_LIMITED` on an entitlement-gated operation |
| `NotFoundError` | `NOT_FOUND` |
| `BadRequestError`, `InvalidArgumentError`, `UnselectiveContentQueryError`, `UnsupportedContentQueryError` | `INVALID_REQUEST` |
| `QuotaExceededError` | `QUOTA_EXCEEDED` |
| `TooManyRequestsError` | `RATE_LIMITED` |
| `NotAvailableYet`, `TransientError`, `DeadlineExceededError`, `FailedDependencyError` | `TRANSIENT_ERROR` |
| anything else | `UNKNOWN_ERROR` |

A `NotFoundError` on the primary lookup becomes a **`NO_DATA` envelope** rather
than a propagated error. Both routes report `NO_DATA` through Task 6, but only an
envelope can be negatively cached, so an unknown hash costs one API call rather
than one per investigation that asks about it.

**`NO_DATA` is not benign.** It means GTI has never seen the object.

Error messages are scrubbed of the known key literal, then generically redacted,
then dropped entirely if they still resemble credential material.

## 15. Partial results

A recognized field that will not parse degrades the result to `PARTIAL` and keeps
whatever did parse — losing a whole useful response because one optional
attribute changed shape would be the wrong trade. Task 6 keeps a partial
result's evidence while declining to cache it, so a truncated answer cannot later
be mistaken for a complete one.

A **missing** `gti_assessment` is different: it warns `GTI_ASSESSMENT_UNAVAILABLE`
and stays `SUCCESS`. It is common and benign — an entitlement, or simply no
assessment yet — and nothing here guesses which.

## 16. Caching and isolation

Task 6's cache is used unchanged, so isolation is per user and per provider
connection by construction:

```
success  -> 1 hour     (a GTI verdict on a file is stable over hours)
no data  -> 5 minutes  (what GTI has never seen is what changes first)
partial  -> not cached
failures -> never cached
```

There is no cross-user GTI cache sharing, and no Redis in Task 7 — all execution
state remains in-memory and single-process, as documented in
[provider-execution.md](../provider-execution.md).

## 17. Data-use boundary — read before connecting an AI layer

GTI data is **provider-policy-sensitive**. Task 7 deliberately does not connect
GTI to Claude, MCP, or any other AI layer, and nothing here should be taken as
permission to.

> Before exposing raw or normalized GTI content to an AI layer — MCP tool
> results, Claude prompts, a Skill, or any model-visible surface — the applicable
> Google Threat Intelligence contractual and data-use terms must be reviewed.
> Provider terms commonly restrict redistribution and onward processing, and
> "the model is just summarizing it" is not a determination this codebase can
> make on an operator's behalf.

The architectural boundary that makes this reviewable already exists: the core
engine is Claude-independent, and the MCP and Skill layers sit above TI Recon as
separate future components. Task 7 preserves it and adds no policy engine.

## 18. Optional live tests

Disabled by default. Enable explicitly:

```bash
RUN_GTI_LIVE_TESTS=1 VT_APIKEY=<your key> uv run pytest tests/live -q
# optional
GTI_X_TOOL=yourorg.yourtool.0.1
```

Without both variables every live test skips, so a default `pytest` run, CI and
pre-commit never contact Google.

They use passive GETs at `QUICK` depth (one API call each), make no submissions,
scans or downloads, write nothing to disk, and never print the key. They assert
that a request succeeds and that the response normalizes — **not** today's
verdict for any object. Provider data changes, and a test that fails because
Google reclassified something teaches people to ignore failures. The smoke
object is `8.8.8.8`: well-known, public, and not infrastructure that may vanish.

## 19. Not implemented

Deliberately out of scope for Task 7:

```
GTI Intelligence Search        Threat Profiles       Threat Lists
IOC Streams                    DTM                   ASM
full threat-object research    active scanning       file/URL submission
sample downloads               sandbox detonation
```

Intelligence Search is a **pivot and discovery** capability, not something core
IOC enrichment needs. It belongs with the query planner and pivot engine, and
deferring it keeps both the complexity and the quota risk of this milestone down.
