# Censys

Task 9. `src/ti_recon/providers/censys/`

Censys is TI Recon's source of **internet exposure and infrastructure context**.
It scans the internet and records what answered: which ports respond, what
software is visible behind them, which certificate is served, which names point
at the asset.

It is the complement to GreyNoise. GreyNoise says what an address *does*; Censys
says what is *exposed on* it. Neither says whether it is malicious.

---

## 1. What this provider is, and is not

**It is** a first-hand observer of exposure. Censys runs its own scanners, so a
service, a certificate, a DNS name and a reported vulnerability from one response
are all things Censys saw — four claims from one scan, sharing one lineage group.

**It is not a verdict source.** Not one function in this package can produce a
direction. An open port is not an accusation, an outdated nginx is not malware, a
reported CVE is not a compromise, and a `login-page` label describes millions of
legitimate sign-in forms. The descriptor says so too: there is no `REPUTATION`
capability and no `THREAT_ASSOCIATIONS`.

**It is not the web-forensics provider.** urlscan owns that. Nothing here
retrieves a response body, and `WEB_FORENSICS` is not declared.

**It cannot search.** One observable maps onto one deterministic asset identity
and one request. CenQL is deferred — see §11.

---

## 2. Credentials

A Censys personal access token, stored per analyst by the Task 4 credential
layer.

| | |
|---|---|
| Auth type | `AuthType.BEARER_TOKEN` |
| Header | `Authorization: Bearer <PAT>` |
| Credential group | `censys` |
| Placement | Header only, applied by the shared transport at request time |

The token never appears in a path, a query string, a cache key, an error message
or a log line. `CensysConfig` has no field for it.

Validation reads the account's **credit balance**, which costs zero credits. That
is the whole point: every asset read costs a credit, so validating a token by
looking something up would charge the analyst for the privilege of being told
their key still works.

### The organization id

Censys reports credits at two addresses — one for the user a token belongs to,
one for a named organization — and which applies is a property of the
*credential*, not the deployment.

It is not a secret; it appears in a URL path. But it is not global configuration
either, so it lives in `ProviderConnection.metadata` under `organization_id` and
is resolved per lookup through `OrganizationDirectory`. `CredentialMaterial`
deliberately carries nothing but identifiers and the secret, and widening it to
hold provider-specific settings would make every future provider's configuration
travel with every resolved secret.

Every resolution is scoped by **user and connection**. The id decides whose
balance is read; if one analyst's connection id could resolve another's
organization, TI Recon would report the wrong balance and send a request against
an account the caller has nothing to do with.
`ConnectionOrganizationDirectory` resolves through the Task 4 repository, which
already refuses to hand one user another's connection.

The id is shape-checked (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`) before it reaches a
path. An unusable value resolves to `None`, which falls back to the user-scoped
endpoint — and is logged without the value itself.

---

## 3. Endpoints used, and endpoints that do not exist here

Used:

| Endpoint | Cost | Accept |
|---|---|---|
| `GET /v3/global/asset/host/{ip}` | one credit | `application/vnd.censys.api.v3.host.v1+json` |
| `GET /v3/global/asset/webproperty/{hostname}:{port}` | one credit | `application/vnd.censys.api.v3.webproperty.v1+json` |
| `GET /v3/accounts/users/credits` | free | `application/json` |
| `GET /v3/accounts/organizations/{id}/credits` | free | `application/json` |

Deliberately absent, with no code path — not even an unused one:

- `POST /v3/global/search/query` — CenQL and every search
- historical timelines, `at_time` enumeration
- collections, Adversary Investigation
- live rescan, live discovery
- any body or content retrieval

### The client is read-only by construction

`CensysClient` is a `Protocol` with exactly five members — the four reads plus
`aclose` — and `CensysHttpClient` is asserted at type-check time to satisfy it.
Tests also parse the client module and assert that no `post` call and no
`search`/`rescan` literal appears in it.

### Schema-versioned Accept headers

Each asset endpoint asks for the **exact response schema this adapter was written
against**. Sending `application/json` would get whatever shape the API considers
current, which means a schema change could silently reshape normalized evidence;
asking for a pinned schema makes a future incompatible version a visible failure
instead.

### Path safety

Three path parameters exist and each is validated before interpolation:

- an address is parsed with `ipaddress.ip_address` and **re-rendered from the
  parsed object**;
- a hostname is IDNA-validated by the same normalizer that validates analyst
  input, yielding ASCII with no delimiter that could escape a path segment;
- a port must be an integer in `1..65535`;
- an organization id must match the strict identifier pattern above.

---

## 4. The asset mapping

`assets.py` — pure functions, no I/O, no guessing. Censys addresses two kinds of
asset, each with exactly one identity:

| Observable | Asset | Identity | Match scope |
|---|---|---|---|
| IPv4 / IPv6 | host | the address | `EXACT_OBSERVABLE` |
| `https://example.com/login?x=1` | web property | `example.com:443` | `SAME_HOST` |
| `http://example.com/` | web property | `example.com:80` | `SAME_HOST` |
| `https://example.com:8443/a` | web property | `example.com:8443` | `SAME_HOST` |
| `http://198.51.100.7/panel` | host | `198.51.100.7` | `SAME_IP` |
| bare domain | — | none | — |
| file hash | — | none | — |
| `ftp://…` | — | none | — |

Path, query and fragment do not participate in a web property's identity, so they
are dropped from the *lookup* while the original URL remains the investigated
object.

**A web property is not the URL.** It is the host and port the URL lives on, so
its evidence is `SAME_HOST`. Reporting it as exact would let "Censys sees an nginx
here" read as "Censys sees this page".

**A bare domain is unsupported on purpose.** A web property must have a port and a
domain names none. Quietly querying `domain:443` and `domain:80` would spend two
credits and produce a result an analyst would reasonably read as "Censys knows
nothing about this domain" when only two of sixty-five thousand ports were asked
about. That is a blind spot dressed as coverage. Answering it properly needs a
search, which is deferred.

**A file hash is unsupported for a different reason.** Censys does index
certificates by fingerprint, and a SHA-256 file hash is the same 64 hex
characters — so reinterpreting one as the other would be a category error that
produced confident nonsense.

**An address-literal URL becomes a host lookup**, rather than a refusal, and says
so: `MatchScope.SAME_IP`, plus `derived_from: url_authority` in the coverage
evidence. Nobody can mistake "port 443 is open on this address" for "Censys has
seen this page". Its relationships also hang off a *derived* address object
rather than the URL, because a URL does not belong to an autonomous system and a
PTR record does not resolve to a page.

---

## 5. Depth

One asset read is one credit. Depth does not buy a second request, a search, a
historical timeline or an `at_time` enumeration — none of those exist here, at
any depth. Depth decides how much of the already-paid-for document is normalized:

| Depth | Kept |
|---|---|
| `QUICK` | responding ports, ownership, labels |
| `STANDARD` | the above plus services (25), DNS names (25), certificates (5), endpoints (10), vulnerabilities (15) |
| `DEEP` | the same document, bounds raised to the normalizer's ceilings |

Ceilings: 100 services, 200 ports, 100 DNS names, 20 certificates, 50 endpoints,
30 labels, 50 vulnerabilities. A depth policy chooses a number at or below each
ceiling and pydantic refuses anything higher, so no policy — however
constructed — can ask for an unbounded expansion of a provider-controlled list.

Nothing about a deeper lookup makes an asset look more malicious, because nothing
Censys reports has a direction to begin with.

---

## 6. Evidence produced

| Claim type | Class | Effect |
|---|---|---|
| `censys_host_observation` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `censys_network_ownership` | `CONTEXT` | `CONTEXT_ONLY` |
| `censys_services` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `censys_dns_names` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `censys_tls_certificates` | `CONTEXT` | `CONTEXT_ONLY` |
| `censys_labels` | `CONTEXT` | `CONTEXT_ONLY` |
| `censys_vulnerabilities` | `CONTEXT` | `CONTEXT_ONLY` |
| `censys_web_property_observation` | `DIRECT_OBSERVATION` | `CONTEXT_ONLY` |
| `censys_asset_not_observed` | `CONTEXT` | `CONTEXT_ONLY` |
| `censys_asset_coverage` | `CONTEXT` | `CONTEXT_ONLY` |

Every one of them is `CONTEXT_ONLY`, and most are `EvidenceClass.CONTEXT` as
well — which makes the Task 3 model *refuse* to attach a direction rather than
relying on this package to remember not to.

The exposed surface is **one observation, not one per service**. A host with forty
open ports is one observation of one host; splitting it would make a busy server
look like a mountain of findings.

### Lineage: one scan, one source

Everything shares one lineage group, `censys:censys`. "Port 443 open, Let's
Encrypt certificate, two DNS names" is one scanner saying three things, and a
fusion layer must never read it as three sources agreeing.

---

## 7. Raw content is never kept

A Censys response is large and partly attacker-shaped. A banner is whatever the
scanned host chose to send; a certificate subject is whatever was requested; an
HTTP title is whatever the page says.

Never read, and asserted so by tests whose fixtures put attacker-shaped values in
exactly these fields:

- service **banners**
- HTTP **bodies** and **headers**
- **HTML titles**
- geographic **coordinates** and **postal codes** — neither adds anything to an
  exposure question, and both are more precise than an investigation record needs
  to be about a datacentre

What is kept is the *shape* of the exposure: which port, which transport, which
application protocol, which vendor/product/version, which digest. Each block has
an explicit allow-list, unknown keys are ignored, every list is capped, and a
truncation is recorded rather than left silent.

### Fingerprints are not files

Censys reports SHA-256 digests in two places, and neither becomes a `file`
object:

- a **certificate fingerprint** becomes an `x509-certificate` object, because
  that is what it identifies. Certificates are among the best pivots that exist —
  the same certificate on two unrelated-looking hosts is often the strongest link
  between them — and that only works if the fingerprint is modelled as the
  certificate;
- a **body hash** stays a pivot string. Nothing retrieves the body behind it.

Turning either into a `file` would produce an object claiming to be a sample
nobody has.

---

## 8. Vulnerability semantics

This is where the temptation is strongest, so it gets the firmest rule: a
reported vulnerability is `EvidenceClass.CONTEXT`, and the model therefore
refuses to let it carry a direction at all.

A reported CVE means Censys inferred, from a banner or a version string, that the
service *may* be affected. It does not mean the host was exploited, that the
finding was confirmed, or that the host is hostile:

- vulnerable ≠ malicious
- exposed ≠ compromised
- outdated ≠ malware
- an open admin service ≠ an attacker

The evidence records `basis: inferred_from_observed_service_version` so the claim
states its own scope. Findings are collected from the asset block and from each
service, de-duplicated by identifier and bounded. Censys risk names are read
alongside CVE ids.

A future fusion layer may reason about infrastructure risk separately. That is a
different question from whether an indicator is malicious, and keeping them apart
starts here.

---

## 9. Objects and relationships

Each relationship references the evidence that justifies it:

- the **autonomous system** that announces the address → `belongs-to-asn`;
- each **DNS name** → `resolves-to` *pointing at* the address;
- each served **certificate** → `uses-certificate` from the asset.

Ownership and DNS are read for **host assets only**. A web property is a name on
a port, so asking which autonomous system a hostname belongs to would attach a
fact about the address behind it to the wrong object.

Relationships hang off an **anchor**: the submitted observable, except when a URL
was looked up as a host, in which case the address is a derived object and the
links belong to it. The anchor is derived once per lookup and threaded through,
so one address never mints two ids.

Hostnames are validated by the same normalizer that validates analyst input — a
PTR record is chosen by whoever owns the address block, and is no more
trustworthy than something a user typed.

Stable facts are attached to the submitted object under a `censys` namespace: the
ASN and its name, the BGP prefix, country and city, service or endpoint count,
last observed instant.

---

## 10. Credits, rate limits and errors

Censys meters **two independent resources**, and TI Recon must not collapse them:

- **requests per minute** is a throttle. It lifts by itself and retrying is
  exactly the right response.
- **credits** are a purchased balance. When they are gone, waiting achieves
  nothing and every retry is a wasted request against an account that cannot pay
  for one.

Task 6 already models these separately — `RATE_LIMITED` is retryable and produces
a short cooldown, `QUOTA_EXCEEDED` is not — so the whole job of `errors.py` is
routing each status to the right one:

| Status | Category | Note |
|---|---|---|
| 401 | `AUTHENTICATION_ERROR` | the token is wrong |
| 402 | `QUOTA_EXCEEDED` | payment required = the wallet is empty |
| 403 | `PERMISSION_ERROR` | valid token, not permitted — never a quota claim |
| 404 / 410 | `NOT_FOUND` → `NO_DATA` | a finding, not a failure |
| 400 / 406 / 422 | `INVALID_REQUEST` | 406 means the pinned schema was refused |
| 429 | `RATE_LIMITED` | always the throttle, never a credit statement |
| 408 / 500 | `TRANSIENT_ERROR` | |
| 502 / 503 / 504 | `PROVIDER_UNAVAILABLE` | |

Marking a `403` a quota problem would put a working credential on a long cooldown
over an entitlement it will never gain by waiting.

### The credit snapshot

A balance becomes a `ProviderQuotaSnapshot` with a single bucket over
`QuotaPeriod.CUSTOM`. `CUSTOM` is the honest period: labelling a wallet `MONTH`
would invite a scheduler to believe it resets on the first, which nothing about
the balance promises.

A response with no readable counter produces an **empty** snapshot rather than a
bucket of zeroes. That distinction is load-bearing: empty means "we do not know",
and Task 6 treats not knowing as permission to try, while a zero bucket means
"spent" and stops the provider from being called at all.

The balance is refreshed only when Task 6's quota store has nothing fresh, and a
failed refresh is swallowed — the balance is useful context, and losing it must
not turn a successful asset lookup into a failed one. An operator can switch the
refresh off entirely, making a Censys lookup strictly one request per uncached
asset.

Provider text is never trusted verbatim: a message is kept only if it survives
redaction and contains no long opaque token, and `provider_error_code` is the
status code and nothing else. Only a rejected token is ever marked `INVALID` — an
empty wallet, a permission refusal and a throttled minute all mean the token is
fine.

---

## 11. Caching and isolation

`build_censys_execution_policy()` returns a Task 6 policy:

| | |
|---|---|
| Cache scope | `USER` — never `GLOBAL` |
| Success TTL | 6 hours |
| `NO_DATA` TTL | 10 minutes |
| `PARTIAL` TTL | not cached |
| Concurrency | **1** (tunable) |

Three parts are load-bearing.

**The scope stays `USER`.** Censys visibility and entitlement are per-account, and
a lookup is charged to whichever account's token paid for it. Serving one
analyst's asset document to another would hand out data the second analyst's plan
may not include, and would spend nobody's credit for it.

**The cache matters more than usual.** Every asset read costs a credit, so a
repeated lookup that hits the cache is not merely faster — it is the difference
between one credit and two. Successes are therefore kept for a good while: an
asset's exposure profile is the last observed scan, and Censys does not rescan
the internet every hour.

**Concurrency defaults to one.** Censys's per-minute allowance depends on the
plan, this integration cannot discover it, and a free-tier token being throttled
is a worse outcome than a slightly slower investigation. An operator who knows
their plan raises it.

---

## 12. Configuration

`CensysConfig`: `host` (pinned to `https://api.platform.censys.io`),
`user_agent`, `timeout_seconds`.

`CensysLookupPolicy`: `credit_ttl_seconds`, `refresh_credits_on_lookup`,
`depth_detail`.

The host must be `https`, must be an origin with no path, query or fragment, and
is not configurable from a request.

---

## 13. Not implemented

- **CenQL and `POST /v3/global/search/query`** — deferred deliberately: it needs
  query construction and escaping, a pagination strategy, and a cost model that
  charges per page rather than per asset, and deciding *what* to search for is
  query-planner work that does not exist yet
- historical timelines and `at_time` enumeration
- collections, Adversary Investigation
- live rescan and live discovery
- certificate lookup by fingerprint (a TI Recon `file` hash is not a certificate
  fingerprint — see §4)
- bare domains and file hashes as observables
- any body or content retrieval; Censys is not the web-forensics provider
- any active operation — `supports_active` is `False` with no code path to turn on

Live tests are off by default: `RUN_CENSYS_LIVE_TESTS=1` plus `CENSYS_PAT`, and
optionally `CENSYS_ORGANIZATION_ID`. They read the free credit endpoints first and
spend exactly one credit on one well-known host; there is no search test at any
depth.

## Temporal semantics (Task 15)

`providers/censys/qualification.py` maps the asset-level observation instant to
`LAST_OBSERVED` with `SourceLifecycleState.POINT_IN_TIME`, from the host and
web-property records only. Every other Censys record repeats the same instant,
and emitting a dozen copies of one observation would look like a dozen
observations.

It emits **no** certificate validity. Task 9 keeps a certificate's fingerprint,
subject and issuer and deliberately does not normalize `not_before`/`not_after`,
so there is nothing to emit — reading a validity window out of a raw response
would be new provider behaviour rather than a qualification of existing
behaviour.

That omission sits on the safe side of the distinction anyway: a certificate
valid 2024-2026 does not mean the host served it throughout. A validity window is
a property of the certificate; hosts rotate what they present.
