# MISP Warning Lists

Task 11. `src/ti_recon/providers/misp_warninglists/`

MISP Warning Lists is TI Recon's source of **local false-positive and
infrastructure context**. It answers a question none of the remote providers do:

> Does this observable have characteristics — shared hosting, a public resolver,
> a special-use range, a known scanner, a popular domain, a known-good hash, a
> test artifact — that should change how I read the other evidence?

It is not a reputation source, and it never says anything is benign.

---

## 1. The one rule

**Every warninglist hit is `EvidenceClass.CONTEXT` with
`EvidenceEffect.CONTEXT_ONLY`.** Never `SUPPORTS_BENIGN`. Never
`SUPPORTS_MALICIOUS`.

A match means *this value has characteristics that may explain, qualify or
de-prioritise other evidence*. It does not mean the value is safe:

* a cloud range hosts malicious infrastructure daily;
* a CDN serves malware;
* a popular domain has a malicious path on it right now;
* a legitimate scanner still trips alerts;
* an EICAR hash is a *test artifact*, which is a specific thing rather than an
  ordinary benign file;
* and a warninglist can simply be stale — upstream has carried infrastructure
  later found to be hosting attacks.

So this provider contributes context and stops. Deciding what a
`SUPPORTS_MALICIOUS` ThreatFox record plus an Azure-range hit adds up to is
false-positive reasoning; it belongs to the future fusion layer, and an adapter
that pre-empted it would be overwriting a provider's fact with a guess.

The class is not a parameter of the evidence builder. `EvidenceClass.CONTEXT`
also makes the Task 3 model *enforce* the direction ban, so a future edit here
cannot quietly introduce one.

---

## 2. No server, no key, no network

| | |
|---|---|
| MISP instance | **not required** |
| MISP URL or API key | **not required** |
| PyMISP / PyMISPWarningLists at runtime | **not used** |
| MISP Feedback daemon, Rust, Redis, a database | **not required** |
| Network access during a lookup | **none** |
| Credential | **none** — `requires_credentials = False` |

A lookup reads an in-memory index compiled at adapter construction. No file is
opened, no path resolved, no name looked up and no socket created while an
investigation is running.

This is enforced structurally rather than by discipline. The package contains no
client and no transport, and tests assert by AST that no module imports `httpx`,
`requests`, `aiohttp`, `socket`, `ssl`, `urllib.request`, `http.client`, `pymisp`
or the shared transport, and that none calls `Popen`, `getaddrinfo`, `urlopen` or
`connect`. A further test asserts the lookup path opens no file at all.

That absence is the point of the task: a false-positive-context source needing a
server and a key would be unavailable exactly when an analyst most wants it —
during triage, offline, on a laptop.

---

## 3. The dataset, and its provenance

The authoritative source is [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists),
licensed **CC0-1.0** (individual lists may carry their own terms; the manifest
records the dataset license rather than flattening that away).

TI Recon ships a pinned snapshot **inside the package**, at
`src/ti_recon/data/misp_warninglists`:

```
src/ti_recon/data/misp_warninglists/
  manifest.json        provenance, per-list metadata, omissions, diagnostics
  lists/<slug>.json    one upstream list, compact, exactly the raw schema
```

`DEFAULT_SNAPSHOT_ROOT` resolves it with `importlib.resources.files("ti_recon")`,
so a source checkout, an editable install and an installed wheel all find the same
dataset without anyone counting directory levels.

> **A packaging bug worth recording.** The default used to be
> `Path(__file__).parents[3].parent / "data" / "misp_warninglists"`, which found
> the snapshot in a checkout and, once installed, resolved to
> `<venv>/lib/python3.12/data/misp_warninglists` — a directory that never
> existed, because the wheel shipped `src/ti_recon` only. The source tree and the
> distribution had different default behaviour, which is the one thing a default
> must not have. Moving the dataset into the package made it a resource the
> import system can locate rather than a path derived from repository layout.

The packaged copy is an **immutable baseline**: read-only application data that a
deployment can rely on offline. `MispWarningListsConfig.snapshot_root` overrides
it with a newer external snapshot, and an explicit path always wins — a bad one is
reported rather than quietly replaced by the baseline.

The manifest records the upstream repository, the exact commit, when the snapshot
was built and by what, a schema fingerprint, a dataset fingerprint, per-list
entry counts and per-list SHA-256s. A local dataset without that is a pile of
JSON somebody has to take on faith.

Two properties follow from putting each list's matcher type and entry count in
the manifest:

* a **profile decides what to load before anything is parsed**, so an excluded
  list is never read off disk;
* a **modified list file is refused** rather than surfacing later as a strange
  match.

### PyMISPWarningLists is not the runtime engine

It was considered and rejected as the authoritative matcher, for reasons worth
recording:

* its bundled snapshot lags upstream — 1.7.0 was released in January 2026 while
  upstream has continued changing through August;
* its convenience search does not gate by `matching_attributes`, which is the
  authoritative rule this provider is built around (§5);
* TI Recon needs explicit match scope, lineage and coverage semantics that a
  generic search does not express.

A small native matcher that fits our data model beats wrapping behaviour that
does not, so the dependency is not taken.

### MISP Feedback is not a dependency

Referenced as useful prior art — matcher behaviour, performance expectations,
include/exclude design — but not required. Task 11 must not need a Rust
toolchain, a daemon or a Unix socket to consult a list of private IP ranges. The
measurements in §8 say the Python implementation is comfortably adequate, so no
optional backend is designed on speculation.

---

## 4. Refreshing the snapshot

An explicit operator action, and the only code in the repository that runs
`git`:

```bash
git clone --depth 1 https://github.com/MISP/misp-warninglists /tmp/mwl
uv run python tools/update_misp_warninglists.py \
    --source-dir /tmp/mwl \
    --output-dir src/ti_recon/data/misp_warninglists
```

The tool takes a **directory, never a URL**. That split is the security boundary:
acquisition is yours, parsing is the tool's, so there is no origin to redirect, no
credential to leak and no download to validate. Automate the `git clone` in your
own pipeline if you want it automated.

It validates the checkout's shape, refuses anything that is not the official
schema, bounds the snapshot by entry count, writes compact per-list files plus
the manifest, and **swaps atomically** — an interrupted build leaves the previous
snapshot exactly as it was. Nothing updates a snapshot on application startup and
nothing can trigger a refresh from a lookup.

The tool refuses an `--output-dir` inside `site-packages` or `dist-packages`:
rewriting an installed distribution in place would leave the wheel's `RECORD`
hashes wrong and be discarded on the next reinstall, while looking exactly like a
successful refresh. Build a new snapshot into a checkout or an external directory
and point `snapshot_root` at it.

`--max-list-entries` (default 100,000) keeps the shipped dataset small enough to
live in a repository. Pass `0` for an unbounded snapshot.

---

## 5. `matching_attributes` is authoritative

A warninglist declares which MISP attribute types it is about. Evaluating it
against anything else is not a generous near-miss — it is a different question. A
hostname list checked against an MD5 would be nonsense even if the strings
happened to collide.

So a lookup does not search "the observable" against "the lists". It builds the
explicit MISP attribute values the observable legitimately *is*, and each list is
offered only the candidates whose attribute type it declares.

| Observable | Candidates | Scope |
|---|---|---|
| IPv4 / IPv6 | `ip-src`, `ip-dst` (same value) | `EXACT_OBSERVABLE` |
| Domain | `domain`, `hostname` | `EXACT_OBSERVABLE` |
| URL | `url`, `uri` (full canonical URL) | `EXACT_OBSERVABLE` |
| URL | `hostname` (**parsed host**) | `SAME_HOST` |
| File | `md5`, `sha1`, `sha256` — every digest present | `EXACT_OBSERVABLE` |
| File | `filename|md5` etc. — only with a real filename | `EXACT_OBSERVABLE` |

An absent `matching_attributes` means the list applies to everything. Worth
noting: **no list in the pinned snapshot omits the field** — all 143 declare
theirs — so that path exists for schema correctness rather than for today's data,
and a fixture exercises it.

**Nothing is fabricated.** No `domain|ip` for a bare domain, no `ip-src|port` for
a portless address, no `filename|md5` unless a filename is genuinely recorded. A
composite invented from half its parts would match upstream entries about
something else. A file's filename is rejected if it contains `|`, which would
change which attribute type the composite is.

**Every hash is checked, not just the strongest.** Unlike a metered remote API
there is no request to spend, and the false-positive hash lists genuinely differ
in which algorithm they hold.

### One observable, several candidates, one finding

A domain is both a MISP `domain` and a `hostname`; a file offers three digests. A
list matching through two of them is deduplicated into one match record — one
contextual fact about one artifact. Without that, a single dataset would look
like corroboration.

---

## 6. A URL's host is not the URL

The distinction this provider turns on.

`https://github.com/attacker/payload.exe` matching a popular-domain list is a
fact about `github.com`. Reporting it as a fact about the URL is how a
living-off-trusted-sites payload gets waved through.

So the derived host is a separate candidate at `SAME_HOST` scope, tagged
`url_host`, and the evidence says so three ways: the record's `match_scope`, each
match's `candidate_component`, and an explicit `host_component_only` flag that is
true when *every* match came from the host rather than the artifact.

The host is **parsed**, never searched for. Substring-matching a raw URL against
a hostname list would let a path or query string masquerade as a host:
`http://evil.example/?ref=github.com` is not GitHub-hosted, and returns no match.

`match_scope` on the finding is the **narrowest** scope among its matches —
deliberately pessimistic, because overstating precision is the failure that turns
a hosting fact into a statement about an artifact.

No URL is ever fetched or resolved.

---

## 7. Matchers

| Matcher | Lists (snapshot) | Entries | Supported |
|---|---|---|---|
| `cidr` | 80 | 142,874 | yes |
| `string` | 38 | 3,977,343 | yes |
| `hostname` | 20 | 1,086,279 | yes |
| `substring` | 3 | 8,368 | yes |
| `regex` | 2 | 34 | **no — see below** |

**`string`** is exact. No case folding, no trimming, no dot repair.

**`substring`** is containment. Blank entries are refused at load: an empty or
whitespace-only entry would match nearly every value ever submitted, which is
exactly the sort of upstream typo that would flag every observable forever.

**`hostname`** is domain-boundary-safe suffix matching, done by comparing whole
label suffixes rather than `endswith` — so the boundary cannot be straddled:

```
example.com  matches  example.com, sub.example.com, deep.sub.example.com
             not      evil-example.com, notexample.com, example.com.evil.test
```

Hostnames are lowercased and one trailing root dot is trimmed.

**`cidr`** uses the standard library only, with single addresses in a set of
integers and real networks bucketed by prefix length, so a lookup masks once per
distinct prefix length instead of testing 72,600 networks. **No DNS**: a domain
is never resolved to make a CIDR list applicable, because that would turn a
deterministic local lookup into a network call whose answer changes with the
resolver.

### Upstream data is honoured, not repaired

`dynamic-dns` writes all 35,467 of its hostname entries with a leading dot
(`.dynv6.net`). With the dot upstream means "subdomains of dynv6.net" and
deliberately not the bare domain, so `foo.dynv6.net` matches and `dynv6.net` does
not. Stripping the dot would look like tidying and would silently widen the
claim.

`google` and `microsoft` are **`string`** lists — exact matching — that *also*
hold leading-dot entries. Those can never equal a canonical domain. Rewriting
them into suffix rules would manufacture matches upstream never asserted, so they
are counted in `unmatchable_entry_count` and left exactly as they are.

### Regex: recognized, recorded, never executed

Upstream regex entries are PHP `preg_match` patterns, delimited and flagged for
that engine — `/((?:\+|00)1)?([0-9]{3})55501([0-9]{2})/g` is a real one, and
Python's `re` has no `g` flag at all.

The pinned snapshot settles whether a compatibility layer is needed. It contains
exactly two regex lists holding 34 entries:

| List | `matching_attributes` |
|---|---|
| `common-contact-emails` | `email-src`, `email-dst`, `target-email` |
| `phone_numbers` | `phone-number`, `whois-registrant-phone` |

Neither declares a single attribute type TI Recon can produce a candidate for. So
**no applicable regex list exists**, and adding a regex engine would buy nothing
while adding a dependency, a timeout and a class of catastrophic-backtracking
hang inside an investigation. Patterns are parsed far enough to confirm they are
PCRE literals and counted; that is all.

**No claim of PCRE compatibility is made.** If a future snapshot adds a regex
list targeting an IP, domain, URL or hash attribute, it is reported as an
unsupported *applicable* matcher and the lookup becomes `PARTIAL` — visibly,
rather than skipped in silence. A test asserts the current situation against the
real dataset, so that refresh fails loudly and the decision gets revisited.

---

## 8. Profiles, and the measured default

The pinned upstream snapshot holds **143 lists and 5,214,898 entries**. Twenty
lists hold **4,910,632** of them, and the popularity rankings among those are
nested subsets of each other — `example.com` appears in thirteen Cloudflare tiers
plus Tranco, CrUX, Majestic and Moz. Loading everything costs about **510 MB** of
retained heap to learn one fact sixteen times.

So the default `core` profile bounds it, by two explicit rules:

| Reason | Rule | Lists |
|---|---|---|
| `oversized` | more than `max_list_entries` (default 100,000) | 8 |
| `redundant_popularity_tier` | a nested tier superseded by a retained one | 12 |

Two independently produced 10k rankings are kept (`cloudflare-top10k`,
`cisco_top10k`) so "this is a commonly visited domain" still has more than one
source, at 20,000 entries total.

### Measured

Against the shipped snapshot, via `tools/measure_misp_warninglists.py`:

| | core (default) | full, unbounded snapshot |
|---|---|---|
| Lists | 123 | 143 |
| Entries | 304,266 | 5,214,898 |
| Retained heap | **34.3 MB** | ~510 MB |
| Transient peak | 41.0 MB | ~538 MB |
| Cold load | 2.18 s | ~3 s |
| Disk (shipped) | 9.3 MB | 133 MB compact |

Applicable lists and entries per observable family, core profile:

| Family | Lists | Entries |
|---|---|---|
| IPv4 / IPv6 | 81 | 143,015 |
| Domain | 33 | 120,234 |
| URL | 33 | 120,234 |
| File | 6 | 32,919 |

Median lookup latency: IPv4 1.8 ms, domain 0.8 ms, URL+host 0.9 ms, file hash
0.7 ms. IPv4 is slowest because 81 CIDR lists apply to it. All of it is an order
of magnitude under any remote provider.

The transient peak sitting just above the retained size is the manifest-driven
profile working: excluded lists are never parsed, so the million-entry rankings
cost nothing rather than being allocated and freed.

### Exclusion is never silent

Two different kinds of absence, kept apart because they need different fixes:

* **`snapshot_omitted`** — the snapshot never contained it. Needs a rebuild.
* **`profile_excluded`** — the profile left it out. Needs a config change.

Both travel into coverage, and `all_lists_checked` is `false` whenever either
applies. **No result may imply "all MISP warninglists checked".**

### Profile fingerprint

A digest over every setting that changes what gets checked: profile id, includes,
excludes, entry ceiling, dropped tiers. Paired with the snapshot's dataset
fingerprint as the cache discriminator — see §10.

---

## 9. Status, coverage and staleness

| Status | When |
|---|---|
| `SUCCESS` | at least one list matched. Every record `CONTEXT_ONLY`. |
| `NO_DATA` | everything applicable was checked and nothing matched. |
| `PARTIAL` | a list that **applies to this observable** could not be evaluated. |
| `ERROR` | no usable dataset: snapshot absent, unreadable, or manifest invalid. |
| `NOT_SUPPORTED` | the observable produces no MISP candidates. |

**`NO_DATA` does not mean benign.** It means no selected list in this snapshot
matched, and nothing more — not clean, not trusted, not safe. Most values an
analyst submits are in no warninglist at all; that is the normal case for a
targeted attack and equally for an ordinary corporate host. The record says so
outright with `means_benign: false` rather than leaving it to be inferred.

**`ERROR` is never reported as an absence.** A provider that could not read its
data has not answered the question, and telling an analyst "no warninglist
matched" in that situation is the one failure mode worth being strict about.

**Partiality is applicability-aware.** A malformed phone-number regex list is
irrelevant to an IPv4 lookup and does not degrade it; an unusable CIDR list does.
Without that, every lookup would inherit every defect in the dataset and
`PARTIAL` would stop carrying information.

### Coverage

Reported as a `misp_warninglist_coverage` context record — the Task 9/10 pattern,
since `CoverageItem` is a per-capability investigation model with no place for
per-lookup dataset provenance. It carries:

`dataset_commit`, `dataset_fingerprint`, `dataset_license`,
`snapshot_generated_at`, `snapshot_age_days`, `snapshot_stale`,
`snapshot_stale_after_days`, `profile_id`, `profile_fingerprint`, `depth`,
`snapshot_lists`, `snapshot_entries`, `loaded_lists`, `loaded_entries`,
`profile_excluded_lists`, `snapshot_omitted_lists`, `applicable_lists`,
`applicable_entries`, `checked_lists`, `candidate_attribute_types`,
`matcher_types_available`, `unsupported_applicable_lists`,
`unusable_applicable_lists`, `invalid_entry_count`, `invalid_cidr_count`,
`invalid_regex_count`, `unmatchable_entry_count`, `malformed_list_count`,
`total_matches`, `normalized_matches`, `truncated`, `all_lists_checked`, and
`partial_reason` when partial.

Diagnostics are counts and short reasons only. A diagnostic that dumped list
contents would be a log that leaks a dataset.

### Staleness

`stale_after` is operator-configurable (default 30 days). A stale snapshot is a
**successful lookup whose coverage says the data is old** — not a failure, and
never an automatic refresh. Failing would be useless; refreshing silently would
be dishonest. Health reports `degraded`.

---

## 10. Evidence, lineage and caching

| Claim type | Class | Effect |
|---|---|---|
| `misp_warninglist_matches` | `CONTEXT` | `CONTEXT_ONLY` |
| `misp_warninglist_no_match` | `CONTEXT` | `CONTEXT_ONLY` |
| `misp_warninglist_coverage` | `CONTEXT` | `CONTEXT_ONLY` |

**One finding, not one per list.** `8.8.8.8` matches `public-dns-v4` and
`vpn-ipv4`; `example.com` matches `rfc6761` and the retained popularity tiers.
They become a single `misp_warninglist_matches` record with bounded per-list
detail — one Evidence per list would let a single curated dataset outvote
genuinely independent intelligence purely by being thorough.

Each match record carries: `list`, `list_name`, `matcher`, `matched_entry`,
`candidate_attribute_type`, `candidate_component`, `match_scope`,
`list_entry_count`, `matching_attributes`, and `matched_by_hash` for a file. The
matched entry is kept because it makes the finding checkable; **one** entry,
never the list. `list_name` is the upstream list's own name, bounded, so the
analyst report can say "Matched misp list: Reserved IPv4 (rfc5735)" rather than
a slug alone (Task 24 Phase 3); the upstream *description* is prose and is
deliberately not carried. Both the name and the matched entry travel on the
Task 15 context signal and reach the report's `context` section.

A URL whose host is an IP literal currently derives no host-component
candidate, so a warninglist match on that address is not found through the
URL. Recorded as T24-FINDING-10; a hostname host is derived as documented in §6.

There is **no `category` field**. MISP's runtime database and Feedback expose
`false_positive` and `known`, but the raw upstream schema does not — so putting
one here would mean inventing provenance for a value nothing depends on, since
every hit is `CONTEXT_ONLY` regardless.

### Lineage

| | |
|---|---|
| `transport_provider` | `misp_warninglists` |
| `origin_provider` | `misp_warninglists` |
| `source_family` | `misp` |
| `lineage_group_id` | `misp:warninglists:<dataset fingerprint prefix>` |

**One group for the whole dataset.** `public-dns-v4`, `censys-scanning`,
`rfc1918` and `cloudflare` are not four providers agreeing — they are four
records from one curated source. The snapshot fingerprint is part of the group so
context from two dataset versions stays distinguishable rather than silently
merged.

No Admiralty grading and no `provider_confidence`: how much a warninglist hit is
worth is TI Recon policy, and an adapter asserting it would smuggle in the
judgement this provider exists not to make.

### Caching

The generic `ProviderDescriptor.dataset_version` field carries
`<profile fingerprint>:<dataset fingerprint>`, and `build_cache_key` includes it
exactly as it already includes `api_version` and `adapter_version`. Refreshing
the snapshot or changing the profile changes every cache key.

Both halves are load-bearing: the snapshot alone would serve one profile's
answers to another, the profile alone would serve yesterday's data after a
refresh. **No provider-name branch in `ProviderExecutor`**, no snapshot hash in
the provider id or the observable value, and no invented API version — a test
asserts `execution/` mentions nothing about MISP, warninglists, snapshot roots or
profile fingerprints.

| Setting | Value |
|---|---|
| Cache scope | `CacheScope.USER` |
| Success / no-data TTL | 24 h |
| Max concurrency | 8 |
| Quota pre-check | off — there is no allowance to consult |
| Retries | 1 attempt; retrying a local match changes nothing |

---

## 11. Depth

Every depth searches the **same** lists. This departs from the remote providers,
where QUICK legitimately means "spend less" because each request costs an
allowance. There is nothing to spend here, and a QUICK lookup consulting fewer
warninglists would answer a *different question* — an analyst would have to know
which depth ran to know what "no match" covered. Coverage that varies by depth is
worse than useless.

| Depth | Match records rendered |
|---|---|
| `QUICK` | 10 |
| `STANDARD` | 25 |
| `DEEP` | 50 |
| Hard ceiling | 100 |

`total_matches`, `normalized_matches`, `truncated` and the full `matched_lists`
always survive truncation.

---

## 12. Security boundaries

* **No network, no DNS, no URL fetch, no subprocess, no MISP API, no git** during
  a lookup — asserted structurally by AST, not by convention.
* **No directory traversal.** Slugs are pattern-checked before they touch a path;
  resolved paths must stay under the snapshot's `lists/` directory, which also
  catches a symlink pointing out of the tree.
* **Bounded reads.** File sizes are checked before the read, so an implausible
  file is never brought into memory. Entries are length- and
  control-character-bounded.
* **Checksums verified** before a list is parsed as a warninglist.
* **Safe error messages.** A manifest that fails validation reports a stable
  message rather than echoing content that could quote the dataset.
* **No raw list contents in logs or diagnostics** — counts and short reasons only.
* **No regex execution**, so no regex hang.
* **Atomic snapshot replacement**, and no updater origin to point anywhere.

---

## 13. Not implemented

* Any MISP instance integration: events, attributes, galaxies, taxonomies,
  sightings, or the MISP REST API. A future MISP-instance provider would share
  `source_family = "misp"` so it cannot read as an independent second source.
* Regex matching (§7), and any claim of PCRE compatibility.
* Non-TI-Recon attribute families: email, phone, `x509-fingerprint-*`, `sha512`,
  `sha224`, and the composites TI Recon cannot construct.
* Automatic dataset refresh, upstream fetching from the provider, and any
  network integration test.
* An optimised non-Python backend. The measurements in §8 say none is needed;
  if that changes, the numbers are the argument, not the intuition.

## Semantic categories (Task 15)

This provider deliberately invented no category field: the pinned CC0 schema has
no authoritative semantic classification, and putting one here would have meant
fabricating provenance.

Task 15 supplies the categories as **engine policy** instead, in
`reasoning/policy.py`, keyed on the **exact slug** and versioned
(`WARNINGLIST_MAP_VERSION`). Seventy slugs map to `PUBLIC_RESOLVER`,
`KNOWN_SCANNER`, `PRIVATE_OR_SPECIAL_USE`, `SHARED_CLOUD_OR_CDN`,
`POPULAR_OR_COMMON_SERVICE`, `TEST_ARTIFACT` and `EMPTY_ARTIFACT`.

Never on a name, a description or a substring: `if "scanner" in name` would
reclassify a list the day upstream reworded it, and would call
`automated-malware-analysis` scanning infrastructure because of a word. A test
asserts every mapped slug exists in the shipped snapshot, so a refresh that
renames or drops one fails loudly instead of silently downgrading a categorized
signal. An unmapped list still produces `WARNINGLIST_MATCH` with its slug.

`snapshot_generated_at` becomes a `SNAPSHOT_GENERATED_AT` fact on a
**dataset-scoped** subject, so it can never be mistaken for a fact about the
observable, and this provider's own staleness verdict is carried through as
`DATASET_STALE` / `DATASET_CURRENT` rather than re-derived. A match on a URL's
host stays `SAME_HOST` and `host_component_only`, and raises
`HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL`.

None of it certifies benignness. The upstream project describes these lists as
values associated with potential false positives, errors and mistakes — a prompt
to look again, not an acquittal.
