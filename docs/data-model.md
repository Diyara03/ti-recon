# TI Recon — Common Threat Intelligence Data Model

> Task 3. This document describes what is implemented in
> `src/ti_recon/enums.py`, `src/ti_recon/models/` and
> `src/ti_recon/normalization/`.
>
> Nothing here computes a verdict. The fusion and scoring engine is a later
> task; what exists is the shape a verdict must take in order to be
> explainable.

## 1. Vocabularies

All vocabularies are `StrEnum`s in `ti_recon.enums`, so serialized values are
stable readable strings. Implemented vocabularies:

| Enum | Purpose |
|------|---------|
| `ObjectClass` | `observable`, `infrastructure`, `threat` |
| `IntelObjectType` | STIX-style object type |
| `InvestigationDepth` | `quick`, `standard`, `deep` |
| `ActivityMode` | `passive` (default), `active` |
| `InvestigationStatus` | investigation lifecycle |
| `ProviderRunStatus` | outcome of one provider operation |
| `EvidenceClass` | what kind of claim a piece of evidence is |
| `EvidenceEffect` | which direction it points |
| `MatchScope` | how precisely a claim applies to the object |
| `CoverageStatus` / `CoverageRelevance` | capability coverage reporting |
| `Verdict` | `malicious`, `suspicious`, `inconclusive`, `likely_benign` |
| `AssessmentState` | how much weight an assessment deserves |
| `SourceReliabilityGrade` | Admiralty `A`-`F` (source) |
| `InformationCredibilityGrade` | Admiralty `1`-`6` (claim) |
| `RelationshipType` | initial relationship vocabulary |
| `ConflictType` / `ConflictSeverity` / `ConflictStatus` | evidence conflicts |
| `ContributionRole` | role a piece of evidence played |
| `ProviderCapability` | intelligence capability (vendor-neutral) |
| `ProviderOperation` | kind of provider call |
| `ProviderErrorCategory` | provider-neutral error category |

`ProviderCapability`, `ProviderOperation` and `ProviderErrorCategory` live in
`ti_recon.enums` rather than in `ti_recon.providers` because the data model
refers to them — an investigation requests capabilities, a provider run serves
one and records a normalized error category, coverage is reported per
capability. The data model must not depend on the provider framework, so the
shared vocabulary sits below both. `ti_recon.providers` re-exports them.

## 2. Object types

```
ipv4-addr   ipv6-addr   domain-name   url   file
autonomous-system   x509-certificate   malware
```

`SUBMITTABLE_OBJECT_TYPES` marks the subset an analyst may submit directly:
`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`. The remaining types are
only ever *derived* during enrichment.

Submitted concrete artifacts are called **Observables** internally (STIX
Cyber-observables), not STIX Indicators — at input time there is no detection
logic and no asserted confidence, which is what an Indicator implies. Analyst
documentation may still say *IOC*.

## 3. `IntelObject`

`ti_recon.models.intel_object.IntelObject`

| Field | Notes |
|-------|-------|
| `id` | opaque UUID string |
| `object_class` | `ObjectClass` |
| `object_type` | `IntelObjectType` |
| `canonical_value` | normalized, comparable form |
| `display_value` | analyst-facing form (e.g. IDN Unicode label) |
| `canonical_key` | de-duplicating key; derived if not supplied |
| `properties` | type-specific attributes |
| `created_at`, `updated_at` | timezone-aware UTC |

Timestamps use the `UtcDatetime` annotation: naive datetimes are **rejected**
rather than assumed to be UTC, and aware datetimes are converted to UTC. Guessing
a zone would silently corrupt first-seen/last-seen ordering across providers.

`canonical_key` examples:

```
ipv4-addr:198.51.100.7
ipv6-addr:2001:db8::1
domain-name:evil.example
domain-name:xn--e1afmkfd.xn--p1ai
url:http://evil.example/a
file:sha256:<64 hex>
```

## 4. File hashes are properties, not object types

There are no `md5` / `sha1` / `sha256` object types. A hash identifies a `file`
object:

```json
{
  "object_type": "file",
  "canonical_key": "file:sha256:e3b0c442...b855",
  "properties": {
    "hashes": {
      "SHA-256": "e3b0c442...b855"
    }
  }
}
```

Rationale: providers key the same file by different algorithms. With hash-typed
objects, one file submitted as an MD5 and returned by another provider as a
SHA-256 would become two unrelated objects. As properties, they converge.

Rules enforced by the model:

- hash property names are the STIX forms `MD5`, `SHA-1`, `SHA-256`; anything
  else is rejected;
- digests must be lowercase hexadecimal of the exact length for the algorithm
  (32 / 40 / 64);
- a `file` object must carry at least one hash;
- `canonical_key` uses the strongest hash present, preferring
  SHA-256 > SHA-1 > MD5.

## 5. Observable normalization

`ti_recon.normalization.normalize_observable(raw) -> NormalizationResult`

`NormalizationResult` is frozen and carries both `original_input` (exactly as
submitted) and the normalized `intel_object`, so an investigation can always
show what the analyst actually typed.

Two hard rules:

- **No network I/O.** No DNS resolution, no WHOIS. Normalization is syntactic.
- **Conservative.** Only ambiguity that is safe to remove is removed.

### 5.1 Detection order

```
hex digest of length 32/40/64      -> file
contains a scheme separator "://"  -> url
parses as an IP address            -> ipv4-addr / ipv6-addr
otherwise                          -> domain-name (validated)
```

Anything that fails all four is rejected with `NormalizationError` rather than
guessed at. Input is bounded at 4096 characters; internal whitespace,
control characters, zero-width characters and bidi overrides are rejected
(they are a homograph/obfuscation vector, never a legitimate part of an
observable).

### 5.2 Supported defanging

```
[.]  (.)  {.}  [dot]        dot mangling (whitespace tolerated inside)
hxxp:// hxxps://            scheme mangling (any case)
[://]   [:]//               separator mangling
```

For inputs with a URL scheme, dot-undefanging is applied **only to the
authority component**. `http://evil[.]example/redirect?to=a[.]b` normalizes to
`http://evil.example/redirect?to=a[.]b` — the path and query are part of the
artifact under investigation, and rewriting them would change the IOC.

### 5.3 IP addresses

Parsed with the standard library `ipaddress` module, which also gives useful
strictness for free: `010.1.1.1` is rejected as ambiguous (octal), `1.2.3.4/24`
is not an address. IPv6 is lowercased and compressed; a bracketed `[::1]` form
is accepted. IPv4-mapped IPv6 canonicalizes to hextet form
(`::ffff:192.0.2.1` -> `::ffff:c000:201`), matching `ipaddress`.

### 5.4 Domains

- supported defanging removed;
- a single trailing root dot stripped;
- ASCII names lowercased;
- non-ASCII names converted to IDNA A-labels via UTS-46 (`idna` library), with
  the Unicode U-label kept as `display_value`;
- syntax validated: at least two labels, each 1-63 characters of
  `[a-z0-9_-]` not starting or ending with a hyphen, total length <= 253, and a
  top-level label that is alphabetic or `xn--`-prefixed.

Underscores are permitted in labels because service names (`_dmarc`,
`_acme-challenge`) are legitimately observed.

Single-label input such as `localhost` is rejected as ambiguous.

### 5.5 URLs

Normalized:

- scheme — undefanged and lowercased; only `http`, `https`, `ftp` accepted;
- host — undefanged, lowercased, IDNA-encoded, IP literals canonicalized;
- default port for the scheme dropped (`:80` for http, `:443` for https,
  `:21` for ftp);
- empty path becomes `/`.

Deliberately **not** normalized, because each carries meaning for a suspicious
URL:

- path case (`/Path/To/CaseSensitive.PHP` stays as written);
- percent-encoding (never decoded);
- query parameter order, duplicates, empty values or bare flags;
- fragments.

`display_value` mirrors `canonical_value` but keeps the Unicode host form.

### 5.6 Hashes

Hex validated, length matched to MD5 / SHA-1 / SHA-256, lowercased. A hex string
of another length (for example a SHA-512) is reported as a hash-shaped input of
unsupported length rather than being misread as a domain.


## 6. Investigation and provider runs

### `Investigation`

| Field | Notes |
|-------|-------|
| `id` | |
| `primary_object_id` | the submitted observable |
| `original_input` | exactly what the analyst typed |
| `depth` | `InvestigationDepth`, default `standard` |
| `activity_mode` | `ActivityMode`, default `passive` |
| `status` | `InvestigationStatus` |
| `requested_capabilities` | deduplicated and sorted for reproducibility |
| `started_at`, `completed_at` | UTC; completion may not precede start |
| `engine_version`, `policy_version` | required, for later explainability |

There is no Claude or MCP field, and a test asserts there never is. An
investigation must be runnable from a library, CLI or HTTP API with no LLM in
the loop.

Capabilities are requested, not providers. Coverage is reported against this
list.

### `ProviderRun`

One provider operation. Fields: `id`, `investigation_id`, `provider`,
`capability`, `operation`, `status`, `cache_hit`, `started_at`, `completed_at`,
`api_version`, `adapter_version`, `error_code`, `raw_reference_id`.

`status` is `ProviderRunStatus` — the outcome of *this call*:

```
success                    no_data                  not_configured
not_supported              plan_limited             quota_exceeded
partial                    temporarily_unavailable  error
```

Enforced: a `success` run may not carry an `error_code`, and an `error` run
must. `status` is deliberately not a statement about provider health or
credential validity; those are tracked separately so one failed lookup is not
mistaken for a broken integration.

## 7. Evidence

**One `Evidence` object is one factual claim or observation — never a whole
provider response.** A single reputation report typically yields several: a
detection aggregate, a resolution observation, a submission-name observation.
Each carries its own class, scope and provenance.

`Evidence` is frozen. It records what a provider said; engine interpretation
lives in `AssessmentContribution` and never rewrites the fact.

| Group | Fields |
|-------|--------|
| identity | `id`, `investigation_id`, `subject_object_id` |
| claim | `evidence_class`, `claim_type`, `effect` |
| provenance | `transport_provider`, `origin_provider`, `source_family` |
| confidence signals | `provider_confidence`, `source_reliability`, `information_credibility` |
| specificity | `match_scope` |
| time | `first_seen`, `last_seen`, `observed_at`, `retrieved_at` |
| lineage | `lineage_group_id`, `upstream_evidence_refs` |
| payload | `attributes`, `raw_reference_id` |

### 7.1 Evidence classes and effects

```
DIRECT_OBSERVATION          the provider itself observed this
CURATED_THREAT_ASSERTION    a curated feed asserts a threat association
AGGREGATED_REPUTATION       an aggregation of third-party opinions
CONTEXT                     neutral context, no direction on its own
RELATIONSHIP                a link between two objects

SUPPORTS_MALICIOUS   SUPPORTS_BENIGN   CONTEXT_ONLY
```

`CONTEXT`-class evidence is required to have effect `CONTEXT_ONLY`; context that
silently points somewhere is how a "neutral" signal ends up steering a verdict.

### 7.2 `claim_type`

An open vocabulary with a fixed format: lowercase alphanumeric segments joined
by `.`, `_` or `-` (`malware.c2-association`, `dns.a-record`,
`scanner.benign-classification`). Providers always surface claims nobody
anticipated, so the set is not closed — but the format is, so claims stay
groupable.

### 7.3 Four separate confidence numbers

Never merged:

| Signal | Grades what | Owner |
|--------|-------------|-------|
| `provider_confidence` | the provider's own assertion (0-100) | provider |
| `source_reliability` | how dependable the source is (Admiralty `A`-`F`) | TI Recon policy |
| `information_credibility` | how credible this claim is (Admiralty `1`-`6`) | TI Recon policy |
| `Assessment.confidence` | confidence in the final conclusion (0-100) | assessment engine |

There is deliberately no aggregate confidence field on `Evidence`.

### 7.4 `match_scope`

How precisely the claim applies: `exact_observable`, `same_host`,
`parent_domain`, `same_ip`, `ip_network`, `same_asn`, `same_certificate`,
`cluster`, `unknown`. Defaults to `unknown`, so an adapter that forgets to
state scope never accidentally implies an exact match.

### 7.5 Lineage

`transport_provider` is whose API was called; `origin_provider` is who produced
the data. `is_relayed` is true when they differ.

`lineage_group_id` groups evidence that must not be counted as independent. If
an adapter does not set it, it defaults to `f"{source_family}:{origin_provider}"`
— a conservative approximation: same origin means not independent. An adapter
may state a narrower group when it can.

Worked example: a scanner-context provider that relays noise-classification
data from another vendor produces evidence with
`transport_provider = fake_scanview`, `origin_provider = fake_noise`,
`lineage_group_id = "scanner_noise:fake_noise"` — the same group the origin
provider's own evidence would land in, so querying both cannot inflate
confidence.

### 7.6 `attributes` guard

`attributes` is rejected if any key (at any nesting depth, including inside
lists) looks like credential material — `api_key`, `x-apikey`, `Auth-Key`,
`authorization`, `bearer`, `secret`, `cookie` and similar. The error names the
key path only, never the value.

This is defence in depth against an adapter copying a request header into
normalized output. Relatedly, all models set
`hide_input_in_errors=True`: pydantic otherwise embeds rejected input in
`ValidationError` messages, which would leak a secret into any log that catches
the exception.

### 7.7 `RawEvidenceReference`

A pointer to a stored raw provider response — `storage_key`, `content_type`,
`content_sha256`, `size_bytes`, `retrieved_at`, `redacted` — and deliberately
*not* the payload. Normalized evidence can then be serialized and logged
without dragging an unaudited provider payload (which may echo request headers)
along with it.

## 8. Relationships

`Relationship`: `id`, `source_object_id`, `relationship_type`,
`target_object_id`, `first_seen`, `last_seen`, `confidence`, `evidence_refs`.

Vocabulary:

```
resolves-to        redirects-to      contacts        downloads
drops              hosts             uses-certificate
belongs-to-asn     associated-with-malware           similar-to
derived-from       duplicate-of      related-to
```

`evidence_refs` must contain at least one reference. A relationship with no
evidence behind it is an assertion TI Recon cannot explain, and unexplainable
links are how a pivot graph turns into guesswork. Self-references are rejected.

## 9. `EvidenceConflict`

`investigation_id`, `evidence_a_id`, `evidence_b_id`, `conflict_type`,
`severity`, `status`, `resolution_note`, `detected_at`.

Status: `OPEN` (nobody has looked), `RESOLVED` (reconciled — a note is
required), `UNRESOLVED` (examined and irreconcilable). The distinction matters:
an unresolved conflict is itself an input to confidence, and hiding it would
turn a murky picture into a confident-looking verdict.

## 10. `CoverageItem`

`capability`, `relevance`, `status`, `providers_considered`, `reason`.

```
status:    COVERED  PARTIAL  NOT_COVERED  NOT_APPLICABLE
relevance: REQUIRED RELEVANT OPTIONAL     NOT_APPLICABLE
```

Incomplete coverage must state a reason. `is_gap` is true when a `REQUIRED` or
`RELEVANT` capability is `NOT_COVERED` or `PARTIAL` — i.e. when the absence of
findings should not be read as a clean result.

## 11. Assessment

### `Assessment`

`verdict`, `risk_score` (0-100), `confidence` (0-100), `assessment_state`,
`supporting_evidence_refs`, `benign_evidence_refs`, `context_evidence_refs`,
`conflict_refs`, `coverage`, `policy_version`, `engine_version`, `assessed_at`.

Evidence is referenced by role rather than merged into the score, so "which
observations pushed this to malicious?" always has an answer. A piece of
evidence may hold only one role; overlap is rejected. `coverage` travels with
the verdict, because a verdict without its blind spots is misleading.

`assessment_state` is orthogonal to `verdict`: the verdict says what TI Recon
thinks, the state (`preliminary`, `complete`, `insufficient_coverage`,
`conflicted`, `superseded`) says how much weight that opinion deserves.

### `AssessmentContribution`

The interpretation layer, kept in its own model:

`assessment_id`, `evidence_id`, `role`, `base_strength`, `freshness_factor`,
`independence_factor`, `specificity_factor`, `false_positive_factor`,
`effective_contribution`, `reason_codes`.

`base_strength` (0-100) is what the claim would be worth alone. The four
factors are dampeners in `[0, 1]`:

- `freshness_factor` — how much the claim's age discounts it;
- `independence_factor` — discounted when the evidence shares lineage with
  evidence already counted;
- `specificity_factor` — discounted when `match_scope` is broader than the
  object under investigation;
- `false_positive_factor` — discounted by known false-positive context.

Because every factor is a dampener, `effective_contribution` can never exceed
`base_strength`; that is enforced. Context-role contributions must be exactly
zero — context informs the narrative, it does not move the score.

This is what replaces provider counting. Two malicious signals do not add up to
"more malicious": a curated exact-artifact assertion keeps most of its strength,
while an aggregated reputation count is discounted for independence and
freshness, and the reason codes say why.

## 12. Version stamps

`ti_recon.versions` provides `ENGINE_VERSION` (the package version) and
`POLICY_VERSION`. `POLICY_VERSION` is the literal string `0-unimplemented`,
because no scoring policy exists yet and a plausible-looking version number
would be a lie in an audit trail.
