# TI Recon — Common Threat Intelligence Data Model

> Task 3. This document describes what is implemented in
> `src/ti_recon/enums.py`, `src/ti_recon/models/` and
> `src/ti_recon/normalization/`.
>
> **Coverage at this commit:** vocabularies, `IntelObject` and observable
> normalization. The investigation / evidence / assessment models land in the
> next commit of this series and are documented then.

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
