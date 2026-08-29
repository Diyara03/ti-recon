# Temporal Evidence Qualification

> Task 15, first half. What a timestamp actually means, and what it does not.
> Implemented in `src/ti_recon/reasoning/`.

## 1. The problem

A threat-intelligence platform accumulates timestamps from every provider it
touches, and almost none of them answer the same question. Left untyped they all
become "when was this last seen", and that single collapse produces the most
common and most confident kind of wrong answer a SOC tool can give:

> **"VirusTotal last analysed this file yesterday"** becomes
> **"this malware was active yesterday"**.

A file uploaded by a stranger in 2019 and rescanned this morning has a
`last_analysis_date` of this morning. Nothing about it has been near anybody
since 2019.

Task 15 exists to keep those apart. It is a **qualification** layer: it says what
each finding means in time and context, and never what the case is. There is no
verdict, no confidence, no risk score, no evidence weight, no decay curve and no
false-positive flag anywhere in it.

## 2. Five different time questions

Every instant TI Recon holds answers exactly one of these. They are not
interchangeable, and the vocabulary in `reasoning/models.py` keeps them apart by
construction.

| # | Question | `TemporalFactKind` |
|---|----------|--------------------|
| 1 | When did a source **receive** the object? | `FIRST_SUBMITTED`, `LAST_SUBMITTED` |
| 2 | When did a source **analyze** it? | `ANALYZED_AT`, `SCANNED_AT` |
| 3 | When was activity actually **observed**? | `FIRST_OBSERVED`, `LAST_OBSERVED`, `LAST_ONLINE_AT`, `RELATIONSHIP_FIRST_OBSERVED`, `RELATIONSHIP_LAST_OBSERVED` |
| 4 | What does the source say is **true now**? | not an instant — `SourceLifecycleState` |
| 5 | How fresh is the **dataset**? | `SNAPSHOT_GENERATED_AT`, `ADDED_TO_DATASET_AT` |

Only family 3 is about the threat. Families 1, 2 and 5 are about the platform.

Two further kinds describe things rather than events: `VALID_FROM` /
`VALID_UNTIL` for a certificate's window, and `SOURCE_RECORD_UPDATED_AT` for a
provider touching its own record.

### Query time is never observation time

A lookup on 2026-08-29 does **not** mean `last_seen = 2026-08-29`. No instant is
ever manufactured from a request time, an enrichment time, a cache time or a
Task 13 execution time. Those are system metadata and stay there.

## 3. Provider mapping table

Every mapping lives in that provider's own `qualification.py`. The generic
evaluator knows none of these field names, and a test reads its AST to prove it.

| Provider | Provider field | Kind | Lifecycle |
|----------|----------------|------|-----------|
| GTI | `first_submission_date` | `FIRST_SUBMITTED` | — |
| GTI | `last_submission_date` | `LAST_SUBMITTED` | — |
| GTI | `last_analysis_date` | `ANALYZED_AT` | — |
| urlscan | `task.time` | `SCANNED_AT` | `POINT_IN_TIME` |
| urlscan | `page.tlsValidFrom` | `VALID_FROM` | — |
| GreyNoise | `first_seen` / `last_seen` | `FIRST_OBSERVED` / `LAST_OBSERVED` | — |
| GreyNoise | BSI `last_updated` | `SOURCE_RECORD_UPDATED_AT` | — |
| Censys | `last_updated_at` | `LAST_OBSERVED` | `POINT_IN_TIME` |
| ThreatFox | `first_seen` / `last_seen` | `FIRST_OBSERVED` / `LAST_OBSERVED` | `WITHIN_SOURCE_API_HORIZON` |
| URLhaus | `date_added` | `ADDED_TO_DATASET_AT` | from `url_status` |
| URLhaus | `last_online` | `LAST_ONLINE_AT` | from `url_status` |
| URLhaus | payload `firstseen` / `lastseen` | `FIRST_OBSERVED` / `LAST_OBSERVED` | — |
| MalwareBazaar | `first_seen` / `last_seen` | `FIRST_OBSERVED` / `LAST_OBSERVED` | — |
| Hybrid Analysis | `analysis_start_time` | `ANALYZED_AT` | — |
| Hybrid Analysis | certificate `valid_from` / `valid_until` | `VALID_FROM` / `VALID_UNTIL` | — |
| MISP Warning Lists | `snapshot_generated_at` | `SNAPSHOT_GENERATED_AT` | `DATASET_STALE` / `DATASET_CURRENT` |
| Task 14 graph | assertion `first_seen` / `last_seen` / `observed_at` | `RELATIONSHIP_*` | — |

### The GTI case, specifically

Task 7 stores `last_analysis_date` in `Evidence.last_seen`, because that is the
field the Task 3 model has for a claim's most recent instant. Task 15 does not go
back and change that. Instead it refuses to read the field generically: the GTI
extractor holds a per-claim-type table saying which *provider* field each model
field actually carries, and maps it to `ANALYZED_AT` regardless of where it sits.

A generic evaluator reading `last_seen` off every provider would be exactly wrong
here — which is why no generic evaluator is allowed to read it. A dedicated
regression test asserts `ANALYZED_AT` is produced and `LAST_OBSERVED` is not.

### Censys certificates

Task 9 keeps a certificate's fingerprint, subject and issuer, and deliberately
does **not** normalize `not_before`/`not_after`. So Censys emits no `VALID_FROM`
or `VALID_UNTIL`: there is nothing normalized to emit, and reading a validity
window out of a raw response would be new provider behaviour rather than a
qualification of existing behaviour.

That omission sits on the safe side of the distinction anyway. A certificate
valid 2024-2026 does not mean the host served it throughout. A validity window is
a property of the certificate; hosts rotate what they present.

## 4. `as_of` is an argument

```python
engine = TemporalContextEngine()
result = engine.evaluate(
    as_of=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
    results=envelopes,
    graph=graph,          # optional Task 14 graph
    root=target,          # optional: the observable the run was about
)
```

* `as_of` is **required** and must be timezone-aware. A naive value is refused,
  exactly as Task 3 refuses a naive provider timestamp: guessing the local zone
  would shift every age by hours and the numbers would still look plausible.
* Nothing in the package reads a wall clock, and an extractor is handed no clock
  at all — so a rule cannot quietly become time-dependent in a place that is
  never given a time.
* `result.evaluated_at` is the `as_of` supplied, never a clock reading.
* Same inputs + same `as_of` ⇒ byte-identical serialization, forever.

## 5. Age, and the absence of decay

For a valid past instant, `TemporalQualification` carries `age_seconds` and
`age_days`. Exact, and unlabelled.

There is deliberately no `fresh`, no `stale`, no `old` and no decay function.
Different artifacts age differently and no single half-life describes them:

| Artifact | How it ages |
|----------|-------------|
| Phishing URL | Worthless within days |
| Malware SHA-256 | Cryptographic identity; the bytes do not change |
| Cloud IP address | Changes tenant, possibly this week |
| Scanner infrastructure | Stable for years |
| Certificate | Expires on a date it announces |
| Sandbox report | Describes a moment that will never recur |

MISP itself maintains *separate* decay models for different use cases. Inventing
one number here would be wrong for most of them while looking principled.

Where a **source** defines a lifecycle, the source's word is carried. Where it
does not, a later layer gets the number and decides.

## 6. Source-managed lifecycle

`SourceLifecycleState` is qualitative and source-owned:

| State | Meaning | Set by |
|-------|---------|--------|
| `ACTIVE_BY_SOURCE` | The source says it is serving now | URLhaus `online` |
| `INACTIVE_BY_SOURCE` | The source says it is not | URLhaus `offline` |
| `STATUS_UNKNOWN` | The source was asked and could not say | URLhaus `unknown` |
| `WITHIN_SOURCE_API_HORIZON` | Inside a retention window, nothing more | ThreatFox |
| `POINT_IN_TIME` | One observation, no claim about before or after | urlscan, Censys |
| `DATASET_STALE` / `DATASET_CURRENT` | Local corpus freshness | MISP Warning Lists |

There is no `ACTIVE_NOW`, no `SAFE`, no `BENIGN` and no `TRUSTED`. A record
coming back from an API proves the API holds it, not that anything is live.

### ThreatFox: a horizon is not a heartbeat

ThreatFox expires indicators from its API after roughly six months —
deliberately, to limit false positives on infrastructure that changes hands,
cloud addresses above all. A returned record therefore means **unexpired**, which
is much weaker than "this is live". Task 15 records
`WITHIN_SOURCE_API_HORIZON` plus the horizon in months, and raises a
`SOURCE_MANAGED_LIFECYCLE` cue.

The inverse matters more. A ThreatFox **miss** is compatible with never having
been listed, with having been listed and expired, and with an indicator reported
an hour ago. Task 15 emits nothing at all for an absence: no times, no lifecycle,
no "expired". Manufacturing one would turn a coverage horizon into a claim about
the world.

### URLhaus: offline is history, not absolution

```
URLhaus:  this exact URL distributed malware       -> SUPPORTS_MALICIOUS
URLhaus:  url_status = offline
URLhaus:  last_online = 2026-06-20T08:00Z
```

Task 15 output:

* the evidence keeps `SUPPORTS_MALICIOUS`, **untouched**;
* `ADDED_TO_DATASET_AT` (from `date_added`) and `LAST_ONLINE_AT`, both carrying
  `INACTIVE_BY_SOURCE`;
* an `HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE` cue, purpose `TEMPORAL_CAUTION`.

A URL that distributed malware in March and stopped in April distributed malware.
Nothing here converts `offline` into anything resembling benign.

### MalwareBazaar: a hash does not expire

`first_seen` and `last_seen` are repository observation times, with **no**
lifecycle attached, because MalwareBazaar states none. A sample last seen in 2023
is a sample last seen in 2023 — not expired, not inactive, and certainly not
benign. Task 15 records the exact age and applies no decay.

## 7. Relationship times stay per assertion

Task 14 keeps times on the `RelationshipAssertion`, not on the edge, and Task 15
reads them there.

```
edge:  file:sha256:… --contacts--> domain-name:evil.example
       assertion A (provider alpha):  observed 2025-01-02
       assertion B (provider beta):   observed 2026-01-02
```

That is **two observations**, not a one-year continuous association. Task 14's
`earliest_observed` / `latest_observed` are documented as display-only bounding
boxes and are deliberately not qualified: turning a bounding box into a fact is
the inference this layer refuses to make.

Each fact keeps its own asserter and its `RelationBasis`, so neither can be read
as covering the other.

## 8. Temporal issues

Two members only:

| Issue | When |
|-------|------|
| `FUTURE_TIMESTAMP` | An instant after `as_of` by more than the clock-skew tolerance |
| `INVALID_INTERVAL` | An interval whose start follows its end |

A **missing** timestamp is coverage, not an error. Most providers time some
claims and not others — a warninglist hit and a blocklist relay legitimately have
none — and turning every absence into an issue would bury the two cases that mean
the data is actually wrong.

### Nothing is repaired

* A future timestamp keeps its value and is left **unaged**. An age of zero would
  read as "observed just now", which is the opposite of what a bad timestamp
  means.
* An inverted interval keeps both endpoints. Swapping them would invent an
  observation window the source never described, and the correction would be
  invisible.
* `CLOCK_SKEW_TOLERANCE` is five minutes, explicit and documented. Inside it, a
  small negative is a clock difference rather than a claim about the future, and
  the age floors at zero silently.
* Intervals are pairs of facts from **one origin**. Two providers each reporting
  one bound are two observations, and pairing them would manufacture a
  disagreement out of two consistent records.
* A certificate's `not_after` is exempt from `FUTURE_TIMESTAMP`: a future expiry
  is what a valid certificate looks like. It is also not aged while it is still
  ahead — time remaining is a different quantity from elapsed time, and is left
  for a later layer. Once it has passed, the ordinary age applies and means "how
  long ago it expired".

## 9. What Task 15 never does

* No network, DNS, socket, provider call, credential, cache, Task 13 enrichment
  or Task 14 pivot. It reasons over data already in hand, so a stored result can
  be requalified years later with the network unplugged.
* No mutation of anything: `EvidenceEffect`, `EvidenceClass`, `source_family`,
  `lineage_group_id`, `origin_provider`, `transport_provider`, `MatchScope`,
  `Relationship`, `RelationBasis` and every graph edge are read-only here.
* No verdict, confidence, risk score, malicious/benign score, evidence weight,
  numerical decay, block recommendation, case-closure recommendation or
  `is_false_positive` boolean — enforced at field-name level across every model.

See [context-qualification.md](context-qualification.md) for the context half.
