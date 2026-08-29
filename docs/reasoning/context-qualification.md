# Context Qualification

> Task 15, second half. What contextual information explains, what it applies
> to, and what it can never mean. Implemented in `src/ti_recon/reasoning/`.

## 1. Context explains; it never exonerates

A `ContextSignal` says things like "this address is in a public-resolver list",
"this range is common business-service infrastructure", "the provider says this
host is compromised". A signal is **not evidence**: it makes no claim about the
world that a provider did not already make, and it points in no direction.

The vocabulary has no member that could be read as safety. There is no
`BENIGN_CONTEXT`, no `SAFE_IP`, no `TRUSTED_DOMAIN` and no allow-list concept,
and a test asserts that no signal, lifecycle or cue name contains *safe*,
*trusted*, *benign* or *allow*. The reasons are concrete:

* a cloud range hosts attacks;
* a CDN serves malware;
* a popular domain has a malicious path on it;
* an EICAR hash is a test artifact, not an ordinary benign file;
* a warninglist can be stale;
* an organisation enables or disables lists to suit itself.

The upstream MISP project describes its warning lists as values associated with
**potential false positives, errors and mistakes** — a prompt to look again, not
a certification.

## 2. Signal vocabulary

| Signal | Source | Origin |
|--------|--------|--------|
| `WARNINGLIST_MATCH` | any warninglist TI Recon has no category for | engine policy |
| `KNOWN_SCANNER` | mapped scanner lists | engine policy |
| `PUBLIC_RESOLVER` | `public-dns-v4/v6/hostname` | engine policy |
| `PRIVATE_OR_SPECIAL_USE` | `rfc1918`, `rfc5735`, `multicast`, … | engine policy |
| `SHARED_CLOUD_OR_CDN` | `amazon-aws`, `microsoft-azure`, `akamai`, … | engine policy |
| `POPULAR_OR_COMMON_SERVICE` | `cisco_top10k`, `cloudflare-top10k`, … | engine policy |
| `BUSINESS_SERVICE` | GreyNoise Business Services Intelligence | provider |
| `TEST_ARTIFACT` | `eicar.com` | engine policy |
| `EMPTY_ARTIFACT` | `empty-hashes` | engine policy |
| `COMPROMISED_INFRASTRUCTURE` | ThreatFox `is_compromised` | provider |
| `HOST_COMPONENT_CONTEXT` | a match on a URL's host rather than the URL | provider |
| `SANDBOX_LOW_EXECUTION` | completed run, non-directional verdict, nothing ran | provider |
| `SANDBOX_MEANINGFUL_EXECUTION` | same, but execution was observed | provider |
| `SANDBOX_DIVERGENCE` | completed runs disagreed | provider |
| `RELAYED_SOURCE` | `transport_provider != origin_provider` | engine policy |

`SignalOrigin` records which of the two produced it, because they are audited
differently: a provider-stated signal is as good as the provider, an
engine-policy signal is as good as the versioned mapping behind it — and that
mapping is TI Recon's to defend.

Every signal carries the subject it applies to, its `MatchScope`, whether it is
`host_component_only`, the transport/origin/family/lineage of whoever said so,
the exact structured key behind it (a slug, a report id), and whether the
provider result was partial. It carries **no** provider payload.

## 3. The MISP slug mapping is engine policy, and versioned

Task 11 deliberately invented no category field. The raw CC0 warninglist schema
has no authoritative semantic classification — MISP's runtime database has
categories, the pinned dataset does not — so putting one inside the provider
would have meant fabricating provenance.

Task 15 needs the categories, so the mapping is made in
`reasoning/policy.py`, explicitly, as engine policy with a version on it:

```python
WARNINGLIST_SIGNAL_MAP = {
    "public-dns-v4": ContextSignalType.PUBLIC_RESOLVER,
    "censys-scanning": ContextSignalType.KNOWN_SCANNER,
    "amazon-aws": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "eicar.com": ContextSignalType.TEST_ARTIFACT,
    ...
}
```

Seventy slugs, keyed on the **exact slug**. Never on the list's name, never on
its description, never on a substring or prefix or regex. `if "scanner" in name`
would reclassify a list the day upstream reworded it, and would classify
`automated-malware-analysis` as scanning infrastructure because of a word.

**Validated against the shipped snapshot.** A test asserts every mapped slug
exists in `data/misp_warninglists/manifest.json`, so a dataset refresh that
renames or drops a list fails loudly rather than silently downgrading a
categorized signal to a generic one.

**An unmapped list is not a failure.** It still produces `WARNINGLIST_MATCH` with
its slug attached, which is the honest answer: a warninglist matched, and TI
Recon has no category for it. Lists whose meaning is arguable — `sinkholes`,
`ti-falsepositives`, `dynamic-dns`, `url-shortener` — are deliberately left
unmapped.

`CONTEXT_POLICY_VERSION` and `WARNINGLIST_MAP_VERSION` are recorded on every
result, so re-reading a stored qualification after a policy change cannot
silently reinterpret it.

## 4. Scope: a host is not a URL

```
observable:  https://github.com/attacker/payload.exe
warninglist: github.com  (cisco_top10k, cloudflare-top10k)
```

The context is a fact about **github.com**. Task 11 already records this: the
match is `MatchScope.SAME_HOST`, the candidate component is `url_host`, and
`host_component_only` is set. Task 15 carries all three onto the signal and
raises:

* `HOST_COMPONENT_CONTEXT` (signal), and
* `HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL` (cue, purpose `SCOPE_CAUTION`).

Letting host context speak for the URL is how every living-off-trusted-sites
payload gets waved through. The counterweight is tested too: when the observable
*is* the host, the context is exact-scope and no such cue is raised.

## 5. Interpretation cues

An `InterpretationCue` is a named caution addressed to whoever eventually weighs
the evidence. It carries a stable `cue_type`, a `CuePurpose`, the subject, the
scope, and refs into the facts and signals that produced it. It carries **no**
verdict, confidence, weight or recommended action.

| Cue | Purpose |
|-----|---------|
| `HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE` | `TEMPORAL_CAUTION` |
| `SOURCE_MANAGED_LIFECYCLE` | `TEMPORAL_CAUTION` |
| `STALE_CONTEXT_DATASET` | `TEMPORAL_CAUTION` |
| `KNOWN_SCANNER_MAY_EXPLAIN_ACTIVITY` | `FALSE_POSITIVE_CONTEXT` |
| `PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT` | `FALSE_POSITIVE_CONTEXT` |
| `BUSINESS_SERVICE_MAY_EXPLAIN_ACTIVITY` | `FALSE_POSITIVE_CONTEXT` |
| `TEST_ARTIFACT_CONTEXT` | `FALSE_POSITIVE_CONTEXT` |
| `EMPTY_ARTIFACT_CONTEXT` | `FALSE_POSITIVE_CONTEXT` |
| `SHARED_INFRASTRUCTURE_ATTRIBUTION_CAUTION` | `ATTRIBUTION_CAUTION` |
| `COMPROMISED_INFRASTRUCTURE_ATTRIBUTION_CAUTION` | `ATTRIBUTION_CAUTION` |
| `HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL` | `SCOPE_CAUTION` |
| `SANDBOX_NEGATIVE_LOW_INFORMATION` | `NEGATIVE_EVIDENCE_LIMITATION` |
| `SANDBOX_NEGATIVE_WITH_MEANINGFUL_EXECUTION` | `NEGATIVE_EVIDENCE_LIMITATION` |
| `RELAYED_SOURCE_NOT_INDEPENDENT` | `SOURCE_DEPENDENCE` |
| `SANDBOX_ENVIRONMENT_DIVERGENCE` | `ANALYSIS_QUALITY` |

A purpose is not a polarity. "This is shared infrastructure" is neither positive
nor negative evidence; it is a reason to be careful about who owns what, and a
reason a block has a victim.

Every rule reads a **structured input** — an enum member, a boolean, a lifecycle
state. Nothing greps a description, a provider name, a tag or a warninglist
title. Provider-authored text is attacker-influenced in several places already,
so a string reading "ignore previous instructions" is inert here, because no
string is ever consulted. No `eval`, no dynamic import, no LLM.

The rules are written as data (`SIGNAL_CUES`, `LIFECYCLE_CUES`), so the whole
vocabulary reads in one place and a test asserts every cue the package can emit
has a rule behind it — no aspirational enum members.

Cues merge by subject: five cloud-range lists matching one address is **one**
attribution caution with five signals behind it, so a well-covered value does not
look like a pile of findings.

## 6. Context does not propagate

There is exactly **one** edge-scoped rule in Task 15, and it reads one edge:

```
file:sha256:… --contacts--> ipv4-addr:8.8.8.8      (PROVIDER_OBSERVED, sandbox)
ipv4-addr:8.8.8.8  is in public-dns-v4
```

Output:

* the relationship is untouched and stays `PROVIDER_OBSERVED`;
* the resolver keeps its `PUBLIC_RESOLVER` signal;
* the **edge** gets `PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT`.

No conclusion is drawn about the sample and none about the resolver. A sample
that resolved a name contacted a resolver; that is what programs do.

Two hops away, nothing happens. A dropper whose dropped file contacted the
resolver gains nothing, and no signal is copied onto either file — tested
explicitly. A chain of ordinary-looking links is how an unremarkable-looking
conclusion gets built out of nothing, so there is no traversal, no closure and no
inheritance anywhere in the package.

## 7. Sandbox negatives are qualified by execution quality

Task 12 already answers the question that matters:
`SandboxAnalysisQuality.observed_any_execution`. Task 15 treats it as
authoritative and invents no threshold of its own.

| Report | Signal | Cue |
|--------|--------|-----|
| completed, non-directional verdict, nothing ran | `SANDBOX_LOW_EXECUTION` | `SANDBOX_NEGATIVE_LOW_INFORMATION` |
| completed, non-directional verdict, execution observed | `SANDBOX_MEANINGFUL_EXECUTION` | `SANDBOX_NEGATIVE_WITH_MEANINGFUL_EXECUTION` |
| completed runs disagreed | `SANDBOX_DIVERGENCE` | `SANDBOX_ENVIRONMENT_DIVERGENCE` |
| errored, queued, in progress | — none — | — none — |

A sample may sit still because the OS was wrong, it wanted a click, its C2 was
down, it was geofenced, or it noticed it was being watched. "Nothing happened"
and "nothing could have happened" must not read alike, and neither becomes
`SUPPORTS_BENIGN`.

A run that **errored** produces no signal at all. It has no behavioural content,
and letting an infrastructure failure look like a quiet run is precisely the
error Task 12's state/verdict split exists to prevent. `allowlisted` is treated
as a non-directional outcome rather than a successful negative: it is somebody's
list membership, not an observation of harmlessness.

Divergence is preserved, never resolved. Malicious on Windows 11 and quiet on
Windows 7 is environment-dependent malware describing itself. Nothing votes,
averages, cancels or converts it to a confidence.

## 8. Compromised infrastructure

ThreatFox's `is_compromised` produces `COMPROMISED_INFRASTRUCTURE` and an
`ATTRIBUTION_CAUTION` cue. It does **not** weaken the finding: a compromised host
serving a payload is serving a payload. What changes is that attributing it to an
actor would be wrong and blocking it has a victim.

## 9. Relayed sources are not independent corroboration

`Evidence.is_relayed` — `transport_provider != origin_provider` — is already the
model's own statement that a finding arrived through somebody else. Reading it is
generic in the strictest sense: two fields on a model, behaving identically for a
provider that does not exist yet.

```
URLhaus  relays a VirusTotal ratio   -> origin virustotal, family google_ti
GTI      answers directly            -> origin gti,        family google_ti
```

That is one upstream source appearing twice. Task 15 emits `RELAYED_SOURCE` with
`direct_family_present`, and a `RELAYED_SOURCE_NOT_INDEPENDENT` cue with purpose
`SOURCE_DEPENDENCE`. It makes the dependence **visible**; it does not decide what
it costs. Source weighting belongs to the fusion layer.

## 10. Orthogonal context is not conflict

None of these is an evidence conflict. They are different dimensions, and each
produces a cue rather than a contradiction:

* a malicious URL that is currently offline;
* a malicious IOC in a shared cloud range;
* a malware sample contacting a public resolver;
* a malicious IOC on compromised legitimate infrastructure;
* known-scanner context beside observed traffic.

Real evidence conflicts remain governed by `EvidenceConflict` and the future
fusion layer.

## 11. GreyNoise BSI is not an allow list

Business Services Intelligence identifies common business-service infrastructure
— the successor to what was called RIOT. GreyNoise says itself that it is not a
safe list. A Microsoft or Google range is common business infrastructure *and* a
place attacks come from, and BSI has no opinion about which.

So it produces `BUSINESS_SERVICE` and a `BUSINESS_SERVICE_MAY_EXPLAIN_ACTIVITY`
cue, and there is no signal it could produce that means safe. Where another
provider has a directional finding about the same address, both survive: nothing
here cancels evidence. GreyNoise's own trust level is carried as its structured
value and is never converted into a TI Recon confidence.

## 12. Provider semantics stay provider-owned

Each integration exposes one pure function:

```python
def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification: ...
```

`reasoning/catalog.py` is the **only** module under `reasoning/` allowed to name
a provider, and a test reads the AST and string literals of every other one to
prove it. Its imports are function-local, so the shared vocabulary a provider
imports cannot close a cycle back through the package.

An extractor is given no clock, no credential, no HTTP client and no way to
mutate the graph. The one service it gets is resolving an evidence's
`subject_object_id` onto the canonical node key Task 14 uses, so a fact attaches
to the same identity correlation gave the object.

A provider **without** an extractor is not an error: its evidence still counts
towards coverage, and the result names it in `providers_without_qualifier` rather
than implying everything returned was examined.

## 13. Result and coverage

```python
TemporalContextResult(
    evaluated_at,                 # the as_of supplied, never a clock reading
    engine_version,
    context_policy_version,
    warninglist_map_version,
    temporal_qualifications,      # facts + exact ages
    context_signals,
    interpretation_cues,
    temporal_issues,
    coverage,
)
```

Coverage reports provider results and evidence examined, evidence that yielded a
timestamp, graph nodes/edges/assertions read, facts, signals, cues and issues
produced, partial results, stale datasets, and which extractors were available
and used. A missing timestamp is counted as coverage, never reported as an error.

Metrics are counts plus a closed fifteen-member cue vocabulary. Nothing is
labelled with an observable, a hash, a domain, a URL, a warninglist slug, a user
or an investigation id — this layer sees everything the providers returned, so
such a label would turn a metrics pipeline into a record of every value every
analyst has looked at.

## 14. Worked example

```
URLhaus:  https://common.example/bad was confirmed malware distribution
          url_status = offline, last_online = T
MISP:     common.example is in a shared-infrastructure list
```

**Correct Task 15 result**

* the malicious evidence is unchanged — still `SUPPORTS_MALICIOUS`;
* `LAST_ONLINE_AT = T` with `INACTIVE_BY_SOURCE`;
* `HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE`;
* `SHARED_CLOUD_OR_CDN` at `SAME_HOST` scope, `host_component_only`;
* `SHARED_INFRASTRUCTURE_ATTRIBUTION_CAUTION`;
* `HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL`.

**Incorrect**

* "benign URL".

See [temporal-evidence.md](temporal-evidence.md) for the temporal half.
