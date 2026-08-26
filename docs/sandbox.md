# Sandbox intelligence framework

Task 12. `src/ti_recon/sandbox/`

The provider-neutral vocabulary for **what a sample did when somebody ran it**.
Hybrid Analysis ([providers/hybrid-analysis.md](providers/hybrid-analysis.md)) is
the first provider to populate these shapes; a second sandbox would populate the
same ones without changing anything here.

Nothing in this package carries a provider's field names. A model shaped around
one sandbox's JSON is not a framework — it is that sandbox with extra steps, and
the first thing a second provider would have to do is fight it. A test reads the
AST to keep it that way.

---

## 1. A report is an observation, not a verdict

The distinction the whole package exists for.

The same SHA-256 routinely has a Windows 11 report saying malicious, a Windows 7
report saying nothing specific, one from last year, and one that failed to
execute at all. Flattening file, report and environment into one identity throws
away the only information that makes a negative result interpretable.

So there are three things:

| Model | What it is |
|---|---|
| `SandboxSampleView` | every run a provider holds for one sample |
| `SandboxReportRef` | one run, as the index describes it — enough to *choose* between runs |
| `SandboxReportSummary` | one run, in detail, once fetched |

`SandboxEnvironment` is separate because it is the axis along which results
legitimately disagree.

### Divergence is preserved, not resolved

```
Windows 11 -> malicious
Windows 7  -> no specific threat
```

`verdicts_by_environment` and `divergent_verdicts` keep both. This is not a
contradiction to resolve: environment-dependent behaviour is *how targeted
malware works*, so a model that averaged those into one verdict would delete the
finding. Resolution belongs to the future fusion layer.

---

## 2. A sandbox that saw nothing did not see safety

`SANDBOX_VERDICT_EFFECT` maps every verdict to an evidence direction, and the
asymmetry is deliberate:

| Verdict | Effect |
|---|---|
| `MALICIOUS` | `SUPPORTS_MALICIOUS` |
| `SUSPICIOUS` | `SUPPORTS_MALICIOUS` |
| `NO_SPECIFIC_THREAT` | `CONTEXT_ONLY` |
| `NO_VERDICT` | `CONTEXT_ONLY` |
| `ALLOWLISTED` | `CONTEXT_ONLY` |
| `UNKNOWN` | `CONTEXT_ONLY` |

**Two verdicts point at malicious and none points at benign.** A sample may sit
still because the OS was wrong, the architecture was wrong, it wanted a command
line, it wanted a click, its C2 was down, it was geofenced, it was waiting on a
clock, or it noticed it was being watched. Letting a non-detection produce
`SUPPORTS_BENIGN` would reward evasion — the better a sample hides, the cleaner it
would look.

`ALLOWLISTED` is deliberately not called benign either: a sandbox allow-list means
the provider recognised the file as something it does not analyse, which is a
statement about their list.

`SUSPICIOUS` maps to `SUPPORTS_MALICIOUS` because direction and strength are
separate concerns in the Task 3 model — the provider's weaker word travels
alongside the effect rather than being flattened into it.

### State is not verdict

`SandboxReportState` is kept apart from the verdict, because "no verdict" and
"never ran" look identical once collapsed. A report that errored has no
behavioural content, and `is_complete` gates both selection and
`strongest_verdict` so an infrastructure failure never becomes an opinion —
including when the failed report itself claims to be malicious, which providers do
emit.

### Quality: nothing happened vs nothing could have happened

`SandboxAnalysisQuality` is what makes a quiet run interpretable rather than
merely unusable. Two runs can both report nothing while meaning opposite things:
one executed two minutes, spawned eleven processes and made forty connections;
the other errored after four seconds having started nothing.

It keeps state, analysis start, the provider's process/connection/signature
totals, runtime, network mode, action script, anti-evasion, script logging,
tampering, and the provider's own warnings — plus `observed_any_execution`, the
one-line answer to "did anything run at all?".

Task 12 does not diagnose *why* a run was uninformative. It records enough for a
later false-positive layer to ask.

---

## 3. One provider is one source

A hash detonated on Windows 7, 10 and 11 has three observations from **one**
sandbox of **one** sample. A fusion layer that counted them separately would let a
well-studied file outvote genuinely independent intelligence by having been run
more often.

The framework supports that by keeping the sample as the top-level identity and
leaving report detail inside it. How the rule is enforced in evidence is each
provider's job: Hybrid Analysis emits one directional finding per sample and
shares a sample-level lineage group.

`source_family` is deliberately **per sandbox**, not a generic `"sandbox"`. Two
independent sandboxes agreeing *is* real corroboration, and a shared family would
suppress it.

---

## 4. Selection: which runs are worth fetching

`ti_recon.sandbox.selection`. A hash can have dozens of detonations, each
detailed summary is a separate metered request, and the first provider's
restricted key allows about five requests a minute — so "fetch them all" is not a
strategy, it is an outage.

| Depth | Summaries |
|---|---|
| `QUICK` | 0 |
| `STANDARD` | 1 |
| `DEEP` | 2 |

`MAX_SUMMARIES_PER_LOOKUP` is an absolute ceiling: a planner may lower a budget,
nothing raises it past that constant.

**Recency is deliberately unavailable.** A hash search returns identity,
environment, state and verdict — no analysis timestamp. Ordering by report id
would be ordering by an opaque string, and calling it "latest" would be a claim
the data cannot back, which is worse than not having it: an analyst who believes
they are reading the newest run will read an old one as current.

So: candidates are **completed runs only**; the primary pick is the strongest
verdict; and at DEEP the second pick prefers a **different verdict**, else a
different environment, else nothing. Contrast beats confirmation — a second
malicious run tells an analyst almost nothing the first did not, while the
Windows 7 run that saw nothing beside the Windows 11 run that saw credential
theft says the sample is environment-dependent.

Everything is deterministic (environment identity, then report id), so the same
index always produces the same requests and a cached answer stays meaningful. The
strategy is named so coverage can state it.

---

## 5. Bounds

`ti_recon.sandbox.bounds`. One detonation can produce six hundred processes, four
hundred signatures and a thousand connections, and none of that belongs in an
evidence record whole.

Bounds are per depth with hard ceilings, and an unknown depth falls back to
STANDARD rather than the largest — a new depth value must not silently authorise
the most expensive normalization. A configured bound is still clamped: a
configuration cannot raise a ceiling.

Provider totals are always kept beside the normalized counts, so a bounded view
never reads as a complete one.

---

## 6. Deliberately absent: anything active

There is no submission, detonation or download model here, and none should be
added speculatively. Inactive submission code is submission code waiting for
someone to call it.

A future active path is a separate design with real requirements: explicit
analyst approval, a privacy warning about whichever platform receives the file,
artifact classification, a provider entitlement check, and environment selection.
The passive evidence semantics above should not need to change when it arrives —
that is what makes them worth writing down now.

The other clear extension point is a second provider. `SandboxVerdict`,
`SandboxReportState` and the summary shapes are the translation target, so a CAPE
or Triage integration writes a reader and a descriptor rather than a data model.
Neither is implemented.
