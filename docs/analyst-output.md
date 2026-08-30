# The analyst output contract (Task 20)

The supported public result of an investigation. A CLI reads it, a future MCP
server will read it, and a UI could — which is the point: one contract, so no
interface has to interpret the engine for itself and none of them can drift.

## Why not `InvestigationResult`

`InvestigationResult` is the complete internal record: planner decisions, the
correlation graph, every engine's coverage counters. It is the wrong thing to
publish.

* Reading it correctly means knowing what all seven layers mean.
* It changes whenever any of those layers is refactored, so every consumer
  would be coupled to internal structure.
* It is unbounded — a large investigation carries hundreds of records nobody
  wants in a response.

`AnalystInvestigationReport` is the curated view instead. It is still available
internally: `InvestigationApplication.run()` returns the full result for anyone
debugging a disagreement between layers.

## Versioning

`ANALYST_REPORT_SCHEMA_VERSION` is `1.0.0`, and is deliberately separate from
the workflow and policy versions the report carries.

They change for different reasons. A fusion policy bump means the engine would
decide something differently; a schema bump means an application has to
re-integrate. Coupling them would force every consumer to react to changes that
do not affect them.

| Change | Allowed in 1.x |
| --- | --- |
| add an optional field | yes |
| remove or rename a field | no — version review |
| change what a field means | no — version review |
| change the meaning of a value | no — version review |

Every policy version that shaped a result travels in `versions`, so a stored
report stays explainable after the engine moves on.

## What the report may not do

The builder performs zero analysis. It does not decide which claim matters,
whether two sources are independent, whether an explanation applies, or whether
coverage is adequate — all of those already have an engine that owns them, and a
second opinion formed here would eventually disagree with the first.

| Section | Comes from | Never |
| --- | --- | --- |
| `assessment` | Task 17 verdict, band, rule ids | recomputed, scored, or turned into a probability |
| `assessment_basis` | Task 17 contributions marked `SUPPORTS_VERDICT` | a "most important provider" chosen here |
| `opposing_evidence` | Task 17 contributions marked `OPPOSES_VERDICT` | mixed into the basis, where it would read as part of the argument |
| `alternative_explanations` | Task 16 `ALTERNATIVE_EXPLANATION` findings with an `EXPLAINS` link | any other finding role |
| `unexplained_evidence` | Task 17 dispositions | re-derived by inspecting findings |
| `conflicts` | Task 17 conflicts | resolved, balanced, or given a winner |
| `qualifications` | Task 15 temporal facts | given a freshness label or a decay |
| `coverage` / `gaps` | Task 18 evaluations | re-judged for adequacy |
| `related_observables` | Task 14 graph edges | called indicators |
| `source_checks` | Task 13 attempts | counted as votes |

## Distinctions the report must preserve

**Confidence is not a probability.** `confidence_stix` carries the canonical STIX
integer (15/50/85) for consumers that need one, and it expresses *confidence
that the assessment is correct* — never the probability that the observable is
malicious. There is no calibration behind any such number. The human renderer
prints the band alone for exactly this reason; the integer stays in the JSON,
where a consumer asking for it knows what it means.

**Readiness is coverage, not permission to act.** The human renderer labels it
"TI coverage" because `READY` means the external-intelligence collection was
adequate for triage — not ready to close, ready to block, or incident-ready. The
model field name is unchanged.

**Verdict, confidence and readiness are three different answers.** The verdict is
about the observable. The confidence is about whether *the assessment* is
correct — never how bad the thing is. The readiness is about whether the
*collection* behind it was adequate. `MALICIOUS / MEDIUM / READY_WITH_LIMITATIONS`
is coherent, and so is `LIKELY_BENIGN / MEDIUM / NEEDS_MORE_DATA`.

**A related observable is not an indicator.** A contacted host, a resolved
address and a dropped file are relationships. `assessed` says whether this run
separately reached a verdict about the object; where it did not, no verdict is
implied. Rendering these as IOCs is how a public resolver ends up on a blocklist.

**Observed is not reported.** A sandbox watching a connection happen and a
provider reporting a historical association are different kinds of knowledge, and
`observation_basis` keeps them apart. Neither says anything about maliciousness.

**`NO_DATA` is not benign.** A source that answered "nothing known" completed its
check. That is also true of every threat nobody has caught yet.

**`UNATTRIBUTED` is not `NO_DATA`.** One call answered two capabilities and the
record cannot say which returned what. Rendering it as `NO_DATA` would assert the
source held nothing.

**An explanation covers linked evidence and nothing else.** Only a Task 16
alternative explanation with an `EXPLAINS` link appears, and the evidence ids
travel with it. One explanation never becomes "the investigation was a false
positive".

**Opposition is not basis.** Task 17 can reach a verdict while recording claims
that pushed the other way. Both are contributions and both appear, but in
separate sections: under one heading meaning "why", a benign assertion would
read as a reason the object was called malicious. Every item carries its Task 17
role in either section, so the machine contract is unambiguous regardless.

**Historical is not current.** Task 15's lifecycle states travel unchanged. A URL
that distributed malware in March and went offline in April did distribute
malware, and is not currently active.

## Bounds

Every section is capped, and every section reports `total` and `omitted`. An
analyst who cannot see that a list was cut has been told something false about
the investigation, so truncation is always stated — in the JSON counts and in the
text renderer's `... N more of M not shown`.

## Determinism

The same `InvestigationResult` always produces the same report and the same
bytes. Report generation performs no I/O: no clock (the instant is Task 19's
`evaluated_at`), no network, no filesystem, no randomness. `report_id` is derived
from the schema version and the result id rather than generated.

Two identities are run-scoped by design, inherited from the engine:
`assessment_id` and the claim and evidence ids incorporate the ids of the run
that produced them. Two collections of the same intelligence therefore differ
there and agree everywhere else.

## No action, ever

The report states an assessment. It never says to block, quarantine, isolate,
allowlist, suppress, close an alert or declare an incident. A `MALICIOUS` verdict
on shared or compromised infrastructure can make blocking actively harmful, and
whether to act needs asset criticality, business impact and incident policy this
engine has no access to.
