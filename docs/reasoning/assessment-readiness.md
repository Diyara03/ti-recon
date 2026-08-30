# Assessment Readiness and Coverage Adequacy

**Task 18.** Task 17 says what assessment the evidence justifies. Task 18 asks
whether the collection behind it was adequate — and answers for exactly one
purpose: **external-TI analyst triage**.

---

## 1. Why this is a separate layer

The two questions come apart in both directions, which is the entire reason the
layer exists:

| Task 17 says | Task 18 may say | Because |
|---|---|---|
| `MALICIOUS`, `HIGH` | `READY_WITH_LIMITATIONS` | behavioural coverage was unavailable |
| `LIKELY_BENIGN` | `NEEDS_MORE_DATA` | nothing independent has tried to contradict it |
| `INCONCLUSIVE` | `UNRESOLVED` | every applicable source was asked and knew nothing |

None of those readiness answers changes the assessment. A correct verdict about
an incompletely investigated observable is still correct, and an incomplete
investigation of a correctly-assessed observable is still incomplete.

## 2. Five distinctions the layer keeps

- **verdict ≠ readiness** — one is about the observable, the other about the run;
- **confidence ≠ completeness** — STIX confidence means confidence in
  *correctness*, so collection gaps must never be spent lowering it;
- **`NO_DATA` ≠ `NOT_RUN`** — a source that answered "nothing known" completed
  its check, and that is not evidence of safety either;
- **`EXHAUSTED` ≠ `ADEQUATE`** — asking everything available and learning nothing
  is a finished search with an open question;
- **a provider failure ≠ a gap** — it matters only when it prevents a *material*
  requirement from being met.

## 3. Two axes, one derived headline

`CoverageAdequacy` answers "is there enough coverage for this purpose?"
`ContinuationState` answers "could more enrichment still help?" `ReadinessStatus`
is derived from the pair, and exists for convenience only.

| Adequacy | Continuation | Status |
|---|---|---|
| `ADEQUATE` | `COMPLETE`, no limitations | `READY` |
| `ADEQUATE` / `LIMITED` | `COMPLETE`, with limitations | `READY_WITH_LIMITATIONS` |
| `INADEQUATE` | `MORE_DATA_AVAILABLE` | `NEEDS_MORE_DATA` |
| `INADEQUATE` | `BLOCKED` / `EXHAUSTED` / `COMPLETE` | `UNRESOLVED` |

`ADEQUATE` and `LIMITED` both require zero material gaps, and every continuation
other than `COMPLETE` requires at least one — so those pairings are unreachable
by construction rather than merely unused, and a test enumerates the reachable
set to keep it that way.

When material gaps disagree about what can be done next, precedence is
**addressable, then blocked, then exhausted**. An orchestrator's question is "can
anything still be attempted now?", so a run with one addressable gap and one
blocker reports `MORE_DATA_AVAILABLE`. The blocker does not disappear — it stays
in `gaps` — and once the addressable work is done a later evaluation surfaces it
as the remaining obstacle. Reporting `BLOCKED` first would stop a run that still
had useful work in front of it.

`READY` means **no material gap remains**, not "nothing else could conceivably be
queried". An optional capability that was never obtained is an execution fact in
the trace, not a headline limitation; otherwise every investigation would be
limited by whatever the catalogue contains but did not run. A limitation reaches
the headline only when it qualifies a check that *did* complete — a bounded
search horizon, a partial answer, a sandbox that watched nothing, a stale
supporting dataset.

Collapsing the axes earlier would hide the difference between "we could learn
more" and "there is nothing left to ask", which is exactly what an analyst
deciding whether to wait needs to know.

`BLOCKED` is deliberately not a top-level status: the limiting cause may be a
missing credential, an outage, a spent quota, an unimplemented capability or an
unattributable claim, and `UNRESOLVED` covers all of them without implying one.

## 4. Completion is not yield

The core model. Two independent questions about one check:

| `CheckCompletion` | `InformationYield` |
|---|---|
| `COMPLETE`, `PARTIAL`, `NOT_ATTEMPTED`, `BLOCKED`, `OUT_OF_SCOPE` | `DIRECTIONAL`, `CONTEXT_ONLY`, `NO_DATA`, `NONE` |

A source queried about an exact hash that answers "nothing known" is
`COMPLETE` + `NO_DATA`. That is strictly more coverage than a source nobody
configured, and it is not one atom of evidence that the file is safe.

Every `ProviderRunStatus` is mapped explicitly in `STATUS_COMPLETION` with no
default branch — a new status must be classified deliberately, because
defaulting one to "complete" would report an unasked question as answered and
defaulting it to "blocked" would invent a gap.

Two statuses need more than the table:

- **`PLAN_LIMITED` is a refusal, not a partial answer.** It reaches an attempt
  only through Task 6's error path, where the envelope is `None` — the execution
  model requires a result for `SUCCESS` alone. The credential is valid and the
  account's plan does not cover the data, so *nothing was retrieved*. That is
  `BLOCKED`, the same shape as a missing credential or a spent quota, and it
  gets its own gap type because supplying an entitlement is a different operator
  action from supplying a credential.
- **`PARTIAL` has two shapes.** Task 6 documents that a partial result is
  "usually an envelope carrying reduced evidence, but an adapter may also raise
  `PARTIAL_RESULT` when it could not retrieve enough to build one". The first
  partly covered the capability; the second covered none of it. A status table
  cannot tell them apart, so `completion_for` refines the status with the
  attempt's own record of whether anything came back.

## 5. Requirements come from Task 13

Readiness does not model what an observable needs; `EnrichmentPolicy.goals_for`
already does, and reconstructing it would produce a second opinion that could
drift from the one the planner used.

That gives three ways to be out of play, none of them a gap:

- **out of depth** — the goal does not exist below the requested depth, so a
  QUICK run is not incomplete for skipping DEEP work nobody asked for;
- **not activated** — a conditional goal whose trigger never fired, read from the
  planner's own recorded `SkipReason` rather than re-derived;
- **not applicable** — wrong observable type.

Criticality reuses Task 3's `CoverageRelevance` (`REQUIRED` / `RELEVANT` /
`OPTIONAL`) rather than inventing a parallel scale, and it is never a number.

## 6. Materiality

A gap is material only when resolving it could address something the assessment
has not settled:

- `REQUIRED` always;
- `RELEVANT` only when the basis is *not* strong;
- `OPTIONAL` never — it becomes a limitation, which is recorded and does not
  block.

Basis strength is read from Task 17's own `verdict_rule_id`, which is already
provider-neutral. A decisive exact claim, independent corroboration, and a benign
verdict where every malicious claim was individually explained are strong; a
residual suspicion and a single unopposed benign assertion are not.

So materiality never derives from provider identity. "Censys exists and did not
run" is not a gap.

### Capability availability is a catalogue fact

`CAPABILITY_UNAVAILABLE` is inferred from an uncovered `CoverageItem` whose
`providers_considered` is empty. That is safe because Task 13 builds that list by
walking the registry and asking each descriptor whether it supports the
capability for this object type — "candidacy, not success or configuration" —
before budget, credentials, activation, depth or ranking touch anything. So an
empty set is a statement about the catalogue, not about this particular run.

Where the two kinds of fact disagree, **execution history outranks catalogue
inference**: a recorded budget skip is direct evidence that a candidate existed,
so it is classified `BUDGET_LIMITED` rather than "no source exists". Reporting a
budget stop as unanswerable would tell an operator to give up on a question a
larger allowance would answer.

### One call can answer several capabilities

Task 13 bundles compatible goals into a single request wherever a provider
declares that one read returns its whole document, and it records **one**
`ProviderAttempt` carrying that call's *primary* capability. The capabilities the
response actually answered are credited in the `CoverageItem`s instead.

So the two records describe different things, and readiness reads both:

| Record | Says |
|---|---|
| `ProviderAttempt` | what was executed, and why anything failed |
| `CoverageItem` | which capabilities were **answered** |

Completion takes the better of the two. A ledger built from attempts alone
reports a bundled capability as never attempted and demands a second call the
planner deliberately avoided — a gap no enrichment could close, because the
information is already in hand. Reading the coverage record does not hide
execution problems: a blocked attempt for a capability covered elsewhere stays in
that requirement's check trace.

Evidence for capability A never establishes coverage for capability B. The
crediting comes from Task 13's own per-capability statement, never from the
presence of evidence in a shared envelope, and never from reading a claim type.

**Yield does not travel with completion.** `InformationYield` is derived only
from attempts keyed to the capability, so a secondary bundled capability reports
`NONE` — never the primary's `DIRECTIONAL`. That matters most for the challenge
rules: a context requirement that inherited a directional yield would look like a
search that had happened.

The honest limit: Task 13 records the outcome per *call*, not per capability, so
where one response answered two capabilities the repository cannot say which of
them returned data, context or nothing. `NONE` is the narrowest representation
the existing vocabulary offers, and no yield is guessed from evidence sharing the
envelope. Nothing decides on yield — it is reported and counted — so the
imprecision costs a summary figure rather than an answer.

An adverse search can also arrive as the *secondary* half of a bundle, leaving no
attempt of its own. The benign challenge therefore reads `PlanningDecision.call`
as well: `answered_capabilities` says the search was answered and `source_family`
says by whom, which is exactly what independence is judged on. A `CoverageItem`
would not do here — it records candidacy rather than who answered, so crediting a
challenge from it could let the benign basis's own family challenge itself.

## 7. Aggregation is at the capability

Three sources may serve one capability. If one is unconfigured, one is out of
quota and the third answered, the capability is **covered** — a requirement asks
for information, not a quorum. Both failures stay in the trace, because hiding
them would make the investigation look tidier than it was.

There is no provider percentage and no success ratio. Seven of nine providers
succeeding says nothing when the two that failed were the only ones that could
resolve the question.

## 8. The benign asymmetry

A malicious finding is self-limiting: something was found, and looking further
would not unfind it. A benign finding is an *absence*, and an absence is only as
good as the search behind it.

So a `LIKELY_BENIGN` reached from one unopposed assertion
(`likely_benign.unopposed_benign_claim.v1`) is not fully ready until an
**independent** adverse search has completed. Independence follows Task 17's
provenance grouping, so a second dataset from the organisation that made the
benign claim has not challenged it — it has agreed with itself under a different
name.

The challenge may return `NO_DATA`. That satisfies the requirement that somebody
looked, and adds no benign evidence whatsoever. **This is not provider voting**;
it is a requirement that a benign conclusion has been exposed to a search that
could have contradicted it.

**Independence is resolved through Task 17, not re-derived.** The benign basis's
component comes from `independence_groups`, which unions over source family,
origin provider *and* lineage group. A family comparison is not equivalent: a
relaying transport carries a different family while everything it reports
originates elsewhere, so comparing families alone would let one information
origin appear to challenge itself — the precise inflation Task 17 abandoned a
family-only model to fix.

**One honest limit.** A check that returned `NO_DATA` produced no claim, so it
has no origin or lineage to group on; the only provenance an attempt records is
its provider id and source family. For those, family separation is the strongest
defensible test available, and it is *weaker* than Task 17's claim-level
precision — two sources silently sharing an upstream feed are indistinguishable
here. That is a limit of what the execution record contains, and it is not
papered over by inventing an origin the data never had.

**Independence is necessary and not sufficient.** The challenging check must also
be an adverse search: a capability whose job is to look for what is known against
the object. That is a small explicit set — `REPUTATION`, `MALWARE_INTELLIGENCE`,
`THREAT_ASSOCIATIONS` — declared in policy and provider-neutral. A separate
origin that only looked at infrastructure exposure, certificate context,
scanner context or business-service membership has searched for nothing adverse,
however independent it is, and leaves the challenge unmet.

`FILE_BEHAVIOR` is deliberately outside the set: watching a sample run is a
different question from searching for what is known about it, and letting one
stand in for the other would satisfy the challenge without anybody having
searched.

The other benign route — every malicious claim specifically explained at exact
scope — has already engaged with adverse evidence, and needs no separate
challenge.

## 9. Context never satisfies a directional need

Warninglist matches, business-service membership, shared hosting and popularity
are context in Tasks 15–17, and stay context here. They cover the
false-positive and infrastructure requirements they belong to. They cannot cover
a reputation or threat-search requirement in either direction.

## 10. Scoped, not global

Two rules that would be easy to get wrong run-wide:

- **stale context** limits the requirement whose supporting data was stale, and
  nothing else. An out-of-date local dataset says nothing about an exact
  malware-sample identification. This is Task 16's scoping fix carried forward.
- **sandbox execution quality** affects behavioural *coverage* quality, never
  verdict direction. A completed run that watched nothing execute is `LIMITED`
  behavioural coverage — the sample may have wanted a click, noticed the watcher
  or found its C2 down — and it is evidence of nothing either way.

## 11. What Task 18 does not do

No enrichment: no HTTP, DNS, provider call, planner run or clock read. It reads
`evaluated_at` from Task 15, so a stored investigation re-evaluated years later
answers as it did the first time.

No score, no percentage, no severity, no priority, no risk number, no incident
declaration and no remediation action. TI Recon does not know asset criticality,
business impact, user context, internal telemetry, compensating controls or
incident policy — so it cannot say whether to block, quarantine, escalate or
close. It can say whether the external sources worth asking have been asked.

## 12. Standards framing

This is TI Recon policy, not an algorithm defined by any standard.

NIST CSF emphasises multi-source correlation, integration of CTI and context,
and organisationally-defined incident criteria for triage and validation. That
separation is why TI Recon keeps *external-TI assessment readiness* apart from
*organisational incident declaration, priority and response* — the second
depends on context this engine does not have.

STIX confidence means confidence that an assertion is **correct**. That is why
Task 17 confidence and Task 18 coverage are different fields decided by different
rules: an assessment can be correct and under-investigated at the same time.

## 13. Determinism and versioning

`READINESS_POLICY_VERSION` is `1.0.0`. Every result carries it alongside the
Task 15, 16 and 17 policy versions, so a stored answer can always be traced to
the rules that produced it.

`result_id` is **record identity, not a cross-run semantic fingerprint**. It
incorporates the Task 17 `assessment_id`, which is built over `Evidence.id` — a
UUID minted when the evidence was collected. So it is deterministic for one
stored investigation and differs across fresh collections of the same
intelligence, exactly as Task 17's is. The stable cross-run identities remain the
proposition and the requirement.
