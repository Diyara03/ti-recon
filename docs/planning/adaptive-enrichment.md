# Adaptive enrichment planner and orchestrator

Task 13. `src/ti_recon/planning/`

Answers one question: **what should TI Recon ask next?**

Given an observable, a depth and optionally a list of capabilities the caller
wants, the planner decides which provider to query, for which capability, in what
order, whether another query would add anything, whether the budget allows it,
and when to stop. The orchestrator then runs each decision through the Task 6
executor and folds the result back in before deciding again.

It is deliberately **not** the fusion engine. Nothing here produces a verdict, a
risk score or a confidence number, and no stop reason means "the answer is
known". A run ends because the requested coverage was collected, the budget ran
out, or nothing eligible remains — all three are operational facts about the
*investigation*, not conclusions about the observable.

---

## 1. Why a planner at all

Without one, "enrich this" means "call every configured provider". That has three
problems, and they get worse as the catalogue grows:

- **Cost scales with the catalogue, not the question.** Adding a tenth provider
  makes every QUICK triage lookup 11% more expensive, forever.
- **Nothing informs anything.** Firing nine providers at once spends the whole
  allowance before any answer can change what is worth asking. Whether a file
  has ever been seen is exactly what decides whether a sandbox query is worth
  buying.
- **Provider agreement gets miscounted.** ThreatFox, URLhaus and MalwareBazaar
  are three datasets run by one organization. "Three providers agree" is a
  sentence a fan-out invites and the evidence does not support.

So enrichment is expressed as **coverage of questions** rather than as a provider
list, and each answer is folded in before the next decision.

---

## 2. Capabilities, not vendors

Planning is stated as *what is still missing*, never as *who has not been called
yet*:

```
"is anything covering FILE_BEHAVIOR?"      not  "have we tried the sandbox?"
```

A `CapabilityGoal` names a `ProviderCapability` from the Task 3 vocabulary, how
many **independent source families** should cover it, when it activates, and the
shallowest depth at which it exists at all. `DEFAULT_GOAL_TEMPLATES` declares
those per observable type per depth.

No template names a provider. `src/ti_recon/planning/` contains exactly one
module that may — `catalog.py`, the shipped registry — and a test reads the AST of
every other module to prove no provider id or source family appears as a value.

The consequence is the point: a provider being added, removed, renamed,
unconfigured or denied changes which provider answers a goal and never whether
the goal exists.

### Goals nobody can serve are dropped

`initial_state` keeps only goals some registered, plannable provider offers *for
this observable type*. A goal nothing can satisfy would sit permanently
unsatisfied and be reported as a coverage gap, as though a provider had failed.
Coverage distinguishes the two cases in its reason text: "no registered provider
offers this capability for this observable" is a blind spot in the catalogue, not
a failure in the run.

---

## 3. Source families, not provider counts

Coverage is tracked **per source family**, so:

- three abuse.ch platforms answering is **one** family covered;
- one provider emitting twenty-five evidence records is **one** family;
- one sandbox returning reports from four environments is **one** family;
- an independent family saying the same thing is real corroboration.

`NoveltyClass` is what a candidate would add:

| Novelty | Meaning |
|---|---|
| `NEW_CAPABILITY` | nobody has answered this kind of question |
| `NEW_SOURCE_FAMILY` | a family that has not answered this question |
| `NEW_DATASET_SAME_FAMILY` | another dataset from a family that already did |
| `REDUNDANT` | nothing left to add |

Buying a *kind* of answer nobody has beats buying the same answer from someone
else, which beats buying it from the same house again. Note the second-order
effect: a provider in an already-covered family is still chosen readily for a
capability nobody covers. Family independence bounds corroboration, not
usefulness.

### An empty answer does not close a family (Task 24 Phase 2)

A family target counts a family once it has **answered**. A dataset that
returned data has answered for its family; a dataset that returned `NO_DATA`
has answered *for that dataset*. While a sibling dataset in the same family
that serves the capability for this observable is still eligible — configured,
affordable, not blocked, not yet asked — the family stays **open** and the goal
stays unsatisfied, so the sibling is a candidate (`NEW_DATASET_SAME_FAMILY`)
rather than closed out by its relative's silence. Once every eligible dataset
has answered, or none remains eligible, the family counts exactly as before.

Reconstructed live: an address's two-family reputation target was met by one
family's data plus a URL tracker's `NO_DATA`, so the same house's IOC tracker —
eligible, unattempted, and built for a different question — was never a
candidate, the only continuation directive named a capability nobody configured
could serve, and the run stopped "without progress" with an unasked source in
the catalogue. Family sameness bounds *corroboration*: three abuse.ch datasets
are still one origin in Task 17. It does not mean "never ask another dataset in
the family" when the first one held nothing.

This is gap closure, not query-everything. A family that answered with data is
closed; a provider that already answered a capability — by name, or as part of
a whole-document response it declared invariant — is never the sibling that
reopens it; the budget, the depth, the activation rules, the blocked set and the
attempted set all apply unchanged. `PlanningState.answered` records which
provider answered which capability so that last rule holds.

### One provider, one call, several questions

A provider that serves several *currently active* goals is asked **once**, for all
of them. `PlannedProviderCall` therefore carries three capability sets:

| Field | Meaning |
|---|---|
| `capability` | the one that won the ranking; explains the decision and sets the cost class |
| `capabilities` | everything the provider request carries |
| `answered_capabilities` | everything one response from this provider answers |

Only *current candidates* are bundled, which keeps three rules intact without a
single provider-specific condition:

- a goal that does not exist at this depth is not a candidate, so a bundle can
  never widen depth — QUICK asks nothing for `FILE_BEHAVIOR` however many
  providers support it;
- a goal still waiting for its activation is not a candidate either;
- an **elevated-cost** capability is excluded outright. It has to win a decision
  of its own, or a bundle becomes a way to spend the high-cost budget nobody
  decided to spend — and, for retrieved page content, a way around the rule that
  forensics needs an explicit request.

Bundling therefore never costs more than the decision that created it: one
bundled call is one logical run and one budget unit.

### Whether asking again is incremental work or a duplicate

`ProviderPlanningProfile.capability_invariant_response` is the provider's own
statement about the shape of its answer:

- **`True`** — one read returns everything it knows, whatever the request named.
  Seven of the nine integrations are like this. Coverage is credited for every
  capability that response answered (bounded by what the descriptor supports for
  this observable), so a goal activating later finds itself already covered
  instead of buying the identical document again at full price.
- **`False`** — the response is *shaped* by the request. GTI filters its
  relationship plan by exactly the requested capabilities and fetches the
  behaviour summary only when `FILE_BEHAVIOR` is among them; urlscan retrieves
  page artifacts only for `WEB_FORENSICS`. A capability nobody asked for was not
  answered, so a later call for it is genuine incremental work and is allowed —
  and charged.

This is why the deduplication has to happen in the planner rather than in the
cache: `requested_capabilities` is part of the Task 6 cache key, and correctly so,
because for a request-shaped provider two sets are two different questions. A
duplicate cannot be absorbed below the planner; it has to not be made.

Worked example — DEEP file, shipped catalogue:

```
misp_warninglists  [false_positive_context]
malwarebazaar      [reputation + malware_intelligence]   one read, two goals
gti                [reputation]                          second independent family
gti                [file_behavior]                       separate endpoint, real work
```

Four logical runs, three of them remote. GTI appears twice and that is correct;
MalwareBazaar appears once where three separate calls would once have been made.

---

## 4. Locality: a passive lookup is still disclosure

`ProviderLocality` is `LOCAL` or `REMOTE`, and it is a **declared** property, not
an inference.

Reading `requires_credentials == False` as "local" would be wrong in the
direction that matters: a credential-free HTTP API still sends the observable to
a third party. Today exactly one provider is `LOCAL` — the MISP warninglist
snapshot, which is a file on disk — and a test asserts that a `LOCAL` provider
genuinely needs no credential while deliberately *not* asserting the converse.

`PlanningConstraints.allow_remote_lookup = False` therefore has a precise
meaning: enrich using only what does not leave the machine. It is not a cost
control; it is a disclosure control, and a run under it stops with
`REMOTE_LOOKUPS_DISABLED` rather than pretending it finished.

---

## 5. Budgets

`EnrichmentBudget` caps two things per run:

| Depth | Remote runs | High-cost runs |
|---|---|---|
| `QUICK` | 2 | 0 |
| `STANDARD` | 4 | 1 |
| `DEEP` | 6 | 2 |

Every number is a TI Recon policy default, configurable, and makes no claim about
any provider's real limits — those are the providers' business and are enforced
inside them by Task 6.

A caller may **lower** a budget and never raise it: `max_remote_provider_runs` is
reduction-only, so a constraint cannot become a way to spend more than the depth
allows.

### What is charged, and what is not

The budget is charged on `ProviderExecutionOutcome.called_provider` — which is
`attempts > 0`, the execution layer's own truth about whether anybody was
contacted:

| Situation | Charged |
|---|---|
| real provider request | yes |
| Task 6 cache hit | **no** |
| request coalesced into another in flight | **no** |
| credential not configured | **no** |
| provider in cooldown | **no** |
| quota pre-check refused | **no** |
| local provider | **no** — never, whatever happened |

This is what makes cache-first ranking safe: the planner can pick the *best*
source and let the execution layer answer for free if it already knows. A budget
charged on decisions rather than calls would make a warm cache look expensive.

`CallCostClass` (`ZERO`/`LOW`/`MEDIUM`/`HIGH`) ranks candidates, and
`elevated_cost_capabilities` exists because one class per provider cannot describe
urlscan or GTI honestly: both are ordinary for a summary read and expensive when
asked to retrieve and analyse stored content. That capability is charged against
the high-cost budget regardless of the provider's own class.

---

## 6. Ranking: lexicographic, and deliberately so

There is no weighted score — no `0.37 * reputation - 0.21 * cost + …`. There is no
evidence for any such constant, and inventing one produces a number that looks
principled, cannot be explained to an analyst, and changes behaviour
unpredictably every time a provider is added.

`RANKING_FACTORS` is the order, as data, compared in sequence with the first
difference winning:

| # | Factor | Why here |
|---|---|---|
| 1 | explicitly requested capability | a caller who asked by name gets it before the defaults, not after the budget went on baseline work |
| 2 | local before remote | free and discloses nothing, so deferring one can never help |
| 3 | required, unsatisfied goal | learning something required beats deepening something optional |
| 4 | baseline before specialized | asking what a file *did* before knowing whether anyone has seen it is the wrong order, and spends the expensive request first |
| 5 | novelty | a kind of answer nobody has > a new family > the same family again |
| 6 | cheaper cost class | |
| 7 | higher profile priority | a tie-break between equally suitable providers, never a quality score |
| 8 | provider id, then capability | total, stable order rather than one determined by iteration order |

Three properties follow: it is deterministic, every decision can be explained by
naming the first factor that separated two candidates, and a test can pin it.
Identical inputs produce identical plans, and registration order changes nothing.

---

## 7. Activation: not everything should be bought up front

`GoalActivation` says when a goal may spend budget:

- **`IMMEDIATE`** — baseline coverage, from the first round.
- **`AFTER_BASELINE`** — once every required goal has been attempted. With
  `requires_trigger`, it additionally needs a *reason*: directional evidence to
  explain, or a baseline that came back uncovered.
- **`EXPLICIT_ONLY`** — only when the caller named the capability. For work
  nobody should pay for on an analyst's behalf.

So sandbox behaviour is conditional at `STANDARD` and expected at `DEEP`; web
forensics is explicit-only at `STANDARD` and conditional at `DEEP`. An explicit
request activates any goal immediately — the caller has already made the
judgement the rule exists to make for them — but never lowers a provider's
`minimum_depth`, because depth is the caller's own statement about how much work
this investigation warrants.

A provider may also declare a floor **per capability**
(`ProviderPlanningProfile.capability_minimum_depth`, Task 24 Phase 3): GTI
answers reputation at QUICK and detonation data only at DEEP. The planner
skips such a capability below its floor with `DEPTH_TOO_SHALLOW` before cost
and budget are consulted, so a call the adapter would refuse is never
selected, never charged and never recorded as an attempt. The adapter's own
refusal stays as defence in depth.

---

## 8. What counts as an answer

The difference between "asked and told nothing" and "could not ask" is most of
why a planner is worth having:

| Status | Effect on coverage |
|---|---|
| `SUCCESS` | covered |
| `NO_DATA` | **answered, empty** — counts toward a family target once no eligible sibling dataset in the family remains unasked (§3) |
| `PARTIAL` | recorded, but satisfies no family target |
| everything else | no coverage |

`NO_DATA` is coverage of a *source*, never evidence about the observable. Nothing
in the planner can turn absence into reassurance: there is no `SUPPORTS_BENIGN`
path, no vendor counting, and no member of `StopReason` meaning "confident
enough". A planner that treated silence as safety would stop early on exactly the
samples nobody has seen yet.

Likewise, false-positive context never substitutes for threat intelligence. A
warninglist match is `CONTEXT_ONLY`; it explains evidence rather than replacing
the need for any. Stopping on one would systematically under-investigate
everything hosted on shared infrastructure — which is now most things.

---

## 9. Stopping

Every `StopReason` is operational:

| Reason | Meaning |
|---|---|
| `GOALS_SATISFIED` | every **active** goal has the coverage it asked for |
| `REMOTE_BUDGET_EXHAUSTED` | the depth's remote allowance is spent |
| `HIGH_COST_BUDGET_EXHAUSTED` | only expensive candidates remain |
| `REMOTE_LOOKUPS_DISABLED` | local providers only, and they are done |
| `ALL_REMAINING_BLOCKED` | everything left refused, throttled or unconfigured |
| `ALL_REMAINING_REDUNDANT` | everything left would repeat a family already asked |
| `NO_ELIGIBLE_PROVIDER` | nothing left that could add anything |

`MAX_PLANNING_ROUNDS` is a hard backstop on rounds, independent of budget. The
loop terminates on its own — every executed decision marks a provider/capability
pair attempted, and that set is finite — so hitting it is a bug, and it is
reported as `NO_ELIGIBLE_PROVIDER` rather than as a satisfied plan.

Only *active* goals gate `GOALS_SATISFIED`. A goal deliberately withheld — web
forensics nobody asked for, a follow-up whose trigger never fired — is not an
unmet objective, and reporting "no eligible provider" for it would describe a
design decision as a failure.

`AdaptiveEnrichmentResult.has_uncovered_required_capability` is the field to read
when the distinction matters: a run can stop tidily and still not have answered
the question it existed to answer.

---

## 10. Layering

```
  AdaptiveEnrichmentPlanner        what to ask      no I/O, deterministic
           |
  AdaptiveEnrichmentOrchestrator   loop            plan -> execute -> observe
           |
  ProviderExecutor  (Task 6)       how to ask      cache, retry, quota,
           |                                       cooldown, concurrency
  ProviderAdapter   (Task 5)       ask             transport, normalization
           |
  Evidence          (Task 3)       facts
           |
  Fusion            (future)       what it means
```

`AdaptiveEnrichmentOrchestrator.with_outcome_sink()` offers each provider outcome
to a caller as it completes — the seam Task 14 uses to reach the objects and
relationships a result carries, which the report model deliberately does not hold.
The sink is never read back, so collecting cannot influence what gets asked.

The planner performs no I/O, resolves no credentials, reads no cache and never
retries — Task 6 owns all four, and a planner-side retry would silently multiply
the retry policy it cannot see. It never touches an adapter's client; a test
asserts nothing under `planning/` imports `httpx`, the credential layer or
`SecretStr`, or calls a client method or `sleep`.

### Sequential, on purpose

The orchestrator runs one provider at a time. Fanning out would spend the whole
budget before any answer could inform the next decision, which is the behaviour
this task exists to replace. That is a deliberate trade of latency for provider
usage; `ProviderExecutor`'s concurrency remains available to other callers, and
planning *waves* can be added later if latency data ever justifies it — with real
numbers rather than an assumption.

### Passive, and one observable

Since Task 14, the planner also has a caller that *does* enrich more than one
observable — the correlation orchestrator, which hands it one bounded pivot target
at a time. Nothing about this layer changes: each pivot is a separate planning run
over a single observable, at a reduced depth, with its remote budget already
lowered by the caller. Planning still never recruits its own work.


`EnrichmentPlanningRequest` refuses a non-passive activity mode or a non-`LOOKUP`
operation **at construction**, so a plan that submits, detonates or rescans
cannot be built at all. A structural test additionally asserts that every
`ProviderOperation` and `ActivityMode` name mentioned anywhere in the package is
the passive one.

A run enriches **the requested observable only**. Providers return related
objects — domains a sample contacted, files it dropped, hosts serving a URL — and
none of them is planned. Recursive pivoting needs pivot-value judgement, graph
deduplication, fan-out limits and cycle prevention, and a task of its own; doing
it here would turn one file into hundreds of queries.

### No AI in the loop

The planner is deterministic code. It calls no LLM and no external ranking
service. Claude and MCP sit *above* TI Recon and will eventually call it — which
is exactly why they must not choose which intelligence sources it queries
internally, or provider selection becomes non-reproducible and prompt-shaped.

---

## 11. The shipped catalogue

`ProviderPlanningProfile` adds only what planning needs and the descriptor has no
business knowing. Which observables and capabilities a provider supports is read
from the Task 5 descriptor, not restated here.

| Provider | Locality | Cost | Min depth | Priority | Elevated |
|---|---|---|---|---|---|
| `misp_warninglists` | local | zero | quick | 90 | |
| `gti` | remote | medium | quick | 70 | `file_behavior` |
| `greynoise` | remote | low | quick | 60 | |
| `urlhaus` | remote | low | quick | 55 | |
| `malwarebazaar` | remote | low | quick | 55 | |
| `threatfox` | remote | low | quick | 50 | |
| `hybrid_analysis` | remote | high | standard | 50 | |
| `urlscan` | remote | medium | quick | 40 | `web_forensics` |
| `censys` | remote | medium | standard | 30 | |

`threatfox`, `urlhaus` and `malwarebazaar` share `source_family = "abuse_ch"`, so
two of them agreeing can never read as two corroborations.

`auto_enrichment_allowed` can keep a provider out of automatic plans entirely
while leaving it callable directly — an integration can land before anybody
decides default enrichment should use it. A test discovers provider descriptors
from the package tree and fails when one has no planning profile, so that decision
cannot be skipped by omission.

---

## 12. Metrics

`PlanningMetricsSink` records selections, skips and completed runs. Skips matter
most: a provider skipped as `BLOCKED` all week is an entitlement problem, one
skipped as `UNSUPPORTED_OBSERVABLE` all week is a catalogue gap, and both look
like silence without a counter.

Every field is an enum member, a bounded provider id, a small integer or a bool.
There is no observable value and no free text anywhere — a metric labelled with
the IOC would quietly turn a metrics pipeline into a log of everything every
analyst has investigated, with a retention story nobody agreed to. Nothing is
load-bearing: the default sink discards and no decision reads a metric back.

---

## 13. What this task is not

- No verdict, risk score, confidence or provider weighting.
- No evidence fusion, conflict resolution or decay.
- No related-object pivoting.
- No active operation of any kind.
- No provider-specific behaviour outside `catalog.py`.
- No new live provider test suite: scheduling logic is tested against fake
  providers and mocked clients, because spending real API quota to test a
  decision that never leaves the process buys nothing.

## Where the results go next

An `AdaptiveEnrichmentResult` says what was asked and what came back. Task 14
assembles the objects and relationships into a graph, and Task 15 qualifies the
provider result envelopes — plus that graph — in time and context.

Nothing flows the other way. Task 15 performs no I/O and never triggers a plan:
"this evidence is old" is a fact it records, not a reason to call a provider.
Orchestrating a refresh stays a caller's decision made with Task 13, so a
qualification can never multiply provider traffic. See
[docs/reasoning/temporal-evidence.md](../reasoning/temporal-evidence.md).
