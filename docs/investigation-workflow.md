# End-to-End Investigation Workflow

**Task 19.** One observable in, one structured investigation out — composed from
the engines Tasks 13–18 already built.

---

## 1. The flow

```
canonical root observable
    │
    ├─► Task 13  adaptive planning ─► Task 6 execution
    │        └─► Task 14 correlation: graph, controlled pivots
    │
    ├─► Task 15  temporal and context qualification
    ├─► Task 16  alternative-explanation reasoning
    ├─► Task 17  evidence fusion and assessment
    └─► Task 18  readiness and coverage adequacy
             │
             └─► if readiness says a material gap remains *and* a path exists,
                 ask Task 13 again ─┐
                                    └─► recompute Tasks 15–18 over everything
```

Task 19 decides **when to stop asking**, and nothing else. It contains no
maliciousness rule, no coverage judgement and no provider choice. Each belongs to
a layer that already models it, and a second opinion formed here would eventually
disagree with the first.

## 2. The continuation state machine

| Task 18 says | Task 19 does |
|---|---|
| `READY` | stop — `READINESS_TERMINAL` |
| `READY_WITH_LIMITATIONS` | stop — `READINESS_TERMINAL` |
| `UNRESOLVED` + `BLOCKED` | stop — `READINESS_BLOCKED` |
| `UNRESOLVED` + `EXHAUSTED` | stop — `READINESS_EXHAUSTED` |
| `NEEDS_MORE_DATA` + `MORE_DATA_AVAILABLE` | build directives and ask Task 13 |

And within a continuation:

| Outcome | Stop reason |
|---|---|
| no need names a capability | `NO_ACTIONABLE_CONTINUATION` |
| the round added no execution, result or coverage | `NO_PROGRESS` |
| …and the remote allowance is spent | `CURRENT_BUDGET_EXHAUSTED` |
| new evidence arrived | recompute Tasks 15–18 and re-read the table |

**Only Task 18 triggers a continuation.** Not a suspicious verdict, not an
inconclusive one, not a failed provider, not a missing sandbox. Each is a reason a
person might feel the investigation is unfinished, and readiness has already
weighed every one against what the assessment actually rests on.

`READY_WITH_LIMITATIONS` is terminal **even with optional provider failures on the
record**. Tidying those up is spending an analyst's budget on the workflow's
discomfort.

Termination does not rest on a round count. It comes from finite candidates, a
cumulative budget and no-progress detection; the round ceiling in the code is a
defensive invariant whose reaching would be a bug.

## 3. What never changes between rounds

Depth, pivot mode and budget are ceilings the caller set. A continuation asks for
information *within* them.

- **Budget carries, never resets.** A fresh allowance per round would make the
  loop's total cost unbounded while every individual round looked well behaved.
  Task 13's state carries the spend forward, so round two sees only what remains.
- **Depth never escalates.** A QUICK investigation that would have benefited from
  DEEP work wanted a different investigation — the caller's decision.
- **Pivot mode never escalates.** `RECOMMEND` means the caller declined the
  disclosure a pivot lookup makes. Readiness wanting more data about the root is
  not their consent to tell a third party about something the root merely touched.
- **Calls are never repeated.** Task 13's state carries what has been asked, so a
  continuation cannot re-ask it. This is not left to the cache: a cache is an
  optimisation, and correctness that depends on one breaks the first time it
  misses. What is carried is `(provider_id, capability)` — a *question*, not a
  source. A provider that answered a reputation lookup remains eligible for a
  behaviour lookup, because a response shaped by what was requested has genuinely
  not answered the other question yet. Where a provider declares
  `capability_invariant_response`, Task 13 credits everything the one document
  answered, and the second call never happens at all.
- **Pivot budget and hop limit are investigation-wide.** `MAX_AUTOMATIC_PIVOT_HOP`
  stays 1 across every round, and a target enriched in round one is not enriched
  again in round two — which is also how a second hop would appear without anyone
  deciding to allow one.

Cache hits, coalesced results and local credential-free sources are valid coverage
at zero remote cost. The workflow therefore does **not** stop when the remote
allowance empties: it hands the remaining state to Task 13 and lets its locality
policy decide, because a local check that costs nothing may still close the gap.

### Two allowances, one unit each

The root observable and the pivot targets spend **different** budgets, and this is
deliberate rather than accidental:

| Allowance | Bounds | Carried by | Charged on |
| --- | --- | --- | --- |
| `EnrichmentBudget` | provider runs about the *submitted* observable | `PlanningState`, through `continuation()` | `called_provider` |
| `PivotBudget` | targets and provider runs about things the root merely touched | `CorrelationSession` | `called_provider`, via Task 13's own figure |

A pivot is handed the *remaining pivot* allowance as a Task 13
`max_remote_provider_runs` reduction, and its planning state is its own — a pivot
is a different observable with its own goals, and carrying the root's spend into
it would charge one call to two budgets. Neither allowance can rise: the
investigation's maximum remote disclosure is the sum of the two, both of which are
reduction-only and both of which survive every continuation.

Charging is on `called_provider` in both, so a cache hit, a coalesced request, a
cooldown, an unconfigured credential and every local provider cost nothing on
either side. A pivot served from cache discloses nothing and is free.

### Where a pivot's results go

Into the graph, *and* into the reasoning stages. Every provider outcome the
investigation produced — root and pivot alike — is recorded on the
`CorrelationSession`, and Tasks 15-18 read the whole set. A pivot result that
reached the graph but not the session would leave the picture looking complete
while the evidence behind half of it had never been qualified, explained or
assessed.

Present is not decisive. A pivot claim is indexed, qualified, explained and
recorded as a contribution, and it does **not** vote on the root's verdict —
Task 17 admits only claims whose subject is the assessment's own target. That
rule needs the claims to exist in order to have anything to decline.

## 3a. The capability envelope is frozen at the first round

Depth bounds the *questions*, not only the budget. Task 13 decides which
capabilities a root of this type is worth investigating at this depth; the
workflow records that set once, from the first round's own coverage items, and
every later round is bounded by it.

```
round 1 coverage  ─►  admissible capabilities  ─┐
                                                ├─►  directives ⊆ admissible
Task 18 material information needs  ────────────┘
```

Read from Task 13's answer rather than from a second copy of the depth table,
which would eventually disagree with the first.

**Why this is not a detail.** `requested_capabilities` is not a filter: Task 13
turns every member into a `REQUIRED`, `IMMEDIATE` goal *whatever the depth
template said*, because a caller naming a capability has overridden the default
judgement. A continuation that added its directives there would therefore do
three things nobody asked for — create a goal the requested depth never
admitted, activate a conditional goal whose trigger had not fired, and promote
an optional goal to required — and a QUICK investigation would become a DEEP one
a capability at a time. So the planning request is byte-identical every round,
and narrowing happens entirely through the session's focus.

Three categories, deliberately not collapsed into two:

| Category | Continuation may target it? |
| --- | --- |
| admissible at this depth, and active | yes |
| admissible, activation condition not met | no — Task 13's activation rule stays authoritative |
| outside the requested depth | never |

When no admissible capability can address a material need, the workflow stops
with `NO_ACTIONABLE_CONTINUATION` and records the issue. Readiness is right that
more data would help; deciding the investigation should have been deeper is the
caller's decision, and starting one remains theirs to make.

## 3b. Excluding a source family from one question

Readiness can require an adverse search *independent* of whatever produced an
assessment. Family is the only provenance knowable before a call, so the
directive carries the families Task 17 has already grouped with that origin, and
Task 13 receives them as `excluded_source_families` — a mapping, not a set:

```
ContinuationDirective(capability=X, avoid_source_families={A})
        │
        ▼
CorrelationSession.excluded_families = {X: {A}}
        │
        ▼
PlanningState.family_excluded(X, "A") -> SkipReason.SOURCE_FAMILY_EXCLUDED
```

Keyed per capability throughout. One set for the whole round would withdraw a
family from every other question too, where independence was never what was
being asked and the family's answer is worth exactly what it always was.

Checked before cost and budget, because the point is that this source cannot
answer *this* question at all. Letting it win the ranking would spend the
remaining allowance on a source that could not satisfy the requirement the round
was released for, leaving the genuinely independent candidate unaffordable — so
the investigation would end further from an answer than it began.

Still not a proof of independence. A family nobody has linked to the origin is
*potentially* independent; only the returned provenance settles it, and Task 17
regroups from that afterwards.

## 4. Continuation directives name capabilities

A directive says `FILE_BEHAVIOR`, never a sandbox. Which source can serve a
capability, whether one is configured, what it costs and whether it is worth the
remaining budget are all Task 13's questions, answered with a catalogue and a
ranking this layer does not have.

```
readiness information need  ─►  ContinuationDirective(capability=…)
                                      │
                                      ▼
                            Task 13 planner + ranking
                                      │
                                      ▼
                              Task 6 executor
```

### The benign challenge, and why pre-call family separation is only a hint

When Task 18 wants an adverse search independent of whatever asserted an object
was benign, the directive carries the source families already known to share that
origin, so the planner can prefer something else.

That is a **planning hint, not a claim of independence**. Family is the only
provenance knowable before a call. A source that looks unrelated can turn out to
relay the very origin it was meant to challenge — and when it does, Task 17's
provenance grouping sees it in the returned evidence and Task 18 reports the
challenge as still missing. The workflow does not get to declare the answer
independent because it picked a different family.

## 5. Recompute, never patch

After new evidence arrives the pure engines run again over the accumulated state.
Nothing is edited in place. A patched verdict is a verdict nobody can re-derive,
and the engines are deterministic and side-effect free — re-running them is
simpler than reasoning about which conclusions a new claim might have invalidated.

**Readiness may get worse after new evidence, and that is correct.** A round-two
finding that genuinely conflicts can take `SUSPICIOUS`/`NEEDS_MORE_DATA` to
`INCONCLUSIVE`/`UNRESOLVED`. Task 18's monotonicity rules concern satisfying a
fixed requirement without new adverse information; they are not a promise that
investigations only improve.

Each pass uses **one instant**, taken after that round's collection finished, so
the pass is internally consistent. A later continuation gets its own. The final
result records the instant its final pass used, and the four analytical results
it carries are all outputs of that same pass.

## 6. Failures

| Kind | Treatment |
|---|---|
| unconfigured, rate limited, quota exceeded, unavailable, error, `NO_DATA`, `NOT_SUPPORTED`, `PLAN_LIMITED`, `PARTIAL` | analytical input — the run continues and Task 18 decides materiality |
| stages describing different observables, a merge conflict between rounds | `InvestigationError` — raised |
| `asyncio.CancelledError` | propagates untouched |

A structural fault returned as `INCONCLUSIVE` would dress a software error as an
analytical conclusion somebody could act on. A cancellation converted into a
provider failure would put an operational event into an analytical record, where a
reader would later mistake it for something a source did.

## 7. State, isolation and persistence

The orchestrator is reusable and holds no run state: the graph, the accumulated
outcomes, the planner memory, the pivot set and the round history all live in a
per-run object. Two investigations through one instance share nothing — without
that, a long-lived service would slowly accumulate one enormous investigation.

The `ExecutionScope` in the caller's context reaches every provider call in every
round unchanged. Substituting a shared or default scope would cross the user
isolation every cache, cooldown and entitlement store depends on.

**No persistence, and no resumability is claimed.** The result is returned to the
caller. Continuation happens *inside one invocation*; an investigation does not
survive a process restart, and two independent calls to `investigate()` are two
independent investigations — the Task 6 cache may reduce the work, but no durable
idempotency is offered. That belongs to later production work.

## 8. Boundaries

Task 19 is transport-neutral: no HTTP, no CLI, no MCP, no database, no background
worker. Everything one invocation needs arrives in the request, the execution
scope and the injected dependencies, so a future stateless interface can wrap it
cleanly.

It adds no network surface of its own — every external call goes through
Task 13 → Task 6 → an adapter, which is where the cache, cooldown, quota, retry,
scope and budget accounting live. It introduces no active operation: no
submission, no rescan, no download.

Its output is structured. There is no narrative, no severity, no priority, no risk
number and no recommendation — what a reader should *do* depends on asset
criticality, business impact and incident policy this engine has never seen.
Task 20 can render it; Task 21 can summarise it.

## 9. Versioning

`INVESTIGATION_WORKFLOW_VERSION` is `1.0.0` and covers *composition* semantics:
stage ordering, when a continuation is attempted, when it stops, how budgets carry
and how the result is assembled. It says nothing about the analytical policies,
which carry their own versions and travel on the result beside it.

Once 1.0.0 ships, a behavioural change here needs an explicit review.

`result_id` is **record identity, not a cross-run semantic fingerprint**. It
incorporates the readiness result id, which incorporates the Task 17 assessment
id, which is built over `Evidence.id` — a UUID minted when the evidence was
collected. Deterministic for one stored investigation; different across fresh
collections of the same intelligence, exactly as every id below it is.
