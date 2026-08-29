# Evidence Fusion and Final Assessment

> Task 17. What assessment is justified, and how confident TI Recon is that it is
> right. Implemented in `src/ti_recon/reasoning/fusion/`.

## 1. The first layer allowed to conclude

Everything below Task 17 deliberately refused to reach a verdict:

```
Task 13  what should we query?
Task 14  what objects and relationships did we learn?
Task 15  what do those facts mean in time and context?
Task 16  which evidence has a plausible alternative explanation?
Task 17  what assessment is justified?          <- here
Task 18  is it sufficient for a particular decision?
```

Task 17 is not the end of that chain. It assesses the **observable**; whether to
act on that assessment depends on the environment, and belongs to a later layer.

## 2. No score, no votes

There is no `risk_score`, `malicious_score`, `probability` or `evidence_weight`
anywhere, and no arithmetic in the policy — a structural test asserts that
`policy.py` and `confidence.py` contain no multiplication, division or
exponentiation.

That is a position, not an omission. There is no calibration data behind any
coefficient anybody could write here, so a weighted formula would manufacture
precision that looks defensible, cannot be explained to an analyst, and shifts
unpredictably when a provider is added. A rule hierarchy can always answer *which
rule decided this*, which is the question that actually gets asked.

Providers are never counted. VirusTotal is itself an aggregator; forty vendor
detections are one source reporting forty opinions. `AGGREGATED_REPUTATION`
corroborates nothing, including another aggregate.

## 3. Independence

Dependence is a **relation**, and grouping is its transitive closure. Three pieces
of provenance each make two claims dependent, and any one of them is enough:

- the same `source_family` — three abuse.ch datasets are one organisation;
- the same `origin_provider` — whoever produced it, however many transports
  relayed it;
- the same `lineage_group_id` — one provider's repeated renderings of one finding.

Claims are unioned into connected components over those edges. If A shares a
family with B and B shares an origin with C, then A, B and C are one origin — even
though A and C have no key in common.

| Situation | Result |
|---|---|
| Same lineage group | one origin |
| Relayed through another transport | one origin |
| Same source family, different vendor ids | **one origin** |
| Different families naming the same `origin_provider` | **one origin** |
| Different families, different origins | potentially independent |

Note the asymmetry: two different vendor ids are *not* assumed independent, but
two different families with nothing else in common are treated as potentially so.
Independence must be earned by provenance; difference of vendor is not evidence of
it.

> **Two bugs worth recording, with one cause.** The first implementation keyed on
> lineage, on the reasoning that lineage is narrower and more deliberate. It is —
> but Task 3 *defaults* `lineage_group_id` to `"{family}:{origin}"`, so two members
> of one family arrived with different lineage keys and were counted as two
> independent origins. Keying on family instead fixed that and introduced the
> mirror-image failure: a relay whose transport belongs to a different family
> names the same origin, and a family-only partition read one source reporting
> once as two independent confirmations — escalating the verdict to `MALICIOUS`.
>
> Neither rule was too weak. Both were too narrow: dependence is a set of edges,
> and any scheme that picks one of them in a precedence order silently discards
> the rest. Independence is now a connected component, and the verdict and the
> confidence band both count components rather than families.

Nothing is discarded. Every claim stays in the trace with its own provenance; only
its ability to *corroborate* something already counted collapses, and the
contribution records that as `DEPENDENT_CORROBORATION`.

## 4. Task 16 is read exactly

Only an `ALTERNATIVE_EXPLANATION` finding, through an `EXPLAINS` link, to a piece
of **evidence**, removes support.

Everything else Task 16 produces is a caution about how to *read* evidence:

| Task 16 role | Effect in fusion |
|---|---|
| `ALTERNATIVE_EXPLANATION` + `EXPLAINS` → evidence | `EXPLAINED_BY_ALTERNATIVE` — not relied upon |
| `ATTRIBUTION_CAUTION` | `QUALIFIED_ONLY` — still support |
| `TEMPORAL_RELEVANCE` | `QUALIFIED_ONLY` — still support |
| `ANALYSIS_QUALITY_LIMITATION` | `QUALIFIED_ONLY` — still support |
| `INTERPRETATION_LIMITATION` | `QUALIFIED_ONLY` — still support |
| `SOURCE_DEPENDENCE` | `QUALIFIED_ONLY` — still support |

Getting this wrong would be the most expensive bug in the system: an attribution
caution says a compromised host has a victim, and treating it as an explanation
would clear real malicious evidence behind a verdict that looked thoroughly
reasoned. A parametrized test walks every non-explanation role and asserts none of
them marks evidence explained.

**Explained is not false.** Such a claim is retained in full; the trace says the
verdict did not rest on it, not that the source was wrong.

## 5. Decision roles

`decision_role_for` reads semantic, scope, assertion strength and evidence class —
no provider appears anywhere in it.

| Role | Meaning | Examples |
|---|---|---|
| `DECISIVE` | Can justify a verdict alone | exact `MALWARE_SAMPLE_IDENTITY`, exact `MALWARE_DISTRIBUTION`, directly-observed sandbox |
| `CORROBORATIVE` | Real support that wants company | reputation verdicts, threat associations, non-exact scope |
| `WEAK` | Never carries a verdict | aggregates, unclassified, hedged claims |

A hedged claim is never decisive however specific its semantic — a source that
said "suspicious" did not say "malicious".

## 6. Verdict rules

| Rule | When |
|---|---|
| `malicious.decisive_exact_claim.v1` | one unexplained decisive exact-scope malicious claim |
| `malicious.independent_corroboration.v1` | compatible non-weak support from ≥2 independent families |
| `likely_benign.unopposed_benign_claim.v1` | a genuine directional benign assertion, nothing malicious |
| `suspicious.residual_support_under_conflict.v1` | genuine conflict, real malicious support survives |
| `inconclusive.unresolved_conflict.v1` | genuine conflict, both sides weak |
| `suspicious.unexplained_residual_support.v1` | unexplained malicious support short of decisive |
| `likely_benign.all_malicious_claims_explained.v1` | every malicious claim specifically explained, none left |
| `inconclusive.no_directional_support.v1` | nothing pointed anywhere |

**SUSPICIOUS and INCONCLUSIVE are not interchangeable.** SUSPICIOUS means there is
an affirmative reason for concern. INCONCLUSIVE means neither direction can be
justified. Missing data, a provider that returned nothing and a sandbox that ran
nothing are none of them reasons for concern, and reporting them as suspicion
would flood an analyst with alarm generated by absence.

## 7. What can never reach LIKELY_BENIGN

Each was refused deliberately at an earlier layer, and is refused again here:

* a warninglist hit, business-service context, shared hosting, a scanner
  classification — none is a claim at all, so none reaches a verdict rule;
* an offline URL — `TEMPORAL_RELEVANCE`, which qualifies rather than explains;
* an absence of detections, a provider returning `NO_DATA` — no claim;
* a sandbox that observed no execution — an analysis-quality limitation;
* a low detection count — an aggregate, which corroborates nothing;
* a valid code signature — context, never a directional claim.

Two paths do reach it: a **genuine directional benign assertion** with nothing
malicious standing against it, and **every malicious claim specifically explained**
by an exact-object Task 16 alternative explanation with none left over.

## 8. Conflict

A conflict needs the same subject, the same semantic and the same scope, pointing
opposite ways. A malicious URL that is offline, a malicious address in a cloud
range and a file that contacted a resolver are none of them conflicts — Tasks 15
and 16 already filed those as different questions.

Nothing cancels. There is no balance, no winner and no arithmetic; if real support
survives on the malicious side the verdict is SUSPICIOUS with the disagreement
recorded and confidence capped, and if both sides are weak it is INCONCLUSIVE.

> **A second bug worth recording.** The conflict branch originally filtered opposed
> claims out of the malicious set before running, making its residual-support rule
> unreachable and collapsing every genuine disagreement to INCONCLUSIVE — a real
> malicious claim disappearing because something disagreed with it. Cancellation
> by omission is still cancellation.

## 9. Confidence

Confidence answers **"how confident is TI Recon that this assessment is
correct?"** It does not answer "what are the odds this object is malicious?".

Decided separately from the verdict, from different inputs. `MALICIOUS` at
`MEDIUM` is ordinary when one good source is unopposed but alone; `SUSPICIOUS` at
`MEDIUM` is ordinary when the concern is well established. Nothing reads the
verdict's ordinal.

| Band | Structure |
|---|---|
| `HIGH` | a decisive claim plus a separate origin agreeing |
| `MEDIUM` | one decisive claim unopposed; or multiple independent support; or a complete exact explanation |
| `LOW` | limited or qualified support only |
| `UNSPECIFIED` | nothing was concluded |

`STIX_CONFIDENCE` maps the bands onto the canonical STIX 2.1 values — `15`, `50`,
`85`, or `None`. Nothing computes an integer, and no other value is ever produced:
an assessment reporting 63 would claim a precision nobody measured.

**Caps, not penalties.** An unresolved conflict, an unclassified basis, a partial
source, sandbox divergence or a decision resting on stale context each lower the
band by name. Nothing is subtracted, and stacking caps never reaches a fourth band
— that arithmetic would be the weighted score by another route.

**Caps are scoped to the decision.** This is Task 16's scoping fix, generalised: a
cap requires both a finding carrying the condition *and* that finding linking to a
piece of evidence the verdict's basis actually used. An unrelated stale
warninglist leaves an independent malware-sample assessment alone, and so does a
divergent sandbox detonation of some other object reached on a pivot. A run-level
`any()` over findings is the shape of the original bug and is deliberately not
available in `confidence.py`.

`INCONCLUSIVE` reaches `UNSPECIFIED` by two different rules, kept distinct because
the situations are opposites: `unspecified.no_directional_support.v1` when nothing
was said, and `unspecified.unresolved_conflict.v1` when sources said incompatible
things. Reporting the first for the second would tell an analyst there was no
directional support when there was plenty of it.

## 10. The assessment

`FusionAssessment` is **the authoritative assessment model from Task 17 onward**,
returned inside a `FusionResult`. Task 18 decision readiness, the MCP layer and any
future interface consume that pair and not Task 3's `Assessment`.

It deliberately is **not** Task 3's `Assessment`. That model requires a
`risk_score` this layer must not produce, and `AssessmentContribution` is built on
`base_strength` times multiplicative dampening factors — the arithmetic fusion
model Tasks 15 and 16 spent two tasks refusing. Task 3's shape is left untouched
and retained for backward compatibility, exercised only by its own model tests and
marked legacy in its own docstring; Task 17 reuses its `Verdict` enum, which was
always the right part. A boundary test parses every module under
`reasoning/claims/` and `reasoning/fusion/` and asserts neither imports it, because
that import would be the weighted score returning through a type.

Every assessment carries four policy versions — fusion, claim semantics,
qualification and false-positive reasoning — plus the rule that produced the
verdict and the separate rule that produced the confidence. `as_of` comes from
Task 15 and nothing reads a clock, so a stored assessment stays re-derivable.

`assessment_id` is content-derived from the policy version, target, verdict,
confidence, claim ids, finding ids and `as_of` — sorted, so discovery order cannot
mint two identities for one conclusion.

## 11. What Task 17 does not do

No blocking, containment, ticket closure, alert suppression or remediation. No
re-query of any provider. No network, DNS or socket. No LLM. No mutation of
evidence, graph, qualification or reasoning findings — a test asserts all four are
byte-identical afterwards.

## 12. Worked examples

| # | Inputs | Verdict |
|---|---|---|
| A | exact known malware sample, unexplained | `MALICIOUS` — one decisive claim, no second vote needed |
| B | one generic malicious reputation claim | `SUSPICIOUS` — concern, not conclusion |
| C | only warninglist and shared-infrastructure context | `INCONCLUSIVE` — never `LIKELY_BENIGN` |
| D | exact test artifact, classification specifically explained, nothing left | `LIKELY_BENIGN` — detection retained, explanation retained |
| E | exact malicious URL, currently offline | `MALICIOUS` — current state noted separately |
| F | conflicting independent same-scope claims | `SUSPICIOUS` if real support survives, else `INCONCLUSIVE` — never a vote |
| G | five providers repeating one upstream feed | one independent origin, not five confirmations |
| H | scanner classification and C2 association on one address | different propositions; neither corroborates the other |

See [claim-semantics.md](claim-semantics.md) for the layer beneath this one, and
[false-positive-reasoning.md](false-positive-reasoning.md) for the explanations it
consumes.
