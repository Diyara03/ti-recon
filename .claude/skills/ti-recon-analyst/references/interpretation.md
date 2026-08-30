# What the report actually says

Precise meanings for the fields of an `AnalystInvestigationReport`. Consult this
when a value's meaning matters and you are not certain of it. Every definition
here is the engine's; none of it is yours to adjust.

## Three separate answers

An analyst reading a result needs to keep these apart, because they answer
different questions and any of the nine combinations is coherent.

**Verdict** — what the external intelligence supports about the observable.

**Confidence** — whether *this assessment* is correct. Not how bad the thing is,
not how likely it is to be malicious, not severity, not risk. `MALICIOUS` at
`MEDIUM` is an ordinary result, not a hedge.

**TI coverage** (`readiness` in the JSON) — whether the *collection behind the
assessment* was adequate for analyst triage. A correct assessment and an
incomplete search are simultaneously possible, and saying so is the point.

## Verdicts

| Value | Say |
| --- | --- |
| `MALICIOUS` | The available evidence supports a malicious assessment. |
| `SUSPICIOUS` | There is meaningful malicious evidence, but it does not meet TI Recon's policy for a malicious verdict. |
| `LIKELY_BENIGN` | The available evidence supports a likely-benign assessment. Not a guarantee of safety and not an allowlist decision. |
| `INCONCLUSIVE` | The available external intelligence does not support a directional conclusion either way. |

Never soften or strengthen the verdict in the retelling. `SUSPICIOUS` is not
"probably malicious" and `LIKELY_BENIGN` is not "clean".

## Confidence

`unspecified`, `low`, `medium`, `high`. Show the band.

`confidence_stix` carries the canonical STIX integer — 15, 50, 85 — for
consumers that need one. Give it only when asked for technical detail, and say
what it is: confidence that the assessment is correct, **not** the probability
that the observable is malicious. There is no calibration behind any such
number, which is why the engine refuses to produce one.

`confidence_caps` names the reasons the band was held down. Those are the honest
answer to "why is confidence low" — not missing provider coverage, unless a cap
says so.

## TI coverage

| Value | Say |
| --- | --- |
| `READY` | No material external-TI gap remains for triage. |
| `READY_WITH_LIMITATIONS` | Sufficient for this triage assessment; non-material caveats remain. |
| `NEEDS_MORE_DATA` | A material gap remains and further permitted enrichment could still help. |
| `UNRESOLVED` | A material gap remains that the current external-TI path cannot resolve. |

None of these is a response decision. `READY` does not mean ready to block,
ready to close, or safe.

## Evidence sections

**`assessment_basis`** — the claims the verdict rested on, with the role the
engine gave each. This is "why", and the only thing that belongs under that
heading.

**`opposing_evidence`** — claims that pushed the other way and did not prevail.
Real, and shown separately. Putting them under "why" would read as though a
benign assertion were a reason the object was called malicious.

**`unexplained_evidence`** — directional claims no alternative explanation
accounted for. Relevant when the user asks whether a detection could be wrong.

**`conflicts`** — sources disagreeing about the same proposition. Preserved, not
resolved. Nothing balances or picks a winner.

**`alternative_explanations`** — a Task 16 finding that legitimately accounts
for a specific detection, with `explains_evidence_ids` naming exactly which. Say
what was explained and check what remains. One explained detection is not a
false-positive case; the case is false-positive only if the final assessment
says so. `does_not_establish` records what the explanation explicitly does not
prove — worth quoting when a user over-reads it.

## Coverage vocabulary

Each check carries a completion *and* a yield, and they answer different things.

| Value | Means | Never means |
| --- | --- | --- |
| `NO_DATA` | The source was consulted and held nothing applicable. | Clean, safe, benign, trusted. It is equally true of every threat nobody has caught yet. |
| `NOT_ATTEMPTED` | Nobody asked. | The same as `NO_DATA`. |
| `UNATTRIBUTED` | One call answered several capabilities and the record cannot say which returned what. | `NO_DATA`, absence, or benign evidence. |
| `NOT_CONFIGURED` | Not checked, because its credential is not set up locally. | Offline, unreachable, or a rejected key. |
| `PARTIAL` | Something was learned, short of the whole check. | A failure. |

## Related observables

Things a source connected to the root: a contacted host, a resolved address, a
dropped file. **A relationship is not an accusation.** `assessed` says whether
the engine separately reached a verdict about that object; where it did not,
none is implied, and calling it an IOC is how a public resolver ends up on a
blocklist.

`observation_basis` keeps two different kinds of knowledge apart:

- `provider_observed` — a source watched it happen.
- `provider_reported` — a source said so.

Neither says anything about maliciousness. Preserve the distinction where it
matters and never flatten "observed contact" into "malicious connection".

## Time

`qualifications` carry typed instants with the provider's own field name, so a
scan time is never mistaken for an observation. Ages are exact and unlabelled:
there is no freshness verdict and no decay model, because a phishing URL, a
malware hash and a cloud address do not age alike.

A URL that distributed malware in March and went offline in April **did**
distribute malware and **is** currently inactive. Both are true; report both.
Never promote historical evidence to current activity.

## Sources

`source_checks` records who was asked and what happened. It is provenance.

**There is no counting anywhere in this engine.** No score, no ratio, no
majority, no "5 of 9 providers". Evidence is weighed by what kind of claim it
is, whose origin produced it, whether two claims are genuinely independent, and
whether anything explains it — never by how many sources agreed. Three datasets
run by one organisation are one origin. If a user asks how many providers said
malicious, explain what contributed rather than producing a tally.
