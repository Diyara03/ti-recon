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
heading. An item may carry `highlights`: the source's own bounded words about
its claim (a sandbox verdict and classification, a Sigma rule title, a MITRE
technique, a named family). Quote them as what that source said. They are
presentation and carry no weight of their own — an item without highlights
weighs exactly the same as one with eight.

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
| `NOT_CONFIGURED` | **Not checked**, because no usable credential is available for this account. | Offline, unreachable, a rejected key, or a source that was asked and found nothing. |
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

## Provider credentials

`NOT_CONFIGURED` says a check did not happen. What to say *next* depends on the
deployment, and the server's own instructions state which one you are connected
to — read them rather than assuming.

**Hosted / remote.** Say the source was not checked because no credential is
available for this account, and stop there. Self-service provider credential
setup is not available in this version. Do not describe local configuration, a
server environment variable, a `.env` file or reconnecting: none of them is
something a hosted caller can do, and suggesting it sends somebody to edit a
server they do not run.

**Local stdio.** Configuration is a genuine local step, read once at server
startup, so a newly added credential appears after a restart or reconnect. The
server's instructions say which step it is: the documented environment
variables for a repository or CLI installation, or the plugin's configuration
(`/plugin`, TI Recon, Configure) when TI Recon runs as the Claude Code plugin —
in which case an environment variable is never the answer, because the plugin's
configuration is the only place the server reads from.

Both, without exception: **no provider API key is ever pasted into a
conversation, a tool argument, a prompt or a header.** No tool accepts one, and
a secret sent that way is in the transcript permanently.

## Your knowledge is not TI Recon's

You may independently know things a report does not contain — that a range is
reserved documentation space, who operates an ASN, what a malware family
typically does. That is useful and allowed, and it is **not evidence TI Recon
collected**.

Label it as yours ("not from TI Recon", "for context, from general knowledge")
and keep it out of the assessment basis, the opposing evidence, the coverage
judgement and the source provenance. It never changes the verdict, the
confidence or the coverage status, and it may never be described as something a
source reported. A reader has to be able to tell which sentences the engine
stands behind.

## Time

`qualifications` carry typed instants with the provider's own field name, so a
scan time is never mistaken for an observation. Ages are exact and unlabelled:
there is no freshness verdict and no decay model, because a phishing URL, a
malware hash and a cloud address do not age alike.

A URL that distributed malware in March and went offline in April **did**
distribute malware and **is** currently inactive. Both are true; report both.
Never promote historical evidence to current activity.

## Sources

`source_checks` records who was asked and what happened. It is provenance, and
it is the **authority** for what was actually consulted: a source with no entry
was not asked, whatever the installation ships and whatever is configured.

### Existing is not the same as asked

A provider passes through several distinct states, and collapsing them produces
a false claim about what was actually queried. Keep them straight even when you
only say one of them out loud:

| State | Means | Where you learn it |
| --- | --- | --- |
| Catalogued | The installation ships this integration. | `provider_status` |
| Configured | A credential is stored for this account. Not that it is valid, entitled, in quota, or healthy. | `provider_status.configured` |
| Considered | The planner could apply it to this observable. | `coverage[].providers_considered` |
| Attempted | Task 13 selected it and Task 6 ran it. | a `source_checks` entry exists |
| Called | A provider was physically contacted. | `called_provider` |
| Served from cache | A real check that reused this caller's earlier result; the source was **not** contacted again. | `cache_hit` |
| Succeeded | It returned a usable result. | `status` |

**Never say a provider was queried, checked or used because it exists.** A
source in the catalogue may be unconfigured, inapplicable to this observable
type, not selected at this depth, served from cache, or never reached. If
`source_checks` has no entry for it, it was not asked — say that, or say nothing
about it.

"Which providers did you use?" is answered from `source_checks`. "Which
providers are available?" is answered from `provider_status`. They are different
questions with different answers, and the second is never evidence for the
first.

**There is no counting anywhere in this engine.** No score, no ratio, no
majority, no "5 of 9 providers". Evidence is weighed by what kind of claim it
is, whose origin produced it, whether two claims are genuinely independent, and
whether anything explains it — never by how many sources agreed. Three datasets
run by one organisation are one origin. If a user asks how many providers said
malicious, explain what contributed rather than producing a tally.
