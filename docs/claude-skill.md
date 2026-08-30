# The TI Recon analyst Skill (Task 21)

A Claude Code Skill that teaches Claude how to drive the TI Recon MCP server and
how to read what it returns. It lives at:

```
.claude/skills/ti-recon-analyst/
    SKILL.md
    references/
        interpretation.md    what each report field means
        response-style.md    how much to show, and in what order
        examples.md          worked cases for the shapes easy to get wrong
```

It is instructions only — no scripts, no assets. `SKILL.md` is a compact control
plane; the references load when Claude needs them.

## What it does and does not do

The Skill **presents** TI Recon's answer. It never recomputes one. The verdict,
the confidence, the coverage judgement and the choice of sources are all decided
by Tasks 13–19 and reach the Skill through the Task 20 report.

It drives the three MCP tools. It never shells out to the `ti-recon` CLI, never
calls a provider API, and cannot ask for a particular provider — Task 13 ranks
sources, and a Skill choosing one would make results depend on who was asking.

## Using it

It activates on its own for a real investigation request:

```
Investigate this suspicious URL: https://example.invalid/path
Is this hash malicious? 44d88612fea8a8f36de82e1278abb02f
Could this detection be a false positive?
```

Or invoke it directly:

```
/ti-recon-analyst example.com
/ti-recon-analyst            # no target: shows a short capability guide
```

It deliberately does **not** trigger on general security questions — "what is
SHA-256", "explain VirusTotal", "write a URL parser" — which are answered
normally.

Requires the MCP server to be connected. Without it the Skill says so and stops
rather than substituting its own assessment.

## Defaults

`Standard` depth, related observables `Recommend`ed, external pivot lookup off.
No setup questions.

| Ask for | Get |
| --- | --- |
| "quick check" | Quick — smaller collection scope, not less accurate |
| anything ordinary | Standard |
| "thoroughly investigate" | Deep — more collection, more provider quota |

A suspicious result never escalates depth by itself. That is the user's call.

## More detail versus broader collection

The distinction the Skill treats as first-class, because the two have very
different costs.

**More detail** — the evidence, opposing evidence, alternative explanations,
source checks, coverage gaps, related observables, technical ids, raw JSON. All
of it is already in the report, and **none of it causes a new lookup**. Asking
"explain this thoroughly" re-reads the result; it does not re-run it.

**Broader collection** — Deep, pivot enrichment, external pivot enrichment.
These contact providers and spend quota.

An ambiguous "give me more data" gets one clarifying question rather than a
guess.

## Related infrastructure and disclosure

| Mode | What leaves the machine |
| --- | --- |
| Recommend *(default)* | nothing about the related observables |
| Enrich | nothing — enrichment uses sources that disclose nothing |
| Enrich + external pivot lookup | eligible related observables go to external providers |

The external permission is set only on unambiguous intent. "Show me the related
infrastructure" is Recommend; a bare "enrich it" is Enrich without external
disclosure, and the Skill says the external option exists rather than taking it.

## Local files

`investigate_file` runs only for a file the user supplied, attached or named.
The Skill will not browse directories, enumerate files, read `.env`, or choose a
file itself — "check my machine" gets a request for a specific path.

The file is hashed locally with SHA-256 and the hash is investigated. **The file
is never uploaded and never submitted for detonation.** Claude Code additionally
prompts for human approval on every call, overriding any allow rule.

## How results are worded

Leads with `Assessment · Confidence · TI coverage` in human case, then what that
combination means, then why — from the assessment basis alone. Opposing
evidence, alternative explanations, gaps and related activity appear only when
material.

Three wordings are load-bearing:

- **Confidence** is confidence the assessment is correct — never a probability
  of maliciousness. The STIX integer appears only on request, with that caveat.
- **TI coverage**, not bare "readiness": `READY` never means ready to block,
  ready to close, or safe.
- **`NO_DATA`** means checked and nothing applicable found — never clean or
  benign. `NOT_CONFIGURED` means a credential is not set up locally, not that a
  provider is offline.

Related observables are relationships, not indicators. Sources are provenance,
never votes — the Skill will not produce a "3 of 9 providers" tally, because the
engine does not decide that way.

## Configuration

`provider_status` shows which sources are set up. `configured` means the
credential was present when the server started — **not** that it is valid,
authenticated or healthy.

The Skill never asks anyone to paste a key into the conversation. When a source
is missing it points at the local configuration and notes that the MCP server
must be reconnected afterwards, because configuration is read at startup.

## What it will not decide

Blocking, quarantine, isolation, allowlisting, alert closure, incident
declaration. Asked "should I block it?", the Skill gives the assessment and
explains that the response decision needs internal telemetry, asset context and
policy — it answers the question rather than dodging it.
