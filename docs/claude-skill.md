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

## It is not delivered with the MCP server

This matters more than anything else on this page.

A Skill is a filesystem artifact of *this repository*. A Claude Code session
working in this checkout picks it up; **an ordinary client that merely connects
the TI Recon MCP server does not**. Claude Web with the hosted connector, another
MCP host, a future integration — all of them get the server's `instructions`, the
tool descriptions and the report's output schema, and none of them gets a line of
this Skill. Skills and MCP are separate delivery layers, and a future plugin
bundling a connector with a Skill would be a convenience rather than the
dependency model.

So the rule is:

> **No essential semantic rule may live only in the Skill.** If deleting
> `.claude/skills/ti-recon-analyst/` would make MCP-only interpretation wrong or
> ambiguous, the MCP contract is incomplete and that is the bug.

Everything an analyst must not misread — what each verdict claims, that
`INCONCLUSIVE` is not clean, that `not_configured` is a check that never ran,
that a cache hit made no request, that `configured` is not `validated`, that
confidence is not a probability, that coverage is not permission to act, that
`source_checks` is the authority on what was consulted, that a related observable
is not an indicator, that a client's own knowledge is not TI Recon evidence, and
that hosted callers have no self-service credential setup — is carried by the MCP
contract itself. `tests/unit/mcp_server/test_interpretation_contract.py` asserts
that against a live protocol session and opens no Skill file.

What the Skill adds is real and is all of the second kind: response structure,
progressive disclosure, when to re-run versus re-read, depth and pivot judgement,
the false-positive workflow, and worked cases for the shapes that are easy to
summarise wrongly. It reinforces the semantics and does not own them — and where
it and the server contract could ever disagree, the server contract wins.

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

## How it is distributed

The Skill is a **project** asset: a user gets it by working in this repository.
It is tracked source, so it ships inside the sdist — but **installing the Python
wheel does not install it**. The wheel carries the MCP server and the CLI;
`.claude/skills/` is not Python and pip puts nothing where Claude Code looks.

To use it across all your projects, copy it into your personal skills directory:

```bash
cp -r .claude/skills/ti-recon-analyst ~/.claude/skills/
```

That is your choice to make, not something this project does to your home
directory.

The MCP registration made during development is **local scope** — this project
only, private to that machine. `--scope user` makes it available in every
project; it is not the default here, deliberately. Credentials never belong in
an MCP registration command: they stay TI Recon runtime configuration.

## What it will not decide

Blocking, quarantine, isolation, allowlisting, alert closure, incident
declaration. Asked "should I block it?", the Skill gives the assessment and
explains that the response decision needs internal telemetry, asset context and
policy — it answers the question rather than dodging it.
