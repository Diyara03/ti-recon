# The local MCP server (Task 21)

`ti-recon-mcp` exposes the Task 20 application over the Model Context Protocol
so an MCP host — Claude Code, for instance — can investigate an observable and
receive the same analyst report a CLI invocation produces.

It adds capability and no analysis. The verdict is Task 17's, the coverage
judgement is Task 18's, the provider choice is Task 13's, and this layer could
not express an opinion about any of them if it wanted to.

## Local transport is not offline collection

This is the sentence worth reading twice. The *transport* is local: the host
starts the server as a child process and speaks to it over stdin and stdout. No
port is opened and nothing listens.

**The investigation is not local.** When the planner selects a configured remote
provider, the observable is sent to that provider. A local MCP server with
credentials configured discloses exactly what the CLI would.

## Setup

```jsonc
// .mcp.json, or your host's server configuration
{
  "mcpServers": {
    "ti-recon": { "command": "ti-recon-mcp" }
  }
}
```

Credentials are read from the environment variable names `.env.example`
documents, into the per-user credential store — the same mechanism the CLI uses.
There are no credential arguments and no credential tool inputs: a secret in a
tool call would land in a conversation transcript.

**Or install the plugin.** The TI Recon Claude Code plugin (`plugins/ti-recon/`,
see [`claude-plugin.md`](claude-plugin.md)) starts this same server itself and
fills those variables from the plugin's configuration, which Claude Code keeps
in its sensitive plugin storage. It sets `TI_RECON_CREDENTIAL_SETUP=claude-plugin` so the
server describes *that* setup step to a client instead of the environment one;
left unset, the server describes the environment. The variable selects
instruction text only — the tools and credential resolution are identical.

**This is the local deployment model, and it is not the hosted one.** A server
started by an analyst on their own machine reads that machine's environment;
somebody talking to a hosted deployment has no such environment and no process
to restart, and telling them otherwise sends them to configure a server they do
not run. The hosted profile states that difference in its own MCP instructions —
see [`remote-mcp.md`](remote-mcp.md).

Starting the server contacts nothing. Adapters create their clients lazily and no
credential is validated at startup, so a server starts cleanly on a machine with
no keys at all and reports what is missing through `provider_status`.

**Credentials are read once, when the server process starts.** After adding or
changing one, restart or reconnect the server — in Claude Code, `/mcp` and
reconnect — or the new configuration will not appear. `provider_status` and the
investigation tools read the *same* snapshot, so they cannot disagree with each
other: whatever the diagnostic reports is what an investigation will actually
have available.

## Tools

### `investigate_observable`

| Input | Default | Meaning |
| --- | --- | --- |
| `observable` | required | URL, domain, IPv4/IPv6 address, or MD5/SHA-1/SHA-256 hash |
| `observable_type` | `auto` | explicit type only where the input is genuinely ambiguous |
| `depth` | `standard` | `quick` minimal · `standard` normal · `deep` broader, more quota |
| `pivot_mode` | `recommend` | what to do with related observables |
| `allow_remote_pivot_lookup` | `false` | effective only with `enrich` |
| `objective` | `triage` | `triage` stops when coverage is adequate; `corroborate` spends at most one extra round seeking an adverse search from a source family independent of the assessment's basis, if one is eligible and the budget permits |

Returns `AnalystInvestigationReport` as structured output. The output schema is
derived from the Task 20 model, so there is one definition of what a report is.

### `investigate_file`

Takes a `path` to a regular local file. The file is hashed locally with SHA-256
and **the hash is what gets investigated**. The file is never uploaded and never
submitted for detonation; its bytes do not leave the machine. Special files —
pipes, devices — are refused rather than opened, because opening a pipe waits
for a writer and would hang the call.

Reading a file off somebody's disk gets its own consent beat. The tool carries
`anthropic/requiresUserInteraction` in its `_meta`, and **Claude Code 2.1.199+
prompts for human approval on every call — including where an allow rule would
otherwise match it**. That is the case worth protecting: a standing yes to
investigating observables should not quietly become a standing yes to opening
local files. Other MCP clients apply their own permission model and may ignore
the key.

It is defence in depth, never the boundary that matters most. Those are: the
user chooses the file, Task 20 refuses anything that is not a regular file, the
bytes are hashed locally and never sent, and an agent driving this server must
not go looking for files on its own. There is deliberately no `user_confirmed`
argument — a model can set its own arguments, so that would be consent from
nobody.

### `provider_status`

Which sources this installation ships, what they cover, and whether *the caller*
has the configuration each one needs. **Makes no provider requests at all.**

`configured` means one thing: the required credential is stored for that
principal. It does not mean the credential is valid, that authentication would
succeed, that an entitlement covers the operation, or that quota remains — none
of which can be known without contacting somebody, which this tool must never
do. That is why there is no `verified` or `healthy` field.

It is also not a statement about what was *asked*. This diagnostic describes the
installation; which sources an investigation actually consulted is
`source_checks` in the analyst report. "Which sources are available?" and "which
did you use?" are different questions with different answers, and the first is
never evidence for the second.

## The interpretive contract travels with the protocol

An MCP client gets the server `instructions`, each tool's `description` and the
structured `outputSchema` — and, in general, nothing else. It does not get this
document, and it does not get the project Skill: `.claude/skills/` is a
filesystem artifact of this repository, delivered to a Claude Code session
working in this checkout and to nobody who merely connects the server.

So the vocabulary an analyst must not misread lives in those three places:

* the instructions carry the short rules whose loss produces a confidently wrong
  answer — `INCONCLUSIVE` is not clean, `not_configured` is not a failed check,
  confidence is not a probability, coverage is not permission to act,
  `source_checks` is the authority for what was consulted, and a client's own
  knowledge must be labelled as its own;
* the tool descriptions carry disclosure and the setup reality of *this*
  deployment;
* the report's output schema carries the per-field and per-value meanings.

`tests/unit/mcp_server/test_interpretation_contract.py` asserts all of it
against a live protocol session and reads no Skill file, so "correct without the
Skill" is a checked property rather than an intention. See
[`analyst-output.md`](analyst-output.md).

## What the data flow actually is

| Situation | What leaves the machine |
| --- | --- |
| Any investigation | The submitted observable may be sent to configured external providers selected automatically. |
| `pivot_mode=recommend` (default) | Related observables are recorded and shown. **They are not sent anywhere.** |
| `pivot_mode=enrich` | Related observables may be enriched, but only through providers that disclose nothing. |
| `enrich` + `allow_remote_pivot_lookup` | Eligible related observables may also be sent to external providers, and consume quota. |
| `investigate_file` | The SHA-256 only. Never the bytes. |

`enrich` alone is **not** remote enrichment: Task 14 gates that on both switches,
deliberately, because following a lead and telling a third party about it are
different disclosures. Setting the permission without `enrich` is refused rather
than ignored.

## Resources

| URI | Contents |
| --- | --- |
| `ti-recon://schema/request` | JSON Schema for the request |
| `ti-recon://schema/report` | JSON Schema for the analyst report |

Both come from Task 20's own generators. Nothing internal is exposed — not the
investigation result, the planner state, the correlation graph, a provider
payload or any configuration.

## Errors

A failure a caller can fix — an unparseable observable, a path that is not a
regular file, `allow_remote_pivot_lookup` without `enrich` — returns
`is_error=true` with a plain message.

**A provider problem is not a tool failure.** If a source is unconfigured,
throttled, out of quota or broken but the investigation still completes, the call
succeeds and Task 18's coverage records what the failure cost. So does a
`MALICIOUS` verdict, and an `UNRESOLVED` readiness: those are answers, and
reporting them as errors would make a real finding indistinguishable from a
crash.

An unexpected internal failure returns a generic message. The exception type is
logged to stderr and its text is not — a dependency can put a credential or a raw
provider payload in an exception string.

## Result size

An MCP result carries the report twice: `structuredContent` for a program, and a
JSON text block for clients that predate structured output. The MCP
specification asks for both, and the SDK builds them together — so the text is
not a second rendering this server produced, and removing it would break a
spec-compliant client.

Measured on the wire, with the whole report in both halves:

| Result | structured | text | total |
| --- | --- | --- | --- |
| A typical investigation | ~4 KB | ~5 KB | ~9 KB |
| An investigation with nothing configured | ~6 KB | ~8 KB | ~14 KB |
| A report saturating every bound | ~10 KB | ~15 KB | ~25 KB |
| `provider_status` | ~3 KB | ~5 KB | ~8 KB |

Even the saturated case stays well inside a host's usual output budget, so
Task 20's bounds are left exactly as they are. The schema resources are larger
(~38 KB for the report schema) and are fetched only when a client asks for them
— they are never embedded in a tool result.

## Streams

stdout carries the MCP protocol and nothing else. Every diagnostic goes to
stderr; `TI_RECON_LOG_LEVEL` sets the level, defaulting to `WARNING`.

## Not in this task

No HTTP transport, no multi-user deployment, no persistence, and no active
provider operation — nothing submits, detonates, rescans or downloads a sample.
Provider selection stays with Task 13 and cannot be influenced from a tool call.

Task 22 added the authenticated remote surface — see
[remote-mcp.md](remote-mcp.md) — as an optional path. The primary usage model is
this local server, per analyst, distributed through the Claude Code plugin
described in [claude-plugin.md](claude-plugin.md).

## The host's instruction budget

Claude Code 2.1.259 truncates a server's `instructions` to 2048 characters and
says so only at debug level. Each profile's deployment-specific sentence is the
last thing in its instructions, so every profile has to fit whole; a test holds
each one under the limit.
