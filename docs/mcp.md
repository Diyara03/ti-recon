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

Starting the server contacts nothing. Adapters create their clients lazily and no
credential is validated at startup, so a server starts cleanly on a machine with
no keys at all and reports what is missing through `provider_status`.

## Tools

### `investigate_observable`

| Input | Default | Meaning |
| --- | --- | --- |
| `observable` | required | URL, domain, IPv4/IPv6 address, or MD5/SHA-1/SHA-256 hash |
| `observable_type` | `auto` | explicit type only where the input is genuinely ambiguous |
| `depth` | `standard` | `quick` minimal · `standard` normal · `deep` broader, more quota |
| `pivot_mode` | `recommend` | what to do with related observables |
| `allow_remote_pivot_lookup` | `false` | effective only with `enrich` |

Returns `AnalystInvestigationReport` as structured output. The output schema is
derived from the Task 20 model, so there is one definition of what a report is.

### `investigate_file`

Takes a `path` to a regular local file. The file is hashed locally with SHA-256
and **the hash is what gets investigated**. The file is never uploaded and never
submitted for detonation; its bytes do not leave the machine. Special files —
pipes, devices — are refused rather than opened, because opening a pipe waits
for a writer and would hang the call.

### `provider_status`

Which sources this installation can use, what they cover, and whether their
credentials were present at startup. **Makes no provider requests at all.**

`configured` means one thing: the required configuration was present when the
server was assembled. It does not mean the credential is valid, that
authentication would succeed, or that quota remains — none of which can be known
without contacting somebody, which this tool must never do. That is why there is
no `verified` or `healthy` field.

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

## Streams

stdout carries the MCP protocol and nothing else. Every diagnostic goes to
stderr; `TI_RECON_LOG_LEVEL` sets the level, defaulting to `WARNING`.

## Not in this task

No HTTP transport, no OAuth, no multi-user deployment, no persistence, and no
active provider operation — nothing submits, detonates, rescans or downloads a
sample. Provider selection stays with Task 13 and cannot be influenced from a
tool call.
