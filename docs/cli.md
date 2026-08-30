# The `ti-recon` command (Task 20)

A thin shell over the application service. Everything it does is reachable
programmatically without a terminal — which is what lets a future MCP server
consume the same contract instead of parsing this output.

## Commands

```bash
ti-recon investigate <observable> [--type ...] [--depth ...] [--pivot ...] [--format text|json]
ti-recon investigate --file ./sample.bin
ti-recon schema report
ti-recon schema request
ti-recon providers
ti-recon --version
```

### `investigate`

Takes an address, domain, URL or file hash. `--type auto` (the default) uses the
engine's own detection, which is ordered — hash, then URL, then address, then
domain — and refuses what it cannot place rather than guessing. A bare domain is
never promoted to a URL.

`--file` hashes a local file and investigates the digest. **The file is read and
hashed on your machine and its contents are never sent anywhere.** There is no
upload, no submission and no detonation: a hash lookup asks "has anybody seen
this exact sample?", which the owner of a sample can ask without handing the
sample to anybody.

### `schema`

Prints a JSON Schema (Draft 2020-12, read from Pydantic rather than asserted)
for the report or the request. Local: contacts nothing and reads no credential.
This is the document a tool consumer integrates against.

### `providers`

A local diagnostic listing what is registered and whether a provider *requires*
a credential. It never prints a credential, its length, or any part of its value,
and it contacts nothing.

## Defaults

| Option | Default | Why |
| --- | --- | --- |
| `--depth` | `standard` | The engine's own default. Not `deep`: deeper spends more of somebody's quota, and asking for it is the caller's decision. |
| `--pivot` | `recommend` | Task 14's own default. Related objects are recorded and **not** queried, because looking up something the observable merely touched is a wider disclosure than looking up what the analyst typed. |
| `--format` | `text` | `json` is the integration contract. |

Neither default is invented here; both are the values the engine already
documents.

## Streams

**In `--format json`, stdout carries exactly one JSON document and nothing
else.** Every log line, warning and diagnostic goes to stderr. A single stray
line on stdout would make the output unparseable for the automation the format
exists to serve.

```bash
ti-recon investigate example.com --format json | jq .assessment
```

## Exit codes

The exit status reports whether the **command** ran. It never encodes the
verdict: a `MALICIOUS` result returning nonzero would be indistinguishable from a
crash to every shell that checks `&&`.

| Code | Meaning |
| --- | --- |
| `0` | The investigation completed — whatever it found, including `INCONCLUSIVE` and an `UNRESOLVED` readiness. |
| `1` | Operational failure: broken configuration, structural fault, unexpected error. |
| `2` | The command line was wrong, including an observable the engine cannot parse. |
| `130` | Interrupted. |

An interrupted run prints no report and no traceback: the caller went away, and a
partial result would present an investigation that never finished.

## Credentials

**There are no credential flags.** Not `--api-key`, not `--token`. A secret on a
command line lands in shell history and in the process list, where anyone on the
machine can read it.

Credentials are resolved per user by the credential layer, which is where they
already live. Configuring them is a deployment concern and is unchanged by this
task.

## What the local command can reach

Out of the box, `ti-recon` composes only the providers that need neither a
credential nor a network client — the local dataset provider that answers from a
snapshot inside the package. So a fresh install does something honest and
discloses nothing to anybody.

Remote providers need an HTTP client, a base URL and a resolved per-user
credential. That is deployment configuration: a deployment builds its own
registry and executor and injects the orchestrator, and nothing in the
application layer changes. Until it does, coverage says exactly which
capabilities nobody could serve — which is the honest answer, not a hidden one.

## Using the application layer directly

The CLI is one caller. Any other one skips it entirely:

```python
from ti_recon.application import AnalystInvestigationRequest, InvestigationApplication
from ti_recon.cli.runtime import build_local_context, build_local_runtime

application = InvestigationApplication(orchestrator=build_local_runtime())
report = await application.investigate(
    AnalystInvestigationRequest(observable="example.com"),
    build_local_context(),
)
print(report.model_dump_json())
```

This is the seam Task 21's MCP server consumes. It must not parse CLI text.

## What this command does not do

It does not block, quarantine, isolate, allowlist, suppress an alert, close a
ticket or declare an incident. It produces external threat-intelligence analysis
for analyst triage; deciding what to do about it needs organisational context
this engine does not have.
