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

Only regular files are accepted — a FIFO or a character device would block the
command indefinitely. The check is against the resolved target, so a symlink to
a real file is followed and a symlink to a pipe is refused. Hashing is streamed,
so a large sample costs constant memory.

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
| `--allow-remote-pivot-lookup` | off | The second half of Task 14's deliberate double gate. Only meaningful with `--pivot enrich`. |
| `--format` | `text` | `json` is the integration contract. |

Neither default is invented here; both are the values the engine already
documents.

### Pivots: three distinct behaviours

`--pivot` and `--allow-remote-pivot-lookup` are two switches because they
authorise two different things — following a lead, and telling a third party
about it.

| Setting | What happens |
| --- | --- |
| `--pivot none` | Related objects are not even ranked. |
| `--pivot recommend` *(default)* | Related objects are graphed and recommended. **Nothing about them leaves the machine.** |
| `--pivot enrich` | Eligible related objects may be enriched — but only through providers that disclose nothing, because the remote gate is still shut. |
| `--pivot enrich --allow-remote-pivot-lookup` | Eligible related objects may be sent to configured external providers. **This discloses observables the analyst did not type, and consumes provider quota.** |

`enrich` on its own is *not* remote enrichment. Everything else is unchanged by
the flag: the same depth buys the same budget, the one-hop limit still holds,
and the privacy rules that refuse private addresses and credential-bearing URLs
still refuse them. It changes who may be asked, and nothing else.

Enabling the flag without `--pivot enrich` is refused rather than ignored —
there would be no pivot enrichment for it to apply to, and accepting it silently
would leave you believing you had authorised something that was never going to
happen.

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

## What the command can reach

`ti-recon` composes **every provider the repository ships**. Which of them can
actually answer depends on what is configured:

```bash
ti-recon providers
```

reports each one's credential group and whether that group has a value — a
boolean, never the value, its length or any part of it. The same catalogue backs
the diagnostic and the investigation, so a provider reported as configured is
genuinely available to the planner.

Credentials come from the environment variable names `.env.example` documents,
loaded into the ordinary per-user credential store:

| Variable | Serves |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Google Threat Intelligence (the `virustotal` group) |
| `ABUSECH_AUTH_KEY` | ThreatFox, URLhaus and MalwareBazaar (one `abuse_ch` group) |
| `URLSCAN_API_KEY` | urlscan.io |
| `GREYNOISE_API_KEY` | GreyNoise |
| `CENSYS_PAT` | Censys (with optional `CENSYS_ORGANIZATION_ID`) |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis |

One secret per *group*, stored once — an analyst with an abuse.ch key does not
enter it three times.

**Nothing is required.** A provider with no credential stays registered and
reports `NOT_CONFIGURED` if the planner selects it, which is what lets Task 18
tell "the analyst has not set this up" from "no such source exists". A fresh
install with no keys still investigates, using the credential-free local dataset
provider, and says exactly which capabilities nobody could serve.

Building the application contacts nothing: adapters create their clients lazily,
and no credential is validated at startup. The first packet leaves when the
planner selects a provider and Task 6 executes it.

## Using the application layer directly

The CLI is one caller. Any other one skips it entirely:

```python
from ti_recon.application import AnalystInvestigationRequest
from ti_recon.application.composition import build_default_application
from ti_recon.cli.runtime import build_local_context

application, credentials = await build_default_application(user_id="analyst-a")
report = await application.investigate(
    AnalystInvestigationRequest(observable="example.com"),
    build_local_context(user_id="analyst-a"),
)
print(report.model_dump_json())
```

`build_default_application` is the whole engine: every shipped provider, the
execution stores, and credential loading. A deployment injects its own secret
store, connection repository or clock through the same function.

This is the seam Task 21's MCP server consumes. It must not parse CLI text.

## What this command does not do

It does not block, quarantine, isolate, allowlist, suppress an alert, close a
ticket or declare an incident. It produces external threat-intelligence analysis
for analyst triage; deciding what to do about it needs organisational context
this engine does not have.
