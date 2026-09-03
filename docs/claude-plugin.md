# The TI Recon Claude Code plugin (Task 23, Phase 1)

TI Recon's primary internal usage model is local and per analyst:

```
Claude Enterprise
    -> Claude Code on each analyst workstation
    -> the TI Recon plugin (this document)
    -> the local stdio ti-recon-mcp server
    -> the analyst's own TI-provider credentials
```

There is **no shared deployment** in this model. Nothing is hosted, nothing
listens, no identity provider is contacted, and every provider credential
belongs to the analyst whose workstation it is on. The authenticated remote MCP
surface from Task 22 (`docs/remote-mcp.md`) stays intact as an optional path;
nothing here depends on it and nothing here changes it.

## Where this stands

Two things are deliberately kept apart on this page.

| | State |
| --- | --- |
| **Current phase** | a *developer proof* plugin: the committed plugin under `plugins/ti-recon/` validates, loads, carries the Skill and declares the MCP server and its configuration — but bundles **no runtime**. Its launcher fails closed. A generated, clearly marked developer copy runs this checkout's own virtual environment so the host mechanics could be proved against the real server. |
| **Target** | an *analyst-installable* plugin: install from an internal marketplace, enter whichever provider credentials you have, start Claude Code anywhere, ask. No checkout, no virtual environment, no `uv sync`, no `.mcp.json`, no `claude mcp add`, no copied Skill, no `.env`, no key in a prompt. |

One-click distribution is **not** complete. Phase 1 proves the host mechanics
and settles the design; runtime packaging and the marketplace are later phases.

## The verified host

Everything below was verified against the installed host, not assumed from
older plugin documentation.

| | |
| --- | --- |
| Claude Code | **2.1.259** (Linux x86-64) |
| Manifest | `.claude-plugin/plugin.json`; `name` is the namespace, `version` pins updates |
| Components | `skills/` and `.mcp.json` at the plugin root are discovered by default; nothing lives inside `.claude-plugin/` except the manifest |
| `userConfig` | `type` / `title` / `description` / `sensitive` / `required` / `default`; prompted at enable time |
| `sensitive: true` | value stored in the host's secure storage (keychain, or `~/.claude/.credentials.json` as fallback) rather than `settings.json`; **~2 KB total, shared with OAuth tokens** |
| `${user_config.KEY}` | substituted into MCP server `env`, `args`, `command`, `headers`; into Skill content only for **non-sensitive** options (the host refuses sensitive ones there) |
| Unset option | substitutes to the **empty string** in MCP `env` — not a literal placeholder, and the server still starts *(measured with a throwaway probe plugin)* |
| `CLAUDE_PLUGIN_OPTION_<KEY>` | exported to **hook** processes only; **not** to MCP server subprocesses *(measured)* |
| `${CLAUDE_PLUGIN_ROOT}` | the plugin's installation directory, exported to the MCP subprocess *(measured)* |
| `${CLAUDE_PLUGIN_DATA}` | `~/.claude/plugins/data/<plugin>-<marketplace>/`, persistent across updates, exported to the MCP subprocess *(measured: `ti-recon-inline` for a sideloaded plugin)* |
| Sideloaded plugin id | `<name>@inline`; its user configuration is read from `pluginConfigs["<name>@inline"].options` |
| Config sources | user `settings.json`, the `--settings` flag, managed settings; project settings are ignored for `pluginConfigs` |
| Validation | `claude plugin validate [--strict] [--json] <path>` |
| Inventory | `claude --plugin-dir <path> plugin details <name>` |
| Loading | `--plugin-dir <path>`; `/reload-plugins` restarts an MCP server only when its config changed |
| MCP lifecycle | plugin servers start with the session and are keyed `plugin:<plugin>:<server>`; tools are `mcp__plugin_<plugin>_<server>__<tool>` |
| Cache | installed versions are copied to `~/.claude/plugins/cache/`, one directory per version |
| Instruction budget | server `instructions` are **truncated to 2048 characters**, logged only at debug level |

That last row was a finding rather than a lookup. Every TI Recon profile put
its deployment-specific sentence *last*, and every profile was over the limit
by roughly that sentence — so in Claude Code the plugin, stdio and hosted
setup advice were all being cut off (`Server instructions truncated from 2628
to 2048 chars` in the MCP debug log of the first proof run). The profiles were
shortened to fit, a test holds each complete profile under the limit, and the
proof was re-run: the server connects with no truncation logged.

## The plugin

```
plugins/ti-recon/
    .claude-plugin/
        plugin.json          name, version, userConfig
    .mcp.json                the one stdio server, started from the launcher
    bin/
        ti-recon-mcp         POSIX sh launcher; fails closed until a runtime is bundled
    skills/
        ti-recon-analyst/    byte-identical copy of .claude/skills/ti-recon-analyst
            SKILL.md
            references/
                interpretation.md
                response-style.md
                examples.md
    README.md
```

No agent, no hook, no command, no output style. The plugin bundles the two
things the usage model needs — the MCP integration and the Skill — and nothing
the plugin system merely permits.

### `.mcp.json`

One server, named `ti-recon`, started from `${CLAUDE_PLUGIN_ROOT}/bin/ti-recon-mcp`
with an environment the host assembles from the plugin's configuration:

| Plugin option | Environment variable | Credential group | Adapters |
| --- | --- | --- | --- |
| `virustotal_api_key` *(sensitive)* | `VIRUSTOTAL_API_KEY` | `virustotal` | `gti` |
| `abusech_auth_key` *(sensitive)* | `ABUSECH_AUTH_KEY` | `abuse_ch` | `threatfox`, `urlhaus`, `malwarebazaar` |
| `urlscan_api_key` *(sensitive)* | `URLSCAN_API_KEY` | `urlscan` | `urlscan` |
| `greynoise_api_key` *(sensitive)* | `GREYNOISE_API_KEY` | `greynoise` | `greynoise` |
| `censys_pat` *(sensitive)* | `CENSYS_PAT` | `censys` | `censys` |
| `hybrid_analysis_api_key` *(sensitive)* | `HYBRID_ANALYSIS_API_KEY` | `hybrid_analysis` | `hybrid_analysis` |
| `censys_organization_id` | `CENSYS_ORGANIZATION_ID` | `censys` (connection metadata) | `censys` |
| — | `TI_RECON_CREDENTIAL_SETUP=claude-plugin` | — | selects instruction text only |

The variable names are the ones `.env.example` already documents and
`CREDENTIAL_ENVIRONMENT` in `application/composition.py` already reads. The
mapping is **by credential group**, which is the repository's own model: one
abuse.ch Auth-Key is asked for once and serves three adapters, one VirusTotal
key serves GTI, and nothing asks for a provider-specific duplicate. A test
derives the groups from the shipped adapters and checks the manifest against
them, so a new credentialled provider fails the suite until the plugin offers
an option for it.

`misp_warninglists` needs no credential and has no option.

**Every credential is optional.** An analyst with only a GTI key, or with no
remote key at all, gets a server that starts, a `provider_status` that reports
the rest `not_configured`, and investigations whose coverage records exactly
that. No option is `required`, none has a `default`, and the one non-secret
option (`censys_organization_id`) is not marked sensitive, because secure
storage is a shared budget.

### The launcher

`bin/ti-recon-mcp` is a POSIX `sh` script that execs
`${CLAUDE_PLUGIN_ROOT}/runtime/bin/ti-recon-mcp` if it exists and otherwise
writes one line to stderr and exits 1. Nothing on stdout, ever — that stream is
the MCP protocol. There is no environment override, no `PATH` search, no
development mode and no second location: the plugin root decides, and a test
reads the script to keep it that way.

`runtime/` is the seam a bundled runtime would occupy. Nothing is bundled yet.

### The credential-setup profile

The server already read credentials from its environment once at startup. What
the plugin changed is *who puts them there*, and therefore what an analyst has
to do to add one — which the server has to state accurately, because a client
left without a statement supplies the model it already knows and tells a plugin
user to export a shell variable the plugin's mapping will overwrite with an
empty string.

So `.mcp.json` sets `TI_RECON_CREDENTIAL_SETUP=claude-plugin`, and the stdio
entry point selects `LocalCredentialSetup.CLAUDE_PLUGIN`: the same three tools,
the same resolution, and instructions plus a `provider_status` description that
say a credential is entered in the plugin's configuration (`/plugin`, TI Recon,
Configure), stored by Claude Code, and read at startup. Unset, the profile is
`environment`, which is what a checkout, the CLI or a hand-written `.mcp.json`
gets — and it is unchanged. An unrecognised value refuses to start, on stderr,
before the transport opens.

The value reaches nothing below `mcp_server/`. A test asserts no other package
mentions it.

## Secrets never enter model context

This is the invariant the plugin exists to keep, stated as the path a value
takes:

```
plugin configuration UI (/plugin -> Configure)
    -> Claude Code secure storage            (sensitive: true)
    -> ${user_config.KEY} substituted into .mcp.json env
    -> the ti-recon-mcp process environment, read once at startup
    -> load_environment_credentials -> CredentialManager -> the per-user store
    -> CredentialResolver, at request time, for the selected provider only
    -> the transport's _apply_auth, into one header
```

and, just as precisely, the places it never goes:

| Never | Why it cannot |
| --- | --- |
| Skill content | the host refuses to substitute a sensitive option into a Skill, and the Skill contains no `${user_config.*}` reference at all (tested) |
| the Claude prompt, a tool argument | no tool accepts a credential; the input schemas are asserted credential-free |
| MCP `instructions` and tool descriptions | fixed text; a test drives a live session with sentinel credentials and searches every listing |
| the report, JSON or text | `SecretStr` end to end; the same sentinel search covers `provider_status`, and the existing runtime tests cover investigation reports |
| logs, stderr, diagnostics | logging carries provider, group and status, never a value; the out-of-process proof captures the server's stderr at `DEBUG` and searches it |
| exception messages | the tools convert unexpected failures to a fixed message and log the type alone |

**Inspected, not just asserted.** `load_environment_credentials` logs at INFO
with `provider` and `credential_group` only; `CredentialManager` and
`CredentialResolver` log names and groups, never material; the transport logs an
allow-list that excludes headers, bodies and query strings; and the entry
point's one new stderr message names a variable and its accepted values without
echoing what was set.

### The proof

Two layers, both with fake sentinel values and no provider contacted:

* **Deterministic tests** (`tests/unit/plugin/test_credential_path.py`) build
  the environment exactly as the host does — set options substituted, unset
  ones empty — and drive it through the real composition: the sentinel comes
  back from `CredentialResolver.resolve` for `gti`, the omitted `urlscan` raises
  `CredentialNotConfigured`, no empty secret is stored, the Censys organization
  id lands in connection metadata, and `provider_status` over a live in-process
  MCP session reports `configured` per group. Then the *installed entry point*
  is started as a subprocess with that environment and driven over stdio, its
  stderr captured at `DEBUG`; the tool list, the file tool's
  `anthropic/requiresUserInteraction` metadata, the profile and the
  `configured` flags are asserted, and every surface is searched for the
  sentinels.
* **The real host** (`claude` 2.1.259, run from outside the repository so no
  project Skill was in scope), against the generated developer copy:

  | Step | Result |
  | --- | --- |
  | `claude plugin validate --strict plugins/ti-recon` | passed |
  | `claude --plugin-dir … plugin details ti-recon` | 1 Skill (`ti-recon-analyst`), 1 MCP server (`ti-recon`), ~229 always-on tokens |
  | `claude --plugin-dir … mcp list` | `plugin:ti-recon:ti-recon … ✔ Connected` |
  | `-p` session, sentinel VirusTotal key and Censys PAT + organization id supplied through `pluginConfigs["ti-recon@inline"].options` | `provider_status`: `gti=true censys=true misp_warninglists=true`, every other source `false`; tools reported `investigate_file investigate_observable provider_status` |
  | sentinel search over the JSON result, the MCP debug log and stderr | 0 occurrences in each |
  | `-p "/ti-recon:ti-recon-analyst"` with no target | the Skill's capability guide, **zero** tool calls, loaded as the plugin's one Skill |
  | remote path | `--debug mcp` shows one stdio server and no HTTP transport, no OAuth, no JWKS fetch |

  The sentinel investigation was never run: with a fake key configured, an
  investigation would have made a live request and been refused with a 401.
  `provider_status` contacts nothing, and it is what reports whether a
  credential is stored.

The host also reported the server's startup: **11–12 s** from process start
to `initialize` on this machine, consistently across runs. That is a runtime-packaging fact (import time of
the dependency closure plus the MISP snapshot), not a plugin one, and it is
recorded for the next phase.

## Sensitive-storage footprint

Claude Code's secure storage is documented as roughly 2 KB in total, shared
with the host's own OAuth tokens. The plugin declares **six** sensitive options.

The repository documents no credential *formats*: no adapter constrains a key's
length, and the provider docs describe headers, not shapes. So the estimate
below uses stated assumptions, not measured keys, and the calculation contains
no real credential.

| Option | Assumed maximum value length |
| --- | --- |
| VirusTotal API key | 64 |
| urlscan.io API key | 36 (UUID) |
| GreyNoise API key | 64 |
| Censys PAT | 128 |
| abuse.ch Auth-Key | 36 (UUID) |
| Hybrid Analysis API key | 64 |
| **values** | **~392 bytes** |
| storage overhead (option keys, quoting, structure) | ~250 bytes |
| **plugin total, all six set** | **~650 bytes** |

Under those assumptions the plugin uses about a third of the budget, and an
analyst with one or two keys uses far less. **What the repository cannot
establish** is the other half of the sum: how much of the budget the host's
OAuth tokens already occupy on an Enterprise-authenticated workstation, and
whether the limit is enforced by the platform's credential store (a Windows
credential blob, for instance, is capped at 2560 bytes) or by the host. If a
provider issued keys near 256 characters the six would reach ~1.8 KB and the
combined total would fail.

**Design constraint, reported rather than resolved:** `userConfig` is the right
mechanism for Phase 1 and for any rollout where the measured OAuth footprint
leaves ~1 KB free. Before an Enterprise rollout, measure the secure-storage
footprint on a real, authenticated Windows and macOS workstation with real key
lengths. If it does not fit, the fallback that keeps every other property of
this design is a `file`-typed non-sensitive option naming an analyst-owned
credential file the launcher reads — still per analyst, still outside model
context, but outside the host's secure storage.

## The Skill has one source

The repository's project Skill, `.claude/skills/ti-recon-analyst/`, stays
canonical: its tests, its documentation and its history live there, and a
session working in this checkout keeps using it. The plugin carries a
**byte-identical copy** at `plugins/ti-recon/skills/ti-recon-analyst/`, because
the plugin cache copies the plugin directory and cannot follow a symlink — and
a symlink would not survive a checkout on a platform without them either.

Options considered:

* **A. plugin copy canonical, project copy generated** — inverts the ownership
  of a file every test and document already points at, for no gain.
* **B. repository copy canonical, deterministic copy into the plugin, drift
  fails the suite** — chosen.
* **C. one copy only** — would mean removing the project Skill and loading the
  plugin during development through a repository-local marketplace; that is the
  marketplace work of a later phase and changes the developer workflow.

`tools/sync_plugin_skill.py --check` reports drift and `--write` repairs it; a
test runs the same comparison, so an edit to either copy without the other fails
the suite. Nothing is transformed on the way.

The Skill's own wording was adjusted, in the canonical copy, so the local
setup advice names both local shapes and defers to the server's instructions
for which applies.

## Runtime distribution — the Phase 1 decision

The plugin must not depend on this checkout, `~/ti-recon`, `.venv`, an editable
install or a developer's `PYTHONPATH`. Claude Code copies the plugin into its
cache, so whatever runs must be reachable from `${CLAUDE_PLUGIN_ROOT}` or
`${CLAUDE_PLUGIN_DATA}` and survive a change of either path.

Measured on this checkout: the runtime dependency closure is **42
distributions, ~40 MB**, of which nine carry native extensions (`cryptography`,
`pydantic-core`, `aiohttp`, `rpds-py`, `multidict`, `yarl`, `frozenlist`,
`propcache`, `cffi`) and therefore need a wheel per platform; `ti_recon` itself
is ~16 MB, mostly the pinned MISP snapshot. `cryptography`, `pyjwt`, `uvicorn`
and `starlette` are declared for the remote surface and ride along in a local
install — an optional `ti-recon[remote]` extra would take the local closure
down; that is a packaging decision for the next phase, not a change made here.

| Option | Analyst prerequisites | Windows / Linux / macOS | Offline / internal network | Reproducible | Startup | Upgrade | Size | Dependency security | Signing | Python needed | Plugin install alone enough | Survives cache path change |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **A. self-contained executable** bundled in the plugin | none | one build per OS × arch; the plugin would need per-platform variants or a per-platform plugin | yes | yes, if built in CI from the lock | fastest | new plugin version | ~70–100 MB per platform in a git-hosted plugin | frozen at build; rebuild to patch | **required** on macOS (Gatekeeper) and expected on Windows (SmartScreen) | no | yes | yes (relative to plugin root) |
| **B. bundled wheels + first-run venv** in `${CLAUDE_PLUGIN_DATA}` | a Python 3.12+ interpreter | native wheels per platform must be vendored (nine of them) | yes, if all wheels are vendored | yes (hash-pinned) | first run slow, then interpreter start | new plugin version; data dir survives | tens of MB per platform | vendored; rebuild to patch | not for wheels | **yes, system** | only if a suitable Python exists | yes |
| **C. install from an internal package index** on first run | Python 3.12+ and reachable index | native wheels served by the index | internal network only | yes with a lock and hashes | first run slow | bump the pin | small plugin | index is the control point | no | **yes, system** | no (needs Python + index) | yes |
| **D. `uv`-managed environment** from a lock shipped in the plugin, Python provisioned by `uv` | `uv` on the workstation (one static binary, MDM-installable, or vendored per platform) | `uv` supports all three and installs a matching interpreter | yes: a pre-populated `uv` cache or an internal index mirror; `--offline` after first sync | **yes**: `uv.lock` + `--frozen` | first run slow (interpreter + deps, cached in `${CLAUDE_PLUGIN_DATA}`), then interpreter start | bump lock/version in the plugin; `uv sync --frozen` on next start | small plugin; ~40 MB + interpreter in the data dir | lock with hashes; index policy via `UV_INDEX` | `uv` itself is a signed vendor binary; wheels unsigned as today | **no** (uv provisions it) | yes, if `uv` is present | yes |
| E. anything else this host supports | a `command`-source plugin, or the Task 22 HTTP server | — | — | — | — | — | — | — | — | — | — | the HTTP path is excluded by the usage model (no shared deployment); a `command` source moves the problem into another tool the analyst must already have |

**Recommendation: D, with C as its package source, subject to one decision.**
`uv` is the only option that removes the system-Python prerequisite *without*
a per-platform binary build and code-signing pipeline, keeps the plugin small
and git-hostable, is reproducible from the lock file the repository already
maintains, supports an internal index for air-gapped rollouts, and keeps the
environment in `${CLAUDE_PLUGIN_DATA}` where it survives plugin updates and
cache path changes. Its cost is a prerequisite: `uv` must be on every analyst
workstation, installed by IT or vendored per platform inside the plugin. If that
prerequisite is not acceptable, **A** is the fallback and brings a CI build
matrix and signing with it.

Regardless of option, the launcher must become cross-platform: the Phase 1
launcher is POSIX `sh`, and `.mcp.json` has no per-OS command switch, so
Windows needs either a `.cmd`/PowerShell twin selected by a small
platform-neutral entry, or a launcher that is itself a binary.

**The repository documents no target analyst operating system.** Everything
here was measured on Ubuntu Linux x86-64. Windows and macOS behaviour of the
launcher, of secure storage sizing and of `uv` provisioning is unverified.

Phase 1 selects; it does not implement. No packaging code was written.

## What remains before an analyst can install without development prerequisites

1. **Runtime packaging** (decision D or A above): a launcher that provisions and
   starts the runtime from `${CLAUDE_PLUGIN_ROOT}` / `${CLAUDE_PLUGIN_DATA}`,
   cross-platform, with the lock file and index policy, and a startup-time
   budget — the 11 s measured here is worth reducing before it is multiplied by
   every session.
2. **The `ti-recon[remote]` split**, so a local install does not carry the
   remote-only dependencies.
3. **Secure-storage measurement** on real Windows and macOS workstations with
   real key lengths and an Enterprise OAuth session, per the constraint above.
4. **The internal marketplace** (below), a release tagging flow
   (`claude plugin tag`), and a version bump discipline: `plugin.json`'s
   `version` is what triggers an analyst's update.
5. **Windows launcher verification** and macOS verification of the whole path.

## Enterprise distribution — design only

Verified against the current host documentation; nothing built.

```
company-internal plugin marketplace (a private Git repository)
    .claude-plugin/marketplace.json  ->  { "name": "ti-recon", "source": "./plugins/ti-recon" }
        -> the ti-recon plugin, versioned by plugin.json "version" or a release tag
            -> each analyst installs at user scope
                -> optionally pushed and restricted through Enterprise policy
```

* **Private repositories.** A marketplace is a Git repository; analysts need
  read access only. Claude Code uses the analyst's existing git credentials —
  SSH agent, `gh auth`, or a credential helper — and background refresh of a
  private HTTPS marketplace needs a credential helper or SSH to keep working.
* **Versioned releases.** `version` in the marketplace entry or `plugin.json`
  gates updates; without one, the resolved commit SHA is the version. Sources
  may pin `ref` and `sha`. `claude plugin tag` creates `<name>--v<version>`
  release tags.
* **Updates.** `claude plugin update <plugin>`; a restart applies it. The
  plugin's `${CLAUDE_PLUGIN_DATA}` survives, which is what makes a provisioned
  runtime reusable across versions.
* **User scope.** `claude plugin marketplace add <org>/<repo>` and
  `claude plugin install ti-recon@<marketplace>` at the default user scope; the
  plugin's configuration prompt runs at enable time.
* **Managed / Enterprise restrictions.** `strictKnownMarketplaces` (allowlist,
  with owner wildcards from 2.1.223 and host/path patterns),
  `blockedMarketplaces`, `disableSideloadFlags` (rejects `--plugin-dir`, which
  is the *development* route and should be off for analysts),
  `allowManagedHooksOnly`, and organization-level distribution from **Organization
  settings → Plugins** for Team/Enterprise plans, where a private plugin must
  live inside the marketplace repository or share its GitHub owner.
* **Admin approval.** Organization distribution is the approval control: the
  marketplace is private, the source is the organization's own, and analysts
  never need write access or a second source.

## Boundaries kept

* **No second credential system.** The plugin maps onto
  `load_environment_credentials` and the existing per-user store; no plugin
  credential repository, no plugin-specific loader. The one boundary change is
  the credential-setup *profile*, which selects text.
* **No plugin import in the core.** Nothing under `src/ti_recon` reads
  `CLAUDE_PLUGIN_*`, `user_config`, or a plugin path; a test asserts it. The
  plugin is a distribution layer above the MCP server.
* **Task 22 untouched.** The remote profile, its two-tool surface, tenant
  derivation, JWT/JWKS verification and provider-credential boundaries are
  unchanged. Its instruction text was shortened to fit the host's limit; every
  sentence the remote contract tests assert is still there. The plugin
  references none of it, and a test scans it for remote-auth terms.
* **No live provider call, no identity provider, no deployment** was made in
  this phase.

## Developer use

```bash
uv run python tools/sync_plugin_skill.py --check    # Skill copy in sync?
uv run python tools/build_dev_plugin.py             # -> build/dev-plugin/ti-recon (NON-DISTRIBUTABLE)
claude plugin validate --strict plugins/ti-recon
claude --plugin-dir build/dev-plugin/ti-recon       # from any directory
```

The developer copy runs this checkout's `.venv/bin/ti-recon-mcp` through an
absolute path. It says so in its description, in a `NON_DISTRIBUTABLE` file at
its root and in the launcher's header; the committed plugin carries none of
those markers and no absolute path, and a test checks both directions.
