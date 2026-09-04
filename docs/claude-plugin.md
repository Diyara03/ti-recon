# The TI Recon Claude Code plugin (Task 23)

TI Recon's primary internal usage model is local and per analyst:

```
Claude Enterprise
    -> Claude Code on each analyst workstation
    -> the TI Recon plugin (this document)
    -> the local stdio ti-recon-mcp server, provisioned by uv
    -> the analyst's own TI-provider credentials
```

There is **no shared deployment** in this model. Nothing is hosted, nothing
listens, no identity provider is contacted, and every provider credential
belongs to the analyst whose workstation it is on. The authenticated remote MCP
surface from Task 22 (`docs/remote-mcp.md`) stays intact as an optional path;
nothing here depends on it and nothing here changes it.

## Where this stands

| | State |
| --- | --- |
| **Phase 1** (done) | proved the host mechanics with a developer-only proof: plugin loading, Skill discovery, MCP lifecycle, `userConfig` → environment → the existing credential resolver, no leakage. |
| **Phase 2** (done) | made the plugin **self-contained and installable**: it bundles the TI Recon project and its lock, starts the server directly through `uv`, provisions a persistent Python environment under the plugin's data directory, and was installed through the real plugin manager from a disposable local marketplace and run from outside the repository. |
| **Not yet** | an internal Enterprise marketplace, an Enterprise analyst pilot, Windows and macOS execution (statically resolved only), the `ti-recon[remote]` dependency split. |

The analyst experience this now supports:

1. install the plugin from a marketplace;
2. enter whichever provider credentials you have under `/plugin` → TI Recon →
   *Configure*;
3. start Claude Code anywhere and ask.

No repository checkout, no virtual environment, no `uv sync`, no `.mcp.json`
editing, no `claude mcp add`, no copied Skill, no `.env`, no key in a prompt.
The workstation needs **Claude Code and `uv`**, nothing else: `uv` downloads
the Python interpreter if the machine has none.

## The plugin

```
plugins/ti-recon/
    .claude-plugin/
        plugin.json          name, version, userConfig
    .mcp.json                the one stdio server, started directly through uv
    runtime/                 byte-identical, generated copy of the project
        pyproject.toml
        uv.lock
        README.md
        .python-version      derived from requires-python
        src/ti_recon/        the package, including the pinned MISP snapshot
    skills/
        ti-recon-analyst/    byte-identical copy of .claude/skills/ti-recon-analyst
    README.md
```

No agent, no hook, no command, no output style, **no `bin/` and no launcher
script**. Organization-managed distribution rejects a plugin with a top-level
`bin/`, and a shell launcher would have required a shell; the server is
started by a bare executable name the host resolves on `PATH`. Tests assert
the layout: no top-level `bin/`, no symlink anywhere, no placeholder path that
escapes the plugin root, no repository-relative reference, no absolute
developer path, no `.venv`, no remote-authentication term in the plugin's own
files.

### The invocation

`.mcp.json` declares exactly this, and tests pin every part of it:

```json
{
  "command": "uv",
  "args": [
    "run",
    "--project", "${CLAUDE_PLUGIN_ROOT}/runtime",
    "--locked", "--no-dev", "--no-editable", "--no-env-file",
    "--python", "3.12",
    "ti-recon-mcp"
  ],
  "env": {
    "UV_PROJECT_ENVIRONMENT": "${CLAUDE_PLUGIN_DATA}/runtime-env",
    "TI_RECON_CREDENTIAL_SETUP": "claude-plugin",
    "VIRUSTOTAL_API_KEY": "${user_config.virustotal_api_key}",
    "…": "one entry per option, see below"
  }
}
```

| Part | Why |
| --- | --- |
| `uv` | a bare executable, resolved on `PATH` by the host on every platform; no `sh`, no wrapper |
| `--project ${CLAUDE_PLUGIN_ROOT}/runtime` | the bundled project, wherever the host put the plugin; the working directory plays no part |
| `--locked` | install exactly `uv.lock`, and refuse to start if the lock disagrees with `pyproject.toml` |
| `--no-dev` | no development groups; the dev *extra* is never requested either |
| `--no-editable` | a real install of `ti_recon` into site-packages, not a link back to the source tree |
| `--no-env-file` | no `.env` from the working directory is read, so a credential can only arrive from the plugin's configuration |
| `--python 3.12` | the interpreter series derived from `requires-python`, stated identically in `.python-version`; `uv` provisions it if absent |
| `UV_PROJECT_ENVIRONMENT` | the environment lives under `${CLAUDE_PLUGIN_DATA}`, which survives plugin updates; nothing mutable is ever placed under `${CLAUDE_PLUGIN_ROOT}` |
| `TI_RECON_CREDENTIAL_SETUP` | the server describes the plugin's credential step to a client, never an environment variable the plugin's mapping would overwrite |

Measured on Claude Code 2.1.259 and `uv` 0.12.3, Linux x86-64:

| Behaviour | Result |
| --- | --- |
| first start, environment absent, warm `uv` cache, system Python present | `uv` creates the environment and installs 41 distributions in ~3 s, then the server starts |
| first start, **empty** `uv` cache, no Python at all (managed download forced), online | **18.5 s** to a running interpreter with the package importable; 106 MB of interpreter, 54 MB of environment |
| warm start | `uv` overhead **0.2 s**; the server itself then takes ~9–10 s to answer `initialize` on this machine |
| observed through the host | first session connected in 15.2 s, warm sessions in 9.8–11.0 s |
| environment | 41 distributions, 54 MB on disk (65 MB as the host reports it with byte-code) |
| plugin update simulation (same environment, new plugin root) | the project is reinstalled from the new path; a source change under the same path is also detected, through `[tool.uv] cache-keys` |
| a `pyproject.toml` change without a matching lock | refused by `--locked` with a message on stderr |
| two sessions starting on a fresh machine at once | both succeed; `uv` serialises the environment |
| interpreter link removed, `pyvenv.cfg` emptied | repaired on the next start |
| environment path is a plain file | fails closed: nonzero exit, message on stderr, nothing on stdout |
| a package directory deleted from site-packages while its metadata remains | **not** repaired: `uv` audits installed metadata, so this exotic damage needs the environment removed — `claude plugin uninstall` deletes the data directory, or delete `runtime-env` by hand |
| stdout | only the program's output; every `uv` message goes to stderr |
| the plugin root | never written to |

The ~10 s the server itself takes to initialize is unchanged from Phase 1 and
is import and snapshot-loading time in TI Recon, not provisioning. It is
tolerable for a session that starts once, and is recorded as a candidate for
reduction rather than treated as a release blocker.

### Runtime state and the two directories

| Directory | Contents | Lifetime |
| --- | --- | --- |
| `${CLAUDE_PLUGIN_ROOT}` | the plugin as installed: manifest, `.mcp.json`, `runtime/`, Skill | replaced on every plugin update; **immutable** — tests assert no run writes to it |
| `${CLAUDE_PLUGIN_DATA}/runtime-env` | the `uv`-provisioned Python environment | survives updates, deleted by `claude plugin uninstall` (kept with `--keep-data`) |
| `uv`'s own cache and Python installs | wheels and interpreters, shared across plugins | `uv`'s, outside the plugin |

No credential is ever written under either. Credentials live in Claude Code's
sensitive plugin storage and reach the server only as environment variables
at start.

### Package source and network

The plugin bundles the TI Recon source; **TI Recon is never downloaded from
PyPI**. Third-party dependencies and, where the workstation has no Python
3.12, the interpreter itself are fetched by `uv` on the first start, from
`uv`'s configured sources:

* dependencies from the configured index, by default PyPI — for an Enterprise
  rollout set `UV_INDEX_URL` (or `UV_DEFAULT_INDEX`) to the internal
  PyPI-compatible mirror, or configure it in `uv`'s user or system settings
  (`~/.config/uv/uv.toml`, `/etc/uv/uv.toml`); index credentials belong in
  `uv`'s keyring or netrc support, never in the plugin and never in a prompt;
* the interpreter from `uv`'s Python download source — `UV_PYTHON_INSTALL_MIRROR`
  points it at an internal mirror, or IT pre-installs a managed Python;
* fully offline after the first start (`--offline` was used for every test in
  the suite), and offline from the first start if IT pre-populates `uv`'s cache.

The plugin sets none of these. It reads whatever `uv` configuration the
workstation has, which is exactly the control point an organization wants.

### Cross-platform status

| Platform | Status |
| --- | --- |
| Linux x86-64 | **executed**: every proof on this page |
| Windows x86-64, macOS arm64, macOS x86-64 | **resolved statically only**: `uv sync --locked --python-platform … --dry-run` succeeds for each, and every locked distribution has a wheel for each — with one exception below. Not executed on real hardware. |

The exception: **`cryptography` 50.0.1 publishes no macOS x86-64 wheel**, only
arm64. On an Intel Mac `uv` would have to build it from source, which needs a
Rust toolchain and OpenSSL headers — not a portable first start. `cryptography`
enters the lock only through `pyjwt[crypto]`, which the **remote** JWT
verifier needs and the local server never imports. This is the one place the
`ti-recon[remote]` dependency split would matter for portability; per the
Phase 2 instruction it is reported here and **not performed**. Every other
distribution with native code (`pydantic-core`, `aiohttp`, `rpds-py`,
`multidict`, `yarl`, `frozenlist`, `propcache`, `cffi`) has wheels for all four
targets. `pywin32` is Windows-only by marker, as intended.

The design avoids platform-specific mechanics: a direct executable, no shell,
`pathlib` and `subprocess` in the tests, no `/tmp`, no `chmod`, no Unix file
locking (concurrency is `uv`'s), no shebang. What still has to be run on a real
Enterprise machine: the whole path on Windows and macOS, the `uv` prerequisite
under the organization's endpoint management, the interpreter download or
pre-provisioning, and the sensitive-storage sizing below.

### Failure modes

| Situation | What happens |
| --- | --- |
| `uv` not installed | the host cannot spawn the server (`Executable not found in $PATH: "uv"`); `/mcp` shows the server failed, no TI Recon tool exists, and the Skill says the server is not connected — never an assessment |
| dependency source unreachable on first start | `uv` exits nonzero with its message on stderr; nothing on stdout; no half-started server (tested with an empty cache offline) |
| Python 3.12 absent and downloads forbidden | `uv` exits nonzero naming the interpreter problem; nothing on stdout (tested) |
| damaged environment | interpreter and metadata damage repaired on the next start; a non-directory in the environment's place fails closed (tested) |
| an invalid provider credential entered | `provider_status` reports it `configured` — stored, not validated, exactly as documented — and an investigation using it records the provider's rejection in coverage as a check that failed, never as evidence about the observable |
| no credentials at all | the server starts; `provider_status` reports every remote source `not_configured` and the local warninglists configured (tested, in the suite and through the installed plugin) |

In none of these does the engine produce `INCONCLUSIVE` for something that
never started: a provisioning failure is a startup failure the host reports,
and a credential problem is coverage.

## Credentials

### The mapping

One option per credential group, the abuse.ch key asked for once:

| Plugin option | Environment variable | Credential group | Adapters |
| --- | --- | --- | --- |
| `virustotal_api_key` *(sensitive)* | `VIRUSTOTAL_API_KEY` | `virustotal` | `gti` |
| `abusech_auth_key` *(sensitive)* | `ABUSECH_AUTH_KEY` | `abuse_ch` | `threatfox`, `urlhaus`, `malwarebazaar` |
| `urlscan_api_key` *(sensitive)* | `URLSCAN_API_KEY` | `urlscan` | `urlscan` |
| `greynoise_api_key` *(sensitive)* | `GREYNOISE_API_KEY` | `greynoise` | `greynoise` |
| `censys_pat` *(sensitive)* | `CENSYS_PAT` | `censys` | `censys` |
| `hybrid_analysis_api_key` *(sensitive)* | `HYBRID_ANALYSIS_API_KEY` | `hybrid_analysis` | `hybrid_analysis` |
| `censys_organization_id` | `CENSYS_ORGANIZATION_ID` | `censys` (connection metadata) | `censys` |

The variable names are the ones `.env.example` documents and
`CREDENTIAL_ENVIRONMENT` in `application/composition.py` reads; the plugin
maps onto them and restates nothing. A test derives the groups from the
shipped adapters, so a new credentialled provider fails the suite until the
plugin offers an option for it. `misp_warninglists` needs no credential.

**Every credential is optional.** No option is `required`, none has a
`default`, and an analyst with one key or none gets a server that starts and
reports the rest `not_configured`. The one non-secret option is not marked
sensitive.

### Sensitive plugin storage

Provider secrets are `sensitive: true`. What that means, exactly as current
Claude Code documentation describes it:

* Claude Code masks the value in its configuration dialog;
* the value is **not** written to `settings.json`;
* it is stored in **Claude Code's sensitive plugin storage**: the macOS
  Keychain, or `~/.claude/.credentials.json` where a supported keychain is
  unavailable;
* that storage is shared with the host's own OAuth tokens and is documented at
  roughly **2 KB** in total for the Keychain case.

Nothing here claims Windows Credential Manager or a Linux secret service; the
host documents neither, and this machine (Linux) uses the file fallback. What
an Enterprise endpoint does with that storage must be validated on a real
managed workstation before rollout.

The plugin's footprint, under stated assumptions rather than measured keys (the
repository documents no credential formats):

| Item | Bytes |
| --- | --- |
| six values (64 / 36 / 64 / 128 / 36 / 64) | ~392 |
| storage overhead | ~250 |
| **plugin total, all six set** | **~650** |

Roughly a third of the documented budget, which is acceptable for the current
design. The open half of the sum is the OAuth share on an Enterprise
workstation. No custom secret store exists and none is planned; if the budget
ever fails, the fallback that keeps every other property is a `file`-typed,
non-sensitive option naming an analyst-owned credential file — outside the
host's storage, still outside model context.

### Secrets never enter model context

```
plugin configuration UI (/plugin -> Configure)
    -> Claude Code sensitive plugin storage      (sensitive: true)
    -> ${user_config.KEY} substituted into .mcp.json env
    -> the uv-started ti-recon-mcp process environment, read once at startup
    -> load_environment_credentials -> CredentialManager -> the per-user store
    -> CredentialResolver, at request time, for the selected provider only
    -> the transport's _apply_auth, into one header
```

| Never | Why it cannot |
| --- | --- |
| Skill content | the host refuses to substitute a sensitive option into a Skill, and the Skill contains no `${user_config.*}` reference at all (tested) |
| the prompt, a tool argument | no tool accepts a credential; the input schemas are asserted credential-free |
| `instructions` and tool descriptions | fixed text; a live session with sentinel credentials is searched |
| the report, JSON or text | `SecretStr` end to end; the same sentinel search covers `provider_status` and the runtime tests cover investigation reports |
| stdout, stderr, logs | stdout is the protocol; the installed server's stderr is captured at `DEBUG` and searched |
| a `.env` in the working directory | `--no-env-file`; a test plants sentinel keys in one and proves they never become credentials |
| exception messages | unexpected failures become a fixed message and the type alone is logged |
| `${CLAUDE_PLUGIN_DATA}` | holds the environment, never a credential |

### Local files

`investigate_file` is unchanged and is one of the reasons this architecture is
local: the path names a file on the analyst's own workstation, the file is
hashed there with SHA-256, the hash is what gets investigated, the bytes never
leave, and the tool carries `anthropic/requiresUserInteraction` so Claude Code
asks a human every time. The provisioning tests assert that metadata survives
the `uv`-started subprocess boundary.

## The proofs

Two layers, both with fake sentinel values and no provider contacted.

**Deterministic tests** (`tests/unit/plugin/`), all offline:

* structure: manifest, invocation, mapping, layout, no `bin/`, no symlink, no
  escape, no checkout reference, Skill and runtime byte-identity, lock
  integrity, strict host validation;
* provisioning through the real `uv`, from a directory outside the repository
  with a scrubbed environment: first run creates the environment under the
  data directory; the imported package and interpreter are under it and **no
  `sys.path` entry, executable or module path leads back to the checkout**;
  the package is installed, not linked; stdout carries only program output;
  the warm run reinstalls nothing; the plugin root is untouched; two
  concurrent first runs succeed; a damaged interpreter is repaired; a
  non-directory fails closed; an empty cache offline and a forbidden Python
  download fail closed on stderr;
* the server itself over stdio through `uv`: all three tools, the file tool's
  approval metadata, the plugin profile, `configured` per group with sentinel
  keys, and no sentinel on any surface; then with no credentials and a
  sentinel-laden `.env` in the working directory.

**The real host**, Claude Code 2.1.259:

| Step | Result |
| --- | --- |
| `claude plugin validate --strict plugins/ti-recon` | passed |
| `--plugin-dir` from outside the repository, `mcp list` | `plugin:ti-recon:ti-recon … ✔ Connected`; the host spawned `uv run --project …/plugins/ti-recon/runtime … ti-recon-mcp` and provisioned `~/.claude/plugins/data/ti-recon-inline/runtime-env` |
| disposable local marketplace: `claude plugin validate --strict`, `marketplace add`, `plugin install ti-recon@ti-recon-local-test` | validated, added, installed at user scope; `installPath` `~/.claude/plugins/cache/ti-recon-local-test/ti-recon/0.1.0` |
| first session from `$HOME`, `VIRTUAL_ENV` and `PYTHONPATH` removed | environment absent → provisioned under `~/.claude/plugins/data/ti-recon-ti-recon-local-test/runtime-env`; connected in 15.2 s |
| warm session | connected in 9.8 s |
| the installed runtime, run by hand from `/tmp` | interpreter and `ti_recon` both under the data directory; no repository path on `sys.path` |
| `-p` session with sentinel VirusTotal key, Censys PAT and organization id via `pluginConfigs["ti-recon@ti-recon-local-test"]` | `provider_status`: `gti=true censys=true misp_warninglists=true`, all others `false`; tools `investigate_file investigate_observable provider_status` |
| `-p` session with no configuration | only `misp_warninglists` configured; same three tools |
| `-p "/ti-recon:ti-recon-analyst"` | the Skill's capability guide, loaded as the plugin's one Skill, zero tool calls |
| sentinel search over every result, debug log and stderr | 0 occurrences |
| transport and auth | `transport: stdio` only; no OAuth, no JWKS, no HTTP server, no instruction truncation |
| `uv` removed from `PATH` | `Connection failed (ENOENT): Executable not found in $PATH: "uv"`; no environment value in the message |

One host detail worth knowing: for a marketplace added from a **local
directory**, Claude Code resolved `${CLAUDE_PLUGIN_ROOT}` to the marketplace's
own plugin directory rather than to the cache copy it also made. Both are
host-owned copies outside the repository; the cache copy was run by hand to
prove it is complete. A git-hosted marketplace lands under
`~/.claude/plugins/` in either case.

The disposable marketplace was removed after the proof. Nothing was
published.

## The two canonical sources

`.claude/skills/ti-recon-analyst/` is the canonical Skill and the repository
project is the canonical runtime. The plugin carries byte-identical copies of
both, because the plugin cache copies a directory and cannot follow a symlink:

```bash
uv run python tools/sync_plugin_skill.py --check      # or --write
uv run python tools/sync_plugin_runtime.py --check    # or --write
```

The runtime manifest is explicit — `pyproject.toml`, `uv.lock`, `README.md`,
`src/ti_recon/` and a derived `.python-version` — so an unrelated repository
change never obliges a resync, and a test fails if the copy holds anything
else or differs anywhere. The trade-off is repository size: `src/ti_recon`,
with its ~7 MB MISP snapshot, exists twice in the tree. `plugins/` is excluded
from the package's own sdist.

## Task 22 remains intact

The remote profile, its two-tool surface, tenant derivation, JWT and JWKS
verification, the pre-authentication gate and the provider-credential
boundary are unchanged, and their tests run in the same suite. The bundled
runtime *contains* the remote modules — it is the whole package — but nothing
in the plugin starts them, references them, or imports them at startup; the
plugin's own files are scanned for remote-authentication terms.

## What remains before an Enterprise analyst pilot

1. **The internal marketplace** — a private repository holding
   `.claude-plugin/marketplace.json` and this plugin, versioned by
   `plugin.json`'s `version`, distributed at user scope or through
   Organization Settings → Plugins, with `strictKnownMarketplaces` and
   `disableSideloadFlags` in managed settings.
2. **`uv` on the endpoint** through endpoint management, and the index or
   mirror policy in `uv`'s settings; or IT-provisioned caches for offline
   first starts.
3. **Windows and macOS execution** of the whole path on real managed machines,
   and the macOS x86-64 decision: the `ti-recon[remote]` split, or an Intel
   Mac exclusion.
4. **Sensitive-storage measurement** on a real Enterprise-authenticated
   Windows and macOS workstation.
5. **Startup time** — the server's own ~10 s initialize is worth reducing
   before it is paid in every session.

A signed self-contained executable remains the fallback if the organization
declines the `uv` prerequisite.
