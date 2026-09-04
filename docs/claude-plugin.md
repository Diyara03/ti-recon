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
| **Phase 3** (done) | hardened for a pilot: the local/remote dependency boundary (`ti-recon[remote]`), a measured start-up profile and a halved warm start, the pilot marketplace definition at the repository root, a proved versioned upgrade, the package-index policy, the reset procedure and the endpoint pilot checklist. |
| **Not yet** | hosting the marketplace in the organization's private repository, an Enterprise analyst pilot, and Windows and macOS execution (statically resolved only). |

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
    "UV_COMPILE_BYTECODE": "1",
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
| `UV_COMPILE_BYTECODE=1` | `uv` compiles every installed module at provisioning time, so the first start does not pay for compiling 1,100 files (measured: first-start import time 2.4 s → 1.2 s) |
| `TI_RECON_CREDENTIAL_SETUP` | the server describes the plugin's credential step to a client, never an environment variable the plugin's mapping would overwrite |

Measured on Claude Code 2.1.259 and `uv` 0.12.3, Linux x86-64, after Phase 3:

| Behaviour | Result |
| --- | --- |
| first start, environment absent, warm `uv` cache, system Python present | `uv` creates the environment, installs 41 distributions and compiles their byte-code in ~1.3 s, then the server starts; observed through the host, 2.5 s to connected |
| first start, **empty** `uv` cache, no Python at all (managed download forced), online | **18.5 s** to a running interpreter with the package importable (Phase 2 measurement; unchanged by Phase 3) — 106 MB of interpreter, plus the environment |
| warm start, through the host | **2.2–2.4 s** to connected (Phase 2 baseline on the same day: 3.1–3.4 s; the 9.8–11 s recorded in the Phase 2 report was not reproducible and is treated as a load artefact of that session) |
| warm start, direct spawn to `initialize` through the exact plugin command | 2.1–2.6 s (before: 3.3–4.0 s) |
| environment | 41 distributions; 54 MB, or 71 MB with byte-code compiled |
| plugin update simulation (same environment, new plugin root) | the project is reinstalled from the new path; a source change under the same path is also detected, through `[tool.uv] cache-keys` |
| a `pyproject.toml` change without a matching lock | refused by `--locked` with a message on stderr (tested) |
| two sessions starting on a fresh machine at once | both succeed; `uv` serialises the environment |
| interpreter link removed, `pyvenv.cfg` emptied | repaired on the next start |
| environment path is a plain file | fails closed: nonzero exit, message on stderr, nothing on stdout |
| a package directory deleted from site-packages while its metadata remains | **not** repaired: `uv` audits installed metadata. See *Reset* below |
| stdout | only the program's output; every `uv` message goes to stderr |
| the plugin root | never written to |

### The start-up profile

Instrumented in the provisioned environment with a phase-by-phase timeline
and `cProfile`, before any change (interpreter start 0.01 s):

| Phase | Before | After |
| --- | --- | --- |
| import of `ti_recon.mcp_server.main` (whole graph; the MCP SDK alone is ~0.7 s of it) | 1.2–1.5 s warm, 2.4 s on a first start without byte-code | 1.2–1.5 s warm, 1.2 s first start |
| `build_default_adapters()` — eight adapters at ~0 s, **MISP warninglists at 1.5 s** | 1.5 s | 0.75 s |
| application composition, planning registry, credential load | 0.005 s | 0.005 s |
| `build_stdio_server()` (tool and resource registration, schemas) | 0.06 s | 0.06 s |
| MCP `initialize`, `tools/list`, `provider_status` | 0.05 s | 0.05 s |
| `uv run` overhead on a warm environment (`--locked`, online or offline) | 0.03 s | 0.03 s |

The bottleneck was one thing: compiling the MISP snapshot's 80 `cidr` lists.
`cProfile` attributed 4.5 of 6.5 profiled seconds to `_compile_cidr`, of which
~2 s was 142,874 `ipaddress.ip_network()` constructions and ~2 s a
per-character control-character scan over 6.4 million characters. Neither the
JSON parse (0.02 s), the checksum verification nor the Pydantic models
mattered. The snapshot is parsed eagerly, once, at adapter construction, and
deliberately so: a broken snapshot is discovered when the process starts.

Two changes, both keeping every answer byte-identical:

* `parse_cidr` — a fast path for the one canonical IPv4 spelling
  (`d.d.d.d` or `d.d.d.d/n`, no leading zeros, no whitespace), computing the
  masked network address by hand; every other spelling, including all of
  IPv6, goes to `ipaddress.ip_network(strict=False)` exactly as before. A test
  compares the fast path with the standard library over every entry of every
  shipped `cidr` list (140,000+ comparisons) and over the awkward spellings a
  hand-written parser gets wrong.
* the control-character scan is one compiled regular expression.

Not done, on purpose: lazy index construction (it would move a broken
snapshot's discovery to the first lookup), a pickled index cache in the data
directory (a second on-disk format to invalidate), and any global mutable
state. The remaining warm cost is dominated by importing the MCP SDK and the
engine, which is not TI Recon's to remove.

The MISP snapshot is 9.3 MB on disk in the repository and the plugin (2 MB
compressed); it is the only part of start-up that scaled with data, and after
the change it costs ~0.7 s of a ~2.3 s start.

### Runtime state and the two directories

| Directory | Contents | Lifetime |
| --- | --- | --- |
| `${CLAUDE_PLUGIN_ROOT}` | the plugin as installed: manifest, `.mcp.json`, `runtime/`, Skill | replaced on every plugin update; **immutable** — tests assert no run writes to it |
| `${CLAUDE_PLUGIN_DATA}/runtime-env` | the `uv`-provisioned Python environment | survives updates, deleted by `claude plugin uninstall` (kept with `--keep-data`) |
| `uv`'s own cache and Python installs | wheels and interpreters, shared across plugins | `uv`'s, outside the plugin |

No credential is ever written under either. Credentials live in Claude Code's
sensitive plugin storage and reach the server only as environment variables
at start.

**Change detection is `uv`'s, and it is cheap.** Every start audits the
installed metadata against the lock (0.03 s); a new plugin root, a changed
lock or a changed source file (through `[tool.uv] cache-keys`) reinstalls what
changed; a missing interpreter or `pyvenv.cfg` is recreated. What it does not
detect is a package directory removed from site-packages while its metadata
remains, and adding a full reinstall to every start to catch that would cost
every analyst every session for a corruption nobody has observed.

**Reset, when needed, is manual and bounded.** Remove `runtime-env` under the
plugin's own data directory — `~/.claude/plugins/data/ti-recon-<marketplace>/`
— or run `claude plugin uninstall`, which removes that directory. Nothing in
the plugin deletes anything on its own: an automated cleanup would have to
prove a path lies inside `${CLAUDE_PLUGIN_DATA}` and belongs to TI Recon, and
the host already provides exactly that operation as `uninstall`.

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

The plugin sets none of these, and tests assert it: no `UV_INDEX*` variable
in `.mcp.json`, no index in the bundled `pyproject.toml`, and a lock whose
only hosts are `pypi.org` and `files.pythonhosted.org` with no credential in
any URL. It reads whatever `uv` configuration the workstation has, which is
exactly the control point an organization wants:

```toml
# /etc/uv/uv.toml (system) or ~/.config/uv/uv.toml (user) — managed by IT
[[index]]
name = "internal"
url = "https://pypi.example.internal/simple"   # placeholder
default = true

python-install-mirror = "https://python-mirror.example.internal/"  # placeholder
```

Index credentials go through `uv`'s own mechanisms — `UV_INDEX_INTERNAL_USERNAME`
/ `UV_INDEX_INTERNAL_PASSWORD`, the keyring provider, or `netrc` — and are
unrelated to TI provider keys: a package-index credential authenticates the
workstation to a mirror, a provider key authenticates the analyst to a
threat-intelligence service, and neither ever passes through a Claude prompt,
the plugin's files, or the repository lock.

### Cross-platform status

| Platform | Status |
| --- | --- |
| Linux x86-64 | **executed**: every proof on this page |
| Windows x86-64, macOS arm64 (Apple silicon) | **intended pilot platforms, resolved statically only**: `uv sync --locked --python-platform … --dry-run` succeeds for each and every locked distribution has a cp312 wheel for each. Not executed on real hardware; see the pilot checklist. |
| macOS x86-64 (Intel) | **not supported for pilot 0.1.x.** The reason is the dependency closure, not TI Recon: see below. |

### The local/remote dependency boundary

Phase 3 moved what only the remote HTTP surface imports into an extra:

| Declared by | Packages |
| --- | --- |
| `dependencies` (core) | `pydantic`, `httpx`, `idna`, `vt-py`, `mcp` |
| `optional-dependencies.remote` | `pyjwt[crypto]>=2.13,<3`, `uvicorn>=0.34,<1`, `starlette>=0.27,<2` |
| `optional-dependencies.dev` | the test and lint tools, unchanged |

The local stdio server imports none of the three itself, and a test scans its
modules to keep it so. The remote process enforces the extra **at startup**,
explicitly and by name: `require_remote_dependencies` refuses to serve when
PyJWT is missing, below the 2.13 floor the verifier's security tests assume,
or installed without asymmetric algorithms (the `crypto` extra), and when
uvicorn is missing — with no broad `except ImportError` and no environment
value in the message. Nothing about JWT, JWKS, tenant derivation or the
pre-authentication gate changed; the remote suite runs unchanged in the
development environment, which installs `--all-extras`.

**What the split does not do, measured rather than assumed.** The MCP SDK
(`mcp` 2.1.1) declares `pyjwt[crypto]`, `uvicorn`, `starlette` and
`sse-starlette` as its own hard requirements and imports `cryptography` when
`mcp.server` is imported (blocking the import makes `import mcp.server` fail).
So the local runtime's resolved closure is **unchanged**:

| | Before | After |
| --- | --- | --- |
| distributions in the local closure | 41 | 41 |
| environment size | 54 MB (71 MB with byte-code) | 54 MB (71 MB with byte-code) |
| native-extension distributions | 9 | 9 |
| `cryptography`, `pyjwt`, `uvicorn`, `starlette` present | yes | yes, through `mcp` |

The extra therefore changes what TI Recon *declares* and *enforces* — its
security floors are no longer a metadata claim that an environment installed
without the extra could silently miss — not what an analyst's environment
contains. Removing `cryptography` from a local install would require the SDK
to drop its own requirement, which is outside this repository.

### Intel Macs: not supported for the pilot

`cryptography` releases from 49.0.0 (June 2026) publish macOS wheels for
arm64 only; the upstream project no longer supports macOS x86-64. It reaches
the local runtime through the MCP SDK's own requirement — `mcp →
pyjwt[crypto] → cryptography` — so the local/remote split does not remove it,
and on an Intel Mac `uv` would fall back to building it from source, which
needs a Rust toolchain and OpenSSL headers the pilot does not permit on a
workstation.

**Pilot 0.1.x therefore does not support macOS x86-64.** The dependency floor
is *not* weakened to reach it: the last `cryptography` release with x86-64
wheels (48.0.1) has since-fixed security advisories recorded against it, so
pinning it for one platform was rejected. TI Recon itself has no Intel-Mac
incompatibility; support returns if the dependency closure regains x86-64
wheels or the SDK stops requiring the package. A test records this as the one
tolerated wheel gap and fails if any other appears.

Every other distribution with native code has cp312 wheels for all four
targets, no local package is source-only, and `uv sync --locked
--python-platform … --dry-run` resolves for each target from the plugin's
lock.

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
| **Phase 3**, the repository itself as the pilot marketplace: `claude plugin validate --strict .`, `marketplace add <checkout>`, `plugin install ti-recon@ti-recon-pilot` | validated, added, installed at `~/.claude/plugins/cache/ti-recon-pilot/ti-recon/0.1.0`; sentinel configuration → `gti=true censys=true`; no configuration → only `misp_warninglists`; three tools; 0 sentinel occurrences; stdio only; 2.2–2.5 s to connected |
| **Phase 3**, upgrade: install 0.1.0 from a scratch marketplace, replace it with a 0.1.1 build (version bumped in `plugin.json`, the marketplace entry, the runtime's `pyproject.toml`, lock and `__version__`; a marker appended to the Skill), `marketplace update`, `plugin update` | `serverVersion` 0.1.0 → 0.1.1; `installPath` `…/0.1.0` → `…/0.1.1`; the data directory and its `pyvenv.cfg` unchanged; `ti_recon-0.1.1.dist-info` replaces 0.1.0 with `Installed 1 package`; the cached Skill carries the marker; the configuration key `ti-recon@<marketplace>` is version-independent; the 0.1.0 cache directory stays until the host's grace period |

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

## The pilot marketplace

The repository is the marketplace. `.claude-plugin/marketplace.json` at the
repository root lists the plugin at `./plugins/ti-recon` under the package
version, so hosting a copy of this repository — or a repository that contains
only `.claude-plugin/marketplace.json` and `plugins/ti-recon/` — in a private
GitHub repository, an internal Git server or GitHub Enterprise Server is the
whole distribution step. No hostname is written anywhere; the marketplace
name is `ti-recon-pilot`, its owner a placeholder, and it has been validated
with `claude plugin validate --strict`, installed from, and never pushed or
registered anywhere.

**Versioning.** The pilot release is `0.1.0`, and 1.0 is not used because the
plugin works: it is reserved for after a real endpoint pilot. One version is
stated in four places and tests hold them equal — `ti_recon.__version__`,
`pyproject.toml`, `plugin.json` and the marketplace entry. Bumping all four
(and relocking, since the lock records the project version) is a release;
`claude plugin update` picks it up because the host gates updates on
`plugin.json`'s `version`. `claude plugin tag` can create `ti-recon--v0.1.0`
tags once the repository is hosted.

### Enterprise administration (templates, nothing applied)

Placeholders throughout: `acme-corp`, `ti-recon-marketplace`.

Allow the internal marketplace and nothing else, in managed settings:

```json
{
  "strictKnownMarketplaces": [
    { "source": "github", "repo": "acme-corp/ti-recon-marketplace" }
  ],
  "disableSideloadFlags": true
}
```

(`hostPattern` for a GitHub Enterprise Server host, or `pathPattern` for an
approved local path, are the alternatives the host documents.
`disableSideloadFlags` turns off `--plugin-dir`, which is the development
route and not an analyst one.)

Register the marketplace for a team automatically, in a project's
`.claude/settings.json` or in managed settings:

```json
{
  "extraKnownMarketplaces": {
    "ti-recon-pilot": {
      "source": { "source": "github", "repo": "acme-corp/ti-recon-marketplace" }
    }
  },
  "enabledPlugins": { "ti-recon@ti-recon-pilot": true }
}
```

Distribute through **Organization Settings → Plugins** on Team or Enterprise
plans: the marketplace repository must be private or internal, and a private
plugin is accepted when it lives inside the marketplace repository — which
this layout satisfies — or shares the marketplace's GitHub owner. Analysts
then install at user scope (`claude plugin install ti-recon@ti-recon-pilot`)
or receive it through organization sync, and update with
`claude plugin update ti-recon@ti-recon-pilot`. None of this has been applied,
and no administrator has approved this repository; these are the settings the
current host documents, written down so the pilot can start from them.

## What remains before an Enterprise analyst pilot

1. **Hosting** the marketplace in the organization's private repository and
   the managed-settings entries above, by an administrator.
2. **`uv` on the endpoint** through endpoint management, and the index or
   mirror policy in `uv`'s settings; or IT-provisioned caches for offline
   first starts. The plugin never downloads `uv`.
3. **Windows and Apple-silicon macOS execution** of
   `docs/claude-plugin-pilot-checklist.md` on real managed machines,
   including the sensitive-storage observation.

A signed self-contained executable remains the fallback if the organization
declines the `uv` prerequisite.
