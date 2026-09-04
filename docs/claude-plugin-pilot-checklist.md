# TI Recon plugin — endpoint pilot checklist

For execution on a **real, managed analyst workstation**. Everything on this
page was designed on Linux x86-64; nothing below has been run on Windows or
macOS yet, and this checklist exists so that claim can be made honestly once it
has. Run it once per platform:

| Platform | Run by | Date | Result |
| --- | --- | --- | --- |
| Windows x86-64 | | | |
| macOS arm64 (Apple silicon) | | | |
| macOS x86-64 (Intel) — only if the fleet still has them; see step 0 | | | |

No real provider key is needed for any step. Where a key is asked for, use a
fake sentinel such as `PILOT_SENTINEL_KEY_0001` and never a real one.

Prerequisites: Claude Code and `uv` on `PATH`. Nothing else — no Python, no
Git checkout, no virtual environment, no Render, no Auth0, no Claude Desktop.

`<marketplace>` below is the internal marketplace name your administrator
published (`ti-recon-pilot` in the repository's own manifest).

---

## 0. Platform decision (Intel Mac only)

`cryptography` ≥ 49 ships no macOS x86-64 wheel and is required by the MCP
SDK. Before piloting on an Intel Mac, the maintainers must have chosen one of:
a marker-scoped constraint to `cryptography` 48.0.1 (with its published
advisories accepted), or excluding Intel Macs. If neither is recorded in
`docs/claude-plugin.md`, stop here for that platform.

## 1. Versions

```
claude --version
uv --version
```

Record both. Claude Code 2.1.259 and uv 0.12.3 are the versions the plugin was
developed against; older ones are untested.

- [ ] Claude Code ≥ 2.1.259
- [ ] `uv` found on `PATH` from a fresh terminal (not only from the shell that installed it)

## 2. Install from the internal marketplace

```
claude plugin marketplace add <org>/<repo>      # or the internal Git URL
claude plugin install ti-recon@<marketplace>
claude plugin list --json
```

- [ ] `installPath` is under `~/.claude/plugins/cache/` (Windows: `%USERPROFILE%\.claude\plugins\cache\`)
- [ ] `version` is the pilot version the administrator announced
- [ ] the install printed "7 userConfig options not yet set" and nothing about credentials

## 3. First start — runtime provisioning

From a directory that is **not** a TI Recon checkout (your home directory):

```
claude --debug mcp --debug-file mcp-first.log mcp list
```

- [ ] `plugin:ti-recon:ti-recon … ✔ Connected`
- [ ] the log's "Server stderr" line shows `Creating virtual environment at:` under `~/.claude/plugins/data/ti-recon-<marketplace>/runtime-env`
- [ ] record "Successfully connected … in N ms" as the **first-run** time
- [ ] no line mentions Rust, a compiler, `cargo`, `cl.exe` or Xcode
- [ ] if the workstation had no Python 3.12, the log shows `uv` downloading one (or IT pre-provisioned it)

## 4. Warm start

```
claude --debug mcp --debug-file mcp-warm.log mcp list
```

- [ ] connected again, no `Creating virtual environment`, no `Installed N packages`
- [ ] record the **warm** connect time (Linux reference: 2.2–2.4 s)

## 5. Zero-key behaviour

In a Claude Code session started from your home directory:

```
/mcp
```

- [ ] `ti-recon` shows connected with three tools: `investigate_observable`, `investigate_file`, `provider_status`
- [ ] ask: "Call provider_status and list each provider with its configured flag"
- [ ] every remote source is `false`; `misp_warninglists` is `true`
- [ ] the answer says those sources were **not checked**, not that they are down

## 6. Fake configuration

```
/plugin
```

Select TI Recon → Configure. Enter `PILOT_SENTINEL_KEY_0001` for **Google TI /
VirusTotal API key** only. Leave everything else empty.

- [ ] the field masks its input
- [ ] Windows/macOS: open `~/.claude/settings.json` — the sentinel is **not** there
- [ ] macOS: Keychain Access shows a Claude Code item; Windows/Linux: `~/.claude/.credentials.json` exists and is not world-readable
- [ ] `/mcp` → reconnect ti-recon, then ask for `provider_status` again: `gti` is `true`, everything else unchanged
- [ ] search the debug log and the session transcript for `PILOT_SENTINEL_KEY_0001`: zero occurrences

Record which storage the platform actually used; this is the measurement the
design still lacks.

## 7. Local file path

Create a small harmless file (an empty text file is enough) and ask:

> Investigate the file at `<path>`

- [ ] Claude Code asks for approval before the tool runs, even if you approved investigate_observable earlier
- [ ] the answer names the SHA-256 and says the file was hashed locally
- [ ] with only the sentinel key configured, the run reports GTI as a failed check (a rejected credential), never as a verdict — **do not enter a real key to make it succeed; this pilot is about the plugin, not the providers**

## 8. Plugin reload

```
/reload-plugins
```

- [ ] the ti-recon server keeps its connection (config unchanged)

## 9. Upgrade

When the administrator publishes the next pilot version:

```
claude plugin marketplace update <marketplace>
claude plugin update ti-recon@<marketplace>
```

Restart Claude Code, then `claude --debug mcp --debug-file mcp-upgrade.log mcp list`.

- [ ] `claude plugin list --json` shows the new version and a new `installPath`
- [ ] the log shows the old environment reused (no `Creating virtual environment`) and `Installed 1 package` for `ti-recon`
- [ ] `~/.claude/plugins/data/ti-recon-<marketplace>/` still exists
- [ ] the sentinel configuration from step 6 is still in effect (`gti` still `true`)
- [ ] `/ti-recon:ti-recon-analyst` shows the updated Skill

## 10. Uninstall and reinstall

```
claude plugin uninstall ti-recon@<marketplace>
```

- [ ] `~/.claude/plugins/data/ti-recon-<marketplace>/` is gone (uninstall deletes plugin data unless `--keep-data`)
- [ ] the sentinel configuration is gone from settings and from sensitive storage

```
claude plugin install ti-recon@<marketplace>
```

- [ ] first start provisions again (step 3) and connects

## 11. Failure experience (optional)

Temporarily remove `uv` from `PATH` (or rename it), start Claude Code, `/mcp`.

- [ ] ti-recon shows a connection failure naming `uv`; no TI Recon tool exists; asking to investigate something yields "the server is not connected", never an assessment
- [ ] restore `uv`; the server connects again without reprovisioning

## Report back

Attach `mcp-first.log`, `mcp-warm.log` and `mcp-upgrade.log` (they contain no
credentials; search them for your sentinel first), the two timings, the
storage location observed in step 6, and any step that failed with its exact
message.
