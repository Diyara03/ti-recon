# TI Recon — Claude Code plugin

Passive external threat-intelligence investigation from inside Claude Code,
using each analyst's own provider credentials. Nothing is hosted and nothing
listens: the plugin starts a local MCP server over stdio on your workstation.

The plugin bundles:

* the local TI Recon MCP server, as a self-contained Python project under
  `runtime/` (source, project metadata and the exact dependency lock), and
* the TI Recon analyst Skill under `skills/ti-recon-analyst/`.

## Prerequisites

Required on the workstation:

* Claude Code
* `uv` on `PATH` (installed by IT or by the analyst; the plugin never downloads it)

Not required:

* a Git checkout of TI Recon
* a system Python, or a manually created virtual environment
* a hosted TI Recon deployment, or the identity provider one would use
* Claude Desktop

Nothing else. On first start `uv` provisions a Python 3.12 environment for the
bundled project under the plugin's persistent data directory, downloading an
interpreter if the workstation has none, and reuses it afterwards. First-run
provisioning needs access to a Python package index and a Python download
source unless IT has pre-provisioned `uv`'s caches; see `docs/claude-plugin.md`
in the TI Recon repository for how an internal mirror is configured through
`uv`'s own settings without touching this plugin.

## Platforms

Pilot 0.1.x targets Windows x86-64, macOS on Apple silicon and Linux x86-64.
Intel (x86-64) Macs are not supported by this pilot release.

## Configuration

Every provider credential is optional and is entered through the plugin's
configuration (`/plugin`, then this plugin, then *Configure*), which Claude Code
keeps in its sensitive plugin storage. A source with no credential is reported
as `not_configured` and is never asked. Credentials are never typed into a
conversation, never tool arguments, and never appear in any report.

## If the server does not start

The server's own message is on its stderr, visible through `/mcp` and in
Claude Code's MCP log. A missing `uv` is a missing prerequisite, not a TI Recon
failure. A damaged runtime environment is repaired by `uv` on the next start
in most cases (a missing interpreter link, an emptied `pyvenv.cfg`); a
package deleted from the environment while its metadata remains is not
detected. The safe reset is to remove the environment the plugin created —
`runtime-env` under the plugin's data directory
(`~/.claude/plugins/data/ti-recon-<marketplace>/`) — or to uninstall and
reinstall the plugin, which removes that directory. Nothing else is ever
deleted, and nothing in the plugin deletes anything on its own.
