# TI Recon — Claude Code plugin

Passive external threat-intelligence investigation from inside Claude Code,
using each analyst's own provider credentials. Nothing is hosted and nothing
listens: the plugin starts a local MCP server over stdio on your workstation.

The plugin bundles:

* the local TI Recon MCP server, as a self-contained Python project under
  `runtime/` (source, project metadata and the exact dependency lock), and
* the TI Recon analyst Skill under `skills/ti-recon-analyst/`.

## Prerequisites

* Claude Code
* `uv` on the workstation's `PATH`

Nothing else. On first start `uv` provisions a Python 3.12 environment for the
bundled project under the plugin's persistent data directory, downloading an
interpreter if the workstation has none, and reuses it afterwards. First-run
provisioning needs access to a Python package index and a Python download
source unless IT has pre-provisioned `uv`'s caches; see `docs/claude-plugin.md`
in the TI Recon repository for how an internal mirror is configured through
`uv`'s own settings without touching this plugin.

## Configuration

Every provider credential is optional and is entered through the plugin's
configuration (`/plugin`, then this plugin, then *Configure*), which Claude Code
keeps in its sensitive plugin storage. A source with no credential is reported
as `not_configured` and is never asked. Credentials are never typed into a
conversation, never tool arguments, and never appear in any report.

## If the server does not start

The server's own message is on its stderr, visible through `/mcp`. A missing
`uv` is a missing prerequisite, not a TI Recon failure. A damaged runtime
environment is repaired by `uv` on the next start in most cases; if not,
uninstalling and reinstalling the plugin removes its data directory and the
environment with it.
