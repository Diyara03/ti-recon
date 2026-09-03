# TI Recon — Claude Code plugin

Passive external threat-intelligence investigation from inside Claude Code,
using each analyst's own provider credentials.

The plugin bundles two things:

* the local TI Recon MCP server (`.mcp.json`, started automatically), and
* the TI Recon analyst Skill (`skills/ti-recon-analyst/`), a packaged copy of
  the repository's Skill.

## Status

**Phase 1: host proof only.** This build carries no TI Recon runtime, so the
bundled launcher (`bin/ti-recon-mcp`) fails closed with a message rather than
starting a server. Runtime packaging is the next phase; the design is in
`docs/claude-plugin.md` at the repository root.

## Configuration

Every provider credential is optional and is entered through the plugin's
configuration (`/plugin`, then this plugin, then *Configure*), which Claude Code
stores in its secure storage. A source with no credential is reported as
`not_configured` and is never asked. Credentials are never typed into a
conversation, never tool arguments, and never appear in any report.
