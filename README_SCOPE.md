# Repo Scope (Transition Note)

**Updated:** 23 February 2026

This repository is transitioning from a single integration assumption (MCP stdio proxy) to:

- **One core engine** — enforcement pipeline, amber mediator, telemetry, rollback, flight recorder
- **Multiple adapters:**
  - OpenClaw plugin + Python sidecar (primary target)
  - MCP stdio proxy (for Claude Desktop, Cursor, and other MCP clients)

## What's where

| Path | Status | Purpose |
|------|--------|---------|
| `unwind/enforcement/` | Active | Core engine — untouched by transition |
| `unwind/sidecar/` | Scaffold | Python sidecar for OpenClaw adapter |
| `unwind/transport/stdio.py` | Active | MCP stdio proxy adapter (existing) |
| `openclaw-adapter/` | Scaffold | TypeScript plugin for OpenClaw |
| `ghostmode/` | Active | Standalone dry-run proxy |
| `evidence/mcp-stdio/2026-02-22/` | Archived | Stage evidence for MCP stdio path |
| `archive/raw-imports/` | Archived | Transfer tarballs (Pi review cycles) |

## Key context

See `SESSION-UPDATE-2026-02-23.md` for the full architecture correction story.
