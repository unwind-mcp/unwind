# UNWIND

[![PyPI](https://img.shields.io/pypi/v/unwind-mcp)](https://pypi.org/project/unwind-mcp/)
[![Tests](https://img.shields.io/badge/tests-1%2C859_passing-brightgreen)](https://github.com/unwind-mcp/unwind)
[![Python](https://img.shields.io/pypi/pyversions/unwind-mcp)](https://pypi.org/project/unwind-mcp/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Ghost Mode](https://img.shields.io/pypi/v/ghostmode?label=ghostmode&color=purple)](https://pypi.org/project/ghostmode/)
[![CRAFT](https://img.shields.io/pypi/v/craft-auth?label=craft-auth&color=orange)](https://pypi.org/project/craft-auth/)

*Your agent can read email, write files, send messages, and call APIs. Do you know what it did while you were away?*

**See Everything. Rewind File Changes. Test Without Consequences.**

UNWIND is a security layer for AI agents. Install it once, and every real-world action your agent takes — file writes, API calls, shell commands — is monitored, checked, and recorded. If something goes wrong, you'll know. If it changes a file, you can rewind it in one click.

Check on your agent from your phone. Green light means everything's fine. Amber means something needs your attention. Red means something was blocked.

No AI in the security path. Your agent doesn't know UNWIND exists.

![UNWIND Dashboard](https://raw.githubusercontent.com/unwind-mcp/unwind/main/unwind/dashboard/static/dashboard-preview.jpg)

## Install

**OpenClaw users** — tell your agent:

> Install the UNWIND security engine with `pip install unwind-mcp`, then install the experimental OpenClaw adapter from this repo with `openclaw plugins install ./openclaw-adapter`. Restart the gateway when done.

Or manually:

```bash
pip install unwind-mcp
openclaw plugins install ./openclaw-adapter
```

**Just want to watch first?** Ghost Mode shows you what your agent would do, without letting it do anything:

```bash
pip install ghostmode
ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents
```

**MCP clients** (Claude Desktop, Cursor, Windsurf, VS Code):

```bash
pip install unwind-mcp
unwind serve -- npx @modelcontextprotocol/server-filesystem ~/Documents
```

Point your client at UNWIND instead of the upstream server. The agent doesn't know it's there.

## What You Get

- **Trust Light** — a green, amber, or red indicator that tells you at a glance whether your agent is operating normally. Check it from your phone.
- **Timeline** — every action your agent took, when, and whether it was allowed. Expandable detail on each event. Scroll through it on mobile.
- **Rewind** — before every file write, UNWIND takes a snapshot. Changed your mind? One click to restore.
- **While You Were Away** — a summary of what happened while you weren't watching, with anything that needs your attention highlighted.
- **Ghost Mode** — test untrusted tools or risky prompts without consequences. Your agent thinks it worked, but nothing real changed.

**Advanced controls:** [trusted source rules](docs/TRUSTED_SOURCE_RULES.md) for scheduled tasks, [15-stage deterministic pipeline](docs/ARCHITECTURE.md), [tamper-evident audit chain](https://pypi.org/project/craft-auth/).

## Dashboard

Open `http://your-machine:9001` from any browser — including your phone.

```bash
unwind dashboard
```

See what your agent is doing now, review what happened while you were away, undo file changes, toggle Ghost Mode, and verify the audit chain — all from one mobile-friendly page.

## Compatibility

One core engine, multiple adapters. UNWIND works with OpenClaw, standard MCP clients, and any agent framework that can route tool calls through a proxy or sidecar.

| Platform | Integration |
|----------|------------|
| OpenClaw | Native plugin (fail-closed) |
| Claude Desktop, Cursor, Windsurf, VS Code | MCP stdio proxy (drop-in) |
| LangChain, CrewAI, AutoGPT, custom agents | HTTP sidecar API (~50 lines) |

[Compatibility matrix →](docs/COMPATIBILITY_MATRIX.md)

## Packages

`pip install unwind-mcp` gives you **everything** — pipeline, dashboard, Ghost Mode, CRAFT chain, rewind, CLI. One install.

The standalone packages below are for people who want just one piece:

| Package | What | Install |
|---------|------|---------|
| [**ghostmode**](https://pypi.org/project/ghostmode/) | Dry-run proxy only (MIT, zero deps) | `pip install ghostmode` |
| [**craft-auth**](https://pypi.org/project/craft-auth/) | Transport auth library only (zero deps) | `pip install craft-auth && craft-auth demo` |

## Architecture

UNWIND is built on a six-layer security model, from immediate enforcement to deep cryptographic attestation:

| Layer | What it does | Status |
|-------|-------------|--------|
| **UNWIND** | 15-stage enforcement pipeline, flight recorder, trust light | Operational |
| **Rollback** | File-level smart snapshots with one-command undo | Operational |
| **Ghost Mode** | Dry-run sandbox with shadow VFS | Operational |
| **CRAFT** | Transport-layer auth + tamper-evident hash chain | Operational |
| **CADENCE** | Temporal anomaly detection (timing-based) | Live prototype |
| **CRIP** | Consent protocol for rhythm data | Verify |

[Full architecture →](docs/SIX_LAYER_ALIGNMENT.md) · [Pipeline stages →](docs/ARCHITECTURE.md) · [Threat model →](docs/THREAT_MODEL_BOUNDARIES.md)

## CLI

```
unwind serve -- <command>      MCP stdio proxy
unwind status                  Trust state + recent events
unwind log [--since TIME]      Event timeline
unwind verify                  Hash chain integrity check
unwind undo last|ID|--since    Rollback actions
unwind dashboard               Web UI
unwind ask "question"          Natural language query
unwind export json|html        Export events
unwind anchor                  Chain checkpoint
unwind tamper-check            Tamper detection report
```

[CLI reference →](docs/CLI_REFERENCE.md)

## Development

```bash
git clone https://github.com/unwind-mcp/unwind
cd unwind
pip install -e ".[dev]"
pytest    # 1,859 tests
```

[Contributing →](CONTRIBUTING.md) · [Security policy →](SECURITY.md) · [Changelog →](CHANGELOG.md)

## License

AGPL-3.0-or-later (Ghost Mode is MIT)

---

[PyPI](https://pypi.org/project/unwind-mcp/) · [Ghost Mode](https://pypi.org/project/ghostmode/) · [CRAFT](https://pypi.org/project/craft-auth/) · [Dashboard Demo](docs/screenshots/) · [Architecture](docs/SIX_LAYER_ALIGNMENT.md) · [Threat Model](docs/THREAT_MODEL_BOUNDARIES.md) · [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md)
