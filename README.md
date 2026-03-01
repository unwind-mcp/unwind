# UNWIND

**See Everything. Undo Anything. Test Anything Safely.**

One core security engine, multiple adapters. UNWIND makes AI agents observable, enforceable, and reversible — regardless of which platform runs them.

No LLM in the hot path. Every check is deterministic. Sub-millisecond overhead on clean calls.

```
                    ┌─────────────────────────────────────────┐
                    │          UNWIND Core Engine              │
                    │                                         │
                    │  Enforcement Pipeline (13 checks, <10ms)│
                    │  Flight Recorder (SQLite + CR-AFT chain)│
                    │  Smart Snapshots (reflink-first, 25MB)  │
                    │  Rollback Engine (undo any action)       │
                    │  Trust Light (green / amber / red)       │
                    └──────────┬──────────────┬───────────────┘
                               │              │
                ┌──────────────┘              └──────────────┐
                │                                            │
    ┌───────────┴───────────┐              ┌─────────────────┴──────────┐
    │  OpenClaw Adapter     │              │  MCP Stdio Proxy Adapter   │
    │  (native plugin hook) │              │  (command-chain wrapper)   │
    │                       │              │                            │
    │  before_tool_call     │              │  Agent → UNWIND → Server   │
    │  after_tool_call      │              │  (stdio JSON-RPC 2.0)     │
    │  fail-closed policy   │              │                            │
    └───────────────────────┘              └────────────────────────────┘
```

## Two Products, One Codebase

| | **Ghost Mode** | **UNWIND** |
|---|---|---|
| What it does | See what your agent would do | See, control, undo, and audit |
| Enforcement | Write blocking only | 15-stage+substage pipeline |
| Rollback | No | Yes (smart snapshots) |
| Audit chain | No | CR-AFT hash chain |
| Dashboard | No | Web UI with trust light |
| Price | Free | Open core (free core, enterprise dashboard) |

**Ghost Mode** is the entry point — zero risk, instant value. **UNWIND** is the full security suite for when you need control, not just visibility.

## Quick Start

### OpenClaw Users

OpenClaw users can ask their agent to perform the install end-to-end — plugin install, sidecar setup, gateway restart — then verify with a built-in smoke check. Tell it:

> Install the UNWIND security plugin. The Python engine is at `pip install unwind-mcp` and the OpenClaw adapter is at `openclaw plugins install @unwind/openclaw-adapter`. Restart the gateway when done.

Or step by step:

```bash
# 1. Install the Python security engine
pip install unwind-mcp

# 2. Install the OpenClaw plugin adapter
openclaw plugins install @unwind/openclaw-adapter

# 3. Restart the gateway
```

UNWIND hooks into OpenClaw's native `before_tool_call` / `after_tool_call` plugin system. Every tool call passes through the enforcement engine. Fail-closed — if anything goes wrong, the call is blocked, not allowed.

### MCP Client Users (Claude Desktop, Cursor, etc.)

```bash
pip install unwind-mcp
unwind serve -- npx @modelcontextprotocol/server-filesystem ~/Documents
```

Point your MCP client at UNWIND instead of the upstream server. In your client config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "unwind",
      "args": ["serve", "--", "npx", "@modelcontextprotocol/server-filesystem", "~/Documents"]
    }
  }
}
```

The agent doesn't know UNWIND exists.

### Ghost Mode (just watching — any platform)

```bash
pip install ghostmode
ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents
```

Reads pass through. Writes get intercepted. When the session ends, you see everything the agent tried to do. Nothing was modified.

## Compatibility

| Platform | Adapter | Install |
|----------|---------|---------|
| OpenClaw | Native plugin (before_tool_call hook) | pip + openclaw plugins install |
| Claude Desktop | MCP stdio proxy | pip + config change |
| Cursor | MCP stdio proxy | pip + config change |
| Windsurf | MCP stdio proxy | pip + config change |
| VS Code (Copilot) | MCP stdio proxy | pip + config change |
| Any MCP client with stdio server config | MCP stdio proxy | pip + config change |

See `docs/COMPATIBILITY_MATRIX.md` for details.

## Why UNWIND Exists

AI agents can read your email, write files, send messages, and call APIs. When something goes wrong — a prompt injection, a hallucinated command, an overeager automation — there's no audit trail, no undo button, and no way to know what happened while you were away.

UNWIND fixes that.

## What It Does

### The Flight Recorder
Every tool call is logged to a tamper-evident SQLite database with SHA-256 hash chaining (CR-AFT). Parameters are hashed, not stored — the audit trail proves what happened without leaking secrets.

### The Enforcement Pipeline
15 deterministic checks/sub-stages run on every tool call, in order:

1. **Self-Protection** — blocks access to UNWIND's own data (`.unwind/`)
2. **Path Jail** — confines filesystem access to the workspace root
3. **SSRF Shield** — blocks requests to private IPs, cloud metadata, IPv6 transition bypasses (NAT64, 6to4, Teredo per CVE-2026-26322), non-standard IPv4 forms (octal, hex, short)
4. **DLP-Lite** — scans egress for API keys, JWTs, PEM certs, high-entropy blobs (Shannon entropy gate)
5. **Circuit Breaker** — rate-limits rapid state-modifying calls
6. **Taint Tracking** — marks sessions that ingested external content (email, web, etc.)
7. **Session Scope** — per-session tool allowlists
8. **Canary Honeypot** — fake high-sensitivity tools injected into the manifest; if called, instant session kill
9. **Ghost Mode Gate** — dry-run mode with shadow VFS for read-after-write fidelity

### The Undo Button
Smart snapshots are captured before every state-modifying action. Reflink-first (instant on APFS/btrfs), falling back to copy, with a 25MB cap and atomic moves for deletions.

```bash
unwind undo last              # Undo the most recent action
unwind undo evt_abc123        # Undo a specific event
unwind undo --since "2h"      # Undo everything in the last 2 hours
unwind undo --since "3pm"     # Undo everything since 3pm
```

### The Trust Light
A real-time indicator of session health:

- **Green** — all clear, routine operations
- **Amber** — tainted session (external content ingested), high-risk actuators need confirmation
- **Red** — action blocked, circuit breaker tripped, or canary triggered

Taint uses graduated decay (120s per level, with clean-op gating), typically clearing over ~6–8 minutes under normal traffic.

### The Dashboard
A web UI with a glowing trust orb, event timeline, Away Mode summary, and chain verification.

```bash
unwind dashboard              # Launch at http://127.0.0.1:9001
```

### Ghost Mode
Test untrusted tools or risky prompts without consequences. All state-modifying calls are logged but not executed. A shadow VFS serves back "written" content on subsequent reads, so the agent stays consistent. Available as a standalone package (`pip install ghostmode`) or as part of UNWIND.

### CR-AFT External Anchoring
Export the hash chain for third-party audit. Create periodic anchor checkpoints. Detect tampering across the full event history.

```bash
unwind verify                 # Check chain integrity
unwind anchor                 # Create a checkpoint
unwind tamper-check           # Full tamper detection report
unwind export html -o audit.html  # Printable audit report
```

### Conversational Interface
Ask questions about agent activity in plain English:

```bash
unwind ask "what happened today?"
unwind ask "how many emails were sent this morning?"
unwind ask "were any actions blocked?"
```

## Architecture

One core engine, multiple adapters. The enforcement pipeline, flight recorder, snapshot engine, and trust logic are shared across all integration paths. Only the adapter layer changes.

**OpenClaw adapter:** A TypeScript plugin hooks into OpenClaw's native `before_tool_call` / `after_tool_call` system. The plugin communicates with a local Python sidecar running the UNWIND engine. Fail-closed — if the sidecar is unreachable, the plugin blocks the tool call.

**MCP stdio proxy adapter:** UNWIND wraps the upstream MCP server process, intercepting JSON-RPC messages on stdin/stdout. The agent talks to UNWIND; UNWIND talks to the real server.

Both adapters enforce the same policy, produce the same telemetry, and use the same rollback infrastructure.

## Security Model and Limits

UNWIND focuses on practical risk reduction through deterministic enforcement and reversibility. It is designed for real-world developer and SME environments where most threats are accidental or opportunistic.

**Designed to mitigate:**

- Accidental destructive tool use (wrong file deleted, unintended email sent)
- Prompt-injection-triggered misuse (hostile content causes agent to exfiltrate data)
- Opportunistic data exfiltration (API keys, credentials, PEM certs in outbound payloads)
- Runaway automation (rapid-fire state modifications without human oversight)
- Unobserved autonomous sessions (agent acts while user is away)

**Not designed to defend against:**

- Kernel-level compromise
- Fully compromised host operating system
- Determined adversary with full system access
- Side-channel attacks on the proxy process itself

**Adapter-specific considerations:**

- **OpenClaw adapter:** Plugin slash commands bypass the tool loop and are not intercepted by `before_tool_call`. The adapter enforces fail-closed policy mode — sidecar errors result in blocked calls, never silent allows.
- **MCP stdio proxy:** The agent cannot access upstream servers without passing through the proxy. Self-protection checks guard UNWIND's own data directory.

UNWIND reduces the practical attack surface for agent-driven operations. It is not a guarantee against all possible threats — it is a meaningful layer of defence that makes agent actions visible, enforceable, and recoverable.

## Security Coverage

UNWIND maintains a `SECURITY_COVERAGE.md` mapping every attack category to the specific check, test, and CVE reference that covers it. Currently 36+ coverage entries across path traversal, SSRF (including IPv6 transition bypasses), DLP, canary honeypots, taint tracking, and more.

## CLI Reference

```
unwind serve -- <command>     Start the MCP stdio proxy adapter
unwind sidecar serve          Start the OpenClaw sidecar (managed by plugin)
unwind status                 Trust state + recent high-risk events
unwind log [--since TIME]     Event timeline
unwind verify                 CR-AFT chain integrity check
unwind undo last|ID|--since   Rollback actions
unwind dashboard [--port N]   Web UI
unwind ask "question"         Natural language query
unwind export json|jsonl|html Export events
unwind anchor                 CR-AFT checkpoint
unwind tamper-check           Tamper detection report
```

```
ghostmode -- <command>         Dry-run proxy (standalone)
ghostmode -v -- <command>      Verbose mode
ghostmode --export log.json    Export session on exit
```

## Configuration

UNWIND uses sensible defaults. Override via environment variables:

```bash
UNWIND_HOME=~/.unwind          # Data directory
UNWIND_WORKSPACE=~/workspace   # Path jail root
```

## Project Structure

```
unwind/                        # Core security engine (pip install unwind-mcp)
├── enforcement/               # 15-stage+substage pipeline (path jail, SSRF, DLP, canary...)
├── recorder/event_store.py    # SQLite flight recorder (WAL + CR-AFT chain)
├── snapshots/                 # Smart snapshots + rollback engine
├── sidecar/                   # OpenClaw adapter sidecar (local policy server)
├── transport/stdio.py         # MCP stdio proxy adapter
├── dashboard/                 # Flask web UI + Away Mode
├── anchoring/                 # CR-AFT external anchoring + tamper detection
├── conversational/            # Natural language query interface
├── export/                    # JSON, JSONL, HTML report export
└── cli/main.py                # CLI entry point

openclaw-adapter/              # OpenClaw native plugin (TypeScript)
├── src/hooks/                 # before_tool_call / after_tool_call handlers
├── src/service/               # Sidecar lifecycle manager
├── src/ipc/                   # Sidecar communication client
├── openclaw.plugin.json       # Plugin manifest
└── package.json               # Node package config

ghostmode/                     # Standalone dry-run proxy (pip install ghostmode)
├── proxy.py                   # Write-blocking proxy + shadow VFS
├── shadow_vfs.py              # In-memory filesystem overlay
├── event_log.py               # Lightweight session recorder
└── cli.py                     # One-command entry point

tests/                         # 1,702 tests across all packages (Pi, 2026-03-01)
```

## Development

```bash
git clone https://github.com/unwind-mcp/unwind
cd unwind
pip install -e ".[dev]"
pytest                         # 1,702 tests (Pi, 2026-03-01)
```

## Development Discipline

- One PR = one intent: **refactor OR feature/fix**, never both in the same PR.
- For any Tier A security-path change, include this checklist in the commit message:
  - fail-closed: yes/no
  - path jail order: unchanged/changed
  - ghost semantics: unchanged/changed
  - CRAFT chain: verified/not applicable
  - rollback: unchanged/changed
- Mandatory checks:
  - `pytest -q` passes
  - `unwind verify` is clean (Tier A changes)
- One bug = one regression test.
- Pin adapter contract in tested constants (not scattered assumptions):
  - tool mapping: `write→fs_write`, `read→fs_read`, `edit→fs_write`
  - param expectations: `path`, `content`
- Deferred until multi-contributor stage:
  - RFC template / PR template / formal review workflow / extra process docs

## License

MIT
