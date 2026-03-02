# UNWIND

**See Everything. Undo Anything. Test Anything Safely.**

One core security engine, multiple adapters. UNWIND makes AI agents observable, enforceable, and reversible — regardless of which platform runs them.

No LLM in the hot path. Every check is deterministic. Sub-millisecond overhead on clean calls. Framework-agnostic — zero coupling to any specific agent platform.

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                     CRAFT Protocol (v4.2)                       │
    │  Transport-layer command provenance + anti-spoofing             │
    │  HKDF key schedule · HMAC envelopes · strict FIFO · cap tokens │
    └──────────────────────────────┬──────────────────────────────────┘
                                   │ authenticated command stream
    ┌──────────────────────────────┴──────────────────────────────────┐
    │                      UNWIND Core Engine                         │
    │                                                                 │
    │  Enforcement Pipeline (15 stages, <10ms)                        │
    │  Flight Recorder (SQLite + CR-AFT chain)                        │
    │  Smart Snapshots (reflink-first, 25MB)                          │
    │  Rollback Engine (undo any action)                              │
    │  Trust Light (green / amber / red)                              │
    └──────────┬──────────────────────────────────┬───────────────────┘
               │                                  │
    ┌──────────┴───────────┐           ┌──────────┴──────────────────┐
    │  OpenClaw Adapter    │           │  MCP Stdio Proxy Adapter    │
    │  (native plugin hook)│           │  (command-chain wrapper)    │
    │                      │           │                             │
    │  before_tool_call    │           │  Agent → UNWIND → Server   │
    │  after_tool_call     │           │  (stdio JSON-RPC 2.0)      │
    │  fail-closed policy  │           │                             │
    └──────────────────────┘           └─────────────────────────────┘
```

## Two Products, One Codebase

| | **Ghost Mode** | **UNWIND** |
|---|---|---|
| What it does | See what your agent would do | See, control, undo, and audit |
| Enforcement | Write blocking only | 15-stage+substage pipeline |
| Transport auth | No | CRAFT protocol (command provenance + anti-spoofing) |
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

UNWIND's core engine is framework-agnostic. The Python codebase has zero imports from any agent platform — no OpenClaw SDK, no MCP library, no framework-specific dependencies. Integration happens at the adapter boundary, not in the engine.

**Three integration paths:**

| Path | How it works | Code needed |
|------|-------------|-------------|
| **MCP stdio proxy** | `unwind serve -- <command>` wraps any MCP server | Zero — out of the box |
| **HTTP sidecar API** | POST `{toolName, params}` to `/v1/policy/check`, get back `ALLOW\|BLOCK\|MUTATE\|CHALLENGE` | ~50 lines in any language |
| **OpenClaw plugin** | Native `before_tool_call` / `after_tool_call` hooks | Zero — adapter ships with UNWIND |

**Platform compatibility:**

| Platform | Integration | Install |
|----------|-------------|---------|
| Claude Desktop | MCP stdio proxy | `pip install unwind-mcp` + config |
| Cursor | MCP stdio proxy | `pip install unwind-mcp` + config |
| Windsurf | MCP stdio proxy | `pip install unwind-mcp` + config |
| VS Code (Copilot) | MCP stdio proxy | `pip install unwind-mcp` + config |
| OpenClaw | Native plugin | `pip install unwind-mcp` + `openclaw plugins install` |
| LangChain / CrewAI / AutoGPT / Haystack | HTTP sidecar API | `pip install unwind-mcp` + adapter code |
| Custom Python agents | HTTP sidecar API or `UnwindProxy` class | `pip install unwind-mcp` + integration |
| Non-Python agents | HTTP sidecar API | `pip install unwind-mcp` + HTTP calls |

See `docs/COMPATIBILITY_MATRIX.md` for details.

## Why UNWIND Exists

AI agents can read your email, write files, send messages, and call APIs. When something goes wrong — a prompt injection, a hallucinated command, an overeager automation — there's no audit trail, no undo button, and no way to know what happened while you were away.

UNWIND fixes that.

## What It Does

### The Flight Recorder
Every tool call is logged to a tamper-evident SQLite database with SHA-256 hash chaining (CR-AFT). Parameters are hashed, not stored — the audit trail proves what happened without leaking secrets.

### The CRAFT Protocol (Transport-Layer Security)

CRAFT (Cryptographic Relay Authentication for Faithful Transmission) sits at the front of the ingress path, authenticating every command before it reaches the enforcement pipeline. It provides cryptographic proof of who sent a command, that it hasn't been tampered with, and that it's in the correct sequence. CRAFT uses HKDF-derived directional keys, HMAC-SHA256 envelope authentication, strict FIFO state commitment chains, and issuer-authenticated capability tokens for scoped tool delegation. See `docs/CRAFT_Protocol_v4.2.md` for the full specification.

CRAFT does not claim to solve prompt injection. It solves transport-layer command spoofing, relay tampering, replay attacks, session hijacking, and confused-deputy misuse — making the downstream pipeline's job easier by guaranteeing the commands it processes are genuine.

### The Enforcement Pipeline

15 deterministic checks/sub-stages run on every tool call, in order:

1. **0a Session Kill** — immediate termination check (canary triggered, break-glass, admin kill)
2. **0b Supply Chain** — pre-RBAC trust gate (plugin/tool provenance verification)
3. **1 Canary** — honeypot tripwire (fake high-sensitivity tools; if called, instant session kill)
4. **2 Self-Protection** — blocks access to UNWIND's own data (`.unwind/`)
5. **2b Exec Tunnel** — detects shell/exec invocations disguised as safe tool calls
6. **2c Credential Exposure** — pre-execution parameter scan for secrets in outbound args
7. **3 Path Jail** — confines filesystem access to the workspace root (canonicalisation + symlink resolution)
8. **3b Ghost Egress Guard** — blocks network reads in Ghost Mode before DNS resolution
9. **4 SSRF Shield** — DNS resolve + IP block (private IPs, cloud metadata, IPv6 transition bypasses per CVE-2026-26322, non-standard IPv4 forms)
10. **4b Egress Policy** — domain-level enforcement (metadata endpoints, internal ranges, denylists)
11. **5 DLP-Lite** — scans egress for API keys, JWTs, PEM certs, high-entropy blobs (Shannon entropy gate)
12. **6 Circuit Breaker** — rate-limits rapid state-modifying calls
13. **7 Taint Tracking** — marks sessions that ingested external content (email, web, etc.)
14. **8 Session Scope** — per-session tool allowlists
15. **9 Ghost Mode Gate** — dry-run mode with shadow VFS for read-after-write fidelity

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
Test untrusted tools or risky prompts without consequences. All state-modifying calls are logged but not executed. A shadow VFS serves back "written" content on subsequent reads, so the agent stays consistent. An egress guard scans outbound URLs and search queries for known secret patterns (API key formats, high-entropy strings) before they leave. Available as a standalone package (`pip install ghostmode`) or as part of UNWIND.

**Ghost Mode vs Amber Challenges:** Ghost Mode is a sandbox — "what would happen?" with fake success, nothing real changes. Amber challenges are a pause — "are you sure?" before executing a high-risk action for real. They are architecturally distinct.

### Cadence (Temporal Awareness)
Your agent learns your rhythm — when you're focused, when you're away, when you're reading. Cadence watches timing patterns (never content) and feeds trust signals into the enforcement pipeline. If someone fires tool calls at machine speed while you're away, it triggers an amber challenge. Enable with `UNWIND_CADENCE_BRIDGE=1`. All timing data stays on your device (enforced by the CRIP consent protocol), auto-deletes in 7 days, and UNWIND works fully without it.

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

Two layers, one engine, multiple adapters.

**CRAFT (transport layer):** Authenticates command provenance at the front of the ingress path. Every command is MAC'd, sequenced, and state-chained before it reaches the enforcement pipeline. Capability tokens gate privileged tool execution. CRAFT sits between the client and the proxy; the pipeline never sees an unauthenticated command.

**UNWIND (enforcement layer):** The 15-stage pipeline, flight recorder, snapshot engine, and trust logic are shared across all integration paths. Only the adapter layer changes. The core Python engine has zero framework imports — it takes generic `{tool_name, target, parameters}` inputs and returns `{decision}` outputs. Any agent framework that can serialize a tool call to JSON can use it.

**HTTP sidecar API:** The universal integration point. Any language, any framework — POST a tool call to `/v1/policy/check`, get back an enforcement decision. This is how the OpenClaw adapter communicates with the engine, and it's the same API available to any other integration.

**MCP stdio proxy adapter:** UNWIND wraps the upstream MCP server process, intercepting JSON-RPC messages on stdin/stdout. The agent talks to UNWIND; UNWIND talks to the real server.

**OpenClaw adapter:** A TypeScript plugin hooks into OpenClaw's native `before_tool_call` / `after_tool_call` system. The plugin communicates with the sidecar API. Fail-closed — if the sidecar is unreachable, the plugin blocks the tool call.

All adapters enforce the same policy, produce the same telemetry, and use the same rollback infrastructure.

## Security Model and Limits

UNWIND focuses on practical risk reduction through deterministic enforcement and reversibility. Designed for real-world developer and SME environments where most threats are accidental or opportunistic.

**Mitigates:** transport-layer spoofing/replay/tampering (CRAFT), accidental destructive tool use, prompt-injection-triggered exfiltration, opportunistic data leakage (DLP-lite), runaway automation (circuit breaker), unobserved autonomous sessions (taint + trust light).

**Does not defend against:** host OS / Python runtime / MCP client compromise, determined adversary with full system access, side-channel attacks on the proxy process. UNWIND is a user-space enforcement layer, not a trusted execution environment.

**Adapter notes:** OpenClaw plugin slash commands bypass the tool loop. The adapter enforces fail-closed — sidecar errors block, never allow. MCP stdio proxy fully mediates agent-to-server communication.

See `docs/THREAT_MODEL_BOUNDARIES.md` for the full threat model, and `SECURITY_COVERAGE.md` for the attack-to-check mapping.

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
docs/
├── CRAFT_Protocol_v4.2.md     # CRAFT specification (signed off, live on hardware)
├── CRAFT_Protocol_v4.2.docx   # Formatted spec for external review
└── ...                        # Compatibility matrix, security coverage, etc.

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

AGPL-3.0-or-later
