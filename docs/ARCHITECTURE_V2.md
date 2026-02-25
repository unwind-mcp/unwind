# Architecture V2: One Core Engine, Multiple Adapters

**Updated:** 23 February 2026

## Overview

UNWIND's architecture separates the security engine from the integration layer. The core engine handles all policy decisions, telemetry, rollback, and audit. Adapters handle how the engine connects to a specific host platform.

```
┌──────────────────────────────────────────────┐
│              UNWIND Core Engine               │
│                                               │
│  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Enforcement  │  │ Flight Recorder      │   │
│  │ Pipeline     │  │ (SQLite + CR-AFT)    │   │
│  │ (13 stages)  │  └──────────────────────┘   │
│  └─────────────┘                              │
│  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Amber       │  │ Snapshot + Rollback  │   │
│  │ Mediator    │  │ Engine               │   │
│  └─────────────┘  └──────────────────────┘   │
│  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Telemetry   │  │ Trust Light          │   │
│  │ Chain       │  │ (green/amber/red)    │   │
│  └─────────────┘  └──────────────────────┘   │
└──────────┬───────────────────┬───────────────┘
           │                   │
    ┌──────┴──────┐     ┌──────┴──────┐
    │  Adapter A  │     │  Adapter B  │
    │  OpenClaw   │     │  MCP Stdio  │
    │  Plugin     │     │  Proxy      │
    └─────────────┘     └─────────────┘
```

## Core Engine (shared)

Lives in `unwind/` Python package. Adapter-agnostic.

### Enforcement Pipeline (`unwind/enforcement/`)
13 deterministic stages, <10ms total. No LLM calls. Stages include self-protection, path jail, SSRF shield, DLP-Lite, circuit breaker, taint tracking, session scope, canary honeypots, and ghost mode gate.

### Amber Mediator (`unwind/enforcement/amber_store.py`, `amber_telemetry.py`, `amber_rollout.py`)
Graduated trust with persistence. Challenges for high-risk actions. Replay defence. Telemetry chain with 5 event types.

### Flight Recorder (`unwind/recorder/`)
SQLite with WAL mode. CR-AFT hash chain for tamper evidence. Parameters hashed, not stored.

### Snapshot + Rollback (`unwind/snapshots/`)
Reflink-first smart snapshots. Atomic moves for deletions. 25MB cap. Rollback by event ID, time range, or "last."

### Trust Light
Real-time session health: green (clear), amber (tainted, needs confirmation), red (blocked/tripped).

## Adapter A: OpenClaw Plugin (primary target)

Lives in `openclaw-adapter/` (TypeScript) + `unwind/sidecar/` (Python).

### How it works

1. OpenClaw calls `before_tool_call` on every tool execution in the agent loop
2. The TS plugin receives `toolName`, `params`, `agentId`, `sessionKey`
3. Plugin sends a policy check request to the Python sidecar via local HTTP
4. Sidecar runs the enforcement pipeline and returns allow/block/mutate
5. Plugin returns the decision to OpenClaw
6. On `after_tool_call`, plugin sends telemetry to sidecar for audit logging

### Sidecar lifecycle

The plugin uses OpenClaw's `registerService` to manage the Python sidecar:

- **gateway_start**: Plugin spawns the sidecar process, waits for health check
- **gateway_stop**: Plugin sends shutdown signal to sidecar
- **Health monitoring**: Periodic checks; if sidecar is down, all tool calls are blocked

### Fail-closed contract

- Sidecar unreachable → block
- Sidecar timeout (configurable, default 500ms) → block
- Sidecar error response → block
- Plugin exception (should never happen) → OpenClaw catches and continues (fail-open) — this is why exceptions must never escape the handler
- Sidecar process crash → detected by health check → block until restart

### Limitations

- Plugin slash commands bypass the tool loop — not intercepted
- No principal/account ID in hook context — session mapping in sidecar
- Plugin API may change across OpenClaw versions — pin version

## Adapter B: MCP Stdio Proxy (secondary)

Lives in `unwind/transport/stdio.py`.

### How it works

1. UNWIND spawns the upstream MCP server as a subprocess
2. Agent connects to UNWIND via stdin/stdout (JSON-RPC 2.0)
3. UNWIND intercepts every request, runs enforcement pipeline
4. Allowed requests are forwarded to upstream; responses returned to agent
5. Blocked requests get a JSON-RPC error response

### Fail-closed by architecture

If UNWIND crashes, the upstream server is unreachable (it was spawned as a child process). No implicit bypass path.

### Limitations

- Requires MCP client that supports command-based server launch config
- Does not work with OpenClaw (MCP transport disabled in ACP)

## Shared guarantees (both adapters)

- Same 13-stage enforcement pipeline
- Same telemetry event format
- Same CR-AFT audit chain
- Same rollback infrastructure
- Same trust light semantics
- Same amber mediator protocol

## What differs between adapters

| Aspect | OpenClaw Plugin | MCP Stdio Proxy |
|--------|----------------|-----------------|
| Language | TypeScript + Python sidecar | Python only |
| Integration | In-process hook | Process wrapping |
| Fail-closed mechanism | Explicit in handler code | Architectural (child process) |
| Coverage gaps | Slash commands | None (all traffic via proxy) |
| Principal ID | Not available in hook | Available in MCP session |
| Install complexity | 3 steps (pip + plugin + restart) | 2 steps (pip + config) |
