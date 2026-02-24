# Compatibility Matrix

**Updated:** 23 February 2026

## Adapter Paths

UNWIND uses one core security engine with two adapter paths. The adapter determines how UNWIND connects to the host platform. The enforcement logic, telemetry, rollback, and audit chain are identical regardless of adapter.

### OpenClaw Adapter (native plugin)

| | |
|---|---|
| **Integration** | OpenClaw `before_tool_call` / `after_tool_call` plugin hooks |
| **Runtime** | TypeScript plugin (in-process) + Python sidecar (out-of-process) |
| **Install** | `pip install unwind-mcp` + `openclaw plugins install @unwind/openclaw-adapter` + gateway restart |
| **Coverage** | All tool calls in the agent loop. Plugin slash commands bypass the tool loop and are not intercepted. |
| **Fail mode** | Fail-closed. Sidecar timeout, error, or unreachable = tool call blocked. |
| **Status** | Scaffold — not yet functional |

### MCP Stdio Proxy Adapter

| | |
|---|---|
| **Integration** | Wraps upstream MCP server process, intercepts JSON-RPC on stdin/stdout |
| **Runtime** | Python (single process) |
| **Install** | `pip install unwind-mcp` + update MCP client config to point at `unwind serve` |
| **Coverage** | All MCP tool calls (agent cannot reach upstream without passing through proxy) |
| **Fail mode** | Proxy process crash = upstream unreachable (implicit fail-closed) |
| **Status** | Functional — 1,027 tests passing |

## Platform Compatibility

| Platform | Adapter | Verified | Notes |
|----------|---------|----------|-------|
| OpenClaw (any OS) | OpenClaw plugin | Pending | Primary target. Plugin hooks verified from OpenClaw v2026.2.21-2 source. |
| Claude Desktop (Mac/Windows) | MCP stdio proxy | Pending | Standard mcpServers config. |
| Cursor | MCP stdio proxy | Pending | Standard mcpServers config. |
| Windsurf | MCP stdio proxy | Pending | Standard mcpServers config. |
| VS Code + Copilot | MCP stdio proxy | Pending | Standard mcpServers config. |
| Any MCP client with stdio server config | MCP stdio proxy | Pending | Should work if client supports command-based server launch. |

## What's NOT supported

| Platform / Mode | Reason |
|----------------|--------|
| OpenClaw via MCP server launch chaining | OpenClaw ACP has MCP transport disabled (`mcpCapabilities.http=false, sse=false`). It ignores `mcpServers` config. |
| MCP clients without stdio server config | No insertion point for proxy wrapping. |
| Non-MCP tool frameworks | UNWIND currently targets MCP and OpenClaw tool execution only. |

## OpenClaw-specific constraints

These are verified from OpenClaw v2026.2.21-2 and may change in future versions:

1. **No principal ID in hook context** — `before_tool_call` provides `toolName`, `params`, optional `agentId`, optional `sessionKey`. No account/principal ID. Session-to-principal mapping maintained by sidecar.
2. **Fail-open on exception** — if hook handler throws, OpenClaw catches and continues (tool executes). Adapter must catch all errors internally.
3. **Plugin slash commands bypass tool loop** — not interceptable via `before_tool_call`.
4. **Plugin API evolving** — changelog shows recent hook behaviour changes. Pin OpenClaw version for stability.
5. **Gateway restart required** after plugin install/config changes.
6. **Service start failures don't stop gateway** — logged and continued. Adapter must independently detect sidecar-down.
