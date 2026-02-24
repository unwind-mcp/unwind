# UNWIND OpenClaw Adapter

OpenClaw-native plugin that mediates tool calls through the UNWIND security engine.

## Architecture

```
OpenClaw Gateway
  |
  ├── before_tool_call hook ──> TS adapter ──> Python sidecar (UNWIND engine)
  |                                              |
  |   <── allow / block / mutate ───────────────┘
  |
  └── after_tool_call hook ──> TS adapter ──> telemetry emission
```

## Install (target)

```bash
# 1. Install Python engine
pip install unwind-mcp

# 2. Install OpenClaw plugin
openclaw plugins install ./openclaw-adapter

# 3. Restart gateway
```

## Security Contract

- **Fail-closed**: If sidecar is unreachable, timed out, or returns an error, the adapter blocks the tool call. Never allows silently on uncertainty.
- **Exception safety**: All errors caught inside hook handler. OpenClaw's default behaviour on hook exception is fail-open (tool executes). We prevent this by never letting exceptions escape.
- **No principal ID**: OpenClaw hook context provides toolName, params, agentId, sessionKey — but no principal/account ID. Session-to-principal mapping is handled by the sidecar.

## Status

Scaffold only. Not yet functional. See TODO markers in source files.
