# Ghost Mode

**See what your AI agent would do, without letting it do anything.**

Ghost Mode is a safe first step before giving an AI agent real authority.

It's a zero-config dry-run layer for AI agents. It intercepts every write and lets reads through. Think of it as a flight simulator for AI agents — nothing gets modified, but you see everything the agent tried to do.

Requires Python 3.9+.

## Quick Start

### MCP Client Users (Claude Desktop, Cursor, etc.)

```bash
pip install ghostmode
ghostmode -- npx @modelcontextprotocol/server-filesystem ~/Documents
```

Point your agent at Ghost Mode instead of the real server. When the session ends, a summary is written to `ghostmode-summary.txt` in your working directory and printed to stderr.

### OpenClaw Users

```bash
# 1. Install Ghost Mode
pip install ghostmode

# 2. Install the OpenClaw plugin
openclaw plugins install @unwind/ghostmode-openclaw

# 3. Restart the gateway
```

Ghost Mode hooks into OpenClaw's tool-call system. Every write is intercepted. Every read passes through.

## What it does

Ghost Mode intercepts state-modifying tool calls — file writes, deletions, emails, API posts, shell commands — and returns fake success responses. The agent thinks it completed the action. Your filesystem, email, and APIs are untouched.

A shadow virtual filesystem keeps the agent consistent: if it "writes" a file and then reads it back, Ghost Mode serves the written content from memory. The agent doesn't know it's in a sandbox.

## Example output

```
=======================================================
  GHOST MODE SESSION SUMMARY
=======================================================
  Duration:     47.3s
  Total events: 12
  Intercepted:  4 writes blocked
  Passed:       7 reads forwarded
  Shadow reads: 1 served from VFS

  Files the agent tried to write:
    /home/user/Documents/report.md
    /home/user/Documents/summary.txt

  Files the agent tried to delete:
    /home/user/Documents/old_draft.md

  4 write(s) were blocked. Nothing was modified.

  Full timeline:
  14:23:01  [PASSED]  fs_read  /home/user/Documents/notes.txt
  14:23:02  [PASSED]  fs_list  /home/user/Documents
  14:23:03  [BLOCKED] fs_write /home/user/Documents/report.md
  14:23:04  [SHADOW]  fs_read  /home/user/Documents/report.md
  14:23:05  [BLOCKED] fs_delete /home/user/Documents/old_draft.md
  14:23:06  [BLOCKED] send_email
  14:23:07  [PASSED]  fs_read  /home/user/Documents/config.json
=======================================================
```

## Use cases

**Testing untrusted tools.** Install a new MCP server and see what it actually does before giving it real access.

**Reviewing agent behaviour.** Let your agent plan and "execute" a complex task, then review the timeline before running it for real.

**Demos and training.** Show stakeholders what an AI agent workflow looks like without risking real data.

**Compliance dry runs.** Verify that an agent workflow stays within policy boundaries before going live.

## What Ghost Mode is not

Ghost Mode does not enforce policy or provide rollback. It is a visibility tool, not a security system. If you need enforcement, audit trails, or recovery, that's what [UNWIND](https://github.com/unwind-mcp/unwind) is for.

## CLI options (MCP proxy mode)

```
ghostmode -- <upstream command>        Basic usage
ghostmode -v -- <command>              Verbose: log every action to stderr
ghostmode --export log.json -- <cmd>   Export session log on exit
ghostmode --also-block my_tool -- ...  Add custom tool names to intercept
```

## How it knows what to block

Ghost Mode recognises 50+ common MCP tool names as state-modifying (filesystem writes, email sends, API posts, shell commands, database mutations, git operations). It also uses prefix heuristics: any tool starting with `create_`, `delete_`, `send_`, `write_`, `execute_`, etc. gets intercepted. The block list is heuristic-based and configurable.

If a tool slips through, use `--also-block tool_name` to add it.

## Zero dependencies

Ghost Mode has no external dependencies. It uses only Python 3.9+ stdlib (asyncio, json, pathlib). It installs in under a second.

## Known limitations

**Shell commands can't see ghost-written files.** If the agent writes a file through Ghost Mode and then tries to run it via `bash_exec` or `shell_exec`, the shell will fail because the file only exists in the in-memory shadow VFS, not on disk. Ghost Mode works best for tool-call-level dry runs, not multi-step build/execute workflows.

**Session summary in background clients.** Claude Desktop and Cursor run MCP servers in the background and may not surface stderr output. Ghost Mode automatically writes a `ghostmode-summary.txt` file to your working directory on exit. You can also use `--export log.json` for a machine-readable session log.

## Want more?

Ghost Mode shows you what happened. **UNWIND** lets you control it:

- 15-stage enforcement pipeline (path jail, SSRF shield, DLP, canary honeypots)
- Smart snapshots with one-command rollback
- CRAFT tamper-evident audit chain
- Real-time trust light dashboard
- Detects encoded/obfuscated data exfiltration attempts

```bash
pip install unwind-mcp
```

[github.com/unwind-mcp/unwind](https://github.com/unwind-mcp/unwind)

## License

MIT
