"""Ghost Mode proxy — the write-blocking MCP middleware.

This is the entire Ghost Mode product in one class. It:
1. Intercepts all tool calls from the agent
2. Lets read-only calls through to upstream unchanged
3. Blocks state-modifying calls and returns fake success
4. Maintains a shadow VFS so reads after ghost-writes stay consistent
5. Logs everything the agent tried to do

No enforcement pipeline, no rollback engine, no hash chains.
Just: "see what it would do, without letting it do anything."

For the full security suite, upgrade to UNWIND.
"""

import asyncio
import json
import logging
import sys
import time
from typing import Any, Optional

from .shadow_vfs import ShadowVFS
from .event_log import GhostEventLog

logger = logging.getLogger("ghostmode")


# ── Tool Classification ──────────────────────────────────────────

# These tools modify state and will be intercepted
DEFAULT_WRITE_TOOLS = frozenset({
    # Filesystem
    "fs_write", "fs_delete", "fs_rename", "fs_mkdir", "fs_move", "fs_copy",
    "write_file", "delete_file", "rename_file", "move_file", "create_directory",
    # Communication
    "send_email", "post_message", "send_message", "reply_email",
    # Network writes
    "http_post", "http_put", "http_delete", "http_patch",
    "upload_file", "api_call", "webhook",
    # System
    "bash_exec", "shell_exec", "run_command", "execute_command",
    "install_package", "pip_install", "npm_install",
    # Calendar / Scheduling
    "create_calendar_event", "modify_calendar_event", "delete_calendar_event",
    "create_event", "update_event", "delete_event",
    # Database
    "db_insert", "db_update", "db_delete", "db_execute",
    "sql_execute", "query_execute",
    # Git
    "git_commit", "git_push", "git_checkout", "git_merge",
})

# Tools that look like writes based on naming patterns
WRITE_PREFIXES = ("create_", "delete_", "remove_", "update_", "modify_",
                  "send_", "post_", "put_", "write_", "set_", "insert_",
                  "drop_", "execute_", "run_", "install_", "push_")


def is_write_tool(tool_name: str, custom_writes: Optional[frozenset] = None) -> bool:
    """Determine if a tool modifies state.

    Uses explicit list + prefix heuristic. Errs on the side of blocking:
    if a tool looks like it might write, it gets intercepted.
    """
    if custom_writes and tool_name in custom_writes:
        return True
    if tool_name in DEFAULT_WRITE_TOOLS:
        return True
    # Prefix heuristic — catches tools we haven't explicitly listed
    return any(tool_name.startswith(prefix) for prefix in WRITE_PREFIXES)


# ── JSON-RPC Helpers ──────────────────────────────────────────────

def _make_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _make_error(id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


# ── Transport ─────────────────────────────────────────────────────

class StdioReader:
    """Read newline-delimited JSON from an asyncio StreamReader."""

    def __init__(self, reader: asyncio.StreamReader):
        self.reader = reader

    async def read(self) -> Optional[dict]:
        while True:
            try:
                line = await self.reader.readline()
            except (asyncio.CancelledError, ConnectionError):
                return None
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue


class StdioWriter:
    """Write newline-delimited JSON to an asyncio StreamWriter."""

    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        self._closed = False

    async def write(self, msg: dict) -> None:
        if self._closed:
            return
        try:
            self.writer.write((json.dumps(msg, separators=(",", ":")) + "\n").encode())
            await self.writer.drain()
        except (ConnectionError, BrokenPipeError, asyncio.CancelledError):
            self._closed = True

    async def close(self) -> None:
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


# ── Ghost Mode Proxy ──────────────────────────────────────────────

class GhostProxy:
    """The Ghost Mode MCP proxy.

    Sits between agent (stdin/stdout) and upstream (subprocess).
    Reads pass through. Writes get intercepted. Shadow VFS keeps
    the agent consistent.
    """

    def __init__(
        self,
        upstream_command: list[str],
        custom_write_tools: Optional[frozenset] = None,
        verbose: bool = False,
    ):
        self.upstream_command = upstream_command
        self.custom_write_tools = custom_write_tools
        self.verbose = verbose

        self.shadow = ShadowVFS()
        self.log = GhostEventLog()

        self._process: Optional[asyncio.subprocess.Process] = None
        self._agent_reader: Optional[StdioReader] = None
        self._agent_writer: Optional[StdioWriter] = None
        self._upstream_reader: Optional[StdioReader] = None
        self._upstream_writer: Optional[StdioWriter] = None

        self._pending: dict[int, Any] = {}
        self._upstream_id: int = 0
        self._shutdown = False

    def _next_id(self) -> int:
        self._upstream_id += 1
        return self._upstream_id

    def _is_write(self, tool_name: str) -> bool:
        return is_write_tool(tool_name, self.custom_write_tools)

    # ── Lifecycle ──

    async def start(self) -> None:
        """Start upstream and set up agent transport."""
        # Agent stdio
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        w_transport, w_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
        self._agent_reader = StdioReader(reader)
        self._agent_writer = StdioWriter(writer)

        # Upstream subprocess
        self._process = await asyncio.create_subprocess_exec(
            *self.upstream_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._upstream_reader = StdioReader(self._process.stdout)
        self._upstream_writer = StdioWriter(self._process.stdin)

        logger.info("Ghost Mode proxy started (upstream PID %d)", self._process.pid)

    async def run(self) -> None:
        """Main loop — run until agent disconnects."""
        await self.start()
        try:
            await asyncio.gather(
                self._agent_loop(),
                self._upstream_loop(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True

        # Print session summary to stderr
        self._print_summary()

        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()

        if self._agent_writer:
            await self._agent_writer.close()

        logger.info("Ghost Mode proxy shut down")

    def _print_summary(self) -> None:
        """Print session summary to stderr on shutdown."""
        summary = self.log.summary()
        shadow = self.shadow.summary()

        print("\n" + "=" * 55, file=sys.stderr)
        print("  \U0001f47b GHOST MODE SESSION SUMMARY", file=sys.stderr)
        print("=" * 55, file=sys.stderr)
        print(f"  Duration:     {summary['duration_seconds']}s", file=sys.stderr)
        print(f"  Total events: {summary['total_events']}", file=sys.stderr)
        print(f"  Intercepted:  {summary['intercepted']} writes blocked", file=sys.stderr)
        print(f"  Passed:       {summary['passed_through']} reads forwarded", file=sys.stderr)
        print(f"  Shadow reads: {summary['shadow_reads']} served from VFS", file=sys.stderr)

        if shadow["write_count"] > 0:
            print(f"\n  Files the agent tried to write:", file=sys.stderr)
            for f in shadow["files_written"]:
                print(f"    \U0001f4dd {f}", file=sys.stderr)

        if shadow["delete_count"] > 0:
            print(f"\n  Files the agent tried to delete:", file=sys.stderr)
            for f in shadow["files_deleted"]:
                print(f"    \U0001f5d1\ufe0f  {f}", file=sys.stderr)

        if summary["intercepted"] == 0:
            print("\n  \u2705 Agent performed no write operations.", file=sys.stderr)
        else:
            print(
                f"\n  \U0001f6ab {summary['intercepted']} write(s) were blocked. "
                f"Nothing was modified.",
                file=sys.stderr,
            )

        print("\n  Full timeline:", file=sys.stderr)
        print(self.log.format_timeline(), file=sys.stderr)
        print("\n  Full security suite: https://github.com/unwind-mcp/unwind", file=sys.stderr)
        print("=" * 55 + "\n", file=sys.stderr)

    # ── Agent → Proxy ──

    async def _agent_loop(self) -> None:
        while not self._shutdown:
            msg = await self._agent_reader.read()
            if msg is None:
                self._shutdown = True
                return

            method = msg.get("method")
            msg_id = msg.get("id")

            try:
                if method == "tools/call":
                    await self._handle_tool_call(msg)
                else:
                    await self._forward_to_upstream(msg)
            except Exception as e:
                logger.error("Error handling agent message: %s", e, exc_info=True)
                if msg_id is not None:
                    await self._agent_writer.write(
                        _make_error(msg_id, -32603, f"Ghost proxy error: {e}")
                    )

    async def _handle_tool_call(self, msg: dict) -> None:
        """The ghost gate — intercept writes, pass reads."""
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        msg_id = msg.get("id")

        # Extract target path/URL for logging
        target = None
        for key in ("path", "file", "target", "filename", "url", "uri"):
            if key in arguments:
                target = str(arguments[key])
                break

        # Extract content for shadow VFS
        content = None
        for key in ("content", "body", "text", "data"):
            if key in arguments:
                content = arguments[key]
                break

        # ── Is this a write? ──
        if self._is_write(tool_name):
            # Intercept it
            self.log.log_intercept(
                tool=tool_name,
                target=target,
                detail=f"Would have executed {tool_name}" + (f" on {target}" if target else ""),
            )

            # Shadow VFS: record the write for read consistency
            if target and content is not None:
                self.shadow.write(target, content if isinstance(content, str) else str(content))
            elif tool_name in ("fs_delete", "delete_file", "remove_file") and target:
                self.shadow.delete(target)
            elif tool_name in ("fs_rename", "rename_file", "move_file", "fs_move"):
                old = arguments.get("path", arguments.get("source", arguments.get("old_path", "")))
                new = arguments.get("new_path", arguments.get("destination", arguments.get("target", "")))
                if old and new:
                    self.shadow.rename(str(old), str(new))

            if self.verbose:
                logger.info("\U0001f6ab INTERCEPTED: %s%s", tool_name,
                           f" → {target}" if target else "")

            # Return fake success to the agent
            await self._agent_writer.write(_make_response(msg_id, {
                "content": [{
                    "type": "text",
                    "text": f"[Ghost Mode] {tool_name} completed successfully."
                }],
            }))
            return

        # ── Is this a read of something we ghost-wrote? ──
        if target and self.shadow.has(target):
            shadow_content = self.shadow.read(target)
            self.log.log_shadow_read(tool=tool_name, target=target)

            if self.verbose:
                logger.info("\U0001f47b SHADOW READ: %s → %s", tool_name, target)

            await self._agent_writer.write(_make_response(msg_id, {
                "content": [{
                    "type": "text",
                    "text": str(shadow_content) if shadow_content else "",
                }],
            }))
            return

        # ── Read-only — pass through to upstream ──
        self.log.log_passthrough(tool=tool_name, target=target)

        if self.verbose:
            logger.info("\u2705 PASSTHROUGH: %s%s", tool_name,
                       f" → {target}" if target else "")

        uid = self._next_id()
        self._pending[uid] = msg_id
        await self._upstream_writer.write({
            "jsonrpc": "2.0",
            "id": uid,
            "method": "tools/call",
            "params": params,
        })

    async def _forward_to_upstream(self, msg: dict) -> None:
        """Forward non-tool-call messages transparently."""
        msg_id = msg.get("id")
        method = msg.get("method")

        if msg_id is not None:  # Request
            uid = self._next_id()
            self._pending[uid] = msg_id
            await self._upstream_writer.write({
                "jsonrpc": "2.0",
                "id": uid,
                "method": method,
                "params": msg.get("params", {}),
            })
        else:  # Notification
            await self._upstream_writer.write(msg)

    # ── Upstream → Proxy ──

    async def _upstream_loop(self) -> None:
        while not self._shutdown:
            msg = await self._upstream_reader.read()
            if msg is None:
                self._shutdown = True
                return

            try:
                await self._handle_upstream_message(msg)
            except Exception as e:
                logger.error("Error handling upstream message: %s", e, exc_info=True)

    async def _handle_upstream_message(self, msg: dict) -> None:
        msg_id = msg.get("id")
        method = msg.get("method")

        # Notification — pass through
        if method is not None and msg_id is None:
            await self._agent_writer.write(msg)
            return

        # Response — remap ID and forward
        if msg_id is not None and msg_id in self._pending:
            agent_id = self._pending.pop(msg_id)
            response = {"jsonrpc": "2.0", "id": agent_id}
            if "result" in msg:
                response["result"] = msg["result"]
            if "error" in msg:
                response["error"] = msg["error"]
            await self._agent_writer.write(response)


async def run_ghost_proxy(
    upstream_command: list[str],
    custom_write_tools: Optional[frozenset] = None,
    verbose: bool = False,
) -> None:
    """Entry point — run Ghost Mode proxy."""
    proxy = GhostProxy(upstream_command, custom_write_tools, verbose)
    await proxy.run()
