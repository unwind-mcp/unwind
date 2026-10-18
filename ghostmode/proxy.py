from __future__ import annotations

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
import difflib
import json
import logging
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .shadow_vfs import EditNotFound, ShadowVFS, apply_edits, normalize
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
    # Edit operations
    "edit_file", "patch_file", "replace_in_file",
})

# Tools that look like writes based on naming patterns
WRITE_PREFIXES = ("create_", "delete_", "remove_", "update_", "modify_",
                  "send_", "post_", "put_", "write_", "set_", "insert_",
                  "drop_", "execute_", "run_", "install_", "push_", "edit_",
                  "patch_", "replace_", "rename_", "move_", "copy_")

# Known read-only tools. Anything that is neither a known read nor marked
# read-only by the server is treated as a write: unknown tools are blocked.
DEFAULT_READ_TOOLS = frozenset({
    "directory_tree", "list_allowed_directories", "get_file_info",
    "search_files", "fs_read", "fs_list", "fs_stat", "fs_search",
})

READ_PREFIXES = ("read_", "get_", "list_", "search_", "fetch_", "find_",
                 "describe_", "show_", "view_", "lookup_")


def classify_tool(tool_name: str, custom_writes: Optional[frozenset] = None,
                  annotations: Optional[dict] = None,
                  allowed: Optional[frozenset] = None) -> str:
    """Classify a tool as "write", "read" or "unknown".

    Order: --also-block, --allow, known write names, the server's own
    readOnlyHint annotation, known read names. Anything left is "unknown",
    which Ghost Mode blocks.
    """
    if custom_writes and tool_name in custom_writes:
        return "write"
    if allowed and tool_name in allowed:
        return "read"
    if tool_name in DEFAULT_WRITE_TOOLS or tool_name.startswith(WRITE_PREFIXES):
        return "write"
    if annotations and "readOnlyHint" in annotations:
        return "read" if annotations["readOnlyHint"] else "write"
    if tool_name in DEFAULT_READ_TOOLS or tool_name.startswith(READ_PREFIXES):
        return "read"
    return "unknown"


def is_write_tool(tool_name: str, custom_writes: Optional[frozenset] = None,
                  annotations: Optional[dict] = None,
                  allowed: Optional[frozenset] = None) -> bool:
    """Determine if a tool modifies state.

    Errs on the side of blocking: a tool is only passed through when it is
    known to be read-only, by name or by the server's readOnlyHint.
    """
    return classify_tool(tool_name, custom_writes, annotations, allowed) != "read"


# Tool families the shadow VFS understands (official filesystem server
# names plus common aliases)
FILE_READ_TOOLS = frozenset({"read_text_file", "read_file", "fs_read"})
FILE_INFO_TOOLS = frozenset({"get_file_info", "fs_stat"})
EDIT_TOOLS = frozenset({"edit_file", "patch_file", "replace_in_file"})
MOVE_TOOLS = frozenset({"move_file", "rename_file", "fs_rename", "fs_move"})
MKDIR_TOOLS = frozenset({"create_directory", "fs_mkdir"})
DELETE_TOOLS = frozenset({"fs_delete", "delete_file", "remove_file"})

PATH_KEYS = ("path", "file_path", "file", "filename")
LOG_TARGET_KEYS = PATH_KEYS + ("target", "url", "uri", "source", "old_path")
CONTENT_KEYS = ("content", "body", "text", "data")

_LISTING_LINE = re.compile(r"^\[(FILE|DIR)\] (.+?)(?:\s{2,}(\S.*))?$")


# ── JSON-RPC Helpers ──────────────────────────────────────────────

def _make_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _make_error(id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _text_result(text: str, is_error: bool = False, structured: bool = False) -> dict:
    result: dict = {"content": [{"type": "text", "text": text}]}
    if structured:
        result["structuredContent"] = {"content": text}
    if is_error:
        result["isError"] = True
    return result


def _result_text(result: dict) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", [])
                     if c.get("type") == "text")


def _enoent(path: str) -> dict:
    return _text_result(f"ENOENT: no such file or directory, open '{path}'", is_error=True)


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
        allowed_tools: Optional[frozenset] = None,
    ):
        self.upstream_command = upstream_command
        self.custom_write_tools = custom_write_tools
        self.allowed_tools = allowed_tools
        self.verbose = verbose

        self.shadow = ShadowVFS()
        self.log = GhostEventLog()

        self._process: Optional[asyncio.subprocess.Process] = None
        self._agent_reader: Optional[StdioReader] = None
        self._agent_writer: Optional[StdioWriter] = None
        self._upstream_reader: Optional[StdioReader] = None
        self._upstream_writer: Optional[StdioWriter] = None

        # upstream id -> (agent id, method)
        self._pending: dict[int, tuple[Any, Optional[str]]] = {}
        # upstream id -> future, for requests Ghost Mode makes itself
        self._internal: dict[int, asyncio.Future] = {}
        # tool name -> annotations, learned from tools/list responses
        self._tools: dict[str, dict] = {}
        self._unknown_blocked: set[str] = set()
        self._upstream_id: int = 0
        self._stop: Optional[asyncio.Event] = None
        self._shutdown = False
        self._summary_printed = False

    def _next_id(self) -> int:
        self._upstream_id += 1
        return self._upstream_id

    def _classify(self, tool_name: str) -> str:
        return classify_tool(tool_name, self.custom_write_tools,
                             self._tools.get(tool_name), self.allowed_tools)

    def _is_write(self, tool_name: str) -> bool:
        return self._classify(tool_name) != "read"

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

        # Upstream subprocess, in its own process group so shutdown can stop
        # launchers like npx together with the server they spawn
        self._process = await asyncio.create_subprocess_exec(
            *self.upstream_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        self._upstream_reader = StdioReader(self._process.stdout)
        self._upstream_writer = StdioWriter(self._process.stdin)

        logger.info("Ghost Mode proxy started (upstream PID %d)", self._process.pid)

    def stop(self) -> None:
        """Ask the proxy to shut down (safe to call from a signal handler)."""
        if self._stop is not None:
            self._stop.set()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for name in ("SIGTERM", "SIGHUP", "SIGINT"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError, ValueError):
                pass  # Windows / non-main thread: fall back to default handling

    async def run(self) -> None:
        """Main loop — run until the agent disconnects, upstream exits,
        or the proxy is asked to stop by a signal."""
        self._stop = asyncio.Event()
        await self.start()
        self._install_signal_handlers()
        tasks = [
            asyncio.ensure_future(self._agent_loop()),
            asyncio.ensure_future(self._upstream_loop()),
            asyncio.ensure_future(self._stop.wait()),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            pass
        finally:
            for task in tasks:
                task.cancel()
            await self.shutdown()

    async def shutdown(self) -> None:
        if self._shutdown:
            # Already shutting down, but still print summary if not yet printed
            if not self._summary_printed:
                self._print_summary()
            return
        self._shutdown = True

        # Print session summary to stderr
        self._print_summary()

        if self._process and self._process.returncode is None:
            self._signal_upstream(signal.SIGTERM)
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._signal_upstream(getattr(signal, "SIGKILL", signal.SIGTERM))

        if self._agent_writer:
            await self._agent_writer.close()

        logger.info("Ghost Mode proxy shut down")

    def _signal_upstream(self, sig: int) -> None:
        try:
            if os.name == "posix":
                os.killpg(self._process.pid, sig)
            elif sig == signal.SIGTERM:
                self._process.terminate()
            else:
                self._process.kill()
        except (ProcessLookupError, PermissionError):
            pass

    def _print_summary(self) -> None:
        """Print session summary to stderr on shutdown."""
        self._summary_printed = True
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

        if shadow["dirs_created"]:
            print(f"\n  Directories the agent tried to create:", file=sys.stderr)
            for d in shadow["dirs_created"]:
                print(f"    \U0001f4c1 {d}", file=sys.stderr)

        if shadow["delete_count"] > 0:
            print(f"\n  Files the agent tried to delete or move away:", file=sys.stderr)
            for f in shadow["files_deleted"]:
                print(f"    \U0001f5d1️  {f}", file=sys.stderr)

        if self._unknown_blocked:
            print(f"\n  Unknown tools blocked to be safe "
                  f"(pass with --allow NAME if read-only):", file=sys.stderr)
            for t in sorted(self._unknown_blocked):
                print(f"    ❓ {t}", file=sys.stderr)

        if summary["intercepted"] == 0:
            print("\n  ✅ Agent performed no write operations.", file=sys.stderr)
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

        # Auto-write summary to file for clients that hide stderr
        lines = []
        lines.append("GHOST MODE SESSION SUMMARY")
        lines.append(f"Duration:     {summary['duration_seconds']}s")
        lines.append(f"Total events: {summary['total_events']}")
        lines.append(f"Intercepted:  {summary['intercepted']} writes blocked")
        lines.append(f"Passed:       {summary['passed_through']} reads forwarded")
        lines.append(f"Shadow reads: {summary['shadow_reads']} served from VFS")
        if shadow["write_count"] > 0:
            lines.append(f"\nFiles the agent tried to write:")
            for f in shadow["files_written"]:
                lines.append(f"  {f}")
        if shadow["dirs_created"]:
            lines.append(f"\nDirectories the agent tried to create:")
            for d in shadow["dirs_created"]:
                lines.append(f"  {d}")
        if shadow["delete_count"] > 0:
            lines.append(f"\nFiles the agent tried to delete or move away:")
            for f in shadow["files_deleted"]:
                lines.append(f"  {f}")
        if self._unknown_blocked:
            lines.append(f"\nUnknown tools blocked to be safe (pass with --allow NAME if read-only):")
            for t in sorted(self._unknown_blocked):
                lines.append(f"  {t}")
        if summary["intercepted"] == 0:
            lines.append("\nAgent performed no write operations.")
        else:
            lines.append(f"\n{summary['intercepted']} write(s) were blocked. Nothing was modified.")
        lines.append("\nFull timeline:")
        lines.append(self.log.format_timeline())
        text = "\n".join(lines) + "\n"

        # MCP clients often start servers with an unwritable working
        # directory (e.g. "/"), so fall back to the home directory
        for summary_path in (Path("ghostmode-summary.txt"),
                             Path.home() / "ghostmode-summary.txt"):
            try:
                summary_path.write_text(text)
            except Exception:
                continue  # Best-effort — don't fail shutdown over summary file
            print(f"  Summary written to {summary_path.resolve()}", file=sys.stderr)
            break

    # ── Agent → Proxy ──

    async def _agent_loop(self) -> None:
        while not self._shutdown:
            msg = await self._agent_reader.read()
            if msg is None:
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
        arguments = params.get("arguments") or {}
        msg_id = msg.get("id")

        # File path the call acts on (for the shadow VFS)
        path = next((str(arguments[k]) for k in PATH_KEYS if arguments.get(k)), None)

        # Target path/URL for logging
        target = next((str(arguments[k]) for k in LOG_TARGET_KEYS if arguments.get(k)), None)

        # ── Is this a write? ──
        kind = self._classify(tool_name)
        if kind != "read":
            if kind == "unknown":
                self._unknown_blocked.add(tool_name)
                detail = (f"Unknown tool {tool_name} blocked by default "
                          f"(use --allow {tool_name} if it is read-only)")
            else:
                detail = f"Would have executed {tool_name}" + (f" on {target}" if target else "")
            self.log.log_intercept(tool=tool_name, target=target, detail=detail)

            if self.verbose:
                logger.info("\U0001f6ab INTERCEPTED: %s%s", tool_name,
                           f" → {target}" if target else "")

            result = await self._ghost_write(tool_name, arguments, path)
            await self._agent_writer.write(_make_response(msg_id, result))
            return

        # ── Is this a read of something we ghost-wrote? ──
        shadow_result = await self._shadow_read(tool_name, arguments, path)
        if shadow_result is not None:
            self.log.log_shadow_read(tool=tool_name, target=target or "")

            if self.verbose:
                logger.info("\U0001f47b SHADOW READ: %s → %s", tool_name, target)

            await self._agent_writer.write(_make_response(msg_id, shadow_result))
            return

        # ── Read-only — pass through to upstream ──
        self.log.log_passthrough(tool=tool_name, target=target)

        if self.verbose:
            logger.info("✅ PASSTHROUGH: %s%s", tool_name,
                       f" → {target}" if target else "")

        uid = self._next_id()
        self._pending[uid] = (msg_id, "tools/call")
        await self._upstream_writer.write({
            "jsonrpc": "2.0",
            "id": uid,
            "method": "tools/call",
            "params": params,
        })

    # ── Shadow VFS: writes ──

    async def _ghost_write(self, tool_name: str, arguments: dict,
                           path: Optional[str]) -> dict:
        """Record an intercepted write in the shadow VFS and build the
        fake response the agent sees."""
        ok = _text_result(f"[Ghost Mode] {tool_name} completed successfully.")

        if tool_name in EDIT_TOOLS and path and isinstance(arguments.get("edits"), list):
            base, error = await self._current_text(path)
            if base is None:
                return _text_result(error, is_error=True) if error else ok
            try:
                new = apply_edits(base, arguments["edits"])
            except EditNotFound as e:
                return _text_result(str(e), is_error=True)
            if not arguments.get("dryRun"):
                self.shadow.write(path, new)
            diff = "".join(difflib.unified_diff(
                base.replace("\r\n", "\n").splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"{path}\toriginal", tofile=f"{path}\tmodified",
            ))
            return _text_result(f"```diff\n{diff}```\n\n")

        if tool_name in MOVE_TOOLS:
            src = arguments.get("source") or arguments.get("path") or arguments.get("old_path")
            dst = (arguments.get("destination") or arguments.get("new_path")
                   or arguments.get("target"))
            if not (src and dst):
                return ok
            src, dst = str(src), str(dst)
            if self.shadow.is_file(src) or self.shadow.is_dir(src):
                self.shadow.rename(src, dst)
            elif self.shadow.is_deleted(src):
                return _enoent(src)
            else:
                content, error = await self._real_text(src)
                if content is not None:
                    self.shadow.write(dst, content)
                elif error is not None:
                    if not await self._real_is_dir(src):
                        return _text_result(error, is_error=True)
                    # Directory move: the new path exists, its contents are
                    # not mirrored in the shadow
                    self.shadow.mkdir(dst)
                self.shadow.delete(src)
            return _text_result(f"Successfully moved {src} to {dst}")

        if tool_name in MKDIR_TOOLS and path:
            self.shadow.mkdir(path)
            return _text_result(f"Successfully created directory {path}")

        if tool_name in DELETE_TOOLS and path:
            self.shadow.delete(path)
            return ok

        if path:
            content = next((arguments[k] for k in CONTENT_KEYS if k in arguments), None)
            if content is not None:
                self.shadow.write(path, content if isinstance(content, str) else str(content))
                if tool_name == "write_file":
                    return _text_result(f"Successfully wrote to {path}")

        return ok

    # ── Shadow VFS: reads ──

    async def _shadow_read(self, tool_name: str, arguments: dict,
                           path: Optional[str]) -> Optional[dict]:
        """Answer a read from the shadow VFS, or return None to pass it
        through to upstream unchanged."""
        shadow = self.shadow

        if tool_name == "read_multiple_files":
            paths = [str(p) for p in arguments.get("paths") or []]
            if not any(shadow.has(p) or shadow.is_deleted(p) for p in paths):
                return None
            parts = []
            for p in paths:
                content, error = await self._current_text(p)
                parts.append(f"{p}:\n{content}\n" if content is not None
                             else f"{p}: Error - {error}")
            return _text_result("\n---\n".join(parts))

        if not path:
            return None

        if tool_name in ("list_directory", "list_directory_with_sizes",
                         "directory_tree", "search_files"):
            if shadow.is_deleted(path):
                return _enoent(path)
            if not shadow.touches_tree(path):
                return None
            return await self._patched_listing(tool_name, arguments, path)

        if tool_name in FILE_INFO_TOOLS:
            if shadow.is_deleted(path):
                return _enoent(path)
            if not (shadow.is_file(path) or shadow.is_dir(path)):
                return None
            is_dir = shadow.is_dir(path)
            size = 0 if is_dir else len(shadow.read(path) or "")
            stamp = time.strftime("%a %b %d %Y %H:%M:%S GMT%z",
                                  time.localtime(shadow.mtime(path)))
            return _text_result(
                f"size: {size}\ncreated: {stamp}\nmodified: {stamp}\naccessed: {stamp}\n"
                f"isDirectory: {str(is_dir).lower()}\nisFile: {str(not is_dir).lower()}\n"
                f"permissions: {'755' if is_dir else '644'}",
                structured=True,
            )

        if shadow.is_deleted(path):
            return _enoent(path)

        if shadow.is_file(path):
            content = str(shadow.read(path))
            if tool_name in FILE_READ_TOOLS:
                lines = content.split("\n")
                if arguments.get("head"):
                    content = "\n".join(lines[:int(arguments["head"])])
                elif arguments.get("tail"):
                    content = "\n".join(lines[-int(arguments["tail"]):])
            return _text_result(content, structured=tool_name in FILE_READ_TOOLS)

        return None

    async def _patched_listing(self, tool_name: str, arguments: dict,
                               path: str) -> Optional[dict]:
        """Run a listing upstream, then overlay the shadow's changes."""
        response = await self._upstream_call(
            "tools/call", {"name": tool_name, "arguments": arguments})
        result = (response or {}).get("result")
        failed = result is None or result.get("isError")
        if failed and not self.shadow.is_dir(path):
            return None  # Let upstream's own answer (or error) stand
        base = "" if failed else _result_text(result)
        structured = bool(result and "structuredContent" in result)
        shadow = self.shadow

        if tool_name == "search_files":
            hits = [] if base.strip() in ("", "No matches found") else base.split("\n")
            hits = [h for h in hits if not shadow.is_deleted(h)]
            seen = {normalize(h) for h in hits}
            hits += [m for m in shadow.search(path, str(arguments.get("pattern", "")))
                     if normalize(m) not in seen]
            return _text_result("\n".join(hits) if hits else "No matches found",
                                structured=structured)

        if tool_name == "directory_tree":
            try:
                tree = json.loads(base) if base.strip() else []
            except json.JSONDecodeError:
                return None
            self._patch_tree(tree, path)
            return _text_result(json.dumps(tree, indent=2), structured=structured)

        # list_directory / list_directory_with_sizes
        added, deleted = shadow.children(path)
        entries, footer = [], []
        for line in base.split("\n"):
            m = _LISTING_LINE.match(line)
            if m:
                if m.group(2) not in deleted and m.group(2) not in added:
                    entries.append((m.group(2), m.group(1), m.group(3)))
            elif line.strip():
                footer.append(line)
        for name, kind in added.items():
            size = None
            if tool_name == "list_directory_with_sizes":
                size = "" if kind == "dir" else \
                    f"{len(str(shadow.read(os.path.join(path, name)) or ''))} B"
            entries.append((name, "DIR" if kind == "dir" else "FILE", size))
        entries.sort(key=lambda e: e[0])

        if tool_name == "list_directory":
            text = "\n".join(f"[{k}] {n}" for n, k, _ in entries)
        else:
            text = "\n".join(f"[{k}] {n.ljust(30)} {(s or '').rjust(10)}" if k == "FILE"
                             else f"[{k}] {n}" for n, k, s in entries)
            files = sum(1 for e in entries if e[1] == "FILE")
            footer = [f"Total: {files} files, {len(entries) - files} directories"] + \
                [l for l in footer if not l.startswith("Total:")]
            text += "\n\n" + "\n".join(footer)
        return _text_result(text, structured=structured)

    def _patch_tree(self, entries: list, directory: str) -> None:
        """Overlay shadow changes onto a directory_tree JSON listing."""
        added, deleted = self.shadow.children(directory)
        entries[:] = [e for e in entries if e.get("name") not in deleted]
        names = {e.get("name") for e in entries}
        for name, kind in added.items():
            if name not in names:
                entries.append({"name": name, "type": "directory", "children": []}
                               if kind == "dir" else {"name": name, "type": "file"})
        for e in entries:
            child = os.path.join(directory, e.get("name", ""))
            if e.get("type") == "directory" and self.shadow.touches_tree(child):
                e.setdefault("children", [])
                self._patch_tree(e["children"], child)

    async def _current_text(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """The file's content as the agent should see it: shadow first, then disk.

        Returns (content, None), or (None, error message).
        """
        if self.shadow.is_file(path):
            return str(self.shadow.read(path)), None
        if self.shadow.is_deleted(path):
            return None, f"ENOENT: no such file or directory, open '{path}'"
        return await self._real_text(path)

    async def _real_text(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """Read a real file through upstream, so its own access rules apply.

        Returns (content, None), (None, error message), or (None, None) when
        upstream has no file-read tool to ask.
        """
        tool = next((t for t in ("read_text_file", "read_file", "fs_read")
                     if t in self._tools), None)
        if tool is None:
            return None, None
        response = await self._upstream_call(
            "tools/call", {"name": tool, "arguments": {"path": path}})
        if response is None:
            return None, "Upstream did not respond"
        if "error" in response:
            return None, str(response["error"].get("message", response["error"]))
        result = response.get("result") or {}
        if result.get("isError"):
            return None, _result_text(result)
        return _result_text(result), None

    async def _real_is_dir(self, path: str) -> bool:
        if "get_file_info" not in self._tools:
            return False
        response = await self._upstream_call(
            "tools/call", {"name": "get_file_info", "arguments": {"path": path}})
        result = (response or {}).get("result") or {}
        return not result.get("isError") and "isDirectory: true" in _result_text(result)

    async def _upstream_call(self, method: str, params: dict,
                             timeout: float = 30) -> Optional[dict]:
        """Send a request of Ghost Mode's own to upstream and await the reply."""
        uid = self._next_id()
        future = asyncio.get_event_loop().create_future()
        self._internal[uid] = future
        await self._upstream_writer.write(
            {"jsonrpc": "2.0", "id": uid, "method": method, "params": params})
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._internal.pop(uid, None)

    async def _forward_to_upstream(self, msg: dict) -> None:
        """Forward non-tool-call messages transparently."""
        msg_id = msg.get("id")
        method = msg.get("method")

        if msg_id is not None:  # Request
            uid = self._next_id()
            self._pending[uid] = (msg_id, method)
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

        # Reply to a request Ghost Mode made itself
        if msg_id in self._internal:
            future = self._internal.pop(msg_id)
            if not future.done():
                future.set_result(msg)
            return

        # Response — remap ID and forward
        if msg_id is not None and msg_id in self._pending:
            agent_id, request_method = self._pending.pop(msg_id)
            if request_method == "tools/list":
                for tool in (msg.get("result") or {}).get("tools", []):
                    if isinstance(tool, dict) and "name" in tool:
                        self._tools[tool["name"]] = tool.get("annotations") or {}
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
    allowed_tools: Optional[frozenset] = None,
) -> None:
    """Entry point — run Ghost Mode proxy."""
    proxy = GhostProxy(upstream_command, custom_write_tools, verbose, allowed_tools)
    await proxy.run()
