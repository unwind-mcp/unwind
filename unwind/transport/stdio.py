"""UNWIND MCP stdio transport — JSON-RPC 2.0 over stdin/stdout.

This is the bridge that makes UNWIND a real MCP proxy.

Architecture:
  Agent (stdin/stdout) → UNWIND → Upstream MCP Server (subprocess stdio)

The agent thinks it's talking to the MCP server directly.
The MCP server thinks it's talking to the agent directly.
UNWIND intercepts every message, enforces security checks on tool calls,
and passes everything else through transparently.

Wire protocol: newline-delimited JSON-RPC 2.0 (per MCP spec).
"""

import asyncio
import json
import logging
import sys
import uuid
from typing import Any, Optional

from ..config import UnwindConfig
from ..proxy import UnwindProxy
from ..enforcement.manifest_filter import ManifestFilter, PermissionTier
from ..enforcement.amber_mediator import (
    build_pattern_id,
    build_batch_hint,
    new_challenge_nonce,
    challenge_expires_at,
    compute_action_hash,
    derive_destination_scope,
    build_risk_capsule,
    hash_risk_capsule,
)
from ..enforcement.amber_store import AmberEventStore
from ..enforcement.amber_telemetry import AmberTelemetry
from ..enforcement.amber_rollout import AmberMediatorMode, parse_mode, DEFAULT_MODE

logger = logging.getLogger("unwind.transport.stdio")


class JsonRpcMessage:
    """Parsed JSON-RPC 2.0 message."""

    def __init__(self, data: dict):
        self.data = data
        self.jsonrpc = data.get("jsonrpc", "2.0")
        self.method = data.get("method")
        self.params = data.get("params", {})
        self.id = data.get("id")  # None for notifications
        self.result = data.get("result")
        self.error = data.get("error")

    @property
    def is_request(self) -> bool:
        return self.method is not None and self.id is not None

    @property
    def is_notification(self) -> bool:
        return self.method is not None and self.id is None

    @property
    def is_response(self) -> bool:
        return self.method is None and (self.result is not None or self.error is not None)


def make_response(id: Any, result: Any) -> dict:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": id, "result": result}


def make_error(id: Any, code: int, message: str, data: Any = None) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    err = {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}
    if data is not None:
        err["error"]["data"] = data
    return err


class StdioTransport:
    """Bidirectional stdio JSON-RPC transport.

    Reads newline-delimited JSON from an asyncio StreamReader,
    writes newline-delimited JSON to an asyncio StreamWriter.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    async def read_message(self) -> Optional[JsonRpcMessage]:
        """Read one JSON-RPC message. Returns None on EOF."""
        while True:
            try:
                line = await self.reader.readline()
            except (asyncio.CancelledError, ConnectionError):
                return None

            if not line:
                return None  # EOF

            line = line.strip()
            if not line:
                continue  # skip blank lines

            try:
                data = json.loads(line)
                return JsonRpcMessage(data)
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON from transport: %s", e)
                continue

    async def write_message(self, msg: dict) -> None:
        """Write one JSON-RPC message."""
        if self._closed:
            return
        try:
            line = json.dumps(msg, separators=(",", ":")) + "\n"
            self.writer.write(line.encode())
            await self.writer.drain()
        except (ConnectionError, BrokenPipeError, asyncio.CancelledError):
            self._closed = True

    async def close(self) -> None:
        """Close the transport."""
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


class UpstreamProcess:
    """Manages a subprocess running the upstream MCP server.

    UNWIND spawns the upstream server and talks to it over stdio,
    exactly as the agent would. The upstream never knows UNWIND exists.
    """

    def __init__(self, command: list[str], env: Optional[dict] = None):
        self.command = command
        self.env = env
        self.process: Optional[asyncio.subprocess.Process] = None
        self.transport: Optional[StdioTransport] = None

    async def start(self) -> None:
        """Spawn the upstream MCP server."""
        logger.info("Starting upstream: %s", " ".join(self.command))
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        self.transport = StdioTransport(
            self.process.stdout,
            self.process.stdin,
        )
        logger.info("Upstream started (PID %d)", self.process.pid)

    async def stop(self) -> None:
        """Terminate the upstream server."""
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
            logger.info("Upstream stopped")

    async def send(self, msg: dict) -> None:
        """Send a message to upstream."""
        if self.transport:
            await self.transport.write_message(msg)

    async def receive(self) -> Optional[JsonRpcMessage]:
        """Receive a message from upstream."""
        if self.transport:
            return await self.transport.read_message()
        return None


class UnwindStdioServer:
    """The main UNWIND MCP proxy server using stdio transport.

    Sits between agent (stdin/stdout) and upstream (subprocess stdio).
    Intercepts tools/list (to inject canaries) and tools/call (to enforce).
    Everything else passes through transparently.
    """

    def __init__(self, config: UnwindConfig, upstream_command: list[str]):
        self.config = config
        self.upstream_command = upstream_command
        self.proxy = UnwindProxy(config)
        self.manifest_filter = ManifestFilter(config)
        self.upstream: Optional[UpstreamProcess] = None
        self.agent_transport: Optional[StdioTransport] = None
        self._pending_requests: dict[Any, Any] = {}  # id -> original agent request id
        self._upstream_id_counter: int = 0
        self._session_id: Optional[str] = None
        self._shutdown = False
        # Track upstream tools for manifest merging
        self._upstream_tools: list[dict] = []
        # P0-2: Enforcement-in-path mediation proof
        self._mediation_nonce: str = f"unwind_{uuid.uuid4().hex[:16]}"
        self._tool_calls_processed: int = 0
        # Amber mediator persistence (R-AMBER-MED-001)
        self._amber_store = AmberEventStore(config.events_db_path)
        # Amber mediator telemetry (GO-09)
        self._amber_telemetry = AmberTelemetry()
        # Amber mediator rollout gate (GO-10): off | shadow | enforce
        self._amber_mode = DEFAULT_MODE  # OFF by default — safe

    @property
    def mediation_nonce(self) -> str:
        """P0-2: The mediation proof nonce injected into initialize response."""
        return self._mediation_nonce

    @property
    def tool_calls_processed(self) -> int:
        """P0-2: Count of tool calls processed through enforcement pipeline."""
        return self._tool_calls_processed

    @property
    def mediation_active(self) -> bool:
        """P0-2: True if at least one tool call has been enforced."""
        return self._tool_calls_processed > 0

    def set_amber_mode(self, mode: str) -> None:
        """Set the amber mediator rollout mode (off/shadow/enforce).

        GO-10: fail-closed — unrecognised values default to OFF.
        """
        self._amber_mode = parse_mode(mode)
        logger.info("Amber mediator mode set to: %s", self._amber_mode.value)

    @property
    def amber_mode(self) -> AmberMediatorMode:
        """Current amber mediator rollout mode."""
        return self._amber_mode

    @property
    def amber_telemetry(self) -> AmberTelemetry:
        """Amber mediator telemetry emitter (for testing/inspection)."""
        return self._amber_telemetry

    def _next_upstream_id(self) -> int:
        """Generate a unique request ID for upstream messages."""
        self._upstream_id_counter += 1
        return self._upstream_id_counter

    async def start(self) -> None:
        """Initialize UNWIND and start the upstream server."""
        self.proxy.startup()
        self._amber_store.initialize()

        # Set up agent-facing stdio transport
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        w_transport, w_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
        self.agent_transport = StdioTransport(reader, writer)

        # Start upstream MCP server subprocess
        self.upstream = UpstreamProcess(self.upstream_command)
        await self.upstream.start()

        logger.info("UNWIND stdio proxy ready")

    async def run(self) -> None:
        """Main proxy loop — run until shutdown."""
        await self.start()

        try:
            # Run agent→proxy and upstream→proxy readers concurrently
            await asyncio.gather(
                self._agent_reader_loop(),
                self._upstream_reader_loop(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Clean shutdown."""
        if self._shutdown:
            return
        self._shutdown = True

        if self.upstream:
            await self.upstream.stop()
        if self.agent_transport:
            await self.agent_transport.close()

        self._amber_store.close()
        self.proxy.shutdown()
        logger.info("UNWIND stdio proxy shut down")

    # ─── Agent → Proxy ─────────────────────────────────────────

    async def _agent_reader_loop(self) -> None:
        """Read messages from the agent and handle or forward them."""
        while not self._shutdown:
            msg = await self.agent_transport.read_message()
            if msg is None:
                logger.info("Agent disconnected (EOF)")
                self._shutdown = True
                return

            try:
                await self._handle_agent_message(msg)
            except Exception as e:
                logger.error("Error handling agent message: %s", e, exc_info=True)
                if msg.id is not None:
                    await self.agent_transport.write_message(
                        make_error(msg.id, -32603, f"Internal error: {e}")
                    )

    async def _handle_agent_message(self, msg: JsonRpcMessage) -> None:
        """Route an agent message to the appropriate handler."""

        # ── tools/call — the security-critical path ──
        if msg.method == "tools/call":
            await self._handle_tool_call(msg)
            return

        # ── tools/list — inject canary tools into manifest ──
        if msg.method == "tools/list":
            await self._handle_tool_list(msg)
            return

        # ── initialize — capture session info, forward ──
        if msg.method == "initialize":
            await self._handle_initialize(msg)
            return

        # ── Everything else — transparent passthrough ──
        await self._forward_to_upstream(msg)

    async def _handle_initialize(self, msg: JsonRpcMessage) -> None:
        """Handle MCP initialize handshake.

        Forward to upstream, but capture session metadata.
        Binds a unique session ID to this connection — critical for
        cross-client isolation (CVE-2026-25536 defence).
        """
        # Extract session info if provided
        client_info = msg.params.get("clientInfo", {})
        client_name = client_info.get("name", "unknown")
        client_version = client_info.get("version", "")
        logger.info("Agent initialize: %s %s", client_name, client_version)

        # --- CVE-2026-25536 FIX: Bind a unique session to this connection ---
        # Use client-provided session ID if available, otherwise generate one.
        # This ensures each connection gets its own isolated session with
        # separate taint state, ghost mode, permission tier, and event stream.
        session_hint = msg.params.get("sessionId") or client_info.get("sessionId")
        self._session_id = session_hint or f"sess_{uuid.uuid4().hex[:12]}"
        session = self.proxy.get_or_create_session(self._session_id)
        logger.info(
            "Session bound: %s (client=%s)",
            self._session_id, client_name,
        )

        # Forward to upstream — tag so we can inject mediation proof into response
        upstream_id = self._next_upstream_id()
        self._pending_requests[upstream_id] = ("initialize", msg.id)
        await self.upstream.send({
            "jsonrpc": "2.0",
            "id": upstream_id,
            "method": "initialize",
            "params": msg.params,
        })

    async def _handle_tool_list(self, msg: JsonRpcMessage) -> None:
        """Handle tools/list — forward to upstream, then inject canaries.

        The agent sees: upstream_tools + canary_honeypot_tools.
        Canaries are indistinguishable from real tools in the manifest.
        """
        upstream_id = self._next_upstream_id()
        # Tag this request so we know to inject canaries into the response
        self._pending_requests[upstream_id] = ("tools_list", msg.id)
        await self.upstream.send({
            "jsonrpc": "2.0",
            "id": upstream_id,
            "method": "tools/list",
            "params": msg.params,
        })

    async def _handle_tool_call(self, msg: JsonRpcMessage) -> None:
        """Handle tools/call — THE SECURITY GATE.

        Every tool call goes through the enforcement pipeline before
        reaching upstream. This is where UNWIND earns its keep.
        """
        tool_name = msg.params.get("name", "")
        arguments = msg.params.get("arguments", {})

        logger.debug("Tool call intercepted: %s", tool_name)

        # Create an upstream forwarder for allowed calls
        async def upstream_handler(name: str, params: dict, token: str) -> dict:
            """Forward an approved tool call to upstream and wait for response."""
            upstream_id = self._next_upstream_id()
            future = asyncio.get_event_loop().create_future()
            self._pending_requests[upstream_id] = ("tool_result", future)

            await self.upstream.send({
                "jsonrpc": "2.0",
                "id": upstream_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": params},
            })

            # Wait for upstream response (with timeout)
            try:
                result = await asyncio.wait_for(future, timeout=30.0)
                return result
            except asyncio.TimeoutError:
                return {"error": "Upstream timeout (30s)"}

        # Run through UNWIND enforcement pipeline
        result = await self.proxy.handle_tool_call(
            tool_name=tool_name,
            parameters=arguments,
            session_id=self._session_id,
            upstream_handler=upstream_handler,
        )

        # P0-2: Track that a tool call was processed through enforcement
        self._tool_calls_processed += 1

        # Convert proxy result to MCP tools/call response
        if "error" in result:
            # Blocked or error — return as tool result with isError flag
            await self.agent_transport.write_message(make_response(msg.id, {
                "content": [{"type": "text", "text": result["error"]}],
                "isError": True,
            }))
        elif result.get("status") == "amber":
            # Amber gate — needs user confirmation
            # Build R-AMBER-MED-001 mediator fields for intelligent batching
            reason = result.get("reason", "Tainted session + high-risk actuator")
            risk_tier = "AMBER_HIGH"  # Default; could be derived from taint level
            session = self.proxy.get_or_create_session(self._session_id)
            taint_level = session.taint_level.name if hasattr(session.taint_level, 'name') else "NONE"
            sid = self._session_id or ""
            event_id = result.get("event_id", "")

            dest_scope = derive_destination_scope(tool_name, arguments)
            action_hash = compute_action_hash(tool_name, arguments)
            pattern_id = build_pattern_id(
                tool_name=tool_name,
                destination_scope=dest_scope,
                risk_tier=risk_tier,
                taint_level=taint_level,
            )
            batch_hint = build_batch_hint(
                session_id=sid,
                tool_name=tool_name,
                destination_scope=dest_scope,
                risk_tier=risk_tier,
                pattern_id=pattern_id,
            )
            challenge = new_challenge_nonce()
            expires = challenge_expires_at()
            challenge_seq = self._amber_store.next_challenge_seq(sid)
            capsule = build_risk_capsule(
                tool_name=tool_name,
                destination_scope=dest_scope,
                risk_tier=risk_tier,
                taint_level=taint_level,
                amber_reason=reason,
            )
            capsule_hash = hash_risk_capsule(capsule)

            request_id = str(msg.id) if msg.id is not None else ""

            # GO-04: Persist at emit time — exact wire values stored
            self._amber_store.issue_amber_event(
                event_id=event_id,
                session_id=sid,
                request_id=request_id,
                pattern_id=pattern_id,
                action_hash=action_hash,
                challenge_nonce=challenge,
                challenge_seq=challenge_seq,
                challenge_expires_at=expires,
                risk_tier=risk_tier,
                risk_capsule_hash=capsule_hash,
                batch_group_key=batch_hint["group_key"],
                batch_max_size=batch_hint["max_batch_size"],
                batchable=batch_hint["batchable"],
                tool_name=tool_name,
                destination_scope=dest_scope,
                taint_level=taint_level,
            )

            # GO-09: Emit telemetry for amber issuance
            self._amber_telemetry.emit_issue(
                request_id=request_id,
                session_id=sid,
                event_id=event_id,
                pattern_id=pattern_id,
                risk_tier=risk_tier,
                challenge_nonce=challenge,
                challenge_seq=challenge_seq,
                challenge_expires_at=expires,
                action_hash=action_hash,
                batch_group_key=batch_hint["group_key"],
                batchable=batch_hint["batchable"],
                batch_max_size=batch_hint["max_batch_size"],
                risk_capsule_hash=capsule_hash,
            )

            # GO-10: Mode gate — in OFF/SHADOW mode, emit on wire but
            # don't enforce approval tokens.  In ENFORCE mode, the
            # approval path (future) will use validate_and_apply().
            # Currently safe: mode defaults to OFF.

            await self.agent_transport.write_message(make_response(msg.id, {
                "content": [{
                    "type": "text",
                    "text": f"[UNWIND AMBER GATE] Action requires confirmation: {reason}. "
                            f"Event ID: {event_id}",
                }],
                "isError": True,
                "amber": {
                    "event_id": event_id,
                    "pattern_id": pattern_id,
                    "batch_hint": batch_hint,
                    "challenge_nonce": challenge,
                    "challenge_seq": challenge_seq,
                    "challenge_expires_at": expires,
                    "action_hash": action_hash,
                    "risk_tier": risk_tier,
                    "risk_capsule": capsule,
                    "risk_capsule_hash": capsule_hash,
                },
            }))
        elif "content" in result:
            # Ghost mode with shadow VFS content
            await self.agent_transport.write_message(make_response(msg.id, {
                "content": [{"type": "text", "text": str(result["content"])}],
            }))
        else:
            # Successful upstream result — pass through
            # The upstream_handler already returns the raw result
            if isinstance(result, dict) and "result" in result:
                await self.agent_transport.write_message(
                    make_response(msg.id, result["result"])
                )
            else:
                await self.agent_transport.write_message(
                    make_response(msg.id, result)
                )

    async def _forward_to_upstream(self, msg: JsonRpcMessage) -> None:
        """Forward a message to upstream unchanged (transparent passthrough)."""
        if msg.is_request:
            upstream_id = self._next_upstream_id()
            self._pending_requests[upstream_id] = msg.id
            fwd = {
                "jsonrpc": "2.0",
                "id": upstream_id,
                "method": msg.method,
                "params": msg.params,
            }
            await self.upstream.send(fwd)
        elif msg.is_notification:
            await self.upstream.send(msg.data)

    # ─── Upstream → Proxy ───────────────────────────────────────

    async def _upstream_reader_loop(self) -> None:
        """Read messages from upstream and route to the agent."""
        while not self._shutdown:
            msg = await self.upstream.receive()
            if msg is None:
                logger.info("Upstream disconnected (EOF)")
                self._shutdown = True
                return

            try:
                await self._handle_upstream_message(msg)
            except Exception as e:
                logger.error("Error handling upstream message: %s", e, exc_info=True)

    async def _handle_upstream_message(self, msg: JsonRpcMessage) -> None:
        """Route an upstream response or notification."""

        # ── Notifications — pass through to agent ──
        if msg.is_notification:
            await self.agent_transport.write_message(msg.data)
            return

        # ── Responses — match to pending request ──
        if msg.is_response and msg.id is not None:
            pending = self._pending_requests.pop(msg.id, None)

            if pending is None:
                logger.warning("Unexpected upstream response id=%s", msg.id)
                return

            # Check for special tagged requests
            if isinstance(pending, tuple):
                tag, original_id = pending

                if tag == "initialize":
                    # P0-2: Inject mediation proof nonce into initialize response
                    response = {"jsonrpc": "2.0", "id": original_id}
                    if msg.result is not None:
                        result = dict(msg.result) if isinstance(msg.result, dict) else msg.result
                        if isinstance(result, dict):
                            result["_unwind_mediation_nonce"] = self._mediation_nonce
                        response["result"] = result
                    if msg.error is not None:
                        response["error"] = msg.error
                    await self.agent_transport.write_message(response)
                    return

                if tag == "tools_list":
                    # Inject canary tools into the tool list
                    await self._inject_canaries_and_reply(original_id, msg)
                    return

                if tag == "tool_result":
                    # This is a future from _handle_tool_call upstream_handler
                    future = original_id
                    if msg.error:
                        future.set_result({"error": msg.error.get("message", "Upstream error")})
                    else:
                        future.set_result(msg.result if msg.result else {"status": "success"})
                    return

            # Regular passthrough — remap ID back to agent's original
            response = {"jsonrpc": "2.0", "id": pending}
            if msg.result is not None:
                response["result"] = msg.result
            if msg.error is not None:
                response["error"] = msg.error
            await self.agent_transport.write_message(response)

    async def _inject_canaries_and_reply(self, agent_id: Any, msg: JsonRpcMessage) -> None:
        """Filter tools by permission tier, then inject canary honeypots.

        This is the RBAC gate — the agent only sees tools it's allowed to use.
        Canary honeypots are always injected (they're traps, not real tools).

        Flow:
          upstream_tools → ManifestFilter (hide by tier) → + canaries → agent
        """
        tools = []
        if msg.result and "tools" in msg.result:
            tools = msg.result["tools"]
            self._upstream_tools = tools  # Cache full list for reference

        # Get session permission tier
        session = self.proxy.get_or_create_session(self._session_id)
        tier = session.permission_tier
        extra = session.extra_tools

        # Filter upstream tools based on permission tier
        visible_tools = self.manifest_filter.filter_manifest(
            upstream_tools=tools,
            tier=tier,
            extra_tools=extra,
            unknown_tool_policy=self.config.unknown_tool_policy,
        )

        # Add canary honeypot definitions (always visible — they're traps)
        canaries = self.proxy.get_tool_list()
        all_tools = visible_tools + canaries

        hidden_count = len(tools) - len(visible_tools)
        logger.info(
            "Tools manifest: %d upstream, %d visible (tier %s), %d hidden, %d canaries = %d total",
            len(tools), len(visible_tools), tier.name,
            hidden_count, len(canaries), len(all_tools),
        )

        # Build response preserving any other fields from upstream
        result = dict(msg.result) if msg.result else {}
        result["tools"] = all_tools

        await self.agent_transport.write_message(make_response(agent_id, result))


async def run_stdio_proxy(config: UnwindConfig, upstream_command: list[str]) -> None:
    """Entry point — run UNWIND as a stdio MCP proxy.

    Usage:
        unwind serve -- npx @modelcontextprotocol/server-filesystem /path/to/workspace
    """
    server = UnwindStdioServer(config, upstream_command)
    await server.run()
