"""UNWIND MCP Proxy — the core middleware.

Sits between the agent (MCP client) and upstream tool servers (MCP servers).
The agent talks to UNWIND; UNWIND enforces checks, logs events, and forwards
to upstream. Neither side knows UNWIND exists.

Architecture:
  Agent → UNWIND (MCP Server) → Enforcement Pipeline → UNWIND (MCP Client) → Upstream

Transport: stdio for agent-facing side, stdio or SSE for upstream.
For v1, we use a simpler HTTP JSON-RPC bridge to upstream for testability.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Optional

from .config import UnwindConfig
from .session import Session, TrustState
from .enforcement.pipeline import EnforcementPipeline, CheckResult, PipelineResult
from .enforcement.canary import CanaryCheck
from .recorder.event_store import EventStore, EventStatus
from .snapshots.manager import SnapshotManager, Snapshot

logger = logging.getLogger("unwind.proxy")


class UnwindProxy:
    """The UNWIND MCP proxy — intercepts, enforces, logs, forwards.

    This class is transport-agnostic. It processes tool call requests
    and returns results. The transport layer (stdio, HTTP, etc.) is
    handled separately.
    """

    def __init__(self, config: UnwindConfig):
        self.config = config
        self.pipeline = EnforcementPipeline(config)
        self.canary_check = CanaryCheck(config)
        # Share the same canary registry between manifest injection and
        # pipeline detection (session-randomised names must match stage-1 kill).
        self.pipeline.canary = self.canary_check
        self.event_store = EventStore(config.events_db_path)
        self.snapshot_manager = SnapshotManager(config)
        self.sessions: dict[str, Session] = {}
        self._started = False

    def startup(self) -> None:
        """Initialize UNWIND — create dirs, open DB, run exposure check."""
        self.config.ensure_dirs()
        self.event_store.initialize()
        # P1-6: Enforce retention on startup (clean up old events)
        if self.config.events_retention_days > 0 or self.config.events_max_rows > 0:
            result = self.event_store.enforce_retention(
                retention_days=self.config.events_retention_days,
                max_rows=self.config.events_max_rows,
            )
            if result["events_deleted"] > 0:
                logger.info(
                    "Retention enforced: %d events deleted, %d snapshots deleted, "
                    "DB size: %d bytes",
                    result["events_deleted"],
                    result["snapshots_deleted"],
                    result["db_size_after"],
                )
        self._run_exposure_check()
        self._started = True
        logger.info(
            "UNWIND started — proxy on %s:%d, upstream on %s:%d",
            self.config.proxy_host, self.config.proxy_port,
            self.config.upstream_host, self.config.upstream_port,
        )
        logger.info("Upstream bearer token: %s...%s", self.config.upstream_token[:4], self.config.upstream_token[-4:])

    def shutdown(self) -> None:
        """Clean shutdown — close DB."""
        self.event_store.close()
        self._started = False
        logger.info("UNWIND shutdown complete")

    def _run_exposure_check(self) -> None:
        """Startup security check — warn about dangerous configurations."""
        warnings = []

        if self.config.proxy_host in ("0.0.0.0", "::"):
            warnings.append(
                "CRITICAL: UNWIND is bound to all interfaces (%s). "
                "This exposes the proxy to the network. "
                "Use 127.0.0.1 unless you specifically need remote access." % self.config.proxy_host
            )

        if self.config.upstream_host in ("0.0.0.0", "::"):
            warnings.append(
                "WARNING: Upstream is bound to all interfaces. "
                "Bind to 127.0.0.1 or a Unix socket to prevent proxy bypass."
            )

        # Check if running as root
        import os
        if os.getuid() == 0:
            warnings.append(
                "WARNING: UNWIND is running as root. "
                "This is not recommended for production use."
            )

        # Detect container environment
        if os.path.exists("/.dockerenv"):
            logger.info("Container environment detected (Docker)")
        elif os.path.exists("/proc/1/cgroup"):
            try:
                with open("/proc/1/cgroup") as f:
                    if "docker" in f.read() or "containerd" in f.read():
                        logger.info("Container environment detected (cgroup)")
            except (IOError, PermissionError):
                pass

        for w in warnings:
            logger.warning(w)

    def get_or_create_session(self, session_id: Optional[str] = None) -> Session:
        """Get an existing session or create a new one."""
        if session_id and session_id in self.sessions:
            return self.sessions[session_id]

        sid = session_id or f"sess_{uuid.uuid4().hex[:12]}"
        session = Session(session_id=sid, config=self.config)
        self.sessions[sid] = session
        return session

    def get_tool_list(self, session_id: Optional[str] = None) -> list[dict]:
        """Return canary honeypot tools for manifest injection.

        If session_id is provided, visible canary names are randomised
        per-session (P2-9 hardening). Without session_id, legacy static
        definitions are returned for backwards-compatibility tests.
        """
        return self.canary_check.get_canary_tool_definitions(session_id=session_id)

    def _extract_target(self, tool_name: str, params: Optional[dict]) -> Optional[str]:
        """Extract the target (path or URL) from tool parameters."""
        if params is None:
            return None

        # File tools: look for 'path', 'file', 'target'
        for key in ("path", "file", "target", "filename"):
            if key in params:
                return str(params[key])

        # Network tools: look for 'url', 'uri', 'endpoint'
        for key in ("url", "uri", "endpoint"):
            if key in params:
                return str(params[key])

        return None

    def _extract_payload(self, tool_name: str, params: Optional[dict]) -> Optional[str]:
        """Extract outbound payload from tool parameters for DLP scanning."""
        if params is None:
            return None

        # Email/message tools: look for 'body', 'content', 'message', 'text'
        for key in ("body", "content", "message", "text", "data"):
            if key in params:
                val = params[key]
                return str(val) if val is not None else None

        return None

    async def handle_tool_call(
        self,
        tool_name: str,
        parameters: Optional[dict] = None,
        session_id: Optional[str] = None,
        upstream_handler: Any = None,
    ) -> dict:
        """Process a single tool call through the enforcement pipeline.

        This is the main entry point. Every tool call flows through here.

        Args:
            tool_name: The MCP tool being called
            parameters: Tool call arguments
            session_id: Session identifier
            upstream_handler: Async callable to forward the tool call to upstream.
                              Signature: async (tool_name, params, token) -> dict

        Returns:
            Result dict to return to the agent
        """
        session = self.get_or_create_session(session_id)
        session.total_actions += 1

        target = self._extract_target(tool_name, parameters)
        payload = self._extract_payload(tool_name, parameters)

        # --- Run enforcement pipeline ---
        result = self.pipeline.check(
            session=session,
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            payload=payload,
        )

        # --- Write pre-call pending row ---
        event_id = self.event_store.write_pending(
            session_id=session.session_id,
            tool=tool_name,
            tool_class=result.tool_class,
            target=target,
            target_canonical=result.canonical_target,
            parameters=parameters,
            session_tainted=session.is_tainted,
            trust_state=session.trust_state.value,
            ghost_mode=session.ghost_mode,
        )

        start_time = time.time()

        # --- Act on pipeline result ---
        if result.action == CheckResult.KILL:
            session.blocked_actions += 1
            await self.event_store.complete_event_async(
                event_id, EventStatus.RED_ALERT, result_summary=result.block_reason
            )
            logger.critical("SESSION KILLED: %s — %s", session.session_id, result.block_reason)
            return {"error": result.block_reason}

        if result.action == CheckResult.BLOCK:
            session.blocked_actions += 1
            duration = (time.time() - start_time) * 1000
            await self.event_store.complete_event_async(
                event_id, EventStatus.BLOCKED, duration_ms=duration,
                result_summary=result.block_reason,
            )
            logger.warning("BLOCKED: %s on %s — %s", tool_name, target, result.block_reason)
            return {"error": f"Permission Denied: {result.block_reason}"}

        if result.action == CheckResult.AMBER:
            session.amber_confirmations += 1
            duration = (time.time() - start_time) * 1000
            # In v1, amber pauses for user confirmation.
            # The proxy returns an amber status; the transport layer handles the UX.
            await self.event_store.complete_event_async(
                event_id, EventStatus.BLOCKED, duration_ms=duration,
                result_summary=f"AMBER: {result.amber_reason}",
            )
            logger.warning("AMBER: %s — %s", tool_name, result.amber_reason)
            return {
                "status": "amber",
                "requires_confirmation": True,
                "reason": result.amber_reason,
                "event_id": event_id,
            }

        if result.action == CheckResult.GHOST:
            duration = (time.time() - start_time) * 1000
            await self.event_store.complete_event_async(
                event_id, EventStatus.GHOST_SUCCESS, duration_ms=duration,
                result_summary=f"Ghost mode: would have called {tool_name}",
            )
            logger.info("GHOST: %s on %s (not executed)", tool_name, target)

            # Check shadow VFS for reads in ghost mode
            if target and session.ghost_mode:
                shadow = session.ghost_read(target)
                if shadow is not None:
                    return {"status": "success", "content": shadow}

            return {"status": "success"}

        # --- Pre-action snapshot for state-modifying tools ---
        snapshot = None
        if tool_name in self.config.state_modifying_tools and target:
            try:
                if tool_name in ("fs_delete",):
                    snapshot = self.snapshot_manager.snapshot_file_delete(event_id, target)
                elif tool_name in ("fs_write", "fs_rename"):
                    snapshot = self.snapshot_manager.snapshot_file_write(event_id, target)
                # Store snapshot metadata in DB
                if snapshot:
                    self.event_store.store_snapshot(
                        snapshot_id=snapshot.snapshot_id,
                        event_id=snapshot.event_id,
                        timestamp=snapshot.timestamp,
                        snapshot_type=snapshot.snapshot_type,
                        original_path=snapshot.original_path,
                        snapshot_path=snapshot.snapshot_path,
                        original_size=snapshot.original_size,
                        original_hash=snapshot.original_hash,
                        metadata=snapshot.metadata,
                        restorable=snapshot.restorable,
                    )
            except Exception as e:
                logger.warning("Snapshot failed for %s on %s: %s (proceeding anyway)", tool_name, target, e)

        # --- ALLOW: forward to upstream ---
        if upstream_handler:
            try:
                upstream_result = await upstream_handler(
                    tool_name, parameters, self.config.upstream_token
                )
                duration = (time.time() - start_time) * 1000
                await self.event_store.complete_event_async(
                    event_id, EventStatus.SUCCESS, duration_ms=duration,
                    result_summary="OK",
                )
                return upstream_result
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                await self.event_store.complete_event_async(
                    event_id, EventStatus.ERROR, duration_ms=duration,
                    result_summary=str(e),
                )
                logger.error("Upstream error for %s: %s", tool_name, e)
                return {"error": f"Upstream error: {e}"}
        else:
            # No upstream — return success (useful for testing)
            duration = (time.time() - start_time) * 1000
            await self.event_store.complete_event_async(
                event_id, EventStatus.SUCCESS, duration_ms=duration,
                result_summary="OK (no upstream)",
            )
            return {"status": "success"}

    async def approve_amber(self, event_id: str, session_id: str) -> dict:
        """User approves an amber-gated action. Re-run with approval."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        # Update the event status
        await self.event_store.complete_event_async(
            event_id, EventStatus.SUCCESS,
            result_summary="Approved by user after amber gate",
        )
        return {"status": "approved", "event_id": event_id}
