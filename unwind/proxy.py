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
from .craft import (
    CraftVerifier,
    CraftSessionState,
    CraftLifecycleManager,
    CraftStateStore,
)
from .craft.crypto import derive_session_keys, state_commit_0

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

        # CRAFT ingress runtime (v4.2 integration scaffolding)
        self.craft_verifier = CraftVerifier()
        self.craft_lifecycle = CraftLifecycleManager()
        self.craft_state_store: CraftStateStore | None = None
        self.craft_sessions: dict[str, CraftSessionState] = {}

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
        self.craft_state_store = CraftStateStore(self.config.unwind_home / "craft_state.json")
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

    # --- CRAFT ingress integration (v4.2 scaffolding) ---

    def create_craft_session(
        self,
        *,
        session_id: str,
        account_id: str,
        channel_id: str,
        conversation_id: str,
        context_type: str,
        ikm: bytes,
        salt0: bytes,
        server_secret: bytes,
        epoch: int = 0,
    ) -> CraftSessionState:
        """Create/register a CRAFT session state from handshake key material."""
        ctx = (
            f"CRAFT/v4.2|{session_id}|{account_id}|{channel_id}|{conversation_id}|{context_type}"
        ).encode("utf-8")
        keys = derive_session_keys(
            ikm=ikm,
            salt0=salt0,
            ctx=ctx,
            epoch=epoch,
            server_secret=server_secret,
        )
        craft = CraftSessionState.from_session_keys(
            session_id=session_id,
            account_id=account_id,
            channel_id=channel_id,
            conversation_id=conversation_id,
            context_type=context_type,
            epoch=epoch,
            keys=keys,
            ctx=ctx,
        )
        craft.last_state_commit["c2p"] = state_commit_0(keys.c2p.k_state, ctx)
        craft.last_state_commit["p2c"] = state_commit_0(keys.p2c.k_state, ctx)
        craft.record_state_commit("c2p", craft.last_state_commit["c2p"])
        craft.record_state_commit("p2c", craft.last_state_commit["p2c"])

        # Restore persisted continuity if available
        if self.craft_state_store:
            self.craft_state_store.restore_session_into(craft)

        self.craft_sessions[session_id] = craft
        return craft

    def verify_craft_envelope(
        self,
        *,
        session_id: str,
        envelope: dict,
        now_ms: Optional[int] = None,
    ) -> dict:
        """Verify/hold one CRAFT envelope on ingress.

        Returns a transport-friendly dict with accepted/held/error.
        Capability enforcement remains dispatch-only and is not invoked here.
        """
        craft = self.craft_sessions.get(session_id)
        if not craft:
            return {"accepted": False, "error": "ERR_CRAFT_SESSION_NOT_FOUND"}

        result = self.craft_verifier.verify_or_hold(envelope, craft, now_ms=now_ms)
        if self.craft_state_store and (result.accepted or result.held):
            self.craft_state_store.save_session(craft)

        return {
            "accepted": result.accepted,
            "held": result.held,
            "drained": result.drained,
            "error": result.error.value if result.error else None,
        }

    def craft_rekey_prepare(self, session_id: str) -> dict:
        craft = self.craft_sessions.get(session_id)
        if not craft:
            return {"error": "ERR_CRAFT_SESSION_NOT_FOUND"}
        p = self.craft_lifecycle.initiate_rekey(craft)
        return {
            "action": p.action,
            "session_id": p.session_id,
            "epoch_new": p.epoch_new,
            "boundary_seq_c2p": p.boundary_seq_c2p,
            "boundary_seq_p2c": p.boundary_seq_p2c,
        }

    def craft_rekey_apply(self, session_id: str, prepare_msg: dict) -> dict:
        craft = self.craft_sessions.get(session_id)
        if not craft:
            return {"ok": False, "error": "ERR_CRAFT_SESSION_NOT_FOUND"}
        try:
            prep = self.craft_lifecycle.initiate_rekey(craft)
            # Validate caller intent matches expected transition envelope
            if int(prepare_msg.get("epoch_new", -1)) != prep.epoch_new:
                return {"ok": False, "error": "ERR_REKEY_EPOCH_MISMATCH"}
            self.craft_lifecycle.apply_rekey_ack(craft, prep)
            if self.craft_state_store:
                self.craft_state_store.save_session(craft)
            return {"ok": True, "epoch": craft.current_epoch}
        except Exception as e:
            return {"ok": False, "error": f"ERR_REKEY_APPLY: {e}"}

    def craft_teardown(self, session_id: str, max_network_delay_ms: int = 5000) -> dict:
        craft = self.craft_sessions.get(session_id)
        if not craft:
            return {"ok": False, "error": "ERR_CRAFT_SESSION_NOT_FOUND"}
        self.craft_lifecycle.teardown_session(craft, max_network_delay_ms=max_network_delay_ms)
        if self.craft_state_store and craft.tombstoned_until_ms:
            self.craft_state_store.save_tombstone(session_id, craft.tombstoned_until_ms)
            self.craft_state_store.save_session(craft)
        return {"ok": True, "tombstoned_until_ms": craft.tombstoned_until_ms}

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

    # --- P3-10: Ghost Mode status / approve / discard ---

    def ghost_status(self, session_id: str) -> dict:
        """Return the current ghost mode shadow VFS status for a session.

        P3-10: Gives visibility into what ghost mode has buffered.
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        return session.ghost_status()

    async def ghost_approve(self, session_id: str) -> dict:
        """Commit all ghost-buffered writes to the real filesystem.

        P3-10: Approve = make ghost writes real, then clear shadow VFS.
        Safety: validates every path stays within workspace_root (path jail).
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        if not session.ghost_mode:
            return {"error": "Ghost mode is not active on this session"}
        if not session.shadow_vfs:
            return {"error": "Nothing buffered in ghost mode"}

        # --- Path jail validation (pre-flight) ---
        import os
        workspace = os.path.realpath(str(self.config.workspace_root))
        jail_violations = []
        for path in session.shadow_vfs:
            real = os.path.realpath(path)
            if not real.startswith(workspace + os.sep) and real != workspace:
                jail_violations.append(path)

        if jail_violations:
            return {
                "error": "Path jail violation — refusing to approve",
                "violations": jail_violations,
            }

        # --- Commit writes ---
        files_written = 0
        errors = []
        for path, content in session.shadow_vfs.items():
            try:
                real_path = os.path.realpath(path)
                os.makedirs(os.path.dirname(real_path), exist_ok=True)
                if isinstance(content, bytes):
                    with open(real_path, "wb") as f:
                        f.write(content)
                else:
                    with open(real_path, "w", encoding="utf-8") as f:
                        f.write(content)
                files_written += 1
            except Exception as e:
                errors.append({"path": path, "error": str(e)})

        # --- Log event ---
        event_id = self.event_store.write_pending(
            session_id=session.session_id,
            tool="_ghost_approve",
            tool_class="ghost_management",
            target=None,
            parameters={"files_approved": files_written},
            session_tainted=session.is_tainted,
            trust_state=session.trust_state.value,
            ghost_mode=True,
        )
        await self.event_store.complete_event_async(
            event_id, EventStatus.SUCCESS,
            result_summary=f"Ghost approved: {files_written} files committed",
        )

        # --- Clear shadow VFS ---
        session.clear_ghost()

        logger.info(
            "GHOST APPROVED: session %s — %d files committed",
            session_id, files_written,
        )

        result = {
            "status": "approved",
            "files_written": files_written,
        }
        if errors:
            result["errors"] = errors
        return result

    async def ghost_discard(self, session_id: str) -> dict:
        """Discard all ghost-buffered writes without committing.

        P3-10: Discard = throw away shadow VFS, agent starts fresh.
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        if not session.ghost_mode:
            return {"error": "Ghost mode is not active on this session"}

        files_discarded = len(session.shadow_vfs)

        # --- Log event ---
        event_id = self.event_store.write_pending(
            session_id=session.session_id,
            tool="_ghost_discard",
            tool_class="ghost_management",
            target=None,
            parameters={"files_discarded": files_discarded},
            session_tainted=session.is_tainted,
            trust_state=session.trust_state.value,
            ghost_mode=True,
        )
        await self.event_store.complete_event_async(
            event_id, EventStatus.SUCCESS,
            result_summary=f"Ghost discarded: {files_discarded} files dropped",
        )

        # --- Clear shadow VFS ---
        session.clear_ghost()

        logger.info(
            "GHOST DISCARDED: session %s — %d files dropped",
            session_id, files_discarded,
        )

        return {
            "status": "discarded",
            "files_discarded": files_discarded,
        }

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
