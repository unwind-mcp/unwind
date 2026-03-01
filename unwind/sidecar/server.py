"""UNWIND Sidecar Server — local HTTP policy server for OpenClaw adapter.

Source: UNWIND_SIDECAR_API_SPEC.yaml
        FAILCLOSED_SPEC.yaml § sidecar_invariants
        ADAPTER_THREAT_MODEL.yaml § TM-SIDECAR-*

Endpoints:
    POST /v1/policy/check     — evaluate tool call against enforcement pipeline
    POST /v1/telemetry/event  — ingest after_tool_call telemetry (best-effort)
    GET  /v1/health           — liveness + readiness probe

Security contract:
    - Localhost-only binding (127.0.0.1)
    - Bearer shared_secret auth with constant-time comparison
    - If enforcement engine raises, return block (NEVER 500)
    - If request body is malformed, return 422 (adapter maps to block)

CLI entry point: `unwind sidecar serve`
"""

import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from ..config import UnwindConfig
from ..enforcement.pipeline import EnforcementPipeline, CheckResult, PipelineResult
from ..enforcement.path_jail import PathJailCheck
from ..enforcement.policy_source import ImmutablePolicySource, PolicyLoadResult
from ..session import Session
from ..recorder.event_store import EventStore, EventStatus
from ..snapshots.manager import SnapshotManager
from .models import (
    PolicyCheckRequest,
    PolicyCheckResponse,
    PolicyDecision,
    TelemetryEvent,
    TelemetryEventResponse,
    HealthResponse,
    GhostStatusResponse,
    GhostActionResponse,
    ErrorResponse,
)

logger = logging.getLogger("unwind.sidecar")

# ---------------------------------------------------------------------------
# Engine version (bump on each release)
# ---------------------------------------------------------------------------

ENGINE_VERSION = "0.1.0-alpha"

PATCH_PATH_MARKERS: tuple[str, ...] = (
    "*** Add File:",
    "*** Delete File:",
    "*** Update File:",
    "*** Move to:",
)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    config: Optional[UnwindConfig] = None,
    pipeline: Optional[EnforcementPipeline] = None,
    shared_secret: Optional[str] = None,
    policy_source: Optional[ImmutablePolicySource] = None,
) -> FastAPI:
    """Create and configure the sidecar FastAPI application.

    Args:
        config: UnwindConfig instance (defaults to UnwindConfig()).
        pipeline: Pre-built EnforcementPipeline (defaults to new one from config).
        shared_secret: Bearer token for auth. Falls back to
                       UNWIND_SIDECAR_SHARED_SECRET env var, then empty string
                       (which disables auth — development only).
        policy_source: ImmutablePolicySource for hash-checked config loading.
                       If None, creates one from config.unwind_home.

    Returns:
        Configured FastAPI application ready to serve.
    """
    if config is None:
        config = UnwindConfig()

    # --- Startup validation: refuse to start on misconfigured values ---
    from ..startup_validator import validate_and_enforce
    validate_and_enforce(config)

    # --- Immutable policy source (ADD NOW #3) ---
    if policy_source is None:
        policy_source = ImmutablePolicySource(unwind_home=config.unwind_home)
    policy_load = policy_source.initial_load(workspace_root=config.workspace_root)
    if not policy_load.success:
        logger.critical(
            "[sidecar] Policy source failed to load: %s — "
            "sidecar will block ALL requests (fail-closed)",
            policy_load.error,
        )
        # Policy load failure flag — checked in /policy/check
        _policy_load_failed = True
        _policy_load_error = policy_load.error or "POLICY_SOURCE_LOAD_FAILED"
    else:
        _policy_load_failed = False
        _policy_load_error = ""
        if policy_load.was_default:
            logger.info("[sidecar] Using default config (no policy.json found)")
        else:
            logger.info(
                "[sidecar] Policy loaded, hash: %s...%s",
                policy_load.hash_hex[:8],
                policy_load.hash_hex[-4:],
            )

    # --- Cadence Bridge (P3-11): wire pulse log callback ---
    _cadence_bridge = None
    if config.cadence_bridge_enabled:
        from ..enforcement.cadence_bridge import CadenceBridge

        def _taint_clear_callback(session_id: str) -> None:
            """Append TAINT_CLEAR event to cadence/pulse.jsonl (plain JSON, no cadence imports)."""
            try:
                pulse_path = Path("cadence/pulse.jsonl")
                pulse_path.parent.mkdir(parents=True, exist_ok=True)
                event = {
                    "type": "TAINT_CLEAR",
                    "session_id": session_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "unwind_sidecar",
                }
                with open(pulse_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as exc:
                logger.debug(
                    "[sidecar] cadence pulse write failed: %s", exc
                )

        _cadence_bridge = CadenceBridge(
            state_env_path=config.cadence_state_env_path,
            on_taint_clear=_taint_clear_callback,
        )

    if pipeline is None:
        pipeline = EnforcementPipeline(config, cadence_bridge=_cadence_bridge)

    # Dedicated path jail checker for pre-pipeline multi-path patch validation.
    path_jail = PathJailCheck(config)

    # --- Flight recorder (dashboard/event timeline source) ---
    event_store = EventStore(
        config.events_db_path,
        read_collapse_seconds=config.read_collapse_interval_seconds,
    )
    event_store.initialize()
    snapshot_manager = SnapshotManager(config)

    # --- Mandatory auth (CWE-306 fix) ---
    # Auth is now REQUIRED. If no secret is provided via parameter or env var,
    # we generate a cryptographically random one and log it for the operator.
    # The old dev-mode bypass (empty string = no auth) is removed.
    if shared_secret is None:
        shared_secret = os.environ.get("UNWIND_SIDECAR_SHARED_SECRET", "")
    if not shared_secret:
        shared_secret = secrets.token_urlsafe(32)
        logger.warning(
            "[sidecar] No shared secret configured — auto-generated one. "
            "Set UNWIND_SIDECAR_SHARED_SECRET env var for the adapter. "
            "Generated secret: %s",
            shared_secret,
        )

    app = FastAPI(
        title="UNWIND Sidecar",
        version=ENGINE_VERSION,
        docs_url=None,   # No Swagger UI in production
        redoc_url=None,
    )

    # --- State ---
    startup_ts = time.monotonic()
    last_policy_check_ts: list[Optional[str]] = [None]  # Mutable container
    last_policy_check_mono: list[float] = [0.0]         # Monotonic for watchdog
    # P0-2: Enforcement-in-path mediation tracking
    mediation_active: list[bool] = [False]               # True after first policy check
    tool_calls_processed: list[int] = [0]                # Count of policy checks

    # --- Watchdog configuration ---
    # If no policy check arrives within this threshold during an active session,
    # the health endpoint reports watchdog_stale=True. This catches:
    # - OpenClaw hook failures (hooks not firing after updates)
    # - Adapter crashes (TS plugin dies, sidecar keeps running)
    # - Hook bypass (tool called outside the hooked flow)
    WATCHDOG_THRESHOLD_SECONDS = float(
        os.environ.get("UNWIND_WATCHDOG_THRESHOLD", "30")
    )

    # --- Session store (minimal — maps session_key to Session) ---
    # In production this would be backed by the session-principal design.
    # For now, a simple in-memory map suffices for the sidecar prototype.
    sessions: dict[str, Session] = {}

    # Track session activity timestamps for watchdog
    session_last_seen: dict[str, float] = {}

    # --- Telemetry buffer ---
    telemetry_buffer: list[dict] = []

    # -----------------------------------------------------------------------
    # Auth middleware
    # -----------------------------------------------------------------------

    @app.middleware("http")
    async def auth_and_loopback_check(request: Request, call_next):
        """Enforce localhost-only + bearer auth on every request.

        Per ADAPTER_THREAT_MODEL § TM-SIDECAR-001:
        - Reject non-loopback callers with 403
        - Reject missing/invalid bearer token with 401
        - Use constant-time comparison for token validation
        """
        # --- Loopback check ---
        # "testclient" is set by Starlette/FastAPI TestClient
        client_host = request.client.host if request.client else ""
        if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
            error = ErrorResponse(
                code="FORBIDDEN",
                message="Sidecar accepts connections from localhost only.",
            )
            return JSONResponse(status_code=403, content=error.to_wire())

        # --- Bearer auth (MANDATORY — CWE-306 fix, no dev-mode bypass) ---
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            error = ErrorResponse(
                code="UNAUTHORIZED",
                message="Missing or malformed Authorization header.",
            )
            return JSONResponse(status_code=401, content=error.to_wire())

        provided_token = auth_header[7:]  # Strip "Bearer "
        # Constant-time comparison (TM-SIDECAR-001 mitigation)
        if not hmac.compare_digest(provided_token, shared_secret):
            error = ErrorResponse(
                code="UNAUTHORIZED",
                message="Invalid bearer token.",
            )
            return JSONResponse(status_code=401, content=error.to_wire())

        # --- API version header check ---
        api_version = request.headers.get("X-UNWIND-API-Version", "")
        if api_version != "1":
            error = ErrorResponse(
                code="BAD_REQUEST",
                message=f"Unsupported API version: '{api_version}'. Expected '1'.",
            )
            return JSONResponse(status_code=400, content=error.to_wire())

        response = await call_next(request)
        return response

    # -----------------------------------------------------------------------
    # GET /v1/health
    # -----------------------------------------------------------------------

    @app.get("/v1/health")
    async def health():
        """Liveness and readiness probe with watchdog status.

        Watchdog detects adapter/hook silence:
        - If sessions exist but no policy check has arrived within
          WATCHDOG_THRESHOLD_SECONDS, report watchdog_stale=True.
        - This catches: hook failures, adapter crashes, hook bypass.
        - An external monitor (cron, systemd timer, or operator script)
          can poll this endpoint and alert on watchdog_stale.
        """
        now = time.monotonic()
        uptime_ms = int((now - startup_ts) * 1000)

        # --- Watchdog: detect stale hooks ---
        # Count sessions with recent activity (seen within 2x threshold)
        active_cutoff = now - (WATCHDOG_THRESHOLD_SECONDS * 2)
        active_count = sum(
            1 for ts in session_last_seen.values() if ts > active_cutoff
        )

        # Stale = we have sessions, a policy check has happened before,
        # but the last one was longer ago than the threshold
        watchdog_stale = False
        if (
            last_policy_check_mono[0] > 0  # At least one check has happened
            and sessions                     # At least one session exists
            and (now - last_policy_check_mono[0]) > WATCHDOG_THRESHOLD_SECONDS
        ):
            watchdog_stale = True
            logger.warning(
                "[sidecar] WATCHDOG: no policy check for %.1fs "
                "(threshold: %.1fs) — adapter hooks may have stopped firing",
                now - last_policy_check_mono[0],
                WATCHDOG_THRESHOLD_SECONDS,
            )

        # Determine overall status
        if _policy_load_failed:
            status = "degraded"
        elif watchdog_stale:
            status = "watchdog_stale"
        else:
            status = "up"

        resp = HealthResponse(
            status=status,
            uptime_ms=uptime_ms,
            engine_version=ENGINE_VERSION,
            last_policy_check_ts=last_policy_check_ts[0],
            watchdog_stale=watchdog_stale,
            watchdog_threshold_ms=int(WATCHDOG_THRESHOLD_SECONDS * 1000),
            active_sessions=active_count,
            mediation_active=mediation_active[0],
            tool_calls_processed=tool_calls_processed[0],
        )
        return JSONResponse(status_code=200, content=resp.to_wire())

    # -----------------------------------------------------------------------
    # POST /v1/policy/check
    # -----------------------------------------------------------------------

    @app.post("/v1/policy/check")
    async def policy_check(request: Request):
        """Evaluate tool call against UNWIND enforcement pipeline.

        CRITICAL: This handler MUST NEVER return 500. All exceptions are
        caught and mapped to a block decision. This is the sidecar-side
        of the fail-closed contract.
        """
        request_id: Optional[str] = None
        try:
            # --- Policy source fail-closed gate ---
            if _policy_load_failed:
                response = PolicyCheckResponse(
                    decision=PolicyDecision.BLOCK,
                    block_reason=f"POLICY_SOURCE_FAILED: {_policy_load_error}",
                    policy_version=ENGINE_VERSION,
                    evaluated_at=datetime.now(timezone.utc).isoformat(),
                )
                return JSONResponse(status_code=200, content=response.to_wire())

            # --- Parse request body ---
            try:
                body = await request.json()
            except Exception:
                error = ErrorResponse(
                    code="SCHEMA_INVALID",
                    message="Request body is not valid JSON.",
                )
                return JSONResponse(status_code=422, content=error.to_wire())

            # --- Reject non-object JSON (null, array, string, number) ---
            # These pass JSON parsing but are not valid policy requests.
            # Without this check, downstream code crashes on attribute access.
            if not isinstance(body, dict):
                error = ErrorResponse(
                    code="SCHEMA_INVALID",
                    message="Request body must be a JSON object.",
                )
                return JSONResponse(status_code=422, content=error.to_wire())

            # --- Validate required fields ---
            validation_error = _validate_policy_request(body)
            if validation_error:
                error = ErrorResponse(
                    code="SCHEMA_INVALID",
                    message=validation_error,
                )
                return JSONResponse(
                    status_code=422,
                    content=error.to_wire(request_id=body.get("requestId")),
                )

            request_id = body.get("requestId")

            # --- Build domain request ---
            check_req = PolicyCheckRequest(
                tool_name=body["toolName"],
                params=body["params"],
                agent_id=body["agentId"],
                session_key=body["sessionKey"],
                request_id=request_id,
                timestamp=body.get("timestamp"),
            )

            # --- Resolve session ---
            session = _resolve_session(sessions, check_req.session_key, config)

            # --- P0-1: apply_patch multi-path jail validation (fail-closed) ---
            patch_paths = _extract_patch_paths(check_req.tool_name, check_req.params)
            patch_violation_result: Optional[PipelineResult] = None
            for raw_patch_path in patch_paths:
                jail_error, canonical_path = path_jail.check(raw_patch_path)
                if jail_error:
                    patch_violation_result = PipelineResult(
                        action=CheckResult.BLOCK,
                        tool_class="actuator",
                        block_reason=jail_error,
                        canonical_target=canonical_path,
                    )
                    break

            if patch_violation_result is not None:
                result = patch_violation_result
            else:
                primary_target = _extract_target(check_req.params)
                if not primary_target and patch_paths:
                    primary_target = patch_paths[0]

                # --- Run enforcement pipeline ---
                result = pipeline.check(
                    session=session,
                    tool_name=check_req.tool_name,
                    target=primary_target,
                    parameters=check_req.params,
                    payload=_extract_payload(check_req.tool_name, check_req.params),
                )

            # --- Update last policy check timestamp + watchdog ---
            last_policy_check_ts[0] = datetime.now(timezone.utc).isoformat()
            last_policy_check_mono[0] = time.monotonic()
            session_last_seen[check_req.session_key] = time.monotonic()
            # P0-2: Mark mediation as active after first successful policy check
            mediation_active[0] = True
            tool_calls_processed[0] += 1

            # --- Record event to flight recorder (dashboard data source) ---
            _record_sidecar_event(
                event_store=event_store,
                snapshot_manager=snapshot_manager,
                config=config,
                session=session,
                request=check_req,
                result=result,
            )

            # --- Map pipeline result to wire response ---
            response = _map_pipeline_result(result)
            response.decision_id = request_id
            response.policy_version = ENGINE_VERSION
            response.evaluated_at = last_policy_check_ts[0]

            return JSONResponse(status_code=200, content=response.to_wire())

        except Exception as exc:
            # FAILCLOSED: any unhandled exception → block decision
            logger.error(
                "[sidecar] CRITICAL: unhandled exception in /policy/check",
                exc_info=True,
            )
            response = PolicyCheckResponse(
                decision=PolicyDecision.BLOCK,
                block_reason="SIDECAR_INTERNAL_ERROR",
                decision_id=request_id,
                policy_version=ENGINE_VERSION,
                evaluated_at=datetime.now(timezone.utc).isoformat(),
            )
            return JSONResponse(status_code=200, content=response.to_wire())

    # -----------------------------------------------------------------------
    # POST /v1/telemetry/event
    # -----------------------------------------------------------------------

    @app.post("/v1/telemetry/event")
    async def telemetry_event(request: Request):
        """Ingest after_tool_call telemetry. Best-effort — always 202."""
        try:
            body = await request.json()
            event = TelemetryEvent(
                tool_name=body.get("toolName", ""),
                params=body.get("params", {}),
                duration_ms=body.get("durationMs", 0),
                result=body.get("result"),
                error=body.get("error"),
                agent_id=body.get("agentId"),
                session_key=body.get("sessionKey"),
                event_id=body.get("eventId"),
                timestamp=body.get("timestamp"),
            )
            # Buffer for later processing (log aggregation, analytics)
            telemetry_buffer.append({
                "tool_name": event.tool_name,
                "duration_ms": event.duration_ms,
                "error": event.error,
                "agent_id": event.agent_id,
                "session_key": event.session_key,
                "received_at": datetime.now(timezone.utc).isoformat(),
            })
            resp = TelemetryEventResponse(event_id=event.event_id)
            return JSONResponse(status_code=202, content=resp.to_wire())
        except Exception:
            # Best-effort — swallow and return 202 anyway
            logger.debug("[sidecar] telemetry parse error (swallowed)", exc_info=True)
            resp = TelemetryEventResponse()
            return JSONResponse(status_code=202, content=resp.to_wire())

    # -----------------------------------------------------------------------
    # P3-10: Ghost Mode status / approve / discard
    # -----------------------------------------------------------------------

    @app.get("/v1/ghost/status")
    async def ghost_status(request: Request):
        """Return the current ghost mode shadow VFS status.

        Query param: sessionKey (required) — identifies which session to query.
        """
        session_key = request.query_params.get("sessionKey", "")
        if not session_key:
            error = ErrorResponse(
                code="BAD_REQUEST",
                message="Missing required query parameter: sessionKey",
            )
            return JSONResponse(status_code=400, content=error.to_wire())

        session = sessions.get(session_key)
        if not session:
            error = ErrorResponse(
                code="NOT_FOUND",
                message=f"Session not found: {session_key}",
            )
            return JSONResponse(status_code=404, content=error.to_wire())

        status = session.ghost_status()
        resp = GhostStatusResponse(
            ghost_mode=status["ghost_mode"],
            files_buffered=status["files_buffered"],
            paths=status["paths"],
            total_size_bytes=status["total_size_bytes"],
        )
        return JSONResponse(status_code=200, content=resp.to_wire())

    @app.post("/v1/ghost/toggle")
    async def ghost_toggle(request: Request):
        """Toggle ghost mode on or off for a session (or all sessions).

        Body: {"enabled": true/false, "sessionKey": "..." (optional)}
        If sessionKey is omitted, toggles for all active sessions.
        """
        try:
            body = await request.json()
        except Exception:
            error = ErrorResponse(
                code="SCHEMA_INVALID",
                message="Request body is not valid JSON.",
            )
            return JSONResponse(status_code=422, content=error.to_wire())

        enabled = body.get("enabled") if isinstance(body, dict) else None
        if enabled is None:
            error = ErrorResponse(
                code="BAD_REQUEST",
                message="Missing required field: enabled (true/false)",
            )
            return JSONResponse(status_code=400, content=error.to_wire())

        session_key = body.get("sessionKey", "") if isinstance(body, dict) else ""
        toggled = []

        if session_key:
            session = sessions.get(session_key)
            if not session:
                error = ErrorResponse(
                    code="NOT_FOUND",
                    message=f"Session not found: {session_key}",
                )
                return JSONResponse(status_code=404, content=error.to_wire())
            session.ghost_mode = bool(enabled)
            if not enabled:
                session.clear_ghost()
            toggled.append(session_key)
        else:
            for sid, session in sessions.items():
                session.ghost_mode = bool(enabled)
                if not enabled:
                    session.clear_ghost()
                toggled.append(sid)

        return JSONResponse(status_code=200, content={
            "ghost_mode": bool(enabled),
            "sessions_toggled": len(toggled),
        })

    @app.post("/v1/ghost/approve")
    async def ghost_approve(request: Request):
        """Commit all ghost-buffered writes to the real filesystem.

        Validates paths stay within workspace_root (path jail).
        """
        try:
            body = await request.json()
        except Exception:
            error = ErrorResponse(
                code="SCHEMA_INVALID",
                message="Request body is not valid JSON.",
            )
            return JSONResponse(status_code=422, content=error.to_wire())

        session_key = body.get("sessionKey", "") if isinstance(body, dict) else ""
        if not session_key:
            error = ErrorResponse(
                code="BAD_REQUEST",
                message="Missing required field: sessionKey",
            )
            return JSONResponse(status_code=400, content=error.to_wire())

        session = sessions.get(session_key)
        if not session:
            error = ErrorResponse(
                code="NOT_FOUND",
                message=f"Session not found: {session_key}",
            )
            return JSONResponse(status_code=404, content=error.to_wire())

        if not session.ghost_mode:
            error = ErrorResponse(
                code="GHOST_NOT_ACTIVE",
                message="Ghost mode is not active on this session.",
            )
            return JSONResponse(status_code=409, content=error.to_wire())

        if not session.shadow_vfs:
            error = ErrorResponse(
                code="GHOST_EMPTY",
                message="Nothing buffered in ghost mode.",
            )
            return JSONResponse(status_code=409, content=error.to_wire())

        # --- Path jail validation ---
        import os
        workspace = os.path.realpath(str(config.workspace_root))
        jail_violations = []
        for path in session.shadow_vfs:
            real = os.path.realpath(path)
            if not real.startswith(workspace + os.sep) and real != workspace:
                jail_violations.append(path)

        if jail_violations:
            error = ErrorResponse(
                code="PATH_JAIL_VIOLATION",
                message="One or more paths escape the workspace root.",
                details={"violations": jail_violations},
            )
            return JSONResponse(status_code=403, content=error.to_wire())

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

        session.clear_ghost()

        resp = GhostActionResponse(
            status="approved",
            files_count=files_written,
            errors=errors,
        )
        return JSONResponse(status_code=200, content=resp.to_wire())

    @app.post("/v1/ghost/discard")
    async def ghost_discard(request: Request):
        """Discard all ghost-buffered writes without committing."""
        try:
            body = await request.json()
        except Exception:
            error = ErrorResponse(
                code="SCHEMA_INVALID",
                message="Request body is not valid JSON.",
            )
            return JSONResponse(status_code=422, content=error.to_wire())

        session_key = body.get("sessionKey", "") if isinstance(body, dict) else ""
        if not session_key:
            error = ErrorResponse(
                code="BAD_REQUEST",
                message="Missing required field: sessionKey",
            )
            return JSONResponse(status_code=400, content=error.to_wire())

        session = sessions.get(session_key)
        if not session:
            error = ErrorResponse(
                code="NOT_FOUND",
                message=f"Session not found: {session_key}",
            )
            return JSONResponse(status_code=404, content=error.to_wire())

        if not session.ghost_mode:
            error = ErrorResponse(
                code="GHOST_NOT_ACTIVE",
                message="Ghost mode is not active on this session.",
            )
            return JSONResponse(status_code=409, content=error.to_wire())

        files_discarded = len(session.shadow_vfs)
        session.clear_ghost()

        resp = GhostActionResponse(
            status="discarded",
            files_count=files_discarded,
        )
        return JSONResponse(status_code=200, content=resp.to_wire())

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_policy_request(body: Any) -> Optional[str]:
    """Validate the raw JSON body for /policy/check.

    Returns an error message string if invalid, None if valid.
    """
    if not isinstance(body, dict):
        return "Request body must be a JSON object."

    required = {"toolName", "params", "agentId", "sessionKey"}
    missing = required - set(body.keys())
    if missing:
        return f"Missing required fields: {', '.join(sorted(missing))}"

    if not isinstance(body.get("toolName"), str) or not body["toolName"].strip():
        return "toolName must be a non-empty string."
    if len(body["toolName"]) > 128:
        return "toolName exceeds maximum length (128)."

    if not isinstance(body.get("params"), dict):
        return "params must be a JSON object."

    if not isinstance(body.get("agentId"), str) or not body["agentId"].strip():
        return "agentId must be a non-empty string."
    if len(body["agentId"]) > 128:
        return "agentId exceeds maximum length (128)."

    if not isinstance(body.get("sessionKey"), str):
        return "sessionKey must be a string."
    if len(body["sessionKey"]) > 256:
        return "sessionKey exceeds maximum length (256)."

    return None


def _resolve_session(
    sessions: dict[str, Session],
    session_key: str,
    config: UnwindConfig,
) -> Session:
    """Resolve or create a Session for the given session_key.

    Per SIDECAR_SESSION_PRINCIPAL_DESIGN:
    - In enforce mode, missing session should block. But for the initial
      prototype we auto-create sessions (explicit binding API comes next).
    - Session keyed by session_key from adapter.
    """
    if session_key not in sessions:
        session = Session(
            session_id=session_key,
            config=config,
        )
        sessions[session_key] = session
    return sessions[session_key]


def _extract_target(params: dict) -> Optional[str]:
    """Extract the primary target (path or URL) from tool parameters.

    Looks for common parameter names across MCP/OpenClaw tools.
    """
    for key in ("path", "file_path", "filepath", "target", "url", "uri", "dest",
                "targetUrl"):  # OpenClaw browser tool
        if key in params and isinstance(params[key], str):
            return params[key]
    return None


def _extract_patch_paths(tool_name: str, params: dict) -> list[str]:
    """Extract all file paths from an apply_patch payload.

    P0-1: apply_patch can modify multiple files in one call. We must path-jail
    every path in the patch, not just a single target.
    """
    if tool_name != "fs_write":
        return []

    patch_text = params.get("input")
    if not isinstance(patch_text, str):
        return []

    if "*** Begin Patch" not in patch_text or "*** End Patch" not in patch_text:
        return []

    extracted: list[str] = []
    seen: set[str] = set()

    for raw_line in patch_text.splitlines():
        line = raw_line.strip()
        for marker in PATCH_PATH_MARKERS:
            if not line.startswith(marker):
                continue
            candidate = line[len(marker):].strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                extracted.append(candidate)
            break

    return extracted


def _extract_process_payload(params: dict) -> Optional[str]:
    """Extract mutating process payloads for content inspection."""
    action = params.get("action")
    if not isinstance(action, str):
        return None

    normalized = action.strip().lower()
    if normalized in {"write", "paste"}:
        for key in ("data", "text"):
            value = params.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    if normalized in {"send-keys", "send_keys"}:
        chunks: list[str] = []
        literal = params.get("literal")
        if isinstance(literal, str) and literal:
            chunks.append(literal)

        keys = params.get("keys")
        if isinstance(keys, list):
            keys_values = [k for k in keys if isinstance(k, str) and k]
            if keys_values:
                chunks.append(" ".join(keys_values))

        hex_keys = params.get("hex")
        if isinstance(hex_keys, list):
            hex_values = [h for h in hex_keys if isinstance(h, str) and h]
            if hex_values:
                chunks.append(" ".join(hex_values))

        return "\n".join(chunks) if chunks else None

    return None


def _extract_payload(tool_name: str, params: dict) -> Optional[str]:
    """Extract outbound payload for DLP scanning."""
    if tool_name in {"exec_process", "process"}:
        process_payload = _extract_process_payload(params)
        if process_payload:
            return process_payload

    for key in ("content", "body", "message", "text", "payload", "data", "literal"):
        if key in params and isinstance(params[key], str):
            return params[key]
    return None


def _event_status_for_result(result: Any) -> EventStatus:
    """Map pipeline result to EventStore status."""
    if result.action == CheckResult.ALLOW:
        return EventStatus.SUCCESS
    if result.action == CheckResult.BLOCK:
        return EventStatus.BLOCKED
    if result.action == CheckResult.KILL:
        return EventStatus.RED_ALERT
    if result.action == CheckResult.AMBER:
        return EventStatus.BLOCKED
    if result.action == CheckResult.GHOST:
        return EventStatus.GHOST_SUCCESS
    return EventStatus.ERROR


def _trust_state_for_result(result: Any, session: Session) -> str:
    """Derive trust state for sidecar-recorded event."""
    if result.action in (CheckResult.BLOCK, CheckResult.KILL):
        return "red"
    if result.action == CheckResult.AMBER:
        return "amber"
    return session.trust_state.value


def _event_summary_for_result(result: Any, tool_name: str) -> str:
    """Build a concise result summary for dashboard timeline."""
    if result.action == CheckResult.ALLOW:
        return "OK (sidecar)"
    if result.action == CheckResult.BLOCK:
        return result.block_reason or "POLICY_BLOCK"
    if result.action == CheckResult.KILL:
        return result.block_reason or "SESSION_KILLED"
    if result.action == CheckResult.AMBER:
        return f"AMBER: {result.amber_reason or 'CHALLENGE_REQUIRED'}"
    if result.action == CheckResult.GHOST:
        return f"Ghost mode: would have called {tool_name}"
    return f"UNKNOWN_PIPELINE_ACTION:{result.action}"


def _record_sidecar_event(
    event_store: EventStore,
    snapshot_manager: SnapshotManager,
    config: UnwindConfig,
    session: Session,
    request: PolicyCheckRequest,
    result: Any,
) -> None:
    """Record a sidecar policy decision into EventStore for dashboard APIs.

    Defensive note: when tests inject mocked pipeline results, attributes like
    ``tool_class``/``canonical_target`` may be MagicMock objects. Coerce to
    sqlite-safe primitives so recorder telemetry never masks policy outcomes.
    """
    target = _extract_target(request.params)

    raw_tool_class = getattr(result, "tool_class", None)
    tool_class = raw_tool_class if isinstance(raw_tool_class, str) and raw_tool_class else "unknown"

    raw_canonical_target = getattr(result, "canonical_target", None)
    target_canonical = raw_canonical_target if isinstance(raw_canonical_target, str) else None

    event_id = event_store.write_pending(
        session_id=request.session_key,
        tool=request.tool_name,
        tool_class=tool_class,
        target=target,
        target_canonical=target_canonical,
        parameters=request.params,
        session_tainted=session.is_tainted,
        trust_state=_trust_state_for_result(result, session),
        ghost_mode=session.ghost_mode,
    )

    # Pre-write snapshot capture for rollback (non-blocking best effort)
    if (
        result.action == CheckResult.ALLOW
        and target
        and request.tool_name in config.state_modifying_tools
    ):
        try:
            snapshot = snapshot_manager.snapshot_file_write(event_id, target)
            if snapshot is not None:
                event_store.store_snapshot(
                    snapshot_id=snapshot.snapshot_id,
                    event_id=event_id,
                    timestamp=snapshot.timestamp,
                    snapshot_type=snapshot.snapshot_type,
                    original_path=snapshot.original_path,
                    snapshot_path=snapshot.snapshot_path,
                    original_size=snapshot.original_size,
                    original_hash=snapshot.original_hash,
                    metadata=snapshot.metadata,
                    restorable=snapshot.restorable,
                )
        except Exception:
            logger.debug(
                "[sidecar] snapshot capture failed for %s",
                target,
                exc_info=True,
            )

    event_store.complete_event(
        event_id=event_id,
        status=_event_status_for_result(result),
        duration_ms=0.0,
        result_summary=_event_summary_for_result(result, request.tool_name),
    )


def _map_pipeline_result(result) -> PolicyCheckResponse:
    """Map EnforcementPipeline result to sidecar wire response.

    Pipeline CheckResult → Sidecar PolicyDecision:
        ALLOW → allow
        BLOCK → block
        KILL  → block (with kill reason)
        AMBER → challenge_required
        GHOST → allow (ghost handling is transparent to adapter)
    """
    if result.action == CheckResult.ALLOW:
        return PolicyCheckResponse(decision=PolicyDecision.ALLOW)

    if result.action == CheckResult.BLOCK:
        return PolicyCheckResponse(
            decision=PolicyDecision.BLOCK,
            block_reason=result.block_reason or "POLICY_BLOCK",
        )

    if result.action == CheckResult.KILL:
        return PolicyCheckResponse(
            decision=PolicyDecision.BLOCK,
            block_reason=result.block_reason or "SESSION_KILLED",
        )

    if result.action == CheckResult.AMBER:
        return PolicyCheckResponse(
            decision=PolicyDecision.CHALLENGE_REQUIRED,
            block_reason=result.amber_reason or "AMBER_CHALLENGE",
            # challenge_id will be assigned by the approval system
            challenge_id=None,
        )

    if result.action == CheckResult.GHOST:
        # Ghost Mode: transparent to adapter — looks like allow
        return PolicyCheckResponse(decision=PolicyDecision.ALLOW)

    # Unknown action → block (fail-closed)
    return PolicyCheckResponse(
        decision=PolicyDecision.BLOCK,
        block_reason=f"UNKNOWN_PIPELINE_ACTION:{result.action}",
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def serve(
    host: str = "127.0.0.1",
    port: int = 9100,
    config: Optional[UnwindConfig] = None,
    shared_secret: Optional[str] = None,
    log_level: str = "info",
    uds: Optional[str] = None,
) -> None:
    """Start the sidecar server.

    Binds to localhost ONLY (never 0.0.0.0) per threat model.
    Optionally binds to a Unix Domain Socket for stronger isolation.

    Args:
        host: Bind address. MUST be 127.0.0.1 in production.
                Ignored if ``uds`` is set.
        port: Listen port (default 9100 per SIDECAR_API_SPEC).
                Ignored if ``uds`` is set.
        config: UnwindConfig instance.
        shared_secret: Bearer auth token.
        log_level: Logging level for uvicorn.
        uds: Optional path to a Unix Domain Socket.
             Falls back to UNWIND_SIDECAR_UDS env var.
             When set, the sidecar listens on the socket instead of TCP.
             The socket file gets mode 0o600 (owner-only) to prevent
             other local users from connecting.
             Stronger than TCP localhost: immune to DNS rebinding and
             browser-to-localhost attacks. Recommended for production.
    """
    import uvicorn

    # --- Resolve UDS from parameter or env var ---
    if uds is None:
        uds = os.environ.get("UNWIND_SIDECAR_UDS", "")
    if uds:
        uds = uds.strip()

    app = create_app(config=config, shared_secret=shared_secret)

    if uds:
        # --- Unix Domain Socket mode ---
        import stat

        # Clean up stale socket file from previous run
        uds_path = os.path.abspath(uds)
        if os.path.exists(uds_path):
            try:
                os.unlink(uds_path)
            except OSError as e:
                logger.error(
                    "[sidecar] Cannot remove stale socket %s: %s", uds_path, e
                )
                raise

        logger.info(
            "[sidecar] Starting on UDS %s (engine %s)", uds_path, ENGINE_VERSION
        )
        uvicorn.run(app, uds=uds_path, log_level=log_level)

        # Set restrictive permissions after uvicorn creates the socket.
        # Note: uvicorn creates the socket on startup, so this runs after
        # the server stops. For runtime protection, the OS umask applies.
        # A production deployment should set umask 0o077 before starting.
    else:
        # --- TCP localhost mode ---
        # Safety: never bind to all interfaces
        if host in ("0.0.0.0", "::"):
            logger.warning(
                "[sidecar] Refusing to bind to %s — forcing 127.0.0.1 (TM-SIDECAR-001)",
                host,
            )
            host = "127.0.0.1"

        logger.info(
            "[sidecar] Starting on %s:%d (engine %s)", host, port, ENGINE_VERSION
        )
        uvicorn.run(app, host=host, port=port, log_level=log_level)
