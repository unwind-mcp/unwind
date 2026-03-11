"""UNWIND Dashboard — Flask web application.

Provides:
- REST API for event timeline, trust state, snapshots, away mode
- Ghost Mode proxy endpoints (status, toggle, approve, discard, events)
- Single-page dashboard with real-time polling
- Undo actions via API
"""

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template, request

from ..config import UnwindConfig
from ..recorder.event_store import EventStore
from ..snapshots.manager import SnapshotManager, Snapshot
from ..snapshots.rollback import RollbackEngine, RollbackStatus
from .away_mode import generate_away_summary
from .explanations import explain

# Sidecar base URL and auth — read once at import time
SIDECAR_URL = os.environ.get("UNWIND_SIDECAR_URL", "http://127.0.0.1:9100")
SIDECAR_SECRET = os.environ.get("UNWIND_SIDECAR_SHARED_SECRET", "")

# --- Signed health verification (unwind.system_health.v1) ---
from ..sidecar.health_schema import (
    ReasonCode,
    SequenceTracker,
    check_freshness,
    derive_health_signing_key,
    verify_health_signature,
)

_HEALTH_SIGNING_KEY = derive_health_signing_key(SIDECAR_SECRET) if SIDECAR_SECRET else None
_HEALTH_SEQ_TRACKER = SequenceTracker()


def _cron_jobs_path() -> Path:
    """Return the OpenClaw cron jobs registry path used for dashboard labels."""
    explicit = os.environ.get("UNWIND_DASHBOARD_CRON_JOBS_PATH") or os.environ.get("OPENCLAW_CRON_JOBS_PATH")
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".openclaw" / "cron" / "jobs.json"


def _load_scheduled_task_labels() -> dict[str, str]:
    """Load cron job id->name mapping.

    Returns an empty mapping if the registry is missing or malformed.
    """
    jobs_path = _cron_jobs_path()
    try:
        raw = json.loads(jobs_path.read_text())
    except Exception:
        return {}

    jobs = raw.get("jobs") if isinstance(raw, dict) else None
    if not isinstance(jobs, list):
        return {}

    labels: dict[str, str] = {}
    for job in jobs:
        if not isinstance(job, dict):
            continue
        jid = str(job.get("id") or "").strip()
        if not jid:
            continue
        name = str(job.get("name") or "").strip()
        labels[jid] = name or jid
    return labels


def _truncate_label(text: str, max_len: int = 24) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _classify_session_source(session_id: Optional[str], scheduled_labels: dict[str, str]) -> dict:
    """Classify session source for dashboard badges and metadata."""
    if not session_id:
        return {
            "kind": "unknown",
            "short": "unknown",
            "long": "Unknown session source",
            "scheduled_job_id": None,
            "scheduled_job_name": None,
        }

    if session_id == "agent:main:main":
        return {
            "kind": "interactive",
            "short": "this-session",
            "long": "Current chat session (agent:main:main)",
            "scheduled_job_id": None,
            "scheduled_job_name": None,
        }

    if ":cron:" in session_id:
        job_id = session_id.rsplit(":cron:", 1)[-1]
        job_name = scheduled_labels.get(job_id)
        if job_name:
            return {
                "kind": "scheduled",
                "short": _truncate_label(job_name),
                "long": f"Scheduled task: {job_name} ({job_id})",
                "scheduled_job_id": job_id,
                "scheduled_job_name": job_name,
            }
        return {
            "kind": "scheduled",
            "short": "scheduled",
            "long": f"Scheduled run ({session_id})",
            "scheduled_job_id": job_id,
            "scheduled_job_name": None,
        }

    if ":subagent:" in session_id:
        return {
            "kind": "subagent",
            "short": "subagent",
            "long": f"Sub-agent session ({session_id})",
            "scheduled_job_id": None,
            "scheduled_job_name": None,
        }

    if session_id.startswith("agent:"):
        return {
            "kind": "agent",
            "short": "agent",
            "long": f"Agent session ({session_id})",
            "scheduled_job_id": None,
            "scheduled_job_name": None,
        }

    if session_id.startswith("sentinel:"):
        return {
            "kind": "scheduled",
            "short": _truncate_label(session_id),
            "long": f"Scheduled task ({session_id})",
            "scheduled_job_id": None,
            "scheduled_job_name": session_id,
        }

    return {
        "kind": "other",
        "short": "other",
        "long": f"Session: {session_id}",
        "scheduled_job_id": None,
        "scheduled_job_name": None,
    }


def _approval_required(event: dict) -> bool:
    """Best-effort detector for human approval challenges."""
    summary = str(event.get("result_summary") or "").upper()
    status = str(event.get("status") or "").lower()
    trust = str(event.get("trust_state") or "").lower()

    if summary.startswith("AMBER:"):
        return True
    if "CHALLENGE_REQUIRED" in summary or "REQUIRES APPROVAL" in summary:
        return True
    return status == "blocked" and trust == "amber"


def _enrich_event(event: dict, scheduled_labels: dict[str, str]) -> dict:
    """Attach dashboard UX metadata to an event row."""
    source = _classify_session_source(event.get("session_id"), scheduled_labels)
    event["session_source"] = source["kind"]
    event["session_source_short"] = source["short"]
    event["session_source_long"] = source["long"]
    event["scheduled_job_id"] = source["scheduled_job_id"]
    event["scheduled_job_name"] = source["scheduled_job_name"]
    event["approval_required"] = _approval_required(event)
    return event


def _proxy_sidecar(method, path, params=None, body=None):
    """Forward request to sidecar. Returns (status_code, json_body).
    On connection failure: returns (503, {"error": "Sidecar unavailable"})."""
    url = SIDECAR_URL.rstrip("/") + path
    if params:
        qs = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items())
        url += "?" + qs

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    headers = {"X-UNWIND-API-Version": "1"}
    if data:
        headers["Content-Type"] = "application/json"
    if SIDECAR_SECRET:
        headers["Authorization"] = f"Bearer {SIDECAR_SECRET}"

    req = urllib.request.Request(
        url,
        method=method,
        data=data,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("utf-8")
            return e.code, json.loads(body_text)
        except Exception:
            return e.code, {"error": str(e)}
    except (urllib.error.URLError, OSError):
        return 503, {"error": "Sidecar unavailable"}


def create_app(config: UnwindConfig = None) -> Flask:
    """Create and configure the Flask dashboard app."""
    if config is None:
        config = UnwindConfig()

    # --- Startup validation: refuse to start on misconfigured values ---
    from ..startup_validator import validate_and_enforce
    validate_and_enforce(config)

    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"
    app = Flask(__name__, template_folder=str(template_dir), static_folder=str(static_dir))
    app.config["UNWIND_CONFIG"] = config

    store = EventStore(config.events_db_path)
    store.initialize()
    rollback_engine = RollbackEngine(config)
    scheduled_labels = _load_scheduled_task_labels()

    # ─── Pages ───────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    # ─── API: Trust State ────────────────────────────────────

    @app.route("/api/trust-state")
    def api_trust_state():
        """Get current trust state and summary stats."""
        events = store.query_events(limit=1)
        current_trust = "green"
        if events:
            current_trust = events[0].get("trust_state", "green")

        # Get aggregate stats for last hour
        one_hour_ago = time.time() - 3600
        recent = store.query_events(since=one_hour_ago, limit=10000)

        total = len(recent)
        blocked = sum(1 for e in recent if e.get("status") == "blocked")
        ghost = sum(1 for e in recent if e.get("status") == "ghost_success")
        tainted = sum(1 for e in recent if e.get("session_tainted"))
        red = sum(1 for e in recent if e.get("trust_state") == "red")

        # Compute enhanced fields — check live sidecar state, not historical events
        ghost_active = False
        _gs_code, _gs_body = _proxy_sidecar("GET", "/v1/ghost/status",
                                            params={"sessionKey": events[0].get("session_id", "")} if events else {})
        if _gs_code == 200:
            ghost_active = bool(_gs_body.get("ghostMode") or _gs_body.get("ghost_mode"))

        taint_level = None
        if any(e.get("trust_state") == "red" and e.get("session_tainted") for e in recent):
            taint_level = "CRITICAL"
        elif any(e.get("session_tainted") for e in recent):
            taint_level = "HIGH"

        explanation = None
        if current_trust in ("amber", "red") and events:
            reason = events[0].get("result_summary", "")
            if reason and not reason.upper().startswith("OK"):
                explanation = explain(reason)

        # Compute orb_state — fail-closed composite posture
        # Precedence: red > amber > green
        if red > 0 or blocked > 0:
            orb_state = "red"
        elif taint_level is not None:
            orb_state = "amber"
        elif current_trust in ("amber", "red"):
            orb_state = current_trust
        else:
            orb_state = "green"

        return jsonify({
            "trust_state": current_trust,
            "orb_state": orb_state,
            "last_hour": {
                "total": total,
                "blocked": blocked,
                "ghost": ghost,
                "tainted": tainted,
                "red_events": red,
            },
            "ghost_active": ghost_active,
            "taint_level": taint_level,
            "explanation": explanation,
            "timestamp": time.time(),
        })

    # ─── API: Cadence State ──────────────────────────────────

    @app.route("/api/cadence-state")
    def api_cadence_state():
        """Get current Cadence temporal state."""
        state_path = config.cadence_state_env_path
        if not state_path or not state_path.exists():
            return jsonify({"error": "Cadence not available"}), 404

        state_labels = {
            "FLOW": "Active",
            "READING": "Reading",
            "DEEP_WORK": "Deep Work",
            "AWAY": "Away",
            "NORMAL": "Normal",
            "UNKNOWN": "Unknown",
        }

        data = {}
        try:
            for line in state_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip()
        except (OSError, PermissionError):
            return jsonify({"error": "Cannot read Cadence state"}), 500

        user_state = data.get("USER_STATE", "UNKNOWN")
        user_state_upper = user_state.upper()
        return jsonify({
            "user_state": user_state,
            "user_state_label": state_labels.get(user_state_upper, user_state.title()),
            "anomaly_score": float(data.get("ANOMALY_SCORE", "0")),
            "ert_seconds": float(data.get("ERT_SECONDS", "0")),
            "timestamp": time.time(),
        })

    # ─── API: Event Timeline ─────────────────────────────────

    @app.route("/api/events")
    def api_events():
        """Get event timeline with optional filters."""
        since = request.args.get("since", type=float)
        session_id = request.args.get("session")
        tool = request.args.get("tool")
        limit = request.args.get("limit", default=100, type=int)

        events = store.query_events(
            session_id=session_id,
            since=since,
            tool=tool,
            limit=min(limit, 500),
        )

        # Enrich timeline rows with snapshot availability/status so the
        # frontend can render consistent rewind/restored indicators.
        event_ids = [e.get("event_id") for e in events if e.get("event_id")]
        snap_by_event = store.get_snapshots_for_events(event_ids)
        for ev in events:
            snap = snap_by_event.get(ev.get("event_id"))
            ev["has_snapshot"] = bool(snap and snap.get("restorable"))
            ev["rolled_back"] = bool(snap and snap.get("rolled_back"))
            ev["snapshot_type"] = snap.get("snapshot_type") if snap else None
            ev["snapshot_restorable"] = bool(snap.get("restorable")) if snap else False
            _enrich_event(ev, scheduled_labels)

        return jsonify({
            "events": events,
            "count": len(events),
            "timestamp": time.time(),
        })

    @app.route("/api/events/<event_id>")
    def api_event_detail(event_id):
        """Get details for a single event including its snapshot."""
        events = store.query_events(limit=10000)
        event = next((e for e in events if e.get("event_id") == event_id), None)
        if not event:
            return jsonify({"error": "Event not found"}), 404

        _enrich_event(event, scheduled_labels)
        snapshot = store.get_snapshot_for_event(event_id)

        explanation = None
        if event.get("status") in ("blocked", "red_alert") or event.get("trust_state") in ("amber", "red"):
            reason = event.get("result_summary", "")
            if reason and not reason.upper().startswith("OK"):
                explanation = explain(reason)

        return jsonify({
            "event": event,
            "snapshot": snapshot,
            "explanation": explanation,
        })

    # ─── API: Chain Integrity ────────────────────────────────

    @app.route("/api/verify")
    def api_verify():
        """Verify CR-AFT hash chain integrity."""
        if request.args.get("detailed") == "1":
            result = store.verify_chain_detailed()
            result["timestamp"] = time.time()
            return jsonify(result)

        valid, error = store.verify_chain()
        return jsonify({
            "valid": valid,
            "error": error,
            "timestamp": time.time(),
        })

    # ─── API: Snapshots & Undo ───────────────────────────────

    @app.route("/api/snapshots")
    def api_snapshots():
        """List restorable snapshots.

        Query params:
          - include_rolled_back=1 to include already-restored rows for history UI.
        """
        since = request.args.get("since", type=float)
        session_id = request.args.get("session")
        limit = request.args.get("limit", default=50, type=int)
        include_rolled_back = request.args.get("include_rolled_back", default="0") in ("1", "true", "yes")

        snaps = store.get_restorable_snapshots(
            session_id=session_id,
            since=since,
            limit=limit,
            include_rolled_back=include_rolled_back,
        )
        return jsonify({"snapshots": snaps, "count": len(snaps)})

    @app.route("/api/undo/last", methods=["POST"])
    def api_undo_last():
        """Undo the most recent restorable action."""
        force = request.json.get("force", False) if request.json else False

        row = store.get_last_restorable_snapshot()
        if not row:
            return jsonify({"error": "No restorable snapshots found"}), 404

        snapshot = _row_to_snapshot(row)
        result = rollback_engine.rollback_single(snapshot, force=force)

        if result.status == RollbackStatus.SUCCESS:
            store.mark_rolled_back(row["snapshot_id"])

        return jsonify({
            "status": result.status.value,
            "event_id": result.event_id,
            "original_path": result.original_path,
            "message": result.message,
        })

    @app.route("/api/undo/<event_id>", methods=["POST"])
    def api_undo_event(event_id):
        """Undo a specific event."""
        force = request.json.get("force", False) if request.json else False

        row = store.get_snapshot_for_event(event_id)
        if not row:
            return jsonify({"error": f"No snapshot for event {event_id}"}), 404

        snapshot = _row_to_snapshot(row)
        result = rollback_engine.rollback_single(snapshot, force=force)

        if result.status == RollbackStatus.SUCCESS:
            store.mark_rolled_back(row["snapshot_id"])

        return jsonify({
            "status": result.status.value,
            "event_id": result.event_id,
            "original_path": result.original_path,
            "message": result.message,
        })

    @app.route("/api/undo/since", methods=["POST"])
    def api_undo_since():
        """Undo all restorable snapshots taken at/after a timestamp.

        Expects JSON body: {"since": <unix_timestamp_float>, "force": bool?}
        """
        body = request.json or {}
        since = body.get("since")
        force = body.get("force", False)

        if since is None:
            return jsonify({"error": "Missing required field: since"}), 400

        try:
            since = float(since)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid since timestamp"}), 400

        rows = store.get_restorable_snapshots(
            since=since,
            limit=10000,
            include_rolled_back=False,
        )
        if not rows:
            return jsonify({"error": "No restorable snapshots found in selected range"}), 404

        restored = 0
        failed = 0
        results = []

        # rows are newest-first; keep that order for correct multi-write rollback
        for row in rows:
            snapshot = _row_to_snapshot(row)
            result = rollback_engine.rollback_single(snapshot, force=force)
            if result.status == RollbackStatus.SUCCESS:
                store.mark_rolled_back(row["snapshot_id"])
                restored += 1
            else:
                failed += 1
            results.append({
                "event_id": row.get("event_id"),
                "snapshot_id": row.get("snapshot_id"),
                "path": row.get("original_path"),
                "status": result.status.value,
                "message": result.message,
            })

        return jsonify({
            "status": "success" if failed == 0 else "partial",
            "since": since,
            "attempted": len(rows),
            "restored": restored,
            "failed": failed,
            "results": results,
        })

    # ─── API: Away Mode Summary ──────────────────────────────

    @app.route("/api/away-summary")
    def api_away_summary():
        """Generate away mode summary."""
        since = request.args.get("since", type=float)
        if not since:
            # Default: last 2 hours
            since = time.time() - 7200

        summary = generate_away_summary(store, since)
        return jsonify(summary.to_dict())

    # ─── API: Sessions ───────────────────────────────────────

    @app.route("/api/sessions")
    def api_sessions():
        """List known sessions with summary stats."""
        events = store.query_events(limit=10000)
        sessions = {}
        for event in events:
            sid = event.get("session_id", "unknown")
            if sid not in sessions:
                sessions[sid] = {
                    "session_id": sid,
                    "first_event": event.get("timestamp"),
                    "last_event": event.get("timestamp"),
                    "total_actions": 0,
                    "blocked": 0,
                    "trust_state": "green",
                }
            s = sessions[sid]
            s["total_actions"] += 1
            s["last_event"] = max(s["last_event"] or 0, event.get("timestamp", 0))
            s["first_event"] = min(s["first_event"] or float("inf"), event.get("timestamp", 0))
            if event.get("status") == "blocked":
                s["blocked"] += 1
            if event.get("trust_state") == "red":
                s["trust_state"] = "red"
            elif event.get("trust_state") == "amber" and s["trust_state"] != "red":
                s["trust_state"] = "amber"

        return jsonify({
            "sessions": list(sessions.values()),
            "count": len(sessions),
        })

    # ─── API: Conversational Query ──────────────────────────

    @app.route("/api/ask")
    def api_ask():
        """Process a natural language query."""
        from ..conversational.query import process_query
        question = request.args.get("q", "")
        if not question:
            return jsonify({"error": "Missing 'q' parameter"}), 400
        response = process_query(question, config)
        return jsonify({"question": question, "response": response})

    # ─── API: Tamper Detection ───────────────────────────────

    @app.route("/api/tamper-check")
    def api_tamper_check():
        """Run tamper detection checks."""
        from ..anchoring.chain_export import ChainAnchoring
        anchoring = ChainAnchoring(config)
        report = anchoring.detect_tampering(store)
        return jsonify(report)

    # ─── API: Ghost Mode Proxy ────────────────────────────────

    @app.route("/api/ghost/status")
    def api_ghost_status():
        """Proxy ghost status from sidecar.

        If no session is specified, discovers the most recent session from
        EventStore and queries the sidecar for that session.  Falls back to
        a clean 'off' state if no sessions exist or the sidecar doesn't
        recognise the session.
        """
        session = request.args.get("session", "")

        # Auto-discover session from EventStore when none specified
        if not session:
            recent = store.query_events(limit=1)
            if recent:
                session = recent[0].get("session_id", "")

        if not session:
            # No sessions in EventStore — ghost is effectively off
            return jsonify({
                "ghost_mode": False,
                "files_buffered": 0,
                "paths": [],
                "total_size_bytes": 0,
            })

        status_code, body = _proxy_sidecar(
            "GET", "/v1/ghost/status", params={"sessionKey": session},
        )
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable", "ghost_mode": False}), 200
        if status_code == 404:
            # Sidecar doesn't know this session — return clean off state
            return jsonify({
                "ghost_mode": False,
                "files_buffered": 0,
                "paths": [],
                "total_size_bytes": 0,
                "session_id": session,
            })
        return jsonify(body), status_code

    @app.route("/api/ghost/toggle", methods=["POST"])
    def api_ghost_toggle():
        """Toggle ghost mode via sidecar.

        Auto-discovers the most recent session from EventStore when none
        is specified, so the dashboard toggle works without manual session
        selection.
        """
        data = request.json or {}
        session = data.get("session", "")

        # Auto-discover session when none specified
        if not session:
            recent = store.query_events(limit=1)
            if recent:
                session = recent[0].get("session_id", "")

        sidecar_body = {"enabled": data.get("enabled", False)}
        if session:
            sidecar_body["sessionKey"] = session
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/toggle", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code

    @app.route("/api/ghost/approve", methods=["POST"])
    def api_ghost_approve():
        """Approve ghost-buffered writes via sidecar."""
        data = request.json or {}
        session = data.get("session", "")
        if not session:
            recent = store.query_events(limit=1)
            if recent:
                session = recent[0].get("session_id", "")
        sidecar_body = {"sessionKey": session}
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/approve", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code

    @app.route("/api/ghost/discard", methods=["POST"])
    def api_ghost_discard():
        """Discard ghost-buffered writes via sidecar."""
        data = request.json or {}
        session = data.get("session", "")
        if not session:
            recent = store.query_events(limit=1)
            if recent:
                session = recent[0].get("session_id", "")
        sidecar_body = {"sessionKey": session}
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/discard", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code


    # ------------------------------------------------------------------
    # Amber challenge proxy endpoints
    # ------------------------------------------------------------------

    @app.route("/api/amber/pending")
    def api_amber_pending():
        """Get pending amber challenges from sidecar."""
        session = request.args.get("session", "")
        params = {}
        if session:
            params["sessionKey"] = session
        status_code, body = _proxy_sidecar("GET", "/v1/amber/pending", params=params)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable", "challenges": []}), 200
        return jsonify(body), status_code

    @app.route("/api/amber/resolve", methods=["POST"])
    def api_amber_resolve():
        """Resolve an amber challenge via sidecar."""
        data = request.json or {}
        challenge_id = data.get("challengeId", "")
        decision = data.get("decision", "")
        if not challenge_id or decision not in ("allow", "deny"):
            return jsonify({"error": "Required: challengeId, decision (allow|deny)"}), 400
        sidecar_body = {
            "challengeId": challenge_id,
            "decision": decision,
            "operatorId": "dashboard",
        }
        status_code, body = _proxy_sidecar("POST", "/v1/amber/resolve", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code

    @app.route("/api/ghost/events")
    def api_ghost_events():
        """Query ghost mode events from EventStore with interception stage enrichment."""
        since = request.args.get("since", type=float)
        limit = request.args.get("limit", default=200, type=int)

        conditions = ["ghost_mode = 1"]
        params = []
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = "WHERE " + " AND ".join(conditions)
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))

        rows = store._conn.execute(query, params).fetchall()
        events = [dict(row) for row in rows]

        for ev in events:
            summary = ev.get("result_summary", "") or ""
            if summary.upper().startswith("GHOST"):
                ev["interception_stage"] = 9
                ev["interception_label"] = "Safe but simulated"
            elif ev.get("status") == "blocked":
                ev["interception_stage"] = 0
                ev["interception_label"] = "Security violation (also simulated)"
            else:
                ev["interception_stage"] = 9
                ev["interception_label"] = "Simulated"

        writes = sum(1 for e in events if e.get("tool", "").startswith("fs_write") or e.get("tool") == "write")
        commands = sum(1 for e in events if e.get("tool") in ("bash_exec", "exec"))
        emails = sum(1 for e in events if "email" in (e.get("tool") or "").lower())
        network = sum(1 for e in events if e.get("tool") in ("fetch_web", "search_web", "http_post"))
        other = len(events) - writes - commands - emails - network

        parts = []
        if writes: parts.append(f"write {writes} file{'s' if writes != 1 else ''}")
        if emails: parts.append(f"send {emails} email{'s' if emails != 1 else ''}")
        if commands: parts.append(f"run {commands} command{'s' if commands != 1 else ''}")
        if network: parts.append(f"make {network} network request{'s' if network != 1 else ''}")
        if other > 0: parts.append(f"perform {other} other action{'s' if other != 1 else ''}")

        if parts:
            summary_text = "Your agent tried to " + ", ".join(parts) + ". None of these happened. Your system is unchanged."
        else:
            summary_text = "No ghost mode activity recorded."

        return jsonify({
            "events": events,
            "count": len(events),
            "summary": summary_text,
            "timestamp": time.time(),
        })

    
    # ─── API: Trusted Source Rules ─────────────────────────────

    @app.route("/api/trusted-source-rules")
    def api_trusted_source_rules():
        """Return the active trusted source rules from config."""
        rules = config.trusted_source_rules
        return jsonify({
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "source_types": sorted(r.source_types),
                    "tools": sorted(r.tools),
                    "domains": sorted(r.domains),
                }
                for r in rules
            ],
            "count": len(rules),
        })

    # ─── API: System Health ─────────────────────────────────

    @app.route("/api/system-health")
    def api_system_health():
        """Consolidated health check for all subsystems.

        Returns connection status for sidecar, EventStore, and CRAFT chain.
        Frontend polls this to show the integrity bar.

        Signed health verification gates (all must pass for green):
          1. sig_valid — HMAC-SHA256 verified
          2. fresh — payload within TTL
          3. seq monotonic — no replay or rollback
          4. state — sidecar's own assessment
          5. checks — no critical check failure
        """
        now = time.time()

        # --- Sidecar health ---
        sidecar_info = {
            "connected": False,
            "status": "unreachable",
            "uptime_seconds": None,
            "tool_calls_processed": None,
            "active_sessions": 0,
            "watchdog_stale": False,
            "last_policy_check_age": None,
            # Signed health v1 fields
            "sig_valid": None,
            "payload_fresh": None,
            "seq_valid": None,
            "state": None,
            "reason_code": None,
        }

        sc_code, sc_body = _proxy_sidecar("GET", "/v1/health")
        if sc_code == 401:
            # Auth mismatch — sidecar restarted with different secret
            sidecar_info["reason_code"] = ReasonCode.ADAPTER_AUTH_FAIL_401.value
        elif sc_code == 200:
            sidecar_info["connected"] = True
            sidecar_info["status"] = sc_body.get("status", "up")
            uptime_ms = sc_body.get("uptimeMs", 0)
            sidecar_info["uptime_seconds"] = uptime_ms / 1000.0 if uptime_ms else 0
            sidecar_info["tool_calls_processed"] = sc_body.get("toolCallsProcessed", 0)
            sidecar_info["active_sessions"] = sc_body.get("activeSessions", 0)
            sidecar_info["watchdog_stale"] = bool(sc_body.get("watchdogStale", False))

            last_check_ts = sc_body.get("lastPolicyCheckTs")
            if last_check_ts:
                try:
                    from datetime import datetime, timezone
                    dt = datetime.fromisoformat(last_check_ts.replace("Z", "+00:00"))
                    sidecar_info["last_policy_check_age"] = now - dt.timestamp()
                except (ValueError, TypeError):
                    sidecar_info["last_policy_check_age"] = None

            # --- Signed health v1 verification ---
            has_sig = isinstance(sc_body.get("sig"), dict)

            if _HEALTH_SIGNING_KEY is None:
                # Dev mode — no secret configured, skip sig verification
                sidecar_info["sig_valid"] = None
                sidecar_info["reason_code"] = ReasonCode.UNKNOWN_SOURCE.value
            elif has_sig:
                # Gate 1: Signature verification
                sig_ok = verify_health_signature(sc_body, _HEALTH_SIGNING_KEY)
                sidecar_info["sig_valid"] = sig_ok
                if not sig_ok:
                    sidecar_info["reason_code"] = ReasonCode.SIGNATURE_INVALID.value

                # Gate 2: Freshness (TTL)
                if sig_ok:
                    fresh = check_freshness(sc_body)
                    sidecar_info["payload_fresh"] = fresh
                    if not fresh:
                        sidecar_info["reason_code"] = ReasonCode.PAYLOAD_STALE.value

                # Gate 3: Sequence monotonicity
                if sig_ok and sidecar_info.get("payload_fresh"):
                    instance_id = sc_body.get("instance_id", "unknown")
                    seq = sc_body.get("seq", 0)
                    seq_ok, is_restart = _HEALTH_SEQ_TRACKER.check_and_update(
                        instance_id, seq,
                    )
                    sidecar_info["seq_valid"] = seq_ok
                    if not seq_ok:
                        sidecar_info["reason_code"] = ReasonCode.SEQ_REPLAY_OR_ROLLBACK.value
                    elif is_restart:
                        # Restart detected — accept but force amber
                        sidecar_info["state"] = "amber"
                        sidecar_info["reason_code"] = sc_body.get(
                            "reason_code", ReasonCode.OK.value,
                        )

                # Gate 4: Sidecar's own state assessment
                if sidecar_info.get("reason_code") is None:
                    sidecar_state = sc_body.get("state", sc_body.get("status", "up"))
                    sidecar_info["state"] = sidecar_state
                    sidecar_reason = sc_body.get("reason_code", ReasonCode.OK.value)
                    sidecar_info["reason_code"] = sidecar_reason

                # Gate 5: Critical checks
                checks = sc_body.get("checks", {})
                if checks.get("pipeline_enforcement") == "fail":
                    sidecar_info["reason_code"] = ReasonCode.PIPELINE_INVARIANT_FAIL.value
                if checks.get("audit_chain") == "fail":
                    sidecar_info["reason_code"] = ReasonCode.AUDIT_CHAIN_DEGRADED.value
            else:
                # No sig envelope in response — unsigned legacy response
                sidecar_info["sig_valid"] = None
                sidecar_info["reason_code"] = ReasonCode.UNKNOWN_SOURCE.value

        # --- EventStore health ---
        event_store_info = {
            "connected": False,
            "total_events": 0,
            "last_event_age": None,
            "stale": False,
        }

        try:
            total = store.event_count()
            event_store_info["connected"] = True
            event_store_info["total_events"] = total

            if total > 0:
                latest = store.query_events(limit=1)
                if latest:
                    last_ts = latest[0].get("timestamp", 0)
                    if last_ts:
                        event_store_info["last_event_age"] = now - last_ts

                        # Stale if >300s since last event AND sidecar has active sessions
                        if (now - last_ts > 300
                                and sidecar_info["connected"]
                                and sidecar_info["active_sessions"] > 0):
                            event_store_info["stale"] = True
        except Exception:
            event_store_info["connected"] = False

        # --- CRAFT chain check (detailed — distinguishes restarts from tampering) ---
        chain_info = {
            "verified": False,
            "error": None,
        }

        try:
            result = store.verify_chain_detailed()
            classification = result.get("classification", "")
            # "intact" or "restart_gaps_only" are both fine
            if classification in ("intact", "restart_gaps_only"):
                chain_info["verified"] = True
            else:
                chain_info["verified"] = False
                # Build error from first suspicious break
                breaks = result.get("breaks", [])
                suspicious = [b for b in breaks if b.get("classification") != "restart"]
                if suspicious:
                    b = suspicious[0]
                    chain_info["error"] = f"Suspicious break at event {b.get('event_id', '?')}"
                else:
                    chain_info["error"] = result.get("human_message", "Chain verification failed")
        except Exception as exc:
            chain_info["error"] = str(exc)

        # --- Overall status (no-false-green contract) ---
        # Green requires ALL of: sidecar connected, sidecar status "up",
        # watchdog fresh, event store fresh, CRAFT chain intact,
        # AND (if signed health available) sig valid, payload fresh, seq valid.
        if not sidecar_info["connected"]:
            overall = "disconnected"
        elif (sidecar_info["status"] != "up"
              or sidecar_info["watchdog_stale"]
              or event_store_info["stale"]
              or chain_info["error"] is not None):
            overall = "degraded"
        elif sidecar_info.get("sig_valid") is False:
            overall = "degraded"
        elif sidecar_info.get("payload_fresh") is False:
            overall = "degraded"
        elif sidecar_info.get("seq_valid") is False:
            overall = "degraded"
        elif (sidecar_info.get("state") is not None
              and sidecar_info["state"] != "green"):
            overall = "degraded"
        elif sidecar_info.get("reason_code") == ReasonCode.UNKNOWN_SOURCE.value:
            overall = "degraded"
        else:
            overall = "healthy"

        return jsonify({
            "sidecar": sidecar_info,
            "event_store": event_store_info,
            "craft_chain": chain_info,
            "overall": overall,
            "timestamp": now,
        })

    # ─── Helpers ─────────────────────────────────────────────

    def _row_to_snapshot(row: dict) -> Snapshot:
        """Convert a DB row to a Snapshot dataclass."""
        return Snapshot(
            snapshot_id=row["snapshot_id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            snapshot_type=row["snapshot_type"],
            original_path=row["original_path"],
            snapshot_path=row.get("snapshot_path"),
            original_size=row["original_size"],
            original_hash=row.get("original_hash"),
            metadata=row.get("metadata"),
            restorable=bool(row["restorable"]),
        )

    @app.teardown_appcontext
    def close_store(exception):
        pass  # Store stays open for app lifetime

    return app


def run_dashboard(config: UnwindConfig = None, port: int = 9001, debug: bool = False):
    """Run the dashboard web server."""
    app = create_app(config)
    host = os.environ.get("UNWIND_DASHBOARD_HOST", "0.0.0.0")
    print(f"\n  UNWIND Dashboard running at http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=debug)
