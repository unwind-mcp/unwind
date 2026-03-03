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

from flask import Flask, jsonify, render_template, request

from ..config import UnwindConfig
from ..recorder.event_store import EventStore
from ..snapshots.manager import SnapshotManager, Snapshot
from ..snapshots.rollback import RollbackEngine, RollbackStatus
from .away_mode import generate_away_summary
from .explanations import explain

# Sidecar base URL — read once at import time, endpoints build on this
SIDECAR_URL = os.environ.get("UNWIND_SIDECAR_URL", "http://127.0.0.1:9100")


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

    req = urllib.request.Request(
        url,
        method=method,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
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

        # Compute enhanced fields
        ghost_active = any(e.get("ghost_mode") for e in recent)

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

        return jsonify({
            "trust_state": current_trust,
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
        return jsonify({
            "user_state": user_state,
            "user_state_label": state_labels.get(user_state, "Unknown"),
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
        """List restorable snapshots."""
        since = request.args.get("since", type=float)
        session_id = request.args.get("session")
        limit = request.args.get("limit", default=50, type=int)

        snaps = store.get_restorable_snapshots(
            session_id=session_id,
            since=since,
            limit=limit,
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
        """Proxy ghost status from sidecar."""
        session = request.args.get("session", "")
        params = {"sessionKey": session} if session else {}
        status_code, body = _proxy_sidecar("GET", "/v1/ghost/status", params=params)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable", "ghost_mode": False}), 200
        return jsonify(body), status_code

    @app.route("/api/ghost/toggle", methods=["POST"])
    def api_ghost_toggle():
        """Toggle ghost mode via sidecar."""
        data = request.json or {}
        sidecar_body = {"enabled": data.get("enabled", False)}
        if data.get("session"):
            sidecar_body["sessionKey"] = data["session"]
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/toggle", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code

    @app.route("/api/ghost/approve", methods=["POST"])
    def api_ghost_approve():
        """Approve ghost-buffered writes via sidecar."""
        data = request.json or {}
        sidecar_body = {"sessionKey": data.get("session", "")}
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/approve", body=sidecar_body)
        if status_code == 503:
            return jsonify({"error": "Sidecar unavailable"}), 503
        return jsonify(body), status_code

    @app.route("/api/ghost/discard", methods=["POST"])
    def api_ghost_discard():
        """Discard ghost-buffered writes via sidecar."""
        data = request.json or {}
        sidecar_body = {"sessionKey": data.get("session", "")}
        status_code, body = _proxy_sidecar("POST", "/v1/ghost/discard", body=sidecar_body)
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
    print(f"\n  UNWIND Dashboard running at http://127.0.0.1:{port}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host="127.0.0.1", port=port, debug=debug)
