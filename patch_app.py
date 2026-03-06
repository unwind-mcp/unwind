"""Patch unwind/dashboard/app.py to add signed health verification."""
import sys

path = "unwind/dashboard/app.py"
with open(path, "r") as f:
    content = f.read()

# --- Patch 1: Add imports after SIDECAR_SECRET line ---
old_block_1 = 'SIDECAR_SECRET = os.environ.get("UNWIND_SIDECAR_SHARED_SECRET", "")\n'
new_block_1 = '''SIDECAR_SECRET = os.environ.get("UNWIND_SIDECAR_SHARED_SECRET", "")

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
'''

if old_block_1 not in content:
    print("ERROR: Could not find SIDECAR_SECRET line")
    sys.exit(1)
if "_HEALTH_SIGNING_KEY" in content:
    print("SKIP: Patch 1 already applied")
else:
    content = content.replace(old_block_1, new_block_1, 1)
    print("OK: Patch 1 applied (imports)")

# --- Patch 2: Replace system-health endpoint ---
old_endpoint = '''    @app.route("/api/system-health")
    def api_system_health():
        """Consolidated health check for all subsystems.

        Returns connection status for sidecar, EventStore, and CRAFT chain.
        Frontend polls this to show the integrity bar.
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
        }

        sc_code, sc_body = _proxy_sidecar("GET", "/v1/health")
        if sc_code == 200:
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

        # --- EventStore health ---'''

new_endpoint = '''    @app.route("/api/system-health")
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

        # --- EventStore health ---'''

if old_endpoint not in content:
    print("ERROR: Could not find system-health endpoint start")
    sys.exit(1)
content = content.replace(old_endpoint, new_endpoint, 1)
print("OK: Patch 2 applied (sidecar health section)")

# --- Patch 3: Replace overall status block ---
old_overall = '''        # --- Overall status ---
        if not sidecar_info["connected"]:
            overall = "disconnected"
        elif (sidecar_info["watchdog_stale"]
              or event_store_info["stale"]
              or chain_info["error"] is not None):
            overall = "degraded"
        else:
            overall = "healthy"'''

new_overall = '''        # --- Overall status (no-false-green contract) ---
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
            overall = "healthy"'''

if old_overall not in content:
    print("ERROR: Could not find overall status block")
    sys.exit(1)
content = content.replace(old_overall, new_overall, 1)
print("OK: Patch 3 applied (overall status)")

with open(path, "w") as f:
    f.write(content)
print(f"DONE: {path} patched successfully")
