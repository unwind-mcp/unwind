"""Patch Pi's dashboard app.py to add amber proxy endpoints.

Inserts /api/amber/pending and /api/amber/resolve between
ghost/discard and ghost/events. Idempotent — skips if already present.
"""
import sys

MARKER = "api_amber_pending"
INSERT_AFTER = "        return jsonify(body), status_code\n"
INSERT_BEFORE = "    @app.route(\"/api/ghost/events\")"

PATCH = '''
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

'''

path = sys.argv[1] if len(sys.argv) > 1 else "unwind/dashboard/app.py"
with open(path, "r") as f:
    content = f.read()

if MARKER in content:
    print("Already patched — skipping.")
    sys.exit(0)

if INSERT_BEFORE not in content:
    print("ERROR: could not find insertion point.")
    sys.exit(1)

content = content.replace(INSERT_BEFORE, PATCH + INSERT_BEFORE)

with open(path, "w") as f:
    f.write(content)

print(f"Patched {path} — added amber proxy endpoints.")
