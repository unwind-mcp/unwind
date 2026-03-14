#!/usr/bin/env bash
# UNWIND Full Stack Startup — single script, correct order, verified.
# Usage: bash tools/start-stack.sh
# Then open a second terminal and run: openclaw tui

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ─── Load secrets ───────────────────────────────────────────
if [ -f "$ROOT/.env" ]; then
    set -a; source "$ROOT/.env"; set +a
fi
export UNWIND_SIDECAR_SHARED_SECRET="${UNWIND_SIDECAR_SHARED_SECRET:?ERROR: Set UNWIND_SIDECAR_SHARED_SECRET in $ROOT/.env}"
export UNWIND_WATCHDOG_THRESHOLD="${UNWIND_WATCHDOG_THRESHOLD:-86400}"
export UNWIND_SIDECAR_URL="http://127.0.0.1:9100"

# ─── 1. Kill existing services ─────────────────────────────
echo "=== [1/5] Stopping existing services ==="
pkill -f "unwind sidecar serve" 2>/dev/null || true
pkill -f "unwind.dashboard" 2>/dev/null || true
pkill -f "openclaw.*gateway" 2>/dev/null || true
sleep 1

# ─── 2. Start Sidecar ──────────────────────────────────────
echo "=== [2/5] Starting Sidecar (port 9100) ==="
nohup .venv/bin/unwind sidecar serve --port 9100 --log-level warning > /tmp/unwind-sidecar.log 2>&1 &
sleep 3

# Verify sidecar
SC_RESP=$(curl -sf \
    -H "Authorization: Bearer $UNWIND_SIDECAR_SHARED_SECRET" \
    -H "X-UNWIND-API-Version: 1" \
    http://127.0.0.1:9100/v1/health 2>&1) || SC_RESP="FAILED"

if echo "$SC_RESP" | grep -q '"status":"up"'; then
    echo "  ✓ Sidecar healthy"
else
    echo "  ✗ Sidecar FAILED. Check /tmp/unwind-sidecar.log"
    echo "    Response: $SC_RESP"
    echo ""
    echo "  Common fix: policy hash mismatch →"
    echo "    sha256sum ~/.unwind/policy.json | cut -d' ' -f1 > ~/.unwind/policy.sha256"
    echo "    Then re-run this script."
    exit 1
fi

# ─── 3. Start Dashboard ────────────────────────────────────
echo "=== [3/5] Starting Dashboard (port 9001) ==="
nohup .venv/bin/python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()" > /tmp/unwind-dash.log 2>&1 &
sleep 2

# Verify dashboard
DASH_RESP=$(curl -sf http://127.0.0.1:9001/api/trusted-source-rules 2>&1) || DASH_RESP="FAILED"

if echo "$DASH_RESP" | grep -q '"rules"'; then
    RULE_COUNT=$(echo "$DASH_RESP" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    echo "  ✓ Dashboard healthy (${RULE_COUNT} trusted source rules loaded)"
else
    echo "  ✗ Dashboard FAILED. Check /tmp/unwind-dash.log"
    exit 1
fi

# ─── 4. Start Gateway ──────────────────────────────────────
echo "=== [4/5] Starting Gateway ==="
nohup openclaw gateway > /tmp/unwind-gateway.log 2>&1 &
sleep 1
echo "  ✓ Gateway started"

# ─── 5. Status ──────────────────────────────────────────────
echo ""
echo "=== STACK READY ==="
echo "  Sidecar:   http://127.0.0.1:9100   (auth required)"
echo "  Dashboard: http://$(hostname):9001  (open in browser)"
echo "  Gateway:   running"
echo ""
echo "  Logs: tail -f /tmp/unwind-sidecar.log"
echo "        tail -f /tmp/unwind-dash.log"
echo "        tail -f /tmp/unwind-gateway.log"
echo ""
echo "  Next: open a new terminal, SSH in, export the shared secret, run: openclaw tui"
