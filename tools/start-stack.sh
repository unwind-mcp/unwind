#!/usr/bin/env bash
# UNWIND Full Stack Startup — One script for all.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Source .env if secret not already set
if [ -z "${UNWIND_SIDECAR_SHARED_SECRET:-}" ] && [ -f "$ROOT/.env" ]; then
    set -a; source "$ROOT/.env"; set +a
fi

export UNWIND_SIDECAR_SHARED_SECRET="${UNWIND_SIDECAR_SHARED_SECRET:?ERROR: UNWIND_SIDECAR_SHARED_SECRET not set. Create .env in project root.}"
export UNWIND_WATCHDOG_THRESHOLD="${UNWIND_WATCHDOG_THRESHOLD:-86400}"

echo "=== [1/4] Stopping existing services ==="
pkill -f "unwind sidecar serve" || true
pkill -f "unwind.dashboard" || true
pkill -f "openclaw.*gateway" || true

echo "=== [2/4] Starting Sidecar (Security Brain) ==="
nohup .venv/bin/unwind sidecar serve --host 0.0.0.0 --port 9100 --log-level warning > /tmp/unwind-sidecar.log 2>&1 &
sleep 2

echo "=== [3/4] Starting Dashboard (UI) ==="
export UNWIND_SIDECAR_URL=http://localhost:9100
nohup .venv/bin/python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()" > /tmp/unwind-dash.log 2>&1 &
sleep 2

echo "=== [4/4] Starting OpenClaw Gateway ==="
nohup openclaw gateway > /tmp/unwind-gateway.log 2>&1 &

echo ""
echo "=== STACK READY ==="
echo "Sidecar:   http://$(hostname):9100"
echo "Dashboard: http://$(hostname):9001"
echo ""
echo "Check logs: tail -f /tmp/unwind-*.log"
