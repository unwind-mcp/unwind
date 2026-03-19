set -euo pipefail

cd ~/.openclaw/workspace/UNWIND
echo "== pull latest =="
git pull origin main

echo "== rebuild adapter =="
cd openclaw-adapter
npm install
cd ..

echo "== keep cron disabled =="
openclaw config set cron.enabled false || true

fails=0

for i in 1 2 3 4 5; do
  echo "================ CYCLE $i =============="

  bash tools/start-stack.sh

  sleep 5

  echo "-- gateway health --"
  openclaw gateway health || true

  echo "-- status probe --"
  openclaw status --deep | sed -n '1,80p' || true

  echo "-- sidecar error scan (recent log) --"
  LOGFILE="/tmp/openclaw/openclaw-$(date +%F).log"
  if [[ -f "$LOGFILE" ]]; then
    if grep -E "SIDECAR_HEALTH_UNKNOWN|SIDECAR_CONNECT_ERROR" "$LOGFILE" >/dev/null; then
      echo "❌ sidecar error signature detected in $LOGFILE"
      grep -E "SIDECAR_HEALTH_UNKNOWN|SIDECAR_CONNECT_ERROR" "$LOGFILE" | tail -n 5
      fails=$((fails+1))
    else
      echo "✅ no sidecar error signatures in $LOGFILE"
    fi
  else
    echo "⚠️ log file not found: $LOGFILE"
  fi

  pkill -f "openclaw.*gateway" || true
  pkill -f "unwind.dashboard" || true
  pkill -f "unwind sidecar serve" || true
  pkill -f "uvicorn.*9100" || true

  sleep 3
done

echo "==== RESULT ==="
if [[ "$fails" -eq 0 ]]; then
  echo "PASS: 5/5 cycles clean (no SIDECAR_HEALTH_UNKNOWN or SIDECAR_CONNECT_ERROR)"
else
  echo "FAIL: $fails cycle(s) showed sidecar error signatures"
fi