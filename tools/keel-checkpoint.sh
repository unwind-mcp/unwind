#!/usr/bin/env bash
# KEEL Checkpoint Script - Captures the State Fingerprint
# Usage: bash tools/keel-checkpoint.sh [output_path]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_FILE="${1:-$ROOT/docs/KEEL/STATE_FINGERPRINT.json}"
export PATH="$HOME/Downloads/KEEL_BIN:/opt/homebrew/bin:$PATH"
# Map python to python3.11 to avoid xcode-select shim
export PATH="/opt/homebrew/bin:$PATH"
alias python=python3.11
shopt -s expand_aliases
MD_FILE="$ROOT/docs/KEEL/STATE_FINGERPRINT.md"

# 1. Capture Git State
BRANCH=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
SHA=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
DIRTY=$(git -C "$ROOT" status --short | wc -l | xargs)

# 2. Capture Test State (using the venv we verified)
VENV_PY="$ROOT/.venv/bin/python"
if [ ! -f "$VENV_PY" ]; then
    VENV_PY="/opt/homebrew/bin/python3.11"
fi

echo "Running test collection for fingerprint..."
TEST_SUMMARY=$("$VENV_PY" -m pytest --collect-only "$ROOT/tests" 2>&1 | tail -n 1)
TEST_COUNT=$(echo "$TEST_SUMMARY" | grep -oE '[0-9]+ tests collected' | awk '{print $1}')

# 3. Write JSON
cat > "$OUT_FILE" <<JSON
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "host": "$(hostname)",
  "branch": "$BRANCH",
  "commit_sha": "$SHA",
  "dirty_files": $DIRTY,
  "test_count": "${TEST_COUNT:-0}",
  "last_test_summary": "$TEST_SUMMARY"
}
JSON

# 4. Write Human-readable MD
cat > "$MD_FILE" <<MD
# KEEL State Fingerprint
Captured: $(date)

| Metric | Value |
|--------|-------|
| **Host** | $(hostname) |
| **Branch** | $BRANCH |
| **Commit** | $SHA |
| **Dirty Files** | $DIRTY |
| **Tests** | ${TEST_COUNT:-0} |
| **Status** | $TEST_SUMMARY |

---
*Next sync must verify this SHA and Test Count before proceeding.*
MD

echo "KEEL Checkpoint complete: $OUT_FILE"
