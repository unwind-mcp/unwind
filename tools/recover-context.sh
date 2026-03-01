#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python "$ROOT/tools/build-recovery-packet.py"

echo
printf '=== QUICK VIEW: memory/RECOVERY_PACKET.md ===\n\n'
# Show first chunk only (operator skim target)
sed -n '1,120p' "$ROOT/memory/RECOVERY_PACKET.md"
