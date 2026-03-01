#!/usr/bin/env bash
set -euo pipefail

# Safe sync: Pi -> Mac (non-destructive by default)
#
# Usage:
#   ./tools/sync-from-pi.safe.sh [--apply] [--prune] [--yes]
#
# Defaults:
#   - Dry-run preview only
#   - No deletions unless --prune is explicitly provided
#
# Environment overrides:
#   PI_IP, PI_USER, PI_PATH, MAC_PATH

PI_IP="${UNWIND_PI_HOST:?Set UNWIND_PI_HOST}"
PI_USER="${UNWIND_PI_USER:-pi}"
PI_PATH="${UNWIND_PI_PATH:-/home/${PI_USER}/.openclaw/workspace/UNWIND/}"
MAC_PATH="${MAC_PATH:-$HOME/Downloads/UNWIND/}"

APPLY=0
PRUNE=0
YES=0

usage() {
  cat <<'EOF'
Usage:
  ./tools/sync-from-pi.safe.sh [--apply] [--prune] [--yes]

Options:
  --apply   Execute sync (default is preview-only)
  --prune   Allow deletions on target (destructive)
  --yes     Non-interactive; skip confirmation prompt
  -h, --help

Examples:
  ./tools/sync-from-pi.safe.sh
  ./tools/sync-from-pi.safe.sh --apply
  ./tools/sync-from-pi.safe.sh --apply --prune
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --prune) PRUNE=1 ;;
    --yes) YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

require_cmd rsync
require_cmd ssh
require_cmd tar
require_cmd find

remote() {
  ssh -o BatchMode=no "${PI_USER}@${PI_IP}" "$@"
}

count_local_files() {
  local p="$1"
  find "$p" -type f \
    ! -path '*/.git/*' \
    ! -path '*/.sync-backups/*' \
    | wc -l | tr -d ' '
}

count_remote_files() {
  remote "find '$PI_PATH' -type f ! -path '*/.git/*' ! -path '*/.sync-backups/*' | wc -l" | tr -d ' '
}

git_head_local() {
  if git -C "$MAC_PATH" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$MAC_PATH" rev-parse --short HEAD
  else
    echo "n/a"
  fi
}

git_head_remote() {
  remote "if git -C '$PI_PATH' rev-parse --is-inside-work-tree >/dev/null 2>&1; then git -C '$PI_PATH' rev-parse --short HEAD; else echo n/a; fi"
}

pytest_count_local() {
  if [[ -x "$MAC_PATH/.venv/bin/python" && -f "$MAC_PATH/pyproject.toml" ]]; then
    (cd "$MAC_PATH" && .venv/bin/python -m pytest --collect-only 2>/dev/null | awk '/tests collected/{print $1}' | tail -1)
  else
    echo "n/a"
  fi
}

summarize_dry_run() {
  local file="$1"
  local add=0
  local upd=0
  local del=0

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^\*deleting[[:space:]] ]]; then
      del=$((del + 1))
      continue
    fi

    if [[ "$line" =~ ^[\>\<ch\.\*][^[:space:]]+[[:space:]] ]]; then
      local code="${line%% *}"
      if [[ "$code" == *"+++++++++"* ]]; then
        add=$((add + 1))
      else
        upd=$((upd + 1))
      fi
    fi
  done <"$file"

  echo "$add $upd $del"
}

echo "[SYNC] Direction: Pi -> Mac"
echo "[SYNC] Source:    ${PI_USER}@${PI_IP}:$PI_PATH"
echo "[SYNC] Target:    $MAC_PATH"
if (( APPLY == 1 )); then
  if (( PRUNE == 1 )); then
    echo "[SYNC] Mode:      apply + prune (destructive)"
  else
    echo "[SYNC] Mode:      apply (non-destructive)"
  fi
else
  if (( PRUNE == 1 )); then
    echo "[SYNC] Mode:      preview + prune simulation"
  else
    echo "[SYNC] Mode:      preview (non-destructive)"
  fi
fi

echo ""
echo "[PRECHECK]"
remote "test -d '$PI_PATH'" >/dev/null 2>&1 || {
  echo "  - Source path not found or unreachable: ${PI_USER}@${PI_IP}:$PI_PATH"
  exit 1
}
echo "  - Source reachable: YES"

mkdir -p "$MAC_PATH"
echo "  - Target path exists: YES"

if remote "git -C '$PI_PATH' rev-parse --is-inside-work-tree >/dev/null 2>&1"; then
  if [[ -n "$(remote "git -C '$PI_PATH' status --porcelain" || true)" ]]; then
    echo "  - Source git dirty: YES (warning)"
  else
    echo "  - Source git dirty: NO"
  fi
else
  echo "  - Source git repo: NO"
fi

if git -C "$MAC_PATH" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -n "$(git -C "$MAC_PATH" status --porcelain)" ]]; then
    echo "  - Target git dirty: YES (warning)"
  else
    echo "  - Target git dirty: NO"
  fi
else
  echo "  - Target git repo: NO"
fi

echo ""
echo "[DRY-RUN]"
DRYRUN_OUT="$(mktemp)"
trap 'rm -f "$DRYRUN_OUT"' EXIT

RSYNC_ARGS=(
  -az
  --itemize-changes
  --human-readable
  --exclude='.git'
  --exclude='.sync-backups'
  --dry-run
)
if (( PRUNE == 1 )); then
  RSYNC_ARGS+=(--delete-after)
fi

rsync "${RSYNC_ARGS[@]}" "${PI_USER}@${PI_IP}:$PI_PATH" "$MAC_PATH" | tee "$DRYRUN_OUT"

read -r ADD_COUNT UPD_COUNT DEL_COUNT < <(summarize_dry_run "$DRYRUN_OUT")

echo ""
echo "[DRY-RUN SUMMARY]"
echo "  + add:    $ADD_COUNT"
echo "  ~ update: $UPD_COUNT"
if (( PRUNE == 1 )); then
  echo "  - delete: $DEL_COUNT"
else
  echo "  - delete: 0 (prune disabled)"
fi

if (( APPLY == 0 )); then
  echo ""
  echo "[RESULT] Preview only. Re-run with --apply to execute."
  exit 0
fi

if (( PRUNE == 1 )) && (( YES == 0 )); then
  echo ""
  echo "[WARNING] Destructive sync requested (--prune)."
  echo "          Files deleted on target cannot be auto-restored without backup."
  read -r -p "Type PRUNE to continue: " token
  if [[ "$token" != "PRUNE" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

if (( PRUNE == 1 )); then
  echo ""
  echo "[BACKUP] Creating target backup before destructive sync..."
  TS="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "${MAC_PATH%/}/.sync-backups"
  BACKUP_PATH="${MAC_PATH%/}/.sync-backups/${TS}-before-prune.tar.gz"
  tar -czf "$BACKUP_PATH" --exclude='.git' --exclude='.sync-backups' -C "$MAC_PATH" .
  echo "[BACKUP] OK: $BACKUP_PATH"
fi

echo ""
echo "[APPLY] Running sync..."
APPLY_ARGS=(
  -az
  --itemize-changes
  --human-readable
  --exclude='.git'
  --exclude='.sync-backups'
)
if (( PRUNE == 1 )); then
  APPLY_ARGS+=(--delete-after)
fi

rsync "${APPLY_ARGS[@]}" "${PI_USER}@${PI_IP}:$PI_PATH" "$MAC_PATH"

echo "[APPLY] Complete."

echo ""
echo "[INTEGRITY]"
SRC_COUNT="$(count_remote_files)"
DST_COUNT="$(count_local_files "$MAC_PATH")"
SRC_HEAD="$(git_head_remote)"
DST_HEAD="$(git_head_local)"
DST_TESTS="$(pytest_count_local)"

echo "  source files: $SRC_COUNT"
echo "  target files: $DST_COUNT"
echo "  source HEAD:  $SRC_HEAD"
echo "  target HEAD:  $DST_HEAD"
echo "  target tests collected: ${DST_TESTS:-n/a}"

INTEGRITY_OK=1
if [[ "$SRC_COUNT" != "$DST_COUNT" ]]; then
  INTEGRITY_OK=0
fi
if [[ "$SRC_HEAD" != "n/a" && "$DST_HEAD" != "n/a" && "$SRC_HEAD" != "$DST_HEAD" ]]; then
  INTEGRITY_OK=0
fi

if (( INTEGRITY_OK == 1 )); then
  echo "  integrity: PASS"
else
  echo "  integrity: FAIL (review counts/heads above)"
fi
