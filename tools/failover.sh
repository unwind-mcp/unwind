#!/usr/bin/env bash
set -euo pipefail

# OpenClaw seat failover helper (UNWIND)
# Commands:
#   ./tools/failover.sh status
#   ./tools/failover.sh switch [cooldown_minutes]
#   ./tools/failover.sh topup
# Optional:
#   ./tools/failover.sh mark <seat1|seat2|seat3> <minutes>

STATE_DIR="${HOME}/.openclaw/failover"
STATE_FILE="${STATE_DIR}/state.env"
DEFAULT_COOLDOWN_MINUTES="${FAILOVER_DEFAULT_COOLDOWN_MINUTES:-5534}"

SEAT_ORDER=("seat1" "seat2" "seat3")

seat_label() {
  case "$1" in
    seat1) echo "Seat 1 — Team workspace (shared team bucket)" ;;
    seat2) echo "Seat 2 — Personal Plus (<operator-email>)" ;;
    seat3) echo "Seat 3 — Anthropic Claude API (placeholder)" ;;
    *) echo "$1" ;;
  esac
}

usage() {
  cat <<'EOF'
Usage:
  ./tools/failover.sh status
  ./tools/failover.sh switch [cooldown_minutes]
  ./tools/failover.sh topup

Optional:
  ./tools/failover.sh mark <seat1|seat2|seat3> <minutes>

Notes:
- seat1 and seat2 are OpenAI OAuth workspace switches.
- switch runs `openclaw onboard --auth-choice openai-codex` and restarts gateway.
EOF
}

init_state() {
  mkdir -p "$STATE_DIR"
  if [[ ! -f "$STATE_FILE" ]]; then
    cat >"$STATE_FILE" <<EOF
ACTIVE_SEAT=seat2
SEAT1_COOLDOWN_UNTIL=0
SEAT2_COOLDOWN_UNTIL=0
SEAT3_COOLDOWN_UNTIL=0
LAST_RATE_LIMIT_SEAT=
LAST_RATE_LIMIT_AT=0
LAST_RATE_LIMIT_MINUTES=0
LAST_RATE_LIMIT_SOURCE=
LAST_DETECTION_HASH=
LAST_SWITCH_AT=0
EOF
  fi
}

load_state() {
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  ACTIVE_SEAT="${ACTIVE_SEAT:-seat2}"
  SEAT1_COOLDOWN_UNTIL="${SEAT1_COOLDOWN_UNTIL:-0}"
  SEAT2_COOLDOWN_UNTIL="${SEAT2_COOLDOWN_UNTIL:-0}"
  SEAT3_COOLDOWN_UNTIL="${SEAT3_COOLDOWN_UNTIL:-0}"
  LAST_RATE_LIMIT_SEAT="${LAST_RATE_LIMIT_SEAT:-}"
  LAST_RATE_LIMIT_AT="${LAST_RATE_LIMIT_AT:-0}"
  LAST_RATE_LIMIT_MINUTES="${LAST_RATE_LIMIT_MINUTES:-0}"
  LAST_RATE_LIMIT_SOURCE="${LAST_RATE_LIMIT_SOURCE:-}"
  LAST_DETECTION_HASH="${LAST_DETECTION_HASH:-}"
  LAST_SWITCH_AT="${LAST_SWITCH_AT:-0}"
}

save_state() {
  cat >"$STATE_FILE" <<EOF
ACTIVE_SEAT=${ACTIVE_SEAT}
SEAT1_COOLDOWN_UNTIL=${SEAT1_COOLDOWN_UNTIL}
SEAT2_COOLDOWN_UNTIL=${SEAT2_COOLDOWN_UNTIL}
SEAT3_COOLDOWN_UNTIL=${SEAT3_COOLDOWN_UNTIL}
LAST_RATE_LIMIT_SEAT=${LAST_RATE_LIMIT_SEAT}
LAST_RATE_LIMIT_AT=${LAST_RATE_LIMIT_AT}
LAST_RATE_LIMIT_MINUTES=${LAST_RATE_LIMIT_MINUTES}
LAST_RATE_LIMIT_SOURCE=${LAST_RATE_LIMIT_SOURCE}
LAST_DETECTION_HASH=${LAST_DETECTION_HASH}
LAST_SWITCH_AT=${LAST_SWITCH_AT}
EOF
}

now_epoch() {
  date +%s
}

fmt_ts() {
  local ts="$1"
  if [[ "$ts" -le 0 ]]; then
    echo "n/a"
  else
    date -d "@${ts}" "+%Y-%m-%d %H:%M:%S %Z"
  fi
}

fmt_duration() {
  local secs="$1"
  if (( secs <= 0 )); then
    echo "0m"
    return
  fi
  local d=$((secs / 86400))
  local h=$(((secs % 86400) / 3600))
  local m=$((((secs % 3600) + 59) / 60))
  if (( d > 0 )); then
    echo "${d}d ${h}h ${m}m"
  elif (( h > 0 )); then
    echo "${h}h ${m}m"
  else
    echo "${m}m"
  fi
}

cooldown_until() {
  case "$1" in
    seat1) echo "$SEAT1_COOLDOWN_UNTIL" ;;
    seat2) echo "$SEAT2_COOLDOWN_UNTIL" ;;
    seat3) echo "$SEAT3_COOLDOWN_UNTIL" ;;
    *) echo 0 ;;
  esac
}

set_cooldown_until() {
  local seat="$1"
  local until="$2"
  case "$seat" in
    seat1) SEAT1_COOLDOWN_UNTIL="$until" ;;
    seat2) SEAT2_COOLDOWN_UNTIL="$until" ;;
    seat3) SEAT3_COOLDOWN_UNTIL="$until" ;;
  esac
}

seat_configured() {
  local seat="$1"
  case "$seat" in
    seat1|seat2)
      return 0
      ;;
    seat3)
      if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        return 0
      fi
      if grep -q '"provider"[[:space:]]*:[[:space:]]*"anthropic"' "${HOME}/.openclaw/openclaw.json" 2>/dev/null; then
        return 0
      fi
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

seat_available() {
  local seat="$1"
  local now
  now="$(now_epoch)"
  local until
  until="$(cooldown_until "$seat")"
  seat_configured "$seat" || return 1
  (( until <= now ))
}

available_seats_csv() {
  local out=()
  local s
  for s in "${SEAT_ORDER[@]}"; do
    if seat_available "$s"; then
      out+=("$s")
    fi
  done
  if ((${#out[@]} == 0)); then
    echo "none"
  else
    local IFS=,
    echo "${out[*]}"
  fi
}

mark_rate_limit() {
  local seat="$1"
  local mins="$2"
  local source="$3"
  local now
  now="$(now_epoch)"
  local until=$((now + mins * 60))

  set_cooldown_until "$seat" "$until"
  LAST_RATE_LIMIT_SEAT="$seat"
  LAST_RATE_LIMIT_AT="$now"
  LAST_RATE_LIMIT_MINUTES="$mins"
  LAST_RATE_LIMIT_SOURCE="${source// /_}"
}

auto_detect_rate_limit() {
  local line=""
  if compgen -G "/tmp/openclaw/openclaw-*.log" >/dev/null; then
    line="$(grep -hEi 'API rate limit reached|rate limit reached|too many requests|429' /tmp/openclaw/openclaw-*.log 2>/dev/null | tail -n1 || true)"
  fi

  [[ -z "$line" ]] && return 0

  local hash
  hash="$(printf '%s' "$line" | sha1sum | awk '{print $1}')"
  if [[ "$hash" == "$LAST_DETECTION_HASH" ]]; then
    return 0
  fi

  LAST_DETECTION_HASH="$hash"

  local mins
  mins="$(echo "$line" | grep -Eo '[0-9]{2,6}[[:space:]]+minutes?' | tail -n1 | awk '{print $1}' || true)"
  if [[ -z "$mins" ]]; then
    mins="$DEFAULT_COOLDOWN_MINUTES"
  fi

  mark_rate_limit "$ACTIVE_SEAT" "$mins" "auto-log-detect"

  echo ""
  echo "⚠ Rate limit detected on $(seat_label "$ACTIVE_SEAT")"
  echo "   Cooldown: $(fmt_duration $((mins*60))) from now"
  echo "   Available seats now: $(available_seats_csv)"
  echo "   Switch command: ./tools/failover.sh switch"
  echo "   Top-up instructions: ./tools/failover.sh topup"
  echo ""
}

print_status() {
  local now
  now="$(now_epoch)"

  echo "OpenClaw seat failover status"
  echo "Active seat: $ACTIVE_SEAT ($(seat_label "$ACTIVE_SEAT"))"
  echo ""

  local s
  for s in "${SEAT_ORDER[@]}"; do
    local until
    until="$(cooldown_until "$s")"
    local configured="no"
    local state="cooldown"
    local rem=0
    seat_configured "$s" && configured="yes"
    rem=$((until - now))

    if ! seat_configured "$s"; then
      state="not configured"
    elif (( rem > 0 )); then
      state="cooldown $(fmt_duration "$rem") (until $(fmt_ts "$until"))"
    else
      state="available"
    fi

    echo "- $s: $state | configured=$configured | $(seat_label "$s")"
  done

  echo ""
  echo "Available now: $(available_seats_csv)"

  local active_until
  active_until="$(cooldown_until "$ACTIVE_SEAT")"
  local rem=$((active_until - now))
  if (( rem > 0 )); then
    echo ""
    echo "⚠ Active seat cooldown in progress"
    echo "   Expired seat: $ACTIVE_SEAT ($(seat_label "$ACTIVE_SEAT"))"
    echo "   Countdown: $(fmt_duration "$rem")"
    echo "   Available seats: $(available_seats_csv)"
    echo "   Run: ./tools/failover.sh switch"
    echo "   Or top-up: ./tools/failover.sh topup"
  fi
}

next_available_seat() {
  local current="$1"
  local n=${#SEAT_ORDER[@]}
  local i idx=-1

  for i in "${!SEAT_ORDER[@]}"; do
    if [[ "${SEAT_ORDER[$i]}" == "$current" ]]; then
      idx="$i"
      break
    fi
  done

  if (( idx < 0 )); then
    idx=0
  fi

  local step seat
  for ((step=1; step<=n; step++)); do
    seat="${SEAT_ORDER[$(((idx + step) % n))]}"
    if seat_available "$seat"; then
      echo "$seat"
      return 0
    fi
  done

  return 1
}

cmd_status() {
  init_state
  load_state
  auto_detect_rate_limit
  save_state
  print_status
}

cmd_mark() {
  init_state
  load_state
  local seat="${1:-}"
  local mins="${2:-}"
  if [[ -z "$seat" || -z "$mins" ]]; then
    echo "Usage: ./tools/failover.sh mark <seat1|seat2|seat3> <minutes>"
    exit 1
  fi
  if ! [[ "$mins" =~ ^[0-9]+$ ]]; then
    echo "Minutes must be a whole number"
    exit 1
  fi
  mark_rate_limit "$seat" "$mins" "manual"
  save_state
  echo "Marked $seat in cooldown for ${mins} minutes."
  print_status
}

cmd_switch() {
  init_state
  load_state
  auto_detect_rate_limit

  local mins="${1:-}"
  if [[ -n "$mins" ]]; then
    if ! [[ "$mins" =~ ^[0-9]+$ ]]; then
      echo "Usage: ./tools/failover.sh switch [cooldown_minutes]"
      exit 1
    fi
    mark_rate_limit "$ACTIVE_SEAT" "$mins" "manual-switch"
  fi

  local target
  if ! target="$(next_available_seat "$ACTIVE_SEAT")"; then
    save_state
    echo "No available seats right now."
    echo "Try top-up instructions: ./tools/failover.sh topup"
    exit 2
  fi

  echo "Switching: $ACTIVE_SEAT -> $target"

  case "$target" in
    seat1)
      echo "Target is Team workspace."
      echo "When OAuth opens, select TEAM workspace."
      openclaw onboard --auth-choice openai-codex
      openclaw gateway restart
      ;;
    seat2)
      echo "Target is Personal Plus workspace."
      echo "When OAuth opens, select PERSONAL workspace."
      openclaw onboard --auth-choice openai-codex
      openclaw gateway restart
      ;;
    seat3)
      if ! seat_configured seat3; then
        echo "Seat 3 (Anthropic API) is not configured yet."
        echo "Set ANTHROPIC_API_KEY (or configure provider auth), then retry."
        exit 3
      fi
      echo "Seat 3 selected (Anthropic API)."
      openclaw gateway restart
      ;;
  esac

  ACTIVE_SEAT="$target"
  LAST_SWITCH_AT="$(now_epoch)"
  save_state

  echo ""
  echo "✅ Switch complete."
  print_status
}

cmd_topup() {
  init_state
  load_state

  echo "OpenAI top-up instructions (Team workspace bucket)"
  echo ""
  echo "1) Open OpenAI billing for your Team workspace in browser."
  echo "2) Add credits / increase spending limit for the Team workspace."
  echo "3) Wait 1-2 minutes for billing state to propagate."
  echo "4) Re-auth if needed: openclaw models auth login --provider openai-codex"
  echo "5) Restart gateway: openclaw gateway restart"
  echo "6) Verify: ./tools/failover.sh status"
  echo ""
  echo "If you need immediate continuity without top-up: ./tools/failover.sh switch"
}

main() {
  local cmd="${1:-status}"
  shift || true

  case "$cmd" in
    status) cmd_status "$@" ;;
    switch) cmd_switch "$@" ;;
    topup) cmd_topup "$@" ;;
    mark) cmd_mark "$@" ;;
    -h|--help|help) usage ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
