#!/usr/bin/env bash
set -euo pipefail

# SENTINEL engineering automation runner.
#
# Subcommands:
#   test6h              Pull + full tests + state/memory + alert conditions
#   coverage            Daily coverage baseline + >2% drop alert
#   continuity-drift    Compare CONTINUITY.md claims against repo reality
#   release-gate        Daily release gate checklist status
#   log-decision        Append architecture decision log entry
#   log-bug             Append bug pattern log entry

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="$(dirname "$ROOT")"
STATE_DIR="$ROOT/.sentinel"
STATE_FILE="$STATE_DIR/eng-state.json"
MEM_DIR="$WORKSPACE_ROOT/memory"
DECISION_LOG="$MEM_DIR/decision-log.md"
BUG_LOG="$MEM_DIR/bug-patterns.md"

mkdir -p "$STATE_DIR" "$MEM_DIR"

log_ts() {
  TZ=Europe/London date "+%Y-%m-%d %H:%M:%S %Z"
}

today_file() {
  local d
  d="$(TZ=Europe/London date +%F)"
  echo "$MEM_DIR/$d.md"
}

append_daily() {
  local line="$1"
  local f
  f="$(today_file)"
  if [[ ! -f "$f" ]]; then
    echo "# $(TZ=Europe/London date +%F)" > "$f"
    echo >> "$f"
  fi
  echo "- $(log_ts) — $line" >> "$f"
}

init_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    cat >"$STATE_FILE" <<'JSON'
{
  "last_test": {
    "ts": 0,
    "commit": "",
    "count": 0,
    "passed": 0,
    "failed": 0,
    "subtests": 0,
    "ok": false
  },
  "last_coverage": {
    "ts": 0,
    "commit": "",
    "pct": null,
    "ok": false
  },
  "last_release_gate": {
    "ts": 0,
    "ready": false,
    "missing": []
  }
}
JSON
  fi
}

state_get() {
  local py="$1"
  python3 - "$STATE_FILE" "$py" <<'PY'
import json,sys
path,expr=sys.argv[1],sys.argv[2]
obj=json.load(open(path))
print(eval(expr,{},dict(state=obj)))
PY
}

state_update_json() {
  local patch_json="$1"
  python3 - "$STATE_FILE" "$patch_json" <<'PY'
import json,sys
path,patch_raw=sys.argv[1],sys.argv[2]
state=json.load(open(path))
try:
    patch=json.loads(patch_raw)
except Exception as e:
    print("state_update_json parse error:",e,file=sys.stderr)
    print("patch_raw=",patch_raw,file=sys.stderr)
    raise

def merge(a,b):
    for k,v in b.items():
        if isinstance(v,dict) and isinstance(a.get(k),dict):
            merge(a[k],v)
        else:
            a[k]=v
merge(state,patch)
with open(path,'w') as f:
    json.dump(state,f,indent=2,sort_keys=True)
PY
}

detect_python_bin() {
  if python3 -m pytest --version >/dev/null 2>&1; then
    echo "python3"
  elif [[ -x "$ROOT/.venv/bin/python" ]]; then
    echo "$ROOT/.venv/bin/python"
  else
    echo "python3"
  fi
}

collect_count() {
  local pybin="$1"
  (cd "$ROOT" && "$pybin" -m pytest tests/ --collect-only 2>/dev/null || true) | \
    python3 -c 'import re,sys; t=sys.stdin.read(); m=re.search(r"(\d+)\s+tests\s+collected", t); print(m.group(1) if m else "0")'
}

parse_pytest_summary_json() {
  local file="$1"
  python3 - "$file" <<'PY'
import json,re,sys
text=open(sys.argv[1],errors='ignore').read()
passed=failed=subtests=0
m=re.search(r'(\d+)\s+passed',text)
if m: passed=int(m.group(1))
m=re.search(r'(\d+)\s+failed',text)
if m: failed=int(m.group(1))
m=re.search(r'(\d+)\s+subtests?\s+passed',text)
if m: subtests=int(m.group(1))
failed_tests=[]
for line in text.splitlines():
    line=line.strip()
    if line.startswith('FAILED '):
        # format: FAILED tests/x.py::Test::test_name - ...
        token=line.split()[1] if len(line.split())>1 else ''
        if token and token not in failed_tests:
            failed_tests.append(token)
print(json.dumps({
    'passed': passed,
    'failed': failed,
    'subtests': subtests,
    'failed_tests': failed_tests,
}))
PY
}

continuity_drift_json() {
  python3 - "$ROOT" <<'PY'
import json,re,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1])
continuity=root/'docs'/'CONTINUITY.md'
out={'drift':False,'items':[]}

if not continuity.exists():
    out['drift']=True
    out['items'].append('CONTINUITY.md missing')
    print(json.dumps(out)); raise SystemExit

text=continuity.read_text(errors='ignore')

m=re.search(r'Current count:\s*(\d+)\s+tests',text)
claimed_count=int(m.group(1)) if m else None

m=re.search(r'last_known_good_commit:\s*([0-9a-f]{7,40})',text)
claimed_commit=m.group(1) if m else None

actual_commit=subprocess.check_output(['git','-C',str(root),'rev-parse','--short','HEAD'],text=True).strip()
collect=subprocess.check_output([str(root/'.venv/bin/python'),'-m','pytest','tests/','--collect-only'],stderr=subprocess.DEVNULL,text=True)
m=re.search(r'(\d+)\s+tests\s+collected',collect)
actual_count=int(m.group(1)) if m else None

if claimed_count is None:
    out['drift']=True
    out['items'].append('CONTINUITY missing claimed test count')
elif actual_count is not None and claimed_count != actual_count:
    out['drift']=True
    out['items'].append(f'test_count drift: claimed={claimed_count} actual={actual_count}')

if claimed_commit is None:
    out['drift']=True
    out['items'].append('CONTINUITY missing last_known_good_commit')
else:
    # Allow claimed commit to match HEAD or HEAD~1.
    # This avoids impossible self-reference when CONTINUITY.md itself is updated.
    allowed={actual_commit}
    try:
        parent=subprocess.check_output(['git','-C',str(root),'rev-parse','--short','HEAD~1'],text=True).strip()
        if parent:
            allowed.add(parent)
    except Exception:
        pass
    if claimed_commit not in allowed:
        out['drift']=True
        out['items'].append(f'commit drift: claimed={claimed_commit} actual={actual_commit}')

required=[
    root/'unwind'/'enforcement'/'ghost_egress.py',
    root/'unwind'/'enforcement'/'pipeline.py',
    root/'tests'/'test_ghost_egress.py',
    root/'tests'/'canary'/'test_canary_contracts.py',
    root/'tests'/'test_enforcement_in_path.py',
    root/'tests'/'test_events_retention.py',
]
for p in required:
    if not p.exists():
        out['drift']=True
        out['items'].append(f'missing required file: {p.relative_to(root)}')

print(json.dumps(out))
PY
}

run_test6h() {
  init_state
  local pybin out rc count commit summary_json passed failed subtests prev_count failed_names
  pybin="$(detect_python_bin)"
  out="$(mktemp)"
  trap '[[ -n "${out:-}" ]] && rm -f "$out"' RETURN

  echo "[eng-test6h] pulling latest..."
  (cd "$ROOT" && git pull origin main --no-rebase)
  commit="$(cd "$ROOT" && git rev-parse --short HEAD)"

  count="$(collect_count "$pybin")"
  count="${count:-0}"

  echo "[eng-test6h] running full suite with $pybin"
  set +e
  (cd "$ROOT" && "$pybin" -m pytest tests/ -q) 2>&1 | tee "$out"
  rc=${PIPESTATUS[0]}
  set -e

  summary_json="$(parse_pytest_summary_json "$out")"
  passed="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["passed"])' <<<"$summary_json")"
  failed="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["failed"])' <<<"$summary_json")"
  subtests="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["subtests"])' <<<"$summary_json")"
  failed_names="$(python3 -c 'import json,sys;d=json.loads(sys.stdin.read());print("\\n".join(d["failed_tests"]))' <<<"$summary_json")"

  passed="${passed:-0}"
  failed="${failed:-0}"
  subtests="${subtests:-0}"

  prev_count="$(state_get 'state.get("last_test",{}).get("count",0)')"

  local ok="false"
  if [[ "$rc" -eq 0 ]]; then ok="true"; fi

  state_update_json "{\"last_test\":{\"ts\":$(date +%s),\"commit\":\"$commit\",\"count\":$count,\"passed\":$passed,\"failed\":$failed,\"subtests\":$subtests,\"ok\":$ok}}"

  append_daily "eng-test6h: commit=$commit count=$count passed=$passed failed=$failed subtests=$subtests ok=$ok"

  if [[ "$rc" -ne 0 ]]; then
    echo "ALERT: FULL TEST SUITE FAILED on $commit"
    if [[ -n "$failed_names" ]]; then
      echo "ALERT: failing tests:"
      echo "$failed_names"
    fi
    # Bug pattern tracker auto-entry (fix unknown yet)
    "$0" log-bug "test6h failure on $commit" "TBD" "automated-test-failure"
    return 1
  fi

  if [[ "$prev_count" =~ ^[0-9]+$ ]] && (( count < prev_count )); then
    echo "ALERT: test count dropped from $prev_count to $count on $commit"
    append_daily "ALERT: test count drop detected ($prev_count -> $count) on $commit"
  fi

  echo "[eng-test6h] OK: $count tests, $passed passed"
}

run_coverage() {
  init_state
  local pybin out rc commit cov prev_cov
  pybin="$(detect_python_bin)"
  out="$(mktemp)"
  trap '[[ -n "${out:-}" ]] && rm -f "$out"' RETURN

  # Ensure pytest-cov exists (venv preferred)
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    if ! "$ROOT/.venv/bin/python" - <<'PY' >/dev/null 2>&1
import pytest_cov
PY
    then
      echo "[eng-coverage] installing pytest-cov in venv"
      "$ROOT/.venv/bin/python" -m pip install pytest-cov >/dev/null
    fi
    pybin="$ROOT/.venv/bin/python"
  else
    if ! python3 - <<'PY' >/dev/null 2>&1
import pytest_cov
PY
    then
      echo "[eng-coverage] installing pytest-cov with pip3 --user"
      pip3 install --user pytest-cov >/dev/null
    fi
  fi

  commit="$(cd "$ROOT" && git rev-parse --short HEAD)"
  echo "[eng-coverage] running coverage with $pybin"
  set +e
  (cd "$ROOT" && "$pybin" -m pytest tests/ --cov=unwind --cov-report=term -q) 2>&1 | tee "$out"
  rc=${PIPESTATUS[0]}
  set -e

  cov="$(python3 - "$out" <<'PY'
import re,sys
text=open(sys.argv[1],errors='ignore').read()
m=re.findall(r'^TOTAL\s+\d+\s+\d+\s+(\d+)%\s*$',text,re.M)
print(m[-1] if m else '')
PY
)"
  cov="${cov:-0}"

  local ok="false"
  if [[ "$rc" -eq 0 ]]; then ok="true"; fi

  prev_cov="$(state_get 'state.get("last_coverage",{}).get("pct") if state.get("last_coverage",{}).get("pct") is not None else ""')"

  state_update_json "{\"last_coverage\":{\"ts\":$(date +%s),\"commit\":\"$commit\",\"pct\":$cov,\"ok\":$ok}}"

  append_daily "eng-coverage: commit=$commit coverage=${cov}% ok=$ok"

  if [[ "$rc" -ne 0 ]]; then
    echo "ALERT: coverage run failed on $commit"
    return 1
  fi

  if [[ -n "$prev_cov" ]]; then
    local drop gt2
    drop="$(python3 - <<PY
prev=float('$prev_cov')
cur=float('$cov')
print(prev-cur)
PY
)"
    gt2="$(python3 - <<PY
print('true' if float('$drop') > 2.0 else 'false')
PY
)"
    if [[ "$gt2" == "true" ]]; then
      echo "ALERT: coverage dropped by ${drop}% (from ${prev_cov}% to ${cov}%)"
      append_daily "ALERT: coverage drop >2% (${prev_cov}% -> ${cov}%)"
    fi
  fi

  echo "[eng-coverage] OK: ${cov}%"
}

run_continuity_drift() {
  init_state
  local drift_json drift items
  drift_json="$(continuity_drift_json)"
  drift="$(python3 -c 'import json,sys;print("true" if json.loads(sys.stdin.read())["drift"] else "false")' <<<"$drift_json")"
  items="$(python3 -c 'import json,sys;d=json.loads(sys.stdin.read());print("; ".join(d["items"]))' <<<"$drift_json")"

  if [[ "$drift" == "true" ]]; then
    echo "ALERT: CONTINUITY_DRIFT"
    echo "ALERT: $items"
    append_daily "continuity-drift: ALERT $items"
    return 1
  fi

  echo "NO_DRIFT"
  append_daily "continuity-drift: NO_DRIFT"
}

run_release_gate() {
  init_state
  local missing=()
  local ts now age ok
  ts="$(date +%s)"

  echo "[release-gate] checking canary"
  if ! (cd "$ROOT" && .venv/bin/python -m pytest tests/canary/test_canary_contracts.py tests/test_canary_randomization.py -q >/tmp/release_gate_canary.log 2>&1); then
    missing+=("canary")
  fi

  echo "[release-gate] checking enforcement-in-path"
  if ! (cd "$ROOT" && .venv/bin/python -m pytest tests/test_enforcement_in_path.py -q >/tmp/release_gate_enf.log 2>&1); then
    missing+=("enforcement-in-path")
  fi

  echo "[release-gate] checking retention"
  if ! (cd "$ROOT" && .venv/bin/python -m pytest tests/test_events_retention.py -q >/tmp/release_gate_ret.log 2>&1); then
    missing+=("retention")
  fi

  # Full suite status from last 6h run
  ok="$(state_get 'state.get("last_test",{}).get("ok",False)')"
  local last_ts count
  last_ts="$(state_get 'state.get("last_test",{}).get("ts",0)')"
  count="$(state_get 'state.get("last_test",{}).get("count",0)')"
  now="$(date +%s)"
  age=$((now - last_ts))
  if [[ "$ok" != "True" && "$ok" != "true" ]]; then
    missing+=("full-suite-green")
  fi
  if (( age > 12*3600 )); then
    missing+=("full-suite-freshness")
  fi

  # Continuity drift check
  if ! drift_out="$(run_continuity_drift 2>/dev/null)"; then
    missing+=("continuity")
  fi

  if (( ${#missing[@]} == 0 )); then
    echo "RELEASE_GATE: READY"
    echo "- canary ✅"
    echo "- enforcement-in-path ✅"
    echo "- retention ✅"
    echo "- full suite ✅ (count=$count)"
    echo "- continuity ✅"
    state_update_json "{\"last_release_gate\":{\"ts\":$ts,\"ready\":true,\"missing\":[]}}"
    append_daily "release-gate: READY (count=$count)"
  else
    echo "RELEASE_GATE: NOT_READY"
    echo "Missing: ${missing[*]}"
    local missing_json
    missing_json="$(printf '%s\n' "${missing[@]}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')"
    state_update_json "{\"last_release_gate\":{\"ts\":$ts,\"ready\":false,\"missing\":$missing_json}}"
    append_daily "release-gate: NOT_READY missing=${missing[*]}"
    return 1
  fi
}

log_decision() {
  local decision="${1:-}"
  local rationale="${2:-}"
  local alternatives="${3:-}"
  if [[ -z "$decision" || -z "$rationale" ]]; then
    echo "Usage: $0 log-decision \"decision\" \"rationale\" [\"alternatives\"]"
    exit 1
  fi
  if [[ ! -f "$DECISION_LOG" ]]; then
    cat >"$DECISION_LOG" <<'MD'
# Architecture Decision Log

Format:
- date/time
- decision
- rationale
- alternatives considered

MD
  fi
  {
    echo "- $(log_ts)"
    echo "  - decision: $decision"
    echo "  - rationale: $rationale"
    if [[ -n "$alternatives" ]]; then
      echo "  - alternatives: $alternatives"
    fi
  } >> "$DECISION_LOG"
  append_daily "decision-log: $decision"
  echo "logged decision"
}

log_bug() {
  local failure="${1:-}"
  local fix="${2:-}"
  local pattern="${3:-}"
  if [[ -z "$failure" || -z "$fix" ]]; then
    echo "Usage: $0 log-bug \"failure\" \"fix\" [\"pattern\"]"
    exit 1
  fi
  if [[ ! -f "$BUG_LOG" ]]; then
    cat >"$BUG_LOG" <<'MD'
# Bug Pattern Tracker

Format:
- date/time
- failure
- fix
- pattern tag

MD
  fi
  {
    echo "- $(log_ts)"
    echo "  - failure: $failure"
    echo "  - fix: $fix"
    if [[ -n "$pattern" ]]; then
      echo "  - pattern: $pattern"
    fi
  } >> "$BUG_LOG"
  append_daily "bug-log: $failure -> $fix"
  echo "logged bug"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    test6h) run_test6h ;;
    coverage) run_coverage ;;
    continuity-drift) run_continuity_drift ;;
    release-gate) run_release_gate ;;
    log-decision) log_decision "$@" ;;
    log-bug) log_bug "$@" ;;
    *)
      echo "Usage: $0 {test6h|coverage|continuity-drift|release-gate|log-decision|log-bug}"
      exit 1
      ;;
  esac
}

main "$@"
