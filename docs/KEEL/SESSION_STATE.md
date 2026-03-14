# KEEL Session State

**Updated:** 2026-03-14 ~01:00 UTC (Mar 15)

## Stack Status
- Sidecar: running (Pi, port 9100, auth working)
- Dashboard: running (Pi, port 9001, 3 trusted source rules loaded)
- Gateway: running (Pi)
- Sentinel TUI: running (Pi)
- Trust orb: RED (from pytest contamination + interactive AMBER, not real threats)
- Cron jobs CONFIRMED WORKING: eng-test6h and claim-corroborator both succeeded with trusted source rules

## Commits This Session
- `3b39bc1` — Gemini's uncommitted work (auto-cron, principal_context, UI polish)
- `c8f832e` — start-stack.sh requires shared secret
- `6f0a8ba` — start-stack.sh auto-sources .env
- `073b5bf` — KEEL hardening (reboot block, infra wiring, continuity refresh)
- `e6bdace` — SESSION_STATE.md + reboot block update
- `04f36e8` — false drift fix (commit SHA, Mac Python 3.9 warning)
- `c67391a` — start-stack.sh bulletproof + infra wiring simplified
- `5f58a07` — dashboard: Rules tab, mobile CSS, expired AMBER fix, How It Works refresh
- `5700038` — dashboard: mobile fixes (rewind layout, integrity bar, tab scroll hint)

## Verified Working
- start-stack.sh — one command, 5 ticks, every time
- KEEL reboot block — tested twice with Gemini CLI, works correctly
- 3 trusted source rules — sentinel-security-watch, sentinel-repo-maint, sentinel-control-plane
- Cron jobs run clean through trusted source rules (confirmed: eng-test6h, claim-corroborator)
- Dashboard mobile responsive — works on iPhone, still needs refinements
- Rules tab — clean card layout, moved out of page footer

## Open Issues (prioritised)

### 1. Pytest EventStore contamination
- eng-test6h runs pytest which writes test events (fake sessions like `sess1`, `ghost-status-test`) to real `~/.unwind/events.db`
- These show as red/blocked in dashboard, polluting the timeline
- Fix: eng-ops.sh should set a temp UNWIND_HOME so tests use isolated EventStore
- Must NOT open a new vulnerability (e.g. attacker setting env var to bypass audit logging)

### 2. Auto-rule generation for new agent tasks
- When a new cron/heartbeat/scheduled task is created, UNWIND should auto-generate or prompt for trusted source rules
- Currently manual: create task, discover it triggers AMBER, manually add rule, restart sidecar
- Feature request: on task creation, validate against existing rules and suggest additions

### 3. Dashboard mobile refinements
- Some elements still overflow on narrow iPhone screens
- Rewind tab select dropdown needs more width constraint
- "Checked: just now" still slightly overflows on some views

### 4. AMBER Allow/Deny button UX
- CHALLENGE_TTL_SECONDS = 90 in amber_mediator.py (too fast for dashboard approval)
- Buttons show on expired challenges — now show "Challenge expired" but UX could be better
- Fundamental issue: AMBER is synchronous block, agent doesn't wait for dashboard approval
- Needs approval-window mechanism or retry pattern

### 5. Interactive session control-plane tools
- Sentinel using `cron` or `exec` tools from TUI triggers AMBER (correct behaviour)
- But confusing when David asks Sentinel to manage his own jobs
- Consider: principal-based exemption for the main TUI session

## Watch Out For
- index.html, app.py, away_mode.py are DIVERGED — never SCP to Pi, patch scripts only
- After editing ~/.unwind/policy.json: `sha256sum ~/.unwind/policy.json | cut -d' ' -f1 > ~/.unwind/policy.sha256`
