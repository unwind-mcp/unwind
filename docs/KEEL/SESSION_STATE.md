# KEEL Session State

**Updated:** 2026-03-14 ~22:30 UTC

## Stack Status
- Sidecar: running (Pi, port 9100, auth working)
- Dashboard: running (Pi, port 9001, 3 trusted source rules loaded)
- Gateway: running (Pi)
- Sentinel TUI: running (Pi)
- Trust orb: GREEN, sidecar connected, chain verified
- All machines in sync at commit `c67391a` (GitHub)

## Just Completed (this session)
- Full reboot recovery — Mac + Pi
- KEEL hardened — REBOOT_BLOCK.md, SESSION_STATE.md, INFRASTRUCTURE_WIRING.md, CONTINUITY.md all refreshed
- Tested KEEL reboot block with Gemini CLI — works correctly
- start-stack.sh made BULLETPROOF — sources .env, starts all services, verifies each with health checks
- .env created on Pi with shared secret (gitignored)
- Sidecar policy hash mismatch fixed
- Dashboard trusted source rules now showing (3 rules)
- Sentinel allowed task audit — all 14 enabled cron jobs analysed against Sentinel's own report
- Three trusted source rules configured in ~/.unwind/policy.json:
  1. sentinel-security-watch — web tools to Brave API, GitHub, NVD, CISA, OSV, arxiv, HN, PyPI, npm
  2. sentinel-repo-maint — bash/exec tools to localhost, PyPI
  3. sentinel-control-plane — cron/gateway/subagents tools to localhost
- Stale red/amber events cleared from EventStore

## Waiting On
- Next cron job to fire — will confirm the 3 rules prevent AMBER triggers for Sentinel's scheduled tasks

## Working On Next
- Dashboard Allow/Deny button fix — buttons show on expired challenges, need to check if challenge is alive and show "Expired" if gone. AMBER challenge TTL is 90 seconds (code: CHALLENGE_TTL_SECONDS = 90 in amber_mediator.py)
- Dashboard polish — Allow/Deny buttons on Away review items, result_summary humanization

## Known Issues
- AMBER challenges are synchronous blocks — clicking Allow after the fact doesn't retroactively allow the action. Agent has already moved on. Need approval-window or retry mechanism.
- CHALLENGE_TTL_SECONDS = 90 (amber_mediator.py) — MEMORY.md says 300 but code says 90
- Self-protection (stage 2) blocks file reads in UNWIND workspace for interactive sessions — legitimate when David asks Sentinel to read project files

## Watch Out For
- index.html, app.py, away_mode.py are DIVERGED — never SCP to Pi
- After editing ~/.unwind/policy.json, rotate hash: `sha256sum ~/.unwind/policy.json | cut -d' ' -f1 > ~/.unwind/policy.sha256`
- If "Chain Broken" banner appears: run `python3 ~/mend_chain_v2.py` on Pi
