# KEEL Session State

**Updated:** 2026-03-14 ~23:15 UTC

## Stack Status
- Sidecar: running (Pi, port 9100, auth working)
- Dashboard: running (Pi, port 9001, 3 trusted source rules loaded)
- Gateway: running (Pi)
- Sentinel TUI: running (Pi)
- Trust orb: GREEN, 0 blocked, sidecar connected, chain verified

## Just Completed (this session)
- Full reboot recovery — Mac + Pi
- KEEL hardened — REBOOT_BLOCK.md, SESSION_STATE.md, INFRASTRUCTURE_WIRING.md, CONTINUITY.md all refreshed
- Tested KEEL reboot block with Gemini CLI twice — works correctly
- start-stack.sh made BULLETPROOF — one command starts everything with health checks
- .env created on Pi with shared secret (gitignored)
- Sidecar policy hash mismatch fixed
- Sentinel allowed task audit — all 14 enabled cron jobs analysed with Sentinel's own report
- Three trusted source rules in ~/.unwind/policy.json:
  1. sentinel-security-watch — web tools to Brave API, GitHub, NVD, CISA, OSV, arxiv, HN, PyPI, npm
  2. sentinel-repo-maint — bash/exec tools to localhost, PyPI
  3. sentinel-control-plane — cron/gateway/subagents tools to localhost
- Dashboard improvements:
  - Rules tab — dedicated tab with card layout, removed clutter from bottom of every page
  - Mobile responsive CSS — works on phone browsers
  - Expired AMBER buttons now show "Challenge expired" instead of dead Allow/Deny buttons
  - Generic user-facing rules description (not Sentinel-specific)

## Waiting On
- Next cron job (~80 mins) to confirm rules prevent AMBER triggers

## Working On Next
- More mobile CSS refinements
- Dashboard Allow/Deny deeper fix — AMBER TTL is 90s (amber_mediator.py), needs approval-window mechanism
- Rewind tab UX — checkboxes are confusing, needs clearer labels

## Known Issues
- AMBER challenges are synchronous blocks — Allow after the fact doesn't retroactively allow the action
- CHALLENGE_TTL_SECONDS = 90 in code, MEMORY.md incorrectly says 300
- Self-protection (stage 2) blocks file reads in UNWIND workspace for interactive sessions

## Watch Out For
- index.html, app.py, away_mode.py are DIVERGED — never SCP to Pi, patch scripts only
- After editing ~/.unwind/policy.json: `sha256sum ~/.unwind/policy.json | cut -d' ' -f1 > ~/.unwind/policy.sha256`
