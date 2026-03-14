# KEEL Infrastructure Wiring

> **CRITICAL: The Pi runs all servers. The Mac NEVER runs sidecar, dashboard, or gateway.**

## HOST: Raspberry Pi (192.168.0.171)

- **SSH:** `ssh dandare@raspberrypi` (user: dandare)
- **Project dir:** `~/.openclaw/workspace/UNWIND`
- **Python:** `.venv/bin/python`
- **Sidecar:** ALWAYS runs here, port 9100 (`unwind sidecar serve --host 0.0.0.0 --log-level warning`)
- **Dashboard:** ALWAYS runs here, port 9001 (`python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()"`)
- **Gateway:** ALWAYS runs here (`openclaw gateway`)
- **Sentinel (TUI):** ALWAYS runs here (`openclaw tui`) — exit with `/exit` only
- **Events DB:** Canonical version lives here (`~/.unwind/events.db`)
- **Shared secret:** Stored in `.env` in the project root (gitignored, never committed)

### Stack Startup (after reboot)

1. SSH in, then: `export UNWIND_SIDECAR_SHARED_SECRET=<value from .env>`
2. `export UNWIND_WATCHDOG_THRESHOLD=86400`
3. `cd ~/.openclaw/workspace/UNWIND`
4. `bash tools/start-stack.sh` (starts sidecar + dashboard + gateway, sources .env automatically)
5. Open second SSH terminal, export the shared secret, run `openclaw tui`

Or start each service manually — see `docs/CONTINUITY.md` section 3.

### Check / Kill Services

- `pgrep -f "unwind.sidecar"` / `pgrep -f "unwind.dashboard"` / `pgrep -f openclaw.*gateway`
- `pkill -f "unwind.dashboard"` / `pkill -f "unwind.sidecar"` / `pkill -f openclaw.*gateway`
- Logs: `tail -f /tmp/unwind-sidecar.log` / `tail -f /tmp/unwind-dash.log`

## CLIENT: Mac (Orchestrator)

- **Browser:** Open `http://192.168.0.171:9001` (dashboard)
- **AI Agents:** Gemini CLI / Claude Code run here to orchestrate Pi work
- **Code State:** Synced from Pi for review/editing
- **Python:** Mac has system Python 3.9.6 — too old to run the codebase (needs >=3.10). Python 3.11 is at `/opt/homebrew/bin/python3.11` but there is no venv on Mac. **Pi is the only test authority.** Mac test counts will always be lower — this is NOT drift.
- **NEVER start sidecar or dashboard on Mac** — servers are Pi-only

## Sync Rules

- **GitHub main is canonical.** Both Pi and Mac push/pull from GitHub.
- **NEVER SCP diverged files to Pi** — use patch scripts. See `docs/KEEL/SYNC_RUNBOOK.md`.
- **Diverged files (Pi has patches Mac doesn't):** `index.html`, `app.py`, `away_mode.py`
- **Always `git push` after every commit on Pi** — Pi was sole copy for weeks once.
