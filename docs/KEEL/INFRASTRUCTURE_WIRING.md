# KEEL Infrastructure Wiring

## HOST: Raspberry Pi (192.168.0.171)
- **Sidecar:** ALWAYS runs here (unwind sidecar serve --host 0.0.0.0)
- **Dashboard:** ALWAYS runs here (python -m unwind.dashboard --host 0.0.0.0)
- **Events DB:** Canonical version lives here (~/.unwind/events.db)

## CLIENT: Mac (Orchestrator)
- **Browser:** Open http://192.168.0.171:9001
- **AI Agents:** Gemini/Claude CLI run here to orchestrate Pi work.
- **Code State:** Synced from Pi for review/editing.
