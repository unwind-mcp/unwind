# KEEL Reboot Block

Paste the text below into Gemini CLI, Claude Code, or any AI terminal after a reboot.

---

```
I have just rebooted. Restore project context in read-only mode first.

Project: UNWIND (Security proxy for agent/tool execution).
KEEL Protocol is active.

Instruction: Do this in order:
1. Read ~/Downloads/UNWIND/docs/KEEL/INFRASTRUCTURE_WIRING.md — this tells you WHERE things run.
2. Read ~/Downloads/UNWIND/docs/CONTINUITY.md — this is the full project brain.
3. Read ~/Downloads/UNWIND/docs/KEEL/SYNC_RUNBOOK.md — sync safety protocol.
4. Read ~/Downloads/UNWIND/docs/KEEL/STATE_FINGERPRINT.json — last checkpoint.
5. Read ~/Downloads/UNWIND/docs/KEEL/SESSION_STATE.md — what we were just working on.
6. Report any drift (commit SHA, test count, dirty files) before editing anything.

Architecture (do not contradict):
- Raspberry Pi (dandare@raspberrypi / 192.168.0.171) runs ALL servers: sidecar (port 9100), dashboard (port 9001), gateway, and Sentinel TUI.
- Mac runs ONLY: browser (http://192.168.0.171:9001), AI CLIs (Gemini/Claude), code review.
- Mac NEVER starts sidecar, dashboard, or gateway.
- Shared secret is in .env on Pi (gitignored). Never commit it.
- David is a non-coder. One command at a time. No chaining. No multi-line paste.

Hard Constraints:
- GitHub main is the canonical code source.
- Raspberry Pi is the live lab state anchor.
- Sync Rule: Pull into a timestamped snapshot folder first. Never rsync --delete without approval.
- Checkpoint: Run bash tools/keel-checkpoint.sh at stability points and after major tasks.
- Protocol: If drift persists for 2 cycles or no progress in 20 mins, STOP and report to David.
- NEVER SCP index.html, app.py, or away_mode.py from Mac to Pi — Pi versions have patches. Use patch scripts only.
- ALWAYS git push after every commit on Pi.
```
