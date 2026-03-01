# Context Resilience Plan (Pi-side, SENTINEL)

Last updated: 2026-03-01 (Europe/London)

## Objective

Recover to operational context in under 2 minutes after compaction, `/new`, or session churn — without reinstalling OpenClaw and without losing durable memory.

---

## 1) What survives what (clear matrix)

| Event | Survives | Risked/Lost | Notes |
|---|---|---|---|
| Gateway restart (`openclaw gateway restart`) | `~/.openclaw` state dir, workspace files, auth profiles, sessions on disk, extension configs/files | in-flight runs may abort; transient in-memory state resets | Normal operational restart, not a data wipe. |
| Session reset (`/new` or `/reset`) | Workspace memory files, auth, gateway config, extension configs, prior transcripts on disk | current session continuity in active context window (new `sessionId`) | Fresh session context only; infra/auth untouched. |
| Reinstall code only (npm↔git switch) with state/workspace preserved | state + workspace survive | none (if directories preserved) | Docs confirm install flavor switch does not delete `~/.openclaw` or workspace. |
| Full destructive reinstall + deleting `~/.openclaw` and workspace | nothing local survives unless backup restore | config/auth/sessions/memory/workspace all lost | Avoid unless explicitly planned with verified backups. |

Key docs:
- `docs/help/faq.md` (migration + storage + install switch behavior)
- `docs/reference/session-management-compaction.md` (session reset/IDs/transcripts)
- `docs/tools/slash-commands.md` (`/new`, `/reset`)

---

## 2) Fast changeover runbook (target <2 minutes)

1. **Trigger fresh session**: use `/new` (or allow daily/idle reset behavior).
2. **Regenerate recovery packet**:
   ```bash
   python tools/build-recovery-packet.py
   ```
3. **Read in this order**:
   - `memory/RECOVERY_PACKET.md`
   - `memory/CRITICAL_IP.md`
   - `memory/YYYY-MM-DD.md` (today)
4. **Sanity checks**:
   ```bash
   openclaw status
   openclaw memory status --json
   openclaw hooks info session-memory
   ```
5. **Resume operations** using recovered priorities and continuity anchors.

---

## 3) Persistent memory design (Pi-side)

### Files and roles

- `MEMORY.md` — durable, long-lived decisions/constraints.
- `memory/YYYY-MM-DD.md` — daily operational events.
- `memory/decision-log.md` — explicit architecture decisions.
- `memory/CRITICAL_IP.md` — continuity-critical context that must not be lost (origin stories, PoC lineage, priority-claim context).
- `memory/RECOVERY_PACKET.md` — generated cold-start briefing for fast resume.

### Update model

- **Automatic (already available in OpenClaw)**:
  - pre-compaction memory flush (`agents.defaults.compaction.memoryFlush`)
  - bundled `session-memory` hook on `/new`/`/reset` (enabled)
- **Manual (operator discipline)**:
  - update `MEMORY.md` for durable changes
  - update `CRITICAL_IP.md` when high-value narrative/lineage/claims appear
- **Generated**:
  - run `tools/build-recovery-packet.py` after major shifts and before resets

### Startup read order

1. `SOUL.md`
2. `USER.md`
3. `MEMORY.md`
4. `memory/CRITICAL_IP.md`
5. `memory/RECOVERY_PACKET.md`
6. today/yesterday daily logs

---

## 4) Current observed weakness

`openclaw memory status --json` currently reports embeddings unavailable (`reason: missing_api_key`) and zero indexed files/chunks on this runtime. That weakens semantic recall and increases dependence on disciplined file structure + recovery packet generation.

---

## 5) Test protocol for context-reset recovery

1. Generate packet.
2. Start a fresh session context (`/new` or separate isolated run).
3. Recover context from files only.
4. Validate recovered output includes:
   - mission/identity anchors
   - durable architecture track
   - current top risk + continuity status
   - unresolved critical IP gaps.

Pass criteria:
- recovery briefing produced in <2 minutes,
- no dependency on old in-session chat context,
- no reinstall/re-auth required.
