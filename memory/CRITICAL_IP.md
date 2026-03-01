# CRITICAL_IP.md — continuity-critical project knowledge

Purpose: keep high-value context that must survive compaction, `/new`, and session churn.

Update rule:
- Add or update entries when architecture, origin stories, PoC lineage, or priority claims change.
- Every entry must include date, confidence, and a source pointer (file + line when possible).
- If unknown, mark explicitly as `TODO`.

---

## 1) CADENCE origin story

- Status: TODO (not currently captured in durable memory with source trace)
- Last checked: 2026-03-01
- Owner: David + SENTINEL (capture canonical narrative in next working session)
- Required fields once captured:
  - origin date/window
  - initial problem statement
  - first PoC constraints
  - decision inflection points

## 2) PoC lineage and version anchors

- Status: PARTIAL
- Last checked: 2026-03-01
- Known:
  - UNWIND strategic path: OpenClaw adapter + Ghost Mode (NanoClaw deferred) — see `MEMORY.md`
  - Runtime continuity concern: local OpenClaw pinned below known fixed line (`2026.2.21-2` vs `>=2026.2.26`) — see daily logs
- Missing:
  - canonical CADENCE PoC version timeline (tag/commit-level map)

## 3) Priority claim context (continuity/risk claims)

- Status: PARTIAL
- Last checked: 2026-03-01
- Known active claim context:
  - continuity metric drift incident (`test_count claimed=1562 vs actual=1702`) tracked in `memory/2026-03-01.md`
- Missing:
  - explicit root-cause narrative + closure criteria as a durable entry

## 4) Capture checklist (use when context is hot)

When a critical claim appears, capture in this format:

- Claim:
- Why it matters:
- Current verdict (confirmed/partial/unconfirmed):
- Evidence links:
- Effective dates:
- Owner + next action:
- Closure condition:

---

Notes:
- Do not store secrets, credentials, tokens, or private keys in this file.
- This file is intentionally compact and should stay operator-readable in <2 minutes.
