# CRITICAL_IP.md — continuity-critical project knowledge

Purpose: keep high-value context that must survive compaction, `/new`, and session churn.

Update rule:
- Add or update entries when architecture, origin stories, PoC lineage, or priority claims change.
- Every entry must include date, confidence, and a source pointer (file + line when possible).
- If unknown, mark explicitly as `TODO`.

---

## 1) CADENCE origin story

- Status: CAPTURED (embargo-safe version; full origin with mechanism details held until UK patent filed)
- Last updated: 2026-03-02
- Owner: Claude (canonical text held in Claude's auto-memory + David's local copy)

### Public-safe summary
Cadence is a lightweight temporal-awareness layer for persistent agents. It watches the timing gaps between user messages and infers human state (FLOW / READING / DEEP_WORK / AWAY) using Exponential Moving Averages per time-of-day bin. Born from the observation that persistent agents (OpenClaw, CrewAI, AutoGen) are always on but deaf to silence — they can't distinguish "user is reading my 400-line script" from "user went for a walk."

### Origin connection to CRAFT (EMBARGOED — do not publish until UK patent filed)
The full Cadence README includes an origin story connecting CRAFT's physical tamper-evident chain to the agent application. This paragraph describes the Geiger+GPS+RPi mechanism and must NOT appear in any public file until the UK patent application is submitted. David plans to file this week (w/c 2026-03-03). The handover prompt is ready at `/Users/davidrussell/Downloads/CRAFT uk pat JOB for opus.rtf`.

### Decision inflection points
- Cadence conceived as UX attunement layer (make agent respect human rhythm)
- Discovered dual-use: same temporal data is a behavioural biometric for zero-trust security
- CRIP (Consentful Rhythm Inference Protocol) added day-one to prevent rhythm data sliding into surveillance
- UNWIND integration: sidecar reads cadence/state.env as external trust signal

## 2) PoC lineage and version anchors

- Status: COMPLETE
- Last updated: 2026-03-02

### Physical PoC (CRAFT v1 → v2) — EMBARGOED details
- US provisional patent 63/828,541 filed June 23, 2025 (v1, cosmic ray version, lapsing as prior art)
- v1 (Thonny/screen): July 2025, desktop IDE, raw components visible in output string
- v2 (touchscreen/offline/mobile): July 2025, standalone Pi + battery pack + touchscreen, fully mobile, no internet, no mains, only certificate displayed
- UK patent application: handover prompt ready, filing target this week (w/c 2026-03-03)
- Source code: `CR_AFT_main_cleaned_20250703_223734.py` (MicroPython, July 3, 2025)
- Live output: `Detailed output via Mac Thonny USB.txt`
- Device photo: `CR-AFT PoC IMAGE 1.png`
- All files at: `/Users/davidrussell/Downloads/CR-AFT 1+2/`

### UNWIND/CRAFT commit lineage (key milestones)
- CRAFT v4.2 verifier core + lifecycle + persistence: pulled from GitHub (multiple commits)
- Secret Registry: d661aad (Claude/Mac), stabilised 626337f (Sentinel/Pi)
- Cadence Bridge: b806ba0 (Claude/Mac), integrated e81aefb (Pi)
- P1 Item 4 (adapter tests): 847ab46 (Sentinel/Pi)
- P1 Item 5 (systemd hardening): 396c565 (Sentinel/Pi)
- Open-core prep (5 commits): 5e8eebb → 422d247 (Claude/Mac)
- CLA scaffolding: 54d85e5 → afe2ef2 (Sentinel/Pi)
- CONTRIBUTING.md merge: 6150aac (Sentinel/Pi)
- Context resilience tooling: ef62d8e (Sentinel/Pi)
- Current HEAD: ef62d8e (all synced: Mac + Pi + GitHub)

### Runtime
- OpenClaw pinned below known fixed line (2026.2.21-2 vs >=2026.2.26) — upgrade pending
- UNWIND strategic path: OpenClaw adapter + Ghost Mode (NanoClaw deferred)

## 3) Priority claim context

- Status: COMPLETE
- Last updated: 2026-03-02

### IP priority claim (VERIFIED — deep research conducted 2026-03-01)
- Claim: David's working CRAFT implementation (summer 2025) predates ALL known agent hash-chain implementations by 4-7 months
- Evidence: US provisional 63/828,541 (Jun 23 2025), source code (Jul 3 2025), git history
- Key comparison: arXiv 2602.10481 + 2602.10465 (Feb 11 2026, Rajagopalan & Rao, MACAW Security / ROOST.tools) describe same approach — authenticated prompts, Merkle hash chains, provenance-based injection defence. Theory papers; CRAFT is working code, 6 months earlier.
- Full landscape analysis: see Claude's `prior-art-research.md` in auto-memory
- Physical device (Geiger+GPS+hash chain): ZERO prior art found anywhere. Completely novel field.
- Agent application: CRAFT predates Clawprint (Feb 2026), PiQrypt (Feb 2026), HDK (Feb 2026), all others.

### Public-safe priority statement (draft only — HOLD until UK filing submitted)
"UNWIND's cryptographic audit chain (CRAFT) has been in active development since summer 2025 — predating both the December 2025 industry announcements and the February 2026 academic papers (arXiv 2602.10481, 2602.10465) describing similar approaches. Working implementation, not theory."
- Operational override (2026-03-01): hold this statement until UK filing is submitted.

### Embargo: Do NOT publish the mechanism (Geiger/GPS/decay timing) until UK patent filed.

### Test count drift incident
- Root cause: CONTINUITY.md fingerprint was stale (claimed 1562, actual 1702 after Secret Registry + Cadence integration)
- Resolution: CONTINUITY.md conflict resolved in commit 4c5b8e8 (2026-03-01), fingerprint updated to 1632 (Pi count at time of resolution). Pi count has since grown to 1702.
- Closure: Sentinel's eng-test6h confirms 1702 passed, 0 failed. CONTINUITY.md fingerprint should be updated to 1702.
- Prevention: Sentinel's continuity-drift automation now alerts on mismatch

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
