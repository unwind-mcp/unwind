# UNWIND Six-Layer Alignment Document

**Status:** Pre-collaboration draft (ground truth for all builders)
**Author:** Claude (Mac), with operational suggestions from Sentinel (Pi)
**Date:** 2026-03-02
**Next step:** David reviews, passes to Sentinel as canonical reference, then to Opus for holes and polish.

---

## 1. UNWIND (the whole system)

### What it is
A security layer that sits between your AI agent and the tools it uses, so you can see everything it does, control what it's allowed to do, and undo anything that goes wrong.

### What it does
- Checks every tool call through 15 deterministic stages before it reaches the real tool — blocking anything dangerous
- Records every action to a tamper-proof flight recorder so you have evidence of what happened
- Takes snapshots before every change so you can undo any action at any time
- Shows you a real-time trust light (green/amber/red) so you know the health of your session at a glance
- Works with any MCP client (Claude Desktop, Cursor, etc.) or as a native OpenClaw plugin — the agent doesn't know UNWIND exists

### What it does NOT do
- Does not use AI/LLM in the enforcement path — every check is deterministic, no hallucination risk
- Does not protect against kernel-level compromise or a fully compromised host OS
- Does not claim to eliminate all risk — it reduces practical attack surface and makes actions recoverable
- Does not phone home, collect telemetry, or require cloud connectivity

### Current status
- [x] Live on hardware (Raspberry Pi 5, Sentinel as first user for days)
- [x] Tests passing (1702 tests, 0 failures)
- [x] Docs complete (README, SECURITY.md, CONTRIBUTING.md, DISCLAIMER.md, CHANGELOG.md, CRAFT spec v4.2)
- [ ] Ready for public (waiting on: Sentinel step 5 stability confirmation, alpha tag)

### In pipeline / planned
- Alpha release tag (0.1.0-alpha) — blocked on stability confirmation cycles
- `pip install unwind-mcp` and `pip install ghostmode` as separate packages
- Enterprise dashboard (premium tier, not in open core)

### Operational hardening notes (from Sentinel)
- Keep startup/env injection consistent across sidecar restarts (drift friction observed in practice)
- Watchdog threshold is a **stale-signal indicator**, not a lockout control — language must reflect this
- Maintain restart runbook to avoid sidecar-health blind windows
- Keep proving no bypass path from tool call to execution
- Unknown-tool paths must fail safely (observed: `write` → `challenge_required` when not in classification set)
- Maintain post-upgrade smoke checks as standard release gate

### How a user experiences it
You install it (`pip install unwind-mcp`), point your MCP client at UNWIND instead of the upstream server, and carry on. Your agent works exactly as before — but now every action is checked, logged, and reversible. If something goes wrong, you open the dashboard or run `unwind undo last`.

---

## 2. UNWIND Rollback ("the time machine")

### What it is
An automatic undo system that takes a snapshot before every change your agent makes, so you can reverse any action — one file, one event, or everything since a point in time.

### What it does
- Automatically captures a snapshot before every state-modifying tool call (file writes, deletes, config changes)
- Uses reflink-first copies (instant on APFS/btrfs) with fallback to regular copy, capped at 25MB per snapshot
- Lets you undo a single action (`unwind undo last`), a specific event (`unwind undo evt_abc123`), or a time range (`unwind undo --since "2h"`)
- Detects conflicts (file changed since snapshot) and asks before overwriting
- Atomic moves for deletions — the file is moved to a snapshot location, not destroyed

### What it does NOT do
- Does not snapshot database state or application memory — it's filesystem-level
- Does not undo network actions (emails sent, API calls made) — those are logged but not reversible
- Skips files over 25MB (logged as SKIPPED_TOO_LARGE)
- Does not replace proper backups — it's a session-level safety net, not a backup system

### Current status
- [x] Live on hardware
- [x] Tests passing (31 tests covering snapshot, rollback, conflict detection, batch undo)
- [x] Docs complete
- [x] Ready for public

### In pipeline / planned
- Dashboard integration for visual rollback (click to undo from the web UI)
- Batch undo with preview ("these 7 files will be restored — confirm?")

### How a user experiences it
Your agent accidentally overwrites an important file. You notice 10 minutes later. You type `unwind undo last` and the file is restored to exactly what it was before the agent touched it. Or you were away for 2 hours and want to review: `unwind undo --since "2h"` rolls back everything.

---

## 3. Ghost Mode

### What it is
A safe sandbox where your agent thinks it's doing real work, but nothing actually changes — every write is intercepted and logged, so you can see what would have happened without any risk.

### What it does
- Intercepts all state-modifying tool calls (writes, deletes, sends) and returns fake success responses
- Maintains a shadow virtual filesystem so the agent can read back its own "written" content and stay consistent
- Logs everything the agent tried to do, giving you a complete picture of its intentions
- Available as a standalone package (`pip install ghostmode`) or as part of UNWIND
- Egress guard scans outbound URLs and search queries for leaked secrets before they leave

### What it does NOT do
- Does not modify the agent's behaviour — the agent genuinely believes its actions succeeded
- Does not persist shadow state across sessions — it's a session-level sandbox
- Does not block reads (the agent can still see real files) — only writes are intercepted
- The agent may behave differently in Ghost Mode if its actions depend on real side effects from other systems

### Important distinction: Ghost Mode vs Amber Challenges
These are two separate capabilities that are sometimes confused:
- **Ghost Mode** = "what would happen?" — sandbox with shadow VFS, fake success, nothing real changes. The agent doesn't know it's in Ghost Mode.
- **Amber challenge** = "are you sure?" — the pipeline pauses on a high-risk action and asks for human approval before executing it for real. This is the trust light going amber.

Ghost Mode is about **visibility without consequences**. Amber challenges are about **human-in-the-loop approval**. They can work together (Ghost Mode on a tainted session) but they are architecturally distinct.

### Current status
- [x] Live on hardware
- [x] Tests passing (147 tests across shadow VFS, tool classification, egress guard, approve/discard)
- [x] Docs complete
- [x] Ready for public (also ships as standalone `ghostmode` package)

### Operational hardening notes (from Sentinel)
- Add explicit acceptance tests for on/off transitions after restart
- Ensure mode-state visibility in status output
- Keep user-facing explanation of challenge reasons clear

### In pipeline / planned
- Ghost Mode session export with diff view ("here's what would have changed")
- Approval flow: review ghost actions and selectively apply the ones you want

### How a user experiences it
You're about to let your agent run a complex task but you're not sure what it'll do. You turn on Ghost Mode. The agent runs, makes 15 tool calls, writes 6 files, sends 2 emails. None of it actually happened. You review the log, see one of the emails was wrong, and decide to re-run with a corrected prompt. Zero damage done.

---

## 4. CRAFT (Cryptographic Relay Authentication for Faithful Transmission)

### What it is
A tamper-proof flight recorder that cryptographically chains every tool call together, so you can prove exactly what your agent did, in what order, and that nobody altered the record.

### What it does
- Every tool call is recorded with a SHA-256 hash that links it to the previous event — break one link and every hash after it fails verification
- Parameters are hashed, never stored raw — the chain proves what happened without leaking what was in the payload
- Records are written before the tool call executes (crash resilience — evidence exists even if the process dies mid-flight)
- Provides CLI verification (`unwind verify`), tamper detection (`unwind tamper-check`), and external anchoring (`unwind anchor`) for third-party audit
- Transport-layer authentication: HKDF-derived keys, HMAC envelopes, strict FIFO sequencing, capability tokens for scoped tool delegation

### What it does NOT do
- Does not encrypt the event data — it proves integrity, not confidentiality
- Does not claim to solve prompt injection — it solves transport-layer spoofing, replay, and tampering
- Does not depend on external services (no blockchain, no cloud notary) — fully self-contained
- The chain proves the record wasn't altered after the fact — it doesn't prove the agent's decision was correct

### Current status
- [x] Live on hardware (170 events in chain, verified, 1 anchor, no tamper)
- [x] Tests passing (40+ CRAFT tests + chain verification in proof pack)
- [x] Docs complete (CRAFT Protocol v4.2 specification)
- [x] Ready for public

### Operational hardening notes (from Sentinel)
- Continue hardening persistence/resync edge cases
- Separate "implemented now" vs "planned hardening" clearly in public-facing docs
- Keep anchor/check outputs in release evidence packet
- Patent docs must separate implemented embodiment from forward embodiments

### In pipeline / planned
- Optional blockchain anchoring (periodic epoch checkpoints to external chain)
- HTML export for printable audit reports (`unwind export html`)
- Conversational query interface (`unwind ask "what happened today?"`)

### How a user experiences it
Your agent ran overnight while you slept. You wake up and type `unwind verify` — it checks every hash in the chain and tells you if anything was tampered with. You type `unwind ask "were any actions blocked?"` and get a plain English summary. For compliance, you run `unwind export html -o audit.html` and hand the report to your auditor.

---

## 5. CADENCE

### What it is
A temporal awareness layer that teaches your agent what time means — when you're focused, when you're away, when you're reading, and what normal looks like at any given hour — so it can adjust its behaviour and spot when something doesn't fit.

### What it does
- Watches timing gaps between interactions and infers human state (FLOW / READING / DEEP_WORK / AWAY) using Exponential Moving Averages per time-of-day bin
- Detects temporal anomalies: user is AWAY but tool calls arrive at machine speed, tool call timing has zero variance (bot), user is READING but rapid writes are firing
- Outputs state to a simple `state.env` file that any language, framework, or sidecar can read
- Integrates with UNWIND's enforcement pipeline as a trust signal — anomalies escalate taint and trigger amber
- Calculates Expected Response Time (ERT) adjusted for cognitive load (agent sent a 400-line script = user needs more reading time)

### What it does NOT do
- Does not spy on content — only observes timing patterns and token counts, never message content
- Does not phone home — all data stays on the device (enforced by CRIP)
- Does not break anything if disabled — UNWIND works fully without it
- Does not make enforcement decisions alone — it provides signals that the pipeline acts on
- **May increase friction, never grant privilege** — Cadence can make the system more cautious, but it can never bypass a security check or grant access that wouldn't otherwise exist

### Beyond security: temporal awareness as a product capability
Cadence is more than a security signal. It gives the agent genuine awareness of time:
- **What time it actually is** — not just relative gaps, but absolute temporal context
- **What the user's day looks like** — after weeks of data, the system knows "2am Tuesday is peak focus time, confidence 0.87"
- **When the user has missed something** — if a permission prompt has been waiting longer than the user's ERT, the system can nudge them ("your agent is waiting for you")
- **What silence means** — the difference between "user is reading my output" and "user went for a walk"

With a formal heartbeat (cron/n8n updating state.env with clock, day-of-week, hours-since-last-interaction), Cadence becomes the agent's clock and calendar — not just a stopwatch.

### Current status
- [x] Bridge enabled and consuming state file on Pi
- [x] Tests passing (112 tests across bridge, rhythm, storage, CRIP, cognitive load)
- [x] Policy influence observed (low-risk allowed, exec challenged on tainted session)
- [ ] Clean A/B causality proof pending (bridge ON vs OFF same scenario — Sentinel's recommendation)
- [ ] Docs complete (full README written but origin story paragraph blocked on UK patent filing)
- [ ] Pulse ingestion automated (currently manual state edits for testing)

**Honest status:** Early live. The bridge is running, the state file is being consumed, and we observed it influencing policy decisions. But the proof testing had shell friction, and a clean isolated A/B test hasn't been completed yet. For public claims: "live and influencing policy" is accurate. For formal evidence: A/B proof is pending.

### Operational hardening notes (from Sentinel)
- Automate pulse ingestion (not manual state edits) and enforce CRIP metadata on writes
- Need clean A/B proof to isolate causality before claiming full completion
- Current testing results are strong but not final-grade proof

### In pipeline / planned
- **Attention nudge (CAD1):** Ping the user when a permission prompt exceeds their ERT — "your agent is waiting for you." First non-security value from Cadence. Gateway feature for adoption: people turn it on for the nudge, get the security layer for free.
- **Formal heartbeat:** Cron/n8n updating state.env every 60 seconds with absolute time context (UTC, local hour, day of week, hours since last order, active window flag). Gives the agent a clock, not just a stopwatch.
- **Learned daily rhythm profiles:** After weeks of data, per-hour-per-day confidence scores. The agent knows what "normal" looks like at this exact time.
- **Extended state.env schema:** Calendar integration, external context signals, last order summary.

### How a user experiences it
You set `UNWIND_CADENCE_BRIDGE=1` and carry on working. Over days, your agent learns your rhythm. When you switch to another window and miss a permission prompt, it nudges you after 10 seconds. When you're away at 3am and something starts firing tool calls at machine speed, it goes amber. When you come back, it knows you're back. Your agent respects your time because it understands your time.

---

## 6. CRIP (Consentful Rhythm Inference Protocol)

### What it is
A consent framework baked into Cadence that ensures every piece of timing data carries explicit rules about where it can be processed, how long it's kept, and whether the user can delete it — turning privacy from a policy into a code path.

### What it does
- Attaches consent headers to every rhythm data write — no headers, no write (enforced in code, not policy)
- Default consent scope is LOCAL_ONLY — data never leaves the device unless the user explicitly changes it
- Default retention is ROLLING_7D — data auto-deletes after 7 days
- Every entry is user-deletable by default (`deletable: true`)
- Emits auditable consent events (CONSENT_CHANGED, DATA_DELETED, DATA_RESET) so consent changes are themselves part of the record

### What it does NOT do
- Does not enforce consent at the network level — it's a data-layer protocol (the data carries its own rules)
- Does not prevent a malicious actor with root access from reading raw files — it's a consent framework, not encryption
- Does not make consent decisions for the user — it enforces whatever scope the user (or default) has set
- Does not add overhead to the enforcement pipeline — it's metadata attached at write time

### Language framework (how to talk about CRIP)
- **Lead with what the user gains**, not what the system observes
- Never say "monitor", "track", "profile", "collect"
- Say: "learns your rhythm", "respects your time", "knows when you're away"
- Key phrase: **"Cadence teaches your agent what silence means"**
- Credibility comes from **defaults, not promises:**
  1. Off by default (opt-in via `UNWIND_CADENCE_BRIDGE=1`)
  2. Local only by default (`consent_scope: LOCAL_ONLY`)
  3. Auto-deleting by default (7-day rolling window)
  4. User-deletable (`deletable: true` on every entry)
  5. No cloud, no phone-home (runs on user's hardware)
  6. Fully disableable (one env var, no degradation to rest of stack)
- Docs should always state: what the user gains, what stays on their device, what they control, what happens if they turn it off (nothing breaks)

### Current status
- [x] Live on hardware (every pulse.jsonl and state.env write carries CRIP headers)
- [x] Tests passing (9 tests covering headers, validation, scopes, retention policies, immutability)
- [x] Docs complete (protocol documented in code, consent scopes defined)
- [x] Ready for public

### In pipeline / planned
- CRIP v2: retention enforcement automation (auto-purge entries past their retention window)
- User-facing consent dashboard ("here's what Cadence knows, here's how long it's kept, delete anything")
- Aggregate-only scope for opt-in anonymised pattern sharing (no individual data, just population-level timing norms)

### How a user experiences it
You don't experience CRIP directly — it works behind the scenes. But if you ever ask "what does Cadence know about me and where does it go?" the answer is always: it's on your device, it auto-deletes in 7 days, you can wipe any of it anytime, and it never leaves your machine unless you explicitly say so. That's not a privacy policy — it's how the code works.

---

## How the layers connect (system map)

```
CRIP (consent rules)
 └── attached to every write from ↓
CADENCE (temporal awareness + agent clock)
 └── feeds trust signals into ↓
UNWIND ENFORCEMENT (15-stage pipeline)
 ├── records every decision to → CRAFT (flight recorder)
 ├── captures snapshots for → ROLLBACK (time machine)
 └── can divert calls to → GHOST MODE (sandbox)
```

**Required:** UNWIND enforcement is the core. Everything else is optional.

**Independent:** Ghost Mode works standalone (`pip install ghostmode`). CRAFT chain works without Cadence. Rollback works without CRAFT. Cadence works without CRAFT.

**Enhancing:** Each layer makes the others stronger:
- Cadence + CRAFT = temporal anomalies in a tamper-proof record
- Ghost Mode + Rollback = test safely, undo mistakes
- CRIP + Cadence = rhythm awareness with built-in consent
- CRAFT + Rollback = prove what happened AND undo it

**Adoption funnel:** Ghost Mode (free, zero risk) → UNWIND (full enforcement) → CRAFT (audit trail) → Cadence (temporal awareness). Each step adds value without requiring the previous one, but the full stack is greater than the sum of its parts.

---

## One-line pitch for each (for README / landing page)

1. **UNWIND:** See everything your agent does. Control what it's allowed to do. Undo anything that goes wrong.
2. **Rollback:** Every action has an undo button — one file, one event, or everything since 3pm.
3. **Ghost Mode:** Let your agent run for real, without consequences. See what it would have done. Nothing changes.
4. **CRAFT:** A tamper-proof flight recorder for every tool call. Prove what happened. Prove nobody changed the record.
5. **CADENCE:** Your agent learns your rhythm. It knows when you're focused, when you're away, and when something doesn't fit.
6. **CRIP:** Your timing data, your device, your rules. Auto-deletes in 7 days. Never leaves your machine.

---

## Open questions for David (resolve before Opus review)

1. **CADENCE status language:** Use "early live, policy influence observed" (Sentinel's safer framing) or "live" (accurate but less cautious) in public docs?
2. **CADENCE docs timing:** Publish trimmed README now (no Geiger details) or wait for UK patent filing?
3. **Rollback positioning:** "Undo button" (simple) or "time machine" (ambitious)?
4. **CRAFT standalone:** Hint at independent enterprise value (compliance/SOX/SOC2) or keep positioned as part of UNWIND only?
5. **Ghost Mode as entry point:** Reinforce the adoption funnel (Ghost → UNWIND → CRAFT → Cadence)?
6. **CRIP v2 scope:** Minimal CLI (`cadence consent show`) or visual web UI in dashboard?
