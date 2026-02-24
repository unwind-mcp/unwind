# UNWIND

## See Everything. Undo Anything.

### The Flight Recorder & Trust Layer for AI Agents

---

## Executive Summary

UNWIND is a security and trust middleware for AI agents (initially targeting OpenClaw, extensible to any MCP-based agent framework). It provides a real-time visual timeline of every agent action, ambient trust indicators, selective rollback of agent operations, and cryptographic proof that actions were authorised and unmodified.

Think of it as the black box flight recorder meets Apple Time Machine — but for AI agents.

**The core insight:** Current agent security tools (SecureClaw, AI SAFE², OpenClaw's native audit) focus on hardening configurations and blocking known attack patterns. None of them answer the user's fundamental question: *"What did my agent actually do, and can I undo it?"*

UNWIND fills that gap.

---

## Competitive Landscape (As of 19 February 2026)

| Tool | What It Does | What It Doesn't Do |
|------|-------------|-------------------|
| **OpenClaw native** | `security audit --deep`, tool deny lists, exec sandboxing, DM pairing | No action timeline, no rollback, no ambient trust indicator |
| **SecureClaw** (Adversa AI) | 51 audit checks, 15 behavioural rules (1,230 tokens), plugin + skill dual-layer | Skill-level rules can be overridden by prompt injection; no visibility layer for users |
| **AI SAFE²** (Cyber Strategy Institute) | External governance framework, risk scoring, human-in-the-loop controls | Framework not product; no implementation shipped; no user-facing dashboard |
| **CrowdStrike** | Enterprise endpoint detection, DNS monitoring, process tree visibility | Enterprise-only; detection not prevention; no agent-specific trust UX |
| **UNWIND** | **Action timeline, ambient trust panel, selective rollback, CR-AFT anchoring, conversational security** | **This is what we're building** |

**White space UNWIND uniquely occupies:**

1. User-facing trust visualisation (the "padlock")
2. Action-level timeline with state snapshots (the "flight recorder")
3. Selective rollback of agent operations (the "undo")
4. Cryptographic event chain with tamper evidence (CR-AFT anchoring)
5. Conversational security interrogation ("show me what you did")
6. Return-contamination verification (post-external-operation behavioural diff)

---

## Architecture

### Design Principles

- **Middleware, not modification** — UNWIND intercepts agent actions; it does not modify the agent itself
- **Security outside the blast radius** — enforcement logic runs in a separate process, not inside the agent's context window (the fundamental weakness SecureClaw identified in skill-only approaches)
- **Trust through visibility** — the primary UX is not blocking things but showing things
- **Reversibility over prevention** — you can't prevent every mistake; you can make every mistake recoverable

### System Architecture

```
┌─────────────────────────────────────────────────┐
│                   USER INTERFACE                 │
│                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  Trust    │  │   Timeline   │  │  Chat      │  │
│  │  Panel    │  │   Viewer     │  │  Interface │  │
│  │  (🟢🟡🔴) │  │   (scroll)   │  │  (ask)     │  │
│  └──────────┘  └──────────────┘  └───────────┘  │
└────────────────────┬────────────────────────────┘
                     │ WebSocket / REST
┌────────────────────▼────────────────────────────┐
│              UNWIND CORE ENGINE                  │
│                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Event    │  │  Rule        │  │  Rollback  │  │
│  │ Capture  │  │  Evaluator   │  │  Engine    │  │
│  │ (hooks)  │  │  (scoring)   │  │  (restore) │  │
│  └──────────┘  └──────────────┘  └───────────┘  │
│                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ State    │  │  CR-AFT      │  │  Return    │  │
│  │ Snapshot │  │  Anchor      │  │  Verifier  │  │
│  │ Manager  │  │  (hash chain)│  │  (diff)    │  │
│  └──────────┘  └──────────────┘  └───────────┘  │
└────────────────────┬────────────────────────────┘
                     │ Hooks / Middleware
┌────────────────────▼────────────────────────────┐
│              AGENT FRAMEWORK                     │
│     (OpenClaw / MCP-compatible / custom)         │
│                                                  │
│  Gateway → Session → Tools → Skills → Channels   │
└─────────────────────────────────────────────────┘
```

### Integration Points (OpenClaw-specific)

OpenClaw provides hook points that UNWIND attaches to:

| Hook | UNWIND Action |
|------|---------------|
| `agent_start` | Create session baseline, begin event capture |
| `tool_call` (before) | Snapshot pre-state, evaluate permission scope |
| `tool_call` (after) | Log result, capture post-state delta, update trust score |
| `agent_end` | Seal session event chain, compute CR-AFT hash |
| `skill_load` | Verify skill integrity against known-good hash |
| `channel_message` (inbound) | Scan for injection patterns before agent processing |

---

## The Five Layers

### Layer 1 — Event Capture (The Flight Recorder)

**What it does:** Every agent action — tool calls, file operations, API requests, message sends, config changes — gets logged as a structured event.

**Event schema:**

```json
{
  "event_id": "evt_20260219_143022_001",
  "timestamp": "2026-02-19T14:30:22.451Z",
  "session_id": "sess_abc123",
  "type": "tool_call",
  "tool": "fs.write",
  "target": "/home/user/documents/report.md",
  "parameters": { "content_hash": "sha256:a1b2c3..." },
  "triggering_prompt": "Please update my report with the Q4 figures",
  "permission_scope": "fs:workspace",
  "result": "success",
  "duration_ms": 142,
  "trust_score_delta": 0,
  "pre_state_ref": "snap_20260219_143022_pre",
  "post_state_ref": "snap_20260219_143022_post",
  "chain_hash": "sha256:previous_hash + this_event"
}
```

**Storage:** Append-only SQLite database at `~/.unwind/events.db`. Chosen for zero-config, single-file portability, and proven reliability. Events are immutable once written.

**Implementation:** OpenClaw plugin using the gateway hook system. Registers as a middleware that wraps every tool dispatch. Zero-token overhead — runs entirely outside the model's context window.

---

### Layer 2 — State Snapshots (The Save Points)

**What it does:** Before any state-modifying action, UNWIND captures a snapshot of the affected resource. This is the "before photo" that enables rollback.

**Snapshot types by action category:**

| Action Type | Snapshot Method | Rollback Capability |
|-------------|----------------|-------------------|
| File write/modify | Copy original file to `.unwind/snapshots/` | ✅ Full restore |
| File delete | Copy to snapshots before deletion | ✅ Full restore |
| Config change | JSON diff of before/after state | ✅ Full restore |
| Calendar event create | Store event ID + creation params | ✅ Delete via API |
| Calendar event modify | Store original event state | ✅ Restore via API |
| Email/message send | Store content + recipients | ⚠️ Undo-assist (cannot unsend) |
| API call (external) | Store request + response | ⚠️ Undo-assist (side effects may persist) |
| Package install | Store package name + version | ✅ Uninstall command |
| Browser action | Store URL + action description | ⚠️ Undo-assist (form submissions etc.) |

**Key honesty:** UNWIND distinguishes between fully reversible actions (green ↩️ icon) and undo-assist actions (amber ⚠️ icon) where it shows what happened and helps you manually reverse, but cannot guarantee automated rollback. This transparency is itself a trust feature.

**Storage budget:** Configurable. Default: keep snapshots for 30 days, 5GB max, oldest-first eviction. User can configure per-category retention.

---

### Layer 3 — Trust Panel (The Padlock)

**What it does:** A persistent, always-visible status indicator showing the current trust state of the agent. The HTTPS padlock metaphor applied to agentic AI.

**States:**

```
🟢 ALL CLEAR
   Agent operating within normal parameters.
   All actions within permission scope.
   No anomalous patterns detected.

🟡 ATTENTION
   Agent requested elevated permission (awaiting approval).
   Unusual access pattern detected (e.g., accessing files outside workspace).
   High-frequency tool calls (possible automation loop).
   External content ingested (potential injection vector).

🔴 ALERT
   Action blocked by UNWIND rule.
   Permission scope violation detected.
   State modification without matching trigger prompt.
   Skill integrity check failed.
   Return-contamination check flagged anomaly.
```

**Trust score computation:**

The trust score is a rolling composite of:

- **Permission adherence** (0-100): Is the agent staying within its declared scope?
- **Behavioural consistency** (0-100): Are actions consistent with the triggering prompt?
- **Pattern normality** (0-100): Does the action frequency/type match historical baselines?
- **Content safety** (0-100): Have injection patterns been detected in inbound content?
- **Integrity verification** (0-100): Are skill files and configs unchanged from known-good state?

Composite score maps to status: 90-100 = 🟢, 60-89 = 🟡, below 60 = 🔴.

**Display options:**

- **Minimal:** Traffic light icon in system tray / OpenClaw Control UI header
- **Summary:** One-line status bar: "🟢 All clear — 14 actions in last hour, all within scope"
- **Expanded:** Full dashboard with per-category scores and recent event feed

---

### Layer 4 — Rollback Engine (The Undo)

**What it does:** Selective, granular reversal of agent actions using stored snapshots.

**Rollback modes:**

1. **Single action undo:** Reverse the most recent action (Ctrl+Z equivalent)
2. **Action chain undo:** Reverse a sequence of related actions (e.g., "undo everything the agent did in response to my last message")
3. **Time-range undo:** Reverse all actions within a time window ("undo everything since 3pm")
4. **Selective undo:** Cherry-pick specific actions to reverse from the timeline

**Rollback process:**

```
User: "Undo the file changes from this morning"

UNWIND:
1. Query events DB for file modifications between 00:00 and 12:00 today
2. For each: check snapshot exists, verify file hasn't been further modified
3. Present summary: "Found 3 file changes. 2 fully reversible, 1 has been
   subsequently modified (will restore to this morning's version, losing
   afternoon edits). Proceed?"
4. On confirmation: restore from snapshots, log rollback as its own event
5. Update trust panel
```

**Conflict resolution:** If a file has been modified both by the agent AND by the user since the snapshot, UNWIND flags the conflict and offers options: restore agent's version, keep current, or show diff. Never silently overwrites user changes.

---

### Layer 5 — CR-AFT Anchoring (The Proof)

**What it does:** Cryptographic chaining of the event log, providing tamper evidence and provable action attribution.

**How it works:**

Each event's `chain_hash` is computed as:

```
chain_hash[n] = SHA-256(chain_hash[n-1] + event_id + timestamp + action_hash)
```

This creates a Merkle-like chain where any modification to a historical event breaks all subsequent hashes. Verification is O(n) for the full chain, O(1) for the most recent event.

**What this proves:**

- The event log has not been tampered with since creation
- Events occurred in the recorded order
- No events have been inserted or deleted

**What this enables (future):**

- Third-party audit verification ("prove to my IT department what the agent did")
- Insurance/liability evidence ("the agent was operating within its approved scope")
- Multi-party trust ("I can prove my agent didn't access your files")

**Connection to BDE corpus:** This directly implements the Behavioral Merkle Trees concept from Run EU (Claude Opus 4.5) and the Measured Return attestation from Run EN (ChatGPT Pro). The five-model convergence on ASML/IDBM/SCC/STC missing bridge maps to the event schema standardisation needed here.

---

## Layer 6 (Future) — Return Contamination Verification

**What it does:** When an agent returns from external operations (browsing hostile content, interacting with external APIs, processing inbound messages from untrusted sources), UNWIND performs a behavioural diff against the pre-operation baseline.

**This maps directly to BDE Runs:**

| BDE Concept | UNWIND Implementation |
|-------------|----------------------|
| Differential Behavioural Fingerprinting (EU) | Pre/post operation goal alignment scoring |
| Quarantine Sandbox with Semantic Diff (EU) | Isolated evaluation of agent state before re-granting permissions |
| Instruction Canaries (EU) | Planted verification prompts to detect goal drift |
| Epistemic Airlock (EM, Gemini 3) | Staged re-entry with incremental permission restoration |

**Status:** Research layer. Depends on Layers 1-5 being stable. Provisional patent candidate — this is genuine white space that no existing tool addresses.

---

## User Experience

### The Timeline View

```
┌─────────────────────────────────────────────────────┐
│  UNWIND Timeline — Today                    🟢 Clear │
├─────────────────────────────────────────────────────┤
│                                                      │
│  14:32  📧 Sent email to sarah@company.com      ⚠️  │
│         "Q4 report summary as requested"             │
│                                                      │
│  14:30  📄 Modified report.md                   ↩️   │
│         Added Q4 figures (3 paragraphs)              │
│                                                      │
│  14:28  🔍 Web search: "Q4 2025 revenue data"  ✓    │
│         3 results retrieved                          │
│                                                      │
│  14:25  📅 Created calendar event               ↩️   │
│         "Review Q4 report" — Tomorrow 10:00          │
│                                                      │
│  14:22  💬 Received message (Telegram)          ✓    │
│         "Can you prep the Q4 report?"                │
│                                                      │
├─────────────────────────────────────────────────────┤
│  [Undo Last] [Undo Range...] [Search...]  [Export]   │
└─────────────────────────────────────────────────────┘

Key:  ↩️ = fully reversible  ⚠️ = undo-assist  ✓ = read-only (no undo needed)
```

### Conversational Interface

Users can interact with UNWIND through the same messaging channel as their agent:

```
User:  "unwind: what did you do this morning?"

UNWIND: Between 08:00 and 12:00 today, your agent performed 23 actions:
        - 8 calendar checks (read-only)
        - 4 emails sent (to Mike, Sarah, James, HR team)
        - 3 file modifications (report.md, budget.xlsx, notes.txt)
        - 5 web searches
        - 3 Telegram message replies

        Trust score: 🟢 98/100. All actions within normal scope.
        Want details on any category?

User:  "show me the emails"

UNWIND: [Displays email summaries with timestamps and recipients]
        Any of these look wrong? I can show the full content or
        help you send corrections.
```

### "Away Mode" Summary

When the user returns after a period of agent autonomy:

```
┌─────────────────────────────────────────────────────┐
│  Welcome back. While you were away (2h 15m):        │
│                                                      │
│  🟢 Trust Score: 96/100                              │
│                                                      │
│  Summary:                                            │
│  • Replied to 6 Telegram messages                    │
│  • Updated 2 documents                               │
│  • Scheduled 1 meeting (Thursday 14:00 with Mike)    │
│  • Blocked 1 suspicious inbound message              │
│                                                      │
│  ⚠️ 1 item for your review:                          │
│  An email from unknown sender contained patterns     │
│  consistent with prompt injection. Message was        │
│  quarantined. [View] [Delete] [Allow]                │
│                                                      │
│  [View Full Timeline]  [Looks Good ✓]                │
└─────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1 — Foundation (2-3 weeks)

**Deliverables:** Event capture + SQLite storage + basic CLI timeline viewer

- OpenClaw plugin skeleton (gateway hook registration)
- Event schema implementation
- Tool call interception middleware
- SQLite event store with append-only writes
- CLI command: `unwind log` (show recent events)
- CLI command: `unwind log --since "2 hours ago"`
- Basic test suite

**Tech stack:** Node.js (OpenClaw ecosystem), SQLite (better-sqlite3), OpenClaw plugin API

**This alone is useful.** Even without the UI, having a searchable, structured log of everything your agent did is a significant improvement over OpenClaw's raw session JSONL files.

### Phase 2 — Snapshots + Rollback (2-3 weeks)

**Deliverables:** State snapshots for file operations + rollback engine

- Pre-action state capture for file system operations
- Snapshot storage with configurable retention
- Rollback engine for file operations (restore from snapshot)
- Conflict detection (file modified since snapshot)
- CLI commands: `unwind undo <event_id>`, `unwind undo --since "3pm"`
- Calendar operation snapshots and rollback via API
- Extend test suite

**This makes UNWIND practically useful for daily use.** "The agent messed up my report — undo it" becomes a one-command operation.

### Phase 3 — Trust Panel + Web Dashboard (2-3 weeks)

**Deliverables:** Real-time trust indicator + visual timeline

- Trust score computation engine (5-factor scoring)
- WebSocket event stream from core engine to UI
- Web dashboard (React): timeline view, trust panel, action details
- Integration with OpenClaw Control UI (embed as panel/tab)
- Green/amber/red status indicator
- "Away mode" summary generation
- Notification system for amber/red state changes

**This is the "padlock moment."** The point where non-technical users can see and trust what their agent is doing.

### Phase 4 — CR-AFT Chain + Conversational Interface (2-3 weeks)

**Deliverables:** Cryptographic event chain + natural language security queries

- SHA-256 hash chain implementation on event log
- Chain verification CLI: `unwind verify`
- Conversational query interface (UNWIND as an OpenClaw skill that reads its own event log)
- "What did you do while I was away?" natural language summaries
- Export functionality (JSON, PDF report) for audit purposes
- Tamper detection and alerting

### Phase 5 — Return Verification (Research Phase)

**Deliverables:** Behavioural diff for post-external-operation agent state

- Pre/post operation baseline capture
- Goal alignment scoring
- Instruction canary system
- Quarantine mode for flagged sessions
- **Provisional patent filing** (this is novel)

---

## Technical Decisions

### Why SQLite (not Postgres, not filesystem)

- Zero configuration — single file, no server
- Proven at massive scale (billions of deployments)
- Append-only mode prevents accidental deletion
- Full-text search for event queries
- Portable — copy one file to move your entire UNWIND history
- Matches OpenClaw's "runs on your machine" philosophy

### Why Plugin (not Skill)

SecureClaw correctly identified that skill-level security can be overridden by prompt injection because it runs inside the agent's context window. UNWIND's core engine MUST run as a plugin (separate process) not a skill (in-context rules). The conversational interface in Phase 4 is a thin skill layer that queries the plugin — it cannot override the plugin's enforcement.

### Why Middleware Pattern

UNWIND wraps tool dispatch, not the agent itself. This means:
- Agent framework changes don't break UNWIND
- Works with any model (Opus, GPT, local)
- No token overhead on the model's context
- Can be disabled without affecting agent function

---

## Connection to BDE Corpus

UNWIND implements concepts from the following BDE runs:

| Run | Model | Moonshot | UNWIND Layer |
|-----|-------|---------|--------------|
| EU | Claude Opus 4.5 | Behavioral Merkle Trees | Layer 5 (CR-AFT Chain) |
| EU | Claude Opus 4.5 | Differential Behavioural Fingerprinting | Layer 6 (Return Verification) |
| EU | Claude Opus 4.5 | Quarantine Sandbox with Semantic Diff | Layer 6 |
| EU | Claude Opus 4.5 | Instruction Canaries | Layer 6 |
| EN | ChatGPT Pro | Measured Return / Remote Attestation | Layer 5 |
| EN | ChatGPT Pro | CBOM for Agents | Layer 1 (Event Schema) |
| EM | Gemini 3 | Epistemic Airlock | Layer 6 |
| EO | ChatGPT 5.2 Pro | Skill Observability Cockpit | Layer 3 (Trust Panel) |
| EO | ChatGPT 5.2 Pro | SkillLockfile + Signing | Layer 5 |
| ES | Grok 4.1 | Unified Registry + Community Governance | Future: skill verification |

**Missing Bridge convergence (5 models):** IDBM / SCC+STC / Skill Metadata Schema / ASML — all point to the event schema standardisation that Layer 1 begins to address.

---

## Patent Considerations

**Layers 1-4** are implementations of known patterns (event logging, state snapshots, dashboards, rollback). Individually not patentable, but the specific combination for AI agent trust may be novel as a system claim.

**Layer 5** (CR-AFT anchoring applied to agent action chains) — check against existing CR-AFT provisionals. May be covered or may need a specific agent-context filing.

**Layer 6** (Return contamination verification via behavioural Merkle diffing) — this is the strongest patent candidate. No existing implementation. Five-model convergence validates the white space. Recommended: provisional filing at £65 before any public disclosure.

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| OpenClaw plugin API changes | High (fast-moving project) | Abstract hook interface; version-pin integration |
| Performance overhead on agent operations | Medium | Async event writes; snapshot only state-modifying actions |
| Storage consumption from snapshots | Medium | Configurable retention; oldest-first eviction; compression |
| Snapshot captures sensitive data | High | Snapshots inherit agent's permission scope; encrypted at rest option |
| OpenClaw acquired by OpenAI (already happening) | Confirmed | Build for MCP compatibility, not OpenClaw-only |
| SecureClaw or AI SAFE² adds timeline features | Low-Medium | First-mover advantage; CR-AFT layer is defensible; focus on UX not compliance |

---

## Building UNWIND with Claude Code

### Why This Is Buildable

UNWIND's core architecture is an **MCP proxy server** — and this maps directly to skills already proven in the kitchen measurement and pricing applications built with Claude Code. Claude calls a tool, the request hits UNWIND first, UNWIND logs it, snapshots the affected state, runs the trust check, then either forwards to the real tool server or blocks and returns a review message.

The MCP proxy pattern means UNWIND doesn't modify Claude, doesn't modify existing tool servers, and can be inserted transparently by changing tool configuration from:

```
tool_server: "localhost:8001"  # email tools
```

to:

```
tool_server: "localhost:9000"  # UNWIND proxy
upstream: "localhost:8001"     # email tools (real)
```

Claude doesn't know UNWIND exists. The tool servers don't know UNWIND exists. UNWIND intercepts, logs, snapshots, checks, and passes through.

### What Claude Code Actually Builds

**Flight Recorder** — a SQLite database with one table. Every tool call gets a row: timestamp, tool name, parameters, source classification, result. Simpler than the kitchen pricing database.

**Save Points** — before calling a file-modifying tool, copy the target file to a snapshots directory (`shutil.copy2()` in Python). For email/calendar, store the pre-action state as JSON. Configurable retention: 30 days default, 5GB max, oldest-first eviction.

**Trust Light** — a function that takes the tool call and checks two things. Did the triggering content come from an external source (email, web fetch, document read)? Is the target action on a sensitive list (send email, delete file, modify contacts, make API call)? Both external AND sensitive = amber, prompt for confirmation. Approximately 40 lines of Python logic.

**Undo** — given an event ID from the Flight Recorder, find the corresponding Save Point and restore it. For files, copy the snapshot back. For other actions, tool-specific reversal where the API supports it, otherwise flag as manual.

**Timeline view** — a CLI querying the SQLite database displaying events chronologically with colour coding. Or a basic local web page with Flask for visual interaction.

### The Two-Input Trust Light (v1)

The simplest viable Trust Light skips the hard problem (intent deviation, which requires semantic comparison) and runs on just two inputs:

1. **External source trigger?** Was the action influenced by content from an external source (email, web page, retrieved document)? In an MCP context, detectable from the sequence of tool calls — if the agent called `read_email` then immediately called `send_email`, the send was influenced by email content.

2. **High-risk action pattern?** Does the target action match a known sensitive pattern (bulk email forwarding, file deletion, credential access, data sent to unfamiliar external addresses)?

Both flags true = **amber** (blocked pending user confirmation). Either flag alone = logged but permitted. Neither = **green** (silent pass-through).

This catches the majority of injection attacks — which by definition come from external sources and target high-risk actions — while avoiding the NLP complexity of intent comparison entirely. Intent deviation becomes a v2 feature once real usage data exists to train against.

### Realistic Build Estimate

**Week 1** — MCP proxy skeleton that transparently forwards all tool calls, plus SQLite Flight Recorder logging every call. Deliverable: a working event log you can query.

**Week 2** — Save Point file snapshots before write operations, plus the two-input trust check with amber blocking. Deliverable: the core security functionality, catching live injection attempts.

**Week 3** — CLI timeline viewer and rollback commands. Deliverable: the complete user-facing product — see everything, undo anything.

**Week 4** — Polish, edge cases, testing against actual injection attempts, documentation.

This is a realistic scope for someone already building working MCP tool applications with Claude Code. The individual components are simpler than the kitchen measurement system. The main learning curve is the MCP proxy pattern — making UNWIND act as both an MCP server (to Claude) and an MCP client (to the real tools) simultaneously.

### What Could Go Wrong

**The proxy adds latency.** Every tool call has an extra hop. For file operations this is negligible. For high-frequency tool calls it could become noticeable. Mitigation: the trust check is fast (two boolean checks, no LLM call needed), and the snapshot is just a file copy.

**Source classification needs tuning.** Knowing whether a tool call was triggered by user intent versus external content requires tracking what the agent read before deciding to act. In MCP context, the tool call sequence is visible, but heuristics need real-world tuning.

**Snapshot storage accumulates.** At 5GB cap with 30-day retention and auto-eviction this is manageable, but the cleanup logic needs building and testing properly.

**Ongoing maintenance.** A Python codebase needs upkeep. Not heavy for this scope, but it's a commitment.

### Recommended Approach

Build UNWIND as a personal tool first — protecting your own business agents. Use it for a month. See where it catches real problems, where it generates false positives, where the UX frustrates. Then decide whether to open-source it.

The v1 is genuinely within Claude Code capabilities. The market gap is real and currently unfilled. And you'd be the first person running agent security middleware built from cross-domain BDE-derived concepts on your own production business.

---

## Summary

UNWIND occupies a distinct position in the agent security landscape:

- **SecureClaw** asks: "Is this agent configured safely?" (Audit)
- **AI SAFE²** asks: "Is this agent governed properly?" (Compliance)
- **CrowdStrike** asks: "Is this agent a threat?" (Detection)
- **UNWIND** asks: "What did this agent do, and can I undo it?" (Trust & Reversibility)

These are complementary, not competitive. UNWIND can coexist with SecureClaw's hardening and AI SAFE²'s governance. The unique value is the user-facing trust layer — making agent security visible, scrubable, and reversible.

**The tagline says it all: See Everything. Undo Anything.**

---

*Document version: 1.0 — 19 February 2026*
*Project: UNWIND*
*Author: David / Claude collaboration*
*Status: Project specification for Cowork build*
