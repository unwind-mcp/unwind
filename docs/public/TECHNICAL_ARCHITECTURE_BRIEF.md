# UNWIND — Technical Architecture Brief

## System Boundary

UNWIND is a sidecar governance service and/or local enforcement layer that intercepts tool calls before execution. It integrates via adapters/proxies to whichever agent runtime is in use.

### High-Level Flow

1. Agent proposes a tool call (command + parameters + context metadata).
2. Adapter forwards the call to UNWIND for evaluation.
3. UNWIND returns a decision: **ALLOW / BLOCK / AMBER** (+ reasons, policy IDs, required mitigations).
4. If allowed, adapter executes tool call (optionally under UNWIND mediation).
5. UNWIND records the event and decision into CRAFT, updates session trust state, and advances the chain.

## Core Components

### A) Policy Enforcement Pipeline (Deterministic)

A 15-stage pipeline of checks that operates on the proposed tool call, its context, and current session trust state (green / amber / red). Categories:

- **Identity and session integrity** — what generated the call, which adapter/session, session kill state
- **Scope and capability checks** — is this tool/action permitted for this agent and mission (capability tokens)
- **Filesystem constraints** — allowed paths, write protections, sandbox rules (path jail)
- **Self-protection** — prevents agents from modifying UNWIND's own configuration, policy, or state files
- **Network constraints** — allowlists, blocked destinations, protocol rules
- **DLP / data egress heuristics** — prevent obvious sensitive exfiltration paths (secret registry, pattern matching)
- **Rate/tempo gating** — throttle suspicious bursts (circuit breaker)
- **Taint tracking** — mark sessions as tainted after ingestion of external content; graduated decay rules (level, cooldown, op-based)
- **Escalation rules** — when to require explicit user confirmation, step-up policies
- **Ghost Mode gate** — if session is in Ghost Mode, intercept and simulate rather than execute

Key design point: rules are deterministic and reviewable. The system behaves the same way for the same inputs.

### B) Smart Snapshots (Reversibility Engine)

For actions with significant side effects, UNWIND requires a snapshot boundary:

1. Pre-snapshot of relevant state (file content, permissions, metadata).
2. Execute the tool call.
3. If post-checks fail or the user rejects: rollback.
4. If accepted: commit and advance the audit chain.

Implementation: reflink-first snapshots (CoW where filesystem supports it), 25 MB cap per snapshot, batch undo support, conflict detection on rollback.

This makes autonomous tooling tractable in enterprise: "agents can act, because we can undo."

### C) Ghost Mode (Dry-Run Sandbox)

Any session can be switched to Ghost Mode at runtime. The agent continues operating normally, but:

- All state-modifying actions (file writes, commands, network requests) are intercepted and simulated.
- A shadow VFS keeps the agent internally consistent — reads of previously "written" files return the ghost content.
- An egress guard blocks real network activity.
- Nothing real changes on the host system.

The operator reviews what the agent attempted via the dashboard (two-column view: "what the agent tried" vs "what actually happened"), then either approves buffered writes to the real filesystem or discards everything.

Ghost Mode is a pipeline stage, not a separate system — it reuses the same enforcement path and records events into the same CRAFT chain with `ghost_mode` flagged.

### D) CRAFT (Cryptographic Command Chain + Audit Log)

CRAFT provides two functions:

**Transport authentication** — every command is signed using HMAC with HKDF-derived session keys. Commands are strictly FIFO-ordered with epoch boundaries. Capability tokens bind permitted actions to sessions. An injected, replayed, or reordered command breaks the chain cryptographically.

**Tamper-evident audit** — a chained log where each event includes a hash link to the previous entry. Events include:

- Tool call summary (what was requested)
- Decision outcome (allow / block / amber)
- Policy version IDs / rule hits
- Snapshot IDs / rollback or commit result
- Taint state transitions
- Ghost mode flag
- Optional external signals (e.g., Cadence state)
- Hash chain link fields

**Verification property:** an auditor can validate the chain has not been altered without needing to trust the runtime.

### E) Cadence (Temporal State Engine)

Cadence emits a minimal operational state derived from the spacing between interactions. It produces:

- A discrete state: **FLOW / READING / DEEP_WORK / AWAY**
- An **ERT** (Expected Response Time) which expands when agent output was large (cognitive load offset for reading)
- An **anomaly score** — how unusual the current gap is relative to time-of-day norms (EMA-based)

Cadence writes to:

- `pulse.jsonl` — append-only rhythm event log (rolling 7-day window)
- `state.env` — atomic "instant state" file for fast readers
- `profile.md` — human-readable summary

Cadence's schema is contract-first because multiple systems read it.

### F) CRIP (Consent and Retention Contract)

CRIP attaches consent metadata to every rhythm data point:

- **consent_scope** — where it can be processed (LOCAL_ONLY / PRIVATE_CLOUD / AGGREGATE_ONLY)
- **retention** — rolling window / session only / explicit duration
- **deletable** — boolean, always true by default
- **audit_version** — schema version for compliance traceability

It also defines event types for consent changes and deletion actions.

Defaults are maximally restrictive: local only, 7-day rolling window, user-deletable, no cloud sync. These are enforced defaults, not just promises.

This keeps Cadence safe and enterprise-acceptable.

## UNWIND-Cadence Bridge

UNWIND can optionally consume Cadence's `state.env` as an external signal (feature-flagged via `UNWIND_CADENCE_BRIDGE=1`) to adjust trust decisions:

**Timing-only detection rules:**

- **Ghost activity:** user AWAY + machine-speed tool calls → escalate / kill / lock
- **Bot pattern:** ultra-low variance timing over repeated calls → circuit breaker
- **Reading interrupt:** user READING + unexpected tool bursts → flag / escalate
- **Taint bracket:** correlate taint-clear events with tool-call windows in the audit chain

Cadence improves both UX and security posture without invasive telemetry.

## Interfaces That Merit Formal Contracts

Even if initially internal, these become contracts the moment third parties integrate:

- Sidecar API request/response shapes (policy check + telemetry ingestion)
- Cadence data contract (`pulse.jsonl` / `state.env`)
- CRAFT chain verification format
- Adapter/plugin interfaces for agent runtimes

## Deployment Modes

- **Local dev/IDE mode:** sidecar runs on developer machine.
- **Workstation/endpoint mode:** enterprise-managed sidecar with policy packs.
- **Server/agent-host mode:** sidecar co-located with agent runner, with central policy management.
- **Hybrid:** local Cadence + central compliance export.
