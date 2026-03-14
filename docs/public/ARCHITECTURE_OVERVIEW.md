# UNWIND — Agent Governance Infrastructure

## What It Is

UNWIND is a deterministic runtime governance layer for persistent AI agents.

It sits between:

- The agent (LLM + planner),
- The tools (filesystem, network, shell, APIs),
- And the enterprise environment.

It ensures that autonomous agents can act —
without becoming uncontainable, unauditable, or legally risky.

## The Core Problem It Solves

Persistent agents introduce four new enterprise risks:

1. Unbounded tool execution
2. Silent drift from original intent
3. Irreversible side effects
4. Lack of provable audit trail

Most platforms try to solve this with prompt engineering, policy hints, or model-level guardrails.

UNWIND solves it at the runtime layer instead.

## The Stack (Layered Architecture)

### 1. Enforcement Kernel (UNWIND Core)

A 15-stage deterministic policy pipeline that evaluates every tool call before execution.

- Supply chain, scope, DLP, network, and filesystem checks
- Explicit allow / block / amber decisions
- Green / amber / red trust state on every session — real-time security posture visible at a glance
- No LLM in the hot path
- Predictable, inspectable behaviour

Think: "Firewall + transaction validator for agent actions."

### 2. Reversibility Engine (Smart Snapshots)

Every meaningful action can be:

- Snapshotted before execution
- Atomically committed
- Or rolled back — individually or in batch

This turns agent side effects into reversible transactions.
It dramatically lowers enterprise risk.

### 3. Ghost Mode (Dry-Run Sandbox)

Any session can be switched to Ghost Mode. The agent continues operating — but all state-modifying actions (file writes, commands, network requests) are intercepted and simulated. A shadow filesystem keeps the agent internally consistent. Nothing real changes.

The operator reviews what would have happened, then approves or discards.

This turns "should I let the agent try this?" from a leap of faith into a preview.

### 4. CRAFT (Cryptographic Command Chain + Audit Log)

CRAFT provides two things:

**Transport authentication** — every command is HMAC-signed with HKDF-derived keys, strictly FIFO-ordered, and bound to capability tokens. An injected or reordered command breaks the chain cryptographically.

**Tamper-evident audit** — every tool call, decision, snapshot, and policy result is recorded into a verifiable hash chain. Anyone can independently verify integrity.

This enables forensics, compliance, and regulatory defensibility.

Think: "Flight recorder for AI agents."

### 5. Cadence (Temporal Awareness Layer)

Cadence models the timing gaps between user instructions to infer behavioural state:

- **FLOW** — active interaction
- **READING** — consuming output
- **DEEP_WORK** — extended focus
- **AWAY** — absent

It uses Exponential Moving Average (EMA), Expected Response Time (ERT), and Cognitive Load Offset.

Cadence serves two purposes:

**A) UX Attunement** — Agents stop interrupting. They batch intelligently. They behave asynchronously.

**B) Security Signal** — UNWIND uses Cadence state to detect anomalies: machine-speed tool calls while user is AWAY, bot-like timing variance, suspicious execution during READING state. Timing becomes a behavioural anomaly layer — without invasive telemetry.

### 6. CRIP (Consentful Rhythm Inference Protocol)

Every rhythm event carries explicit consent metadata:

- Where it can be processed
- How long it's retained
- Whether it's deletable

This prevents timing intelligence from becoming surveillance.

It ensures user auditability, explicit consent boundaries, and programmatic compliance validation.

## What Makes UNWIND Different

It combines:

1. Deterministic enforcement
2. Reversible execution
3. Dry-run simulation
4. Cryptographic audit with transport authentication
5. Behavioural timing anomaly detection
6. Consent-bound telemetry

In a single coherent architecture.

Most comparable projects provide one or two of these.
UNWIND integrates all six.

## Audience

### Primary

**Enterprise AI Teams** — deploying persistent agents that modify code, access internal systems, and execute automation. They need containment, rollback, audit, and compliance export.

**LLM Platform Vendors** — who want reduced enterprise sales friction, a governance story, and safety guarantees beyond model-level filtering. UNWIND becomes an agent control plane.

**Cybersecurity Vendors** — looking for AI-native anomaly detection, runtime containment for agent actions, and audit-grade telemetry.

### Secondary

- Agent framework builders (CrewAI, AutoGen, etc.)
- Regulated industries (finance, healthcare, legal)
- Infrastructure platforms integrating AI agents

## Why Now?

Persistent agents are moving from chat assistants to autonomous tool-using systems.

This introduces legal liability, operational risk, and governance gaps.

UNWIND addresses these gaps before major incidents force regulation.

It positions itself as: **Agent Governance Infrastructure.**

## Strategic Positioning

UNWIND is not a chatbot feature, a model wrapper, or a prompt guardrail.

It is a **runtime control plane for autonomous agents**.

- Cadence + CRIP define a timing-aware, consent-bound data contract.
- CRAFT defines cryptographically authenticated, tamper-evident audit.
- The enforcement kernel ensures deterministic containment.
- Ghost Mode provides risk-free previews before commitment.

Together: a full-stack trust architecture.

## Business Model

- **AGPL open core** (adoption + credibility)
- **Enterprise tier** (fleet management, compliance exports, hardened builds)
- **Cross-platform adapters**
- **Potential certification layer**

## In One Sentence

UNWIND makes autonomous AI agents reversible, auditable, and behaviourally accountable at runtime — not just prompt time.
