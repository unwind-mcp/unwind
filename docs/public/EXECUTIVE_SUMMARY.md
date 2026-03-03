# UNWIND — One-Page Executive Summary

## What UNWIND Is

UNWIND is a runtime governance layer for persistent AI agents.
It sits between agent orchestration (LLM + planner) and tool execution (filesystem, shell, network, SaaS APIs). Unlike prompt-only guardrails, UNWIND enforces safety where the side effects happen.

## The Problem It Solves

As agents become persistent and tool-enabled, organisations face four predictable problems:

- **Unbounded action:** agents can execute commands and tools faster than humans can supervise.
- **Intent drift:** the system can deviate from the user's stated goal or scope.
- **Irreversible side effects:** a bad tool call can change code, data, or systems permanently.
- **Non-defensible audit:** after an incident, logs are incomplete, mutable, or non-verifiable.

Enterprises don't just need "better answers." They need governable execution.

## What Makes UNWIND Different

UNWIND combines six primitives into one coherent stack:

### Deterministic Enforcement Pipeline (UNWIND Core)

Every tool call is evaluated by a 15-stage pipeline of explicit, inspectable rules.
Outcomes are stable and reviewable (allow / block / amber).
Each session carries a trust state (green / amber / red) reflecting real-time security posture.
Critical decisions are never delegated to an LLM in the hot path.

### Reversibility via Smart Snapshots (Rollback Engine)

Risky actions can be executed as transactions.
Snapshot, execute, commit or rollback.
Reduces fear of letting agents act.

### Ghost Mode (Dry-Run Sandbox)

Any session can be switched to Ghost Mode: the agent keeps operating, but all state-modifying actions are intercepted and simulated. Nothing real changes.
The operator reviews what would have happened, then approves or discards.
This turns agent deployment from a leap of faith into a preview.

### CRAFT (Cryptographic Command Chain + Audit Log)

Every command is HMAC-signed with derived keys and strictly ordered — an injected or reordered command breaks the chain cryptographically.
Tool calls, decisions, snapshots, and outcomes are recorded into a tamper-evident hash chain.
Enables independent verification and strong forensic posture.

### Cadence (Temporal Awareness)

Infers user state from timing gaps between interactions: FLOW / READING / DEEP_WORK / AWAY.
Improves agent etiquette (batching, non-interruptive behaviour).
Provides timing-only anomaly signals to UNWIND (e.g., activity patterns inconsistent with a human).

### CRIP (Consentful Rhythm Inference Protocol)

Cadence's timing data is bound to explicit consent and retention metadata.
Keeps rhythm intelligence from sliding into surveillance.
Supports auditability and deletion semantics.

## Who It's For

**Primary:**

- Enterprise AI/platform teams deploying tool-using agents across internal systems.
- LLM/agent platform vendors who need a governance story for enterprise adoption.
- Security vendors/teams who need AI-native containment, audit, and anomaly signals.

**Secondary:**

- Agent framework builders and integrators (adapters/proxies).
- Regulated sectors (finance, legal, healthcare) where audit and reversibility matter.

## Why Now

Persistent agent adoption is accelerating, and the first major failures will be about execution governance, not just model hallucination. Organisations are already converging on the need for containment, rollback, audit, and non-invasive anomaly detection.

## Business Shape

- **Open core** to drive adoption and credibility (and to block closed SaaS clones depending on licence choice).
- **Commercial tier** for enterprise requirements: fleet management, compliance exports, hardened builds, support, certification.

## In One Sentence

UNWIND makes autonomous agents safe to run in the real world by enforcing deterministic control, enabling rollback and dry-run preview, and producing cryptographically verifiable audit — augmented by consent-bound timing awareness.
