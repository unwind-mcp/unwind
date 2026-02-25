# UNWIND Marathon Session Summary
## 20–22 February 2026

> **Architecture Correction (23 Feb 2026):** The MCP stdio proxy integration model described below does not apply to OpenClaw (UNWIND's primary target). OpenClaw uses native plugin hooks, not MCP server launch chaining. The core engine is unaffected. See `SESSION-UPDATE-2026-02-23.md` for full details.

**Author:** David Russell + Claude (Cowork) + SENTINEL (GPT-5.3 Codex / OpenClaw)
**Duration:** ~60 hours across 8+ context compactions
**Test count:** 0 → 657
**SENTINEL cron jobs:** 0 → 6 standing + 5 overnight one-shots (completed)
**Three-way collaboration:** Claude (implementation), SENTINEL (architecture/security), David (direction/integration)

---

## What Is UNWIND?

UNWIND is a security and trust middleware for AI agents, implemented as an MCP (Model Context Protocol) proxy. It sits between the agent's intent and tool execution, inspecting every JSON-RPC message in real time. No LLM calls in the enforcement path — everything is deterministic, under 10ms.

The architecture is deliberately external: UNWIND cannot modify agent code or MCP server code. It sees only the wire protocol. This constraint drives every design decision.

---

## Session Timeline

### Phase 1: Research & Foundation

**OpenClaw homework.** David began by researching AI agent security, specifically the MCP ecosystem's lack of RBAC. Sources included Jason Haddix (Arcanum Security), Alex Finn, Matthew Berman, and others documenting prompt injection and tool-call exploitation risks.

**Gap analysis against Haddix taxonomy.** Mapped Haddix's 7-point AI agent attack methodology against what UNWIND needed to cover. Identified that UNWIND's sweet spot is Points 1 (inputs), 2 (ecosystem), and 7 (pivot) — the tool layer. Points 3–5 (model, prompts, data) are architecturally out of scope for a proxy.

### Phase 2: Core Enforcement Pipeline

Built the multi-stage enforcement pipeline from scratch:

| Stage | Module | What It Stops |
|-------|--------|---------------|
| Session kill | Dead switch | Compromised sessions terminated instantly |
| Canary honeypots | `canary.py` | Trap tools detect agent probing (`disable_security_audit`) |
| Self-protection | `self_protection.py` | Blocks access to `.unwind/` config |
| Path jail | `path_jail.py` | Prevents `../../etc/passwd` filesystem escapes |
| SSRF shield | `ssrf_shield.py` | 29 CIDR ranges blocked (metadata endpoints, private IPs, IPv6 tricks) |
| DLP-Lite | `dlp_lite.py` | Regex + entropy scanning catches API keys, JWTs, PEM blocks |
| Circuit breaker | (in pipeline) | 5 writes per 5 seconds prevents runaway storms |
| Taint tracking | (in session/pipeline) | Sensor→actuator chains flagged |
| Session scope | (in pipeline) | Tool allowlists per session |

**Manifest rewriting (RBAC).** The headline feature — UNWIND rewrites the MCP tool manifest so agents only see tools they're allowed to use. Not just blocking calls (which the agent can retry), but hiding tools entirely. This directly addresses Haddix's primary MCP critique. 49 tests.

### Phase 3: Session Isolation & Advanced Detection

**Session isolation (CVE-2026-25536 fix).** Each agent session gets its own trust state, taint tracking, and circuit breakers. Cross-session contamination is impossible. 36 tests.

**Exec tunnel detection.** Catches agents using shell-exec tools (`run_command`, `execute_code`) to construct virtual tool calls that bypass the pipeline. Detects command patterns like `curl localhost:port/mcp/tools/call` and synthetic tool invocations. 63 tests.

**DNS pinning.** Prevents DNS rebinding attacks where a hostname resolves to a public IP at check time but a private IP at call time. 19 tests.

**Response principal validation.** Verifies that responses come from the expected MCP server, not from a man-in-the-middle or confused deputy. 25 tests.

### Phase 4: SENTINEL Deployment

**SENTINEL** is an autonomous AI agent running on David's Raspberry Pi 5, powered by OpenClaw + GPT-5.3 Codex. It operates as UNWIND's security research and monitoring wing.

**Personality and mission.** SENTINEL has custom personality files making it a security-focused analyst. It monitors CVEs, MCP ecosystem changes, AI safety developments, and competitive intelligence.

**First intelligence cycle.** SENTINEL's initial CVE scan found real vulnerabilities relevant to MCP/agent security, proving the concept.

**Cron infrastructure built up to 6 standing jobs:**

| Job | Schedule | Purpose |
|-----|----------|---------|
| `sentinel:cve-monitor` | Every 6h | Scans for new CVEs affecting MCP/agent tooling |
| `sentinel:mcp-watch` | Every 6h | Monitors MCP ecosystem for spec changes, new servers |
| `sentinel:ai-safety-watch` | Every 6h | Tracks AI safety papers, advisories, policy changes |
| `sentinel:daily-brief` | Daily 08:30 | Compiles threat intelligence brief to file |
| `sentinel:compintel-watch` | Every 12h | Monitors SecureClaw, ClawSec, ClawShield competitors |
| `sentinel:config-integrity` | Daily 08:00 | Self-monitors its own config for drift (NO_DRIFT confirmed) |

**Delivery wiring.** Monitoring jobs run isolated with `--no-deliver` and `--best-effort`. The daily brief delivers to `~/.openclaw/workspace/sentinel-daily-briefs/`. Config integrity runs 30 minutes before the daily brief.

**First daily brief** contained real threat intelligence: CVE-2025-49113, CVE-2025-68461, BeyondTrust CVE-2026-1731, AI-assisted intrusion reports, and MCP ecosystem drift observations.

### Phase 5: SENTINEL-Designed Modules

SENTINEL shifted from monitoring to actively designing UNWIND's security architecture.

**Prompt injection assessment.** SENTINEL rated UNWIND at 6.5/10 for prompt injection defence. Recommended a two-lane model: hot path (<1ms deterministic transition policy + constant-time lexical scanner) and async path (deeper anomaly scoring feeding versioned rules back). Confirmed content detection belongs upstream of UNWIND, not in the proxy.

**Amber fatigue analysis.** Root cause: binary taint (on/off) meant ANY sensor call + ANY high-risk actuator = amber prompt. The "15 fs_write" scenario was the smoking gun — a single web search followed by 15 file writes would generate 15 amber prompts, all for legitimate work.

**SENTINEL's amber scoring schema.** Full JSON specification including:
- Scoring formula with exact weights
- Tier thresholds (amberLow ≥ 20, amberHigh ≥ 45, amberCritical ≥ 70)
- Approval window durations (AMBER_LOW: 300s, AMBER_HIGH: 120s, AMBER_CRITICAL: 0s)
- Rubber-Stamp Score (RSS) formula
- Autonomous manifest schema for cron sessions
- Risk budget with amber severity costs

### Phase 6: Building SENTINEL's Designs

**Graduated taint decay** (`taint_decay.py`, 51 tests)

Replaced binary `is_tainted` with 5 levels: NONE → LOW → MEDIUM → HIGH → CRITICAL.

- First taint event jumps to MEDIUM (skips LOW — LOW is for decaying sessions)
- CRITICAL requires 2+ distinct taint events
- Time decay: drops one level per 60 seconds since last taint
- Operation decay: drops one level per 10 clean operations
- Cooldown: 5 seconds prevents rapid sensor over-escalation
- Amber threshold: only HIGH and CRITICAL trigger amber prompts
- The "15 fs_write" scenario: search_web → MEDIUM (no amber), 10 writes → LOW. Zero amber prompts.

Integrated into `session.py` (replaced boolean fields with `TaintState`) and `pipeline.py` (stage 7 uses graduated check). 4 existing tests needed updating — all had assumed single sensor call triggers amber.

**Rubber-stamp detector** (`rubber_stamp.py`, 51 tests)

Implements SENTINEL's RSS formula exactly. Detects when human operators are clicking "approve" without reading — which is worse than no gate at all (false confidence).

RSS = clamp(0, 100, 30×I(latency<2s) + 15×I(latency<1s) + 20×I(streak≥12) + 15×I(ratio>0.98/50) + 20×I(pattern_changed) + 10×I(burst≥8/60s))

Action levels:
- NONE (0–34): Normal operation
- MEDIUM (35–54): Add context to approval dialogs
- HIGH (55–74): Insert 5-second hold before approval enabled
- VERY_HIGH (75+): Disable all approval windows for 10 minutes

Fixed a subtle bug: `record_decision()` was updating `last_approved_pattern` before `compute_rss()` could detect pattern changes. Added `pattern_changed_on_last_approve` flag.

**Supply-chain trust** (`supply_chain.py`, 56 tests)

JSON lockfile pins each MCP server/skill to: provider ID, name, version, SHA-256 digest, tool list, origin URL, `trusted_at` timestamp, optional Ed25519 signature.

Tool→provider reverse index is an O(1) dict lookup (HOT path requirement).

5-stage verification: provider lookup → blocklist → expiry → digest match → signature requirement.

6 trust verdicts: TRUSTED, UNTRUSTED, BLOCKED, QUARANTINED, EXPIRED, SIGNATURE_INVALID.

Quarantine workflow for unknown providers: hold for human review, release or block.

SENTINEL reviewed and flagged: R-SIG not complete until cryptographic signature verification is real (presence-check insufficient). Also identified attack vectors: TOCTOU on digest check, lockfile tampering, provider ID spoofing, replay/downgrade.

### Phase 7: SENTINEL Policy Spec

SENTINEL developed the UNWIND policy specification across versions:
- **v0:** Initial security requirements
- **v0.1:** Added session isolation, exec tunnel, DNS pinning
- **v0.2:** Added supply-chain trust (R-SIG, R-LOCK, R-TRUST), budget enforcement (R-BUD-001..009), response validation

**Budget enforcer spec** completed by SENTINEL (commit 36c8745) covering session-level resource budgets.

### Phase 8: Overnight SENTINEL + Day 3 Hardening (22 Feb 2026)

**SENTINEL overnight jobs completed (all 5).** Results reviewed from Pi output files:

1. **Supply-chain code review** — BLOCKED. SENTINEL couldn't find `supply_chain.py` (looked in `~/.openclaw/workspace/` instead of the repo). Blocker-handling clause worked correctly — structured output with explicit failure reason.
2. **Pipeline wiring spec** — Full concrete spec for wiring all 3 modules. Exact stage placement, method signatures, error handling.
3. **OWASP ASI Top 10 traceability** — 2 FULL (ASI02 Tool Misuse, ASI03 Identity/Privilege), 8 PARTIAL, 0 NONE. Biggest gaps: ASI04 (crypto supply-chain), ASI05 (runtime sandbox), ASI01/06/10 (evaluation suites).
4. **Approval windows spec** — Full design with RiskBand enum, TTL model (300s/120s/0s), context_hash binding, ApprovalWindowRepository/Service interfaces, edge cases, concurrency.
5. **Overnight report** — NO_DRIFT on config integrity, prioritised action list, threat intel brief.

**Supply-chain hardening (9 findings, 5 quick fixes):**

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | TOCTOU on digest — check-time vs use-time gap | P0 | Noted — needs compute-at-execution |
| 2 | Lockfile tampering — no integrity protection | P0 | Noted — needs HMAC/signing |
| 3 | Duplicate tool claims — provider spoofing | P1 | FIXED — first-writer-wins + warning log |
| 4 | Version downgrade attacks | P1 | FIXED — raises ValueError unless allow_downgrade=True |
| 5 | Empty digest bypass | P1 | FIXED — rejects when live digest provided but no stored digest |
| 6 | Signature presence-only check | P0 | Noted — needs real Ed25519/ECDSA |
| 7 | Index rebuild not atomic | P2 | FIXED — build new dict then swap |
| 8 | Thread safety on shared state | P2 | Noted — needs locking |
| 9 | Blocklist is list not set | P2 | FIXED — converted to set for O(1) lookup |

**Pipeline wiring — all three modules integrated:**

- **Supply-chain verifier → Stage 0b** (pre-RBAC, pre-dispatch). BLOCKED→BLOCK, QUARANTINED→AMBER, UNTRUSTED/EXPIRED/SIGNATURE_INVALID→BLOCK.
- **Rubber-stamp detector → Approval callback** via `process_approval()`. Checks lockout, records decision, computes RSS, applies actions. VERY_HIGH triggers lockout, HIGH injects hold time.
- **Response principal validator → Transport layer** via `register_request()` and `validate_response()`. Budget enforcement kills session on exceed.

New pipeline docstring documents full stage ordering: 0a (session kill) through 9 (circuit breaker) + approval callback + transport layer.

**SENTINEL collaboration protocol established.** Three-way working model formalised:
- SENTINEL uses 5-point update format: Objective, Change, Evidence, Files, Risks
- Claude responds with agree/modify/reject + rationale
- David retains final approval authority

**Morning brief threat intel reviewed:**
- CVE-2025-49113 (Roundcube RCE) — Not applicable, no self-hosted webmail
- CVE-2025-68461 (Roundcube XSS) — Not applicable
- CVE-2026-1731 (BeyondTrust RS/PRA, ransomware-linked) — Not applicable, enterprise software
- Containment SLA tightening recommendation — Relevant, factored into approval windows design

**Open-core discussion.** Recommended open-core model: enforcement pipeline open source (security tools need transparency/trust), SENTINEL integration + operational tooling + enterprise features proprietary. Don't open source prematurely.

**Tests: 631 → 657 (+26)**

---

## Full Module Inventory

### Enforcement Modules (13 files)

```
unwind/enforcement/
├── __init__.py
├── canary.py          — Honeypot trap tools
├── dlp_lite.py        — Data loss prevention (outbound)
├── exec_tunnel.py     — Shell-exec virtual tool detection
├── manifest_filter.py — RBAC manifest rewriting
├── path_jail.py       — Filesystem confinement
├── pipeline.py        — 9-stage enforcement orchestrator
├── response_validator.py — Response principal validation
├── rubber_stamp.py    — Rubber-stamp detection (RSS)
├── self_protection.py — Config tamper prevention
├── ssrf_shield.py     — Network access control
├── supply_chain.py    — Lockfile + digest + trust verification
└── taint_decay.py     — Graduated 5-level taint tracking
```

### Test Suite (18 files, 631 tests)

```
tests/
├── test_dns_pinning.py         — 19 tests
├── test_enforcement.py         — Core pipeline tests
├── test_exec_tunnel.py         — 63 tests
├── test_ghostmode.py           — Dry-run simulation tests
├── test_manifest_filter.py     — 49 tests (RBAC)
├── test_phase2.py              — Phase 2 features
├── test_phase3.py              — Phase 3 features
├── test_phase4.py              — Phase 4 features
├── test_proxy.py               — End-to-end proxy tests
├── test_response_validator.py  — 25 tests
├── test_rollback.py            — Rollback/recovery tests
├── test_rubber_stamp.py        — 51 tests (RSS)
├── test_sentinel.py            — SENTINEL integration
├── test_session_isolation.py   — 36 tests (CVE fix)
├── test_supply_chain.py        — 56 tests
├── test_taint_decay.py         — 51 tests
└── test_transport.py           — Transport layer tests
```

### Test Count Evolution

```
Start of marathon ........... 0
After core pipeline ......... ~150 (estimated)
After manifest rewriting .... ~200 (estimated)
After session isolation ..... ~236
After exec tunnels .......... ~299
After DNS pinning ........... ~318
After response validation ... ~343
[Multiple compactions — intermediate counts approximate]
Session 3 start ............. 473
After taint decay ........... 524  (+51)
After rubber-stamp .......... 575  (+51)
After supply-chain .......... 631  (+56)
After hardening + wiring .... 657  (+26)  ← 7 hardening + 19 pipeline integration
```

---

## Key Design Decisions

**No LLM in the enforcement path.** Every check is deterministic, constant-time where possible. This means UNWIND can't reason about intent — but it's predictable, auditable, and fast (<10ms total pipeline).

**External proxy, not an SDK.** UNWIND doesn't require modifying agent or MCP server code. Deploys as a drop-in proxy. This limits what it can see (no access to agent memory, prompts, or internal state) but makes adoption trivial.

**SENTINEL as active architect.** SENTINEL evolved from a monitoring tool to an active participant in UNWIND's design. The amber scoring schema, RSS formula, two-lane prompt injection model, and supply-chain review were all SENTINEL's work — reviewed and implemented by Claude.

**Graduated taint over binary.** The single biggest quality-of-life improvement. Binary taint created a flood of false-positive amber prompts. Graduated decay with time and operation cooling means legitimate workflows (search → many writes) pass silently while genuine taint chains (multiple sensors → high-risk actuator) still trigger.

---

## SENTINEL Infrastructure (as of session end)

**Platform:** Raspberry Pi 5, OpenClaw v2026.2.21-2, gateway port 18789
**Model:** openai-codex/gpt-5.3-codex, think high (think low for heartbeat)
**Token usage:** ~67k/272k (25%)
**Git identity:** David Russell, david@brugai.com

**Standing cron jobs (6):** All green, all confirmed operational.

**Overnight one-shots (5, tagged sentinel:overnight-*):**
1. `overnight-supply-chain-review` — Line-by-line code review of supply_chain.py
2. `overnight-pipeline-wiring` — Wiring spec for 3 new modules into pipeline
3. `overnight-owasp-traceability` — OWASP ASI Top 10 mapping to UNWIND
4. `overnight-approval-windows` — Approval windows design spec
5. `overnight-summary-brief` — Morning report compiling all outputs

All configured: isolated, no-deliver, best-effort, deleteAfterRun.

**Pi commits this session:**
- `36c8745` — Budget enforcer spec
- `b7e6cb0` — Config baseline + integrity cron

---

## Pending Work (Priority Order)

### P0 — Real Signature Verification
- supply_chain.py currently checks signature presence only
- SENTINEL flagged: R-SIG not complete without Ed25519/ECDSA cryptographic verification
- Attack vectors: TOCTOU on digest, lockfile tampering, provider spoofing, replay/downgrade
- Lockfile itself needs HMAC or signing to prevent tampering

### P0 — Approval Windows Module (READY TO BUILD)
- SENTINEL overnight spec provides full design: RiskBand enum, TTL model, context_hash binding
- Python API signatures ready: ApprovalWindowRepository, ApprovalWindowService
- Edge cases and concurrency handling specified
- Factor in SENTINEL's containment SLA tightening recommendation

### P1 — OWASP ASI Top 10 Gap Closure
- Traceability matrix complete (2 FULL, 8 PARTIAL, 0 NONE)
- Priority gaps: ASI04 (crypto supply-chain — ties to P0 signature work), ASI05 (runtime sandbox), ASI01/06/10 (evaluation suites)

### P1 — SENTINEL File Path Fix
- Tell SENTINEL the correct path for supply_chain.py: `unwind/enforcement/supply_chain.py` in the repo
- So it can complete its code review (was blocked overnight)

### P1 — SENTINEL Collaboration Update
- Send SENTINEL a 5-point format update on completed pipeline wiring and hardening work
- Include test count, files modified, remaining P0s

### P2 — Taint Nonce Propagation
- SENTINEL's tripwire idea for injection replay detection
- Needs design spec

### P2 — SecureClaw Audit Mode
- Install on Pi alongside UNWIND
- SENTINEL recommended phased rollout

### COMPLETED (previously pending)
- ~~Wire Into Pipeline~~ — All three modules integrated (stage 0b, approval callback, transport layer)
- ~~Supply-chain hardening~~ — 5 of 9 findings fixed, remaining 4 tracked as P0/P2

---

## Competitive Landscape

Monitored via `sentinel:compintel-watch`:
- **SecureClaw** — Competitor in MCP security space
- **ClawSec** — Alternative approach
- **ClawShield** — Another entrant

UNWIND's differentiators: manifest rewriting (proper RBAC), deterministic enforcement (no LLM), graduated taint decay, SENTINEL as autonomous security analyst.

---

## Errors & Fixes Log

| # | Error | Root Cause | Fix |
|---|-------|-----------|-----|
| 1 | test_taint_chain: ALLOW != AMBER | Single sensor → MEDIUM (below amber threshold) | Added second sensor call with cooldown gap → HIGH |
| 2 | test_taint_decay: setter on read-only property | `tainted_at` became @property | Use `taint_state.last_taint_event` directly |
| 3 | test_taint_chain_produces_amber | Same as #1 | Same fix |
| 4 | test_tainted_session_amber | Same as #1 | Same fix |
| 5 | 13 rubber-stamp tests failed | Burst indicator fires in sub-ms tests | Adjusted all test expectations for +10 burst points |
| 6 | Pattern change not detected | `record_decision` updated pattern before RSS check | Added `pattern_changed_on_last_approve` flag |
| 7 | test_careful_operator: RSS=50 not NONE | Rotating patterns triggered pattern_change | Used single "same_pattern" for all approvals |
| 8 | SENTINEL cron 3/5 failing | "cron delivery target is missing" | `--no-deliver`, `--best-effort`, then full delivery wiring split |
| 9 | Blocklist tests failed after set conversion | `.count()` and `.remove()` are list methods, not set | Changed fixture to `{"mcp-malicious"}`, used `in` and `discard()` |
| 10 | Pipeline tests: path jail BLOCK | Hardcoded `/workspace/test.txt` outside temp workspace | Used `config.workspace_root / "test.txt"` |
| 11 | `compute_rss()` signature mismatch | Missing `latest_latency` and `latest_pattern_hash` params | Passed `latency_seconds` and `pattern_hash` to both calls |
| 12 | `apply_rss_actions` wrong return key | Returns `'actions'` not `'indicators'` | Fixed references in pipeline code |
| 13 | `RSSLevel` not imported in test | Missing import in test method | Added `from unwind.enforcement.rubber_stamp import RSSLevel` |

---

## Technical Stack

- **Language:** Python 3
- **Testing:** pytest (657 tests, ~5.6 seconds)
- **SENTINEL:** OpenClaw + GPT-5.3 Codex on Raspberry Pi 5
- **Architecture:** MCP JSON-RPC proxy, no LLM in enforcement path
- **Key algorithms:** SHA-256 digest pinning, constant-time taint lookup, RSS behavioural scoring
- **Key data structures:** Tool→provider reverse index (dict), taint state machine (5-level IntEnum), approval decision ring buffer

---

## Session Handoff Notes (for new session)

**To rebuild context in a new session, read these files in order:**
1. This file — `SESSION-SUMMARY-2026-02-22.md`
2. `unwind/enforcement/pipeline.py` — Full stage ordering, all module integrations
3. `unwind/enforcement/supply_chain.py` — Latest hardened version
4. `tests/test_enforcement.py` — Pipeline integration tests (latest patterns)

**SENTINEL handoff:** Send SENTINEL a 5-point format update covering the pipeline wiring and hardening work. Include the correct file path for `supply_chain.py` so it can complete its blocked code review.

**Key context that compaction might lose:**
- The "go ahead" pattern — David explicitly pauses/resumes coding work, don't start building until told
- SENTINEL collaboration protocol — 5-point format (Objective, Change, Evidence, Files, Risks)
- Morning brief threat intel — Roundcube/BeyondTrust not applicable, containment SLAs are relevant
- Open-core discussion — enforcement pipeline open source, SENTINEL/operational tooling proprietary
- Heartbeat mode bug — SENTINEL shows "heartbeat" label on live prompts, known UI bug in OpenClaw

---

*Session covered 8+ compactions across ~60 hours. 657 tests. From zero to a complete security middleware with autonomous threat intelligence and three-way AI collaboration. Approval windows module is next.*
