# UNWIND Security Framework Mapping

Last updated: 2026-02-24
Pipeline version: 14 stages, 1166 tests

This document maps UNWIND's enforcement pipeline against three industry-standard
security frameworks. UNWIND targets automated mass attacks against AI agents —
not state-level adversaries. Coverage is assessed against that threat model.

---

## OWASP Top 10 for Agentic Applications (2026)

The most directly relevant framework. Published December 2025, it covers
autonomous agents with tools, memory, and planning — exactly UNWIND's domain.

| ID | Risk | UNWIND Coverage | Pipeline Stage(s) | Status |
|----|------|----------------|-------------------|--------|
| ASI01 | Agent Goal Hijack | Canary tripwires detect compromised agents; taint tracking flags behavioural shifts after external input | Stage 1 (canary), Stage 7 (taint) | Partial — by design, we detect effects not prompts |
| ASI02 | Tool Misuse & Exploitation | Core strength. Path jail, SSRF shield, egress policy, credential exposure, DLP, circuit breaker, session scope | Stages 2c, 3, 4, 4b, 5, 6, 8 | Strong |
| ASI03 | Identity & Privilege Abuse | Credential scanning catches tokens in params; supply chain verifies provider trust; session-principal binding prevents cross-session attacks | Stages 0b, 2c, response_validator | Good |
| ASI04 | Supply Chain Vulnerabilities | Three-leg verification: HMAC lockfile integrity, Ed25519 signatures, digest-at-execution | Stage 0b | Strong |
| ASI05 | Unexpected Code Execution | Exec tunnel detector catches shell commands hiding tool calls; self-protection blocks UNWIND file modification | Stages 2, 2b | Good |
| ASI06 | Memory & Context Poisoning | Not covered — outside scope as middleware | — | Out of scope |
| ASI07 | Insecure Inter-Agent Communication | Response principal validation prevents cross-session response injection | response_validator | Partial |
| ASI08 | Cascading Failures | Circuit breaker rate-limits state modifications; fail-closed contract prevents cascade on UNWIND failure | Stage 6, sidecar contract | Partial |
| ASI09 | Human-Agent Trust Exploitation | Rubber-stamp detection (RSS scoring) with mandatory hold times, lockouts, burst tracking | approval_windows, rubber_stamp | Strong — rare capability |
| ASI10 | Rogue Agents | Ghost Mode previews agent actions; taint tracking flags behavioural shifts; session kill switch | Stages 7, 9, session.kill() | Good |

**Summary: 8 of 10 risks covered. 2 out of scope (memory poisoning, deep prompt scanning).**

---

## OWASP Top 10 for LLM Applications (2025)

Covers LLM-specific risks. UNWIND operates at the middleware/action layer,
not the model layer, so coverage is partial by design.

| ID | Risk | UNWIND Coverage | Pipeline Stage(s) | Status |
|----|------|----------------|-------------------|--------|
| LLM01 | Prompt Injection | Canary tripwires and taint tracking detect the effects of successful injection (agent behaviour change) | Stages 1, 7 | Partial — by design |
| LLM02 | Sensitive Information Disclosure | Credential exposure catches secrets in tool params; DLP-lite catches secrets in egress payloads | Stages 2c, 5 | Strong |
| LLM03 | Supply Chain Vulnerabilities | Three-leg supply chain verification; directly relevant to ClawHavoc-type attacks (800+ malicious skills) | Stage 0b | Strong |
| LLM04 | Data Poisoning | Not covered — targets training data, not runtime | — | Out of scope |
| LLM05 | Improper Output Handling | Not covered — downstream application responsibility | — | Out of scope |
| LLM06 | Excessive Agency | Core purpose of UNWIND. Session scope, circuit breaker, taint tracking, Ghost Mode | Stages 6, 7, 8, 9 | Strong |
| LLM07 | System Prompt Leakage | DLP entropy scanner may catch prompt content in egress; no specific prompt detection | Stage 5 | Minimal |
| LLM08 | Vector/Embedding Weaknesses | Not covered — RAG-specific, UNWIND doesn't interact with vector stores | — | Out of scope |
| LLM09 | Misinformation | Not covered — content quality, not security | — | Out of scope |
| LLM10 | Unbounded Consumption | Circuit breaker rate-limits tool calls; session budgets cap total calls; MAX_SCAN_ITEMS prevents scanner DoS | Stage 6, response_validator | Good |

**Summary: 5 of 10 risks covered at middleware level. 4 out of scope (training, output handling, RAG, content quality). 1 minimal (prompt leakage).**

---

## CWE Top 25 Most Dangerous Software Weaknesses (2025)

General software vulnerability list. Filtered for items relevant to UNWIND's
threat model (Python middleware for AI agents, no web frontend, no database).

| Rank | CWE | Weakness | Relevant? | UNWIND Coverage | Notes |
|------|-----|----------|-----------|----------------|-------|
| 1 | CWE-79 | Cross-Site Scripting | No | — | No web frontend |
| 2 | CWE-89 | SQL Injection | No | — | No database |
| 3 | CWE-352 | CSRF | No | — | No web frontend |
| 4 | CWE-862 | Missing Authorization | Partial | Session scope (stage 8) limits tool access per session | Relevant to session design |
| 5 | CWE-787 | Out-of-bounds Write | No | — | Python memory-safe |
| 6 | CWE-22 | Path Traversal | **Yes** | Path jail (stage 3) canonicalises and blocks traversal | **Strong** |
| 7 | CWE-416 | Use After Free | No | — | Python memory-safe |
| 8 | CWE-125 | Out-of-bounds Read | No | — | Python memory-safe |
| 9 | CWE-78 | OS Command Injection | **Yes** | Exec tunnel detector (stage 2b) catches tunnelled commands | **Good** |
| 10 | CWE-94 | Code Injection | Partial | Exec tunnel catches some patterns; full sandboxing is agent runtime responsibility | Partial |
| 11 | CWE-120 | Buffer Overflow | No | — | Python memory-safe |
| 12 | CWE-476 | NULL Pointer Deref | No | — | Python handles None differently |
| 13 | CWE-434 | Unrestricted File Upload | Partial | Self-protection blocks writes to UNWIND config paths | Relevant to agent file ops |
| 14 | CWE-121 | Stack Buffer Overflow | No | — | Python memory-safe |
| 15 | CWE-306 | Missing Auth for Critical Function | **Yes** | Sidecar has bearer auth; dev mode disables it (documented risk) | **Good — minor gap in dev mode** |
| 16 | CWE-122 | Heap Buffer Overflow | No | — | Python memory-safe |
| 17 | CWE-502 | Deserialization of Untrusted Data | **Yes** | policy_source.py loads JSON config; immutable hash check mitigates tampering | **Good** |
| 18 | CWE-863 | Incorrect Authorization | Partial | Session-principal binding prevents cross-session access | Relevant |
| 19 | CWE-284 | Improper Access Control | Partial | Supply chain trust gate, session scope | Relevant |
| 20 | CWE-918 | SSRF | **Yes** | SSRF shield (stage 4) + egress policy (stage 4b) — dual-layer protection | **Strong** |
| 21 | CWE-200 | Sensitive Info Exposure | **Yes** | Credential exposure (stage 2c) + DLP-lite (stage 5) | **Strong** |
| 22 | CWE-77 | Command Injection | **Yes** | Exec tunnel detector (stage 2b) — overlaps with CWE-78 | **Good** |
| 23 | CWE-770 | Resource Allocation Without Limits | **Yes** | Circuit breaker (stage 6), session budgets, MAX_SCAN_ITEMS cap on parameter scanning | **Strong (fixed 2026-02-24)** |
| 24 | CWE-639 | Auth Bypass via User-Controlled Key | Partial | Session keys are adapter-provided; sidecar validates but doesn't generate | Relevant |
| 25 | CWE-611 | XML External Entity | No | — | No XML parsing |

**Summary: 8 of 25 directly relevant. 7 covered with strong/good rating. 1 minor gap (CWE-306 dev-mode auth). 13 not applicable (Python memory safety, no web frontend, no database).**

---

## Security Self-Defence (UNWIND's own attack surface)

Added 2026-02-24 after identifying that automated scanners can attack the
security code itself. 50 dedicated tests covering:

| Attack Class | Tests | Vulnerabilities Found | Status |
|-------------|-------|----------------------|--------|
| ReDoS (regex denial of service) | 11 | 0 — all patterns resist backtracking | Clean |
| Malformed JSON fuzzing | 12 | 3 — non-dict JSON types bypassed validation | Fixed |
| URL parser confusion | 16 | 1 — trailing-dot DNS bypass | Fixed |
| Input size bombs | 3 | 0 — all complete within time limits | Clean |
| Parameter depth/width bombs | 3 | 1 — combinatorial explosion caused OOM | Fixed |
| Unicode/encoding tricks | 5 | 0 — no crashes (detection limitations documented) | Clean |

**5 vulnerabilities found and fixed in one session. All discoverable by automated tools.**

---

## Standing Tasks for SENTINEL

1. Re-map against OWASP Agentic Top 10 whenever it updates
2. Re-map against CWE Top 25 annually (December)
3. Re-map against OWASP LLM Top 10 annually
4. Run self-defence test suite on every code change to credential/DLP/egress patterns
5. Check OWASP ASVS V2 (validation) and V5 (configuration) chapters quarterly

---

## How to Read This Document

- **Strong** = dedicated pipeline stage with targeted tests
- **Good** = covered but could benefit from additional test cases
- **Partial** = addressed as side-effect of another control, or deliberate scope boundary
- **Out of scope** = not UNWIND's responsibility (model layer, training data, downstream app)
- **Minimal** = acknowledged gap, low priority for mass-attack threat model
