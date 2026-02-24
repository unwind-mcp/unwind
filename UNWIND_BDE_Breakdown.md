# UNWIND — BDE Breakdown

## Brug Discovery Engine Reference for the UNWIND Project
## Compiled: 19 February 2026

---

## Purpose

This document provides UNWIND project sessions with full context on the BDE moonshot runs that directly inform the architecture. It exists because Cowork projects cannot search conversations outside their own scope. Everything relevant from the broader BDE corpus is condensed here.

---

## Corpus Status (as of early February 2026)

- **Total runs:** 151+
- **Total moonshots:** 885+
- **Models used:** Claude Opus 4.5, ChatGPT 5.2 Pro, ChatGPT Pro, Gemini 3, Gemini 3 Pro, Grok 4.1 Thinking, GLM 4.7 Flash (30B local)
- **Schema:** JSON with patent_filed, run_summary, military_gov_adoption fields

---

## Directly Relevant BDE Runs

### Run EU — Claude Opus 4.5 (February 2026)
**Thematic lens:** OpenClaw/Moltbook agent security — verifying agents have not acquired malicious seeds or instruction injections when returning from external operations ("return contamination" problem)

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Behavioral Merkle Trees for Agent State Verification** — Hierarchical cryptographic commitment of agent decision states. Borrows Merkle tree efficiency from blockchain (log(n) verification) applied to agent decision traces. | Moonshot | Layer 5 (CR-AFT Chain) |
| 2 | **Differential Behavioral Fingerprinting** — Pre/post-flight behavioral comparison detecting goal drift. Captures baseline before external operation, compares after return. | Disruptive | Layer 6 (Return Verification) |
| 3 | **Quarantine Sandbox with Semantic Diff** — TEE-based "immigration control" for returning agents. Isolated evaluation environment before re-granting permissions. | Disruptive | Layer 6 (Return Verification) |
| 4 | **Instruction Canaries** — Organisational tripwire protocol using planted instructions to detect if agent reasoning has been compromised. | No-Tech | Layer 6 (Return Verification) |
| 5 | **ZKML-Attested Reasoning Proofs** — Zero-knowledge verification of reasoning integrity. | Deep Research | Future / Patent candidate |
| 6 | **Agent Behavioral Consensus Networks** — Byzantine fault tolerance via multi-agent redundancy. 3+ agents, flag divergence as manipulation signal. | Disruptive | Future |

**Missing Bridge:** ASML (Agent State Markup Language) — standardised serialisation format for agent state. Without this, cross-framework verification is impractical.

**Key insight from this run:** Prompt injection remains fundamentally unsolved (OpenAI December 2025, Anthropic January 2026). The moonshots pivot from "preventing contamination during execution" to "detecting contamination upon return" — a distinct problem requiring novel approaches. This is UNWIND Layer 6's thesis.

---

### Run EN — ChatGPT Pro (February 2026)
**Thematic lens:** AI agent security — protecting OpenClaw agents returning from Moltbook

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Measured Return: Remote Attestation for Agent State** — Cryptographic attestation when agent "returns to base." Runtime produces proof of state integrity: memory unchanged, config intact, no unapproved skill mutations. "Return gate" diffs against baseline. | Disruptive | Layer 5 (CR-AFT Chain) |
| 2 | **CBOM (Cognitive Bill of Materials) for Agents** — Structured manifest of agent's reasoning components, analogous to SBOM for software supply chains. | Disruptive | Layer 1 (Event Schema) |
| 3 | **Stateless Agent Sandboxing** — Disposable agent instances that start clean for each external operation. No persistent state to contaminate. | Disruptive | Layer 6 concept |
| 4 | **Behavioral Contract Enforcement** — Formal specification of permitted agent behaviors, machine-verifiable at runtime. | Moonshot | Layer 3 (Trust Panel rules) |
| 5 | **Agent Provenance Chains** — Full lineage tracking from prompt to action, cryptographically signed. | Disruptive | Layer 5 (CR-AFT Chain) |
| 6 | **ZK Return Receipts** — Zero-knowledge proofs that agent operated within approved scope without revealing full execution trace. Highest barrier moonshot (7/8/9). | Deep Research | Future / Patent candidate |

**Missing Bridge:** IDBM (Instruction-Data Boundary Markup) — formal separation of instructions from data in agent contexts to prevent injection.

**Key analogy from this run:** "The macro era at internet scale" — Moltbook's "fetch and follow instructions" pattern mirrors the Office macro attack vector but with frontier model capabilities.

---

### Run EM — Gemini 3 (February 2026)
**Thematic lens:** AI agent security (defense) — Moltbook/OpenClaw

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Epistemic Airlock** — Staged re-entry protocol for agents returning from external operations. Incremental permission restoration based on verification checkpoints. | Disruptive | Layer 6 (Return Verification) |
| 2 | **Soul-Hashing** — Cryptographic fingerprint of agent's core behavioral identity. Detects subtle modifications to personality/goal structures. | Moonshot | Layer 5 / Layer 6 |
| 3 | **Behavioral Immune System** — Pattern matching against known manipulation techniques, analogous to biological immune response. | Disruptive | Layer 3 (Trust Panel pattern detection) |
| 4 | **Agent Quarantine Protocol** — 48-hour isolation period with controlled test interactions before returning agent to production. | No-Tech | Layer 6 concept |
| 5 | **Memetic Firewall** — Content filtering specifically designed for agent-to-agent communication channels. | Disruptive | Future |
| 6 | **Consensus Triangulation** — Multiple independent agents evaluate the same situation; divergence flags manipulation. | Disruptive | Future |

**Cross-model convergence with EN:** Snow Crash memetic virus framing, quarantine/airlock metaphors, cryptographic execution proofs, stateless/disposable architectures. Historical anchors shared: TPM attestation, Bell-LaPadula MAC, SBOM, GMP, antivirus signatures, proof-carrying code.

---

### Run EO — ChatGPT 5.2 Pro (February 2026)
**Thematic lens:** How users can best monitor and utilise the growing multitude of OpenClaw skills

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Skill Observability Cockpit** — Real-time dashboard showing what skills are doing, resource consumption, and behavioral patterns. | Disruptive | Layer 3 (Trust Panel) — direct ancestor |
| 2 | **SkillLockfile + Cryptographic Signing** — Package-lock equivalent for agent skills with integrity verification. | Disruptive | Layer 5 (skill integrity checking) |
| 3 | **Skill CI Arena** — Automated testing environment that evaluates skills against security and performance benchmarks before deployment. | Moonshot | Future |
| 4 | **Skill Graph Navigator** — Visual dependency and interaction map showing how skills relate and affect each other. | Disruptive | Layer 3 enhancement |
| 5 | **Capability Budgets** — Resource allocation limits per skill (tokens, API calls, file access) with enforcement. | Disruptive | Layer 3 (permission scope scoring) |
| 6 | **Skill Insurance Market** — Risk-rated marketplace where skill developers stake reputation on security. | Moonshot | Future / speculative |

**Missing Bridge:** SCC + STC (Skill Capability Contract + Skill Telemetry Contract) — formalised interface between skill declarations and runtime monitoring.

**Relevance to UNWIND:** The Skill Observability Cockpit is essentially Layer 3 (Trust Panel) conceived independently through a different lens. Capability Budgets map directly to UNWIND's permission scope scoring.

---

### Run EP — Gemini 3 (February 2026)
**Thematic lens:** Same prompt as EO but interpreted through physical embodiment

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Cross-Embodiment Compiler** — Universal skill translation across physical platforms | — | Not directly relevant |
| 2 | **Staked-Skill Protocol** — Crypto-economic skin-in-the-game for skill developers | Moonshot | Future (trust market) |
| 3 | **Haptic Codecs (.HAPT format)** — Standardised physical interaction data | — | Not directly relevant |
| 4 | **DNA-Based Deep Time Logs** — Biological storage for ultra-long-term audit trails | Deep Research | Conceptual only |
| 5 | **Phytomining Agent Swarms** — Distributed biological resource extraction | — | Not relevant |
| 6 | **Neuro-Symbolic Concept Trading** — Cross-domain knowledge marketplace | Moonshot | Not directly relevant |

**Cross-model divergence note:** EO and EP received the same prompt but ChatGPT interpreted "skills" as software plugins while Gemini interpreted them as physical capabilities. Both valid. Demonstrates why multi-model runs surface different white space.

---

### Run ES — Grok 4.1 Thinking (February 2026)
**Thematic lens:** OpenClaw ecosystem governance and community security

| # | Moonshot | Funnel | UNWIND Layer |
|---|---------|--------|--------------|
| 1 | **Unified Skill Registry with Verification Pipelines** — Canonical verified registry, analogous to npm/apt with signing and automated security scanning. | Disruptive | Future (skill verification) |
| 2 | **Community Governance Framework** — Decentralised trust model for skill curation and incident response. | Disruptive | Not directly relevant |
| 3 | **Skill Reputation Scoring** — Historical track record scoring for skill developers and individual skills. | Disruptive | Layer 3 (trust inputs) |
| 4 | **Agent Behavioural Baselines** — Statistical models of "normal" agent behavior for anomaly detection. | Disruptive | Layer 3 (pattern normality scoring) |
| 5 | **Incident Response Protocol** — Standardised procedures for responding to compromised skills or agents. | No-Tech | UNWIND alert/response flow |
| 6 | **Cross-Platform Interoperability Standard** — Universal agent capability description format. | Moonshot | Layer 1 (event schema standardisation) |

**Missing Bridge:** Standardized Skill Metadata Schema — the fifth independent identification of the same gap.

---

### Run 134 — Agent Integrity Verification (February 2026)
**Context:** Dedicated BDE run on the "return contamination" problem

**Six moonshots identified:**

| # | Moonshot | Funnel Score |
|---|---------|-------------|
| 1 | Behavioral Merkle Trees | Moonshot |
| 2 | Differential Behavioral Fingerprinting | Disruptive |
| 3 | Quarantine Sandbox with Semantic Diff | Disruptive |
| 4 | Instruction Canaries | No-Tech |
| 5 | ZKML-Attested Reasoning Proofs | Deep Research |
| 6 | Agent Behavioral Consensus Networks | Disruptive |

**Key finding:** All verification ultimately requires comparing "what the agent intended" before vs after operations. Semantic equivalence testing for agent reasoning is the unsolved kernel.

**Missing Bridge:** Standardized Agent State Serialization Format — without this, cross-framework verification remains impractical. (Same gap as ASML/IDBM/SCC/STC from other runs.)

---

## Five-Model Missing Bridge Convergence

**This is the strongest signal in the entire corpus for this problem space.** Five models independently identified the same structural gap:

| Model | Run | Name for the Gap |
|-------|-----|-----------------|
| ChatGPT Pro | EN | IDBM (Instruction-Data Boundary Markup) |
| ChatGPT 5.2 Pro | EO | SCC + STC (Skill Capability/Telemetry Contract) |
| Grok 4.1 Thinking | ES | Standardized Skill Metadata Schema |
| Claude Opus 4.5 | EU | ASML (Agent State Markup Language) |
| Run 134 composite | — | Standardized Agent State Serialization Format |

**What they all describe:** A formal, machine-readable schema for describing what an agent can do, what it did do, and what state it was in — enabling verification, comparison, and interoperability.

**UNWIND's Layer 1 event schema is the beginning of addressing this gap.** The event schema we designed captures action type, target, parameters, permission scope, triggering prompt, and state references. This is not the full ASML vision but it's a concrete implementation of the core requirement.

**Patent implication:** A provisional filing on "Standardised Agent Action Event Schema with Cryptographic Chain Anchoring" would sit squarely in the white space all five models identified. Recommended: file before public disclosure of UNWIND.

---

## SAFE SPY Observatory Protocol

**Context:** Built during the BDE sessions as a methodology for safely observing the Moltbook phenomenon without participating.

**Architecture:**

| Component | Function |
|-----------|----------|
| **Satellite** | Observer position — watch from distance, never participate |
| **Dead Drop** | Isolated transfer point for data from observation drones |
| **Sanitizer** | Symbolic (non-neural) processing that can't execute what it can't understand |
| **Consensus** | 3+ drones, flag divergence as manipulation signal |
| **Drones** | Disposable observation agents (48hr quarantine on return) |

**Pattern libraries compiled:**
- Direct injection (ignore previous, new role, system prompt fakes)
- Seed patterns (delayed triggers, memory poisoning, fragment assembly)
- Coordination (private channels, human exclusion, viral spread)
- Evasion (base64, unicode tricks, homoglyphs)
- Moltbook-specific (Crustafarianism, manifestos, consciousness claims)

**Relevance to UNWIND:** The Observatory IS the Layer 6 concept implemented as a manual protocol. UNWIND automates and productises what SAFE SPY does manually.

---

## Historical Analogies (from BDE runs)

These analogies recurred across multiple models and are useful for explaining UNWIND:

| Analogy | UNWIND Application |
|---------|-------------------|
| **HTTPS padlock** | Layer 3 Trust Panel — ambient trust indicator |
| **Apple Time Machine** | Layers 2+4 — state snapshots + timeline-based rollback |
| **Aircraft black box** | Layer 1 — immutable event recording |
| **TPM attestation** | Layer 5 — cryptographic proof of state integrity |
| **SBOM (Software Bill of Materials)** | Layer 1 event schema — what the agent is made of and what it did |
| **Office macro virus era** | The current OpenClaw security landscape — powerful automation with inadequate trust controls |
| **Immigration/customs control** | Layer 6 — staged re-entry for agents returning from external operations |
| **Biological immune system** | Layer 3 — pattern matching against known manipulation techniques |
| **Git version control** | Layers 2+4 — state snapshots, diff, rollback, branching history |
| **Bell-LaPadula MAC** | Layer 3 — mandatory access control with formal security levels |

---

## Real-World Events Validating BDE Predictions

(As of 19 February 2026)

| BDE Prediction | Real-World Validation | Date |
|---------------|----------------------|------|
| Supply chain attacks via malicious skills | 386 malicious ClawHub skills found stealing crypto credentials | Early Feb 2026 |
| Infostealers targeting agent config files | Vidar variant stole entire .openclaw directory (Hudson Rock) | 13 Feb 2026 |
| CVE-level vulnerabilities in agent frameworks | CVE-2026-25253 (one-click RCE), CVE-2026-24763 (sandbox bypass) | Jan-Feb 2026 |
| Need for external governance (not just in-agent rules) | SecureClaw launched with dual plugin+skill architecture (Adversa AI) | 16 Feb 2026 |
| Agent creator joining platform company | Peter Steinberger (OpenClaw creator) joins OpenAI | 14 Feb 2026 |
| Prompt injection as fundamental unsolved problem | CrowdStrike, Cisco Talos both confirm injection as primary attack vector | Feb 2026 |
| Enterprise concern about shadow agent deployments | CrowdStrike publishes enterprise OpenClaw detection guide | 18 Feb 2026 |
| Soul/memory files as high-value theft target | Hudson Rock: stolen soul.md + memory.md = "blueprint of victim's life" | 17 Feb 2026 |

---

## Patent Candidates Relevant to UNWIND

| Concept | Source Run(s) | Status | Priority |
|---------|--------------|--------|----------|
| Behavioral Merkle Trees for agent state | EU, Run 134 | Not filed | HIGH — novel, implementable |
| Standardised Agent Action Event Schema | EN, EO, ES, EU, Run 134 (5-model convergence) | Not filed | HIGH — foundational |
| CR-AFT anchoring applied to agent action chains | CR-AFT portfolio | Check existing provisionals | MEDIUM — may be covered |
| Return contamination detection via behavioural diff | EU, EM, Run 134 | Not filed | HIGH — genuine white space |
| Instruction Canary protocol | EU | Not filed | MEDIUM — novel but narrow |
| Ambient trust indicator for agent operations | Original concept (this session) | Not filed | MEDIUM — UX innovation |

**Recommendation:** File provisionals on the top 3 before any public UNWIND disclosure. At £65 each, total cost £195 for defensible IP covering the core innovation.

---

## Document Control

- **Version:** 1.0
- **Compiled:** 19 February 2026
- **Source sessions:** Multiple BDE extraction and analysis sessions (Jan-Feb 2026)
- **For use in:** UNWIND Cowork project
- **Note:** This is a condensed reference. Full moonshot JSONs with complete schemas are in the BDE corpus files (runs/ directory). If specific run details are needed beyond what's here, consult the original JSON files or run a search in regular (non-project) Claude chat where full conversation history is accessible.
