# UNWIND Session Update — Architecture Correction
## 23 February 2026

**Author:** David Russell + Claude (Cowork) + SENTINEL (GPT-5.3 Codex / OpenClaw)
**Session type:** Architecture correction — major discovery, no code scrapped, integration model changed
**Follows:** SESSION-SUMMARY-2026-02-22.md

---

## What Happened

### Amber Mediator Persistence (completed before correction)

Built and SENTINEL-verified the full 10-point GO/NO-GO checklist for the Amber Mediator Persistence PR (R-AMBER-MED-001):

- GO-01: Canonical action_hash with deterministic JSON serialisation
- GO-02/03: SQLite event store (`amber_store.py`) with two tables
- GO-04: Issuance persistence with challenge_seq wired into stdio.py
- GO-05/06: Exact-match validation, expiry, sequence enforcement
- GO-07: Replay defence with jti uniqueness (survives restart)
- GO-08: Atomic state transitions (BEGIN IMMEDIATE + re-check under write lock)
- GO-09: Telemetry chain (`amber_telemetry.py`) — 5 event types, chain reconstruction
- GO-10: Rollout guard (`amber_rollout.py`) — config gate, shadow parity test

Two SENTINEL review rounds: first returned CONDITIONAL_GO with 3 blockers (reason codes, required telemetry fields, runtime wiring). All fixed. Second review: full GO.

Dual sign-off attestation: R-AMBER-MED-MERGE-ATT-001.yaml (SENTINEL GO + David GO).

**Test count at this point: 1,027 passing in 6.81s.**

### Stage 2 Formally Closed

SENTINEL verified runtime evidence artifacts (stage2_full.json, stage2_recheck.json — both 17/17 PASS) and formally closed Stage 2.

SENTINEL commit on Pi: 0b46d43 — "Formally close Stage 2 and mark Stage 3 canary readiness from runtime evidence."

### The Discovery (Architecture Correction)

When planning Stage 3 canary deployment, David asked three times for a real user install path: OpenClaw running → install GhostMode → install UNWIND. This instruction was bypassed by both Claude and SENTINEL, who continued planning as if UNWIND was already deployed.

David forced the question. The investigation revealed:

**Finding 1 — OpenClaw does not use MCP tool server launching.**

- `mcpCapabilities.http=false`, `mcpCapabilities.sse=false`
- OpenClaw explicitly logs "ignoring MCP servers" on session creation
- This is not Pi-specific — it's how OpenClaw ACP works on all platforms
- Source: dist/acp-cli-CErUH_1X.js#L796-L833

**Finding 2 — MCP is Anthropic's protocol.** Given competitive dynamics (OpenClaw uses OpenAI's stack), adoption of MCP by OpenClaw was never realistic. This should have been flagged on day one.

**Finding 3 — The entire UNWIND architecture assumed MCP stdio proxy insertion.** Every doc, README, quick-start, and marketing claim described UNWIND as an MCP proxy. The primary target (OpenClaw) cannot use that integration model.

### What Was Scrapped

Only 3 assumptions:
1. "One universal insertion method for all runtimes"
2. "OpenClaw uses MCP server launch chaining"
3. "Single pip install for every environment"

### What Was Kept (70-85% of all work)

- Full enforcement engine (13-stage pipeline)
- Amber mediator + persistence + telemetry + rollback
- Trust light concept
- GhostMode value proposition
- Canary/attestation discipline
- All test infrastructure
- Session isolation, taint decay, rubber-stamp, supply chain
- CR-AFT audit chain, rollback engine, dashboard

### The Corrected Architecture

**OpenClaw has a first-class plugin system with tool-call interception hooks.**

Verified by SENTINEL from actual code/docs on Pi:

- `before_tool_call` / `after_tool_call` hooks exist and are documented
- Hook can inspect params, mutate them, or block with reason
- Plugin lifecycle: `registerService` with start/stop for managed resources
- Discovery: `<workspace>/.openclaw/extensions/`, `~/.openclaw/extensions/`, or `plugins.load.paths`
- Install: `openclaw plugins install <path-or-spec>` (npm/path/archive)

**Critical constraints discovered:**

1. **Plugins are JS/TS only** — no native Python plugin SDK. Our engine is Python. Need a JS plugin adapter that calls Python sidecar via IPC.
2. **Fail-open on exception** — if hook throws, OpenClaw catches and continues (tool executes). Plugin MUST handle all errors and return explicit block. Fail-closed must be enforced in our code.
3. **No principal ID in hook context** — only toolName, params, optional agentId, optional sessionKey. Need session→principal mapping layer.
4. **Plugin slash commands bypass tool loop** — not all operations are interceptable via before_tool_call.
5. **Plugin API is evolving** — multiple changelog entries adjusted hook behaviour. Must pin OpenClaw version.
6. **"Challenge" is not native** — hook return supports allow/block/mutate only. Amber challenge must be implemented as block + out-of-band approval workflow.
7. **Service start failures don't stop gateway** — logged and continued. Don't assume enforcement starts automatically.
8. **Gateway restart required** after plugin config changes.

**New architecture:**

```
OpenClaw → TS Plugin (thin adapter) → Python Sidecar (UNWIND engine)
              │                              │
              ├── before_tool_call            ├── Enforcement pipeline
              ├── after_tool_call             ├── Amber mediator
              ├── Fail-closed handler         ├── Telemetry chain
              └── registerService             ├── Rollback engine
                  (manages sidecar)           └── Flight recorder
```

**Two adapter model (one engine, two front doors):**

| Adapter | Target | Install Path |
|---------|--------|-------------|
| OpenClaw plugin | OpenClaw users (primary) | pip install engine + openclaw plugins install adapter + restart gateway |
| MCP stdio proxy | Claude Desktop, Cursor, etc. | pip install + change mcpServers config |

---

## Infrastructure Reference

### David's Mac
- Username: `davidrussell`
- UNWIND workspace: `/Users/davidrussell/Downloads/UNWIND` (Cowork mount)

### Raspberry Pi 5
- SSH: `ssh dandare@192.168.0.171` (password: **REDACTED — see secure store**)
- OpenClaw workspace: `/home/dandare/.openclaw/workspace/` (NOT ~/UNWIND)
- OpenClaw: v2026.2.21-2, port 18789, think high
- File transfer: `scp /Users/davidrussell/Downloads/UNWIND/<file> dandare@192.168.0.171:/home/dandare/.openclaw/workspace/`

### SENTINEL
- Model: openai-codex/gpt-5.3-codex
- Token budget: ~272k
- Collaboration protocol: 5-point format (Objective, Change, Evidence, Files, Risks)

---

## Key Process Rules (unchanged)

1. **Always pause and check with David before starting work.** Never build without explicit approval.
2. **If we deviate from any assumption, everyone knows — especially David.**
3. **Validate integration assumptions against the actual target platform before writing code.** The first question for any new integration: "Show me exactly how the target system works at the point where we plan to connect."

---

## Pending Work (Priority Order — Post-Correction)

### P0 — OpenClaw Adapter Spec (NEXT)
- SENTINEL to draft fail-closed adapter contract (OPENCLAW_ADAPTER_FAILCLOSED_SPEC.yaml)
- Must include: timeout budgets, error mapping, block-on-uncertainty logic
- Must include: challenge workflow that fits OpenClaw's hook model (block + out-of-band)
- Build NOTHING until spec is reviewed and approved by all three parties

### P0 — README/Doc Correction
- README.md: currently describes MCP-proxy-only model — needs dual-adapter rewrite
- ghostmode/README.md: same issue
- SESSION-SUMMARY-2026-02-22.md: architecture description needs correction note
- UNWIND_Project_Spec*.md: may reference MCP-only assumptions
- SECURITY_COVERAGE.md: check for transport-specific claims

### P1 — Packaging Hardening
- Clean venv install tests for Python engine
- OpenClaw plugin package structure (openclaw.plugin.json manifest)
- Command sanity (ghostmode --help, unwind --help)

### P1 — Real Signature Verification (carried from previous session)
### P1 — Approval Windows Module (carried from previous session)
### P1 — OWASP ASI Top 10 Gap Closure (carried from previous session)

---

## Files on Pi (current state)

Transferred for SENTINEL review (not deployed, not installed):
- amber_store.py, amber_telemetry.py, amber_rollout.py
- R-AMBER-MED-MERGE-ATT-001.yaml
- stage2_full.json, stage2_recheck.json
- unwind-stage2-closure-and-stage3-readiness.yaml (SENTINEL-created)

SENTINEL commits: 0b46d43, 8372136, d262b2a

---

## Lesson Learned

The question that would have prevented 3 days of misaligned work:

**"How does OpenClaw launch and communicate with its tools?"**

Asked before designing anything, before choosing "stdio MCP proxy" as the architecture. One question, ten minutes, would have caught the mismatch on day one.

---

## Post-Correction Work (same session)

### File Reorg (SENTINEL-designed, Claude-executed)

Evidence artifacts archived — not deleted — to `evidence/mcp-stdio/2026-02-22/` with INDEX.md:
- R-AMBER-MED-MERGE-ATT-001.yaml, stage1/2 probe results, execution checklist, GO certificate, drill reports, evidence bundle, canary dry run

Transfer tarballs moved to `archive/raw-imports/`.

Core engine and specs untouched per SENTINEL's guardrail: `unwind/enforcement/**`, `ghostmode/**`, all core recorder/snapshot/rollback modules, all tests.

### OpenClaw Adapter Scaffold Created

New `openclaw-adapter/` directory (TypeScript):
- `package.json`, `openclaw.plugin.json` (plugin manifest with mode/sidecarUrl/timeoutMs config)
- `src/index.ts` — entry point with fail-closed security contract in comments
- `src/hooks/beforeToolCall.ts` — hook handler placeholder with exact signature documented
- `src/hooks/afterToolCall.ts` — telemetry/audit hook placeholder
- `src/service/sidecarManager.ts` — sidecar lifecycle via registerService
- `src/ipc/client.ts` — sidecar communication with timeout/circuit breaker notes
- `src/config/schema.ts` — typed config interface
- `tests/adapter.test.ts` — test cases listed
- `README.md` — architecture, install path, security contract

New `unwind/sidecar/` directory (Python):
- `__init__.py`, `models.py` (request/response models), `server.py` (local HTTP policy server)
- CLI entry point planned: `unwind sidecar serve`

### Documentation Rewritten

**README.md** — full rewrite:
- Leads with "One core security engine, multiple adapters"
- Architecture diagram shows both OpenClaw plugin and MCP stdio proxy paths
- Quick Start has two sections: OpenClaw users ("ask your agent to install") and MCP client users
- Compatibility table listing supported platforms
- Adapter-specific security considerations section
- Project structure updated to include openclaw-adapter/ and unwind/sidecar/
- Test count updated to 1,027
- SENTINEL's wording guardrails applied: no "works with any agent" without matrix, no "cannot bypass" absolutes, no "single-command install everywhere"

**ghostmode/README.md** — updated with OpenClaw install path alongside existing MCP proxy instructions. Core pitch unchanged.

**docs/COMPATIBILITY_MATRIX.md** — created. Two adapter paths, platform table, what's NOT supported (with reasons), OpenClaw-specific constraints (6 items documented).

**docs/ARCHITECTURE_V2.md** — created. Full architecture explanation: core engine (shared), Adapter A (OpenClaw plugin + sidecar), Adapter B (MCP stdio proxy), shared guarantees, what differs between adapters.

**README_SCOPE.md** — repo-level transition note explaining what's where.

**SESSION-SUMMARY-2026-02-22.md** — correction header added pointing to this file.

### SENTINEL Overnight Jobs Scheduled (6 one-shots, 1hr apart)

Monitoring crons rescheduled to 00:05–05:05 (1hr apart, was clustered before).

6 adapter-specific one-shot jobs created by SENTINEL:

| Time (UTC) | Job | ID | Output |
|------------|-----|----|--------|
| 02:08 | sentinel:oneshot:failclosed-spec | 520a5d19 | OPENCLAW_ADAPTER_FAILCLOSED_SPEC.yaml |
| 03:08 | sentinel:oneshot:sidecar-api-spec | 2d69ca43 | UNWIND_SIDECAR_API_SPEC.yaml |
| 04:08 | sentinel:oneshot:session-principal-design | fba574a0 | SIDECAR_SESSION_PRINCIPAL_DESIGN.yaml |
| 05:08 | sentinel:oneshot:plugin-sdk-review | 40507075 | OPENCLAW_PLUGIN_SDK_REVIEW.yaml |
| 06:08 | sentinel:oneshot:adapter-threat-model | 26907784 | ADAPTER_THREAT_MODEL.yaml |
| 07:08 | sentinel:oneshot:docs-security-review | f33790c7 | DOCS_SECURITY_REVIEW.yaml |

All configured: `--no-deliver --best-effort --deleteAfterRun --session isolated`.

Updated docs transferred to Pi via scp before Job 6 (docs security review needs the files).

SENTINEL commit: 4d2b9db (cron reconfiguration + memory log).

### Agreed Product Pitch (SENTINEL-tightened)

- **Green Light** — real-time trust state at a glance
- **Rewind** — undo covered actions quickly, by event or time range
- **Ghost Mode** — dry-run risky workflows safely before execution

One security engine, two front doors:
- **OpenClaw users:** ask your agent to install/configure UNWIND (plugin + sidecar path)
- **MCP-client users:** `pip install unwind-mcp` + minimal config change (where MCP launch-chain is supported)

Same policy engine. Same enforcement semantics. Different integration path. No LLM in the enforcement decision path. Deterministic checks. Low-latency by design. Invisible when safe, unmissable when risk appears.

### Key Insight (David)

OpenClaw users have an AI agent right there that can run the install. The install path isn't "user types three commands" — it's "tell your agent to install UNWIND." That reframes the multi-step install as a feature, not a limitation.

---

## Updated Pending Work (Priority Order)

### P0 — Review SENTINEL overnight specs (morning of 24 Feb)
6 YAML specs on Pi workspace. Review, discuss, approve before building.

### P0 — Build OpenClaw adapter (est. 2-3 sessions / 8-12 hours)
- TS plugin: beforeToolCall handler, afterToolCall handler, sidecar manager, IPC client
- Python sidecar: HTTP server exposing enforcement engine
- Integration tests: fail-closed scenarios, timeout, crash recovery, challenge workflow

### P1 — Packaging hardening
- Clean venv install tests
- OpenClaw plugin package structure
- Command sanity checks

### P1 — Real signature verification (carried forward)
### P1 — Approval windows module (carried forward)
### P1 — OWASP ASI Top 10 gap closure (carried forward)

---

## Session Handoff Notes

**To rebuild context in a new session, read in order:**
1. `SESSION-UPDATE-2026-02-23.md` (this file)
2. `docs/ARCHITECTURE_V2.md` (dual-adapter architecture)
3. `docs/COMPATIBILITY_MATRIX.md` (what works where)
4. `openclaw-adapter/README.md` (adapter security contract)
5. SENTINEL's overnight specs (on Pi, check workspace)

**Key context that compaction might lose:**
- David's rule: always pause and check before building. Never assume. If deviating from any assumption, everyone knows — especially David.
- The "one question" lesson: "How does the target system work at the point where we plan to connect?" — ask before designing.
- OpenClaw plugin hooks are JS/TS only — Python engine runs as sidecar
- Fail-open on hook exception — our handler must never throw
- MCP is Anthropic's protocol — OpenClaw (OpenAI stack) won't adopt it
- SENTINEL monitoring crons now run 00:05–05:05 (1hr apart)
- BDE is fine — no integration dependency, self-contained research engine, not affected by this correction

---

*Architecture corrected. Docs rewritten. Adapter scaffolded. 6 overnight specs queued. 1,027 tests passing. Ready to build the adapter against verified specs.*
