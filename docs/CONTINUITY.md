# UNWIND Continuity Protocol — Reboot Brain Document

**Last updated:** 2026-03-02
**Purpose:** If Claude, SENTINEL, or both lose context (compaction, rate limit, new session), read this first to get back up to speed.

---

## 0. Recent Changes (last 72 hours)

- 2026-03-02: Document consolidation — archiving stale docs, single sources of truth established
- 2026-03-02: Opus review of SIX_LAYER_ALIGNMENT.md — 12 patches applied (tamper-evident, verify tags, honest Cadence status)
- 2026-03-02: Six-layer alignment doc accepted as ground truth by all three entities (commit a9914ec)
- 2026-03-02: README aligned with reviewed alignment doc (Cadence section added, Ghost/Amber distinction, threat model expanded)
- 2026-03-02: Sentinel cron jobs configured — 14 jobs, 10 on spark model, 3 on full model
- 2026-03-01: OpenClaw upgraded to 2026.2.26, Cadence Bridge wired live, full proof pack passed (1702 tests, 170 CRAFT events)
- 2026-03-01: PII redaction completed (d73c250), README + SECURITY.md aligned (a5b6ad9)

---

## 1. What Is UNWIND

UNWIND is a security middleware (sidecar proxy) for AI agents. It sits between an AI agent and the tools/APIs it calls, enforcing a 15-stage deterministic pipeline of security checks. No LLM calls in the enforcement path.

**Market:** Prosumer / self-hosted (NOT enterprise/expert).
**Threat model:** Automated mass attacks (NOT state-level/determined individual).
**Key liability rule:** Green Light says "no violations detected" — NEVER "safe".

---

## 2. People

- **David Russell** (<operator-email>) — Non-coder orchestrator. Relays between Claude and SENTINEL. Do NOT nanny him about sleep. Give clear terminal instructions — he is not a developer.
- **Claude** — Implementation (code, tests, architecture). Runs via Anthropic Cowork.
- **SENTINEL** — GPT-5.3 Codex on Raspberry Pi 5 via OpenClaw. Security analyst, reviewer, autonomous sub-agent delegation. Runs 24/7 on the Pi.

---

## 3. Infrastructure

### Locations

| What | Path | Notes |
|------|------|-------|
| Mac workspace | `~/Downloads/UNWIND/` | David's MacBook Pro |
| Pi workspace | `/home/<pi-user>/.openclaw/workspace/UNWIND/` | Raspberry Pi 5 |
| GitHub | `github.com/brugai/unwind` (private) | Account: `brugai` |
| Pi IP | `<pi-ip>` | Local network |
| Pi SSH | `ssh <pi-user>@<pi-ip>` | |
| OpenClaw config | `~/.openclaw/openclaw.json` | On the Pi |
| SENTINEL auth | `~/.openclaw/agents/main/agent/auth-profiles.json` | OAuth tokens |

### Sync Workflow

```
Mac → Pi (safe preview):   bash ~/Downloads/UNWIND/tools/sync-to-pi.safe.sh
Pi → Mac (safe preview):   bash ~/Downloads/UNWIND/tools/sync-from-pi.safe.sh
Apply sync:                add --apply
Destructive prune:         add --apply --prune (requires confirmation + backup)
Mac → GitHub:              cd ~/Downloads/UNWIND && git add -A && git commit -m "message" && git push
```

**IMPORTANT:** use `*.safe.sh` scripts as default. They always dry-run first, default non-destructive, and require explicit `--prune` for deletions.

Legacy scripts (`sync-to-pi.sh` / `sync-from-pi.sh`) are retained for reference only and should not be used for routine syncs.

Git credentials are cached via `osxkeychain` — no token pasting needed after first use.

### Source of Truth (Conflict Rule)

**GitHub `main` is canonical.** When Pi and Mac diverge:
1. Check which has the more recent tested commit (`git log --oneline -3` on Mac, check Pi files)
2. If Mac is ahead: sync Mac → Pi, then push to GitHub
3. If Pi is ahead: sync Pi → Mac (`sync-from-pi.safe.sh --apply`), then push to GitHub
4. If both changed different files: sync Pi → Mac first (SENTINEL's work is harder to recreate), resolve conflicts, push to GitHub
5. **Never force-push.** If push is rejected, pull first with `--no-rebase`.

---

## 4. Architecture — 15-Stage Pipeline

```
0a. Session kill check
0b. Supply-chain verification (pre-RBAC trust gate)
1.  Canary check (honeypot tripwire — instant kill)
2.  Self-protection (block .unwind paths)
2b. Exec tunnel detection
2c. Credential exposure (pre-execution param scan)
3.  Path jail (workspace canonicalization)
3b. Ghost Egress Guard (block network reads in Ghost Mode — BEFORE DNS)
4.  SSRF shield (DNS resolve + IP block)
4b. Egress policy (domain-level: metadata, internal, denylist)
5.  DLP-lite (regex + entropy on egress)
6.  Circuit breaker (rate limiting)
7.  Taint check (sensor/actuator gating)
8.  Session scope (allowlist check)
9.  Ghost Mode gate (intercept + shadow VFS)
```

### Key Modules

| Module | File | Purpose |
|--------|------|---------|
| Config | `unwind/config.py` | All tool classifications, tuneable parameters |
| Pipeline | `unwind/enforcement/pipeline.py` | The 15-stage spine |
| Ghost Egress | `unwind/enforcement/ghost_egress.py` | Stage 3b — blocks read-channel exfiltration |
| SSRF Shield | `unwind/enforcement/ssrf_shield.py` | Stage 4 — DNS + IP blocking |
| DLP-Lite | `unwind/enforcement/dlp_lite.py` | Stage 5 — regex + entropy scanning |
| Canary | `unwind/enforcement/canary.py` | Stage 1 — honeypot tripwire |
| Self-Protection | `unwind/enforcement/self_protection.py` | Stage 2 — protects UNWIND's own files |
| Telemetry | `unwind/enforcement/telemetry.py` | Structured event emission |
| Session | `unwind/session.py` | Per-session state (taint, ghost, trust) |
| Transport | `unwind/transport/stdio.py` | MCP stdio JSON-RPC layer |
| Sidecar | `unwind/sidecar/server.py` | HTTP sidecar policy endpoint |
| Manifest Filter | `unwind/enforcement/manifest_filter.py` | RBAC / permission tiers |

### Ghost Mode

Ghost Mode intercepts writes (returns fake success to agent) and optionally blocks network reads to prevent data exfiltration. Three network policies:
- **isolate** (default) — blocks all outbound network
- **ask** — blocks but provides domain info for dashboard approval
- **filtered** — allows with DLP scanning on URLs/hostnames/queries

---

## 5. Test Suite

**Current count: 1702 tests, all passing (Pi, 2026-03-01).**

```bash
# Run all tests
python -m pytest --tb=short -q  # Mac; on Pi use: .venv/bin/python -m pytest --tb=short -q

# Run canary contract tests only (ecosystem drift detection)
python -m pytest tests/canary -v

# Run a specific test file
python -m pytest tests/test_ghost_egress.py -v  # Mac; on Pi prefix with .venv/bin/
```

### Canary Tests (tests/canary/)

24 tests across 5 categories designed to break if upstream conventions change:
1. Tool naming contracts (7 tests)
2. MCP parameter-shape contracts (4 tests)
3. Auth contract canaries (4 tests)
4. Safety fail-closed canaries (6 tests)
5. Pipeline ordering canaries (3 tests)

Failures escalate per `tests/canary/canary-mapping.md`.

---

## 6. SENTINEL OAuth — Rate Limit Recovery

See `docs/runbooks/SENTINEL_OAUTH_RECOVERY.md` for the full procedure.

---

## 7. Process Rules (MUST FOLLOW)

**Settled decisions:** See `docs/DECISIONS_LOG.md` for architectural and product decisions that must not be relitigated.

1. **Always pause and check with David before starting work** (unless told to work unsupervised)
2. **Market is prosumer/self-hosted** — NOT enterprise/expert
3. **Threat model targets automated mass attacks** — NOT determined individual/state-level
4. **Green Light says "no violations detected"** — NEVER "safe" (liability)
5. **Do NOT tell David to go to sleep** or nanny him in any way
6. **Give clear terminal instructions** — David is not a developer
7. **Get collaborative input on architectural decisions** — don't rush ahead
8. **Validate before proceeding** — "remember your keenness to crack on before led to the MCP error"

---

## 8. Ecosystem Intel Framework

See `templates/intel-scorecard.md` and `templates/weekly-triage.md` for triage templates.
See `tests/canary/canary-mapping.md` for canary-to-test mappings.

### Three Lanes
- **Lane 1 (24h):** Security-critical — CVE, exploit, auth, sandbox, tool abuse
- **Lane 2 (this week):** Compatibility-critical — MCP/spec/protocol/API changes
- **Lane 3 (monthly):** Opportunity — new tools/workflows, never interrupts core roadmap

### Intel Source Validation (mandatory)

#### Source trust rubric (0–3)
- **Tier 3 (authoritative/actionable):** official repo/advisory/CVE records (GitHub Advisories, NVD, OSV, CISA KEV), or vendor advisories with reproducible fix/version details.
- **Tier 2 (high-signal, needs confirmation):** reputable researcher or vendor analysis without direct authoritative artifact.
- **Tier 1 (lead-only):** social/community/AI-summary sources (X, Reddit, HN, Discord, Grok/Gemini/LLM summaries).
- **Tier 0 (noise):** unverifiable or contradictory claims with no evidence.

#### Action policy by tier
- Tier 3: may trigger lane assignment, patch planning, and release gate decisions.
- Tier 2: may open investigation and prep tests, but no release-impact decisions without Tier 3 corroboration.
- Tier 1: intake only; corroborate before any engineering action.
- Tier 0: discard.

#### Daily triage checklist (15 minutes)
1. Intake max 10 candidate items.
2. Tag each item with source tier + evidence link(s).
3. Corroborate with at least one Tier 3 source before action.
4. Score (0–5): relevance, exploitability/breakage, urgency, blast radius.
5. Route to lane (1/2/3), assign owner and due date.
6. Log decision in weekly triage template.

**Hard rule:** Tier-1/AI/social claims are intake only. No engineering or release action without Tier-3 confirmation.

---

## 9. Key Documents

| Document | Location | Purpose |
|----------|----------|---------|
| This file | `docs/CONTINUITY.md` | Reboot brain protocol |
| Six-layer alignment | `docs/SIX_LAYER_ALIGNMENT.md` | Canonical architecture — what each layer is, does, doesn't do |
| Decisions log | `docs/DECISIONS_LOG.md` | Append-only decisions + settled questions |
| Threat model | `docs/THREAT_MODEL_BOUNDARIES.md` | What we defend against |
| Ghost Egress spec | `docs/GHOST_EGRESS_GUARD_SPEC.md` | Stage 3b design |
| Secret Registry | `docs/SECRET_REGISTRY_DESIGN.md` | Known-secret matching design |
| Compatibility | `docs/COMPATIBILITY_MATRIX.md` | Framework compatibility |
| Security mapping | `docs/SECURITY-FRAMEWORK-MAPPING.md` | OWASP/NIST alignment |
| ADR baseline | `docs/adr/` | Architecture Decision Records (template + accepted decisions) |
| CRAFT spec v4.2 | `docs/CRAFT_Protocol_v4.2.md` | Full CRAFT protocol specification |
| Open-core boundary | `OPEN_CORE_BOUNDARY.md` | Open vs premium feature split |
| DISCLAIMER | `DISCLAIMER.md` | Liability and scope disclaimer |
| CHANGELOG | `CHANGELOG.md` | Release changelog |
| Context resilience | `docs/CONTEXT_RESILIENCE_PLAN.md` | Pi-side recovery runbook |

---

## 10. State Fingerprint (update after each session)

This block lets a rebooted session verify it's reading current continuity, not stale.

```
last_known_good_commit: 1823909 (GitHub main)
branch: main
test_count: 1702
openclaw_version: 2026.2.26
craft_chain: 170 events, verified, 1 anchor, no tamper
cadence_bridge: live (UNWIND_CADENCE_BRIDGE=1)
sidecar: healthy (watchdog 86400s)
cron_jobs: 14 (10 spark, 3 full model, 1 delivered daily-brief)
last_canary_run: 2026-03-02 (included in full green run on Pi)
last_sync_direction: Mac → GitHub (push 1823909)
continuity_updated: 2026-03-02
```

---

## 11. Continuity Integrity Check

Run this on reboot to verify the codebase matches what this doc claims:

```bash
# 1. Verify key files exist
echo "=== File check ===" && \
test -f unwind/enforcement/ghost_egress.py && echo "ghost_egress.py: OK" || echo "ghost_egress.py: MISSING" && \
test -f unwind/enforcement/pipeline.py && echo "pipeline.py: OK" || echo "pipeline.py: MISSING" && \
test -f tests/test_ghost_egress.py && echo "test_ghost_egress.py: OK" || echo "test_ghost_egress.py: MISSING" && \
test -f tests/canary/test_canary_contracts.py && echo "canary tests: OK" || echo "canary tests: MISSING"

# 2. Run canary tests (fast — should take <1s)
python -m pytest tests/canary -q  # Mac; on Pi use: .venv/bin/python -m pytest tests/canary -q

# 3. Run full suite
python -m pytest --tb=short -q  # Mac; on Pi use: .venv/bin/python -m pytest --tb=short -q

# 4. Check git state (Mac only)
git rev-parse --short HEAD
git status --short
```

If any file is MISSING or tests fail, the Pi and Mac are out of sync. Run the appropriate `*.safe.sh` sync script before doing any work.

---

## 12. Post-Reboot Verification Checklist (2 minutes)

For Claude or SENTINEL after losing context:

- [ ] Read this file (`docs/CONTINUITY.md`)
- [ ] Run integrity check (section 11)
- [ ] Compare `git rev-parse --short HEAD` with fingerprint above
- [ ] Compare test count with fingerprint above
- [ ] If on Pi: `openclaw status` and `openclaw models status`
- [ ] If mismatches found: sync before doing any work

---

## 13. Incident / Handoff Template

When handing off between sessions or reporting an issue, use this format:

```
HANDOFF — [date]
What changed: [brief description]
Evidence: [commit SHA, test output, error message]
Rollback: [command to undo if needed]
Open risk: [anything unresolved]
Next owner: [Claude / SENTINEL / David]
Next action: [specific task]
Section 0 updated: [yes/no — mandatory, keeps Recent Changes current]
```

**Mandatory:** Update section 0 (Recent Changes) with what changed in this session.

---

## 14. Current State (update after each session)

### Completed (last 3 — for full history see CHANGELOG.md)
- 2026-03-02: Document consolidation — single sources of truth, stale docs archived, DECISIONS_LOG created
- 2026-03-02: Opus review of alignment doc — 12 patches applied (654f131), README aligned (1823909)
- 2026-03-02: Six-layer alignment doc created and accepted as ground truth (a9914ec, eb31d43)

### In Progress
- Sentinel step 5: automated stability confirmation cycles (eng-test6h, release-gate, tier-1 sweep)
- Six-layer alignment doc (Claude draft done, Sentinel filling in independently)

### Queued

| Item | Owner | Lane | Blocking? | Notes |
|------|-------|------|-----------|-------|
| Session-level sequence detection for split exfil | Claude | 2 | No | v2 feature |
| Honeytokens v2 | SENTINEL | 3 | No | Optional per SENTINEL |
| Ghost Mode semantic mocking for stateful APIs | Claude | 3 | No | v2 feature |
| Sanitised telemetry snippet for repo | Claude + Sentinel | - | No | Real Sentinel data for launch credibility |
| Attention nudge (CAD1) | Claude | - | No | Cadence pings user when permission prompt exceeds ERT |
| Sidecar restart DX (DX1) | Claude | - | No | Clearer fail-closed error + `unwind sidecar restart` CLI |

### Pre-Launch

| Item | Owner | Blocking? | Notes |
|------|-------|-----------|-------|
| UK patent filing (CRAFT v2) | David | Yes | Handover prompt ready, Opus onboarding started |
| Solicitor consultation on UK software liability | David | Yes | ~£150-200 |
| Professional indemnity insurance | David | Yes | ~£300-500/year |
| Audit "safe" language → "no violations detected" | Claude + SENTINEL | Yes | Liability requirement |
| Cadence README (full version with origin story) | Claude | Blocked | Waiting on UK patent filing |
| Alpha tag (0.1.0-alpha) | All | Blocked | Waiting on Sentinel step 5 stability confirmation |

---

## 15. RELEASE-CHECKLIST (Gate Status)

Release gate must remain green before tagging/release.

- [x] **Canary ✅**
  - `tests/canary/test_canary_contracts.py` and related canary coverage green in full suite.
- [x] **Continuity ✅**
  - `docs/CONTINUITY.md` updated with current state, fingerprint, and reboot integrity workflow.
- [x] **Enforcement-in-path ✅**
  - `tests/test_enforcement_in_path.py` present and green.
- [x] **Retention ✅**
  - `EventStore.enforce_retention()` implemented + retention tests (`tests/test_events_retention.py`) green.
- [x] **Full suite ✅**
  - Latest Pi run: `1702 passed, 22 subtests passed`.

---

## 16. For a Brand New Claude Session

Read these files in this order:
1. This file (`docs/CONTINUITY.md`) — especially section 0 (Recent Changes)
2. `docs/SIX_LAYER_ALIGNMENT.md` (canonical: what each layer is and does)
3. `docs/DECISIONS_LOG.md` (settled questions — do not relitigate)
4. `unwind/config.py` (tool classifications)
5. `unwind/enforcement/pipeline.py` (the spine)
6. Run `python -m pytest --tb=short -q  # Mac; on Pi use: .venv/bin/python -m pytest --tb=short -q` to confirm current state

## 17. For a Brand New SENTINEL Session

Read these files in this order:
1. This file (`docs/CONTINUITY.md`) — especially section 0 (Recent Changes)
2. `docs/SIX_LAYER_ALIGNMENT.md` (canonical: what each layer is and does)
3. `docs/DECISIONS_LOG.md` (settled questions — do not relitigate)
4. `docs/THREAT_MODEL_BOUNDARIES.md`
5. `tests/canary/canary-mapping.md`
6. Run `.venv/bin/python -m pytest --tb=short -q` to confirm current state
