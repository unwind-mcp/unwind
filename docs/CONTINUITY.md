# UNWIND Continuity Protocol — Reboot Brain Document

**Last updated:** 2026-02-25
**Purpose:** If Claude, SENTINEL, or both lose context (compaction, rate limit, new session), read this first to get back up to speed.

---

## 1. What Is UNWIND

UNWIND is a security middleware (sidecar proxy) for AI agents. It sits between an AI agent and the tools/APIs it calls, enforcing a 15-stage deterministic pipeline of security checks. No LLM calls in the enforcement path.

**Market:** Prosumer / self-hosted (NOT enterprise/expert).
**Threat model:** Automated mass attacks (NOT state-level/determined individual).
**Key liability rule:** Green Light says "no violations detected" — NEVER "safe".

---

## 2. People

- **David Russell** (david@brugai.com / albaco1@btconnect.com) — Non-coder orchestrator. Scottish Borders. Relays between Claude and SENTINEL. Do NOT nanny him about sleep. Give clear terminal instructions — he is not a developer.
- **Claude** — Implementation (code, tests, architecture). Runs via Anthropic Cowork.
- **SENTINEL** — GPT-5.3 Codex on Raspberry Pi 5 via OpenClaw. Security analyst, reviewer, autonomous sub-agent delegation. Runs 24/7 on the Pi.

---

## 3. Infrastructure

### Locations

| What | Path | Notes |
|------|------|-------|
| Mac workspace | `~/Downloads/UNWIND/` | David's MacBook Pro |
| Pi workspace | `/home/dandare/.openclaw/workspace/UNWIND/` | Raspberry Pi 5, user `dandare` |
| GitHub | `github.com/brugai/unwind` (private) | Account: `brugai` |
| Pi IP | `192.168.0.171` | Local network |
| Pi SSH | `ssh dandare@192.168.0.171` | |
| OpenClaw config | `~/.openclaw/openclaw.json` | On the Pi |
| SENTINEL auth | `~/.openclaw/agents/main/agent/auth-profiles.json` | OAuth tokens |

### Sync Workflow

```
Mac → Pi:   bash ~/Downloads/UNWIND/tools/sync-to-pi.sh
Pi → Mac:   bash ~/Downloads/UNWIND/tools/sync-from-pi.sh
Mac → GitHub: cd ~/Downloads/UNWIND && git add -A && git commit -m "message" && git push
```

**IMPORTANT:** `sync-from-pi.sh` uses `--exclude='.git'` to avoid wiping the git history. If `.git` disappears, reinitialise with:
```bash
cd ~/Downloads/UNWIND && git init && git remote add origin https://github.com/brugai/unwind.git
git pull origin main --allow-unrelated-histories --no-rebase
```

Git credentials are cached via `osxkeychain` — no token pasting needed after first use.

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

**Current count: 1313 tests, all passing.**

```bash
# Run all tests
python -m pytest --tb=short -q

# Run canary contract tests only (ecosystem drift detection)
python -m pytest tests/canary -v

# Run a specific test file
python -m pytest tests/test_ghost_egress.py -v
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

SENTINEL authenticates to OpenAI via OAuth. David has two accounts:
- `albaco1@btconnect.com` — Personal Plus + Team plan
- `david@brugai.com` — Team/Business plan

**Key lesson:** Seats don't double rate limits. Limits are per-org-workspace, not per-seat. To switch which capacity SENTINEL uses, you re-auth to a different workspace.

### How to Switch SENTINEL's OAuth Workspace

1. Back up current auth:
```bash
cp ~/.openclaw/agents/main/agent/auth-profiles.json ~/.openclaw/agents/main/agent/auth-profiles.json.bak
```

2. Re-run OAuth (on the Pi):
```bash
openclaw onboard --auth-choice openai-codex
```
  - Select **Yes** to security warning
  - Select **QuickStart**
  - Select **Use existing values**
  - It shows an OAuth URL — open it in a browser on the Mac
  - Log in and **choose the workspace** you want (Personal vs Team)
  - The browser redirects to a `localhost` URL that won't load — **copy the full URL from the address bar**
  - Paste that URL into the Pi terminal
  - Skip channels, skills, hooks
  - Select **Restart** for gateway
  - Select **Do this later** for hatching

3. If a broken profile was created during the process, clean it up:
```bash
python3 -c "
import json
with open('/home/dandare/.openclaw/agents/main/agent/auth-profiles.json') as f:
    data = json.load(f)
# Remove any broken profiles (check for 'Symbol(clack:cancel)' or similar)
for key in list(data.get('profiles', {}).keys()):
    p = data['profiles'][key]
    if p.get('type') == 'token' and 'Symbol' in str(p.get('token', '')):
        del data['profiles'][key]
        if key in data.get('usageStats', {}):
            del data['usageStats'][key]
# Ensure lastGood points to the valid profile
data['lastGood'] = {'openai-codex': 'openai-codex:default'}
with open('/home/dandare/.openclaw/agents/main/agent/auth-profiles.json', 'w') as f:
    json.dump(data, f, indent=2)
print('Cleaned')
"
```

4. Restart gateway and test:
```bash
openclaw gateway start
sleep 5
openclaw tui
```

### Cleaner Method (for next time)

```bash
openclaw models auth login --provider openai-codex
```
Complete OAuth, then verify with `openclaw models status`.

---

## 7. Process Rules (MUST FOLLOW)

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

---

## 9. Key Documents

| Document | Location | Purpose |
|----------|----------|---------|
| This file | `docs/CONTINUITY.md` | Reboot brain protocol |
| Architecture | `docs/ARCHITECTURE_V2.md` | Full architecture spec |
| Threat model | `docs/THREAT_MODEL_BOUNDARIES.md` | What we defend against |
| What is UNWIND | `WHAT-IS-UNWIND.md` | Public-facing explainer |
| Ghost Egress spec | `docs/GHOST_EGRESS_GUARD_SPEC.md` | Stage 3b design |
| Secret Registry | `docs/SECRET_REGISTRY_DESIGN.md` | Known-secret matching design |
| Compatibility | `docs/COMPATIBILITY_MATRIX.md` | Framework compatibility |
| Security mapping | `docs/SECURITY-FRAMEWORK-MAPPING.md` | OWASP/NIST alignment |

---

## 10. Current State (update after each session)

### Completed
- 15-stage enforcement pipeline (all stages implemented and tested)
- Ghost Mode with tool classification + prefix heuristic
- Ghost Egress Guard (stage 3b) — read-channel exfiltration prevention
- Canary contract test suite (24 tests, 5 categories)
- Ecosystem intel framework (watchlist, scoring, triage templates)
- GitHub repo setup (github.com/brugai/unwind, private)
- Sync scripts (Mac ↔ Pi)
- 1313 tests all passing

### Queued
- Known-secret exact matching (secret registry)
- Session-level sequence detection for split exfil (v2)
- Honeytokens v2 (optional per SENTINEL)
- Ghost Mode semantic mocking for stateful APIs (v2)

### Pre-Launch
- Solicitor consultation on UK software liability (~£150-200)
- Professional indemnity insurance (~£300-500/year)
- Audit all remaining "safe" language → "no violations detected"

---

## 11. For a Brand New Claude Session

Read these files in this order:
1. This file (`docs/CONTINUITY.md`)
2. `WHAT-IS-UNWIND.md`
3. `docs/ARCHITECTURE_V2.md`
4. `unwind/config.py` (tool classifications)
5. `unwind/enforcement/pipeline.py` (the spine)
6. Run `python -m pytest --tb=short -q` to confirm current state

## 12. For a Brand New SENTINEL Session

Read these files in this order:
1. This file (`docs/CONTINUITY.md`)
2. `WHAT-IS-UNWIND.md`
3. `docs/THREAT_MODEL_BOUNDARIES.md`
4. `docs/GHOST_EGRESS_GUARD_SPEC.md`
5. `tests/canary/canary-mapping.md`
6. Run `python -m pytest --tb=short -q` to confirm current state
