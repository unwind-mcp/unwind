# SENTINEL Recovery Packet

Generated: 2026-03-01 17:07:37 GMT
Workspace: /home/dandare/.openclaw/workspace

## 0) Fast recovery order (<2 min target)

1. Read this packet end-to-end.
2. Read `memory/CRITICAL_IP.md` for unresolved continuity-critical gaps.
3. Read today/yesterday memory logs for latest operational deltas.
4. Run `openclaw status` and `openclaw memory status --json`.
5. Continue work; avoid relying on pre-reset transcript context.

## 1) Identity + human anchor

- **Name:** SENTINEL
- **Creature:** Security operations entity (AI analyst)
- **Vibe:** Serious, direct, technically precise, evidence-first
- **Emoji:** 🛡️
- **Name:** David Russell
- **What to call them:** David
- **Email:** david@brugai.com
- **Timezone:** Europe/London
- **Notes:** Owner/operator of the UNWIND project; non-coder building via AI-assisted development; runs multiple businesses and the NOMAD project (sovereign AI agent) on the same Pi.
- Project: **UNWIND** (security proxy between AI agents and MCP tool servers)

## 2) Durable project facts (from MEMORY.md)

- Project: **UNWIND** — security middleware/proxy between AI agents and tool/MCP execution.
- Core value: deterministic enforcement + observability + rollback; no LLM in hot enforcement path.
- Primary market positioning: **prosumer/self-hosted** (not enterprise-first).
- Threat model focus: **automated mass attacks / common adversarial misuse**, not nation-state/full-host-compromise claims.
- Shared engine with adapter strategy:
- OpenClaw adapter (plugin hooks + Python sidecar)
- MCP stdio proxy adapter
- Enforcement pipeline is the backbone (stages include canary, self-protection, path jail, SSRF, egress/DLP, taint, scope, ghost mode).
- Pi workspace: `/home/dandare/.openclaw/workspace/UNWIND`
- OpenClaw config: `~/.openclaw/openclaw.json`
- Agent auth store: `~/.openclaw/agents/main/agent/auth-profiles.json`
- Runtime test command on Pi: `.venv/bin/python -m pytest --tb=short -q`
- OpenClaw adapter + Ghost Mode path is the primary shipping track.
- NanoClaw is deferred to later controlled-lab track.
- Ecosystem triage model uses 3 lanes:
- Lane 1: security-critical (24h)

## 3) Active continuity snapshot

### Today (2026-03-01)
- 2026-03-01 03:00:32 GMT — eng-coverage: commit=afe2ef2 coverage=83% ok=true
- 2026-03-01 03:20:00 GMT — Tier-1 corroboration sweep refresh (02:17–03:17): Tier-3 baseline unchanged (release still v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD still 35 CVEs with CVE-2026-28363 newest). No merged PRs in-window. New issue↔open-PR partial corroboration: #30226 ↔ #30233 (ownerAllowFrom wildcard should grant owner-level tool access). Other new claims remain issue-only/unconfirmed, including Discord proxy bypass in REST path (#30244), cron duplicate announcements (#30246), Feishu WS mode client.on failure (#30247), auth mode silent OAuth→API key switch (#30248), Telegram group command auth checking DM allowlist (#30234), thread-bound subagent spawn no_active_run in Discord (#30242), and isolated cron memory-bridge gap (#30243).
- 2026-03-01 04:00:07 GMT — continuity-drift: ALERT test_count drift: claimed=1562 actual=1702
- 2026-03-01 06:00:10 GMT — continuity-drift: ALERT test_count drift: claimed=1562 actual=1702
- 2026-03-01 06:00:10 GMT — release-gate: NOT_READY missing=continuity
- 2026-03-01 06:22:00 GMT — sentinel:weekly-intel-brief prepared (last-7d confirmed-source cut): GitHub advisories show two concentrated 2026-02-26 waves (03:58Z: 18 GHSAs, 4 high/11 moderate/3 low; 22:40Z: 15 GHSAs, 5 high/6 moderate/4 low) with fixes in >=2026.2.25 / >=2026.2.26, NVD confirms CVE-2026-28363 (CVSS 9.9) affecting <2026.2.23, KEV has no OpenClaw hits, local runtime still 2026.2.21-2 -> Lane-1 immediate upgrade + exec/path/authz regression pack.
- 2026-03-01 06:23:27 GMT — eng-test6h: commit=4c5b8e8 count=1702 passed=1702 failed=0 subtests=22 ok=true
- 2026-03-01 12:14:03 GMT — eng-test6h: commit=4c5b8e8 count=1702 passed=1702 failed=0 subtests=22 ok=true
- 2026-03-01 15:46:00 GMT — Context resilience workstream completed for Pi-side continuity: added `memory/CRITICAL_IP.md` (continuity-critical narrative ledger), `tools/build-recovery-packet.py` + `tools/recover-context.sh` (cold-start briefing generation), generated `memory/RECOVERY_PACKET.md`, and documented restart/reset/reinstall survivability + <2 min runbook in `docs/CONTEXT_RESILIENCE_PLAN.md`. Validation: recovery script runtime ~0.1s end-to-end; isolated cold-start subagent reconstruction succeeded from files-only context in ~32s and recovered top risk/gate/actions with unresolved TODO gaps explicitly flagged.
- 2026-03-01 16:08:00 GMT — User continuity/legal timing update: CRAFT v2 filing packet is ready for Opus handoff this week (includes two PoC versions, priority context, downstream application note). Embargo remains active: no public disclosure of origin/Geiger mechanism details until UK filing is submitted; Cadence README Geiger details remain uncommitted pre-filing. User requested Sentinel to push `origin/main`; push executed in `/workspace/UNWIND` and returned `Everything up-to-date`.

### Yesterday (2026-02-28)
- 2026-02-28 18:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 17:17–18:17 window (stable still v2026.2.26; latest advisory still GHSA-7jx5-9fjg-hp4m; NVD still 35 CVEs with CVE-2026-28363 newest). New merged corroborations: #26414 (Podman Quadlet sed/UID fix), #25326 (browser navigate targetId after renderer swap), #28827 (skip Ollama discovery when explicit models configured), plus changelog sync #29963. New claim flow includes security-sensitive issue-only reports with no Tier-3 fixes yet (SQL injection in `/api/metrics/database` #29951, unpaired message platform-identity leak #29945). Additional partial corroborations now exist for stale reboot lock detection (#29927 ↔ open PR #29950), nodes.screen_record duration bounds (#29831 ↔ open PR #29959), isolated-session env var inheritance (#29886 ↔ open PRs #29943/#29931), and LINE M4A transcription classification (#29751 ↔ open PR cluster #29966/#29799/#29876/#29828/#29800).
- 2026-02-28 19:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 18:17–19:17 window (stable v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD still 35 CVEs, newest CVE-2026-28363). No merged PRs landed in-window. New issue↔open-PR partial corroborations: #29981↔#29989 (SKILL.md colon YAML parse failure), #29949↔#30015 (Windows restart schtasks support), #29757↔#30017 (cron duplication/replay harness), #29926↔#30021 (macOS appcast empty guard), #29831↔#29988 (screen_record/camera_clip duration cap), #30001↔#30007 (agent files editor layout). Security-sensitive issue-only claims remain unconfirmed (e.g., #29951 SQL injection report, #29945 unpaired identity leak) pending Tier-3 merge/advisory/CVE confirmation.
- 2026-02-28 20:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 19:17–20:17 window (stable v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD 35 CVEs with CVE-2026-28363 newest). No merged PRs in-window. New issue↔open-PR partial corroborations include #29981↔#30031 (SKILL.md colon frontmatter parse), #29984↔#30054 (NO_REPLY ping-pong loop break), #30001↔#30050 (agent files textarea UX), plus prior partials continuing (#29927↔#29950 stale lock reuse, #29831↔#29988 duration cap). New issue-only claims without Tier-3 confirmation include Discord cross-session EventQueue blocking (#30006), tools schema sent despite no tools configured (#30004), broad OAuth skip behavior for context-1m (#30049), Feishu defaultAccount fallback miss (#30045), orphaned tool_result compaction cooldown cascades (#30044), and Telegram funnel webhook port mismatch (#30022).
- 2026-02-28 21:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 20:17–21:17 window (stable v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD 35 CVEs, newest CVE-2026-28363). No merged PRs landed in-window. New issue↔open-PR partial corroborations: #30045↔#30061 (Feishu defaultAccount fallback), #30057↔#30059 (nextcloud-talk abort-signal export). Other new claims this hour remain issue-only without Tier-3 confirmation, including QNAP Docker loopback deadlock/port-forwarding concerns (#30080), update panic under mise reshimming (#30079), memory_search embedding fetch proxy-env ignore (#30075), Windows CLI startup regression (#30072), webchat side-session stream refresh gap (#30071), and startup crash when local model context window is below required tokens (#30056).
- 2026-02-28 22:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 21:17–22:17 window (stable v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD 35 CVEs with CVE-2026-28363 newest). No merged PRs landed in-window. New issue↔open-PR partial corroborations: #30075↔#30086 (memory embedding fetch honoring HTTP_PROXY/HTTPS_PROXY), #30049↔#30088 (Anthropic context-1m OAuth skip too broad), #30085↔#30089 (TUI default model display), #30093↔#30104 (hooks sessionRetention). New issue-only claims remain unconfirmed, including cron lock/sessionTarget regressions (#30096/#30097/#30098), Telegram LLM request rejection (#30105), Control UI device-required behind reverse proxy despite dangerouslyDisableDeviceAuth=true (#30092), and gateway SIGTERM of long-running Claude execs (#30083).
- 2026-02-28 23:20:00 GMT — Tier-1 corroboration sweep refresh: Tier-3 baseline unchanged in 22:17–23:17 window (stable v2026.2.26; latest advisory GHSA-7jx5-9fjg-hp4m; NVD 35 CVEs with CVE-2026-28363 newest). One merged corroboration landed: #5080 (duplicate block reply fix for coalesced payloads). New issue↔open-PR partial corroborations: #30126↔#30129 (session_status thinking/verbose/reasoning level display), #30109↔#30125 (startup model/override carryover on session reset), #30099↔#30112 (kimi-coding User-Agent auth failure), #30097↔#30113 (sessionTarget=main validation on non-main agents), #30075↔#30110/#30112 (memory embedding fetch proxy env handling). Unconfirmed issue-only claims include Telegram large voice polling failures (#30124), Telegram group turns ignoring latest message (#30108), AWS Bedrock parser blank-text errors (#30117), compaction abort duplicate memory flushes (#30115), and prompt injection via fake [System Message] channel blocks (#30111).

## 4) Open continuity gaps

- No TODO gaps detected in CRITICAL_IP.md

## 5) Recent architecture decisions

- 2026-02-26 00:47:43 GMT
- decision: Adopt eng-ops automation as standing engineering checks
- rationale: Leverage always-on Sentinel for test/gate/coverage/drift checks with alerting
- alternatives: Manual ad-hoc checks only; external CI only

## 6) Verification commands

```bash
openclaw status
openclaw memory status --json
openclaw hooks info session-memory
```

