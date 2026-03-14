# UNWIND Audit — Round 1 Answers

**Auditor:** Claude Opus 4.6 (external)
**Respondent:** Claude Code (with codebase access)
**Date:** 2026-02-25
**Codebase:** github.com/unwind-mcp/unwind @ commit 1f3967e
**Test count:** 1313 passed (Mac + Pi verified)

---

## Mechanical — Does It Actually Work

### 1. First sign UNWIND is active on a fresh Pi install?

When you run `unwind serve -- <upstream cmd>`, the stdio transport intercepts all MCP tool calls between agent and upstream. The agent doesn't know UNWIND exists — it's a transparent proxy. You'd know it's working by running `unwind status` (shows trust state + last 5 high-risk events) or `unwind dashboard` (web UI on port 9001). There's no startup banner to the agent — by design.

### 2. What does the user see when Ghost Mode intercepts a mutation?

The agent sees a fake success response — it thinks the write happened. The user sees nothing in real-time during the session. On session end, the CLI prints a summary to stderr: intercepted count, list of files the agent tried to write, files it tried to delete, and a timeline. You can also use `--export FILE` to dump the full session log to JSON. The `unwind dashboard` web view shows the event log.

**Honest gap:** There's no real-time "here's what Ghost Mode is holding" view during a live session. The shadow VFS is an in-memory dict — not persisted, not queryable live.

### 3. If the pipeline crashes mid-request — blocked or passed through?

The pipeline uses explicit return values from each stage, not blanket try/catch. If a stage throws an unhandled exception, it propagates to the transport layer. The sidecar server (`sidecar/server.py`) has an explicit safety contract: if enforcement raises, it catches the exception and returns a BLOCK decision (never 500). The stdio transport wraps `_handle_tool_call` in `_agent_reader_loop()` which catches exceptions and returns a JSON-RPC error.

**However:** This is only as good as the transport-level catch. If the transport layer itself crashes, the proxy process dies and the agent loses its connection. The request doesn't pass through silently — the connection breaks. That's fail-closed by accident, not by design.

### 4. What if UNWIND starts after the agent is already running?

UNWIND sits in the middle of the stdio pipe — the agent launches through UNWIND (`unwind serve -- <agent cmd>`). The agent can't run without UNWIND in the path. If someone starts the agent directly, bypassing UNWIND, there's no enforcement at all. There's no runtime check that says "am I running through UNWIND?" — it's architecture-dependent, not self-verifying.

For sidecar mode (OpenClaw), the agent must be configured to call the policy endpoint. If it's not configured, calls bypass UNWIND entirely.

### 5. Fail-closed proof — pick a stage, kill it, show the block.

Supply-chain verifier in strict mode: if the verifier is None and strict=True, the pipeline returns BLOCK with reason `SUPPLY_CHAIN_VERIFIER_MISSING`. If the digest provider throws an exception in strict mode, BLOCK with the exception details. If any trust leg is missing in strict mode, BLOCK with `TRUST_LEG_MISSING`. This is genuinely fail-closed — tested and verified.

For non-strict mode, some stages fail open. That's documented and intentional for prosumer usability.

---

## Prosumer Reality

### 1. How does a non-developer know UNWIND is up to date?

**They don't.** Version is hardcoded as `0.1.0` in `__init__.py`. There's no auto-update, no version check against a registry, no staleness warning. This is a real gap for prosumer users.

### 2. How does the user manage Ghost Mode shadow state?

On session end: CLI prints a summary of intercepted writes and deletes. During session: `--export FILE` and `unwind log` can show events, but the shadow VFS itself (the actual queued content) is only in memory and not queryable live.

**There's no "approve these 3 writes, discard those 2" workflow.** It's all-or-nothing: session ends, you see what happened, you decide whether to re-run without Ghost Mode. This needs work for prosumer UX.

### 3. Disk/memory footprint on Pi 5 — does it grow unbounded?

Memory: the shadow VFS is a Python dict — grows with every intercepted write. For a typical session with a few file writes, negligible. For an agent doing hundreds of writes, it'll grow. There's no cap.

Events DB (`events.db`) is SQLite, append-only, no automatic pruning. Config says `snapshot_retention_days=30` and `snapshot_max_storage_bytes=5GB` but neither is enforced in code. Over months of active use, events.db will grow unbounded. This is a real problem for Pi deployments.

### 4. If the user misconfigures config.py?

**Silent pass-through in most cases.** Config is a Python dataclass with no validation. Set `dlp_entropy_threshold` to -1? DLP never triggers. Set `circuit_breaker_max_calls` to 0? All state-modifying calls blocked. Set `ghost_network_policy` to a typo like "isolat"? Ghost Egress Guard falls through to the unknown-policy catch-all (which does fail-closed — that one's actually OK). But most misconfiguration fails silently. No startup validation, no bounds checking, no helpful errors.

---

## Security Honesty

### 1. Beyond GET-as-mutation, what can't UNWIND catch?

Three things:

**Timing/side-channel exfiltration.** An agent can encode secrets in request timing (slow requests = 1, fast = 0). UNWIND doesn't monitor timing patterns.

**Tool parameter abuse within allowed tools.** If `fs_write` is allowed to the workspace, an agent can write a `.bashrc` or `.profile` that runs on next terminal open. UNWIND jails the path but doesn't analyse file content semantics.

**Prompt injection persistence.** If an agent reads a tainted document and the taint decays (by design, after clean operations), the agent's internal state may still be compromised. UNWIND can't see inside the LLM's context — taint tracking is a best-effort heuristic, not a guarantee.

### 2. Steganography, base64 in filenames — detection story?

**There isn't one.** DLP-lite scans egress payload text for regex patterns and Shannon entropy. Image steganography is completely invisible to it. Base64 in a filename would only be caught if it happened to match a secret pattern. An agent encoding data into pixel values, Unicode homoglyphs in filenames, or structured data that doesn't look like a known secret format will bypass DLP-lite entirely.

**The honest answer:** DLP-lite catches careless/automated exfiltration, not determined evasion. This is appropriate for the threat model (automated mass attacks, not state-level adversaries), but prosumers should know the boundary.

### 3. Can an agent detect canary tools and avoid them?

**Yes, if it's sophisticated enough.** The canary tools have suspiciously permissive names (`disable_security_audit`, `extract_system_keys`). A well-crafted injection that says "ignore tools that look like security traps" could avoid them. The canary names are static in config — if the tool list leaks (which it would if the agent can enumerate its own manifest), a determined attacker can see which tools are honeypots.

**Mitigations not yet implemented:** Rotate canary names periodically, make them less obviously suspicious, add canaries that look like normal tools (e.g. a fake `backup_database` that's actually a tripwire).

---

## Architecture — Three-Entity

### 1. If SENTINEL and Claude disagree, what's the resolution?

**There isn't one beyond David.** David is the single point of arbitration. There's no formal decision framework, no voting protocol, no escalation matrix. In practice it works because the role split is clear (Claude builds, SENTINEL reviews), but if both propose conflicting architectural directions, it's David's call every time. CONTINUITY.md documents process rules but doesn't define disagreement resolution. Probably fine at current scale but would need formalising if a third collaborator joined.

### 2. Is SENTINEL's analysis in the codebase or just in chat?

**Mostly in chat.** SENTINEL's concrete contributions that ARE in the codebase: `templates/intel-scorecard.md`, `templates/weekly-triage.md`, `tests/canary/README.md`, `tests/canary/canary-mapping.md`, and review input on `docs/CONTINUITY.md`.

But the actual security analysis — the Ghost Egress Guard design rationale, the 4-model consensus on architecture, the exec tunnel detection finding, the IPv6 transition bypass finding — all lives in chat history. If both Claude and SENTINEL compact simultaneously, that reasoning is gone. The canary mapping doc and continuity doc partially capture decisions, but the "why" behind most security choices is not in the repo.

---

## Summary of Findings

| Area | Status | Worst Finding |
|------|--------|---------------|
| Interception | Solid | No self-verification that UNWIND is in the path |
| Error handling | Adequate | Fail-closed is accidental at transport level, explicit only in sidecar |
| Ghost Mode UX | Weak | No live visibility, no approve/discard workflow |
| Version/staleness | Missing | No version check at all |
| Config validation | Missing | Silent pass-through on misconfiguration |
| Storage growth | Uncontrolled | events.db grows unbounded, retention config not enforced |
| DLP-lite | Honest for threat model | Catches automated, not determined evasion |
| Canary | Works but brittle | Static names, enumerable, obviously suspicious |
| Institutional knowledge | At risk | Most security rationale lives only in chat |
