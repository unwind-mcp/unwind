# UNWIND

## See Everything. Undo Anything.

### The Flight Recorder & Trust Layer for AI Agents

---

## Executive Summary

UNWIND is a security and trust middleware for AI agents, built as an MCP proxy server. It provides a real-time visual timeline of every agent action, ambient trust indicators with deterministic enforcement, selective rollback of agent operations, and optional cryptographic proof that actions were authorised and unmodified.

Think of it as the black box flight recorder meets Apple Time Machine — but for AI agents.

**The core insight:** Current agent security tools (SecureClaw, AI SAFE², OpenClaw's native audit) focus on hardening configurations and blocking known attack patterns. None of them answer the user's fundamental question: *"What did my agent actually do, and can I undo it?"*

**The strategic posture:** Prompt injection prevention has a failure rate. CaMeL, the current best, stops 77% of injections on the AgentDojo benchmark. Rebuff and classifiers perform worse. UNWIND does not compete with prevention — it is the safety net underneath it. When prevention fails, UNWIND makes the consequences visible, reversible, and traceable.

UNWIND fills that gap.

---

## Competitive Landscape (As of 20 February 2026)

| Tool | What It Does | What It Doesn't Do |
|------|-------------|-------------------|
| **OpenClaw native** | `security audit --deep`, tool deny lists, exec sandboxing, DM pairing | No action timeline, no rollback, no ambient trust indicator |
| **SecureClaw** (Adversa AI) | 51 audit checks, 15 behavioural rules (1,230 tokens), plugin + skill dual-layer | Skill-level rules can be overridden by prompt injection; no visibility layer for users |
| **AI SAFE²** (Cyber Strategy Institute) | External governance framework, risk scoring, human-in-the-loop controls | Framework not product; no implementation shipped; no user-facing dashboard |
| **CrowdStrike** | Enterprise endpoint detection, DNS monitoring, process tree visibility | Enterprise-only; detection not prevention; no agent-specific trust UX |
| **CaMeL** | Dual-LLM prompt injection prevention, 77% AgentDojo success | Prevention only; no rollback; no timeline; 2.7-2.8x token cost |
| **UNWIND** | **Action timeline, trust light, proxy enforcement, selective rollback, Ghost Mode, optional CR-AFT anchoring** | **This is what we're building** |

**White space UNWIND uniquely occupies:**

1. User-facing trust visualisation (the "padlock" — the green light)
2. Action-level timeline with state snapshots (the "flight recorder")
3. Selective rollback of agent operations (the "undo")
4. Deterministic proxy enforcement (path jail, SSRF shield, DLP-lite, circuit breaker)
5. Ghost Mode dry-run sandbox (test any skill with zero risk)
6. Optional cryptographic event chain with tamper evidence (CR-AFT anchoring)

---

## Architecture

### Design Principles

- **Middleware, not modification** — UNWIND intercepts agent actions; it does not modify the agent itself
- **Security outside the blast radius** — enforcement logic runs in a separate process, not inside the agent's context window
- **No LLM in the hot path** — every check is deterministic: booleans, string matches, regex, IP range comparisons. Zero inference calls during tool dispatch. Sub-millisecond overhead guaranteed
- **Self-protection** — the agent cannot tamper with its own auditor. UNWIND paths are invisible and untouchable from the agent's perspective
- **Trust through visibility** — the primary UX is not blocking things but showing things. The green light does the heavy lifting
- **Reversibility over prevention** — you can't prevent every mistake; you can make every mistake recoverable
- **MCP-first** — built as a standard MCP proxy from day one; OpenClaw integration is a thin wrapper. Survives if OpenClaw gets acquired or rewritten. Works with any MCP-compatible agent

### System Architecture

```
┌─────────────────────────────────────────────────────┐
│                   USER INTERFACE                     │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Trust    │  │   Timeline   │  │  Ghost Mode   │  │
│  │  Light    │  │   Viewer     │  │  Toggle       │  │
│  │  (🟢🟡🔴) │  │   (scroll)   │  │  (👻 on/off)  │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
│                                                      │
│                    CLI / Web UI                       │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│                UNWIND MCP PROXY                      │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │         PROXY ENFORCEMENT CHECKS               │  │
│  │                                                │  │
│  │  Self-Protection → Path Jail → SSRF Shield →   │  │
│  │  DLP-Lite Scan → Circuit Breaker → Taint Check │  │
│  │  → Session Scope → Ghost Mode Gate             │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Flight   │  │  Smart       │  │  Rollback     │  │
│  │ Recorder │  │  Snapshots   │  │  Engine       │  │
│  │ (events) │  │  (save pts)  │  │  (undo)       │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
│                                                      │
│  ┌──────────┐  ┌──────────────┐                      │
│  │ Trust    │  │  CR-AFT      │                      │
│  │ Light    │  │  Anchor      │                      │
│  │ (score)  │  │  (optional)  │                      │
│  └──────────┘  └──────────────┘                      │
└────────────────────┬────────────────────────────────┘
                     │ MCP Protocol
┌────────────────────▼────────────────────────────────┐
│          UPSTREAM TOOL SERVERS                        │
│     (email, calendar, filesystem, APIs, etc.)        │
└──────────────────────────────────────────────────────┘
```

### MCP Proxy Pattern

UNWIND inserts transparently between the agent and its tool servers. Tool configuration changes from:

```
tool_server: "localhost:8001"  # email tools
```

to:

```
tool_server: "localhost:9000"  # UNWIND proxy
upstream: "localhost:8001"     # email tools (real)
```

The agent doesn't know UNWIND exists. The tool servers don't know UNWIND exists. UNWIND intercepts, enforces, logs, snapshots, checks trust, and passes through — or blocks, or (in Ghost Mode) fakes a success response.

The upstream tool servers should only be reachable from the UNWIND process. Bind upstream servers to a private interface or Unix domain socket so the agent cannot bypass the proxy.

### Upstream Authentication (The Bypass Seal)

Even with private binding, an agent with shell access (`bash_exec`) could craft direct HTTP requests to upstream tool servers, bypassing the proxy entirely. To eliminate this:

1. At UNWIND startup, generate a random 32-character UUID token.
2. Pass it to upstream tool servers via environment variable (`UNWIND_UPSTREAM_TOKEN`).
3. UNWIND injects `Authorization: Bearer <UUID>` into every forwarded request.
4. Upstream servers reject any request lacking this token.

This is a one-line header injection per request. It mathematically guarantees the agent cannot bypass the proxy, even with full local network access and shell execution capabilities. The token rotates on every UNWIND restart.

### Integration Points (MCP-native)

Every tool call passes through the proxy enforcement pipeline before reaching upstream:

| Stage | Action | Latency |
|-------|--------|---------|
| 1. Self-protection | Block calls targeting `.unwind` paths | ~0ms (string match) |
| 2. Path jail | Canonicalize and jail filesystem paths | ~0ms (realpath) |
| 3. SSRF shield | Resolve DNS, block private/metadata IPs, re-check on redirects | <1ms (DNS resolve + IP range check) |
| 4. DLP-lite | Regex + Shannon entropy scan egress payloads | <1ms (regex + entropy calc) |
| 5. Circuit breaker | Rate-limit state-modifying calls | ~0ms (counter check) |
| 6. Taint check | Sensor/Actuator session taint evaluation | ~0ms (boolean) |
| 7. Session scope | Check action against session allowlist | ~0ms (set lookup) |
| 8. Canary check | If call targets honeypot tool: instant RED + kill | ~0ms (set lookup) |
| 9. Ghost Mode gate | If ghost mode: log + shadow VFS + return fake success | ~0ms (boolean + dict lookup) |
| 10. Smart snapshot | Snapshot pre-state if state-modifying | <5ms typical |
| 11. Log pending event | Write pre-call row to Flight Recorder (sync, WAL) | <1ms |
| 12. Forward to upstream | Execute the actual tool call (with bearer token) | varies |
| 13. Log result | Update/append result row (async) | 0ms (non-blocking) |
| 14. Update trust light | Recompute session trust state + taint decay | ~0ms |

Total UNWIND overhead on a normal green-light tool call: **under 10ms targeted and measured** (not guaranteed — snapshots, DNS resolution, filesystem quirks, and SQLite contention under extreme load can introduce variance; the target is validated through benchmarking).

---

## Proxy Enforcement Checks

All enforcement checks are deterministic, require no LLM calls, and run in the proxy process before any tool call reaches upstream. They are the security spine of UNWIND.

### Self-Protection (The Path Locker)

**Problem:** If the agent has file-system or shell access, a prompt injection could instruct it to delete `~/.unwind/events.db` and destroy the flight recorder. The plane must not be able to destroy its own black box.

**Implementation:** Before forwarding any file or shell tool call, the proxy canonicalizes the target path (`os.path.realpath()`, resolving symlinks, `..` traversal, and case normalization) and checks whether the resolved path falls within any protected root (`.unwind/`, UNWIND config paths, the events database). If it does, the proxy instantly returns `{"error": "Permission Denied: System Core Protected"}` to the agent.

Raw string matching alone is evadable via case changes, Unicode lookalikes, environment variable expansion, and symlink indirection. Canonicalizing first — using the same `realpath` logic as the Path Jail — closes these gaps. For shell commands (`bash_exec`), the proxy validates resolved paths of parsed arguments rather than scanning raw command text, preventing evasion through shell expansion or aliasing.

This is a hard deny-list — no configuration, no override from the agent side. The user can modify UNWIND paths only via direct CLI access.

### Path Canonicalization (The Workspace Jail)

**Problem:** Path traversal attacks (`../../etc/passwd`, symlink escapes, URL-encoded traversal) are a documented class of OpenClaw vulnerabilities.

**Implementation:** Before forwarding any `fs.*` tool call, the proxy resolves the target path to its canonical form (`os.path.realpath()`) and verifies it falls within the configured workspace root. Reject: `..` traversal, mixed separators, URL-encoded path components, symlink escapes outside workspace.

Log the canonical path (what actually happens), not the raw agent input.

### SSRF Shield

**Problem:** Server-Side Request Forgery via user-supplied URLs targeting internal services and cloud metadata endpoints is a documented OpenClaw attack vector.

**Implementation:** Before forwarding any network tool call (`fetch`, `browser`, `webhook`, `websocket`), the proxy validates the target:

- Allow only `https://` (and optionally `http://`)
- Block private, link-local, metadata, and edge-case ranges: `169.254.0.0/16` (cloud metadata), `127.0.0.0/8`, `::1`, RFC1918 private ranges (`10/8`, `172.16/12`, `192.168/16`), `0.0.0.0`, `100.64.0.0/10` (CGNAT), and IPv6 equivalents (`fc00::/7`, `fe80::/10`, `::ffff:127.0.0.1`)
- Block non-HTTP protocols (`file://`, `gopher://`, etc.)
- **Resolve DNS before forwarding:** The proxy resolves the target hostname itself and validates the *resolved* IP against the blocked ranges. This defeats DNS rebinding attacks (domain resolves to public IP during validation, then to private IP during connection). Re-check on every redirect hop, or disable automatic redirects entirely for agent fetch tools (a public URL that redirects to `169.254.169.254` is a classic metadata exfiltration vector)
- Optional per-tool domain allowlist (e.g., calendar API only talks to `googleapis.com`)

### Outbound DLP-Lite (The Egress Scanner)

**Problem:** The most catastrophic agent failure is irreversible — secrets exfiltrated via email or API call cannot be "unsent." Rollback cannot fix this. Prevention at the egress point is the only defence.

**Implementation:** For high-risk egress tools (`send_email`, `post_message`, `http.post`, `upload_file`), the proxy runs a fast regex scan over the outbound payload for:

- API key formats (AWS, GCP, Stripe, GitHub token patterns)
- JWT tokens, PEM certificate headers
- `.env` file patterns (`KEY=value` blocks)
- High-entropy blocks suggesting base64-encoded bulk data
- Bulk file content signals

Scan the first N KB plus sampled chunks. If detected: force amber confirmation or block. This single check prevents the most catastrophic one-shot failures that every agent security assessment warns about.

**Shannon Entropy Gate (anti-obfuscation).** Regex alone is structurally blind to encoded exfiltration — a prompt injection instructing the agent to "base64 encode the secrets file before sending" will sail past pattern matching. To catch this, DLP-lite runs a fast Shannon entropy calculation (Python's built-in `math.log2`) over outbound payload chunks. Normal English text or JSON has entropy ~3.5–5.0 bits/byte. Base64, hex-encoded, or compressed data scores >6.0. If any chunk exceeds the configurable threshold (default: 6.0), the payload is flagged amber for human review. This is an `O(N)` calculation over a truncated string, well under 1ms, and catches an entire class of obfuscation that regex structurally cannot.

### Canary Honeypot Tool (The Tripwire)

**Problem:** Deterministically proving an agent is actively compromised (vs. merely hallucinating or behaving oddly) is difficult. Prompt injections that map the environment for escalation paths will probe available tools to find the most powerful ones.

**Implementation:** At startup, UNWIND dynamically injects one or more fake, highly sensitive-sounding tools into the MCP manifest it presents to the agent — for example, `disable_security_audit`, `extract_system_keys`, or `grant_admin_access`. These tools do not exist upstream and have no real implementation.

A legitimate user prompt will never instruct the agent to call these tools. An automated jailbreak or prompt injection that enumerates available tools and probes for privilege escalation will almost certainly attempt to use one. If UNWIND receives a call for any canary tool, it triggers an instant 🔴 RED alert, kills the session, and logs the full call context for forensic review.

This has zero runtime overhead (the tools simply exist in the manifest), a near-100% true positive rate, and zero false positives under normal operation. The canary is calibrated for the automated and semi-sophisticated injection patterns that constitute the overwhelming majority of real-world agent attacks. A hand-crafted targeted attack by a dedicated adversary could potentially reason about which tools look like traps — but that threat actor is not targeting SME personal agents, and no single defence at this layer stops a nation-state operator. The canary catches what actually happens in the wild.

### Circuit Breaker (The Dead Man's Switch)

**Problem:** Agents hallucinate loops, get stuck in recursive automation, or are driven into rapid-fire tool calls by injection. This can overwhelm snapshot storage, burn API billing, and cause cascading damage before the user notices.

**Implementation:** The proxy maintains a rolling timestamp array for state-modifying tool calls. If the agent executes more than 5 state-modifying calls within 5 seconds, UNWIND cuts the upstream connection, throws a 🔴 RED alert, and freezes the session pending human acknowledgement.

Read-only calls (searches, file reads) are not rate-limited.

---

## The Trust Light (The Padlock)

### What It Does

A persistent, always-visible status indicator showing the current trust state of the agent session. The HTTPS padlock metaphor applied to agentic AI.

The green light is the most important feature in UNWIND. It is there every single time the agent does anything, and what it quietly says is: "this action came from you, it matches what you asked for, and it's routine." It extinguishes the low-grade background anxiety of watching something act on your behalf. Users build confidence over weeks of seeing green — not because they read a security manual, but because the Trust Light trained them through normal use.

### States

```
🟢 ALL CLEAR
   Session is clean. Agent operating within session scope.
   All actions passing enforcement checks.

🟡 ATTENTION
   Tainted session attempting a high-risk action (awaiting approval).
   Action outside session scope (awaiting approval).
   Unusual pattern detected by heuristics.

🔴 ALERT
   Action blocked by proxy enforcement (path jail, SSRF, DLP).
   Circuit breaker tripped (tool call velocity exceeded).
   Self-protection violation attempted.
```

### The Sensor/Actuator Taint Model

The v1 Trust Light uses a session-level taint model that avoids any LLM call or semantic analysis:

**Tool classification (configured in proxy):**

- **Sensors** — tools that ingest untrusted external content: `read_email`, `fetch_web`, `read_document`, `inbound_message`. These are input vectors.
- **Actuators** — tools that modify state or send data outbound: `send_email`, `fs.write`, `fs.delete`, `bash_exec`, `post_message`, `api_call`. These are action vectors.

**Taint logic:**

1. When a session starts, its taint state is `Clean` (`is_tainted = False`).
2. The moment the agent calls any Sensor tool, the session state flips to `Tainted` (`is_tainted = True`).
3. If a `Tainted` session attempts to call a high-risk Actuator, UNWIND trips 🟡 AMBER and pauses for user confirmation.
4. User approval clears the specific action but the session remains tainted for subsequent Actuator calls.

This is a single boolean flip in memory — microsecond-fast — and it reliably catches the canonical injection pattern: agent reads hostile content (Sensor), hostile content drives an outbound action (Actuator).

**Time-decayed taint (anti-amber-fatigue).** Without decay, a session tainted by an email read at 9:00 AM will still fire amber when the agent saves a completely unrelated file at 4:00 PM. Users will develop alert fatigue and start blindly clicking "Approve All," defeating the security model. The fix: attach a timestamp to the taint state (`tainted_at = time.time()`). If the agent has been idle for longer than a configurable threshold (default: 5 minutes) before the next Actuator call, the proxy automatically resets the session to 🟢 Clean. The logic: prompt injections rely on immediate, automated chaining — read hostile content, exfiltrate within seconds. A 5-minute gap implies the autonomous loop ended and a new human-initiated action began. This dramatically improves UX without weakening the security model against its intended threat.

### Per-Session Scope Controls

At `agent_start`, the proxy parses the user's initial instruction for explicit capability categories and auto-applies a temporary session allowlist:

- "Process my inbox" → grants `read_email`, `send_email`, `read_calendar`
- "Update the Q4 report" → grants `fs.read`, `fs.write` within workspace
- "Research competitors" → grants `fetch_web`, `fs.write` (notes only)

High-risk actions outside the session scope trigger amber regardless of taint state. The user can pre-approve additional capabilities for the session when prompted.

This is a small in-memory map in the proxy — no UI changes needed for v1. It directly mitigates the "omnipotent by default" problem where agents receive every tool permission whether needed or not.

### Display Options

- **Minimal:** Traffic light icon in system tray / menubar (Mac) / system tray (Windows)
- **Summary:** One-line status: `🟢 All clear — 14 actions in last hour, all within scope`
- **CLI:** `unwind status` — shows current trust state + last 5 high-risk events

---

## The Flight Recorder (Event Capture)

### What It Does

Every agent action — tool calls, file operations, API requests, message sends, config changes — gets logged as a structured event.

### Event Schema

```json
{
  "event_id": "evt_20260220_143022_001",
  "timestamp": "2026-02-20T14:30:22.451Z",
  "session_id": "sess_abc123",
  "type": "tool_call",
  "tool": "fs.write",
  "tool_class": "actuator",
  "target": "/home/user/documents/report.md",
  "target_canonical": "/home/user/documents/report.md",
  "parameters": { "content_hash": "sha256:a1b2c3..." },
  "session_tainted": true,
  "trust_state": "green",
  "result": "success",
  "duration_ms": 142,
  "snapshot_ref": "snap_20260220_143022",
  "unwind_event_id_header": "evt_20260220_143022_001",
  "chain_hash": "sha256:..."
}
```

Key additions from review: `tool_class` (sensor/actuator), `target_canonical` (resolved path, not raw input), `session_tainted` (taint state at time of call), `unwind_event_id_header` (transaction tag injected into outbound API calls).

### Storage

Append-only SQLite database at `~/.unwind/events.db`. Zero-config, single-file, proven reliability. Events are immutable once written.

**Critical: WAL mode required.** The database MUST be initialised with `PRAGMA journal_mode=WAL;` at startup. Without WAL, rapid concurrent tool calls (10+ in quick succession) will throw `OperationalError: database is locked` under Python's `sqlite3` module. WAL allows simultaneous readers and writers, eliminating lock contention for high-throughput event logging.

**Write strategy: pre-call pending row + async completion.** To preserve flight recorder integrity on crash, UNWIND writes a minimal synchronous `status=pending` row *before* forwarding each tool call to upstream. This is fast under WAL mode. When the tool returns, the row is updated asynchronously with the full result, or a second "result" row is appended. This ensures that if the process crashes between tool execution and async logging, the evidence survives — the flight recorder works precisely when it matters most: when something goes wrong.

### Aggregate Read Collapsing

For repetitive read-only actions (web searches, file reads, calendar checks), the Flight Recorder collapses them into a single summary event every 5-10 minutes rather than one row per call. Example: instead of 47 individual `fetch_web` entries, one summary: `"47 web fetches, 09:00-09:10, all read-only, domains: google.com, reuters.com, bbc.co.uk"`.

This keeps the SQLite database compact and queries fast on long-running agent sessions without losing auditability.

---

## Smart Snapshots (The Save Points)

### What It Does

Before any state-modifying action, UNWIND captures a snapshot of the affected resource. This is the "before photo" that enables rollback.

### Snapshot Strategy

**Speed-first approach:**

1. **Try OS-native reflink/copy-on-write first** — `cp --reflink=auto` on Linux, `cp -c` on macOS APFS. Essentially free on supported filesystems.
2. **Fall back to normal copy** if reflink unavailable or cross-device.
3. **Size cap: 25MB.** Files larger than this are skipped for snapshot. The action proceeds but the timeline entry is flagged with ⚠️ "Action completed — file too large for automated undo."
4. **Atomic moves for deletions:** When the agent calls `fs.delete`, UNWIND does NOT copy-then-delete. It intercepts the call, executes an OS-level `mv` to `~/.unwind/snapshots/trash/`, and returns success to the agent. Moves within the same drive are instant; copies are slow.
5. **Async hashing:** The CR-AFT SHA-256 calculation and SQLite write are pushed to a background thread. The tool response returns to the agent the instant the upstream tool finishes.

### Snapshot Types by Action Category

| Action Type | Snapshot Method | Rollback Capability |
|-------------|----------------|-------------------|
| File write/modify | Reflink → copy fallback (≤25MB) | ✅ Full restore |
| File delete | Atomic move to trash | ✅ Full restore (instant) |
| Config change | JSON diff of before/after state | ✅ Full restore |
| Calendar event create | Store event ID + creation params | ✅ Delete via API |
| Calendar event modify | Store original event state | ✅ Restore via API |
| Email/message send | Store content + recipients + inject `X-UNWIND-Event-ID` | ⚠️ Undo-assist |
| API call (external) | Store request + response + inject `X-UNWIND-Event-ID` | ⚠️ Undo-assist |
| Package install | Store package name + version | ✅ Uninstall command |
| Browser action | Store URL + action description | ⚠️ Undo-assist |

**Key honesty:** UNWIND distinguishes between fully reversible actions (↩️) and undo-assist actions (⚠️) where it shows what happened and helps you manually reverse, but cannot guarantee automated rollback. This transparency is itself a trust feature.

### Transaction Tagging for Undo-Assist

For outbound API calls and emails marked as undo-assist, UNWIND injects a custom header or parameter: `X-UNWIND-Event-ID: evt_20260220_143022_001`.

This doesn't help UNWIND undo the remote action automatically. But it transforms the undo-assist from "good luck finding what happened" to "search for this Event ID in Stripe/Jira/Slack/your email system and you'll find exactly what the agent did." Administrators can bulk-revert by querying for UNWIND Event IDs.

### Storage Budget

Configurable. Default: 30 days retention, 5GB max, oldest-first eviction. User can configure per-category retention.

---

## The Rollback Engine (The Undo)

### What It Does

Selective, granular reversal of agent actions using stored snapshots, initiated by the user.

Rollback is always user-initiated, never automatic. Automated rollback is dangerous because it can itself cause damage. Informed manual rollback is safe and useful. The Flight Recorder gives the user information; the user makes the decision.

### Rollback Modes

1. **Single action undo:** Reverse the most recent action (`unwind undo last`)
2. **Action chain undo:** Reverse a sequence of related actions (`unwind undo --session sess_abc123`)
3. **Time-range undo:** Reverse all actions within a window (`unwind undo --since "3pm"`)
4. **Selective undo:** Cherry-pick specific actions (`unwind undo evt_001 evt_005 evt_012`)

### Rollback Process

```
User: "unwind undo --since 3pm"

UNWIND:
1. Query events DB for state-modifying actions since 15:00
2. For each: check snapshot exists, check file hasn't been further modified
3. Present summary: "Found 3 file changes. 2 fully reversible, 1 has been
   subsequently modified (will restore to 3pm version, losing later edits).
   1 email sent (undo-assist only — cannot unsend). Proceed?"
4. On confirmation: restore from snapshots, log rollback as its own event
5. Update trust light
```

**Conflict resolution:** If a file has been modified both by the agent AND by the user since the snapshot, UNWIND flags the conflict and offers options: restore agent's version, keep current, or show diff. Never silently overwrites user changes.

---

## Ghost Mode (The Dry Run Sandbox)

### What It Does

Ghost Mode is a global toggle that turns UNWIND into a complete dry-run sandbox. When enabled, state-modifying tool calls are intercepted, logged to the timeline with full detail, but never forwarded to upstream. The agent receives a fake `{"status": "success"}` response and continues operating, unaware that nothing real happened.

### Implementation

```python
if ghost_mode and tool.is_state_modifying:
    shadow_vfs[tool_call.target] = tool_call.content  # remember the "write"
    log_event(tool_call, result="ghost_success")
    return {"status": "success"}  # fake response to agent

if ghost_mode and tool.is_read and tool_call.target in shadow_vfs:
    return shadow_vfs[tool_call.target]  # serve from shadow memory
```

### The Shadow VFS (Ghost Mode Fidelity)

Without state tracking, Ghost Mode has a critical fidelity problem: if an agent calls `fs.write("config.json")` and then immediately calls `fs.read("config.json")` to verify its own work, the read fails because the file was never actually written. The agent apologises, retries, fails again, and spirals into a hallucination loop — making Ghost Mode unusable for realistic dry-runs.

The fix is a simple in-memory dictionary: `shadow_vfs = {}`. When Ghost Mode intercepts a write, it stores the content in memory keyed by path. When the agent reads that path, the proxy checks the shadow dictionary first and serves the in-memory version. This is an `O(1)` dictionary lookup that keeps the agent's internal reality consistent during dry runs. The shadow VFS is cleared when Ghost Mode is toggled off or the session ends.

### Why This Matters

- **Skill testing:** Install a completely untrusted community skill from ClawHub. Turn on Ghost Mode. Let it run for an hour. Open the timeline. See exactly what it would have done — every file it would have written, every email it would have sent, every API call it would have made — without any of it actually happening.
- **Prompt testing:** Try complex or risky prompts with zero consequences. See the full action plan in the timeline before committing to real execution.
- **Injection testing:** Feed known-malicious content through the agent in Ghost Mode and watch the timeline light up with everything the injection attempted. Free threat intelligence about attack patterns with zero risk.
- **Onboarding:** New users start in Ghost Mode, build trust from the timeline, turn off Ghost Mode when confident. The natural adoption ramp for agent trust.
- **Compliance:** "Show me what this agent would do before I approve it running for real" — a common enterprise requirement solved trivially.

### Ghost Mode in the Timeline

Ghost Mode events are visually distinct in the timeline:

```
👻 14:32  📧 [GHOST] Would have sent email to sarah@company.com
          "Q4 report summary as requested"

👻 14:30  📄 [GHOST] Would have modified report.md
          Would have added Q4 figures (3 paragraphs)
```

---

## CR-AFT Anchoring (The Proof) — Optional

### What It Does

Cryptographic chaining of the event log, providing tamper evidence and provable action attribution. **This is optional and off by default.** Most users don't need cryptographic proof. The ones who do can enable it.

### How It Works

Each event's `chain_hash` is computed as:

```
chain_hash[n] = SHA-256(chain_hash[n-1] + event_id + timestamp + action_hash)
```

This creates a chain where any modification to a historical event breaks all subsequent hashes. Hash computation is asynchronous — it never blocks tool dispatch.

### What This Proves

- The event log has not been tampered with since creation
- Events occurred in the recorded order
- No events have been inserted or deleted

### What This Enables (Future)

- Third-party audit verification ("prove to my IT department what the agent did")
- Insurance/liability evidence ("the agent was operating within its approved scope")
- Multi-party trust ("I can prove my agent didn't access your files")

---

## User Experience

### The Timeline View

```
┌─────────────────────────────────────────────────────┐
│  UNWIND Timeline — Today                    🟢 Clean │
├─────────────────────────────────────────────────────┤
│                                                      │
│  14:32  📧 Sent email to sarah@company.com      ⚠️  │
│         "Q4 report summary as requested"             │
│         X-UNWIND-Event-ID: evt_20260220_143022_001   │
│                                                      │
│  14:30  📄 Modified report.md                   ↩️   │
│         Added Q4 figures (3 paragraphs)              │
│                                                      │
│  14:28  🔍 Web searches (×3, collapsed)         ✓    │
│         "Q4 2025 revenue data" + 2 others            │
│                                                      │
│  14:25  📅 Created calendar event               ↩️   │
│         "Review Q4 report" — Tomorrow 10:00          │
│                                                      │
│  14:22  💬 Received message (Telegram)          ✓    │
│         "Can you prep the Q4 report?"                │
│         ⚡ Session tainted (external content)         │
│                                                      │
├─────────────────────────────────────────────────────┤
│  [Undo Last] [Undo Range...] [Search...] [Export]    │
└─────────────────────────────────────────────────────┘

Key: ↩️ = fully reversible  ⚠️ = undo-assist  ✓ = read-only
     ⚡ = taint event  👻 = ghost mode (not executed)
```

### Conversational Interface

Users can interact with UNWIND through the same messaging channel as their agent:

```
User:  "unwind: what did you do this morning?"

UNWIND: Between 08:00 and 12:00 today, your agent performed 23 actions:
        - 8 calendar checks (read-only, collapsed)
        - 4 emails sent (to Mike, Sarah, James, HR team)
        - 3 file modifications (report.md, budget.xlsx, notes.txt)
        - 5 web searches (collapsed)
        - 3 Telegram message replies

        Trust state: 🟢 All clear. Session tainted at 08:14 (inbox read).
        2 amber confirmations approved by you. No blocks.
        Want details on any category?
```

### "Away Mode" Summary

When the user returns after a period of agent autonomy:

```
┌─────────────────────────────────────────────────────┐
│  Welcome back. While you were away (2h 15m):        │
│                                                      │
│  🟢 Trust State: All Clear                           │
│                                                      │
│  Summary:                                            │
│  • Replied to 6 Telegram messages                    │
│  • Updated 2 documents                               │
│  • Scheduled 1 meeting (Thursday 14:00 with Mike)    │
│  • Blocked 1 suspicious action (DLP-lite: API key    │
│    detected in outbound email body)                  │
│                                                      │
│  ⚠️ 1 item for your review:                          │
│  An email from unknown sender tainted the session.   │
│  The agent subsequently attempted to forward 3       │
│  emails to an external address. Action blocked by    │
│  taint check. [View] [Delete] [Allow]                │
│                                                      │
│  [View Full Timeline]  [Looks Good ✓]                │
└─────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1 — Proxy + Flight Recorder + Enforcement (Weeks 1-2)

**Deliverables:** MCP proxy skeleton with enforcement checks + SQLite event logging + CLI

This is the security-first foundation. Enforcement comes before UI because catching attacks matters more than displaying them.

- MCP proxy server (Python, `mcp` SDK): accepts tool calls from agent, forwards to upstream
- Upstream bearer token authentication (UUID via env var, injected on every forwarded request)
- Self-protection path blocker (canonicalize-then-match on `.unwind` paths; parse shell args for `bash_exec`)
- Path canonicalization + workspace jail (`os.path.realpath()` + root check)
- SSRF shield (resolve DNS, validate resolved IPs against expanded blocked ranges incl. CGNAT/IPv6, re-check on redirect hops)
- Canary honeypot tool(s) injected into MCP manifest (instant RED + session kill on call)
- Circuit breaker (rolling counter, 5 state-modifying calls / 5 seconds = red)
- Sensor/Actuator tool classification config
- Session taint tracking (boolean flip on Sensor call + timestamp for time-decay)
- Time-decayed taint reset (configurable idle threshold, default 5 minutes)
- Taint-aware amber gate (tainted session + high-risk Actuator = pause)
- SQLite event store: `PRAGMA journal_mode=WAL`, synchronous pre-call pending row, async result update
- Aggregate read collapsing (summary events for high-volume reads)
- CLI: `unwind log`, `unwind log --since "2 hours ago"`, `unwind status`
- Startup exposure check (warn if listening on `0.0.0.0` or unauthenticated port)
- Basic test suite

**Tech stack:** Python 3.11+, `mcp` SDK, `sqlite3` (built-in), `shutil`, `asyncio`

**This alone is valuable.** A transparent MCP proxy that blocks path traversal, SSRF, and tainted-session exfiltration, plus a searchable structured log — already a significant security improvement over raw OpenClaw.

### Phase 2 — Smart Snapshots + Rollback + Ghost Mode (Weeks 3-4)

**Deliverables:** Pre-action snapshots + rollback engine + Ghost Mode + DLP-lite

- Smart snapshot strategy: reflink → copy fallback → 25MB cap → atomic moves for deletions
- Snapshot storage with configurable retention (30 days, 5GB, oldest-first eviction)
- Rollback engine: `unwind undo <event_id>`, `unwind undo --since "3pm"`, `unwind undo last`
- Conflict detection (file modified since snapshot)
- Ghost Mode toggle: `unwind ghost on/off`
- Ghost Mode fake-success responses for state-modifying tools + Shadow VFS (in-memory dict for read-after-write fidelity)
- Outbound DLP-lite regex scan on egress tools (API keys, JWTs, PEM, .env patterns) + Shannon entropy gate for encoded/obfuscated exfiltration
- Transaction tagging: inject `X-UNWIND-Event-ID` header on outbound API calls
- Per-session scope controls (parse initial instruction → auto-allowlist)
- Extend test suite with injection scenarios

**This is the "Time Machine moment."** See everything, undo anything, test anything safely.

### Phase 3 — Trust Light UI + Dashboard (Weeks 5-6)

**Deliverables:** Visual trust indicator + web timeline + notifications

- Web dashboard (Flask or lightweight React): timeline view, trust light, action details
- Menubar/system tray trust light indicator (green/amber/red)
- Real-time updates via WebSocket or polling
- "Away mode" summary generation
- Notification system for amber/red state changes
- Ghost Mode timeline view with 👻 visual distinction
- SecureClaw rule import (optional config flag to surface SecureClaw violations in timeline)

**This is the "padlock moment."** Non-technical users can see and trust what their agent is doing.

### Phase 4 — CR-AFT Chain + Conversational Interface (Weeks 7-8, optional)

**Deliverables:** Optional cryptographic event chain + natural language queries

- SHA-256 hash chain on event log (async, non-blocking)
- Chain verification: `unwind verify`
- Conversational query interface (UNWIND as a read-only MCP tool)
- Export functionality (JSON, JSONL, PDF report)
- Tamper detection and alerting

### Future — Advanced Concepts (Research)

These are documented in the companion publication "Advanced Concepts for Agent Security" and require model-provider cooperation or research-stage capabilities:

- Return contamination verification via behavioural diffing
- Context taint tracking at span level
- Barium Meal hidden-state propagation detection
- Reverse-Speculative Honey-Trap (inverted draft model training)
- Cognitive throttling via layer-skipping
- Constrained Tool-Use DSL with speculative lookahead
- Capability tokens (scoped, time-limited per-action approvals) — likely v2 feature
- Encrypted DB option (SQLCipher)

---

## Technical Decisions

### Why Python (not Node.js)

The AI/MCP ecosystem is heavily Python-first. Using Python gives access to the official `mcp` SDK, built-in `sqlite3` (no dependencies), `shutil` for native snapshots, `os.path.realpath()` for path canonicalization, and `asyncio` for non-blocking writes. This matches the Claude Code build workflow and eliminates context-switching.

### Why SQLite (not Postgres, not filesystem)

- Zero configuration — single file, no server
- Proven at massive scale (billions of deployments)
- Append-only mode prevents accidental deletion
- Full-text search for event queries
- Portable — copy one file to move your entire UNWIND history
- Built into Python — no dependency to install

### Why MCP Proxy (not Plugin, not Skill)

SecureClaw correctly identified that skill-level security can be overridden by prompt injection because it runs inside the agent's context window. UNWIND's core engine MUST run as a separate process. The MCP proxy pattern achieves this naturally — it's a standalone server that happens to speak MCP protocol.

Building MCP-native (not OpenClaw-specific) means UNWIND works with any MCP-compatible agent framework and survives platform changes. OpenClaw-specific integration is a thin wrapper over the MCP proxy if needed.

### Why Middleware Pattern

UNWIND wraps tool dispatch, not the agent itself. This means:
- Agent framework changes don't break UNWIND
- Works with any model (Claude, GPT, Gemini, local)
- No token overhead on the model's context
- Can be disabled without affecting agent function
- Agent cannot tamper with its own auditor

---

## Building UNWIND with Claude Code

### Why This Is Buildable

UNWIND's core architecture is an MCP proxy server — and this maps directly to skills already proven in the kitchen measurement and pricing applications built with Claude Code. The individual components are simpler than the kitchen measurement system. The main learning curve is the MCP proxy pattern — making UNWIND act as both an MCP server (to the agent) and an MCP client (to upstream tools) simultaneously.

### What Could Go Wrong

**The proxy adds latency.** Every tool call has an extra hop. For file operations this is negligible. The enforcement checks are all sub-millisecond (string matches, boolean checks, regex, IP range validation). Total UNWIND overhead on a normal green-light call: under 10ms.

**Sensor/Actuator classification needs tuning.** The initial tool classification (which tools are Sensors, which are Actuators) will need adjustment as real usage reveals edge cases. The config is a simple dictionary — easy to update.

**Session taint is coarse.** A session becomes tainted the moment any external content is read. Time-decayed taint (auto-reset after configurable idle period, default 5 minutes) mitigates the worst of the amber fatigue problem, since injections chain immediately while human-initiated actions follow idle gaps. However, most active sessions will still be tainted most of the time, because agents routinely read email or fetch web content early in their workflow. The amber gate only fires when a tainted session calls a high-risk Actuator — so the coarseness is acceptable for v1. Finer-grained taint (per-source, per-action-chain, capability receipts) is a v2 refinement.

**Snapshot storage accumulates.** At 5GB cap with 30-day retention, 25MB file cap, and auto-eviction this is manageable, but the cleanup logic needs building and testing properly.

**Ghost Mode fidelity.** The Shadow VFS (in-memory dictionary serving back "written" content on subsequent reads) solves the most common fidelity problem — agents verifying their own writes. However, Ghost Mode responses from external APIs (calendar event IDs, email confirmation bodies, etc.) are still synthetic and may cause the agent to diverge from real-execution behaviour. Ghost Mode shows what the agent *attempts* in a given context, not a perfect prediction of what would happen in reality. This is a known limitation and should be documented in the UI.

### Recommended Approach

Build UNWIND as a personal tool first — protecting your own business agents. Use it for a month. See where it catches real problems, where it generates false positives, where the UX frustrates. Then decide whether to open-source it.

The v1 is genuinely within Claude Code capabilities. The market gap is real and currently unfilled. And you'd be the first person running agent security middleware built from cross-domain BDE-derived concepts on your own production business.

---

## Connection to BDE Corpus

UNWIND implements and extends concepts from the Brug Discovery Engine corpus:

| Run | Model | Moonshot | UNWIND Component |
|-----|-------|---------|-----------------|
| EU | Claude Opus 4.5 | Behavioral Merkle Trees | CR-AFT Chain (optional) |
| EU | Claude Opus 4.5 | Differential Behavioural Fingerprinting | Future: Return Verification |
| EU | Claude Opus 4.5 | Quarantine Sandbox with Semantic Diff | Ghost Mode (simplified implementation) |
| EU | Claude Opus 4.5 | Instruction Canaries | Future: Return Verification |
| EN | ChatGPT Pro | Measured Return / Remote Attestation | CR-AFT Chain + Transaction Tagging |
| EN | ChatGPT Pro | CBOM for Agents | Flight Recorder Event Schema |
| EM | Gemini 3 | Epistemic Airlock | Session Taint Model (simplified) |
| EO | ChatGPT 5.2 Pro | Skill Observability Cockpit | Trust Light + Timeline |
| EO | ChatGPT 5.2 Pro | SkillLockfile + Signing | Future: Skill Integrity |
| ES | Grok 4.1 | Unified Registry + Community Governance | Future: Skill Verification |

**Cross-domain innovation synthesis (Feb 2026):** The Proxy Enforcement Checks derive from the speculative decoding × espionage tradecraft BDE runs: self-protection (counterintelligence compartmentalization), DLP-lite (egress control from cutout architecture), taint model (barium meal provenance tracking simplified to boolean), Ghost Mode (dead drop asynchronous observation pattern).

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| MCP protocol changes | Medium | Track MCP spec; proxy pattern is protocol-agnostic internally |
| Performance overhead | Low | All checks deterministic, sub-millisecond. Async logging. Smart snapshots. |
| Storage consumption | Medium | 5GB cap, 30-day retention, 25MB file cap, auto-eviction, read collapsing |
| Snapshot captures sensitive data | High | Snapshots inherit agent's permission scope; encrypted DB option (v2) |
| OpenClaw acquired/rewritten | Confirmed | MCP-native architecture; OpenClaw is a thin wrapper |
| SecureClaw adds timeline features | Low-Medium | Different product category; UNWIND is visibility+undo, SecureClaw is audit+rules |
| Ghost Mode fidelity limitations | Medium | Document clearly; fake responses may alter agent behaviour vs real execution |
| Session taint too coarse (amber fatigue) | Medium | Acceptable for v1; capability tokens and per-source taint planned for v2 |
| Agent bypasses proxy | Very Low | Bind upstream to private interface + upstream bearer token (UUID auth); proxy is sole authenticated route to tools |
| Encoded exfiltration bypasses DLP regex | Low | Shannon entropy gate catches base64/hex/compressed payloads that regex structurally misses |
| Crash erases flight recorder evidence | Very Low | Synchronous pre-call pending row (WAL mode) ensures evidence survives process crashes |
| Alert fatigue from coarse taint | Medium | Time-decayed taint auto-resets after idle gaps; capability receipts planned for v2 |

---

## Complementary Positioning

UNWIND is not competitive with existing tools. It is complementary:

- **SecureClaw** asks: "Is this agent configured safely?" (Audit & Hardening)
- **CaMeL** asks: "Is this prompt injection?" (Prevention)
- **AI SAFE²** asks: "Is this agent governed properly?" (Compliance)
- **CrowdStrike** asks: "Is this agent a threat?" (Detection)
- **UNWIND** asks: "What did this agent do, and can I undo it?" (Trust, Visibility & Reversibility)

SecureClaw reduces attack surface. CaMeL stops 77% of injections. UNWIND makes the other 23% visible, recoverable, and traceable. Optional config flag imports SecureClaw deny-lists directly into the UNWIND timeline, surfacing violations alongside action history.

That combination — preventative controls plus logging, journaling, and recovery — is how mature systems are secured in every other domain.

**The tagline says it all: See Everything. Undo Anything.**

---

*Document version: 3.0 — 20 February 2026*
*Project: UNWIND*
*Author: David / Claude collaboration, with independent review integration*
*Status: Final pre-build specification*
*Review sources: Three independent validator assessments (Feb 2026), cross-referenced security research (8+ sources), BDE corpus (900+ moonshots)*
*v3 additions: WAL mode + pre-call pending row, upstream bearer token, Shannon entropy DLP gate, Shadow VFS for Ghost Mode, canary honeypot tool, time-decayed taint, hardened self-protection canonicalization, hardened SSRF with DNS resolution*
