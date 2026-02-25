# GHOST_EGRESS_GUARD_SPEC

**Status:** Draft (implementation-ready)
**Target:** UNWIND enforcement pipeline
**Stage:** **3b** (new)
**Last updated:** 2026-02-25

---

## 1) Problem Statement

Ghost Mode currently intercepts state-modifying actions, but network/search egress still needs an explicit pre-DNS guardrail that is deterministic, auditable, and policy-driven. We need a dedicated stage that runs **before any DNS resolution or network I/O**, and enforces one of three Ghost network policies:

- `isolate` (default)
- `ask`
- `filtered`

This document specifies the new **Ghost Egress Guard** stage and all required contracts.

---

## 2) Goals and Non-Goals

### Goals

1. Add a new deterministic stage **3b** between Path Jail (3) and SSRF (4).
2. Enforce Ghost network policy only when Ghost Mode is active and tool is network/search.
3. Provide strict block behavior in `isolate` mode with code `GHOST_MODE_NETWORK_BLOCKED`.
4. Support `ask` mode with session-scoped, TTL-bound, auditable domain allows.
5. Support `filtered` mode with preflight DLP + request shaping constraints.
6. Detect exact known-secret leakage in URL/query surfaces using managed registry + transforms.
7. Emit dedicated telemetry events:
   - `ghost_egress_block`
   - `ghost_egress_ask`
   - `ghost_egress_allow`
   - `ghost_egress_dlp_hit`
8. Ensure blocked stage-3b attempts:
   - contribute to suspicion/abuse counters,
   - are **not** treated as sensor ingestion.

### Non-Goals

1. Replacing SSRF stage (4) or egress policy stage (4b).
2. Building full content-semantic DLP (regex-lite + exact known-secret transforms are sufficient here).
3. Persisting domain allows beyond session scope.
4. Changing non-Ghost behavior for normal (non-ghost) sessions.

---

## 3) Pipeline Placement and Ordering

### Required ordering

New order (relevant segment):

- 2c Credential Exposure
- 3 Path Jail
- **3b Ghost Egress Guard (new)**
- 4 SSRF Shield
- 4b Egress Policy
- 5 DLP-lite

### Why 3b must be before stage 4

Stage 4 performs DNS resolution and IP checks. Stage 3b must run first so Ghost policy can block/ask/filter **without any resolver/network side effects**.

### Hard requirement

Stage 3b must not call DNS APIs, socket APIs, HTTP clients, or browser/network adapters. It may only parse and inspect strings/params.

---

## 4) Gate Condition (Authoritative)

Stage 3b executes iff:

```python
session.ghost_mode == True and (
    tool_name in config.network_tools or tool_name == "search_web"
)
```

If condition is false, stage 3b is a no-op and pipeline continues.

---

## 5) Inputs, Normalization, and Scan Surface

## 5.1 Tool/input extraction

For network tools:
- Primary target URL from existing extraction (`url`, `uri`, `target`, etc.).

For `search_web`:
- Extract query text from `query` (fallback: `q`, `text`) [TBD exact precedence if adapter diverges].
- Domain for allow/ask comes from search provider host if configured (e.g., Brave API host) [TBD source of truth].

## 5.2 URL normalization rules (string-only)

1. Parse with URL parser (no resolution).
2. Lowercase host, strip trailing dot.
3. IDN -> ASCII punycode normalization.
4. Remove URL fragment (`#...`) for policy checks.
5. Preserve raw input in memory only for decisioning; never log unsanitized secret-bearing fields.

## 5.3 DLP preflight surface (filtered mode)

Scan exact text from:
- URL host
- URL path
- URL query
- URL userinfo
- search query text

The stage must not inspect response bodies (preflight only).

---

## 6) Policy Modes

## 6.1 `isolate` (default)

Behavior:
- Always block gated network/search attempts.
- Return code `GHOST_MODE_NETWORK_BLOCKED`.
- Include tool/domain metadata in block details.
- Log attempted URL/domain (sanitized/redacted policy below).
- Emit `ghost_egress_block` telemetry.

Reason code examples:
- `GHOST_ISOLATE_NETWORK_DENY`

## 6.2 `ask`

Behavior:
1. Check session allowlist for normalized domain, respecting TTL.
2. If allowed and not expired:
   - permit pipeline to continue,
   - emit `ghost_egress_allow` (decision=`allow_hit`).
3. If not allowed:
   - block with same primary code `GHOST_MODE_NETWORK_BLOCKED`,
   - include ask metadata so UI can present **Allow this domain**,
   - emit:
     - `ghost_egress_ask`
     - `ghost_egress_block` (decision=`awaiting_allow`).

Allowlist properties (mandatory):
- **session-scoped**
- **TTL-bound** (`ghost_network_allowlist_ttl_seconds`, 0 = session lifetime)
- **auditable** (who allowed, when, for what domain, expiry)

## 6.3 `filtered`

Behavior:
- Evaluate request with preflight DLP + shaping checks.
- Allow only if all checks pass.
- Block on first failed check (or collect-and-block with ordered reason list [TBD]).

Mandatory filtered checks:

1. **HTTPS only**
   - URL scheme must be `https`.
2. **No custom headers**
   - Reject if params include non-empty custom header fields.
3. **No cookies**
   - Reject if params include cookies/cookie jar values.
4. **No URL userinfo**
   - Reject if URL contains `username[:password]@host`.
5. **Hostname entropy checks**
   - Reject suspicious high-entropy host labels (details below).
6. **Known-secret exact matching** on scan surface.

On DLP/known-secret hit:
- Block with `GHOST_MODE_NETWORK_BLOCKED`.
- Emit `ghost_egress_dlp_hit` + `ghost_egress_block`.

---

## 7) Known-Secret Exact Matching (Filtered Mode)

## 7.1 Secret registry

Introduce managed secret registry interface (in-memory + optional secure backing) [TBD backing store]:

- `secret_id` (stable non-secret identifier)
- `secret_value` (never logged)
- optional metadata (source, created_at, expires_at)

## 7.2 Required transforms per secret

For each registered secret value, compute exact-match candidates:

1. Raw string
2. URL-encoded
3. Base64 (standard)
4. Base64url
5. Hex (lowercase and uppercase)

Comparison is exact substring match over scan surfaces.

## 7.3 Logging/telemetry safety

Never log plaintext secret values.

Allowed telemetry/log fields:
- `secret_id`
- `secret_fingerprint` (e.g., truncated SHA-256 of matched candidate)
- location category (`host|path|query|userinfo|search_query`)

Forbidden:
- matched plaintext segment
- full unsanitized URL when it may contain secret-bearing query/userinfo

---

## 8) Hostname Entropy Check (Filtered Mode)

Purpose: detect generated/exfil domains (`a9fz1k...`) before network I/O.

Proposed v1 heuristic (configurable):
- compute Shannon entropy per label and full host,
- flag if:
  - max label entropy > `ghost_entropy_label_threshold` [TBD default], or
  - alnum randomness indicators exceed threshold [TBD].

Minimum required behavior:
- deterministic pure-string check,
- false-positive-tolerant thresholds,
- reason code on block (`GHOST_FILTER_HOST_ENTROPY`).

---

## 9) Response Contracts

## 9.1 Pipeline internal contract

Stage 3b returns a block decision with:
- `action = BLOCK`
- `block_reason` contains machine code `GHOST_MODE_NETWORK_BLOCKED`
- metadata attached in structured form [TBD exact container if `PipelineResult` is extended]

## 9.2 Sidecar/API contract (recommended)

Current sidecar wire response supports `blockReason` string only. To satisfy UI and audit requirements, add structured block details:

```json
{
  "decision": "block",
  "blockReason": "GHOST_MODE_NETWORK_BLOCKED",
  "blockDetails": {
    "stage": "3b",
    "policy": "isolate|ask|filtered",
    "reasonCode": "GHOST_ISOLATE_NETWORK_DENY",
    "toolName": "fetch_web",
    "domain": "example.com",
    "urlRedacted": "https://example.com/path?token=<redacted>",
    "allowAction": {
      "offered": true,
      "scope": "session",
      "ttlSeconds": 3600
    }
  }
}
```

If API extension is deferred, embed a compact JSON payload in `blockReason` as temporary fallback [TBD compatibility decision].

## 9.3 Ask-mode allow action contract

UI action should call a sidecar endpoint to grant allow:

`POST /v1/policy/ghost/allow-domain` [TBD final route]

Request:
- `sessionKey`
- `domain`
- optional `ttlSeconds` override (bounded by policy)
- `operatorId`/actor tag

Response:
- status
- normalized domain
- `expiresAt`
- audit id

---

## 10) Telemetry Schema

Required event types:

1. `ghost_egress_block`
2. `ghost_egress_ask`
3. `ghost_egress_allow`
4. `ghost_egress_dlp_hit`

Common fields:
- `timestamp`
- `session_id`
- `tool_name`
- `pipeline_stage = "3b"`
- `ghost_network_policy`
- `domain` (normalized if known)
- `reason_code`
- `request_id` [if available]

Event-specific fields:

- `ghost_egress_block`
  - `blocked=true`
  - `attempt_index` (session counter)
  - `abuse_counter`
- `ghost_egress_ask`
  - `allow_offered=true`
  - `ttl_seconds`
- `ghost_egress_allow`
  - `action = granted|revoked|allow_hit|expired`
  - `expires_at`
  - `actor_id` [if available]
- `ghost_egress_dlp_hit`
  - `match_type = known_secret|pattern|entropy`
  - `surface = host|path|query|userinfo|search_query`
  - `secret_id` / `secret_fingerprint` (never plaintext)

---

## 11) Interaction Rules (Authoritative)

1. **Blocked stage-3b attempts are not sensor ingestion.**
   - No taint increase from blocked `search_web`/network attempts.
   - No tool side-effects executed.

2. **Blocked stage-3b attempts raise suspicion telemetry.**
   - Emit suspicion-linked event metadata on every block.

3. **Repeated blocked attempts contribute to abuse threshold.**
   - Maintain per-session rolling counter.
   - Crossing threshold triggers escalation action [TBD exact action: AMBER trust degradation vs kill-switch integration].

4. **Domain allows are session-scoped and TTL-bound.**
   - Never persisted as global policy by default.

---

## 12) Config Additions (Required)

Add to `UnwindConfig`:

```python
ghost_network_policy: str = "isolate"
ghost_network_allowlist: list[str] = []
ghost_network_allowlist_ttl_seconds: float = 0  # 0=session lifetime
```

Semantics:
- `ghost_network_policy`
  - one of `isolate|ask|filtered`
  - invalid value => fail-closed to `isolate`
- `ghost_network_allowlist`
  - initial seed domains copied into session scope at session start
- `ghost_network_allowlist_ttl_seconds`
  - applies to newly granted ask-mode allows unless overridden by stricter operator policy
  - `0` means valid for session lifetime

Recommended additional config [TBD if accepted]:
- `ghost_network_abuse_threshold_count`
- `ghost_network_abuse_window_seconds`
- `ghost_entropy_label_threshold`
- `ghost_entropy_host_threshold`

---

## 13) Proposed Data Model Changes

Session-scoped structures:

```python
@dataclass
class GhostAllowEntry:
    domain: str
    allowed_at: float
    expires_at: float | None
    actor_id: str | None
    source: str  # seed|ui_allow

Session.ghost_network_allows: dict[str, GhostAllowEntry]
Session.ghost_egress_block_timestamps: deque[float]
Session.ghost_egress_abuse_count: int
```

These remain in memory, tied to session lifecycle.

---

## 14) Decision Flow (Implementation Pseudocode)

```python
def stage_3b_ghost_egress_guard(session, tool_name, params, target, config):
    if not (session.ghost_mode and (tool_name in config.network_tools or tool_name == "search_web")):
        return PASS

    ctx = extract_context(tool_name, params, target)  # url, domain, query_text; no DNS

    policy = normalize_policy(config.ghost_network_policy)  # invalid -> isolate

    if policy == "isolate":
        emit("ghost_egress_block", ...)
        record_abuse(session)
        return block("GHOST_MODE_NETWORK_BLOCKED", reason="GHOST_ISOLATE_NETWORK_DENY", ctx=ctx)

    if policy == "ask":
        if is_domain_allowed(session, ctx.domain, now=time.time()):
            emit("ghost_egress_allow", action="allow_hit", ...)
            return PASS

        emit("ghost_egress_ask", ...)
        emit("ghost_egress_block", reason="GHOST_ASK_REQUIRES_ALLOW", ...)
        record_abuse(session)
        return block("GHOST_MODE_NETWORK_BLOCKED", reason="GHOST_ASK_REQUIRES_ALLOW", allow_offered=True, ctx=ctx)

    # filtered
    shape_err = enforce_filtered_shape(ctx, params)
    if shape_err:
        emit("ghost_egress_block", reason=shape_err.code, ...)
        record_abuse(session)
        return block("GHOST_MODE_NETWORK_BLOCKED", reason=shape_err.code, ctx=ctx)

    dlp_hit = preflight_dlp_scan(ctx)
    if dlp_hit:
        emit("ghost_egress_dlp_hit", ...)
        emit("ghost_egress_block", reason=dlp_hit.code, ...)
        record_abuse(session)
        return block("GHOST_MODE_NETWORK_BLOCKED", reason=dlp_hit.code, ctx=ctx)

    return PASS
```

---

## 15) Edge Cases and Required Handling

1. **Malformed URL**
   - block in filtered/isolate/ask with parse reason; no DNS.
2. **Trailing-dot host (`example.com.`)**
   - normalize to `example.com` before allowlist match.
3. **IDN hostnames**
   - normalize to punycode for matching and telemetry.
4. **IP literals**
   - treat as domain-equivalent identifier for allowlist keys.
5. **Missing host**
   - block in filtered; block in isolate/ask with `domain=""` and parse error reason.
6. **search_web without query**
   - block with invalid request reason [TBD whether upstream validator already handles].
7. **Allowlist expiry race**
   - check expiry at decision time; expired entries removed lazily.
8. **Secret in query value**
   - must be detected by exact matching transforms; never logged raw.
9. **Userinfo secrets**
   - filtered mode blocks all userinfo regardless of content.
10. **Case-variant domain**
   - case-insensitive normalized matching.

---

## 16) Test Plan

## 16.1 Unit tests (stage logic)

1. Gate condition true/false matrix:
   - ghost on/off
   - network tool / `search_web` / unrelated tool
2. Pipeline order test:
   - prove stage 3b runs before SSRF resolver call (mock resolver must not be hit on block).
3. `isolate` mode:
   - always blocks, returns `GHOST_MODE_NETWORK_BLOCKED`, emits block telemetry.
4. `ask` mode:
   - not allowed => block + ask telemetry
   - allowed active => pass + allow telemetry
   - allowed expired => block + expired allow telemetry path
5. `filtered` shaping:
   - non-https blocked
   - custom headers blocked
   - cookies blocked
   - URL userinfo blocked
6. Host entropy:
   - high-entropy host blocked
   - normal host allowed
7. Known-secret matching:
   - raw/url-encoded/base64/base64url/hex all detected
   - no plaintext secret appears in logs/telemetry
8. Search query DLP:
   - secret in search query triggers `ghost_egress_dlp_hit`.

## 16.2 Integration tests (sidecar + adapter)

1. Block details propagate to adapter/UI.
2. Ask flow:
   - UI allow action adds session allow entry with TTL.
   - subsequent matching request allowed.
3. Session boundary:
   - allow in session A does not apply to session B.
4. TTL boundary:
   - allow expires as configured.
5. Suspicion/abuse contribution:
   - repeated blocks increment abuse counters and trigger threshold action.
6. Sensor interaction:
   - blocked `search_web` does not taint session.

## 16.3 Security regression tests

1. No DNS/network calls made when stage 3b blocks.
2. Redaction invariant: no plaintext known secret in telemetry/event store.
3. Policy fallback invariant: invalid policy value => isolate fail-closed.

---

## 17) Rollout Notes

1. Ship stage 3b in shadow-telemetry mode first [TBD if desired].
2. Enable hard enforcement with default `ghost_network_policy="isolate"`.
3. Add operator-visible dashboard widgets for new telemetry types.
4. Document ask-flow UX and audit trail retrieval.

---

## 18) Open TBDs

1. Final sidecar wire shape for structured `blockDetails`.
2. Endpoint/command for UI “Allow this domain”.
3. Default entropy thresholds tuned for acceptable false positives.
4. Exact abuse-threshold escalation behavior (AMBER vs RED/kill).
5. Canonical source of search provider host for `search_web` ask metadata.

---

## 19) Acceptance Criteria Checklist

- [ ] Stage 3b implemented between path jail and SSRF.
- [ ] Gate condition exactly matches spec.
- [ ] `isolate` default active and blocks with `GHOST_MODE_NETWORK_BLOCKED`.
- [ ] `ask` mode supports session-scoped TTL allowlist with audit trail.
- [ ] `filtered` mode enforces shaping + preflight DLP + hostname entropy.
- [ ] Known-secret exact matching includes url-encode/base64/base64url/hex transforms.
- [ ] No plaintext secret values in logs/telemetry.
- [ ] Telemetry events emitted: block/ask/allow/dlp_hit.
- [ ] Blocked attempts increase suspicion/abuse counters and do not taint sensor state.
