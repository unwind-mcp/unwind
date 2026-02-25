# SECRET_REGISTRY_DESIGN

## 1) Purpose

`SecretRegistry` is a **known-secret exact-matching** component for Ghost Egress Guard.

Primary goal:
- Deliver **high-precision, near-zero-false-positive** detection of **actual user secrets** in outbound traffic.

Design principle:
- Prefer deterministic exact matching of user-derived secret material over heuristic “looks-like-a-secret” classifiers.

---

## 2) Scope and Non-Goals

### In scope
- Build a session-local registry of known secret values/tokens from approved sources.
- Match exact substrings against outbound URL components and search query text.
- Return machine-readable hit metadata without exposing raw secret values.

### Out of scope
- Full filesystem discovery/crawling.
- Persistent secret storage.
- Fuzzy/ML-based secret detection.
- Secret rotation/remediation workflows.

---

## 3) Secret Sources (Allowed Inputs)

Source collection is restricted to **workspace-root known locations + user home known files only**:

1. `.env` files in workspace
   - Check only known `.env`-style filenames at workspace root (for example: `.env`, `.env.local`, `.env.production`, `.env.development`) [exact list TBD].
   - Do not recursively crawl subdirectories.
   - Parse `KEY=VALUE` forms; ignore comments/blank lines.

2. `~/.aws/credentials`
   - Parse profile blocks and key-value pairs.
   - Candidate values include access key IDs, secret access keys, session tokens.

3. `~/.ssh/*.pub` (**fingerprint only**)
   - Do **not** treat public key material as secret payload.
   - Compute and keep only key fingerprint artifacts (e.g., SHA-256 fingerprint representation).
   - No raw `.pub` line is emitted to telemetry/logs.

4. Environment variables matching common secret names
   - Name matcher examples: `*API_KEY*`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*PRIVATE_KEY*`, `*CREDENTIAL*`.
   - Case-insensitive name matching.

### Scope limits
- Workspace-limited discovery for `.env` inputs (known file patterns only).
- No arbitrary recursive crawl of full filesystem.
- Home-directory access only for:
  - `~/.aws/credentials`
  - `~/.ssh/*.pub`

---

## 4) Population Model

- Registry is built at **session start**.
- Registry exists **in memory only**.
- Registry is **never persisted** to disk, cache, telemetry backend, or crash dumps.
- Rebuild/refresh occurs only through explicit lifecycle hooks (see §7).

### Source priority (for deterministic behavior)
1. Environment variables
2. Workspace `.env` files
3. `~/.aws/credentials`
4. `~/.ssh/*.pub` fingerprints

(Used for tie-breaking/report ordering only; all valid tokens are considered for matching.)

---

## 5) Matching Model

### Match target
Exact substring matching over:
- URL components:
  - host
  - path
  - query string
  - userinfo
- Search query text (if separate from URL in request context)

### Match rule
A hit occurs only when candidate text contains an **exact token** from registry token set.
No regex heuristics. No partial semantic inference.

### Per-secret transforms
For each normalized secret input, generate tokens:
1. raw value
2. URL-encoded
3. base64
4. base64url
5. hex

Implementation notes:
- Hex token is generated in lowercase canonical form; optional uppercase variant is implementation-configurable.
- URL-encoding uses RFC 3986 safe encoding behavior.
- Empty/whitespace-only values are discarded.

---

## 6) Data Model / Interface Contract

Type signatures shown in TypeScript-like pseudocode.

```ts
type SourceKind =
  | "workspace_env"
  | "aws_credentials"
  | "ssh_pub_fingerprint"
  | "process_env";

type TransformKind =
  | "raw"
  | "url_encoded"
  | "base64"
  | "base64url"
  | "hex";

interface SecretInput {
  source: SourceKind;
  name?: string;                 // e.g., ENV var key or file key label
  value: string;                 // never logged; in-memory only
  originPath?: string;           // sanitized path metadata (optional)
}

interface SecretRecord {
  fingerprintId: string;         // first 8 hex chars of SHA-256(value)
  source: SourceKind;
  name?: string;
  tokenCount: number;
  createdAtMs: number;
}

interface MatchToken {
  token: string;                 // sensitive; in-memory only
  fingerprintId: string;
  source: SourceKind;
  transform: TransformKind;
}

interface RegistrySnapshot {
  registryVersion: number;
  loadedAtMs: number;
  recordCount: number;
  tokenCount: number;
  records: SecretRecord[];       // no raw values
}

interface MatchRequest {
  url?: string;
  searchQueryText?: string;
  mode: "filtered" | "ask";
  allowlistedDomain?: boolean;
}

type MatchLocation =
  | "url.host"
  | "url.path"
  | "url.query"
  | "url.userinfo"
  | "search.queryText";

interface MatchHit {
  fingerprintId: string;
  source: SourceKind;
  transform: TransformKind;
  location: MatchLocation;
}

interface MatchResult {
  matched: boolean;
  hits: MatchHit[];
  decision: "allow" | "ask" | "block";
  reasonCode:
    | "secret_match"
    | "registry_unavailable"
    | "registry_degraded"
    | "no_match";
}

interface SecretRegistry {
  load(): Promise<RegistrySnapshot>;
  refresh(): Promise<RegistrySnapshot>;
  invalidate(reason: string): void;
  match(req: MatchRequest): MatchResult;
  status(): {
    state: "ready" | "loading" | "degraded" | "unavailable";
    registryVersion: number;
    loadedAtMs?: number;
    recordCount: number;
    tokenCount: number;
  };
}
```

---

## 7) Lifecycle Hooks

1. `load()`
   - Trigger: session start.
   - Behavior: collect sources, normalize inputs, derive transforms, compile matcher, expose snapshot.

2. `refresh()`
   - Trigger: explicit operator action or guarded periodic refresh [TBD cadence].
   - Behavior: atomic rebuild; old registry remains active until new build succeeds.

3. `invalidate(reason)`
   - Trigger: corruption, memory pressure, loader failure, policy signal.
   - Behavior: clear in-memory token store and set state to `degraded`/`unavailable`.

### Atomicity requirement
- No partial registry should be served as `ready`.
- Swap-in occurs only after complete successful build.

---

## 8) Decision Flow and Integration Points

### A) Ghost Egress Guard `filtered` mode
- Evaluate request with `SecretRegistry.match()` before egress.
- If `matched=true` -> **block** (`reasonCode=secret_match`).
- Emit non-sensitive audit event (fingerprint IDs only).

### B) Defense-in-depth for `ask` mode allowlisted domains
- Even when domain is allowlisted, run exact-match check.
- If hit found -> override allowlist fast-path and **ask/block per policy** (recommended default: block with user-visible reason).
- Prevents exfiltration through trusted-domain assumptions.

### C) Registry unavailable/degraded path
- Never silently bypass in filtered mode.
- Fail-safe behavior:
  - `filtered` mode: treat as protective degrade (`decision=ask` or `block` per top-level policy; recommended `ask` if availability-critical, otherwise `block`).
  - `ask` mode: disable allowlist bypass and require explicit user confirmation for external egress.

---

## 9) Security, Privacy, and Audit Constraints

1. Never log raw secret values.
2. Never emit transformed secret tokens.
3. Telemetry and logs may include only:
   - `fingerprintId = first 8 chars of SHA-256(secret)`
   - source kind
   - transform kind
   - match location
   - decision/reason code
4. No on-disk persistence of secret registry contents.
5. Redaction required for exceptions/errors (no value echo).
6. Debug mode must preserve the same redaction guarantees.

---

## 10) Failure Modes and Fail-Safe Behavior

### Failure modes
- Missing/inaccessible files (`.env`, AWS credentials, SSH pub files).
- Parse errors in source files.
- Oversized source values or malformed encodings.
- Memory cap exceeded during token expansion.
- Matcher compilation failure.

### Required behavior
- Continue loading from remaining sources when possible.
- Surface degraded status with structured reason.
- Do not emit secret contents in error paths.
- If registry cannot be trusted as `ready`, enforce conservative egress behavior (see §8C).

---

## 11) Performance and Memory Bounds

### Matching engine
- Use linear-time multi-pattern exact matching (e.g., Aho-Corasick) over each inspected text component.
- Complexity target: `O(total_text_len + matches)` per request after compile.

### Build-time profile
- `O(total_token_bytes)` token generation + matcher compile.

### Memory controls
- Configurable hard limits [example defaults]:
  - max secret records: 10,000
  - max tokens: 50,000
  - max token length: 8,192 bytes
  - max total token bytes in memory: 16 MiB
- On limit breach: set degraded state and apply fail-safe egress policy.

---

## 12) Test Strategy

### Unit tests
- Source parsers:
  - `.env` parsing edge cases
  - AWS credentials profile parsing
  - env-var name matcher behavior
  - SSH pub fingerprint extraction only
- Transform correctness:
  - raw/url-encoded/base64/base64url/hex deterministic outputs
- Fingerprinting:
  - SHA-256 -> first-8-hex derivation

### Matching tests
- Exact-positive cases for each transform and location.
- Negative controls to verify near-zero false positives.
- Case-sensitivity behavior coverage.

### Integration tests
- Filtered mode blocks on hit.
- Ask-mode allowlist overridden on hit.
- Degraded/unavailable registry path enforces fail-safe decisions.

### Security/privacy tests
- Assert logs/telemetry never contain raw secret/token strings.
- Assert only fingerprint IDs are exported.
- Assert no registry persistence artifacts are written.

### Performance tests
- Benchmark build and match latency at expected and stress-scale token counts.
- Verify memory cap enforcement and graceful degradation.

---

## 13) Open Decisions [TBD]

1. Exact policy choice in filtered mode when registry is unavailable (`ask` vs `block`) by deployment tier.
2. Refresh cadence policy (manual only vs periodic guarded refresh).
3. Whether to include uppercase hex transform variant by default.
4. Workspace `.env` discovery pattern allowlist (exact glob set) for strictest scope control.

---

## 14) Summary

This design defines a deterministic, in-memory-only secret registry that prioritizes precision by matching exact known secret material (plus fixed transforms) against outbound URL/search surfaces. It integrates directly into Ghost Egress Guard filtered mode and adds defense-in-depth protections for ask-mode allowlisted domains, while preserving strict no-secret-logging guarantees through fingerprint-only telemetry.
