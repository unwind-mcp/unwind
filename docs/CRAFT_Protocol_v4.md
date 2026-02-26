# CRAFT: Cryptographic Relay Authentication for Faithful Transmission (v4)

**Author:** David Russell (Brug.AI)
**Contributing reviewers:** SENTINEL, three external adversarial collaborators
**Date:** February 2026
**Status:** Working Draft v4 (consolidated post-review rewrite)

---

## Abstract

Prompt injection remains a high-impact security risk in LLM agent systems, especially where untrusted content can influence tool execution. CRAFT introduces a **transport-layer command provenance protocol**: it authenticates user-origin instructions before they are admitted into agent execution pipelines.

CRAFT is intentionally scoped. It does **not** claim to solve all prompt injection. Instead, it provides cryptographic guarantees for:

1. Origin authenticity of user commands.
2. Ordering and integrity of the command stream.
3. Replay resistance.
4. Resistance to off-path instruction forgery.
5. Scoped delegation of privileged tool execution via issuer-authenticated capability tokens.

This narrows a major class of scalable attacks (message spoofing, relay tampering, replay, session confusion, and confused-deputy misuse), and strengthens downstream policy enforcement (e.g., UNWIND) by ensuring privileged actions can be bound to authenticated user intent.

---

## 1) Claim Reframe

### 1.1 Correct security claim

**v4 claim:** CRAFT is a **cryptographic command provenance and anti-spoofing layer** for agent transports. It authenticates *who* issued privileged instructions and *when/where* they are valid, within a deterministic, fail-closed verification boundary.

### 1.2 Claims explicitly excluded

- "Prompt injection is solved."
- "Indirect injection via tool outputs is blocked entirely by CRAFT alone."
- "Model-layer controls become unnecessary in all contexts."
- "CRAFT prevents the LLM planner from requesting privileged tools." (That is enforced solely by capability requirement + downstream policy such as UNWIND.)

### 1.3 Precise positioning

CRAFT is one control in a defense-in-depth stack:

- **CRAFT:** authenticates *who* issued privileged instructions and *when/where* they are valid.
- **UNWIND pipeline:** constrains *what* actions are allowed and under what policy.
- **Model/runtime safeguards:** reduce unsafe interpretation and unsafe planning behavior.

---

## 2) Formal Security Goals and Non-Goals

### 2.1 Security Goals

- **G1 — Command authenticity:** Proxy accepts privileged command-bearing messages only when MAC-valid under session keys bound to an authenticated client identity.
- **G2 — Command integrity:** Any in-transit mutation of authenticated envelope fields is detected.
- **G3 — Ordering guarantees:** Message stream tampering (insert, remove, reorder) is detectable. The command provenance path enforces strict FIFO verification.
- **G4 — Replay resistance:** Reuse of previously accepted envelopes outside the replay window is rejected. Sequence numbers are strictly monotonic; the replay bitmap never permits re-accepting an already-accepted sequence number.
- **G5 — Context binding:** Authenticated commands are bound to session, account, channel, context, and conversation/run identifiers to prevent confused routing, including intra-channel confusion.
- **G6 — Delegation safety:** Tool execution requires a short-lived capability token minted by the server (verifier) from authenticated user intent. Capability tokens are issuer-authenticated by a key the client does not hold.
- **G7 — Deterministic verifier behavior:** Verify path is canonical, constant policy, fail-closed for privileged actions.

### 2.2 Non-Goals

- **N1 — Semantic intent validation:** CRAFT does not determine whether a user's authenticated command is wise, safe, or non-malicious.
- **N2 — Tool output trust:** CRAFT does not make model/tool outputs trustworthy; downstream policy still required.
- **N3 — Full prompt-injection elimination:** CRAFT does not by itself stop all indirect prompt injection in model reasoning over untrusted data.
- **N4 — Host compromise immunity:** If client or proxy host is fully compromised, software-only protocol controls are insufficient.
- **N5 — LLM planner control:** CRAFT does not prevent the LLM planner from requesting privileged tools. That authority boundary is enforced by capability requirements and UNWIND policy, not by CRAFT alone.

---

## 3) Threat Model and Assumptions

### 3.1 In scope

- On-path message tampering and replay between client shim and proxy.
- Off-path forgery attempts from untrusted content sources (web pages, email content, docs, tool output text).
- Session confusion and cross-context command routing errors, including intra-channel confusion (wrong thread, wrong agent run, wrong task within the same channel).
- Confused-deputy misuse where an authenticated session is abused to trigger unintended privileged tools.
- Reflection/direction-confusion attacks where a valid MAC from one direction (C→P) is replayed in the other direction (P→C).

### 3.2 Out of scope / partially mitigated

- Fully compromised endpoint with live key use.
- Fully compromised proxy host or verifier binary.
- Social engineering of legitimate user intent.
- Malicious but authenticated insider behavior.
- **Client shim is part of the TCB.** The CRAFT client shim (browser extension, desktop app, mobile SDK) is a trusted component. Partial compromise of the shim (e.g., JS injection, extension takeover) bypasses CRAFT without key exfiltration. Deployments SHOULD sandbox the shim implementation and enforce input sanitisation before envelope creation.

### 3.3 Trust assumptions

- Cryptographic primitives are correctly implemented (HMAC-SHA-256, HKDF-SHA-256, Ed25519/ECDH where used).
- Key material remains protected in client trust anchor (TPM/Secure Enclave/HSM where available).
- Verifier state store is integrity-protected and crash-consistent (see Section 4.10).
- The transport between C and P provides confidentiality and integrity (TLS 1.3, Noise, or equivalent). CRAFT adds command provenance and anti-replay on top; it does not replace transport encryption.

---

## 4) Hardened Protocol Specification

### 4.1 Entities

- **C**: CRAFT client shim (user device).
- **P**: CRAFT verifier (proxy-side).
- **A**: Agent runtime / model orchestrator.
- **T**: Tool execution layer.

### 4.2 Session bootstrap, key schedule, and version negotiation

#### 4.2.1 Version negotiation and downgrade protection

Before key exchange, C and P perform a version negotiation handshake:

- C sends supported protocol versions (e.g., `["CRAFT/v4"]`).
- P selects the highest mutually supported version and includes the selected version in the authenticated handshake transcript.
- If no mutually supported version exists, the session fails closed.
- Downgrade attacks are prevented because the selected version is bound into the key derivation context (Section 4.2.3). Any tampering with the version negotiation produces mismatched keys.

#### 4.2.2 Bootstrap inputs

- `IKM` (input keying material): Derived from the authenticated transport handshake. For TLS 1.3: use a TLS Keying Material Exporter (RFC 8446 Section 7.5) with label `"CRAFT/v4/ikm"`, context = `session_id`, and output length = 32 bytes. For Noise: CRAFT v4 normatively uses `Noise_XX_25519_ChaChaPoly_BLAKE2s` with prologue `"CRAFT/v4"`; derive `IKM` as the final handshake hash (`h`) at handshake completion (32 bytes). Implementations MUST NOT extract the raw ECDH shared secret directly.
- `salt0`: Derived deterministically from the transport handshake transcript. For TLS 1.3: use a second exporter with label `"CRAFT/v4/salt"`, context = `session_id`, output length = 32 bytes. For Noise: derive `salt0` from the final chaining key (`ck`) at handshake completion (32 bytes). This eliminates a network round-trip and prevents MITM alteration of the salt.
- `ctx`: Canonical context string containing protocol version and binding tuple (serialised per Section 4.4):
  - `proto_version`
  - `session_id`
  - `account_id`
  - `channel_id`
  - `conversation_id` (thread/run/task scope within channel)
  - `device_pubkey_fpr`

#### 4.2.3 Key derivation (HKDF)

```text
PRK = HKDF-Extract(salt = salt0, IKM = IKM)

# Directional message MAC keys
K_msg_c2p  = HKDF-Expand(PRK, info = "CRAFT/v4/msg/c2p\0" || len(ctx) || ctx, L=32)
K_msg_p2c  = HKDF-Expand(PRK, info = "CRAFT/v4/msg/p2c\0" || len(ctx) || ctx, L=32)

# Directional state commitment keys
K_state_c2p = HKDF-Expand(PRK, info = "CRAFT/v4/state/c2p\0" || len(ctx) || ctx, L=32)
K_state_p2c = HKDF-Expand(PRK, info = "CRAFT/v4/state/p2c\0" || len(ctx) || ctx, L=32)

# Server-only capability token key (NEVER shared with C)
K_cap_srv  = HKDF-Expand(server_secret, info = "CRAFT/v4/cap\0" || len(ctx) || ctx, L=32)

# Directional resync keys
K_resync_c2p = HKDF-Expand(PRK, info = "CRAFT/v4/resync/c2p\0" || len(ctx) || ctx, L=32)
K_resync_p2c = HKDF-Expand(PRK, info = "CRAFT/v4/resync/p2c\0" || len(ctx) || ctx, L=32)
```

Key purposes:

- `K_msg_c2p` / `K_msg_p2c`: Envelope MAC keys, one per direction. Prevents reflection attacks.
- `K_state_c2p` / `K_state_p2c`: State commitment chain keys, one per direction.
- `K_cap_srv`: Capability token MAC key. Derived from a **server-only secret** (`server_secret`) that C never possesses. This ensures only P can mint valid capability tokens. C treats tokens as opaque.
- `K_resync_c2p` / `K_resync_p2c`: Resync challenge/proof MAC keys, one per direction.

HKDF info fields use null-byte delimiter (`\0`) followed by a 2-byte big-endian length prefix for `ctx` to prevent context-collision ambiguity.

### 4.3 Genesis values

- `seq` starts at `1` and is strictly monotonically increasing. `seq` is an unsigned 64-bit integer. In JSON serialisation, `seq` MUST be encoded as a string to avoid JavaScript number precision loss.
- `state_commit_0` is defined as:

```text
state_commit_0 = HMAC-SHA256(K_state_{direction}, "CRAFT/v4/state0\0" || len(ctx) || ctx)
```

This provides a deterministic, direction-bound genesis value that both sides can compute independently.

### 4.4 Canonical encoding (mandatory)

All authenticated fields MUST be serialised using RFC 8785 JSON Canonicalization Scheme (JCS). This is a MUST, not a recommendation.

JCS mandates I-JSON (RFC 7493) compliance. In addition, CRAFT implementations MUST:

- Reject `NaN`, `Infinity`, and `-Infinity` values.
- Reject duplicate keys in any JSON object.
- Reject leading zeros in numbers.
- Reject non-canonical Unicode escapes.
- Use UTF-8 normalisation form NFC for all string values.

For MAC input construction, the following byte-level rules apply:

- `seq`: unsigned 64-bit big-endian (8 bytes). Not the JSON string representation.
- `state_commit`: raw 32 bytes. Not base64-encoded.
- `nonce` (where used): raw bytes. Not base64-encoded.
- `payload`: UTF-8 bytes of the JCS-canonical JSON serialisation.
- Variable-length field concatenation MUST use length-prefixed encoding: 4-byte big-endian length prefix followed by the field bytes.

Base64 encoding (where used in JSON wire format): MUST use base64url (RFC 4648 Section 5) without padding, no whitespace. Reject non-canonical encodings.

### 4.5 Authenticated envelope

```json
{
  "v": 4,
  "epoch": 0,
  "session_id": "...",
  "account_id": "...",
  "channel_id": "...",
  "conversation_id": "...",
  "context_type": "dm|group|plugin|api",
  "seq": "1234",
  "ts_ms": 1739999999123,
  "state_commit": "<base64url(32B)>",
  "msg_type": "user_instruction|control|control_close",
  "direction": "c2p|p2c",
  "payload": {"text": "...", "meta": {...}},
  "mac": "<base64url(HMAC-SHA256(K_msg_{direction}, MAC_input(envelope)))>"
}
```

Notes:

- `epoch` is incremented on each rekey event (Section 4.9). Envelopes from a previous epoch are rejected.
- `conversation_id` binds to the specific thread, run, or task within the channel.
- `direction` is an explicit field to prevent reflection attacks (in addition to directional keys).
- `seq` is a string-encoded uint64.
- `ts_ms` is advisory (see Section 4.7).
- `msg_type: "control_close"` is used for authenticated session teardown (Section 4.11).
- Capability tokens are NEVER included in the payload. They are carried out-of-band (Section 5.4).

### 4.6 State commitment chain

The state commitment chain provides cryptographic ordering and integrity verification for the command stream.

```text
state_commit_n = HMAC-SHA256(K_state_{direction}, state_commit_{n-1} || envelope_n.mac)
```

By chaining the envelope MAC (which already covers all canonical fields including seq, context, msg_type, direction, epoch, and payload), the state commitment avoids variable-length concatenation ambiguity and ensures complete metadata coverage.

**Strict FIFO requirement:** The state commitment chain is inherently sequential. Verifier P MUST process envelopes in strict sequence order. Out-of-order delivery is NOT permitted on the command provenance path. If message N+1 arrives before N, P MUST hold N+1 until N arrives or reject after a bounded timeout (configurable, default 5 seconds). Privileged messages (requiring capability tokens) MUST reject on any sequence gap with zero tolerance.

### 4.7 Sequence number and anti-replay

Verifier stores per-session, per-direction, per-epoch replay state:

- `highest_accepted_seq`: the highest sequence number successfully verified and committed.
- Sliding window bitmap (width 1024) for duplicate detection within the window.

Acceptance policy:

- Reject if `seq <= 0`.
- Reject unless `seq == highest_accepted_seq + 1` (strict FIFO, no gaps).
- Reject if `seq` previously seen in the bitmap for the current epoch.
- Reject if `epoch` does not match the current session epoch.

**Timestamp handling:** `ts_ms` is treated as an **advisory anomaly signal**, not a rejection gate. The verifier MAY log anomalies when `ts_ms` deviates significantly from server time (e.g., >1 hour), but MUST NOT reject messages solely on timestamp grounds. Replay resistance is provided by `seq` + state chain + epoch, not by timestamps. This prevents availability degradation from clock skew, NTP drift, or attacker-induced packet delay.

**Nonce:** Removed from the standard FIFO verification path. Strict sequential `seq` + bitmap provides complete replay resistance. A `nonce` field MAY be used in resync challenge-response exchanges (Section 4.8) for correlation, but is not required in regular envelopes.

### 4.8 Verification algorithm (proxy)

1. Parse envelope with strict schema validation (reject malformed).
2. Verify `epoch` matches current session epoch (reject stale epoch).
3. Verify `direction` matches expected direction for this channel.
4. Recreate canonical encoding per Section 4.4.
5. Verify MAC using `K_msg_{direction}`.
6. Validate context binding tuple (`session_id`, `account_id`, `channel_id`, `conversation_id`, `context_type`).
7. Validate replay constraints (`seq`, bitmap) per Section 4.7.
8. Validate state transition: recompute `state_commit_n` from `state_commit_{n-1}` and `envelope_n.mac`, compare to declared `state_commit`.
9. If privileged action requested, require valid capability token (Section 5). Token is carried out-of-band, never in the envelope payload.
10. Commit state atomically (`highest_accepted_seq`, `state_commit`, bitmap update — all in one transaction).

On failure: reject with typed error code (Section 4.8.3). No partial state updates.

**Error disclosure policy:** Before MAC validation (steps 1–4), return only a generic error (`ERR_ENVELOPE_INVALID`). Detailed typed error codes are returned only after successful MAC validation (step 5), to prevent information leakage to unauthenticated callers. Rate-limit all error responses per source/session.

#### 4.8.1 Error codes (post-MAC-validation only)

- `ERR_MAC_INVALID` — MAC verification failed (returned as generic error pre-auth).
- `ERR_REPLAY` — Sequence number already accepted or outside window.
- `ERR_STATE_DIVERGED` — State commitment chain mismatch.
- `ERR_CONTEXT_MISMATCH` — Context binding tuple mismatch.
- `ERR_EPOCH_STALE` — Envelope epoch does not match current session epoch.
- `ERR_CAP_REQUIRED` — Privileged action requested without capability token.
- `ERR_CAP_INVALID` — Capability token failed validation.

### 4.9 Periodic rekey (epoch advancement)

To provide forward secrecy and limit the blast radius of key compromise, CRAFT sessions MUST rekey periodically.

**Rekey triggers:** Whichever occurs first:

- 2^20 (1,048,576) messages sent in the current epoch.
- 30 minutes elapsed since last rekey (or session start).
- Explicit rekey request via `msg_type: "control"` with `payload.action: "rekey"`.

**Rekey procedure:**

```text
epoch_new = epoch_current + 1
PRK_new = HKDF-Extract(
    salt = state_commit_current,
    IKM = PRK_current || "CRAFT/v4/rekey\0" || uint64_be(epoch_new)
)
```

All directional keys (`K_msg_*`, `K_state_*`, `K_resync_*`) are re-derived from `PRK_new` using the same HKDF-Expand labels with the updated epoch in the info string. `K_cap_srv` is re-derived from `server_secret` with updated epoch context.

After rekey:

- `seq` resets to `1` for the new epoch.
- `state_commit_0` is recomputed for the new epoch.
- Replay bitmap is cleared for the new epoch (replay tracking is epoch-scoped).
- Envelopes bearing any previous epoch value are rejected.
- Both sides MUST persist `PRK_new` before accepting messages in the new epoch.

**Rekey is also triggered on resync** (see Section 4.10).

### 4.10 Failure and resynchronisation protocol

#### 4.10.1 Failure classes

- `ERR_MAC_INVALID`
- `ERR_REPLAY`
- `ERR_STATE_DIVERGED`
- `ERR_CONTEXT_MISMATCH`
- `ERR_EPOCH_STALE`
- `ERR_CAP_REQUIRED`
- `ERR_CAP_INVALID`

#### 4.10.2 Resync flow

For recoverable divergence (packet loss, client restart), use authenticated challenge-response:

```text
P -> C: RESYNC_CHALLENGE {
    session_id,
    epoch,
    expected_seq,
    challenge_nonce,
    mac = HMAC(K_resync_p2c, canonical(challenge_fields))
}

C -> P: RESYNC_PROOF {
    session_id,
    epoch,
    challenge_nonce,
    client_highest_seq,
    client_state_commit,
    missing_envelopes: [canonical envelope N, N+1, ...],
    mac = HMAC(K_resync_c2p, canonical(proof_fields))
}
```

P MUST walk the state hash forward through the missing envelopes to verify the chain is intact. If C cannot provide the missing envelopes (e.g., buffer lost), the state is unrecoverable and the session MUST terminate (fail-closed).

#### 4.10.3 Resync invariants (MUST-level)

- **No rollback:** `new_highest_seq >= old_highest_seq` at all times. The verifier MUST NOT move its sequence counter backwards.
- **No replay within epoch:** Within an epoch, the replay bitmap MUST NOT permit re-accepting an already-accepted sequence number.
- **Resync is a rekey event:** On successful resync, the session advances to a new epoch (Section 4.9). Old-epoch envelopes are rejected, preventing replay of pre-resync envelopes into post-resync state.
- **Bounded resync rate:** Maximum 5 resync attempts per session per 60-second window, with exponential backoff. Exceeding this limit terminates the session.

#### 4.10.4 Fail mode policy

- **Privileged tool paths:** fail-closed. No exceptions.
- **Low-risk conversational paths:** configurable fail-open with audit flag, if operator permits.

### 4.11 Session lifecycle

#### 4.11.1 Session TTL

Sessions MUST have a bounded maximum lifetime. Default: 24 hours from bootstrap. At TTL expiry, both sides terminate the session and require a fresh handshake.

#### 4.11.2 Authenticated teardown

Either side may initiate graceful session teardown by sending an envelope with `msg_type: "control_close"`. The teardown envelope is MAC-verified like any other message and updates the state chain. After teardown:

- All session keys are zeroised.
- The session entry is moved to a tombstone list (to reject late-arriving envelopes referencing the terminated session).
- Tombstone entries expire after 2x the anti-replay window duration.

#### 4.11.3 Crash/restart persistence

The verifier MUST persist the following state to durable storage with atomic writes:

- `highest_accepted_seq` (per direction, per epoch).
- `state_commit` (current, per direction).
- Replay bitmap (sufficient to reject duplicates after restart).
- Current `PRK` and epoch counter.

If the verifier cannot guarantee persistence (e.g., ephemeral deployment), it MUST invalidate all active sessions on restart and require fresh handshakes. This is the safest default.

Verifiers SHOULD also persist the last 32 `state_commit` values to enable fast re-anchor during resync without requiring full chain replay.

#### 4.11.4 Clock failure handling

If the verifier detects clock rollback (system time moves backwards) or extreme skew (>1 hour drift from last known good time), it MUST:

- Log the anomaly with severity CRITICAL.
- Continue accepting messages based on `seq` and state chain (which are clock-independent).
- Flag all `ts_ms` anomaly checks as unreliable until clock stability is restored.
- NOT terminate sessions solely due to clock failure.

---

## 5) Confused-Deputy Mitigation via Capability Tokens

This is a first-class protocol component, not an optional feature.

### 5.1 Problem

Even authenticated user sessions can trigger unintended privileged actions when context is ambiguous (e.g., cross-channel/account routing, stale intent, delegated execution mismatch, or intra-channel thread confusion). This is the classic confused-deputy class. Additionally, in LLM agent pipelines, the model planner may propose tool calls based on injected content — capability tokens ensure that privileged execution is bound to verified user intent, not model inference.

### 5.2 Issuer-authenticated token model

Capability tokens are minted exclusively by the verifier (P) and are authenticated by `K_cap_srv`, a key derived from a server-only secret that the client (C) never possesses. This is the critical design constraint: the client cannot forge, extend, or modify capability tokens.

#### 5.2.1 Token claims

- `cap_id`: Unique identifier, registered in issuer table.
- `session_id`, `account_id`, `channel_id`, `conversation_id`, `context_type`: Full context binding.
- `subject`: User/device binding.
- `allowed_tools`: Exact tool IDs (no wildcards for privileged tools).
- `arg_constraints`: Canonical constraint specification (see Section 5.5).
- `target_constraints`: Canonical constraint specification (see Section 5.5).
- `issued_at`, `exp`: TTL (30–120 seconds default).
- `max_uses`: Default 1. Explicit `chainable: true` flag required for multi-step use.
- `bind_seq`: Command sequence number of the user_instruction that authorised this capability.
- `state_commit_at_issue`: The state_commit value at the time of issuance, binding the token to a specific point in the transcript.
- `parent_cap_id`: For chained capabilities, references the parent token (see Section 5.3).
- `purpose`: Human-readable intent string for audit.

#### 5.2.2 Token MAC

```text
cap_mac = HMAC-SHA256(K_cap_srv, canonical(cap_claims))
```

For multi-verifier deployments where P and T are in different trust boundaries and secret sharing is undesirable, use Ed25519 signatures instead of HMAC.

#### 5.2.3 Issuer table requirement

The verifier MUST maintain an issuer table mapping `cap_id` to `(canonical_claims_hash, exp, remaining_uses, revoked)`. Any capability token presented for enforcement MUST have a matching `cap_id` in the issuer table. Tokens not in the table are rejected regardless of MAC validity. This prevents any token forgery even if `K_cap_srv` were somehow compromised, as long as the issuer table is integrity-protected.

### 5.3 Capability minting and chaining protocol

#### 5.3.1 Minting trigger

After successful verification of a privileged `user_instruction` envelope at sequence N, the verifier P atomically:

1. Evaluates the deterministic issuance policy to determine which tools and constraints are authorised by this instruction.
2. Mints one or more capability tokens with `bind_seq = N` and `state_commit_at_issue = state_commit_N`.
3. Registers each token in the issuer table.
4. Returns `cap_id` values in the admit response via the authenticated P→C channel (using `K_msg_p2c`).
5. Pushes token metadata to the UNWIND enforcement layer via a secure internal channel (local IPC, not network).

**Issuance gate:** Capabilities are minted ONLY from:

- **User-confirmation gate:** An authenticated user confirmation step that includes explicit tool, args, and target. This may be lightweight UX but must be deterministic, OR
- **Deterministic policy gate:** A policy engine that parses the authenticated request envelope (not LLM reasoning output) and derives narrow capabilities.

Capabilities are NEVER minted from model planner output, LLM-inferred intent, or tool execution results.

#### 5.3.2 Step-up authorisation for dynamic arguments

When an agent plans a privileged tool call whose arguments depend on prior tool output (e.g., Tool A returns a user ID, Tool B deletes that user), the initial capability cannot specify exact arguments at ingress time. In this case:

1. P issues an initial **intent capability** (coarse: tool ID + argument schema, no specific values).
2. When the agent is ready to dispatch Tool B with concrete arguments, P sends a `CAPABILITY_CHALLENGE` to C containing the exact planned tool call (tool ID, resolved arguments, target).
3. C (or the user through the client trust anchor) cryptographically signs the challenge response, confirming the specific action.
4. P mints a **step-up capability** with exact `arg_constraints` and `target_constraints` bound to the confirmed values.

This two-phase flow ensures that dynamic privileged actions always trace back to authenticated user confirmation of the specific operation, not just the general intent.

#### 5.3.3 Chained capabilities

For multi-step tool chains where Tool A's output feeds Tool B's input:

- Tool B's capability MUST include `parent_cap_id` referencing Tool A's capability.
- Tool B's capability MUST include `state_commit_at_issue` matching the transcript state after Tool A completed.
- The verifier checks that the parent capability was successfully used and that the transcript is contiguous.
- `max_uses` for chainable capabilities may exceed 1, but MUST be explicitly declared (`chainable: true`) and bounded.

### 5.4 Token handling (out-of-band requirement)

Capability tokens MUST be carried as structured out-of-band metadata. They MUST NOT be:

- Included in the envelope `payload` field.
- Concatenated into any model-visible prompt or context.
- Logged in full (logs MUST redact token bodies, recording only `cap_id` and decision codes).

This prevents the LLM from leaking, replaying, or reasoning about capability tokens.

### 5.5 Constraint normalisation and validation

Arg and target constraints must be validated against canonical, security-relevant representations at the enforcement boundary.

#### 5.5.1 Network target constraints

- Validate against `scheme + host + port` AND the resolved IP address range.
- Block RFC 1918, loopback (127.0.0.0/8), and link-local (169.254.0.0/16) addresses unless explicitly allowed in the constraint.
- Cache DNS resolution results for the token TTL to prevent DNS rebinding attacks.
- Normalise hostnames to ASCII A-label form (IDNA ToASCII / punycode-encode), lowercase, and strip trailing dots before policy comparison.

#### 5.5.2 Filesystem target constraints

- Validate after `realpath()` / symlink resolution inside the sandbox root.
- Deny if resolution escapes the sandbox boundary.
- Normalise paths: resolve `.` and `..`, resolve symlinks, convert to absolute.

#### 5.5.3 Argument constraints

- `arg_constraints` = `schema_digest` (`SHA-256` of canonical JSON Schema) + allowed value set (exact values or range bounds).
- At use-time, the verifier loads the schema identified by `schema_digest` (from a trusted local schema registry), verifies digest equality, then validates actual runtime args against that schema.
- Value validation: exact match, range check (numeric), enum membership, or regex match (string) as declared in the constraint.

#### 5.5.4 Reference validator

Implementations SHOULD ship a `craft-normalize` reference function with test vectors for URL, path, and argument normalisation.

### 5.6 Enforcement at tool dispatch

At tool dispatch, the enforcement layer (UNWIND) MUST verify:

1. Token `cap_id` exists in issuer table and is not revoked.
2. Token has not expired (`exp`).
3. Token use count has not been exceeded (`max_uses` / `remaining_uses`).
4. Exact context binding matches current execution context.
5. `state_commit_at_issue` is consistent with the current transcript (no splicing).
6. Tool ID is in `allowed_tools`.
7. Arguments satisfy `arg_constraints` after normalisation.
8. Target satisfies `target_constraints` after normalisation (Section 5.5).
9. If `parent_cap_id` is present, parent capability was successfully used.

If any check fails: deny and log a deterministic reason code.

### 5.7 Security effect

This constrains delegated authority to the minimum necessary scope and time, blocks authenticated-but-misrouted action chains, prevents client-forged capabilities, and ensures that dynamic privileged actions in multi-step agent workflows always trace back to specific authenticated user confirmation.

---

## 6) Security Analysis

### 6.1 What CRAFT robustly improves

- Off-path forged instruction injection into transport.
- Replay, reorder, and duplicate injection of authenticated command stream.
- Cross-context and intra-channel session confusion when binding checks are enforced.
- Unauthorised privileged action attempts lacking valid capability tokens.
- Direction/reflection attacks via directional key separation.
- Post-compromise forward secrecy via periodic rekeying.
- Confused-deputy escalation via issuer-authenticated, scope-bound capability tokens.

### 6.2 What CRAFT does not, by itself, eliminate

- Semantic manipulation of model behaviour via untrusted tool content already admitted by legitimate workflows.
- Harmful but genuinely user-authenticated commands.
- Host-level compromise of verifier or signer environment.
- Client shim compromise (shim is TCB; see Section 3.2).

### 6.3 Economic shift

CRAFT shifts attacks from cheap, scalable relay/message forgery to costlier targeted operations (endpoint compromise, social engineering, host compromise), while enabling stronger deterministic gates in UNWIND.

---

## 7) Explicit Out-of-Scope (for this layer)

1. **Fully compromised client endpoint** with active key usage capability.
2. **Fully compromised proxy/verifier host** (attacker can alter verification logic/state).
3. **Social engineering** of a legitimate user into issuing dangerous but authenticated commands.
4. **Malicious trusted tool server outputs** unless separately constrained by policy/taint/approval controls.
5. **Purely semantic prompt manipulation** that remains policy-compliant and does not violate transport authenticity checks.
6. **Opaque encrypted attachment channels** where content-level inspection is unavailable (transport provenance still works, content safety remains separate).

---

## 8) Performance and Operational Targets

### 8.1 Performance targets

- Envelope verify + replay check: p95 < 0.5 ms on commodity hardware.
- Capability validation at tool dispatch: p95 < 0.3 ms.
- Rekey derivation: < 1 ms.
- No external network dependency in hot path.

### 8.2 State/storage requirements

- Per-session, per-direction, per-epoch replay bitmap.
- Persistent `state_commit` checkpoint with atomic writes.
- Capability token issuer table with TTL eviction and revocation support.
- Last 32 `state_commit` values for fast resync re-anchor.
- Session tombstone list (2x replay window TTL).

### 8.3 Availability controls

- Bounded verifier queue depth.
- Rate-limit invalid MAC floods by source/session.
- Rate-limit resync challenges: max 5 per session per 60 seconds, exponential backoff.
- Deterministic error codes for operator triage (detailed codes only post-MAC-validation).
- Clock failure resilience: seq/state chain continue operating independently of wall clock.

---

## 9) UNWIND/MCP Integration Guidance

1. Insert CRAFT verification at **front of ingress path** (before model/tool planning).
2. Bind CRAFT context tuple to UNWIND principal model (`account_id + channel_id + conversation_id + context_type`).
3. Require capability tokens for sensitive tool classes (`exec`, filesystem writes, external egress, credential operations).
4. Enforce capability constraint normalisation (Section 5.5) using UNWIND's existing path jail and egress policy infrastructure.
5. Persist cryptographic decision logs in tamper-evident recorder chain (entries signed with `state_commit` hash).
6. Run GhostMode first for capability policies, then staged enforcement.
7. Capability tokens are passed to UNWIND via secure internal channel (local IPC), never through the model context.

---

## 10) Evaluation Plan

### 10.1 Security tests

- MAC forgery attempts.
- Replay, reorder, duplicate injection.
- Context confusion (session, account, channel, conversation mismatch).
- Resync abuse: rollback attempts, replay window reset attempts, flood attacks.
- Capability overreach: tool, args, target, TTL, reuse, chain splicing.
- Capability forgery: client-minted tokens, tampered claims, replayed tokens.
- Direction reflection: C→P MAC replayed as P→C.
- Downgrade attacks: version negotiation tampering, epoch rollback.
- DNS rebinding against network target constraints.
- Symlink/path traversal against filesystem target constraints.

### 10.2 Robustness tests

- Packet loss and strict FIFO hold/timeout behaviour.
- Client restart and verifier restart (with and without persisted state).
- Long-session epoch rollover and rekey transitions.
- Clock rollback and extreme skew scenarios.
- Resync under concurrent traffic.

### 10.3 Metrics

- False reject rate for valid traffic under normal and degraded conditions.
- False accept rate under adversarial replay/tamper corpus.
- Mean time to detection for replay/tamper attempts.
- p95 and p99 latency contribution (verify, cap validation, rekey).
- Resync success rate and time-to-recovery.

---

## 11) Production Hardening Checklist (v5 targets)

The following items are not required for initial single-proxy deployment but should be addressed for production maturity:

- Session revocation distribution list (beyond TTL eviction).
- Tamper-evident audit log format specification (chain-signed entries with state_commit hash).
- Multi-proxy federation model (shared PRK derivation or per-proxy sub-keys with coordinated replay state).
- Forward secrecy verification in bootstrap (formal proof that ephemeral ECDH + HKDF schedule provides PFS).
- Token binding to tool-call hash (optional one-shot hardening: cap includes digest of canonical intended call).

---

## 12) References

[^1]: Nasr, M., Carlini, N., et al. **"The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections."** arXiv:2510.09023 (2025). Abstract states: "we bypass 12 recent defenses ... with attack success rate above 90% for most."
      https://arxiv.org/abs/2510.09023

[^2]: UK NCSC. **"Prompt injection is not SQL injection (it may be worse)."** States: "it's very possible that prompt injection attacks may never be totally mitigated in the way that SQL injection attacks can be."
      https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection
      PDF: https://www.ncsc.gov.uk/pdfs/blog-post/prompt-injection-is-not-sql-injection.pdf

[^3]: UK NCSC (with CISA and partners). **"Guidelines for secure AI system development."** Recommends layered controls and secure-by-design treatment of AI risk.
      https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development

[^4]: OWASP. **LLM Top 10: Prompt Injection (LLM01).** Industry risk taxonomy reference for generative AI applications.
      https://genai.owasp.org/llmrisk/llm01-prompt-injection/

[^5]: Greshake, K., et al. **"Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection."** arXiv:2302.12173 (2023).
      https://arxiv.org/abs/2302.12173

---

## Appendix A: Minimal Verifier Pseudocode

```text
function verify_and_admit(envelope, direction, session):
    # Phase 1: Pre-auth checks (generic errors only)
    require schema_valid(envelope)
    require envelope.epoch == session.current_epoch
    require envelope.direction == direction

    canonical_fields = canonicalize(remove_mac(envelope))
    mac_input = build_mac_input(canonical_fields)
    K_msg = session.keys[direction].K_msg

    if !hmac_eq(envelope.mac, HMAC(K_msg, mac_input)):
        return reject(ERR_ENVELOPE_INVALID)  # generic, pre-auth

    # Phase 2: Post-auth checks (detailed errors)
    if !context_bind_ok(envelope, session):
        return reject(ERR_CONTEXT_MISMATCH)

    if envelope.seq != session.highest_seq[direction] + 1:
        return reject(ERR_REPLAY)  # strict FIFO gap/rollback

    if replay_detected(envelope.seq, session.replay_bitmap[direction]):
        return reject(ERR_REPLAY)

    expected_commit = HMAC(
        session.keys[direction].K_state,
        session.last_state_commit[direction] || envelope.mac
    )
    if !hmac_eq(envelope.state_commit, expected_commit):
        return reject(ERR_STATE_DIVERGED)

    if requires_privilege(envelope):
        cap = get_out_of_band_capability(envelope.seq)
        if cap is None:
            return reject(ERR_CAP_REQUIRED)
        if !cap_valid_and_scoped(cap, envelope, session):
            return reject(ERR_CAP_INVALID)

    atomic {
        session.highest_seq[direction] = envelope.seq
        session.last_state_commit[direction] = expected_commit
        session.replay_bitmap[direction].mark(envelope.seq)
        if cap: session.issuer_table[cap.cap_id].remaining_uses -= 1
    }

    check_rekey_trigger(session)
    return admit()


function cap_valid_and_scoped(cap, envelope, session):
    require session.issuer_table.contains(cap.cap_id)
    entry = session.issuer_table[cap.cap_id]
    require !entry.revoked
    require now_ms() < cap.exp
    require entry.remaining_uses > 0
    require cap.session_id == session.id
    require cap.conversation_id == envelope.conversation_id
    require cap.context_type == envelope.context_type
    require envelope.seq >= cap.bind_seq
    require transcript_consistent(cap.state_commit_at_issue, session)
    require tool_in(envelope.tool_id, cap.allowed_tools)
    require args_satisfy(envelope.tool_args, cap.arg_constraints)
    require target_satisfies(envelope.tool_target, cap.target_constraints)
    if cap.parent_cap_id:
        require parent_cap_used(cap.parent_cap_id, session)
    return true
```

## Appendix B: Canonical Encoding Example

Example envelope before MAC computation (JCS-canonical output):

```json
{"account_id":"acct_001","channel_id":"ch_main","context_type":"dm","conversation_id":"conv_7f3a","direction":"c2p","epoch":0,"msg_type":"user_instruction","payload":{"meta":{},"text":"delete file /tmp/test.txt"},"seq":"42","session_id":"sess_abc123","state_commit":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ts_ms":1739999999123,"v":4}
```

MAC input bytes (for K_msg_c2p):

```text
Binary `MAC_input(envelope)` as defined in Section 4.4: length-prefixed concatenation of canonical field bytes, including `seq` as uint64 big-endian, `state_commit` as raw 32 bytes, and payload as UTF-8 bytes of JCS-canonical JSON.
```

State commitment input bytes:

```text
state_commit_{n-1}  (32 raw bytes)
||
envelope_n.mac      (32 raw bytes)
```

Total: 64 bytes input to `HMAC-SHA256(K_state_c2p, ...)`.

---

## Appendix C: Collab Review Traceability

This version (v4) incorporates findings from three independent adversarial reviews conducted in February 2026. Key changes from v3 and their provenance:

- **K_cap server-only key** (Collab 3, Finding 1): K_cap_srv derived from server secret, not shared PRK.
- **Strict FIFO** (Collabs 1/2/3, unanimous): Out-of-order language removed; strict sequential verification.
- **Resync invariants** (Collabs 2/3): No rollback, no replay window reset, epoch bump on resync.
- **MAC-chained state commitment** (Collab 2, Finding 4): state_commit chains envelope MACs, not raw fields.
- **Directional keys** (Collab 3, Finding 7): Separate C→P and P→C keys for all operations.
- **Genesis values** (Collab 3, Finding 8): state_commit_0 and initial seq explicitly defined.
- **Capability minting protocol** (Collabs 1/2/3): Deterministic mint trigger, step-up auth, chained caps.
- **Timestamp demotion** (Collab 3, Finding 9): ts_ms advisory only, not rejection gate.
- **Nonce removal from FIFO path** (Collab 3, Finding 10): Strict seq provides replay resistance.
- **Version negotiation** (Collab 1 / SENTINEL): Downgrade protection in bootstrap.
- **Canonical encoding hardened** (Collabs 1/2/3): JCS mandatory, exact byte-level MAC input rules.
- **Constraint normalisation** (Collab 3, Finding 5): DNS rebinding, symlink, punycode handling.
- **Caps out of model context** (Collab 3, Finding 14): Out-of-band metadata, never in prompt.
- **Session lifecycle** (Collabs 1/2/3): TTL, teardown, crash persistence, clock failure handling.
- **Context binding extended** (Collab 3, Finding 13): conversation_id added to binding tuple.
- **Error disclosure** (Collab 3, Finding 16): Generic pre-auth, detailed post-auth only.
- **TLS/Noise IKM extraction** (Collab 3, Finding 17): Exporter labels specified.
- **NCSC citation tightened** (Collabs 1/3): direct wording preserved without over-claiming chronology in-text.
