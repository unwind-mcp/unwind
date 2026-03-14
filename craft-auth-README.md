# CRAFT

**Transport-layer command authentication for AI agents.**

CRAFT proves who issued a command, when it was issued, and that nothing changed it in transit. It turns "we have logs" into "we have evidence."

It is a standalone Python library with zero dependencies — pure stdlib, installs in under a second. Use it independently or as the transport layer for [UNWIND](https://github.com/unwind-mcp/unwind).

Requires Python 3.9+.

## Quick Start

```bash
pip install craft-auth
```

```python
from craft import derive_session_keys, state_commit_0, CraftVerifier, CraftSessionState

# Derive session keys from shared secret
keys = derive_session_keys(
    ikm=shared_secret,
    salt0=session_salt,
    ctx=b"myapp/agent/v1",
    epoch=0,
    server_secret=server_secret,
)

# Create session and verifier
session = CraftSessionState.from_session_keys(
    session_id="sess_01", account_id="acct_01",
    channel_id="ch_01", conversation_id="conv_01",
    context_type="agent", epoch=0, keys=keys, ctx=b"myapp/agent/v1",
)
session.last_state_commit["c2p"] = state_commit_0(keys.c2p.k_state, b"myapp/agent/v1")
session.last_state_commit["p2c"] = state_commit_0(keys.p2c.k_state, b"myapp/agent/v1")

verifier = CraftVerifier()
result = verifier.verify_or_hold(envelope, session)
# result.accepted / result.error / result.held / result.drained
```

## What It Does

CRAFT wraps every command in an HMAC envelope that cryptographically binds it to a session, a sequence number, and the full history of prior commands. The verifier checks each envelope before admitting it into your agent's execution pipeline.

### Key Schedule (RFC 5869 HKDF)

Session setup derives directional key pairs from a shared secret:

- **k_msg** (c2p, p2c) — HMAC-SHA256 envelope authentication
- **k_state** (c2p, p2c) — Hash chain state commitments
- **k_resync** (c2p, p2c) — Resynchronisation challenge-response
- **k_cap_srv** — Capability token issuance (server-side only)

Keys are directional: a valid client-to-proxy MAC cannot be replayed in the proxy-to-client direction.

### HMAC Envelopes

Every message carries a MAC computed over a canonical JSON encoding of its fields (JCS-like deterministic serialisation). The verifier recomputes the MAC and rejects any envelope where the content was modified in transit.

### Strict FIFO Verification

Envelopes must arrive in sequence order. Out-of-order envelopes are held in a bounded queue (default 32 slots, 5s timeout) and drained automatically when the gap is filled. Replays are rejected via a sliding bitmap window.

### Hash Chain (State Commitments)

Each accepted envelope extends a running hash chain: `commit_n = HMAC(k_state, commit_{n-1} || mac_n)`. Both sides maintain the chain independently. If the chains diverge, the session is in a provably inconsistent state — either something was tampered with, or messages were lost.

### Capability Tokens

For privileged operations, CRAFT issues short-lived capability tokens that bind a specific tool call to an authenticated user intent:

- Scoped to session, epoch, tool, target, and arguments
- HMAC-authenticated by a server-side key the client never sees
- Single-use or bounded-use with TTL
- Chainable lineage (child tokens must reference a used parent)
- Transcript-consistent (bound to the state commit at time of issue)

### Epoch Rekeying

Sessions rekey by deriving fresh key material from the current PRK and both directional state commitments. Old keys are dropped. A time-bounded grace window allows in-flight capability tokens from the previous epoch to land.

### Resynchronisation

When a connection drops mid-session, the client can resync by replaying missed envelopes in a challenge-response protocol. The verifier walks the chain forward, validates every link, and rekeys on success. Rate-limited with exponential backoff. Bounds-exceeded terminates the session.

## v2 Attestation Features

### Host and Location Attestation

Each CRAFT envelope carries a `where` field — cryptographic proof of which machine and geographic location issued it. This opens up bespoke chain topologies for enterprise deployments:

- Separate chains per geographic region for data residency compliance
- Per-device audit trails (which laptop, which server, which edge node)
- Cross-site chain verification without centralised trust

### Chain Head Tagging

Chains carry schema version metadata at the head, enabling:

- Chain identification and versioning across deployments
- Migration between protocol versions without breaking verification
- Multi-tenant environments where chains from different applications coexist

## What It Doesn't Do

CRAFT is a transport-layer protocol. It authenticates the command stream, not the content.

- **Not prompt injection defence.** CRAFT does not analyse or filter what the agent says or does. That is the job of content-layer enforcement (like UNWIND's pipeline).
- **Not tool output trust.** CRAFT does not make model outputs or tool results trustworthy.
- **Not semantic intent validation.** A cryptographically authenticated command can still be unwise.
- **Not host compromise immunity.** If the machine is fully compromised, software-only controls are insufficient.

CRAFT is one layer in a defence-in-depth stack. It narrows the attack surface by ensuring that the commands entering your pipeline are authentic, ordered, and untampered — so your policy engine can focus on whether the action should be allowed, not whether the request is genuine.

## API Reference

### Crypto Primitives (`craft.crypto`)

| Symbol | Purpose |
|---|---|
| `hkdf_extract(salt, ikm)` | HKDF extract step (RFC 5869) |
| `hkdf_expand(prk, info, length)` | HKDF expand step |
| `derive_session_keys(...)` | Full session key bundle from shared secret |
| `derive_keys_from_prk(...)` | Key bundle from existing PRK (used by rekey) |
| `derive_rekey_prk(...)` | Derive next-epoch PRK from current state |
| `state_commit_0(k_state, ctx)` | Initial state commitment for a direction |
| `b64url_encode(raw)` | URL-safe base64 encoding (no padding) |
| `b64url_decode(value)` | URL-safe base64 decoding |

### Canonical Encoding (`craft.canonical`)

| Symbol | Purpose |
|---|---|
| `canonicalize_for_mac(envelope)` | Build MAC input object (removes `mac` and `state_commit`) |
| `mac_input_bytes(envelope)` | UTF-8 bytes of canonical MAC input |

### Verifier (`craft.verifier`)

| Symbol | Purpose |
|---|---|
| `CraftVerifier` | Stateless verifier — call `verify_or_hold()` or `verify_and_admit()` |
| `CraftSessionState` | Mutable session state (keys, sequences, replay bitmap, hold queue) |
| `VerifyResult` | Result of verification: `accepted`, `error`, `held`, `drained` |
| `VerifyError` | Error enum: `ERR_ENVELOPE_INVALID`, `ERR_REPLAY`, `ERR_STATE_DIVERGED`, `ERR_CONTEXT_MISMATCH`, `ERR_EPOCH_STALE` |

### Capabilities (`craft.capabilities`)

| Symbol | Purpose |
|---|---|
| `CapabilityIssuer` | Mint, revoke, and enforce capability tokens |
| `CapabilityToken` | Frozen dataclass: `cap_id`, `claims`, `cap_mac` |
| `CapabilityDecision` | Enforcement result: `allowed`, `error`, `subcode` |
| `CapabilityError` | Error enum: `ERR_CAP_REQUIRED`, `ERR_CAP_INVALID` |
| `CapabilitySubcode` | Detailed failure: `CAP_EXPIRED`, `CAP_REVOKED`, `CAP_EPOCH_MISMATCH`, etc. |
| `ToolCall` | Frozen dataclass binding a tool invocation to session context |
| `StepUpChallenge` | Challenge for human-in-the-loop step-up authentication |

### Lifecycle (`craft.lifecycle`)

| Symbol | Purpose |
|---|---|
| `CraftLifecycleManager` | Rekey, resync, session expiry, and teardown |
| `RekeyPrepare` | Rekey boundary markers (epoch + sequence boundaries) |
| `ResyncChallenge` | Server-issued resync challenge with nonce and MAC |
| `ResyncResult` | Resync outcome: `ok`, `error`, `new_epoch` |
| `ResyncError` | Error enum: rate limit, bounds, challenge invalid, proof invalid, state diverged |

### Persistence (`craft.persistence`)

| Symbol | Purpose |
|---|---|
| `CraftStateStore` | Atomic JSON snapshot persistence for session state and tombstones |

## Threat Model

### Attacks CRAFT stops

| Attack | How |
|---|---|
| **Replay** | Strict monotonic sequence numbers + sliding replay bitmap |
| **Tampering** | HMAC-SHA256 over canonical envelope — any modification invalidates the MAC |
| **Spoofing** | Directional keys — client and proxy keys are distinct, cross-direction replay fails |
| **Session hijack** | Context binding — envelope must match session, account, channel, conversation, and context type |
| **Confused deputy** | Capability tokens — privileged tool calls require a server-issued, scope-bound, time-limited token |
| **Chain break** | State commitments — each envelope extends a running hash chain; gaps are detectable and provable |
| **Epoch downgrade** | Stale epoch envelopes rejected; grace windows are time-bounded and cover only the previous epoch |

### Attacks CRAFT does not stop

| Attack | Why | What does |
|---|---|---|
| Prompt injection | Content-layer attack, not transport-layer | Content filtering, UNWIND pipeline |
| Malicious tool output | Trust is about the command source, not the result | Output validation, sandboxing |
| Host compromise | Software-only protocol, not hardware attestation | OS-level security, HSMs |
| Social engineering | Authenticated user can still issue bad commands | Policy enforcement, human review |

## Why It Matters

Most agent frameworks log what happened. Logs are mutable, unsigned, and trivially forgeable after the fact.

CRAFT produces a hash chain where every entry is cryptographically bound to the one before it. You cannot insert, remove, or modify an entry without breaking the chain. This is the difference between "our logs say it was fine" and "here is a cryptographic proof that every command was authentic and in order."

For compliance, incident response, and forensic audit, that distinction matters.

## Relationship to UNWIND

CRAFT is fully standalone. It has zero imports from UNWIND and zero external dependencies.

Inside UNWIND, CRAFT serves as the transport authentication layer — the first thing that touches an incoming command before it reaches the 15-stage enforcement pipeline. But you can use CRAFT without UNWIND in any agent framework, MCP server, or tool-calling system that needs command provenance.

| | **CRAFT standalone** | **CRAFT + UNWIND** |
|---|---|---|
| Command authentication | ✅ | ✅ |
| Tamper-evident audit chain | ✅ | ✅ |
| Capability tokens | ✅ | ✅ |
| Policy enforcement | — | 15-stage pipeline |
| File rollback | — | Smart snapshots |
| Trust dashboard | — | Web UI |
| Ghost Mode (dry-run) | — | Write interception + shadow VFS |

## Zero Dependencies

CRAFT uses only Python 3.9+ stdlib: `hashlib`, `hmac`, `json`, `base64`, `os`, `time`, `dataclasses`, `pathlib`, `enum`, `socket`, `re`, `tempfile`. No cryptography library. No C extensions. Installs in under a second.

## License

AGPL-3.0-or-later
