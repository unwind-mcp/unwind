# What is UNWIND?

UNWIND is a local security sidecar for AI agents (OpenClaw now, NanoClaw planned). It sits between the agent and every tool call, then runs a deterministic enforcement pipeline before anything executes.

If a policy check fails (or an internal error happens), UNWIND fails closed with a block decision.

## What it does in practice

UNWIND layers multiple controls: supply-chain verification, canary tripwires, self-protection, exec-tunnel detection, credential scanning, path jail, SSRF + egress controls, DLP-lite, circuit breaker logic, taint tracking with decay, session scope checks, and Ghost Mode gating.

This is defense-in-depth: each stage reduces attack surface; no single stage is the whole defense.

## Recent hardening highlights

- **Mandatory sidecar auth (CWE-306 fix):** every sidecar request must authenticate.
- **Auto-generated secrets:** if no shared secret is supplied, a cryptographic secret is generated so auth is still enforced.
- **Watchdog stale-hook detection:** health now reports stale enforcement hook state.
- **Unix Domain Socket (UDS) support:** sidecar transport can run over UDS in addition to localhost TCP.
- **Ghost Mode prefix heuristic:** mutating tools can be caught by risky-action prefixes even when not explicitly listed.
- **Taint decay gaming coverage:** taint logic is tested against **29 adversarial attack patterns**.

## Ghost Mode

Ghost Mode is UNWIND’s preview/sandbox path for mutations. Mutating actions are intercepted and redirected to shadow state instead of changing real systems, while reads remain consistent with what the agent believes it changed.

Operator-facing states:
- **Green Light:** **No violations detected** — call proceeds.
- **Amber:** review required.
- **Red:** blocked by policy.
- **Ghost Mode:** agent can continue operating, but mutations stay in shadow state until replay is explicitly approved.

## Known Limitations

- **GET-as-mutation:** Ghost Mode cannot intercept HTTP `GET` requests that trigger server-side mutations (for example, `GET /api/delete?id=5`).
  - This is a fundamental limitation: blocking all GET traffic would also break legitimate read operations.
  - **Future direction (v2 roadmap):** semantic mocking for stateful APIs.
