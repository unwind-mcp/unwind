# ADR-001: Ghost Egress Guard runs before SSRF Shield

- **Status:** Accepted
- **Date:** 2026-02-25
- **Deciders:** David Russell, Claude, SENTINEL
- **Related:** `unwind/enforcement/pipeline.py`, `unwind/enforcement/ghost_egress.py`, `tests/test_ghost_egress.py`, `tests/canary/test_canary_contracts.py`

---

## Context

UNWIND Ghost Mode is designed to simulate risky actions without touching real systems.
A gap was identified: in Ghost Mode, read-channel network tools (HTTP GET, web fetch,
search/query style tools) could still exfiltrate sensitive values through outbound
requests if only SSRF was consulted.

SSRF checks destination trust boundaries (metadata/private/internal), but does not
represent Ghost Mode intent. Ghost Mode requires stronger posture: block or gate
network reads before DNS/SSRF processing.

## Decision

Place **Ghost Egress Guard (stage 3b)** before **SSRF Shield (stage 4)** in the
enforcement pipeline.

- Stage 3b enforces Ghost Mode network policy (`isolate` / `ask` / `filtered`) first.
- Stage 4 SSRF still runs for non-ghost or allowed pathways as defense-in-depth.
- Pipeline ordering is treated as a contract and guarded by canary tests.

## Consequences

### Positive

- Ghost Mode closes read-channel exfil path earlier and more deterministically.
- Policy intent is explicit: Ghost posture is enforced before network resolution.
- Easier reasoning for operators: Ghost egress denial is not conflated with SSRF denial.

### Trade-offs

- Additional stage coupling: ordering now matters for correctness and must be tested.
- Some blocked requests now report Ghost policy reasons instead of SSRF reasons.

### Follow-up actions

- Keep ordering regression tests permanent (`test_ghost_egress_fires_before_ssrf`).
- Keep continuity docs updated with stage 3b→4 rationale.
- Treat any ordering regression as release-blocking.

### Rollback/supersession conditions

Supersede only if a stronger network mediation architecture replaces stage-level ordering
while preserving equivalent or stronger Ghost Mode exfiltration guarantees.
