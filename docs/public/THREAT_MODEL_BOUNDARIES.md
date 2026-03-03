# UNWIND Threat Model Boundaries

This note defines what UNWIND is designed to handle, and what is out of scope.

## In scope

- **Automated and opportunistic attacks** against AI tool execution paths.
- **Mass-scale abuse patterns** (prompt injection chains, SSRF pivots, egress misuse, tunnelled command abuse).
- **Defense-in-depth controls** where each stage reduces attack surface and catches different failure modes.

## Explicitly out of scope

- **Determined individual or state-level adversaries** with sustained, bespoke targeting and deep operational resources.
- **Enterprise SOC replacement** use cases (SIEM/SOAR, full IR lifecycle, organization-wide control planes).

UNWIND is built for a **prosumer/self-hosted** operating model, not as an enterprise security platform.

## Trust boundary

- **Trusted:** the human operator.
- **Untrusted by default:** the agent and external tool/content inputs.

UNWIND enforces policy around agent actions; it does not assume the agent is aligned or benign.

## Security posture statement

UNWIND is a layered control system. **No single stage is a silver bullet.**
Protection comes from composing multiple checks (supply-chain, self-protection, SSRF/egress, taint, approval/ghosting, telemetry/audit) so one bypass does not imply total failure.

## Known gaps and constraints

1. **No capability-token model (yet).**
   Fine-grained capability token delegation depends on MCP ecosystem/spec evolution.

2. **No fd-based path jail (yet).**
   Current path controls rely on canonicalization and policy checks; robust file-descriptor-native confinement is limited by cross-platform OS/tooling constraints in the current architecture.

## Operator guidance

Use UNWIND as a strong risk-reduction layer for local agent operations. For high-assurance adversaries, add external controls (network segmentation, hardened runtime isolation, independent monitoring, and strict operational procedures).
