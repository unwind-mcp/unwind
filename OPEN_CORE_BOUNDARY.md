# OPEN_CORE_BOUNDARY.md

**Project:** UNWIND  
**Status:** Draft (agreed direction, pending legal finalization)  
**Last updated:** 2026-03-01 (Europe/London)

---

## 1) Boundary intent

UNWIND adopts an **open-core** model with a hard rule:

> Any component that can directly change security allow/block semantics must remain open.

Premium value is built on deployment scale, governance, convenience, and enterprise operations — not hidden security logic.

---

## 2) Core principles

1. **Verifiable security path**: policy decisions must be auditable in open code.
2. **No hidden trust assumptions**: core enforcement, provenance, and verifier logic are public.
3. **Premium is additive**: paid features improve operations, not decision integrity.
4. **Deterministic parity**: open users and premium users share the same enforcement semantics.

---

## 3) Open vs Premium boundary

## OPEN CORE (public)

### Enforcement / trust-critical
- `unwind/enforcement/*` pipeline checks
  - canary, self-protection, exec tunnel, credential exposure
  - path jail, SSRF, egress policy, DLP-lite
  - taint, session scope, ghost mode, cadence stage hooks
- `unwind/sidecar/*` policy API + enforcement wiring
- `openclaw-adapter/*` policy hook integration interfaces

### Provenance / verification
- CRAFT protocol + verifier + persistence format
- Chain validation tooling (`unwind verify`) and integrity checks

### Safety contracts
- Canary contract tests
- Security regression tests and policy ordering checks

### Cadence (core layer)
- Cadence data contract/schema (`pulse.jsonl`, `state.env`, CRIP headers)
- Cadence Bridge interface + stage wiring
- Baseline cadence inference engine (FLOW/READING/DEEP_WORK/AWAY)

### Secret handling in enforcement path
- **Secret Registry remains open** (exact-match known-secret detection in Ghost/Egress path)

---

## PREMIUM (commercial)

### Operations at scale
- Fleet policy orchestration / multi-node management
- Centralized policy distribution and drift governance
- Team/org control plane and advanced role workflows

### Enterprise integrations
- SIEM/SOAR/ITSM connectors
- SSO/SCIM integrations
- Compliance export packs and managed evidence pipelines

### Managed trust services
- Managed passkey signing/custody workflows
- Hosted attestation and long-retention forensic services

### Advanced Cadence features
- Multi-device/user synchronization
- Team/family mode and shared rhythm policies
- Predictive availability and personalization layers
- Advanced analytics/forecasting modules

### UX / convenience layers
- Advanced dashboard modules (beyond baseline open observability)
- Premium alerting and workflow automation packs

---

## 4) Explicit inclusions/exclusions

## Explicitly OPEN
- Enforcement decision logic and policy order
- Secret Registry matching behavior
- Cadence Bridge decision interface
- CRAFT verification correctness path

## Explicitly PREMIUM
- Hosted control plane features
- Enterprise/compliance packaging
- Managed identity/workflow products

---

## 5) Repo layout proposal

## Option A (single public repo + private premium repo) — recommended now

Public `unwind` repo:
- `unwind/` (open core runtime)
- `openclaw-adapter/` (open integration layer)
- `cadence/` (open cadence core)
- `tests/` and `tests/cadence/` (open test suites)
- `docs/` (open architecture/spec docs)
- `OPEN_CORE_BOUNDARY.md` (this file)

Private premium repo(s):
- `unwind-enterprise-control-plane`
- `unwind-enterprise-integrations`
- `unwind-enterprise-compliance`

Pros: clear legal boundary, simple OSS consumption, cleaner contributor experience.

## Option B (monorepo with gated packages)

Single repo with `packages/open/*` and `packages/premium/*` split.

Pros: shared CI/release automation.  
Cons: higher accidental boundary drift risk; harder public contribution ergonomics.

---

## 6) Licensing and contribution policy (draft)

### Open core license candidate
- **AGPL-3.0** (current direction): strong network copyleft to deter closed hosted forks.

### Contributor governance
- CLA for relicense/commercial certainty (draft legal policy):
  - patent grant + right to commercial-license premium offerings
  - clear contributor ownership language

### Practical legal note
- Keep legal docs explicit and separated:
  - `LICENSE` (AGPL-3.0 for open core)
  - `CONTRIBUTING.md` (rules)
  - `CLA.md` and signature flow docs

---

## 7) Non-negotiable guardrails

1. No premium-only hidden enforcement checks.
2. No premium-only bypass/override of open enforcement semantics.
3. Any premium workflow affecting allow/block must call the same open core path.
4. Security claims must stay reproducible from open artifacts.

---

## 8) Review cadence

Re-review this boundary at each major release or when adding:
- new enforcement stages
- new trust/provenance primitives
- new Cadence signal classes
- new managed control-plane capabilities
