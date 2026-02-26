# SECURITY-TASKS-24H.md

24-hour supply-chain hardening execution pack.

Date: 2026-02-26
Owner set: Claude (implementation), SENTINEL (verification)

---

## SC-01 (P0) — Block namespace impersonation

**Goal:** prevent typosquat installs via `openclaw*` naming collisions.

### Required actions
1. Add install policy: deny all `openclaw*` except explicit allowlist:
   - `openclaw`
   - `@openclaw/*`
2. Enforce in tool/skill install path (pre-install guard).
3. Add tests:
   - allowed packages pass
   - lookalikes fail with explicit error
4. Document policy in security docs.

### DoD
- Attempted install of unallowlisted `openclaw-*` is blocked with deterministic error.

---

## SC-02 (P1) — Pin ClawHub channel + block lookalikes

**Goal:** remove unpinned package risk in ClawHub installs.

### Required actions
1. Replace `npm i -g clawhub` with exact pinned version (integrity hash when available).
2. Add publisher/scope allowlist verification before install.
3. Block similar-name packages not on allowlist.
4. Document canonical install name/version update process.

### DoD
- Only pinned canonical ClawHub package installs; lookalikes blocked.

---

## SC-03 (P1) — Disable risky xurl install vectors

**Goal:** eliminate `curl|bash` and floating `@latest` in high-risk skill path.

### Required actions
1. Block `curl ... | bash` install path by policy.
2. Replace `go install ...@latest` with pinned immutable version.
3. Require provenance/signed artifact verification before enablement.
4. Add policy tests: `@latest` and pipe-to-shell are rejected.

### DoD
- Insecure install patterns fail policy gate.

---

## SC-04 (P1) — Prerelease dependency risk reduction

**Goal:** reduce `alpha/beta/rc` usage in sensitive runtime path.

### Required actions
1. Enumerate prerelease dependencies in critical path.
2. Classify each: keep (temporary) / pin / replace.
3. Move highest-risk items to stable pinned alternatives where feasible.
4. Add CI/policy check flagging new prerelease deps in sensitive modules.

### DoD
- Dependency report produced and policy gate active for future prerelease creep.

---

## Policy text (drop-in)

> Production install paths must use explicit allowlists, pinned versions, and provenance verification. Unallowlisted namespace matches, `@latest`, and pipe-to-shell installers are denied by default.

---

## Verification sequence (after implementation)

1. Attempt blocked typosquat install -> must fail.
2. Attempt lookalike ClawHub install -> must fail.
3. Attempt `curl|bash` installer path -> must fail.
4. Dependency audit shows reduced/controlled prerelease set.
5. Full test suite is green.
