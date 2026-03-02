# UNWIND Decisions Log

**Purpose:** Append-only record of architectural and product decisions. Both Claude and SENTINEL append here when decisions are made. David has final say on all decisions.

---

## Settled (do not relitigate)

These are closed. A rebooted session must not propose changes to these without explicit David approval.

1. **No LLM in the enforcement hot path.** Every check is deterministic. By design.
2. **Ghost Mode and Amber Challenges are architecturally distinct.** Ghost = sandbox (fake success, shadow VFS). Amber = human-in-the-loop approval pause. Do not merge or conflate.
3. **Six-layer model is boundary-locked.** UNWIND / Rollback / Ghost Mode / CRAFT / CADENCE / CRIP. No agent may redefine boundaries without David's approval. (commit a9914ec, 2026-03-02)
4. **SENTINEL is not in the enforcement path.** Deliberate. SENTINEL is a security analyst and reviewer, not a runtime component.
5. **Market is prosumer/self-hosted.** Not enterprise-first. Threat model targets automated mass attacks, not nation-state.
6. **Green Light says "no violations detected" — never "safe."** Liability rule. Non-negotiable.
7. **One PR = one intent.** Refactor OR feature/fix, never both in the same PR.
8. **tamper-evident, not tamper-proof.** Hash chains detect tampering, they don't prevent it. Use "tamper-evident" in all docs.

---

## Decisions (2026-03-02, David + Claude alignment session)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Ghost Mode stays a separate package (`pip install ghostmode`) | Free entry point, clean adoption funnel. Lower barrier to try. |
| 2 | Dashboard: basic free, enterprise features premium | Basic trust light + timeline + verification = free. Multi-agent, team, compliance export = premium. |
| 3 | CRAFT standalone: roadmap, not for launch | Ships inside UNWIND. Extract to standalone library when enterprise demand emerges. |
| 4 | Cadence first-run messaging: mention it, lead with the nudge | "Enable Cadence to get notified when your agent is waiting for you." Turn on for convenience, keep on for security. |
| 5 | CRIP verification: verify status, audit before launch | Honest status in all docs. Audit enforcement coverage before launch, not before review. |
| 6 | Alpha tag: after Opus review, not before | Let Opus be the first external eyes, then stamp. |

---

## How to add a decision

Append to the table above with date and who decided. If the decision is permanent and must not be relitigated, also add it to the Settled list at the top.
