# UNWIND — 60-Second Acquisition Pitch

UNWIND is agent governance infrastructure: a deterministic control plane that sits between persistent AI agents and the real tools they can touch (files, shells, network, APIs). It prevents the two failure modes enterprises fear most: unbounded autonomous actions and no defensible audit trail.

UNWIND evaluates every tool call through a 15-stage deterministic policy pipeline and returns allow / block / "amber" (needs human confirmation). Before risky actions it takes smart snapshots so side effects become reversible transactions — rollback is a first-class capability, not an afterthought. Ghost Mode goes further: any session can be switched to a dry-run sandbox where the agent keeps operating but nothing real changes. The operator reviews what would have happened, then approves or discards. It turns agent deployment from a leap of faith into a preview.

Every command, decision, and snapshot is recorded into CRAFT — a cryptographically authenticated command chain with tamper-evident audit. Commands are HMAC-signed and strictly ordered; an injected or reordered command breaks the chain. Integrity can be verified independently by anyone.

Cadence adds a primitive most agent stacks lack: temporal awareness. By modelling the gaps between user instructions, it infers human-aligned states (FLOW / READING / DEEP_WORK / AWAY). That improves UX (less interruption) and provides a timing-only anomaly signal (e.g., machine-speed actions while user is AWAY). CRIP binds this timing data to explicit consent and retention rules so it can't drift into surveillance.

Bottom line: UNWIND makes persistent agents containable, reversible, previewable, and auditable at runtime — reducing enterprise risk, increasing deployability, and lowering compliance friction across frameworks and vendors.
