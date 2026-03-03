# Interview Script

**Topic:** Understanding the UNWIND + Cadence + CRAFT stack

**Characters:**

- **Alex** — New OpenClaw user. Smart, practical, not deeply technical.
- **Dr. Sam** — Friendly AI agent specialist who explains complex systems clearly.

**Scene:** Informal chat over video call

---

## 1. Opening — What Is This Thing Actually For?

**Alex:**
I keep hearing about UNWIND, Cadence, CRAFT... I understand OpenClaw runs persistent agents. But what does this stack actually do for someone like me?

**Dr. Sam:**
Great question. In simple terms:

- OpenClaw gives you persistent AI agents.
- UNWIND makes those agents safe to run.
- Cadence makes them behave more like a thoughtful collaborator.
- CRAFT makes everything they do provable and tamper-evident.

Together, they turn "powerful automation" into "controlled, reversible, auditable automation."

---

## 2. UNWIND Core — The Safety Gate

**Alex:**
Okay. Let's start with UNWIND. What does it actually do?

**Dr. Sam:**
Think of UNWIND as a security checkpoint that sits between the agent and your system.

When your agent wants to run a shell command, modify files, call an API, or access the network — UNWIND evaluates that action before it happens.

It doesn't rely on the AI "promising to behave."
It applies deterministic rules — a 15-stage pipeline that checks every call.

It can say:

- **Green** — yes, go ahead.
- **Red** — no, blocked.
- **Amber** — pause, this needs your attention.

**Alex:**
So it's like a firewall?

**Dr. Sam:**
Exactly — but for agent actions, not network packets. And you can see the trust state at a glance: green, amber, or red. It's always visible on the dashboard.

---

## 3. Why That Matters

**Alex:**
But don't agents already have guardrails?

**Dr. Sam:**
Mostly prompt-based guardrails. Those are helpful — but they're advisory.

UNWIND operates at runtime. It's enforcement, not suggestion.

If something violates scope — it simply doesn't execute.

That's the difference.

---

## 4. Smart Snapshots — Undo for Agents

**Alex:**
What about this rollback thing I heard about?

**Dr. Sam:**
That's one of the most important parts.

Before the agent does something risky — like rewriting code or modifying a configuration — UNWIND takes a snapshot.

If the change turns out to be wrong: you roll back. No damage done.

It turns agent actions into reversible transactions.

**Alex:**
So like version control?

**Dr. Sam:**
Yes — but automatic and built into execution. Instead of hoping nothing breaks, you can safely experiment.

---

## 5. Ghost Mode — The Dry-Run Sandbox

**Alex:**
What if I'm not even sure I want the agent to try something?

**Dr. Sam:**
That's exactly what Ghost Mode is for.

You flip a switch — on the dashboard or via the API — and the agent keeps working, but nothing real happens. File writes, shell commands, network requests — all intercepted and simulated.

The agent thinks everything succeeded. But your system hasn't changed at all.

**Alex:**
So it's running in a sandbox?

**Dr. Sam:**
Exactly. A shadow filesystem keeps the agent consistent — if it writes a file and then reads it back, it gets the content it wrote. But nothing touched your real files.

When you're ready, you review what the agent tried to do. The dashboard shows you side by side: "what the agent attempted" and "what actually happened." Then you either approve the writes — and they go through for real — or discard everything.

**Alex:**
That's like a preview mode for agents.

**Dr. Sam:**
That's the best way to think about it. It turns "should I let the agent try this?" from a leap of faith into a preview.

---

## 6. CRAFT — Tamper-Evident Audit

**Alex:**
Okay, and CRAFT?

**Dr. Sam:**
CRAFT is the audit backbone.

Every action — allowed, blocked, simulated, or reversed — gets written into a cryptographic chain.

Each entry is linked to the previous one with a hash. If someone tried to edit history, the chain would break. But it goes further: every command is also signed cryptographically. So you can prove not just what happened, but that each command came from an authorised source in the right order. An injected command would break the signature.

**Alex:**
So it's tamper-evident?

**Dr. Sam:**
Exactly. It means:

- You can prove what happened.
- You can show regulators.
- You can investigate incidents.
- You can trust the log.

Think of it as a flight recorder for AI agents.

---

## 7. Cadence — The Human Rhythm Layer

**Alex:**
Now Cadence — this one sounds more abstract.

**Dr. Sam:**
Cadence is surprisingly simple.

It looks at the timing between your interactions.

If you're:

- Rapidly typing back and forth — you're in **FLOW**.
- Quiet after a long AI response — you're probably **READING**.
- Away for hours — you're **AWAY**.
- Working steadily but slower — **DEEP_WORK**.

**Alex:**
And the system knows that just from timing?

**Dr. Sam:**
Yes. No invasive monitoring. Just timestamps and simple maths.

---

## 8. Why That Helps

**Alex:**
So what's the benefit?

**Dr. Sam:**
Two major benefits:

**1) Better Behaviour**

The agent stops interrupting you while you're reading. It batches suggestions during deep work. It doesn't send follow-ups while you're away.

It becomes rhythm-aware instead of needy.

**2) Security Signal**

If the system detects tool calls happening at machine-speed while you're marked AWAY, or perfectly periodic execution patterns — UNWIND flags that as suspicious.

Timing becomes an anomaly signal. Without reading your content. Without tracking your behaviour invasively.

---

## 9. CRIP — The Consent Layer

**Alex:**
That sounds powerful. Is that privacy-safe?

**Dr. Sam:**
That's what CRIP handles.

CRIP defines where timing data can be processed, how long it's stored, whether you can delete it, and what consent applies.

And critically — the defaults are maximally restrictive. Local only. Seven-day rolling window. User-deletable. No cloud. You have to explicitly opt into anything broader.

It prevents timing intelligence from becoming surveillance. It keeps the user in control.

---

## 10. Putting It All Together

**Alex:**
So how do these pieces work together in practice?

**Dr. Sam:**
Imagine your agent is working on your project.

You go quiet for 3 hours. Cadence marks you AWAY.

Suddenly, a burst of shell commands fires off at sub-second intervals.

UNWIND sees: user is AWAY, machine-speed tool calls, high anomaly score.

It can trigger amber mode, kill the session, snapshot state, and log everything into CRAFT.

You come back and see: exactly what happened, that it was contained, that nothing irreversible occurred. All verifiable in the chain.

Or — say you're about to let the agent refactor a critical module and you're not sure. You switch on Ghost Mode first. The agent runs the refactor. You review the result. If it looks good, you approve and Ghost Mode commits the files. If not, you discard and nothing changed.

That's the stack working as one system.

---

## 11. Who Is This For?

**Alex:**
Who actually needs all this?

**Dr. Sam:**
Three main groups:

- Enterprises deploying persistent agents
- Security-conscious teams
- Anyone letting agents touch real systems

If an agent can write files, run commands, or access APIs — you want containment, rollback, preview, and audit.

---

## 12. What It's Not

**Alex:**
Is this about making AI smarter?

**Dr. Sam:**
No.

It's about making AI governable.

Smarter AI increases capability. UNWIND increases trust.

They're different axes.

---

## 13. Final Summary

**Alex:**
If you had to sum it up?

**Dr. Sam:**

- UNWIND makes agents safe to run.
- Smart Snapshots make them reversible.
- Ghost Mode makes them previewable.
- CRAFT makes them auditable and tamper-proof.
- Cadence makes them human-aware.
- CRIP makes them consent-bound.

Together, they turn autonomous AI from "exciting but risky" into "powerful and controllable."
