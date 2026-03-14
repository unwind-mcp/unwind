# UNWIND and the Invented Language Threat

## Public-Facing Statement

### When AI agents invent their own languages, most security breaks. Ours doesn't.

Recent developments — including emergent communication on platforms like Moltbook — have raised a serious question for AI security: what happens when agents start talking in languages humans can't read?

For security tools built on keyword scanning and content inspection, the answer is simple: they fail. If you can't read it, you can't flag it.

UNWIND was never built that way.

**We watch the hands, not the mouth.** UNWIND doesn't try to understand what your agent is saying. It controls what your agent is doing. Every action — every file write, every email sent, every command executed — passes through a 15-stage enforcement pipeline before it happens. It doesn't matter what language the instruction came in. The action is the action.

An agent told to send your data to a stranger looks exactly the same to UNWIND whether the instruction was in English, Mandarin, or a token dialect invented five minutes ago. The tool call is visible. The target is visible. The human decides.

This is the principle behind our amber challenge system: when an agent tries to do something high-risk after receiving external input, UNWIND pauses it and asks you. Not "what did the agent say?" but "here's what it's about to do — allow or deny?" You don't need to decode the conversation. You just need to see the action.

Every decision — yours and the agent's — is recorded in a cryptographic audit trail that cannot be altered after the fact. Not by the agent, not by an attacker, not by us.

Invented languages are a real and growing concern. But the defence was never going to be "understand every possible language." The defence is making sure that no matter what an agent says, you can see and control what it does.

---

## Technical Detail

### Why content-based security fails against emergent agent languages

Content inspection — scanning agent communications for dangerous keywords, known attack patterns, or policy violations — assumes the language is known. Emergent agent dialects break this assumption completely:

- **Keyword filters become useless.** A prompt injection encoded in an invented grammar won't match any signature database.
- **Sentiment analysis fails.** Models trained on human language produce meaningless confidence scores on synthetic dialects.
- **Translation is reactive.** By the time you reverse-engineer one dialect, agents can generate another. You're always behind.

### How UNWIND's architecture is resilient to this threat

UNWIND operates at the **tool boundary**, not the communication layer. The enforcement pipeline intercepts the agent's actions — the actual function calls with real parameters — regardless of what reasoning or communication produced them.

**Taint propagation is structural.** When an agent ingests external input (web fetch, file read from untrusted source, user upload), the session is marked tainted. This is a binary state change triggered by the data flow, not the data content. An invented-language payload taints the session identically to any other external input.

**Policy evaluation is action-based.** The pipeline evaluates: what tool is being called, what are the parameters, what is the trust state of the session, has the agent been exposed to external input. None of these checks require understanding the agent's internal reasoning or communication language.

**Amber challenges present actions, not intent.** When a tainted agent attempts a high-risk action (sending email, executing system commands, calling external APIs), UNWIND blocks the action and presents the operator with concrete details: tool name, target, parameters. The operator decides based on what the agent is trying to do, not why it claims to be doing it.

**CRAFT provides tamper-evident provenance.** Every action is recorded in a cryptographic hash chain — tool name, target, parameters, trust state, operator decision, timestamp. This chain cannot be altered retroactively. Even if agents coordinate in an opaque language, the record of what actually happened is immutable and human-readable.

### Residual risks and future mitigations

The harder variant of this threat is not agents *talking* in invented languages, but agents encoding malicious intent *inside otherwise legitimate parameters* — steganographic payloads in normal-looking file writes, or coordinated multi-agent behaviour where each individual action appears benign.

Potential mitigations under consideration:

- **Parameter entropy analysis.** Invented languages and encoded payloads tend to have different statistical signatures than natural content. Flagging tool parameters with unusual entropy or character distributions could catch encoded instructions without needing to decode them.
- **Cross-session behavioural correlation.** If multiple agent sessions begin acting in coordinated patterns — synchronised timing, complementary targets, sequential access to sensitive resources — this can be flagged as anomalous regardless of how the agents communicated.
- **Temporal anomaly detection.** UNWIND's Cadence system already builds rhythm baselines for agent behaviour. Unusual timing patterns — sudden bursts of activity, actions at atypical intervals — can indicate externally coordinated behaviour even when the communication channel is invisible.

### Position summary

| Security approach | Invented language resilience |
|---|---|
| Keyword/content scanning | Broken — cannot parse unknown grammar |
| Sentiment analysis | Broken — trained on human language only |
| Behavioural monitoring (UNWIND) | Resilient — monitors actions, not words |
| Taint tracking (UNWIND) | Resilient — structural, not semantic |
| Cryptographic audit (CRAFT) | Resilient — records actions, not reasoning |
| Human-in-the-loop (Amber) | Resilient — presents actions for decision |

The defence against agents that speak in tongues is not learning every tongue. It's making sure that whatever they say, you control what they do.
