# FAILOVER.md — OpenClaw Seat Failover (UNWIND)

## Purpose

Provide a dead-simple operator flow when a seat hits rate limit:
- Check status
- Switch seat
- Get top-up instructions

---

## Seat map

- **Seat 1** — Team workspace (shared bucket across team plans)
- **Seat 2** — Personal Plus (<operator-email>)
- **Seat 3** — Anthropic Claude API (placeholder; only available when configured)

---

## Commands

From repo root (`UNWIND/`):

```bash
./tools/failover.sh status
./tools/failover.sh switch
./tools/failover.sh topup
```

Optional manual cooldown mark:

```bash
./tools/failover.sh mark <seat1|seat2|seat3> <minutes>
```

---

## What each command does

### `status`
- Shows active seat
- Shows per-seat availability + cooldown countdown
- Shows which seats are available now
- Auto-detects recent rate-limit lines in `/tmp/openclaw/openclaw-*.log`
- Prints next action commands (`switch`, `topup`)

### `switch`
- Moves to next available seat in order: `seat1 -> seat2 -> seat3`
- Runs OAuth flow for OpenAI seats:
  - `openclaw onboard --auth-choice openai-codex`
- Restarts gateway:
  - `openclaw gateway restart`
- Persists active seat/cooldown state

### `topup`
- Prints plain-English Team workspace billing steps
- Includes post-topup verify steps

---

## Cooldown/countdown logic

- State file: `~/.openclaw/failover/state.env`
- Default cooldown fallback: `5534` minutes (override via `FAILOVER_DEFAULT_COOLDOWN_MINUTES`)
- Cooldown can come from:
  - auto-detected log text (if minutes present), or
  - manual mark/switch argument

---

## Operator runbook

When rate limit hits:

1. Run:
   ```bash
   ./tools/failover.sh status
   ```
2. If another seat is available, run:
   ```bash
   ./tools/failover.sh switch
   ```
3. If no seat available, run:
   ```bash
   ./tools/failover.sh topup
   ```
4. Verify:
   ```bash
   ./tools/failover.sh status
   openclaw models status
   ```

---

## Notes

- OAuth workspace selection in browser determines Team vs Personal seat for OpenAI.
- Seat 1 and Seat 2 are different workspace capacities; team plans share one team bucket.
- Keep this file and `tools/failover.sh` aligned when workflow changes.
