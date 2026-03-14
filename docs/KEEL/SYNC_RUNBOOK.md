# KEEL Sync Runbook

This is the safety protocol for synchronising UNWIND across the Mac, Raspberry Pi, and GitHub.

## 1. Safety Rails
- GitHub main is Canonical: Always pull from GitHub to verify the base state.
- Snapshot First: Never sync directly into ~/Downloads/UNWIND/ after a reboot.
- No Progress Rule: If sync drift doesn't resolve in 2 cycles, STOP and ask David.
- 20-Minute Timeout: If an AI agent cannot verify sync within 20 mins, it must report and wait.

## 2. Recovery Procedure (Post-Reboot)
1. Pull GitHub: Verify local Mac main is up to date with origin/main.
2. Snapshot Pi: Pull the Pi's current working state into a new timestamped folder.
3. Diff Check: Compare the Snapshot vs. the local Mac folder.
4. Report Drift: List all files that differ and the test count discrepancy.
5. Merge: Only after David's approval, apply changes to the live folder.

## 3. The Checkpoint (Every 30 Mins)
Agents must run: bash tools/keel-checkpoint.sh

## 4. Verification Commands
- Test Count: python3 -m pytest --collect-only tests/
- Git Status: git status
- KEEL Status: cat docs/KEEL/STATE_FINGERPRINT.md
