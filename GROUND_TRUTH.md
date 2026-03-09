# Ground Truth — Source of Truth Manifest

**Purpose:** Prevent stale-file confusion between agents working on the same codebase across multiple machines.

**Last updated:** 2026-03-09 by Claude Code (CLI)

## Authoritative Copy

The **Pi** at `~/.openclaw/workspace/UNWIND/` is the single source of truth for all runtime files. The GitHub repo at `github.com/unwind-mcp/unwind` is the durable backup.

The **Mac** at `/Users/davidrussell/Downloads/UNWIND/` is a working copy. It may be stale. Always verify against Pi or GitHub before asserting file state.

## Diverged Files (Pi ahead of Mac)

These files have been patched directly on Pi. Never overwrite Pi from Mac. Pull FROM Pi if Mac copy needed.

| File | Reason | Last patched |
|------|--------|-------------|
| `unwind/dashboard/templates/index.html` | Multiple dashboard patches applied on Pi | 2026-03-08 |
| `unwind/dashboard/app.py` | Amber endpoints, away mode, proxy routes | 2026-03-08 |
| `unwind/dashboard/away_mode.py` | Away mode patches | 2026-03-07 |
| `unwind/enforcement/pipeline.py` | Fix 1: secondary path jail params | 2026-03-09 |
| `unwind/enforcement/ghost_egress.py` | Fix 3: scheme whitelist | 2026-03-09 |
| `unwind/sidecar/server.py` | Fix 4: Ghost Mode BLOCK + amber wiring | 2026-03-09 |

## Safe on Both (Mac = Pi)

| File | Notes |
|------|-------|
| `ghostmode/*.py` | Fix 5 applied on both Mac and Pi |
| `unwind/enforcement/path_jail.py` | No patches, identical |
| `unwind/enforcement/ssrf_shield.py` | No patches, identical |
| `unwind/recorder/event_store.py` | No patches, identical |

## Rules

1. **Never SCP from Mac to Pi** for any file in the "Diverged" table above
2. **Always pull FROM Pi** if the Mac copy needs updating: `scp dandare@raspberrypi:~/.openclaw/workspace/UNWIND/path /local/path`
3. **Always `git push` after every commit on Pi** — GitHub must stay current
4. **Any agent reading files** should check this manifest first to know if their local copy is authoritative

## For Future KEEL Protocol

This file is a manual prototype of cross-agent ground truth synchronisation. A full KEEL implementation would:
- Auto-detect file divergence via content hashing
- Broadcast state changes between agent sessions
- Maintain per-file provenance chains
- Resolve conflicts with operator approval
