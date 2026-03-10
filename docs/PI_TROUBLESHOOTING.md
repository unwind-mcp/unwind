# Pi Connection Stack — Troubleshooting Guide

**Machine:** Raspberry Pi 5 | **User:** dandare@raspberrypi | **Hostname:** raspberrypi
**Local IP:** 192.168.0.171 | **SSH:** `ssh dandare@raspberrypi`

## Ports & Addresses

| Service | Port | Address | Bind |
|---------|------|---------|------|
| OpenClaw Gateway | 18789 | ws://127.0.0.1:18789 | loopback |
| UNWIND Sidecar | 9100 | http://127.0.0.1:9100 | localhost |
| UNWIND Dashboard | 9001 | http://192.168.0.171:9001 | 0.0.0.0 |
| OpenClaw Web UI | 18789 | http://127.0.0.1:18789 | loopback |

## Key Files

| File | Purpose |
|------|---------|
| `~/.openclaw/openclaw.json` | OpenClaw config (gateway, model, plugins) |
| `~/.openclaw/workspace/UNWIND/` | Project directory |
| `.venv/bin/python` | Python venv |
| `.venv/bin/unwind` | UNWIND CLI |

## Required Environment Variables

```bash
export UNWIND_SIDECAR_SHARED_SECRET=kPjW9d-VD9ySBXe3qJjaKPpX3KcStGbkif1ldupzONZby3s0
export UNWIND_WATCHDOG_THRESHOLD=86400
export UNWIND_LOCATION_HINT="London, GB"   # needed for CRAFT v2 attestation
```

Set these BEFORE starting any services. Every new SSH session needs them.

---

## Problem → Fix

### 1. OAuth Token Expired

**Symptom:** `OAuth token refresh failed for openai-codex`

**Fix:**
```
openclaw configure --section model
```
- Pick OpenAI → completes OAuth flow in browser
- Only touches model/auth config, nothing else
- Backup is automatic (`.bak` file created)

**Prevention:** Tokens expire after inactivity or provider rotation. No way to prevent — just re-auth when it happens.

### 2. Gateway Won't Start — Already Running

**Symptom:** `gateway already running (pid XXXXX); lock timeout`

**Fix:**
```
openclaw gateway stop
openclaw gateway &
```

### 3. Gateway Won't Start — Missing Env Var

**Symptom:** `Missing env var "UNWIND_SIDECAR_SHARED_SECRET"`

**Fix:** Set the env var (see Required Environment Variables above), then:
```
openclaw gateway &
```

### 4. Gateway Won't Start — Port In Use

**Symptom:** `Port 18789 is already in use`

**Fix:**
```
kill $(lsof -ti:18789)
openclaw gateway &
```

### 5. Sidecar Not Running

**Symptom:** Tool calls fail with connection refused on port 9100

**Check:**
```
pgrep -f "unwind.sidecar"
```

**Fix:**
```
cd ~/.openclaw/workspace/UNWIND
.venv/bin/unwind sidecar serve --log-level warning &
```

### 6. Dashboard Not Running

**Symptom:** http://192.168.0.171:9001 doesn't load

**Check:**
```
pgrep -f "unwind.dashboard"
```

**Fix:**
```
cd ~/.openclaw/workspace/UNWIND
.venv/bin/python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()" &
```

### 7. Sidecar Port In Use

**Symptom:** Sidecar fails to bind port 9100

**Fix:**
```
kill $(lsof -ti:9100)
.venv/bin/unwind sidecar serve --log-level warning &
```

### 8. Dashboard Port In Use

**Symptom:** Dashboard fails to bind port 9001

**Fix:**
```
kill $(lsof -ti:9001)
.venv/bin/python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()" &
```

### 9. TUI Stuck / Won't Exit

**Symptom:** Ctrl+C doesn't work in `openclaw tui`

**Try in order:**
1. `Ctrl+C`
2. `q` or `Esc`
3. `Ctrl+\` (SIGQUIT)
4. Close the terminal window entirely and open a fresh SSH session

The TUI is just a client — closing it does NOT kill the gateway, sidecar, or dashboard.

### 10. Sentinel Responds But Tools Fail

**Symptom:** Sentinel talks but can't execute tools (fs_read, etc.)

**Check sidecar is running:**
```
pgrep -f "unwind.sidecar"
```

**Check UNWIND adapter is loaded:**
```
grep unwind-openclaw ~/.openclaw/openclaw.json
```

If adapter missing, copy it:
```
cp -r ~/.openclaw/workspace/UNWIND/openclaw-adapter ~/.openclaw/extensions/unwind-openclaw-adapter
```
Then restart gateway.

### 11. Out of OpenAI Credits

**Symptom:** API errors about billing/quota after successful auth

**Fix:** Top up at https://platform.openai.com/account/billing
No CLI fix — this is an account-level issue.

### 12. SSH Connection Refused

**Symptom:** `ssh: connect to host raspberrypi port 22: Connection refused`

**Check:**
- Is Pi powered on?
- Is Pi on the same network? Try `ping 192.168.0.171`
- SSH service may need restart (requires physical access to Pi)

### 13. All Services Down — Fresh Start

Full startup sequence (one command at a time):

```
ssh dandare@raspberrypi
export UNWIND_SIDECAR_SHARED_SECRET=kPjW9d-VD9ySBXe3qJjaKPpX3KcStGbkif1ldupzONZby3s0
export UNWIND_WATCHDOG_THRESHOLD=86400
cd ~/.openclaw/workspace/UNWIND
.venv/bin/unwind sidecar serve --log-level warning &
.venv/bin/python -c "from unwind.dashboard.app import run_dashboard; run_dashboard()" &
openclaw gateway &
openclaw tui
```

### 14. Check What's Running

```
pgrep -f openclaw.*gateway
pgrep -f "unwind.sidecar"
pgrep -f "unwind.dashboard"
```

### 15. Kill Everything

```
pkill -f "unwind.dashboard"
pkill -f "unwind.sidecar"
openclaw gateway stop
```

If gateway stop doesn't work:
```
kill $(lsof -ti:18789)
```
