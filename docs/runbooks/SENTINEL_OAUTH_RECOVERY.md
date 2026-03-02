# SENTINEL OAuth — Rate Limit Recovery

SENTINEL authenticates to OpenAI via OAuth. David has two accounts:
- `<operator-email-1>` — Personal Plus + Team plan
- `<operator-email-2>` — Team/Business plan

**Key lesson:** Seats don't double rate limits. Limits are per-org-workspace, not per-seat. To switch which capacity SENTINEL uses, you re-auth to a different workspace.

## How to Switch SENTINEL's OAuth Workspace

1. Back up current auth:
```bash
cp ~/.openclaw/agents/main/agent/auth-profiles.json ~/.openclaw/agents/main/agent/auth-profiles.json.bak
```

2. Re-run OAuth (on the Pi):
```bash
openclaw onboard --auth-choice openai-codex
```
  - Select **Yes** to security warning
  - Select **QuickStart**
  - Select **Use existing values**
  - It shows an OAuth URL — open it in a browser on the Mac
  - Log in and **choose the workspace** you want (Personal vs Team)
  - The browser redirects to a `localhost` URL that won't load — **copy the full URL from the address bar**
  - Paste that URL into the Pi terminal
  - Skip channels, skills, hooks
  - Select **Restart** for gateway
  - Select **Do this later** for hatching

3. If a broken profile was created during the process, clean it up:
```bash
python3 -c "
import json
with open('/home/<pi-user>/.openclaw/agents/main/agent/auth-profiles.json') as f:
    data = json.load(f)
# Remove any broken profiles (check for 'Symbol(clack:cancel)' or similar)
for key in list(data.get('profiles', {}).keys()):
    p = data['profiles'][key]
    if p.get('type') == 'token' and 'Symbol' in str(p.get('token', '')):
        del data['profiles'][key]
        if key in data.get('usageStats', {}):
            del data['usageStats'][key]
# Ensure lastGood points to the valid profile
data['lastGood'] = {'openai-codex': 'openai-codex:default'}
with open('/home/<pi-user>/.openclaw/agents/main/agent/auth-profiles.json', 'w') as f:
    json.dump(data, f, indent=2)
print('Cleaned')
"
```

4. Restart gateway and test:
```bash
openclaw gateway start
sleep 5
openclaw tui
```

## Cleaner Method (for next time)

```bash
openclaw models auth login --provider openai-codex
```
Complete OAuth, then verify with `openclaw models status`.
