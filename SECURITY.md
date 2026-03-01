# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in UNWIND, please report it responsibly.

**Email:** security@brugai.com
**Alternative:** Open a [private security advisory](https://github.com/brugai/unwind/security/advisories/new) on GitHub.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected component (enforcement pipeline, CRAFT, sidecar, adapter, Ghost Mode)
- Impact assessment if known

## Response Timeline

- **Acknowledge:** within 48 hours
- **Triage:** within 7 days
- **Fix:** within 90 days (critical vulnerabilities prioritised)

## Scope

**In scope:**
- Enforcement pipeline bypasses
- CRAFT chain integrity issues
- Sidecar authentication or authorization flaws
- Ghost Mode escape or data leakage
- Adapter input validation issues
- Path jail or self-protection bypasses

**Out of scope:**
- Social engineering or phishing
- Denial of service against a self-hosted Pi
- Issues in upstream dependencies (report to those projects directly)
- Attacks requiring physical access to the host

## OpenClaw Hardening Recommendations

If you run UNWIND with OpenClaw, review these settings for defence-in-depth:

- **`session.dmScope`**: Set to `per-channel-peer` (not the default `main`). The default shares a single session across all DM senders, which undermines UNWIND's per-session taint tracking. With `per-channel-peer`, each sender gets an isolated session.
- **`gateway.auth.mode`**: Ensure a token or password is set. If the gateway binds to a non-loopback address without authentication, tool calls can bypass the UNWIND adapter entirely.
- **`tools.fs.workspaceOnly`**: Set to `true` to complement UNWIND's path jail at the OpenClaw level.
- **`tools.elevated.enabled`**: Leave as `false` unless you have a specific need. UNWIND blocks elevated exec on tainted sessions, but defence-in-depth is better.

## Recognition

Valid reporters will be credited in this file's Hall of Fame section (unless they prefer anonymity).

## Hall of Fame

*No reports yet — be the first!*
