# UNWIND Pre-Launch Checklist

Status: DRAFT — updated 2026-02-24

## Legal & Liability

- [ ] Reframe Green Light language: "no violations detected" NOT "safe" — every UI string, README, docs, landing page
- [ ] Write LIABILITY.md / DISCLAIMER.md — prominent, not buried in licence
- [ ] Three core statements in disclaimer: (1) reduces risk, does not eliminate it (2) not a substitute for professional security assessment (3) user responsible for own security posture including updates
- [ ] Add first-run acknowledgement — user must accept before UNWIND activates
- [ ] Write "Limitations" section in docs — honestly list what UNWIND does NOT protect against (determined individual attackers, zero-days, social engineering, physical access, supply chain attacks beyond our verification)
- [ ] Terms of service — even for free tier: provided as-is, no detection rate guarantees, user accepts all risk, liability limited to fees paid in prior 12 months (zero for free tier)
- [ ] AGPL licence in place with sections 15/16 (no warranty, limitation of liability)
- [ ] 30-minute solicitor consultation on UK software liability (budget ~£150-200)
- [ ] Professional indemnity insurance before paid tier launches (budget ~£300-500/year)
- [ ] Never use words "safe," "secure," "guaranteed," "bulletproof," "unhackable" in any user-facing material

## Traffic Light Language (exact wording)

- Green: "No policy violations detected"
- Amber: "Action requires human review"
- Red: "Policy violation — action blocked"
- Ghost Mode: "Simulated — no changes made"
- Rewind: "Reverting to previous state"

## Security Self-Defence

- [ ] ReDoS tests pass for ALL regex patterns (credential, DLP, exec tunnel, self-protection)
- [ ] Malformed input tests pass for ALL external-facing parsers (sidecar, policy_source, lockfile)
- [ ] URL parser confusion tests pass for egress policy and SSRF shield
- [ ] Size bomb tests pass for ALL scanners (credential, DLP, taint, circuit breaker)
- [ ] Parameter depth/width bomb tests pass with MAX_SCAN_ITEMS cap
- [ ] Concurrency tests for session store and RSS state (TODO — not yet written)
- [ ] Stateful sequence tests for taint decay gaming and circuit breaker pacing (TODO — not yet written)

## Code Quality

- [ ] All tests green (current: 1166)
- [ ] Cross-review: SENTINEL reviews all Claude code, Claude reviews all SENTINEL code
- [ ] No hardcoded credentials in repo (grep for sk-, AKIA, ghp_, passwords)
- [ ] SECURITY.md with responsible disclosure process
- [ ] CHANGELOG.md started

## Documentation

- [ ] README in prosumer language — Green Light / Rewind / Ghost Mode, not jargon
- [ ] Installation guide that works end-to-end on fresh machine
- [ ] "What UNWIND protects against" page (honest, scoped)
- [ ] "What UNWIND does NOT protect against" page (equally honest)

## Community & Launch

- [ ] GitHub repo public under AGPL
- [ ] GitHub Sponsors enabled
- [ ] Landing page (Carrd or similar) — plain English, no "safe" or "secure" claims
- [ ] r/selfhosted post drafted
- [ ] r/OpenClaw post drafted
- [ ] OpenClaw community/Discord post drafted
- [ ] Bug bounty / hall of fame structure in SECURITY.md
- [ ] University outreach for masters project security review (Edinburgh, Imperial, UCL)
