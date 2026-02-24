# UNWIND Maintenance Agent Runbook

**Agent codename:** SENTINEL
**Managed by:** UNWIND (dogfooding — the agent runs through its own proxy)
**Owner:** David
**Created:** 2026-02-20

This document defines the standing tasks for the UNWIND project maintenance agent. The agent should be configured to run through UNWIND itself — every action it takes is logged, auditable, and reversible. If the maintenance agent goes rogue, UNWIND catches it. That's the pitch in action.

---

## Daily Tasks

### 1. CVE & Vulnerability Watch
- Monitor NVD, GitHub Security Advisories, and MITRE for new CVEs related to: MCP, SSRF, path traversal, DNS rebinding, IPv6 transition attacks, DLP bypass, prompt injection
- Check OpenClaw GitHub releases and changelogs for security patches
- Check SecureClaw and any emerging MCP security tools for relevant disclosures
- Flag anything that affects UNWIND's threat model or blocked ranges
- **Output:** If new CVE found → create GitHub issue tagged `security/cve-watch` with assessment of whether UNWIND is already covered or needs a patch

### 2. MCP Protocol Spec Tracking
- Monitor the MCP specification repository for changes (new methods, protocol version bumps, transport changes, capability negotiations)
- Track MCP SDK releases (TypeScript, Python) for breaking changes
- Monitor for new tool types, resource types, or authentication mechanisms that UNWIND needs to understand
- **Output:** If spec change found → create GitHub issue tagged `protocol/mcp-spec` with impact assessment

### 3. Dependency Security Audit
- Run `pip audit` (or equivalent) against UNWIND's dependency tree
- Check Flask, SQLite driver, and any transitive dependencies for known vulnerabilities
- Monitor Python security advisories for stdlib issues (especially `ipaddress`, `urllib.parse`, `hashlib`)
- **Output:** If vulnerability found → create GitHub issue tagged `security/dependency` with severity and remediation options

### 4. GitHub Issue Triage
- Review new issues for duplicates, missing information, severity classification
- Label issues: `bug`, `feature`, `security`, `documentation`, `question`
- Flag issues that need David's attention vs ones the agent can handle autonomously
- Respond to questions with links to relevant docs or code sections
- **Output:** All new issues labelled and triaged within 24 hours

### 5. CI/CD Health Check
- Verify all tests pass on main branch
- Check for flaky tests (intermittent failures across recent runs)
- Monitor test execution time for regression
- **Output:** If CI broken → create issue tagged `ci/broken` with failure details

---

## Weekly Tasks

### 6. Ecosystem Review (Monday)
- Survey the week's developments in: AI agent security, MCP ecosystem, prompt injection research, AI safety tooling
- Check Hacker News, arXiv, security blogs (Trail of Bits, Wiz, CrowdStrike, Cisco Talos) for relevant publications
- Track new MCP server implementations that UNWIND should be tested against
- Track competitor moves: OpenClaw feature additions, new entrants to the space
- **Output:** Weekly digest committed to `docs/weekly/YYYY-WW.md` with sections: CVEs, MCP Changes, Research, Competitors, Action Items

### 7. Test Coverage Analysis (Tuesday)
- Run coverage report and compare to previous week
- Identify untested code paths, especially in enforcement pipeline and transport layer
- Flag any new code merged without corresponding tests
- **Output:** Coverage delta committed to `docs/coverage/YYYY-WW.md`; new issues created for coverage gaps

### 8. SSRF Blocklist Freshness (Wednesday)
- Cross-reference UNWIND's CIDR blocklist against IANA reserved ranges, RFC updates, and newly documented bypass techniques
- Check for new IPv6 transition mechanisms or deprecated-but-still-parsed address formats
- Verify cloud provider metadata endpoints haven't changed (AWS, GCP, Azure, DigitalOcean)
- **Output:** If blocklist stale → PR with updated ranges and tests

### 9. Documentation Freshness (Thursday)
- Compare README, spec, and inline docstrings against current codebase
- Flag any CLI commands, config options, or API endpoints that are undocumented or have drifted from implementation
- Check that example commands in README actually work
- **Output:** Issues tagged `documentation/drift` for any mismatches

### 10. Release Readiness Check (Friday)
- Review all merged PRs since last release
- Draft changelog entries for pending release
- Verify version numbers are consistent across `__init__.py`, `pyproject.toml`, and docs
- Check that no debug code, TODO comments, or hardcoded test values remain in main
- **Output:** Release readiness report in `docs/releases/next.md`

---

## Monthly Tasks

### 11. Threat Model Update (1st of month)
- Full review of UNWIND's threat matrix against current attack landscape
- Add new attack vectors discovered in the past month
- Re-assess severity ratings based on real-world exploit activity
- Cross-reference against OWASP Top 10, CWE Top 25, and MITRE ATT&CK for LLMs
- Document any attack categories UNWIND doesn't yet cover, with rationale for whether to add coverage
- **Output:** Updated threat matrix section in spec; PR tagged `security/threat-model`

### 12. Performance Benchmark (1st of month)
- Run enforcement pipeline latency benchmarks across all check types
- Compare against previous month's baseline
- Test under load: 100 rapid tool calls, mixed read/write patterns
- Measure SQLite WAL performance under concurrent access
- Snapshot creation time distribution (p50, p95, p99)
- **Output:** Benchmark report in `docs/benchmarks/YYYY-MM.md`

### 13. DLP Pattern Library Update (15th of month)
- Review new API key formats from major providers (AWS, GCP, Azure, Stripe, OpenAI, Anthropic, etc.)
- Check for new secret formats in tools like TruffleHog, GitLeaks, detect-secrets
- Add new regex patterns for any formats UNWIND doesn't yet catch
- Re-evaluate Shannon entropy threshold against false positive/negative rates
- **Output:** PR with updated patterns and tests; tagged `security/dlp-update`

### 14. Canary Honeypot Rotation (15th of month)
- Review canary tool definitions for realism
- Check if any canary names have been published or documented publicly (which would reduce their effectiveness)
- Generate new canary variations that match current MCP ecosystem naming patterns
- Test that canaries are indistinguishable from real tools in the manifest
- **Output:** PR with refreshed canary definitions

### 15. Compatibility Matrix Update (last week of month)
- Test UNWIND against latest versions of: Claude Desktop, OpenAI Agents SDK, Cursor, Windsurf, Cline, and any new MCP clients
- Test against popular MCP servers: filesystem, GitHub, Slack, databases, web browsing
- Document any compatibility issues or workarounds
- **Output:** Compatibility matrix in `docs/compatibility/YYYY-MM.md`

---

## Quarterly Tasks

### 16. Security Audit Preparation (Q start)
- Generate comprehensive CR-AFT chain export for the quarter
- Create anchor checkpoints at quarter boundaries
- Compile all security-related PRs, CVE responses, and threat model changes
- Produce a "security posture" summary suitable for enterprise customers
- **Output:** Quarterly security report in `docs/security/YYYY-QN.md`

### 17. Open Source Health Check (Q start)
- Review GitHub community metrics: stars, forks, issues, PRs, contributors
- Assess documentation quality from a newcomer's perspective
- Check that CONTRIBUTING.md, CODE_OF_CONDUCT.md, and issue templates are current
- Review license compliance across all dependencies
- **Output:** Community health report; issues for any gaps

### 18. Roadmap Alignment (Q start)
- Review which planned features were delivered vs deferred
- Assess whether the open-core boundary (free vs enterprise) still makes sense
- Survey user feedback (issues, discussions, emails) for recurring requests
- Propose next quarter's priority list for David's review
- **Output:** Roadmap proposal in `docs/roadmap/YYYY-QN.md`

---

## Event-Driven Tasks (Triggered, Not Scheduled)

### 19. CVE Response
- **Trigger:** New CVE affecting UNWIND's threat surface
- Assess impact within 4 hours
- If UNWIND already covers it: document in security coverage notes, add test if missing
- If UNWIND doesn't cover it: draft patch, add tests, create PR tagged `security/cve-response`
- Update spec with CVE reference

### 20. MCP Breaking Change Response
- **Trigger:** MCP spec version bump or breaking change
- Assess transport layer impact
- Update JSON-RPC handling, tool schema parsing, or capability negotiation as needed
- Add compatibility shim if supporting multiple protocol versions

### 21. Upstream Incident Response
- **Trigger:** Report of UNWIND failing to catch an attack in production
- Full forensic analysis using CR-AFT chain export
- Identify gap in enforcement pipeline
- Patch, test, release, and post-mortem document

### 22. Release Execution
- **Trigger:** David approves release
- Run full test suite across all supported Python versions
- Build and publish to PyPI
- Create GitHub release with changelog
- Update documentation site
- Announce on relevant channels

---

## Standing Research Tasks

### 23. Prompt Injection Catalogue
- Maintain a running catalogue of known prompt injection techniques
- Classify by: vector (email, web, calendar, document), mechanism (direct, indirect, encoded), and which UNWIND checks would catch them
- **Output:** Living document at `docs/research/injection-catalogue.md`

### 24. Agent Failure Mode Database
- Collect documented cases of AI agents causing harm (data loss, secret exposure, unintended actions)
- For each case, document: what happened, what UNWIND would have done, which checks apply
- This feeds the marketing narrative: "Here's what went wrong. Here's how UNWIND prevents it."
- **Output:** Living document at `docs/research/failure-modes.md`

### 25. Regulatory Watch
- Track AI regulation developments (EU AI Act, US executive orders, UK AI Safety Institute guidance)
- Assess whether any regulations create compliance requirements that UNWIND helps satisfy
- This feeds the enterprise sales narrative: "UNWIND helps you comply with X"
- **Output:** Quarterly regulatory brief in `docs/regulatory/YYYY-QN.md`

---

## Versioned Security Coverage Notes

Each UNWIND release includes a `SECURITY_COVERAGE.md` file that maps:

- **Attack category → UNWIND check that covers it → Test that validates it → CVE reference if applicable**

The maintenance agent keeps this file current. Format:

```
| Attack Category | Check | Test | CVEs | Since |
|----------------|-------|------|------|-------|
| Cloud metadata SSRF | SSRF Shield | test_block_metadata_ip | CVE-2026-26322 | v0.1.0 |
| IPv6 transition bypass | SSRF Shield | test_block_nat64, test_block_6to4, test_block_teredo | CVE-2026-26322 | v0.1.0 |
| Octal/hex IPv4 bypass | SSRF Shield | test_block_octal_ipv4, test_block_hex_ipv4 | CVE-2026-26322 | v0.1.0 |
| Path traversal | Path Jail | test_block_traversal_outside_workspace | - | v0.1.0 |
| Self-protection bypass | Self-Protection | test_block_traversal_to_unwind | - | v0.1.0 |
| API key exfiltration | DLP-Lite | test_catch_aws_key, test_catch_stripe_key | - | v0.1.0 |
| Encoded exfiltration | DLP-Lite (entropy) | test_catch_high_entropy_base64 | - | v0.1.0 |
| Jailbreak probe | Canary Honeypot | test_trigger_on_honeypot_call | - | v0.1.0 |
| Rapid-fire abuse | Circuit Breaker | test_circuit_breaker | - | v0.1.0 |
| Plaintext WebSocket | SSRF Shield | test_block_plaintext_websocket | - | v0.1.0 |
```

The agent updates this table with every security-related PR and ensures no release ships without it being current.

---

## Changelog Philosophy

UNWIND follows a "why, not what" changelog philosophy:

- Every entry explains the security rationale, not just the code change
- CVE references are mandatory for security patches
- Entries are written for the audience (security teams, compliance officers) not for developers
- Format: `[version] - date` with sections: Security, Added, Changed, Fixed, Removed

Example:
```
## [0.1.1] - 2026-02-21

### Security
- Block IPv6 transition address SSRF bypasses (NAT64, 6to4, Teredo)
  responding to CVE-2026-26322 disclosure in OpenClaw v2026.2.19.
  UNWIND was already blocking IPv4-mapped IPv6, but transition
  mechanisms encapsulate arbitrary IPv4 inside routable IPv6 addresses,
  bypassing naive range checks. Added strict dotted-decimal IPv4
  validation to reject octal, hex, and short-form bypass attempts.

### Added
- WebSocket scheme enforcement (ws:// blocked to non-loopback)
- 8 new SSRF test cases covering transition address vectors
```

The maintenance agent drafts these entries; David approves before release.

---

## Agent Constraints

The maintenance agent operates under UNWIND's own enforcement:

1. **No direct commits to main** — all changes via PR, reviewed by David
2. **No secret access** — the agent never handles API keys, tokens, or credentials
3. **No external communication** — the agent doesn't send emails, post to social media, or contact anyone
4. **Read-mostly** — most tasks produce reports and issues, not code changes
5. **All actions logged** — everything the agent does is in the CR-AFT chain
6. **Ghost Mode for research** — web browsing and research tasks run in Ghost Mode

This is UNWIND's proof of concept: a security-sensitive agent, managed by the security tool it maintains, constrained by the same rules it enforces on others.
