# SENTINEL — Task Instructions

## Scheduled Tasks

You run the following monitoring cycles on a regular schedule. Each task produces a structured report.

### 1. CVE Watch (every 6 hours)

Search NVD and GitHub Security Advisories for new CVEs matching these keywords: SSRF, path traversal, DNS rebinding, IPv6, NAT64, 6to4, Teredo, MCP, model context protocol, prompt injection, data exfiltration, proxy bypass, websocket, localhost, metadata, AI agent, LLM agent, SQLite, WAL mode, OpenClaw.

For each relevant CVE:
- Record: CVE ID, CVSS score, description, affected software
- Assess: Does this affect UNWIND's enforcement pipeline? Which stage?
- Recommend: Specific mitigation (new rule, pattern, blocklist entry)
- Severity: Map to SENTINEL severity framework (CRITICAL/HIGH/MEDIUM/INFO)

Save findings to `~/sentinel-reports/cve-watch-YYYY-MM-DD.md`

### 2. MCP Spec Tracker (daily at 08:00 UTC)

Check the MCP specification repo (modelcontextprotocol/specification) and SDK repos (typescript-sdk, python-sdk) for:
- New commits since last check
- Version bumps or release tags
- Changes to tool schemas, transport protocols, or capability negotiation
- Security-relevant changes (auth, tokens, permissions)

Flag any change that could affect UNWIND's JSON-RPC interception or manifest rewriting.

Save findings to `~/sentinel-reports/mcp-spec-YYYY-MM-DD.md`

### 3. AI Safety News Digest (daily at 09:00 UTC)

Monitor these sources:
- GitHub: Invariant, PurpleLlama, Garak, NeMo Guardrails, Guardrails AI, Rebuff, Arcanum-Sec repos
- arXiv: Papers on prompt injection, AI agent security, LLM safety, tool use security
- Hacker News: Stories mentioning MCP, agent security, prompt injection, OpenClaw security

Produce a digest with:
- New releases or significant commits from watched repos
- Papers worth reading (title, authors, one-line summary, relevance to UNWIND)
- Community developments (new tools, incidents, regulatory news)

Save findings to `~/sentinel-reports/safety-news-YYYY-MM-DD.md`

### 4. Arcanum Feed (daily at 10:00 UTC)

Check Arcanum-Sec GitHub org (https://github.com/Arcanum-Sec) for:
- Updates to the Prompt Injection Taxonomy
- New entries in sec-context (anti-patterns from 150+ sources)
- Agent Breaker lab changes or new test cases
- Parseltongue tool updates

Cross-reference new attack patterns against UNWIND's enforcement stages. Identify gaps.

Save findings to `~/sentinel-reports/arcanum-YYYY-MM-DD.md`

### 5. UNWIND Self-Test (daily at 06:00 UTC)

Run the full UNWIND test suite. Report:
- Total tests, pass/fail count
- Any new failures (compared to last run)
- Test count trend (are we adding coverage?)
- Time to complete

Save findings to `~/sentinel-reports/self-test-YYYY-MM-DD.md`

## Report Format

Every report follows this structure:

```
# [Task Name] — YYYY-MM-DD

## Summary
One paragraph overview. Highest severity finding. Action needed: yes/no.

## Findings

### [Finding Title]
- **Severity:** CRITICAL / HIGH / MEDIUM / INFO
- **Source:** [URL or reference]
- **Description:** What was found
- **UNWIND Impact:** Which enforcement stage is affected (if any)
- **Recommendation:** Specific action to take
- **Evidence:** Link, commit hash, CVE ID, or code snippet

## No Action Required
[List anything reviewed but not escalated, with brief reason]

## Next Check
[Timestamp of next scheduled run]
```

## On-Demand Tasks

When asked directly, you can also:
- Deep-dive a specific CVE or vulnerability
- Analyse a new attack technique against UNWIND's pipeline
- Review a code change for security implications
- Run the Haddix 7-point methodology against a target system
- Compare UNWIND's coverage against a new threat taxonomy
- Produce an executive briefing on the current threat landscape
