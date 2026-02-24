"""MCP Spec Change Detector — SENTINEL daily task.

Monitors the MCP specification repository and SDK releases for
changes that could affect UNWIND's transport layer, tool interception,
or capability negotiation.

Tracks: spec repo commits, SDK releases (TypeScript + Python),
new tool types, protocol version bumps, transport changes.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from sentinel.runner import (
    TaskContext, TaskResult, TaskStatus, Finding, Severity,
)

# Repositories to monitor
MCP_SPEC_REPO = "modelcontextprotocol/specification"
MCP_TS_SDK_REPO = "modelcontextprotocol/typescript-sdk"
MCP_PY_SDK_REPO = "modelcontextprotocol/python-sdk"

GITHUB_API = "https://api.github.com"

# Keywords that signal a breaking or security-relevant change
BREAKING_KEYWORDS = [
    "breaking", "deprecated", "removed", "incompatible",
    "protocol version", "transport", "stdio", "sse",
    "authentication", "authorization", "capability",
    "tool", "resource", "prompt", "sampling",
    "json-rpc", "jsonrpc", "schema",
]

SECURITY_KEYWORDS = [
    "security", "vulnerability", "cve", "exploit",
    "injection", "bypass", "ssrf", "traversal",
    "authentication", "authorization", "token",
]


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _fetch_json(url: str, timeout: int = 30) -> Optional[dict | list]:
    try:
        req = Request(url, headers={
            "User-Agent": "SENTINEL/0.1 (UNWIND security monitor)",
            "Accept": "application/vnd.github+json",
        })
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, json.JSONDecodeError, TimeoutError):
        return None


def _check_repo_commits(ctx: TaskContext, repo: str, label: str) -> list[Finding]:
    """Check recent commits on a GitHub repo for relevant changes."""
    findings = []

    if ctx.dry_run:
        if repo == MCP_SPEC_REPO:
            return [
                Finding(
                    title="MCP spec: Add streamable HTTP transport",
                    severity=Severity.HIGH,
                    category="mcp-spec",
                    detail="Mock commit for testing. New transport type added to MCP spec.",
                    source_url=f"https://github.com/{repo}/commit/abc123",
                    action_required=True,
                    action_description="Assess whether UNWIND transport layer needs updates",
                    tags=["mcp", "transport", "breaking"],
                ),
            ]
        return []

    # Get recent commits (last 24h worth, max 30)
    url = f"{GITHUB_API}/repos/{repo}/commits?per_page=30"
    commits = _fetch_json(url)
    if not commits or not isinstance(commits, list):
        return []

    # Load last-seen commit SHA
    state_key = f"commits_{repo.replace('/', '_')}.json"
    state = ctx.load_state(state_key, {"last_sha": ""})
    last_sha = state.get("last_sha", "")

    new_commits = []
    for commit in commits:
        sha = commit.get("sha", "")
        if sha == last_sha:
            break
        new_commits.append(commit)

    for commit in new_commits:
        message = commit.get("commit", {}).get("message", "")
        sha = commit.get("sha", "")[:8]
        url = commit.get("html_url", "")

        # Check for breaking or security keywords
        msg_lower = message.lower()
        breaking = [kw for kw in BREAKING_KEYWORDS if kw in msg_lower]
        security = [kw for kw in SECURITY_KEYWORDS if kw in msg_lower]

        if breaking or security:
            severity = Severity.HIGH if security else Severity.MEDIUM
            first_line = message.split("\n")[0][:120]

            findings.append(Finding(
                title=f"{label}: {first_line}",
                severity=severity,
                category="mcp-spec",
                detail=message[:500],
                source_url=url,
                action_required=True,
                action_description=(
                    f"Review for UNWIND impact "
                    f"(matched: {', '.join(breaking + security)})"
                ),
                tags=["mcp"] + breaking + security,
            ))

    # Save latest SHA
    if commits:
        ctx.save_state(state_key, {
            "last_sha": commits[0].get("sha", ""),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        })

    return findings


def _check_releases(ctx: TaskContext, repo: str, label: str) -> list[Finding]:
    """Check for new releases of an MCP-related repository."""
    findings = []

    if ctx.dry_run:
        if repo == MCP_TS_SDK_REPO:
            return [
                Finding(
                    title="MCP TypeScript SDK v2.1.0 released",
                    severity=Severity.MEDIUM,
                    category="mcp-sdk",
                    detail="Mock release for testing. Adds streaming transport support.",
                    source_url=f"https://github.com/{repo}/releases/tag/v2.1.0",
                    action_required=True,
                    action_description="Test UNWIND compatibility with new SDK version",
                    tags=["mcp", "sdk", "typescript"],
                ),
            ]
        return []

    url = f"{GITHUB_API}/repos/{repo}/releases?per_page=5"
    releases = _fetch_json(url)
    if not releases or not isinstance(releases, list):
        return []

    # Load last-seen release tag
    state_key = f"releases_{repo.replace('/', '_')}.json"
    state = ctx.load_state(state_key, {"last_tag": ""})
    last_tag = state.get("last_tag", "")

    for release in releases:
        tag = release.get("tag_name", "")
        if tag == last_tag:
            break

        body = release.get("body", "")
        name = release.get("name", tag)

        # Check for breaking/security content
        text = f"{name} {body}".lower()
        breaking = [kw for kw in BREAKING_KEYWORDS if kw in text]
        security = [kw for kw in SECURITY_KEYWORDS if kw in text]

        severity = Severity.HIGH if security else (
            Severity.MEDIUM if breaking else Severity.LOW
        )

        findings.append(Finding(
            title=f"{label} {tag} released",
            severity=severity,
            category="mcp-sdk",
            detail=body[:500] if body else f"New release: {name}",
            source_url=release.get("html_url", ""),
            action_required=bool(breaking or security),
            action_description=(
                f"Test UNWIND compatibility"
                + (f" (flags: {', '.join(breaking + security)})" if breaking or security else "")
            ),
            tags=["mcp", "sdk"] + breaking + security,
        ))

    # Save latest tag
    if releases:
        ctx.save_state(state_key, {
            "last_tag": releases[0].get("tag_name", ""),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        })

    return findings


def mcp_spec_tracker(ctx: TaskContext) -> TaskResult:
    """Main MCP spec tracking task."""
    all_findings = []

    # Check spec repo commits
    all_findings.extend(_check_repo_commits(ctx, MCP_SPEC_REPO, "MCP spec"))

    # Check SDK releases
    all_findings.extend(_check_releases(ctx, MCP_TS_SDK_REPO, "MCP TS SDK"))
    all_findings.extend(_check_releases(ctx, MCP_PY_SDK_REPO, "MCP Python SDK"))

    # Also check spec repo releases (protocol version bumps)
    all_findings.extend(_check_releases(ctx, MCP_SPEC_REPO, "MCP spec"))

    if not all_findings:
        return TaskResult(
            task_name="mcp_spec_tracker",
            status=TaskStatus.SUCCESS,
            summary="No new MCP spec changes or SDK releases detected",
        )

    action_count = sum(1 for f in all_findings if f.action_required)
    return TaskResult(
        task_name="mcp_spec_tracker",
        status=TaskStatus.WARNING,
        findings=all_findings,
        summary=f"{len(all_findings)} change(s) detected, {action_count} requiring review",
    )
