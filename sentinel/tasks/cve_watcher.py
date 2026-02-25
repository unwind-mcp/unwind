"""CVE & Vulnerability Watch — SENTINEL daily task.

Monitors NVD, GitHub Security Advisories, and OpenClaw releases for
CVEs relevant to UNWIND's threat surface: MCP, SSRF, path traversal,
DNS rebinding, IPv6 transition attacks, DLP bypass, prompt injection.

In dry_run mode, uses cached/mock data for testing.
In live mode, queries NVD API and GitHub API.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from sentinel.runner import (
    TaskContext, TaskResult, TaskStatus, Finding, Severity,
)

# Keywords that signal a CVE is relevant to UNWIND's threat model
RELEVANT_KEYWORDS = [
    "ssrf", "server-side request forgery",
    "path traversal", "directory traversal",
    "dns rebinding", "dns rebind",
    "ipv6", "nat64", "6to4", "teredo",
    "mcp", "model context protocol",
    "prompt injection", "indirect injection",
    "data exfiltration", "data leak",
    "proxy bypass", "proxy escape",
    "websocket", "ws://",
    "localhost", "127.0.0.1", "metadata",
    "openclaw", "clawdbot",
    "ai agent", "llm agent", "autonomous agent",
    "sqlite", "wal mode",
]

# NVD API (v2.0) — free, no key required for low-volume queries
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# GitHub Advisory Database API
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

# OpenClaw releases
OPENCLAW_RELEASES_API = "https://api.github.com/repos/openclaw/openclaw/releases"


def _is_relevant(text: str) -> list[str]:
    """Check if text contains keywords relevant to UNWIND. Returns matched keywords."""
    text_lower = text.lower()
    return [kw for kw in RELEVANT_KEYWORDS if kw in text_lower]


def _content_hash(content: str) -> str:
    """Hash content for change detection."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _fetch_json(url: str, timeout: int = 30) -> Optional[dict]:
    """Fetch JSON from a URL. Returns None on failure."""
    try:
        req = Request(url, headers={"User-Agent": "SENTINEL/0.1 (UNWIND security monitor)"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, json.JSONDecodeError, TimeoutError):
        return None


def _check_nvd(ctx: TaskContext, days_back: int = 1) -> list[Finding]:
    """Query NVD for recent CVEs matching our keywords."""
    findings = []

    if ctx.dry_run:
        # Return mock findings for testing
        return [
            Finding(
                title="CVE-2026-99999: SSRF via IPv6 transition in proxy middleware",
                severity=Severity.HIGH,
                category="cve",
                detail="Mock CVE for testing. SSRF bypass using NAT64 prefix.",
                source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
                action_required=True,
                action_description="Verify UNWIND SSRF shield covers this vector",
                tags=["ssrf", "ipv6", "nat64"],
            ),
        ]

    # Query NVD for recent CVEs
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    params = (
        f"?pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}"
        f"&pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.999')}"
        "&resultsPerPage=200"
    )

    data = _fetch_json(f"{NVD_API_BASE}{params}")
    if not data:
        return []

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        # Check relevance
        matched = _is_relevant(f"{cve_id} {desc_text}")
        if not matched:
            continue

        # Determine severity from CVSS
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        if cvss_score >= 9.0:
            severity = Severity.CRITICAL
        elif cvss_score >= 7.0:
            severity = Severity.HIGH
        elif cvss_score >= 4.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        findings.append(Finding(
            title=f"{cve_id}: {desc_text[:120]}",
            severity=severity,
            category="cve",
            detail=desc_text,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            action_required=severity in (Severity.HIGH, Severity.CRITICAL),
            action_description=f"Assess impact on UNWIND threat model (matched: {', '.join(matched)})",
            tags=matched,
        ))

    return findings


def _check_openclaw_releases(ctx: TaskContext) -> list[Finding]:
    """Check OpenClaw releases for security-related updates."""
    findings = []

    if ctx.dry_run:
        return [
            Finding(
                title="OpenClaw v2026.2.21: Security patch for MCP auth bypass",
                severity=Severity.MEDIUM,
                category="openclaw",
                detail="Mock release for testing. Fixes authentication bypass in MCP transport.",
                source_url="https://github.com/openclaw/openclaw/releases/tag/v2026.2.21",
                action_required=True,
                action_description="Review changes for impact on UNWIND compatibility",
                tags=["openclaw", "mcp", "auth"],
            ),
        ]

    # Load last-seen release hash
    last_seen = ctx.load_state("openclaw_releases.json", {"last_hash": ""})

    data = _fetch_json(OPENCLAW_RELEASES_API)
    if not data or not isinstance(data, list):
        return []

    for release in data[:5]:  # Check last 5 releases
        tag = release.get("tag_name", "")
        body = release.get("body", "")
        content_hash = _content_hash(f"{tag}{body}")

        # Skip already-seen releases
        if content_hash == last_seen.get("last_hash"):
            break

        # Check for security-relevant content
        security_keywords = ["security", "cve", "vulnerability", "fix", "patch",
                             "ssrf", "injection", "bypass", "exploit"]
        body_lower = body.lower()
        matched = [kw for kw in security_keywords if kw in body_lower]

        if matched:
            findings.append(Finding(
                title=f"OpenClaw {tag}: {', '.join(matched)} mentioned in release notes",
                severity=Severity.MEDIUM,
                category="openclaw",
                detail=body[:500],
                source_url=release.get("html_url", ""),
                action_required=True,
                action_description="Review release for UNWIND compatibility and threat model impact",
                tags=["openclaw"] + matched,
            ))

    # Save the latest hash
    if data:
        latest = data[0]
        ctx.save_state("openclaw_releases.json", {
            "last_hash": _content_hash(f"{latest.get('tag_name', '')}{latest.get('body', '')}"),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        })

    return findings


def _check_github_advisories(ctx: TaskContext) -> list[Finding]:
    """Check GitHub Security Advisories for relevant entries."""
    findings = []

    if ctx.dry_run:
        return [
            Finding(
                title="GHSA-xxxx-yyyy: Path traversal in MCP filesystem server",
                severity=Severity.HIGH,
                category="github-advisory",
                detail="Mock advisory for testing.",
                source_url="https://github.com/advisories/GHSA-xxxx-yyyy",
                action_required=True,
                action_description="Verify UNWIND path jail catches this vector",
                tags=["path traversal", "mcp"],
            ),
        ]

    # GitHub advisories API supports keyword search
    for keyword in ["mcp", "ssrf", "path+traversal", "prompt+injection"]:
        url = f"{GITHUB_ADVISORY_API}?type=reviewed&per_page=5"
        data = _fetch_json(url)
        if not data or not isinstance(data, list):
            continue

        for advisory in data:
            summary = advisory.get("summary", "")
            description = advisory.get("description", "")
            matched = _is_relevant(f"{summary} {description}")
            if not matched:
                continue

            ghsa_id = advisory.get("ghsa_id", "")
            severity_str = advisory.get("severity", "medium").lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }

            findings.append(Finding(
                title=f"{ghsa_id}: {summary[:120]}",
                severity=severity_map.get(severity_str, Severity.MEDIUM),
                category="github-advisory",
                detail=description[:500] if description else summary,
                source_url=advisory.get("html_url", ""),
                action_required=severity_str in ("critical", "high"),
                action_description=f"Assess UNWIND coverage (matched: {', '.join(matched)})",
                tags=matched,
            ))

    return findings


def cve_watcher(ctx: TaskContext) -> TaskResult:
    """Main CVE watcher task. Checks NVD, GitHub advisories, and OpenClaw releases."""
    all_findings = []

    # Run all three checks
    all_findings.extend(_check_nvd(ctx))
    all_findings.extend(_check_openclaw_releases(ctx))
    all_findings.extend(_check_github_advisories(ctx))

    # Deduplicate by title hash
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = _content_hash(f.title)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Determine status
    if not unique_findings:
        status = TaskStatus.SUCCESS
        summary = "No new relevant CVEs or security advisories found"
    else:
        action_count = sum(1 for f in unique_findings if f.action_required)
        status = TaskStatus.WARNING
        summary = (f"{len(unique_findings)} finding(s), "
                   f"{action_count} requiring action")

    return TaskResult(
        task_name="cve_watcher",
        status=status,
        findings=unique_findings,
        summary=summary,
    )
