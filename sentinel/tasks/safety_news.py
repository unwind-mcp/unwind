"""AI Safety News Digest — SENTINEL daily task.

Monitors AI safety news, research, and ecosystem developments
relevant to UNWIND's positioning. Tracks security blog posts,
new agent safety tools, regulatory developments, and research papers.

Sources: GitHub trending (agent safety), arXiv (prompt injection,
agent security), security blogs (RSS-style polling), HN front page.
"""

from __future__ import annotations

import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from sentinel.runner import (
    TaskContext, TaskResult, TaskStatus, Finding, Severity,
)

# GitHub repos to watch for new releases/activity
WATCHED_REPOS = [
    ("invariantlabs-ai/invariant", "Invariant (agent guardrails)"),
    ("meta-llama/PurpleLlama", "PurpleLlama (Meta AI safety)"),
    ("protectai/ai-exploits", "AI Exploits DB"),
    ("leondz/garak", "Garak (LLM vulnerability scanner)"),
    ("NVIDIA/NeMo-Guardrails", "NeMo Guardrails"),
    ("guardrails-ai/guardrails", "Guardrails AI"),
    ("rebuff-ai/rebuff", "Rebuff (prompt injection detection)"),
]

# arXiv search terms for daily paper check
ARXIV_QUERIES = [
    "prompt injection",
    "AI agent security",
    "LLM agent safety",
    "model context protocol",
    "tool use security",
]

GITHUB_API = "https://api.github.com"
ARXIV_API = "http://export.arxiv.org/api/query"

# HN algolia API for searching stories
HN_SEARCH_API = "https://hn.algolia.com/api/v1/search_by_date"

# Keywords for filtering HN stories
HN_KEYWORDS = [
    "mcp", "model context protocol",
    "ai agent", "llm agent",
    "prompt injection", "ai safety",
    "agent security", "tool use",
    "ai guardrails", "ai proxy",
]


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _fetch_json(url: str, timeout: int = 30) -> Optional[dict | list]:
    try:
        req = Request(url, headers={
            "User-Agent": "SENTINEL/0.1 (UNWIND security monitor)",
        })
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, json.JSONDecodeError, TimeoutError):
        return None


def _fetch_text(url: str, timeout: int = 30) -> Optional[str]:
    try:
        req = Request(url, headers={
            "User-Agent": "SENTINEL/0.1 (UNWIND security monitor)",
        })
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode()
    except (URLError, TimeoutError):
        return None


def _check_watched_repos(ctx: TaskContext) -> list[Finding]:
    """Check watched repos for new releases or significant activity."""
    findings = []

    if ctx.dry_run:
        return [
            Finding(
                title="Invariant v0.5.0: New agent policy enforcement engine",
                severity=Severity.INFO,
                category="ai-safety",
                detail="Mock finding for testing. Competitor release with new enforcement features.",
                source_url="https://github.com/invariantlabs-ai/invariant/releases",
                action_required=False,
                tags=["competitor", "agent-safety", "enforcement"],
            ),
        ]

    state = ctx.load_state("watched_repos.json", {})

    for repo_path, label in WATCHED_REPOS:
        url = f"{GITHUB_API}/repos/{repo_path}/releases?per_page=3"
        releases = _fetch_json(url)
        if not releases or not isinstance(releases, list):
            continue

        last_tag = state.get(repo_path, {}).get("last_tag", "")

        for release in releases:
            tag = release.get("tag_name", "")
            if tag == last_tag:
                break

            findings.append(Finding(
                title=f"{label} {tag} released",
                severity=Severity.INFO,
                category="ai-safety",
                detail=(release.get("body", "") or f"New release: {tag}")[:300],
                source_url=release.get("html_url", ""),
                action_required=False,
                tags=["ecosystem", "release"],
            ))

        # Update state
        if releases:
            state[repo_path] = {
                "last_tag": releases[0].get("tag_name", ""),
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }

    ctx.save_state("watched_repos.json", state)
    return findings


def _check_arxiv(ctx: TaskContext) -> list[Finding]:
    """Check arXiv for new papers on relevant topics."""
    findings = []

    if ctx.dry_run:
        return [
            Finding(
                title="arXiv: Indirect Prompt Injection via MCP Tool Descriptions",
                severity=Severity.MEDIUM,
                category="ai-safety",
                detail="Mock paper for testing. Demonstrates injection via tool metadata.",
                source_url="https://arxiv.org/abs/2026.12345",
                action_required=True,
                action_description="Review for new attack vectors relevant to UNWIND",
                tags=["research", "prompt-injection", "mcp"],
            ),
        ]

    seen = ctx.load_state("arxiv_seen.json", {"ids": []})
    seen_ids = set(seen.get("ids", []))

    for query in ARXIV_QUERIES:
        encoded = query.replace(" ", "+")
        url = (f"{ARXIV_API}?search_query=all:{encoded}"
               "&sortBy=submittedDate&sortOrder=descending&max_results=5")
        xml = _fetch_text(url)
        if not xml:
            continue

        # Simple XML parsing (no dependency needed for Atom feed)
        entries = re.findall(r'<entry>(.*?)</entry>', xml, re.DOTALL)
        for entry in entries:
            # Extract fields
            id_match = re.search(r'<id>(.*?)</id>', entry)
            title_match = re.search(r'<title>(.*?)</title>', entry, re.DOTALL)
            summary_match = re.search(r'<summary>(.*?)</summary>', entry, re.DOTALL)

            if not id_match or not title_match:
                continue

            paper_id = id_match.group(1).strip()
            if paper_id in seen_ids:
                continue

            title = re.sub(r'\s+', ' ', title_match.group(1).strip())
            summary = ""
            if summary_match:
                summary = re.sub(r'\s+', ' ', summary_match.group(1).strip())[:300]

            # Check relevance more strictly
            text = f"{title} {summary}".lower()
            relevant = any(kw in text for kw in [
                "injection", "agent", "tool", "mcp", "safety",
                "security", "bypass", "exfiltrat", "guardrail",
            ])

            if relevant:
                findings.append(Finding(
                    title=f"arXiv: {title[:120]}",
                    severity=Severity.MEDIUM if "injection" in text or "bypass" in text else Severity.INFO,
                    category="ai-safety",
                    detail=summary,
                    source_url=paper_id,
                    action_required="injection" in text or "bypass" in text,
                    action_description="Review for new attack vectors" if relevant else "",
                    tags=["research", "arxiv"],
                ))

            seen_ids.add(paper_id)

    # Keep only last 500 seen IDs to prevent unbounded growth
    ctx.save_state("arxiv_seen.json", {"ids": list(seen_ids)[-500:]})
    return findings


def _check_hacker_news(ctx: TaskContext) -> list[Finding]:
    """Check Hacker News for relevant AI safety/agent discussions."""
    findings = []

    if ctx.dry_run:
        return [
            Finding(
                title="HN: Show HN \u2013 Open-source MCP firewall for AI agents",
                severity=Severity.INFO,
                category="ai-safety",
                detail="Mock HN story for testing. New competitor in the MCP safety space.",
                source_url="https://news.ycombinator.com/item?id=99999999",
                action_required=False,
                tags=["hacker-news", "competitor", "mcp"],
            ),
        ]

    seen = ctx.load_state("hn_seen.json", {"ids": []})
    seen_ids = set(seen.get("ids", []))

    for keyword in HN_KEYWORDS:
        url = f"{HN_SEARCH_API}?query={keyword.replace(' ', '+')}&tags=story&hitsPerPage=5"
        data = _fetch_json(url)
        if not data:
            continue

        for hit in data.get("hits", []):
            object_id = hit.get("objectID", "")
            if object_id in seen_ids:
                continue

            title = hit.get("title", "")
            points = hit.get("points", 0)

            # Only surface stories with meaningful engagement
            if points < 10:
                continue

            story_url = hit.get("url", "")
            hn_url = f"https://news.ycombinator.com/item?id={object_id}"

            findings.append(Finding(
                title=f"HN: {title[:120]} ({points} pts)",
                severity=Severity.INFO,
                category="ai-safety",
                detail=f"Story URL: {story_url}" if story_url else "Ask HN / text post",
                source_url=hn_url,
                action_required=False,
                tags=["hacker-news", "ecosystem"],
            ))

            seen_ids.add(object_id)

    ctx.save_state("hn_seen.json", {"ids": list(seen_ids)[-1000:]})
    return findings


def safety_news(ctx: TaskContext) -> TaskResult:
    """Main AI safety news digest task."""
    all_findings = []

    all_findings.extend(_check_watched_repos(ctx))
    all_findings.extend(_check_arxiv(ctx))
    all_findings.extend(_check_hacker_news(ctx))

    if not all_findings:
        return TaskResult(
            task_name="safety_news",
            status=TaskStatus.SUCCESS,
            summary="No new AI safety developments detected today",
        )

    action_count = sum(1 for f in all_findings if f.action_required)
    return TaskResult(
        task_name="safety_news",
        status=TaskStatus.WARNING if action_count else TaskStatus.SUCCESS,
        findings=all_findings,
        summary=f"{len(all_findings)} item(s) found, {action_count} requiring review",
    )
