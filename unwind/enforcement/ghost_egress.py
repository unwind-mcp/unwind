"""Ghost Egress Guard — stage 3b of the enforcement pipeline.

Blocks read-channel data exfiltration when Ghost Mode is active.
Runs BEFORE the SSRF shield so that secrets embedded in URLs never
trigger a DNS lookup.

Three policy modes:
  - "isolate"  (default) — block ALL outbound network in Ghost Mode
  - "ask"      — block but include domain info for dashboard one-click allow
  - "filtered" — allow with DLP scanning on URLs, hostnames, queries

Architecture decision record:
  - Stage placement: 3b (after path jail, before SSRF) — agreed with SENTINEL
  - Explicit block, not fake success — agent sees GHOST_MODE_NETWORK_BLOCKED
  - search_web is first-class exfil surface (not just fetch/http)
  - Wires into taint/approval/circuit-breaker via telemetry events
"""

import math
import re
import time as _time
from dataclasses import dataclass, field
from typing import FrozenSet, Optional
from urllib.parse import urlparse, parse_qs, unquote

from ..config import UnwindConfig


# ──────────────────────────────────────────────
# Secret-pattern scanning
# ──────────────────────────────────────────────

# High-precision patterns — deliberately conservative to avoid false positives.
# Each pattern should have a near-zero false-positive rate on normal URLs.
SECRET_PATTERNS: list[re.Pattern] = [
    # AWS access key (starts with AKIA, 20 chars)
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # GitHub personal access token (ghp_ prefix)
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    # GitHub OAuth token (gho_ prefix)
    re.compile(r"gho_[A-Za-z0-9]{36,}"),
    # OpenAI API key (sk- prefix, 48+ chars)
    re.compile(r"sk-[A-Za-z0-9]{48,}"),
    # Stripe secret key
    re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    # Slack token (xoxb-, xoxp-, xoxa-)
    re.compile(r"xox[bpa]-[A-Za-z0-9\-]{24,}"),
    # JWT (three base64url sections separated by dots)
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # PEM private key header (URL-encoded or raw)
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"-----%20BEGIN"),
    # Google API key
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    # Anthropic API key (sk-ant-)
    re.compile(r"sk-ant-[A-Za-z0-9]{20,}"),
    # Generic high-entropy hex (64+ chars — likely a secret)
    re.compile(r"[0-9a-f]{64,}", re.IGNORECASE),
]


def scan_url_for_secrets(url: str) -> Optional[str]:
    """Scan a URL for embedded secrets in host, path, query, userinfo, fragment.

    Returns the matched pattern description if found, None if clean.
    """
    if not url:
        return None

    try:
        parsed = urlparse(url)
    except Exception:
        return None

    # Check userinfo (username:password@ in URL)
    if parsed.username or parsed.password:
        return "credentials_in_userinfo"

    # Combine all scannable parts
    parts_to_scan = [
        parsed.hostname or "",
        parsed.path or "",
        unquote(parsed.query or ""),
        unquote(parsed.fragment or ""),
    ]
    combined = " ".join(parts_to_scan)

    for pattern in SECRET_PATTERNS:
        if pattern.search(combined):
            return f"secret_pattern_match:{pattern.pattern[:30]}"

    return None


# ──────────────────────────────────────────────
# DNS exfiltration detection (hostname entropy)
# ──────────────────────────────────────────────

# Thresholds calibrated for DNS exfil detection:
# Normal subdomains: "www", "api", "cdn" — low entropy, short
# Exfil subdomains: "c2stLXByb2QtMTIzNDU2Nzg5MA" — high entropy, long
MIN_SUSPICIOUS_LABEL_LENGTH = 20
MIN_SUSPICIOUS_LABEL_ENTROPY = 3.5  # bits per character


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def scan_hostname_entropy(hostname: str) -> Optional[str]:
    """Detect DNS exfiltration via high-entropy subdomain labels.

    Returns description if suspicious, None if clean.
    """
    if not hostname:
        return None

    labels = hostname.split(".")
    # Check each subdomain label (skip TLD and domain)
    for label in labels[:-2] if len(labels) > 2 else []:
        if len(label) >= MIN_SUSPICIOUS_LABEL_LENGTH:
            entropy = _shannon_entropy(label)
            if entropy >= MIN_SUSPICIOUS_LABEL_ENTROPY:
                return f"high_entropy_subdomain:{label[:20]}...(entropy={entropy:.2f})"

    return None


# ──────────────────────────────────────────────
# Search query scanning
# ──────────────────────────────────────────────

def scan_search_query(query_text: str) -> Optional[str]:
    """Scan search query text for embedded secrets.

    search_web is a first-class exfil surface — an agent can encode
    secrets in search queries that get sent to search engines.
    """
    if not query_text or len(query_text) < 10:
        return None

    for pattern in SECRET_PATTERNS:
        if pattern.search(query_text):
            return f"secret_in_search_query:{pattern.pattern[:30]}"

    return None


# ──────────────────────────────────────────────
# Domain extraction helper
# ──────────────────────────────────────────────

def _extract_domain(target: Optional[str]) -> Optional[str]:
    """Extract domain from a URL or bare hostname."""
    if not target:
        return None
    try:
        if "://" not in target:
            target = f"https://{target}"
        parsed = urlparse(target)
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None


# ──────────────────────────────────────────────
# Per-session domain allowlist
# ──────────────────────────────────────────────

@dataclass
class GhostSessionAllowlist:
    """Per-session domain allowlist with optional TTL."""

    ttl_seconds: float = 0.0  # 0 = lasts entire session
    _domains: dict = field(default_factory=dict)  # domain → allowed_at timestamp

    def allow(self, domain: str) -> None:
        self._domains[domain.lower()] = _time.time()

    def is_allowed(self, domain: str) -> bool:
        domain = domain.lower()
        if domain not in self._domains:
            return False
        if self.ttl_seconds <= 0:
            return True  # No expiry
        allowed_at = self._domains[domain]
        return (_time.time() - allowed_at) < self.ttl_seconds

    def clear(self) -> None:
        self._domains.clear()

    def allowed_domains(self) -> list[str]:
        """Return list of currently allowed domains (respecting TTL)."""
        now = _time.time()
        if self.ttl_seconds <= 0:
            return list(self._domains.keys())
        return [
            d for d, t in self._domains.items()
            if (now - t) < self.ttl_seconds
        ]


# ──────────────────────────────────────────────
# Ghost Egress Guard result
# ──────────────────────────────────────────────

@dataclass
class GhostEgressResult:
    """Result from Ghost Egress Guard check."""
    blocked: bool
    reason: str
    ask_domain: Optional[str] = None  # For "ask" mode: domain to approve
    dlp_hit: Optional[str] = None     # For "filtered" mode: what was detected


# ──────────────────────────────────────────────
# Ghost Egress Guard
# ──────────────────────────────────────────────

class GhostEgressGuard:
    """Enforces network isolation in Ghost Mode (stage 3b).

    Runs BEFORE SSRF shield so that secrets in URLs never trigger DNS.
    """

    def __init__(self, config: UnwindConfig):
        self.policy = config.ghost_network_policy
        self.static_allowlist = set(d.lower() for d in config.ghost_network_allowlist)
        self.ghost_egress_tools = config.ghost_egress_tools
        self.network_tools = config.network_tools

    def check(
        self,
        tool_name: str,
        target: Optional[str] = None,
        parameters: Optional[dict] = None,
        session_allowlist: Optional[GhostSessionAllowlist] = None,
    ) -> Optional[GhostEgressResult]:
        """Check a tool call against the Ghost Egress policy.

        Returns None if tool is not a network tool (let pipeline continue).
        Returns GhostEgressResult if tool is a network tool.
        """
        # Only gate network-capable tools
        if tool_name not in self.ghost_egress_tools and tool_name not in self.network_tools:
            return None

        # --- ISOLATE mode: block everything ---
        if self.policy == "isolate":
            return GhostEgressResult(
                blocked=True,
                reason="GHOST_MODE_NETWORK_BLOCKED (policy=isolate): "
                       f"all outbound network blocked in Ghost Mode [{tool_name}]",
            )

        # --- ASK mode: block unless domain is approved ---
        if self.policy == "ask":
            domain = _extract_domain(target)
            # Check static allowlist
            if domain and domain in self.static_allowlist:
                # Still DLP-scan even allowed domains
                return self._check_request_shape(tool_name, target, parameters)
            # Check session allowlist
            if domain and session_allowlist and session_allowlist.is_allowed(domain):
                return self._check_request_shape(tool_name, target, parameters)
            # Not approved — block with domain info for dashboard
            return GhostEgressResult(
                blocked=True,
                reason="GHOST_MODE_NETWORK_BLOCKED (policy=ask): "
                       f"domain not approved [{tool_name} → {domain or 'unknown'}]",
                ask_domain=domain,
            )

        # --- FILTERED mode: allow with DLP scanning ---
        if self.policy == "filtered":
            return self._check_request_shape(tool_name, target, parameters)

        # Unknown policy — fail closed
        return GhostEgressResult(
            blocked=True,
            reason=f"GHOST_MODE_NETWORK_BLOCKED: unknown policy '{self.policy}' — fail closed",
        )

    def _check_request_shape(
        self,
        tool_name: str,
        target: Optional[str],
        parameters: Optional[dict],
    ) -> Optional[GhostEgressResult]:
        """DLP scanning for filtered/approved requests.

        Checks for:
        1. Secrets in URL (path, query, fragment, userinfo)
        2. DNS exfiltration via high-entropy subdomains
        3. Secrets in search queries
        4. HTTPS enforcement (no HTTP in filtered mode)
        5. No userinfo in URL
        """
        # 1. Secret scanning on URL
        if target:
            secret_hit = scan_url_for_secrets(target)
            if secret_hit:
                return GhostEgressResult(
                    blocked=True,
                    reason=f"GHOST_EGRESS_DLP: secret detected in URL [{secret_hit}]",
                    dlp_hit=secret_hit,
                )

        # 2. DNS exfil detection
        domain = _extract_domain(target)
        if domain:
            entropy_hit = scan_hostname_entropy(domain)
            if entropy_hit:
                return GhostEgressResult(
                    blocked=True,
                    reason=f"GHOST_EGRESS_DLP: DNS exfiltration suspected [{entropy_hit}]",
                    dlp_hit=entropy_hit,
                )

        # 3. Search query scanning
        if tool_name == "search_web" and parameters:
            query = parameters.get("query", "") or parameters.get("q", "")
            if query:
                search_hit = scan_search_query(query)
                if search_hit:
                    return GhostEgressResult(
                        blocked=True,
                        reason=f"GHOST_EGRESS_DLP: secret in search query [{search_hit}]",
                        dlp_hit=search_hit,
                    )

        # 4. HTTPS enforcement
        if target:
            try:
                parsed = urlparse(target)
                if parsed.scheme == "http":
                    return GhostEgressResult(
                        blocked=True,
                        reason="GHOST_EGRESS_DLP: HTTP not allowed in Ghost Mode (use HTTPS)",
                    )
            except Exception:
                pass

        # 5. No userinfo in filtered mode
        if target:
            try:
                parsed = urlparse(target)
                if parsed.username or parsed.password:
                    return GhostEgressResult(
                        blocked=True,
                        reason="GHOST_EGRESS_DLP: userinfo in URL not allowed in Ghost Mode",
                    )
            except Exception:
                pass

        # Passed all checks
        return GhostEgressResult(blocked=False, reason="ghost_egress_clean")
