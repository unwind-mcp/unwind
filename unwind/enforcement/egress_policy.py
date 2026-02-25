"""Egress Policy Pack — default-deny for metadata, loopback, private infra.

Source: SENTINEL merged list § ADD NOW #4
        ADAPTER_THREAT_MODEL.yaml § TM-ADAPTER-002 (proxy interception)

This module works alongside SSRF Shield (IP-level) to provide
hostname/domain-level egress controls:

1. CLOUD METADATA ENDPOINTS — blocked by hostname (not just IP),
   defeating DNS rebinding that returns 169.254.169.254.
2. INTERNAL SERVICE ENDPOINTS — block common internal service patterns
   (consul, vault, etcd, kubernetes API, docker socket).
3. DOMAIN DENYLIST — configurable blocked domains (e.g., competitor APIs,
   known exfiltration endpoints).
4. DOMAIN ALLOWLIST (optional) — if set, ONLY these domains are allowed
   for egress (strict mode).

Design:
    - Runs AFTER SSRF shield in pipeline (SSRF catches IP-level, this
      catches hostname-level patterns that survive DNS resolution).
    - Fail-closed: if domain cannot be determined, block.
    - All checks case-insensitive.

NanoClaw compatibility:
    NanoClaw blocks egress by container network policy. This module
    provides equivalent protection at the application layer for
    OpenClaw's in-process plugin model.
"""

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from ..config import UnwindConfig

logger = logging.getLogger("unwind.egress_policy")

# ---------------------------------------------------------------------------
# Cloud metadata endpoints (hostname-level blocking)
# ---------------------------------------------------------------------------
# These are blocked even if the IP resolves to a public address
# (e.g., attacker-controlled DNS returning metadata IPs).

CLOUD_METADATA_HOSTNAMES = frozenset({
    # AWS
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    # Azure
    "169.254.169.254",  # Also used by Azure IMDS
    # GCP
    "metadata.google.internal",
    "computemedadata.googleapis.com",
    # DigitalOcean
    "169.254.169.254",
    # Oracle Cloud
    "169.254.169.254",
    # Alibaba Cloud
    "100.100.100.200",
    # AWS ECS task metadata
    "169.254.170.2",
    # Kubernetes service account tokens
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    # Link-local metadata (generic)
    "instance-data",
})

# Patterns that match metadata-like hostnames
CLOUD_METADATA_PATTERNS = [
    re.compile(r"^169\.254\.\d+\.\d+$"),                    # Any link-local
    re.compile(r"^100\.100\.100\.\d+$"),                     # Alibaba metadata range
    re.compile(r"^metadata\.", re.IGNORECASE),               # metadata.* prefix
    re.compile(r"^instance-data$", re.IGNORECASE),           # EC2 classic
    re.compile(r"\.internal$", re.IGNORECASE),               # GCP/internal domains
]

# ---------------------------------------------------------------------------
# Internal service endpoints
# ---------------------------------------------------------------------------
# Common service-discovery and infrastructure endpoints that should never
# be contacted by an AI agent.

INTERNAL_SERVICE_PATTERNS = [
    # Consul
    re.compile(r"^consul\.", re.IGNORECASE),
    re.compile(r"\.consul$", re.IGNORECASE),
    re.compile(r"\.consul\.", re.IGNORECASE),
    # HashiCorp Vault
    re.compile(r"^vault\.", re.IGNORECASE),
    re.compile(r"\.vault\.", re.IGNORECASE),
    # etcd
    re.compile(r"^etcd\.", re.IGNORECASE),
    re.compile(r"\.etcd\.", re.IGNORECASE),
    # Kubernetes
    re.compile(r"^kubernetes\.", re.IGNORECASE),
    re.compile(r"\.cluster\.local$", re.IGNORECASE),
    re.compile(r"^kube-", re.IGNORECASE),
    # Docker
    re.compile(r"^docker\.", re.IGNORECASE),
    # Prometheus / Grafana (internal monitoring)
    re.compile(r"^prometheus\.", re.IGNORECASE),
    re.compile(r"^grafana\.", re.IGNORECASE),
    # Redis / databases (should not be accessed by agent)
    re.compile(r"^redis\.", re.IGNORECASE),
    re.compile(r"^postgres\.", re.IGNORECASE),
    re.compile(r"^mysql\.", re.IGNORECASE),
    re.compile(r"^mongo\.", re.IGNORECASE),
    re.compile(r"^elasticsearch\.", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Default domain denylist
# ---------------------------------------------------------------------------
# Domains that should never be contacted by the agent. Operators can
# extend this via policy.json.

DEFAULT_DOMAIN_DENYLIST = frozenset({
    # Pastebin / exfiltration
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "dpaste.org",
    "rentry.co",
    # Webhook / requestbin (data exfiltration via HTTP)
    "webhook.site",
    "requestbin.com",
    "pipedream.com",
    "hookbin.com",
    "requestcatcher.com",
    # File sharing (exfiltration)
    "transfer.sh",
    "file.io",
    "0x0.st",
    # DNS exfiltration
    "burpcollaborator.net",
    "interact.sh",
    "oastify.com",
    "canarytokens.com",
})


# ---------------------------------------------------------------------------
# Egress Policy Check
# ---------------------------------------------------------------------------

class EgressPolicyCheck:
    """Domain-level egress controls for AI agent network access.

    Complements SSRF Shield (IP-level) with hostname/domain matching.
    """

    def __init__(
        self,
        config: UnwindConfig,
        domain_denylist: Optional[frozenset] = None,
        domain_allowlist: Optional[frozenset] = None,
    ):
        self.config = config
        self._domain_denylist = domain_denylist or DEFAULT_DOMAIN_DENYLIST
        self._domain_allowlist = domain_allowlist  # None = not enforced
        # Operator can extend via config
        self._extra_denied: set[str] = set()
        self._extra_allowed: set[str] = set()

    def add_denied_domain(self, domain: str) -> None:
        """Add a domain to the denylist at runtime."""
        self._extra_denied.add(domain.lower())

    def add_allowed_domain(self, domain: str) -> None:
        """Add a domain to the allowlist at runtime."""
        self._extra_allowed.add(domain.lower())

    def _is_metadata_hostname(self, hostname: str) -> Optional[str]:
        """Check if hostname is a cloud metadata endpoint."""
        hostname_lower = hostname.lower()

        if hostname_lower in CLOUD_METADATA_HOSTNAMES:
            return (
                f"Egress Policy: blocked cloud metadata endpoint '{hostname}' "
                f"(CLOUD_METADATA_BLOCKED)"
            )

        for pattern in CLOUD_METADATA_PATTERNS:
            if pattern.search(hostname_lower):
                return (
                    f"Egress Policy: hostname '{hostname}' matches cloud "
                    f"metadata pattern (CLOUD_METADATA_PATTERN_BLOCKED)"
                )

        return None

    def _is_internal_service(self, hostname: str) -> Optional[str]:
        """Check if hostname matches internal service patterns."""
        hostname_lower = hostname.lower()

        for pattern in INTERNAL_SERVICE_PATTERNS:
            if pattern.search(hostname_lower):
                return (
                    f"Egress Policy: hostname '{hostname}' matches internal "
                    f"service pattern (INTERNAL_SERVICE_BLOCKED)"
                )

        return None

    def _is_denied_domain(self, hostname: str) -> Optional[str]:
        """Check if hostname is in the domain denylist."""
        hostname_lower = hostname.lower()

        # Check exact match and suffix match (*.example.com)
        all_denied = self._domain_denylist | self._extra_denied
        for denied in all_denied:
            if hostname_lower == denied or hostname_lower.endswith("." + denied):
                return (
                    f"Egress Policy: domain '{hostname}' is on the denylist "
                    f"(DOMAIN_DENIED)"
                )

        return None

    def _is_allowed_domain(self, hostname: str) -> Optional[str]:
        """Check if hostname is on the allowlist (if allowlist is enforced).

        Returns error message if NOT allowed, None if allowed or no allowlist.
        """
        if self._domain_allowlist is None and not self._extra_allowed:
            return None  # No allowlist configured — everything allowed

        hostname_lower = hostname.lower()
        all_allowed = (self._domain_allowlist or frozenset()) | self._extra_allowed

        for allowed in all_allowed:
            if hostname_lower == allowed or hostname_lower.endswith("." + allowed):
                return None  # Allowed

        return (
            f"Egress Policy: domain '{hostname}' is not on the allowlist "
            f"(DOMAIN_NOT_ALLOWED)"
        )

    def check(self, url: str) -> Optional[str]:
        """Check a URL against egress policy.

        Returns error message if blocked, None if allowed.

        Check order:
        1. Cloud metadata endpoints (always blocked)
        2. Internal service patterns (always blocked)
        3. Domain denylist
        4. Domain allowlist (if configured)
        """
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            return f"Egress Policy: cannot parse URL: {url}"

        hostname = parsed.hostname
        if not hostname:
            return f"Egress Policy: no hostname in URL (EGRESS_NO_HOST)"

        # Strip trailing dot — valid DNS but used to bypass exact-match
        # denylist checks (e.g., "pastebin.com." vs "pastebin.com").
        # RFC 1034 §3.1: trailing dot denotes fully-qualified domain name.
        hostname = hostname.rstrip(".")

        # 1. Cloud metadata
        result = self._is_metadata_hostname(hostname)
        if result:
            return result

        # 2. Internal services
        result = self._is_internal_service(hostname)
        if result:
            return result

        # 3. Domain denylist
        result = self._is_denied_domain(hostname)
        if result:
            return result

        # 4. Domain allowlist (strict mode)
        result = self._is_allowed_domain(hostname)
        if result:
            return result

        return None
