"""SSRF Shield.

Blocks Server-Side Request Forgery by validating target URLs:
- Resolves DNS to check actual IP (defeats DNS rebinding)
- DNS pinning: pins hostname→IP on first resolve, rejects drift (R-NET-004)
- Blocks private, link-local, metadata, CGNAT, and IPv6 equivalents
- Blocks IPv6 transition mechanisms: NAT64, 6to4, Teredo (CVE-2026-26322)
- Strict dotted-decimal IPv4 validation (rejects octal/hex/short forms)
- Scheme validation (HTTPS only by default, ws:// blocked to non-loopback)
- Re-checks on redirect hops (or disables redirects)
"""

import ipaddress
import re
import socket
import time
from typing import Optional
from urllib.parse import urlparse

from ..config import UnwindConfig

# Strict dotted-decimal IPv4: exactly four 0-255 octets, no leading zeros
# This rejects octal (0177.0.0.1), hex (0x7f.0.0.1), short (127.1), packed forms
_STRICT_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$'
)


class SSRFShieldCheck:
    """Block network requests to private/metadata IP ranges."""

    def __init__(self, config: UnwindConfig):
        self.config = config
        # Parse CIDR strings into network objects for fast lookup
        self._blocked_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in config.ssrf_blocked_cidrs:
            try:
                self._blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass  # Skip invalid CIDRs in config

        # --- DNS Pinning Cache (R-NET-004) ---
        # Maps hostname → (pinned_ips, timestamp).
        # Once a hostname resolves, subsequent resolves must return the same IPs.
        # This defeats DNS rebinding where attacker controls DNS and swaps
        # public→private IP between resolve and connect.
        # TTL: 5 minutes (matches taint decay). After TTL, re-resolve is allowed.
        self._dns_pins: dict[str, tuple[frozenset[str], float]] = {}
        self._dns_pin_ttl: float = 300.0  # 5 minutes


    def check_redirect(self, original_url: str, redirect_url: str) -> Optional[str]:
        """Re-validate a redirect target against SSRF rules.

        Call this when an HTTP client receives a 3xx redirect. The redirect
        target must pass the same checks as the original URL: scheme
        whitelist, hostname resolution, IP blocklist, and DNS pinning.

        Returns error message if blocked, None if allowed.
        """
        # Validate the redirect target through the full check pipeline
        redirect_error = self.check(redirect_url)
        if redirect_error:
            return (
                f"SSRF Shield: Redirect blocked — {original_url} redirected to "
                f"{redirect_url} which failed validation: {redirect_error}"
            )
        return None

    def _is_ip_blocked(self, ip_str: str) -> bool:
        """Check if an IP address falls within any blocked range."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return True  # If we can't parse it, block it

        for network in self._blocked_networks:
            if addr in network:
                return True

        return False

    def _resolve_hostname(self, hostname: str) -> list[str]:
        """Resolve a hostname to its IP addresses.

        We resolve ourselves rather than trusting the HTTP library,
        to defeat DNS rebinding attacks.
        """
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return list({result[4][0] for result in results})
        except socket.gaierror:
            return []

    def _check_dns_pin(self, hostname: str, resolved_ips: list[str]) -> Optional[str]:
        """Check resolved IPs against pinned DNS cache (R-NET-004).

        On first resolve: pin the hostname→IPs mapping.
        On subsequent resolves within TTL: reject if IPs changed.
        After TTL expires: allow re-pin (fresh resolve).

        Returns error message if DNS drift detected, None if OK.
        """
        now = time.time()
        ip_set = frozenset(resolved_ips)

        if hostname in self._dns_pins:
            pinned_ips, pinned_at = self._dns_pins[hostname]

            # TTL expired — allow re-pin
            if (now - pinned_at) > self._dns_pin_ttl:
                self._dns_pins[hostname] = (ip_set, now)
                return None

            # Check for drift
            if ip_set != pinned_ips:
                return (
                    f"SSRF Shield: DNS pin violation for {hostname} — "
                    f"previously resolved to {sorted(pinned_ips)}, "
                    f"now resolves to {sorted(ip_set)} "
                    f"(possible DNS rebinding attack, R-NET-004)"
                )
        else:
            # First resolve — pin it
            self._dns_pins[hostname] = (ip_set, now)

        return None

    def clear_dns_pins(self) -> None:
        """Clear all DNS pins. Called on session reset or for testing."""
        self._dns_pins.clear()

    def _is_strict_ipv4(self, hostname: str) -> bool:
        """Check if hostname is a strict dotted-decimal IPv4 address.

        Rejects non-standard forms that Python's ipaddress module accepts:
        - Octal: 0177.0.0.1 (parsed as 127.0.0.1)
        - Hex: 0x7f.0.0.1
        - Short: 127.1 (parsed as 127.0.0.1)
        - Packed decimal: 2130706433 (parsed as 127.0.0.1)

        These non-standard forms are used to bypass naive SSRF checks.
        Ref: OpenClaw v2026.2.19 — CVE-2026-26322 hardening.
        """
        return bool(_STRICT_IPV4_RE.match(hostname))

    def check(self, url: str) -> Optional[str]:
        """Check a URL for SSRF. Returns error message if blocked, None if allowed.

        Args:
            url: The target URL to validate.
        """
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            return f"SSRF Shield: Invalid URL: {url}"

        # Scheme check — block plaintext ws:// to non-loopback
        if parsed.scheme in ("ws", "wss"):
            if parsed.scheme == "ws" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                return f"SSRF Shield: Plaintext ws:// blocked to non-loopback host {parsed.hostname}"
            # wss:// is allowed (encrypted), ws:// to localhost is allowed

        allowed_schemes = ["https", "wss"]
        if self.config.ssrf_allow_http:
            allowed_schemes.extend(["http", "ws"])

        if parsed.scheme not in allowed_schemes:
            return f"SSRF Shield: Blocked scheme '{parsed.scheme}' (allowed: {', '.join(allowed_schemes)})"

        hostname = parsed.hostname
        if not hostname:
            return f"SSRF Shield: No hostname in URL: {url}"

        # Check if hostname is an IP literal
        try:
            addr = ipaddress.ip_address(hostname)

            # For IPv4: enforce strict dotted-decimal (no octal/hex/short/packed)
            if addr.version == 4 and not self._is_strict_ipv4(hostname):
                return (
                    f"SSRF Shield: Non-standard IPv4 format rejected: {hostname} "
                    f"(resolves to {addr}; use strict dotted-decimal)"
                )

            if self._is_ip_blocked(str(addr)):
                return f"SSRF Shield: Blocked IP {hostname} (private/metadata/transition range)"
            return None
        except ValueError:
            pass  # Not an IP literal — resolve it

        # Resolve DNS ourselves
        resolved_ips = self._resolve_hostname(hostname)
        if not resolved_ips:
            return f"SSRF Shield: DNS resolution failed for {hostname}"

        # Check ALL resolved IPs (some hosts resolve to both public and private)
        for ip in resolved_ips:
            if self._is_ip_blocked(ip):
                return (
                    f"SSRF Shield: {hostname} resolves to blocked IP {ip} "
                    f"(possible DNS rebinding or private host)"
                )

        # DNS Pinning (R-NET-004): pin hostname→IPs, reject drift
        pin_error = self._check_dns_pin(hostname, resolved_ips)
        if pin_error:
            return pin_error

        return None
