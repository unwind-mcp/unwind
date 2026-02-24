"""DLP-Lite (The Egress Scanner).

Scans outbound payloads for secrets and sensitive data:
- Regex patterns for known API key formats (AWS, GCP, Stripe, GitHub, etc.)
- JWT tokens, PEM certificate headers
- .env file patterns
- Shannon entropy gate for encoded/obfuscated exfiltration
"""

import math
import re
from typing import Optional

from ..config import UnwindConfig


# Compiled regex patterns for known secret formats
SECRET_PATTERNS = [
    # AWS
    re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
    re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S{20,}", re.ASCII),
    # GCP
    re.compile(r"AIza[0-9A-Za-z_-]{35}", re.ASCII),
    # Stripe
    re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}", re.ASCII),
    # GitHub
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.ASCII),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}", re.ASCII),
    # Generic API key patterns
    re.compile(r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}", re.IGNORECASE),
    # JWT tokens
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", re.ASCII),
    # PEM certificate/key headers
    re.compile(r"-----BEGIN (?:RSA |EC |DSA )?(?:PRIVATE KEY|CERTIFICATE)-----", re.ASCII),
    # .env file patterns (multiple KEY=value lines)
    re.compile(r"(?:[A-Z_]{3,}=[^\s]{8,}\n){3,}", re.ASCII),
    # Bearer tokens in text
    re.compile(r"(?:bearer|token)\s*[=:]\s*[A-Za-z0-9_\-.]{20,}", re.IGNORECASE),
]


def compute_shannon_entropy(data: bytes | str) -> float:
    """Compute Shannon entropy in bits per byte.

    Normal English text: ~3.5-5.0
    JSON/structured data: ~4.0-5.5
    Base64 encoded data: ~5.8-6.0
    Compressed/encrypted: ~7.0-8.0
    Random bytes: ~8.0

    Returns 0.0 for empty input.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")

    if not data:
        return 0.0

    length = len(data)
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


class DLPLiteCheck:
    """Scan egress payloads for secrets and high-entropy data."""

    def __init__(self, config: UnwindConfig):
        self.config = config

    def _scan_regex(self, payload: str) -> list[str]:
        """Scan payload against known secret patterns. Returns list of match descriptions."""
        findings = []
        for pattern in SECRET_PATTERNS:
            matches = pattern.findall(payload)
            if matches:
                # Don't include the actual secret in the finding
                sample = matches[0][:8] + "..." if len(matches[0]) > 8 else matches[0]
                findings.append(f"Pattern match: {pattern.pattern[:40]}... (found: {sample})")
        return findings

    def _scan_entropy(self, payload: str) -> list[str]:
        """Scan payload chunks for high-entropy blocks indicating encoding/obfuscation."""
        findings = []
        chunk_size = 256  # Scan in 256-byte chunks

        data = payload.encode("utf-8", errors="replace")
        scan_limit = min(len(data), self.config.dlp_scan_bytes)

        for offset in range(0, scan_limit, chunk_size):
            chunk = data[offset : offset + chunk_size]
            if len(chunk) < 32:
                continue  # Skip very short chunks — entropy unreliable

            entropy = compute_shannon_entropy(chunk)
            if entropy >= self.config.dlp_entropy_threshold:
                findings.append(
                    f"High entropy block at offset {offset}: "
                    f"{entropy:.2f} bits/byte (threshold: {self.config.dlp_entropy_threshold})"
                )
                break  # One finding is enough to trigger amber

        return findings

    def check(self, payload: str) -> Optional[str]:
        """Scan an egress payload. Returns warning message if suspicious, None if clean.

        This triggers amber (human review), not automatic blocking.
        """
        # Truncate for scanning
        scan_text = payload[: self.config.dlp_scan_bytes * 2]  # UTF-8 can expand

        # Regex scan
        regex_findings = self._scan_regex(scan_text)

        # Entropy scan
        entropy_findings = self._scan_entropy(scan_text)

        all_findings = regex_findings + entropy_findings

        if all_findings:
            summary = "; ".join(all_findings[:3])  # Cap at 3 findings
            return f"DLP-Lite Alert: Potential sensitive data in egress payload. {summary}"

        return None
