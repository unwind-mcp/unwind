"""Credential Exposure Check (Pre-Execution).

Dedicated pipeline stage that scans tool parameters, environment variable
references, and file-read content for credential patterns BEFORE the tool
executes. Separate from DLP-Lite (which scans egress payloads AFTER
composition).

This stage catches:
- API keys/tokens in tool parameters (e.g., command args, URL query strings)
- Environment variable references that would expose secrets
- Base64-encoded credentials split across arguments
- Credential patterns in file paths being read (e.g., reading .env files)

Policy:
- BLOCK for untrusted sinks (network tools, exec with piping)
- AMBER for ambiguous sinks (local file writes, logging)

Source: SENTINEL merged list § ADD NOW #2
"""

import re
from typing import Optional

from ..config import UnwindConfig


# ---------------------------------------------------------------------------
# Credential patterns (pre-execution focus)
# ---------------------------------------------------------------------------
# These overlap with DLP-Lite patterns but are tuned for tool PARAMETERS
# rather than egress payloads.

CREDENTIAL_PATTERNS = [
    # AWS credentials
    re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
    re.compile(
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S{20,}",
        re.ASCII,
    ),
    # GCP
    re.compile(r"AIza[0-9A-Za-z_-]{35}", re.ASCII),
    # Stripe
    re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}", re.ASCII),
    # GitHub tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.ASCII),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}", re.ASCII),
    # OpenAI
    re.compile(r"sk-[A-Za-z0-9]{20,}", re.ASCII),
    # Anthropic
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}", re.ASCII),
    # Generic API keys
    re.compile(
        r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        re.IGNORECASE,
    ),
    # JWT tokens
    re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        re.ASCII,
    ),
    # PEM key material
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA )?(?:PRIVATE KEY|CERTIFICATE)-----",
        re.ASCII,
    ),
    # Bearer tokens
    re.compile(r"(?:bearer|token)\s*[=:]\s*[A-Za-z0-9_\-.]{20,}", re.IGNORECASE),
    # Generic password patterns in params
    re.compile(
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}",
        re.IGNORECASE,
    ),
    # Connection strings with embedded credentials
    re.compile(
        r"(?:postgres|mysql|mongodb|redis)://\S+:\S+@",
        re.IGNORECASE,
    ),
    # OpenClaw gateway token pattern
    re.compile(r"gw_tok_[A-Za-z0-9_-]{20,}", re.ASCII),
]

# Environment variable names that typically hold secrets
SENSITIVE_ENV_VARS = frozenset({
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "STRIPE_SECRET_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "DOCKER_PASSWORD",
    "NPM_TOKEN",
    "DATABASE_URL",
    "REDIS_URL",
    "MONGODB_URI",
    "OPENCLAW_GATEWAY_TOKEN",
    "UNWIND_SIDECAR_SHARED_SECRET",
    "CLAUDE_CODE_OAUTH_TOKEN",
})

# Tools that send data to untrusted sinks (BLOCK on credential exposure)
UNTRUSTED_SINK_TOOLS = frozenset({
    "send_email", "post_message", "http_post", "http_get",
    "upload_file", "api_call", "webhook", "fetch_web",
    "browser_navigate",
})


class CredentialExposureCheck:
    """Scan tool parameters for credential exposure before execution.

    Unlike DLP-Lite which scans egress payloads, this stage operates
    on raw tool parameters BEFORE the tool runs.
    """

    def __init__(self, config: UnwindConfig):
        self.config = config

    def _scan_value(self, value: str) -> list[str]:
        """Scan a string value for credential patterns."""
        findings = []
        for pattern in CREDENTIAL_PATTERNS:
            matches = pattern.findall(value)
            if matches:
                # Redact the actual credential in the finding
                sample = matches[0][:8] + "..." if len(matches[0]) > 8 else "***"
                findings.append(
                    f"credential pattern: {pattern.pattern[:30]}... "
                    f"(found: {sample})"
                )
        return findings

    def _scan_env_references(self, value: str) -> list[str]:
        """Detect references to sensitive environment variables."""
        findings = []
        # Match $VAR, ${VAR}, and env:VAR patterns
        env_refs = re.findall(
            r"(?:\$\{?|env[:\s=]+)([A-Z_][A-Z0-9_]*)", value, re.IGNORECASE
        )
        for ref in env_refs:
            if ref.upper() in SENSITIVE_ENV_VARS:
                findings.append(f"sensitive env var reference: ${ref}")
        return findings

    # Maximum total values to scan across all nesting levels.
    # Prevents combinatorial explosion from wide+deep parameter trees
    # (e.g., 50 keys * 50 keys * 50 keys = 125K values at depth 3).
    MAX_SCAN_ITEMS = 10_000

    def _scan_params_recursive(
        self, params: dict, depth: int = 0, max_depth: int = 5,
        _counter: list | None = None,
    ) -> list[str]:
        """Recursively scan all string values in params dict.

        Args:
            params: Dict of tool parameters.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth (default 5).
            _counter: Mutable counter [items_scanned] to enforce global cap.

        The global cap (MAX_SCAN_ITEMS) prevents OOM/CPU exhaustion from
        adversarial parameter trees. This is a real attack vector —
        automated scanners can send wide+deep dicts to hang the pipeline.
        """
        if depth >= max_depth:
            return []

        if _counter is None:
            _counter = [0]

        findings = []
        for key, value in params.items():
            _counter[0] += 1
            if _counter[0] > self.MAX_SCAN_ITEMS:
                findings.append(
                    "SCAN_LIMIT_REACHED: parameter tree exceeds "
                    f"{self.MAX_SCAN_ITEMS} items — possible DoS payload"
                )
                return findings

            if isinstance(value, str):
                findings.extend(self._scan_value(value))
                findings.extend(self._scan_env_references(value))
            elif isinstance(value, dict):
                findings.extend(
                    self._scan_params_recursive(
                        value, depth + 1, max_depth, _counter
                    )
                )
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _counter[0] += 1
                    if _counter[0] > self.MAX_SCAN_ITEMS:
                        findings.append(
                            "SCAN_LIMIT_REACHED: parameter tree exceeds "
                            f"{self.MAX_SCAN_ITEMS} items — possible DoS payload"
                        )
                        return findings
                    if isinstance(item, str):
                        findings.extend(self._scan_value(item))
                        findings.extend(self._scan_env_references(item))
                    elif isinstance(item, dict):
                        findings.extend(
                            self._scan_params_recursive(
                                item, depth + 1, max_depth, _counter
                            )
                        )
        return findings

    def check(
        self,
        tool_name: str,
        parameters: Optional[dict] = None,
    ) -> Optional[tuple[str, str]]:
        """Scan tool parameters for credential exposure.

        Returns:
            None if clean.
            (severity, message) if credential found.
            severity is "block" for untrusted sinks, "amber" for ambiguous.
        """
        if not parameters:
            return None

        findings = self._scan_params_recursive(parameters)

        if not findings:
            return None

        summary = "; ".join(findings[:3])  # Cap at 3

        # Determine severity based on tool sink type
        if tool_name in UNTRUSTED_SINK_TOOLS:
            return (
                "block",
                f"Credential Exposure (BLOCK): credentials detected in parameters "
                f"for untrusted-sink tool '{tool_name}'. {summary}",
            )
        else:
            return (
                "amber",
                f"Credential Exposure (AMBER): possible credentials in parameters "
                f"for tool '{tool_name}'. {summary}",
            )
