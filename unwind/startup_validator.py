"""Startup Validator — catches misconfiguration before any agent call is processed.

Runs at UNWIND initialisation. If any check fails, UNWIND refuses to start
and prints a plain-English error to stderr explaining what's wrong and how
to fix it.

A prosumer who misconfigures config.py should NEVER get silent pass-through.
"""

import sys
from dataclasses import dataclass, field
from typing import Optional

from .config import UnwindConfig


@dataclass
class ValidationError:
    """A single config validation failure."""
    field_name: str
    message: str
    fix_hint: str


@dataclass
class ValidationResult:
    """Result of config validation."""
    errors: list[ValidationError] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def add(self, field_name: str, message: str, fix_hint: str) -> None:
        self.errors.append(ValidationError(field_name, message, fix_hint))

    def format_errors(self) -> str:
        """Format all errors as plain-English stderr output."""
        lines = [
            "",
            "=" * 60,
            "UNWIND STARTUP FAILED — Configuration errors detected",
            "=" * 60,
            "",
        ]
        for i, err in enumerate(self.errors, 1):
            lines.append(f"  [{i}] {err.field_name}: {err.message}")
            lines.append(f"      Fix: {err.fix_hint}")
            lines.append("")
        lines.append(
            "UNWIND will not start until these are fixed."
        )
        lines.append(
            "No agent calls will be processed — this is intentional."
        )
        lines.append("=" * 60)
        return "\n".join(lines)


def validate_config(config: UnwindConfig) -> ValidationResult:
    """Validate all config values at startup.

    Returns a ValidationResult. If result.valid is False, UNWIND
    must refuse to start.
    """
    result = ValidationResult()

    # --- Numeric bounds ---

    if config.dlp_entropy_threshold <= 0:
        result.add(
            "dlp_entropy_threshold",
            f"Must be positive, got {config.dlp_entropy_threshold}. "
            "DLP-lite cannot detect secrets with a non-positive threshold.",
            "Set dlp_entropy_threshold to a value between 3.0 and 7.0 "
            "(default: 5.7).",
        )
    elif config.dlp_entropy_threshold > 8.0:
        result.add(
            "dlp_entropy_threshold",
            f"Value {config.dlp_entropy_threshold} exceeds maximum Shannon "
            "entropy (8.0 bits/byte). DLP-lite will never trigger.",
            "Set dlp_entropy_threshold between 3.0 and 7.0 (default: 5.7).",
        )

    if config.circuit_breaker_max_calls < 1:
        result.add(
            "circuit_breaker_max_calls",
            f"Must be at least 1, got {config.circuit_breaker_max_calls}. "
            "A value of 0 blocks ALL state-modifying calls.",
            "Set circuit_breaker_max_calls to a positive integer "
            "(default: 5).",
        )

    if config.circuit_breaker_window_seconds <= 0:
        result.add(
            "circuit_breaker_window_seconds",
            f"Must be positive, got {config.circuit_breaker_window_seconds}.",
            "Set circuit_breaker_window_seconds to a positive number "
            "(default: 5.0).",
        )

    if config.dlp_scan_bytes < 256:
        result.add(
            "dlp_scan_bytes",
            f"Must be at least 256, got {config.dlp_scan_bytes}. "
            "Too small to detect any secrets.",
            "Set dlp_scan_bytes to at least 256 (default: 8192).",
        )
    elif config.dlp_scan_bytes > 10 * 1024 * 1024:
        result.add(
            "dlp_scan_bytes",
            f"Value {config.dlp_scan_bytes} exceeds 10MB. "
            "This could cause excessive memory use on each egress scan.",
            "Set dlp_scan_bytes to a reasonable value (default: 8192).",
        )

    if config.taint_decay_seconds < 0:
        result.add(
            "taint_decay_seconds",
            f"Must be non-negative, got {config.taint_decay_seconds}.",
            "Set taint_decay_seconds to 0 (no decay) or positive "
            "(default: 300.0).",
        )

    if config.snapshot_retention_days < 1:
        result.add(
            "snapshot_retention_days",
            f"Must be at least 1, got {config.snapshot_retention_days}.",
            "Set snapshot_retention_days to a positive integer "
            "(default: 30).",
        )

    if config.snapshot_max_storage_bytes < 1024 * 1024:
        result.add(
            "snapshot_max_storage_bytes",
            f"Must be at least 1MB, got {config.snapshot_max_storage_bytes}.",
            "Set snapshot_max_storage_bytes to at least 1048576 "
            "(default: 5GB).",
        )

    if config.read_collapse_interval_seconds < 0:
        result.add(
            "read_collapse_interval_seconds",
            f"Must be non-negative, got {config.read_collapse_interval_seconds}.",
            "Set read_collapse_interval_seconds to 0 or positive "
            "(default: 300.0).",
        )

    # P1-6: Events retention bounds
    if config.events_retention_days < 0:
        result.add(
            "events_retention_days",
            f"Must be non-negative, got {config.events_retention_days}.",
            "Set events_retention_days to 0 (keep forever) or positive "
            "(default: 90).",
        )

    if config.events_max_rows < 0:
        result.add(
            "events_max_rows",
            f"Must be non-negative, got {config.events_max_rows}.",
            "Set events_max_rows to 0 (unlimited) or positive "
            "(default: 500000).",
        )

    # --- Ghost Egress Guard ---

    valid_policies = ("isolate", "ask", "filtered")
    if config.ghost_network_policy not in valid_policies:
        result.add(
            "ghost_network_policy",
            f"Must be one of {valid_policies}, got '{config.ghost_network_policy}'.",
            "Set ghost_network_policy to 'isolate' (safest), 'ask', "
            "or 'filtered'.",
        )

    if config.ghost_network_allowlist_ttl_seconds < 0:
        result.add(
            "ghost_network_allowlist_ttl_seconds",
            f"Must be non-negative, got {config.ghost_network_allowlist_ttl_seconds}.",
            "Set to 0 (no expiry) or a positive number of seconds.",
        )

    # --- Tool classification sets ---

    if not config.canary_tools:
        result.add(
            "canary_tools",
            "Canary honeypot tool set is empty. "
            "No injection detection is active.",
            "Add at least one canary tool name to canary_tools.",
        )

    if not config.network_tools:
        result.add(
            "network_tools",
            "Network tools set is empty. SSRF shield is disabled.",
            "Add network tool names to network_tools.",
        )

    if not config.sensor_tools:
        result.add(
            "sensor_tools",
            "Sensor tools set is empty. Taint tracking is disabled.",
            "Add sensor tool names to sensor_tools.",
        )

    if not config.state_modifying_tools:
        result.add(
            "state_modifying_tools",
            "State-modifying tools set is empty. "
            "Circuit breaker and Ghost Mode are disabled.",
            "Add state-modifying tool names to state_modifying_tools.",
        )

    if not config.ghost_egress_tools:
        result.add(
            "ghost_egress_tools",
            "Ghost Egress tools set is empty. "
            "Ghost Egress Guard cannot block network reads.",
            "Add network-capable tool names to ghost_egress_tools.",
        )

    # --- Permission tier ---

    if config.default_permission_tier not in (1, 2, 3, 4):
        result.add(
            "default_permission_tier",
            f"Must be 1-4, got {config.default_permission_tier}. "
            "1=read-only, 2=scoped-write, 3=communicate, 4=full.",
            "Set default_permission_tier to 1, 2, 3, or 4 (default: 1).",
        )

    # --- Unknown tool policy ---

    valid_policies_tool = ("hide", "tier1", "show")
    if config.unknown_tool_policy not in valid_policies_tool:
        result.add(
            "unknown_tool_policy",
            f"Must be one of {valid_policies_tool}, "
            f"got '{config.unknown_tool_policy}'.",
            "Set unknown_tool_policy to 'hide' (safest), 'tier1', "
            "or 'show'.",
        )

    # --- SSRF CIDR validation ---
    if not config.ssrf_blocked_cidrs:
        result.add(
            "ssrf_blocked_cidrs",
            "SSRF blocked CIDR list is empty. "
            "No private IP ranges are blocked.",
            "Restore the default CIDR list or add your own.",
        )

    return result


def validate_and_enforce(config: UnwindConfig) -> None:
    """Validate config and refuse to start if invalid.

    Call this at UNWIND initialisation. If validation fails,
    prints plain-English errors to stderr and raises SystemExit.
    """
    result = validate_config(config)
    if not result.valid:
        sys.stderr.write(result.format_errors())
        sys.stderr.write("\n")
        raise SystemExit(1)
