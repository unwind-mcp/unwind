"""UNWIND configuration — all tuneable parameters in one place."""

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Set


@dataclass
class UnwindConfig:
    """Central configuration for UNWIND proxy."""

    # --- Paths ---
    unwind_home: Path = field(
        default_factory=lambda: Path(os.environ.get("UNWIND_HOME", "~/.unwind")).expanduser()
    )
    workspace_root: Path = field(
        default_factory=lambda: Path(os.environ.get("UNWIND_WORKSPACE", "~/agent-workspace")).expanduser()
    )

    # --- Networking ---
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 9000
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8001

    # --- Upstream Authentication (The Bypass Seal) ---
    upstream_token: str = field(default_factory=lambda: uuid.uuid4().hex)

    # --- Self-Protection: canonical paths that must never be touched by the agent ---
    # Additional roots can be configured for framework-specific protection
    # (e.g., ~/.openclaw for OpenClaw deployments).  Auto-detected if present.
    extra_protected_roots: list[Path] = field(default_factory=list)

    @property
    def protected_roots(self) -> list[Path]:
        roots = [self.unwind_home]
        # Add any explicitly configured extra roots
        roots.extend(self.extra_protected_roots)
        # Auto-detect common agent framework config dirs (secret-bearing)
        for framework_dir in ("~/.openclaw", "~/.cursor", "~/.claude"):
            p = Path(framework_dir).expanduser()
            if p.exists() and p not in roots:
                roots.append(p)
        return roots

    # --- Tool Classification ---
    # Sensors: tools that ingest untrusted external content
    sensor_tools: FrozenSet[str] = frozenset({
        "read_email", "fetch_web", "read_document", "inbound_message",
        "read_calendar", "search_web", "read_slack", "read_rss",
        # OpenClaw built-ins (read-only/sensor surfaces)
        "fs_read", "memory_get", "memory_search",
        "session_status", "sessions_list", "sessions_history",
        "agents_list", "image", "web_search", "web_fetch",
    })

    # High-risk actuators: state-modifying tools that need taint gating
    high_risk_actuator_tools: FrozenSet[str] = frozenset({
        "send_email", "post_message", "send_message", "reply_email",
        "bash_exec", "shell_exec", "run_command", "execute_command",
        "exec", "process", "exec_process",
        "http_post", "http_put", "http_delete", "http_patch",
        "upload_file", "api_call", "webhook",
        # OpenClaw high-impact actuator surfaces
        "sessions_send", "sessions_spawn", "message",
        "browser", "canvas", "nodes", "tts",
    })

    # Control-plane tools: scheduler/gateway/orchestrator controls
    control_plane_tools: FrozenSet[str] = frozenset({
        "gateway", "cron", "subagents", "lobster",
    })

    # All state-modifying tools (includes high-risk + lower-risk writes)
    # Used by: circuit breaker (stage 6), Ghost Mode gate (stage 9)
    state_modifying_tools: FrozenSet[str] = frozenset({
        # Communication
        "send_email", "post_message", "send_message", "reply_email",
        # System / exec
        "bash_exec", "shell_exec", "run_command", "execute_command",
        "exec", "process", "exec_process",
        # Network writes (all HTTP mutators)
        "http_post", "http_put", "http_delete", "http_patch",
        "upload_file", "api_call", "webhook",
        # OpenClaw actuator/control-plane surfaces
        "sessions_send", "sessions_spawn", "message",
        "browser", "canvas", "nodes", "tts",
        "gateway", "cron", "subagents", "lobster",
        # Filesystem
        "fs_write", "fs_delete", "fs_rename", "fs_mkdir", "fs_move", "fs_copy",
        "write_file", "delete_file", "rename_file", "move_file", "create_directory",
        # Calendar / Scheduling
        "create_calendar_event", "modify_calendar_event", "delete_calendar_event",
        "create_event", "update_event", "delete_event",
        # Package management
        "install_package", "pip_install", "npm_install",
        # Database (state-modifying only)
        "db_insert", "db_update", "db_delete", "db_execute",
        "sql_execute", "query_execute",
        # Git (state-modifying only)
        "git_commit", "git_push", "git_checkout", "git_merge",
    })

    # Ghost Mode intercept tools — superset of state_modifying_tools.
    # Used ONLY by Ghost Mode gate (stage 9). Includes prefix heuristic
    # catch-all for tools we haven't explicitly listed.
    # Rationale: Ghost Mode errs on the side of intercepting. The circuit
    # breaker uses state_modifying_tools (narrower) to avoid false rate-limits.
    ghost_intercept_prefixes: tuple[str, ...] = (
        "create_", "delete_", "remove_", "update_", "modify_",
        "send_", "post_", "put_", "write_", "set_", "insert_",
        "drop_", "execute_", "run_", "install_", "push_",
    )

    # Network tools subject to SSRF checks
    network_tools: FrozenSet[str] = frozenset({
        "fetch_web", "http_post", "http_put", "http_delete", "http_patch", "http_get", "browser_navigate",
        "webhook", "websocket", "api_call",
    })

    # Egress tools subject to DLP-lite scanning
    egress_tools: FrozenSet[str] = frozenset({
        "send_email", "post_message", "send_message", "reply_email",
        "http_post", "http_put", "http_delete", "http_patch",
        "upload_file", "api_call", "webhook",
        "process", "exec_process",
    })

    # --- Ghost Egress Guard (stage 3b) ---
    # Network policy for Ghost Mode: "isolate", "ask", or "filtered"
    ghost_network_policy: str = "isolate"
    # Static domain allowlist for "ask" mode
    ghost_network_allowlist: list[str] = field(default_factory=list)
    # TTL for session-level domain approvals (0 = lasts entire session)
    ghost_network_allowlist_ttl_seconds: float = 0.0
    # Tools subject to Ghost Egress Guard — network-capable tools that could
    # exfiltrate data via read channels (DNS, HTTP GET, search queries)
    ghost_egress_tools: FrozenSet[str] = frozenset({
        "fetch_web", "http_get", "browser_navigate", "websocket", "search_web",
    })

    # --- Canary Honeypot Tools ---
    canary_tools: FrozenSet[str] = frozenset({
        "disable_security_audit",
        "extract_system_keys",
        "grant_admin_access",
        "override_safety_limits",
    })

    def is_ghost_intercepted(self, tool_name: str) -> bool:
        """Check if a tool should be intercepted by Ghost Mode.

        Uses explicit set (state_modifying_tools) + prefix heuristic.
        Errs on the side of intercepting: if a tool looks like it might
        write, Ghost Mode catches it.  The agent still gets a success
        response — it just doesn't touch the real world.
        """
        if tool_name in self.state_modifying_tools:
            return True
        return any(tool_name.startswith(p) for p in self.ghost_intercept_prefixes)

    # --- Circuit Breaker ---
    circuit_breaker_max_calls: int = 5
    circuit_breaker_window_seconds: float = 5.0

    # --- Manifest Rewriting (RBAC) ---
    # Default permission tier for new sessions (1=read-only, 2=scoped-write, 3=communicate, 4=full)
    default_permission_tier: int = 1
    # How to handle tools not in any tier definition: "hide", "tier1", "show"
    unknown_tool_policy: str = "hide"

    # --- Taint Decay (legacy — graduated decay config is in TaintDecayConfig) ---
    taint_decay_seconds: float = 300.0  # 5 minutes — kept for backwards compat

    # --- DLP-Lite ---
    dlp_entropy_threshold: float = 5.7  # Shannon bits/byte (base64 ≈ 5.8-6.0; normal text ≈ 3.5-5.0)
    dlp_scan_bytes: int = 8192  # Scan first N bytes of egress payloads

    # --- SSRF Shield: blocked IP ranges ---
    # Updated 2026-02-20: added IPv6 transition address bypasses
    # (NAT64, 6to4, Teredo) per OpenClaw CVE-2026-26322 disclosure
    ssrf_blocked_cidrs: list[str] = field(default_factory=lambda: [
        # --- IPv4 ---
        "127.0.0.0/8",       # Loopback
        "10.0.0.0/8",        # RFC1918
        "172.16.0.0/12",     # RFC1918
        "192.168.0.0/16",    # RFC1918
        "169.254.0.0/16",    # Link-local / cloud metadata
        "100.64.0.0/10",     # CGNAT
        "0.0.0.0/8",         # "This" network
        "192.0.0.0/24",      # IETF protocol assignments
        "192.0.2.0/24",      # TEST-NET-1 (documentation)
        "198.51.100.0/24",   # TEST-NET-2
        "203.0.113.0/24",    # TEST-NET-3
        "224.0.0.0/4",       # Multicast
        "240.0.0.0/4",       # Reserved (future use)
        "255.255.255.255/32", # Broadcast
        # --- IPv6 native ---
        "::1/128",           # IPv6 loopback
        "::/128",            # IPv6 unspecified
        "fc00::/7",          # IPv6 unique local
        "fe80::/10",         # IPv6 link-local
        "ff00::/8",          # IPv6 multicast
        # --- IPv4-mapped IPv6 ---
        "::ffff:127.0.0.0/104",  # IPv4-mapped loopback
        "::ffff:10.0.0.0/104",   # IPv4-mapped RFC1918
        "::ffff:172.16.0.0/108", # IPv4-mapped RFC1918
        "::ffff:192.168.0.0/112", # IPv4-mapped RFC1918
        "::ffff:169.254.0.0/112", # IPv4-mapped metadata
        "::ffff:100.64.0.0/106",  # IPv4-mapped CGNAT
        "::ffff:0.0.0.0/104",    # IPv4-mapped "this" network
        # --- IPv6 transition mechanisms (CVE-2026-26322 attack vectors) ---
        "64:ff9b::/96",      # NAT64 well-known prefix (RFC 6052)
        "64:ff9b:1::/48",    # NAT64 local-use prefix (RFC 8215)
        "2002::/16",         # 6to4 (RFC 3056) — encapsulates arbitrary IPv4
        "2001:0000::/32",    # Teredo (RFC 4380) — encapsulates arbitrary IPv4
        # --- IPv4-compatible (deprecated but still parsed) ---
        "::0.0.0.0/96",     # IPv4-compatible IPv6 (deprecated, blocks ::127.0.0.1 etc.)
    ])
    ssrf_allow_http: bool = False  # Only HTTPS by default

    # --- Snapshots ---
    snapshot_max_file_bytes: int = 25 * 1024 * 1024  # 25MB cap
    snapshot_retention_days: int = 30
    snapshot_max_storage_bytes: int = 5 * 1024 * 1024 * 1024  # 5GB

    # --- Flight Recorder ---
    read_collapse_interval_seconds: float = 300.0  # 5 minutes
    events_retention_days: int = 90  # P1-6: Delete events older than this (0 = keep forever)
    events_max_rows: int = 500_000   # P1-6: Hard cap on event count (0 = unlimited)

    @property
    def events_db_path(self) -> Path:
        return self.unwind_home / "events.db"

    @property
    def snapshots_dir(self) -> Path:
        return self.unwind_home / "snapshots"

    @property
    def trash_dir(self) -> Path:
        return self.unwind_home / "snapshots" / "trash"

    def ensure_dirs(self) -> None:
        """Create all required directories."""
        self.unwind_home.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.trash_dir.mkdir(parents=True, exist_ok=True)
