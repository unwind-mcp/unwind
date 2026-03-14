"""UNWIND session state — tracks taint, trust light, ghost mode, scope, and permission tier."""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set

from .config import UnwindConfig
from .enforcement.manifest_filter import PermissionTier
from .enforcement.taint_decay import TaintDecayConfig, TaintLevel, TaintState


class TrustState(Enum):
    GREEN = "green"    # All clear
    AMBER = "amber"    # Attention — awaiting confirmation
    RED = "red"        # Alert — action blocked or session killed


@dataclass
class Session:
    """Per-session security state. Lives in memory, never in the agent's context."""

    session_id: str
    config: UnwindConfig

    # --- Taint (graduated decay) ---
    taint_state: TaintState = field(default_factory=TaintState)
    taint_config: TaintDecayConfig = field(default_factory=TaintDecayConfig)

    # --- Trust ---
    trust_state: TrustState = TrustState.GREEN

    # --- Ghost Mode ---
    ghost_mode: bool = False
    shadow_vfs: dict[str, bytes | str] = field(default_factory=dict)

    # --- Circuit Breaker ---
    state_modify_timestamps: list[float] = field(default_factory=list)

    # --- Session Scope ---
    allowed_tools: Optional[Set[str]] = None  # None = no scope restriction

    # --- Permission Tier (Manifest Rewriting / RBAC) ---
    permission_tier: PermissionTier = PermissionTier.TIER_1_READ_ONLY
    extra_tools: Optional[Set[str]] = None  # Per-session tool overrides
    tier_escalation_log: list[dict] = field(default_factory=list)

    # --- Counters ---
    total_actions: int = 0
    blocked_actions: int = 0
    amber_confirmations: int = 0

    # --- Provenance (server-derived, never caller-supplied) ---
    principal_context: Optional[str] = None

    # --- Session kill flag ---
    killed: bool = False

    # --- Backwards-compatible taint properties ---
    @property
    def is_tainted(self) -> bool:
        """Backwards compatibility: any taint level above NONE."""
        return self.taint_state.is_tainted

    @property
    def tainted_at(self) -> Optional[float]:
        """Backwards compatibility: when taint was last raised."""
        return self.taint_state.last_taint_event

    def taint(self, source_tool: str = "unknown") -> None:
        """Mark session as tainted (external content ingested).

        Uses graduated taint — escalates level based on frequency and cooldown.
        """
        self.taint_state.apply_taint(source_tool, self.taint_config)

    def taint_trusted(self, source_tool: str, rule_id: str) -> None:
        """Apply taint capped at LOW for trusted-source rule matches.

        Cannot escalate above LOW, but must not downgrade existing level.
        If current level > LOW (e.g. HIGH from earlier untrusted events),
        the level is left unchanged.
        """
        from .enforcement.taint_decay import TaintLevel

        if self.taint_state.level <= TaintLevel.LOW:
            self.taint_state.level = TaintLevel.LOW
            self.taint_state.last_taint_event = __import__("time").time()
            if self.taint_state.last_level_change is None:
                self.taint_state.last_level_change = self.taint_state.last_taint_event

        # Record source with [trusted] suffix for audit trail
        trusted_source = f"{source_tool} [trusted]"
        if trusted_source not in self.taint_state.taint_sources:
            self.taint_state.taint_sources.append(trusted_source)

        # Record rule_id hit
        if rule_id not in self.taint_state.trusted_hits:
            self.taint_state.trusted_hits.append(rule_id)

    def check_taint_decay(self) -> None:
        """Apply time-based taint decay. Called on each pipeline check."""
        self.taint_state.apply_decay(self.taint_config)

    def record_clean_op(self) -> None:
        """Record a clean (non-sensor) operation for op-based decay."""
        self.taint_state.apply_clean_op(self.taint_config)

    def should_amber_for_taint(self) -> bool:
        """Check if current taint level warrants an amber gate."""
        return self.taint_state.should_amber(self.taint_config)

    @property
    def taint_level(self) -> TaintLevel:
        """Current graduated taint level."""
        return self.taint_state.level

    def record_state_modify(self) -> bool:
        """Record a state-modifying call. Returns True if circuit breaker trips."""
        now = time.time()
        self.state_modify_timestamps.append(now)

        # Trim old timestamps outside the window
        cutoff = now - self.config.circuit_breaker_window_seconds
        self.state_modify_timestamps = [
            t for t in self.state_modify_timestamps if t > cutoff
        ]

        # Check if breaker should trip
        if len(self.state_modify_timestamps) > self.config.circuit_breaker_max_calls:
            self.trust_state = TrustState.RED
            return True  # Breaker tripped

        return False

    def ghost_write(self, path: str, content: str | bytes) -> None:
        """Store a ghost write in the shadow VFS."""
        self.shadow_vfs[path] = content

    def ghost_read(self, path: str) -> Optional[str | bytes]:
        """Read from shadow VFS. Returns None if path not in shadow."""
        return self.shadow_vfs.get(path)

    def clear_ghost(self) -> None:
        """Clear the shadow VFS when ghost mode is toggled off."""
        self.shadow_vfs.clear()

    def ghost_status(self) -> dict:
        """Return a summary of the current ghost shadow VFS state.

        P3-10: Provides visibility into what ghost mode has buffered.
        """
        if not self.ghost_mode:
            return {
                "ghost_mode": False,
                "files_buffered": 0,
                "paths": [],
                "total_size_bytes": 0,
            }

        paths = sorted(self.shadow_vfs.keys())
        total_size = sum(
            len(v.encode("utf-8")) if isinstance(v, str) else len(v)
            for v in self.shadow_vfs.values()
        )
        return {
            "ghost_mode": True,
            "files_buffered": len(self.shadow_vfs),
            "paths": paths,
            "total_size_bytes": total_size,
        }

    def kill(self) -> None:
        """Kill the session (canary tripped or critical violation)."""
        self.killed = True
        self.trust_state = TrustState.RED

    # --- Permission Tier Management ---

    def escalate_tier(self, new_tier: PermissionTier, reason: str = "") -> bool:
        """Escalate session to a higher permission tier.

        Only allows upward escalation. Returns True if escalation happened.
        Logs the escalation for audit trail.
        """
        if new_tier <= self.permission_tier:
            return False  # Can't downgrade or stay same

        self.tier_escalation_log.append({
            "from": self.permission_tier.name,
            "to": new_tier.name,
            "reason": reason,
            "timestamp": time.time(),
        })
        self.permission_tier = new_tier
        return True

    def add_extra_tools(self, tool_names: set) -> None:
        """Add per-session tool overrides (visible regardless of tier)."""
        if self.extra_tools is None:
            self.extra_tools = set()
        self.extra_tools |= tool_names

    def demote_tier(self, new_tier: PermissionTier, reason: str = "") -> bool:
        """Demote session to a lower permission tier (security response).

        Used when trust degrades (e.g., taint + suspicious behaviour).
        """
        if new_tier >= self.permission_tier:
            return False

        self.tier_escalation_log.append({
            "from": self.permission_tier.name,
            "to": new_tier.name,
            "reason": f"DEMOTION: {reason}",
            "timestamp": time.time(),
        })
        self.permission_tier = new_tier
        return True
