"""Graduated taint decay — reduces amber fatigue while preserving security.

Instead of binary taint (on/off), taint has levels that decay over time and
through clean operations. Only elevated taint levels trigger amber gates,
reducing false positives while maintaining protection against genuine threats.

Taint levels (in order of severity):
    NONE     → No taint. All clear.
    LOW      → Recently decayed. Logged but no gate.
    MEDIUM   → Moderate taint. Logged, risk score tracked.
    HIGH     → Elevated. Triggers amber on high-risk actuators.
    CRITICAL → Maximum. Triggers amber on ALL actuators.

Decay mechanics:
    - Time decay: taint drops one level every `decay_interval_seconds`
    - Operation decay: every `clean_ops_per_decay` clean ops drops one level
    - Re-taint escalation: each sensor call raises taint by one level
    - Multiple rapid sensor calls ratchet to CRITICAL
    - Decay is checked lazily on each pipeline call (no background threads)

Performance: HOT path. All operations are comparisons + counter increments.
No I/O, no locks, no allocations on the fast path.
"""

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class TaintLevel(IntEnum):
    """Graduated taint levels. IntEnum so comparisons are natural."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# The amber threshold: taint at or above this level triggers amber gates
AMBER_TAINT_THRESHOLD = TaintLevel.HIGH


@dataclass
class TaintDecayConfig:
    """Tuning knobs for taint decay behaviour."""

    # Time-based decay: drop one level every N seconds of no new taint
    decay_interval_seconds: float = 60.0  # 1 minute per level

    # Operation-based decay: drop one level every N clean operations
    clean_ops_per_decay: int = 10

    # Re-taint cooldown: ignore duplicate sensor calls within N seconds
    # (prevents a single search_web + 5 result fetches from hitting CRITICAL)
    retaint_cooldown_seconds: float = 5.0

    # Maximum taint level that a single sensor call can set
    # (CRITICAL requires 2+ distinct taint events)
    single_event_max: TaintLevel = TaintLevel.HIGH

    # Amber threshold: taint at or above this triggers amber gates
    amber_threshold: TaintLevel = TaintLevel.HIGH


@dataclass
class TaintState:
    """Per-session graduated taint state. Replaces the old boolean is_tainted."""

    level: TaintLevel = TaintLevel.NONE

    # Timestamps
    last_taint_event: Optional[float] = None   # When taint was last raised
    last_decay_check: Optional[float] = None    # When we last evaluated decay
    last_level_change: Optional[float] = None   # When level last changed

    # Clean operation counter (resets on each taint event)
    clean_ops_since_taint: int = 0

    # History for detecting rapid taint escalation
    taint_event_count: int = 0  # Total taint events in current elevated period
    taint_sources: list[str] = field(default_factory=list)  # Tool names that caused taint

    def apply_taint(self, source_tool: str, config: TaintDecayConfig) -> TaintLevel:
        """Apply a new taint event. Returns the new taint level.

        Escalation rules:
        - From NONE: jump to MEDIUM (not LOW — LOW is for decay-down only)
        - From LOW/MEDIUM: raise by one level
        - From HIGH: raise to CRITICAL only if last taint was > cooldown ago
        - From CRITICAL: stays CRITICAL, refreshes timestamp
        """
        now = time.time()

        # Check cooldown — prevent rapid duplicate sensor calls from over-escalating
        if (
            self.last_taint_event is not None
            and (now - self.last_taint_event) < config.retaint_cooldown_seconds
            and self.level >= TaintLevel.MEDIUM
        ):
            # Within cooldown: refresh timestamp but don't escalate
            self.last_taint_event = now
            if source_tool not in self.taint_sources:
                self.taint_sources.append(source_tool)
            return self.level

        # Reset clean ops counter
        self.clean_ops_since_taint = 0
        self.taint_event_count += 1

        # Track source
        if source_tool not in self.taint_sources:
            self.taint_sources.append(source_tool)

        # Escalate
        old_level = self.level
        if self.level == TaintLevel.NONE:
            self.level = TaintLevel.MEDIUM  # Skip LOW on taint-up
        elif self.level < config.single_event_max:
            self.level = TaintLevel(min(self.level + 1, config.single_event_max))
        elif self.level == TaintLevel.HIGH and self.taint_event_count >= 2:
            # CRITICAL requires multiple distinct taint events
            self.level = TaintLevel.CRITICAL
        # CRITICAL stays CRITICAL

        self.last_taint_event = now
        if self.level != old_level:
            self.last_level_change = now

        return self.level

    def apply_decay(self, config: TaintDecayConfig) -> TaintLevel:
        """Check and apply time-based decay. Called lazily on each pipeline check.

        Returns the new taint level after decay (may be unchanged).
        """
        if self.level == TaintLevel.NONE:
            return self.level

        now = time.time()
        reference_time = self.last_taint_event or self.last_level_change or now

        elapsed = now - reference_time
        if elapsed <= 0:
            return self.level

        # How many levels should we decay based on time?
        if config.decay_interval_seconds <= 0:
            # Misconfiguration guard — zero interval = instant decay to NONE
            time_levels = int(self.level)
        else:
            time_levels = int(elapsed / config.decay_interval_seconds)
        if time_levels <= 0:
            return self.level

        old_level = self.level
        new_level_val = max(0, self.level - time_levels)
        self.level = TaintLevel(new_level_val)

        if self.level != old_level:
            self.last_level_change = now
            self.last_decay_check = now

        # If fully decayed, reset all state
        if self.level == TaintLevel.NONE:
            self._reset()

        return self.level

    def apply_clean_op(self, config: TaintDecayConfig) -> TaintLevel:
        """Record a clean (non-sensor) operation and check op-based decay.

        Returns the new taint level after any decay.
        """
        if self.level == TaintLevel.NONE:
            return self.level

        self.clean_ops_since_taint += 1

        if self.clean_ops_since_taint >= config.clean_ops_per_decay:
            old_level = self.level
            new_level_val = max(0, self.level - 1)
            self.level = TaintLevel(new_level_val)
            self.clean_ops_since_taint = 0

            if self.level != old_level:
                self.last_level_change = time.time()

            if self.level == TaintLevel.NONE:
                self._reset()

        return self.level

    def should_amber(self, config: TaintDecayConfig) -> bool:
        """Check if current taint level should trigger an amber gate."""
        return self.level >= config.amber_threshold

    def _reset(self) -> None:
        """Reset all taint state when fully decayed."""
        self.last_taint_event = None
        self.last_level_change = None
        self.clean_ops_since_taint = 0
        self.taint_event_count = 0
        self.taint_sources.clear()

    @property
    def is_tainted(self) -> bool:
        """Backwards compatibility: any level above NONE is 'tainted'."""
        return self.level > TaintLevel.NONE

    @property
    def amber_worthy(self) -> bool:
        """Quick check: is taint high enough for amber gates?"""
        return self.level >= AMBER_TAINT_THRESHOLD

    def summary(self) -> dict:
        """Return a dict summary for logging/audit."""
        return {
            "level": self.level.name,
            "level_value": int(self.level),
            "is_tainted": self.is_tainted,
            "amber_worthy": self.amber_worthy,
            "clean_ops": self.clean_ops_since_taint,
            "taint_events": self.taint_event_count,
            "sources": list(self.taint_sources),
        }
