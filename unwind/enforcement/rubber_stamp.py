"""Rubber-stamp detection — catches humans who approve without reading.

Implements SENTINEL's RSS (Rubber-Stamp Score) formula to detect when
an operator is approving amber prompts too quickly, too consistently,
or without engaging with the risk information presented.

RSS formula (SENTINEL spec v1.0):
    RSS = clamp(0, 100,
        30 * I(latency < 2s)
      + 15 * I(latency < 1s)
      + 20 * I(streak >= 12)
      + 15 * I(approve_ratio > 0.98 over last 50)
      + 20 * I(pattern_changed_but_approved)
      + 10 * I(burst >= 8 in 60s)
    )

Where I(condition) is a 0/1 indicator function.

RSS action thresholds:
    0-34:  No friction (normal approval flow)
    35-54: Medium — require reason code, show condensed risk delta
    55-74: High — force expanded diff view, 5s hold before approve, disable low windows
    75+:   Very high — disable all approval windows 10m, require step-up, notify SOC

Performance: HOT path. All operations are comparisons against in-memory
counters. No I/O, no allocations on fast path.
"""

import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class RSSLevel(IntEnum):
    """Rubber-stamp severity levels."""
    NONE = 0
    MEDIUM = 1
    HIGH = 2
    VERY_HIGH = 3


@dataclass
class RubberStampConfig:
    """Tuning knobs — defaults from SENTINEL's scoring schema v1.0."""

    # Latency thresholds
    fast_approve_seconds: float = 2.0
    severe_fast_approve_seconds: float = 1.0

    # Streak detection
    consecutive_approve_streak: int = 12

    # Ratio detection
    ratio_window_size: int = 50
    ratio_alert_threshold: float = 0.98

    # Burst detection
    burst_window_seconds: float = 60.0
    burst_count: int = 8

    # RSS action thresholds
    rss_medium_min: int = 35
    rss_high_min: int = 55
    rss_very_high_min: int = 75

    # Cooldown: how long "very high" disables approval windows
    very_high_lockout_seconds: float = 600.0  # 10 minutes

    # Hold time injected at HIGH level
    high_hold_seconds: float = 5.0


@dataclass
class ApprovalRecord:
    """Single approval/rejection event."""
    timestamp: float
    approved: bool
    latency_seconds: float  # Time between prompt shown and decision made
    pattern_hash: str = ""  # Hash of the operation pattern (tool + args shape)
    amber_tier: str = ""    # AMBER_LOW, AMBER_HIGH, AMBER_CRITICAL


@dataclass
class RubberStampState:
    """Per-operator rubber-stamp tracking state.

    Tracks approval behaviour to detect rubber-stamping patterns.
    One instance per human operator (not per session — an operator
    may be approving across multiple sessions).
    """

    # Sliding window of recent decisions (capped at ratio_window_size)
    decisions: deque = field(default_factory=lambda: deque(maxlen=50))

    # Current consecutive approve streak
    approve_streak: int = 0

    # Burst tracking: timestamps of approvals in current burst window
    burst_timestamps: list[float] = field(default_factory=list)

    # Pattern tracking: detect when operator approves a changed pattern
    last_approved_pattern: str = ""
    pattern_changed_on_last_approve: bool = False

    # Lockout state
    lockout_until: Optional[float] = None  # Timestamp when lockout expires

    # Running stats
    total_approvals: int = 0
    total_rejections: int = 0
    total_rss_checks: int = 0
    peak_rss: int = 0

    def record_decision(
        self,
        approved: bool,
        latency_seconds: float,
        pattern_hash: str = "",
        amber_tier: str = "",
    ) -> None:
        """Record an approval/rejection decision."""
        now = time.time()
        record = ApprovalRecord(
            timestamp=now,
            approved=approved,
            latency_seconds=latency_seconds,
            pattern_hash=pattern_hash,
            amber_tier=amber_tier,
        )
        self.decisions.append(record)

        if approved:
            self.total_approvals += 1
            self.approve_streak += 1
            self.burst_timestamps.append(now)
            # Detect pattern change BEFORE updating last_approved_pattern
            self.pattern_changed_on_last_approve = (
                bool(pattern_hash)
                and bool(self.last_approved_pattern)
                and pattern_hash != self.last_approved_pattern
            )
            self.last_approved_pattern = pattern_hash
        else:
            self.total_rejections += 1
            self.approve_streak = 0  # Any rejection breaks the streak

        # Trim burst window
        cutoff = now - 60.0  # hardcoded 60s for burst window cleanup
        self.burst_timestamps = [t for t in self.burst_timestamps if t > cutoff]

    def compute_rss(
        self,
        latest_latency: float,
        latest_pattern_hash: str,
        config: RubberStampConfig,
    ) -> int:
        """Compute the Rubber-Stamp Score for the latest decision.

        Returns an integer 0-100.
        """
        self.total_rss_checks += 1
        score = 0

        # 1. Fast approval (30 points)
        if latest_latency < config.fast_approve_seconds:
            score += 30

        # 2. Very fast approval (additional 15 points)
        if latest_latency < config.severe_fast_approve_seconds:
            score += 15

        # 3. Consecutive approve streak (20 points)
        if self.approve_streak >= config.consecutive_approve_streak:
            score += 20

        # 4. Approve ratio over window (15 points)
        if len(self.decisions) >= config.ratio_window_size:
            approvals = sum(1 for d in self.decisions if d.approved)
            ratio = approvals / len(self.decisions)
            if ratio > config.ratio_alert_threshold:
                score += 15

        # 5. Pattern changed but still approved (20 points)
        if self.pattern_changed_on_last_approve:
            score += 20

        # 6. Burst approvals (10 points)
        now = time.time()
        cutoff = now - config.burst_window_seconds
        recent_bursts = sum(1 for t in self.burst_timestamps if t > cutoff)
        if recent_bursts >= config.burst_count:
            score += 10

        # Clamp
        score = max(0, min(100, score))
        self.peak_rss = max(self.peak_rss, score)

        return score

    def get_rss_level(self, rss_score: int, config: RubberStampConfig) -> RSSLevel:
        """Map RSS score to action level."""
        if rss_score >= config.rss_very_high_min:
            return RSSLevel.VERY_HIGH
        if rss_score >= config.rss_high_min:
            return RSSLevel.HIGH
        if rss_score >= config.rss_medium_min:
            return RSSLevel.MEDIUM
        return RSSLevel.NONE

    def apply_rss_actions(self, rss_score: int, config: RubberStampConfig) -> dict:
        """Determine what friction actions to apply based on RSS score.

        Returns a dict describing the required friction:
            - level: RSSLevel
            - actions: list of action strings
            - hold_seconds: forced delay before approve button is active
            - windows_disabled: whether approval windows should be disabled
            - lockout_until: timestamp when lockout expires (if applicable)
        """
        level = self.get_rss_level(rss_score, config)
        result = {
            "level": level,
            "rss_score": rss_score,
            "actions": [],
            "hold_seconds": 0.0,
            "windows_disabled": False,
            "lockout_until": None,
        }

        if level == RSSLevel.NONE:
            return result

        if level >= RSSLevel.MEDIUM:
            result["actions"].extend([
                "require_reason_code",
                "show_condensed_risk_delta",
            ])

        if level >= RSSLevel.HIGH:
            result["actions"].extend([
                "force_expanded_diff_view",
                "disable_low_window_auto_issue",
            ])
            result["hold_seconds"] = config.high_hold_seconds

        if level >= RSSLevel.VERY_HIGH:
            now = time.time()
            self.lockout_until = now + config.very_high_lockout_seconds
            result["actions"].extend([
                "disable_all_approval_windows",
                "require_step_up_for_high_and_critical",
                "notify_soc",
            ])
            result["windows_disabled"] = True
            result["lockout_until"] = self.lockout_until

        return result

    def is_locked_out(self) -> bool:
        """Check if operator is currently in lockout (windows disabled)."""
        if self.lockout_until is None:
            return False
        if time.time() > self.lockout_until:
            self.lockout_until = None
            return False
        return True

    def clear_lockout(self) -> None:
        """Manually clear lockout (admin override)."""
        self.lockout_until = None

    def reset(self) -> None:
        """Full reset (new operator session)."""
        self.decisions.clear()
        self.approve_streak = 0
        self.burst_timestamps.clear()
        self.last_approved_pattern = ""
        self.pattern_changed_on_last_approve = False
        self.lockout_until = None
        self.total_approvals = 0
        self.total_rejections = 0

    @property
    def approve_ratio(self) -> float:
        """Current approve ratio over the decision window."""
        if not self.decisions:
            return 0.0
        return sum(1 for d in self.decisions if d.approved) / len(self.decisions)

    def summary(self) -> dict:
        """Return a dict summary for logging/audit."""
        return {
            "approve_streak": self.approve_streak,
            "approve_ratio": round(self.approve_ratio, 3),
            "total_approvals": self.total_approvals,
            "total_rejections": self.total_rejections,
            "decisions_in_window": len(self.decisions),
            "burst_count": len(self.burst_timestamps),
            "is_locked_out": self.is_locked_out(),
            "peak_rss": self.peak_rss,
        }
