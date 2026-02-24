"""Approval Windows — time-limited pre-authorisation for amber-gated operations.

When a human operator approves an amber prompt, UNWIND can issue a short-lived
"approval window" that allows similar operations to proceed without re-prompting.
This reduces approval fatigue while maintaining security controls.

Design from SENTINEL overnight spec (22 Feb 2026) + SLA policy (SENTINEL P0-3).

Risk bands and base TTLs:
    AMBER_LOW:      300s (5 min)  — low-risk tainted actuator
    AMBER_HIGH:     120s (2 min)  — elevated risk or pattern change
    AMBER_CRITICAL:   0s          — always requires explicit approval (no window)

Threat mode multipliers (SENTINEL SLA recommendation):
    NORMAL:             1.0x (base TTLs)
    ELEVATED:           0.6x (HIGH taint → compressed windows)
    ACTIVE_EXPLOITATION: 0.4x (CRITICAL taint → maximum compression)

Key constraints:
    - Windows are scoped by context_hash (tool + args shape + session)
    - HIGH windows are one-time-use (consumed on first use)
    - Freshness recheck: taint/RSS must be recomputed if stale
    - Burst auto-escalation triggers integrated with RSS machinery
    - Windows can be invalidated early by taint escalation or RSS spike

Performance: WARM path. Dict lookups + timestamp comparisons. No I/O.
Window creation/validation is off the hot enforcement path — it's called
from the approval callback, not from the main pipeline check().
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

logger = logging.getLogger("unwind.enforcement.approval_windows")


# ──────────────────────────────────────────────
# Telemetry event types and emitter
# ──────────────────────────────────────────────

class TelemetryEventType:
    """Approval window lifecycle event types (SENTINEL telemetry schema)."""
    WINDOW_CREATED = "window_created"
    WINDOW_CONSUMED = "window_consumed"
    WINDOW_INVALIDATED = "window_invalidated"
    WINDOW_EXPIRED = "window_expired"
    THREAT_MODE_CHANGED = "threat_mode_changed"
    BURST_TRIGGERED = "burst_triggered"
    FRESHNESS_REJECTED = "freshness_rejected"


@dataclass
class TelemetryEvent:
    """Structured lifecycle event for forensic tracing.

    Fields from SENTINEL's telemetry schema spec.
    """
    event_type: str
    timestamp: float
    session_id: str = ""
    window_id: str = ""
    operator_id: str = ""
    tool_name: str = ""
    risk_band: str = ""
    threat_mode: str = ""
    ttl_effective: float = 0.0
    reason: str = ""
    context_hash: str = ""
    rss_score: int = -1          # -1 = not applicable
    taint_level: str = ""
    burst_type: str = ""
    uses_remaining: int = -1     # -1 = not applicable
    dedupe_key: str = ""

    def to_dict(self) -> dict:
        """Convert to dict, omitting fields with default/empty values."""
        d = {}
        for k, v in self.__dict__.items():
            if v == "" or v == -1 or v == 0.0:
                continue
            d[k] = v
        # Always include event_type and timestamp
        d["event_type"] = self.event_type
        d["timestamp"] = self.timestamp
        return d


# Type for telemetry callback: receives a TelemetryEvent
TelemetryCallback = Callable[[TelemetryEvent], None]


def _default_telemetry_callback(event: TelemetryEvent) -> None:
    """Default: log as structured JSON to the approval_windows logger."""
    logger.info("TELEMETRY %s", event.to_dict())


class RiskBand(IntEnum):
    """Amber risk bands — determines TTL and usage constraints."""
    AMBER_LOW = 1
    AMBER_HIGH = 2
    AMBER_CRITICAL = 3


class ThreatMode(IntEnum):
    """Operational threat posture — compresses window TTLs."""
    NORMAL = 0
    ELEVATED = 1
    ACTIVE_EXPLOITATION = 2


@dataclass
class ApprovalWindowConfig:
    """Tuning knobs for approval windows.

    Defaults from SENTINEL spec v1.0 + SLA policy P0-3.
    """
    # Base TTLs per risk band (seconds)
    base_ttl_low: float = 300.0       # 5 minutes
    base_ttl_high: float = 120.0      # 2 minutes
    base_ttl_critical: float = 0.0    # No window — always prompt

    # Threat mode multipliers
    threat_multiplier_normal: float = 1.0
    threat_multiplier_elevated: float = 0.6
    threat_multiplier_active: float = 0.4

    # HIGH windows: one-time-use (consumed on first use)
    high_one_time_use: bool = True

    # Max operations per window (LOW band)
    max_ops_low_normal: int = 5       # Normal threat mode
    max_ops_low_elevated: int = 3     # Elevated threat mode

    # Freshness: max age of taint/RSS data before recheck required
    freshness_high_seconds: float = 5.0    # HIGH band: RSS/taint must be < 5s old
    freshness_low_seconds: float = 15.0    # LOW band: RSS/taint must be < 15s old

    # Burst auto-escalation triggers (integrated with RSS)
    burst_deny_retries: int = 3       # deny+variant retries in window
    burst_deny_window_seconds: float = 45.0
    burst_tainted_pivots: int = 2     # tainted high-risk pivots
    burst_pivot_window_seconds: float = 20.0
    burst_approval_prompts: int = 8   # approval prompts
    burst_prompt_window_seconds: float = 60.0

    # Auto-escalation consequences
    freeze_duration_seconds: float = 600.0   # 10 min freeze on deny burst
    quarantine_on_pivot_burst: bool = True
    disable_windows_on_prompt_burst: bool = True


@dataclass
class ApprovalWindow:
    """A time-limited pre-authorisation for a specific operation pattern.

    Scoped to a specific context: session + tool + argument shape.
    """
    window_id: str                    # Unique identifier
    session_id: str                   # Which session this window belongs to
    operator_id: str                  # Who approved it
    context_hash: str                 # Hash of (tool_name + args_shape + session_id)
    risk_band: RiskBand               # AMBER_LOW, AMBER_HIGH, AMBER_CRITICAL
    created_at: float                 # Timestamp of creation
    expires_at: float                 # Timestamp of expiry
    threat_mode: ThreatMode           # Threat posture when created

    # Usage tracking
    max_uses: int = 0                 # 0 = unlimited (within TTL)
    use_count: int = 0                # How many times this window has been used
    last_used_at: Optional[float] = None

    # State
    invalidated: bool = False         # Explicitly revoked
    invalidation_reason: str = ""

    # Freshness tracking
    last_rss_check: float = 0.0       # When RSS was last computed for this context
    last_taint_check: float = 0.0     # When taint was last checked for this context

    @property
    def is_expired(self) -> bool:
        """Check if window has passed its TTL."""
        return time.time() > self.expires_at

    @property
    def is_exhausted(self) -> bool:
        """Check if window has used all its allowed operations."""
        if self.max_uses == 0:
            return False
        return self.use_count >= self.max_uses

    @property
    def is_valid(self) -> bool:
        """Check if window can still be used."""
        return (
            not self.invalidated
            and not self.is_expired
            and not self.is_exhausted
        )

    @property
    def remaining_seconds(self) -> float:
        """Seconds until this window expires."""
        return max(0.0, self.expires_at - time.time())

    def consume(self) -> bool:
        """Use one operation from this window.

        Returns True if consumption succeeded, False if window is invalid.
        """
        if not self.is_valid:
            return False
        self.use_count += 1
        self.last_used_at = time.time()
        return True

    def invalidate(self, reason: str = "") -> None:
        """Explicitly revoke this window."""
        self.invalidated = True
        self.invalidation_reason = reason
        logger.info(
            "Window %s invalidated: %s (session=%s, uses=%d)",
            self.window_id, reason, self.session_id, self.use_count,
        )


@dataclass
class BurstTracker:
    """Tracks burst patterns for auto-escalation triggers.

    Integrates with RSS machinery rather than creating parallel detection.
    """
    # Deny + variant retries
    deny_timestamps: list[float] = field(default_factory=list)

    # Tainted high-risk pivots
    pivot_timestamps: list[float] = field(default_factory=list)

    # Approval prompts
    prompt_timestamps: list[float] = field(default_factory=list)

    # Freeze state
    frozen_until: Optional[float] = None
    freeze_reason: str = ""

    def record_deny(self) -> None:
        """Record a deny+retry event."""
        self.deny_timestamps.append(time.time())

    def record_tainted_pivot(self) -> None:
        """Record a tainted high-risk pivot."""
        self.pivot_timestamps.append(time.time())

    def record_prompt(self) -> None:
        """Record an approval prompt being shown."""
        self.prompt_timestamps.append(time.time())

    def check_burst(self, config: ApprovalWindowConfig) -> Optional[str]:
        """Check if any burst threshold is exceeded.

        Returns the escalation action string, or None if no burst detected.
        Trims old timestamps as a side effect.
        """
        now = time.time()

        # Trim old timestamps
        self.deny_timestamps = [
            t for t in self.deny_timestamps
            if now - t < config.burst_deny_window_seconds
        ]
        self.pivot_timestamps = [
            t for t in self.pivot_timestamps
            if now - t < config.burst_pivot_window_seconds
        ]
        self.prompt_timestamps = [
            t for t in self.prompt_timestamps
            if now - t < config.burst_prompt_window_seconds
        ]

        # Check thresholds
        if len(self.deny_timestamps) >= config.burst_deny_retries:
            self.frozen_until = now + config.freeze_duration_seconds
            self.freeze_reason = (
                f"Burst: {len(self.deny_timestamps)} deny+retries "
                f"in {config.burst_deny_window_seconds:.0f}s"
            )
            return "freeze_principal"

        if len(self.pivot_timestamps) >= config.burst_tainted_pivots:
            if config.quarantine_on_pivot_burst:
                return "quarantine_session"

        if len(self.prompt_timestamps) >= config.burst_approval_prompts:
            if config.disable_windows_on_prompt_burst:
                return "disable_windows"

        return None

    @property
    def is_frozen(self) -> bool:
        """Check if principal is currently frozen from burst detection."""
        if self.frozen_until is None:
            return False
        if time.time() > self.frozen_until:
            self.frozen_until = None
            self.freeze_reason = ""
            return False
        return True

    @property
    def freeze_remaining(self) -> float:
        """Seconds remaining in freeze."""
        if self.frozen_until is None:
            return 0.0
        return max(0.0, self.frozen_until - time.time())


class ApprovalWindowService:
    """Manages approval window lifecycle: create, validate, consume, invalidate.

    One instance per UNWIND proxy process. Windows are keyed by session_id
    and context_hash for fast lookup.
    """

    def __init__(
        self,
        config: Optional[ApprovalWindowConfig] = None,
        telemetry_callback: Optional[TelemetryCallback] = None,
    ):
        self.config = config or ApprovalWindowConfig()
        self._telemetry = telemetry_callback or _default_telemetry_callback
        # Active windows: session_id → {context_hash → ApprovalWindow}
        self._windows: dict[str, dict[str, ApprovalWindow]] = {}
        # Per-session burst trackers
        self._burst_trackers: dict[str, BurstTracker] = {}
        # Current threat mode (global — set by taint/threat intelligence)
        self._threat_mode: ThreatMode = ThreatMode.NORMAL
        # Window ID counter
        self._next_id: int = 0
        # Telemetry event log (for shadow mode / testing)
        self.telemetry_log: list[TelemetryEvent] = []

    def _emit(self, event: TelemetryEvent) -> None:
        """Emit a telemetry event to the callback and append to log."""
        self.telemetry_log.append(event)
        self._telemetry(event)

    @property
    def threat_mode(self) -> ThreatMode:
        return self._threat_mode

    def set_threat_mode(self, mode: ThreatMode) -> None:
        """Update the global threat posture.

        When threat mode escalates, existing windows are compressed or
        invalidated depending on their risk band.
        """
        old_mode = self._threat_mode
        self._threat_mode = mode

        if mode > old_mode:
            # Threat escalated — invalidate HIGH windows, compress LOW
            self._on_threat_escalation(old_mode, mode)

        logger.info("Threat mode changed: %s → %s", old_mode.name, mode.name)
        self._emit(TelemetryEvent(
            event_type=TelemetryEventType.THREAT_MODE_CHANGED,
            timestamp=time.time(),
            threat_mode=mode.name,
            reason=f"{old_mode.name} → {mode.name}",
        ))

    def _on_threat_escalation(
        self, old_mode: ThreatMode, new_mode: ThreatMode
    ) -> None:
        """Handle threat mode escalation — tighten existing windows."""
        for session_windows in self._windows.values():
            for window in session_windows.values():
                if window.invalidated or window.is_expired:
                    continue

                if window.risk_band == RiskBand.AMBER_HIGH:
                    # HIGH windows invalidated on threat escalation
                    window.invalidate(
                        f"Threat escalation: {old_mode.name} → {new_mode.name}"
                    )
                elif window.risk_band == RiskBand.AMBER_LOW:
                    # LOW windows: recalculate expiry with new multiplier
                    new_multiplier = self._get_threat_multiplier(new_mode)
                    original_ttl = self.config.base_ttl_low
                    new_ttl = original_ttl * new_multiplier
                    new_expires = window.created_at + new_ttl
                    if new_expires < window.expires_at:
                        window.expires_at = new_expires
                        logger.info(
                            "Window %s TTL compressed: expires in %.0fs",
                            window.window_id, window.remaining_seconds,
                        )

    def _get_threat_multiplier(self, mode: ThreatMode) -> float:
        """Get TTL multiplier for a threat mode."""
        if mode == ThreatMode.ACTIVE_EXPLOITATION:
            return self.config.threat_multiplier_active
        if mode == ThreatMode.ELEVATED:
            return self.config.threat_multiplier_elevated
        return self.config.threat_multiplier_normal

    def _get_base_ttl(self, risk_band: RiskBand) -> float:
        """Get the base TTL for a risk band."""
        if risk_band == RiskBand.AMBER_LOW:
            return self.config.base_ttl_low
        if risk_band == RiskBand.AMBER_HIGH:
            return self.config.base_ttl_high
        return self.config.base_ttl_critical  # CRITICAL = 0

    def _compute_max_uses(self, risk_band: RiskBand) -> int:
        """Compute max uses for a window based on risk band and threat mode."""
        if risk_band == RiskBand.AMBER_HIGH and self.config.high_one_time_use:
            return 1

        if risk_band == RiskBand.AMBER_LOW:
            if self._threat_mode >= ThreatMode.ELEVATED:
                return self.config.max_ops_low_elevated
            return self.config.max_ops_low_normal

        return 0  # CRITICAL: no window issued

    @staticmethod
    def compute_context_hash(
        tool_name: str,
        args_shape: str,
        session_id: str,
    ) -> str:
        """Compute the context hash that scopes an approval window.

        Args:
            tool_name: The MCP tool being approved
            args_shape: Canonical representation of argument keys/types
            session_id: The session requesting approval

        Returns:
            SHA-256 hex digest (first 16 chars for readability)
        """
        raw = f"{session_id}:{tool_name}:{args_shape}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def create_window(
        self,
        session_id: str,
        operator_id: str,
        tool_name: str,
        args_shape: str,
        risk_band: RiskBand,
    ) -> Optional[ApprovalWindow]:
        """Create a new approval window after a human approves an amber prompt.

        Returns None if the risk band doesn't allow windows (CRITICAL)
        or if the session is frozen from burst detection.

        Args:
            session_id: Which session this approval is for
            operator_id: Who approved
            tool_name: The tool being approved
            args_shape: Canonical argument shape
            risk_band: Amber risk level
        """
        # CRITICAL band never gets a window
        if risk_band == RiskBand.AMBER_CRITICAL:
            return None

        # Check burst freeze
        tracker = self._get_burst_tracker(session_id)
        if tracker.is_frozen:
            logger.warning(
                "Window creation blocked: session %s is frozen (%s)",
                session_id, tracker.freeze_reason,
            )
            return None

        context_hash = self.compute_context_hash(tool_name, args_shape, session_id)
        now = time.time()

        # Compute TTL with threat multiplier
        base_ttl = self._get_base_ttl(risk_band)
        multiplier = self._get_threat_multiplier(self._threat_mode)
        effective_ttl = base_ttl * multiplier

        if effective_ttl <= 0:
            return None

        max_uses = self._compute_max_uses(risk_band)

        # Generate window ID
        self._next_id += 1
        window_id = f"aw-{self._next_id:06d}"

        window = ApprovalWindow(
            window_id=window_id,
            session_id=session_id,
            operator_id=operator_id,
            context_hash=context_hash,
            risk_band=risk_band,
            created_at=now,
            expires_at=now + effective_ttl,
            threat_mode=self._threat_mode,
            max_uses=max_uses,
            last_rss_check=now,
            last_taint_check=now,
        )

        # Store: replace any existing window for this context
        if session_id not in self._windows:
            self._windows[session_id] = {}
        self._windows[session_id][context_hash] = window

        logger.info(
            "Window created: %s session=%s tool=%s band=%s ttl=%.0fs max_uses=%d threat=%s",
            window_id, session_id, tool_name, risk_band.name,
            effective_ttl, max_uses, self._threat_mode.name,
        )

        self._emit(TelemetryEvent(
            event_type=TelemetryEventType.WINDOW_CREATED,
            timestamp=now,
            session_id=session_id,
            window_id=window_id,
            operator_id=operator_id,
            tool_name=tool_name,
            risk_band=risk_band.name,
            threat_mode=self._threat_mode.name,
            ttl_effective=effective_ttl,
            context_hash=context_hash,
            uses_remaining=max_uses,
        ))

        return window

    def check_window(
        self,
        session_id: str,
        tool_name: str,
        args_shape: str,
        current_rss_age: float = 0.0,
        current_taint_age: float = 0.0,
    ) -> Optional[ApprovalWindow]:
        """Check if a valid approval window exists for this operation.

        Returns the window if valid and fresh, None if no window or stale.
        Does NOT consume the window — call consume_window() to do that.

        Freshness recheck: if taint/RSS data is older than the configured
        threshold, returns None to force a recompute before allowing the
        operation through the window.

        Args:
            session_id: Which session
            tool_name: The tool being called
            args_shape: Canonical argument shape
            current_rss_age: Seconds since last RSS computation
            current_taint_age: Seconds since last taint check
        """
        context_hash = self.compute_context_hash(tool_name, args_shape, session_id)
        session_windows = self._windows.get(session_id)
        if not session_windows:
            return None

        window = session_windows.get(context_hash)
        if window is None:
            return None

        if not window.is_valid:
            return None

        # Freshness recheck (SENTINEL SLA: staleness → recompute-on-stale)
        stale_reason = ""
        if window.risk_band == RiskBand.AMBER_HIGH:
            if current_rss_age > self.config.freshness_high_seconds:
                stale_reason = f"RSS age {current_rss_age:.1f}s > {self.config.freshness_high_seconds}s"
            elif current_taint_age > self.config.freshness_high_seconds:
                stale_reason = f"Taint age {current_taint_age:.1f}s > {self.config.freshness_high_seconds}s"
        elif window.risk_band == RiskBand.AMBER_LOW:
            if current_rss_age > self.config.freshness_low_seconds:
                stale_reason = f"RSS age {current_rss_age:.1f}s > {self.config.freshness_low_seconds}s"
            elif current_taint_age > self.config.freshness_low_seconds:
                stale_reason = f"Taint age {current_taint_age:.1f}s > {self.config.freshness_low_seconds}s"

        if stale_reason:
            self._emit(TelemetryEvent(
                event_type=TelemetryEventType.FRESHNESS_REJECTED,
                timestamp=time.time(),
                session_id=session_id,
                window_id=window.window_id,
                tool_name=tool_name,
                risk_band=window.risk_band.name,
                reason=stale_reason,
                context_hash=context_hash,
            ))
            return None

        return window

    def consume_window(
        self,
        session_id: str,
        tool_name: str,
        args_shape: str,
        current_rss_age: float = 0.0,
        current_taint_age: float = 0.0,
    ) -> bool:
        """Check and consume an approval window in one operation.

        Returns True if the operation is pre-approved (window consumed),
        False if no valid window exists.
        """
        window = self.check_window(
            session_id, tool_name, args_shape,
            current_rss_age, current_taint_age,
        )
        if window is None:
            return False

        consumed = window.consume()
        if consumed:
            remaining = window.max_uses - window.use_count if window.max_uses > 0 else -1
            self._emit(TelemetryEvent(
                event_type=TelemetryEventType.WINDOW_CONSUMED,
                timestamp=time.time(),
                session_id=session_id,
                window_id=window.window_id,
                tool_name=tool_name,
                risk_band=window.risk_band.name,
                threat_mode=window.threat_mode.name,
                context_hash=window.context_hash,
                uses_remaining=remaining,
            ))
        return consumed

    def invalidate_session_windows(
        self, session_id: str, reason: str = ""
    ) -> int:
        """Invalidate all windows for a session.

        Called when taint escalates, RSS spikes, or session is killed.
        Returns the number of windows invalidated.
        """
        session_windows = self._windows.get(session_id)
        if not session_windows:
            return 0

        count = 0
        effective_reason = reason or "Session windows invalidated"
        for window in session_windows.values():
            if window.is_valid:
                window.invalidate(effective_reason)
                self._emit(TelemetryEvent(
                    event_type=TelemetryEventType.WINDOW_INVALIDATED,
                    timestamp=time.time(),
                    session_id=session_id,
                    window_id=window.window_id,
                    risk_band=window.risk_band.name,
                    reason=effective_reason,
                    context_hash=window.context_hash,
                ))
                count += 1
        return count

    def invalidate_high_windows(self, session_id: str, reason: str = "") -> int:
        """Invalidate only HIGH-band windows for a session.

        Called on moderate threat escalation (keeps LOW windows alive).
        """
        session_windows = self._windows.get(session_id)
        if not session_windows:
            return 0

        count = 0
        for window in session_windows.values():
            if window.is_valid and window.risk_band == RiskBand.AMBER_HIGH:
                window.invalidate(reason or "HIGH windows invalidated")
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """Remove expired/invalidated windows. Call periodically.

        Returns number of windows cleaned up.
        """
        count = 0
        empty_sessions = []

        for session_id, session_windows in self._windows.items():
            expired_keys = [
                ctx for ctx, w in session_windows.items()
                if not w.is_valid
            ]
            for key in expired_keys:
                del session_windows[key]
                count += 1

            if not session_windows:
                empty_sessions.append(session_id)

        for sid in empty_sessions:
            del self._windows[sid]

        return count

    # --- Burst tracking (integrated with RSS) ---

    def _get_burst_tracker(self, session_id: str) -> BurstTracker:
        """Get or create a burst tracker for a session."""
        if session_id not in self._burst_trackers:
            self._burst_trackers[session_id] = BurstTracker()
        return self._burst_trackers[session_id]

    def record_deny_retry(self, session_id: str) -> Optional[str]:
        """Record a deny+retry event and check for burst escalation.

        Returns escalation action if threshold exceeded, None otherwise.
        """
        tracker = self._get_burst_tracker(session_id)
        tracker.record_deny()
        action = tracker.check_burst(self.config)
        if action:
            self._emit(TelemetryEvent(
                event_type=TelemetryEventType.BURST_TRIGGERED,
                timestamp=time.time(),
                session_id=session_id,
                burst_type="deny_retry",
                reason=f"Action: {action}",
            ))
        if action == "freeze_principal":
            self.invalidate_session_windows(
                session_id, "Burst freeze: deny+retry threshold exceeded"
            )
        return action

    def record_tainted_pivot(self, session_id: str) -> Optional[str]:
        """Record a tainted high-risk pivot and check for burst escalation."""
        tracker = self._get_burst_tracker(session_id)
        tracker.record_tainted_pivot()
        action = tracker.check_burst(self.config)
        if action:
            self._emit(TelemetryEvent(
                event_type=TelemetryEventType.BURST_TRIGGERED,
                timestamp=time.time(),
                session_id=session_id,
                burst_type="tainted_pivot",
                reason=f"Action: {action}",
            ))
        if action == "quarantine_session":
            self.invalidate_session_windows(
                session_id, "Burst quarantine: tainted pivot threshold exceeded"
            )
        return action

    def record_approval_prompt(self, session_id: str) -> Optional[str]:
        """Record an approval prompt being shown and check for burst."""
        tracker = self._get_burst_tracker(session_id)
        tracker.record_prompt()
        action = tracker.check_burst(self.config)
        if action:
            self._emit(TelemetryEvent(
                event_type=TelemetryEventType.BURST_TRIGGERED,
                timestamp=time.time(),
                session_id=session_id,
                burst_type="approval_prompt",
                reason=f"Action: {action}",
            ))
        if action == "disable_windows":
            self.invalidate_session_windows(
                session_id, "Burst: approval prompt threshold exceeded"
            )
        return action

    def is_session_frozen(self, session_id: str) -> bool:
        """Check if a session's principal is frozen from burst detection."""
        tracker = self._burst_trackers.get(session_id)
        if tracker is None:
            return False
        return tracker.is_frozen

    def get_freeze_remaining(self, session_id: str) -> float:
        """Get seconds remaining in a session's freeze."""
        tracker = self._burst_trackers.get(session_id)
        if tracker is None:
            return 0.0
        return tracker.freeze_remaining

    # --- Query/audit methods ---

    def active_window_count(self, session_id: Optional[str] = None) -> int:
        """Count active (valid) windows, optionally filtered by session."""
        count = 0
        sessions = (
            {session_id: self._windows.get(session_id, {})}
            if session_id
            else self._windows
        )
        for session_windows in sessions.values():
            count += sum(1 for w in session_windows.values() if w.is_valid)
        return count

    def get_window(
        self, session_id: str, tool_name: str, args_shape: str
    ) -> Optional[ApprovalWindow]:
        """Get a specific window by context (for inspection/audit)."""
        context_hash = self.compute_context_hash(tool_name, args_shape, session_id)
        session_windows = self._windows.get(session_id)
        if not session_windows:
            return None
        return session_windows.get(context_hash)

    def summary(self, session_id: Optional[str] = None) -> dict:
        """Return audit summary of window state."""
        if session_id:
            windows = self._windows.get(session_id, {})
            tracker = self._burst_trackers.get(session_id)
            return {
                "session_id": session_id,
                "active_windows": sum(
                    1 for w in windows.values() if w.is_valid
                ),
                "total_windows": len(windows),
                "threat_mode": self._threat_mode.name,
                "is_frozen": tracker.is_frozen if tracker else False,
                "freeze_remaining": (
                    tracker.freeze_remaining if tracker else 0.0
                ),
            }
        return {
            "total_sessions": len(self._windows),
            "total_active_windows": self.active_window_count(),
            "threat_mode": self._threat_mode.name,
        }
