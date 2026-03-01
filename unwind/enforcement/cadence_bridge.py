"""Cadence Bridge — temporal anomaly detection for UNWIND (P3-11).

Reads Cadence temporal state from cadence/state.env (plain key=value file)
and detects anomalous timing patterns that suggest automated or compromised
sessions. No imports from cadence.* — reads state.env as plain text.

Detection scenarios:
    1. AWAY + machine speed: user is AWAY but tool calls arrive faster
       than human speed → possible automated session.
    2. Zero-variance timing: inter-check intervals have near-zero variance
       (coefficient of variation < threshold) → likely bot/script.
    3. READING + rapid actuators: user is READING (consuming content) but
       rapid actuator calls fire → reading shouldn't produce writes.
    4. TAINT_CLEAR bracketing: session transitions from tainted → not tainted
       after decay → write a pulse event for Cadence to consume.

Feature flag: UNWIND_CADENCE_BRIDGE=1 (off by default). When disabled,
the bridge is None in the pipeline and stage 7a is a single None check.

Fail-open: missing/corrupt state.env → bridge returns no signals.
"""

import json
import logging
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("unwind.cadence_bridge")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CadenceUserState(Enum):
    """Mirrors Cadence's TemporalState — no cadence imports."""
    FLOW = "FLOW"
    READING = "READING"
    DEEP_WORK = "DEEP_WORK"
    AWAY = "AWAY"
    UNKNOWN = "UNKNOWN"


class TemporalAnomalyType(Enum):
    """Types of temporal anomalies the bridge can detect."""
    AWAY_MACHINE_SPEED = "AWAY_MACHINE_SPEED"
    ZERO_VARIANCE = "ZERO_VARIANCE"
    READING_RAPID_ACTUATOR = "READING_RAPID_ACTUATOR"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CadenceState:
    """Parsed state.env fields. Defaults are safe (no-signal) values."""
    user_state: CadenceUserState = CadenceUserState.UNKNOWN
    anomaly_score: float = 0.0
    ert_seconds: float = 0.0
    last_direction: str = ""
    last_tokens: int = 0


@dataclass
class CadenceBridgeConfig:
    """Tuneable thresholds for each detection scenario."""

    # Scenario 1: AWAY + machine speed
    away_speed_threshold_seconds: float = 2.0    # avg inter-check < this → trigger
    away_speed_min_checks: int = 3               # need at least N checks

    # Scenario 2: Zero-variance timing
    zero_variance_cv_threshold: float = 0.05     # coefficient of variation < this → trigger
    zero_variance_min_intervals: int = 8          # need at least N intervals
    zero_variance_window_size: int = 20           # sliding window of intervals

    # Scenario 3: READING + rapid actuators
    reading_actuator_threshold_seconds: float = 3.0  # avg gap < this → trigger
    reading_actuator_min_calls: int = 3              # need at least N actuator calls
    reading_actuator_window_seconds: float = 10.0    # within this time window
    reading_actuator_min_tokens: int = 200           # LAST_TOKENS must be >= this


@dataclass
class CadenceSignal:
    """Output signal from the bridge — one per detected anomaly."""
    anomaly_type: TemporalAnomalyType
    should_amber: bool = False
    should_escalate_taint: bool = False
    taint_escalation_source: str = ""
    amber_reason: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class SessionTimingState:
    """Per-session timing tracker for the cadence bridge."""
    check_timestamps: deque = field(default_factory=lambda: deque(maxlen=25))
    actuator_timestamps: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class CadenceBridge:
    """Reads cadence/state.env and checks for temporal anomalies.

    No cadence imports. Reads state.env as plain key=value text.
    """

    def __init__(
        self,
        state_env_path: Path,
        config: Optional[CadenceBridgeConfig] = None,
        on_taint_clear: Optional[Callable[[str], None]] = None,
    ):
        self.state_env_path = state_env_path
        self.config = config or CadenceBridgeConfig()
        self.on_taint_clear = on_taint_clear
        self._session_timing: dict[str, SessionTimingState] = {}

    def _get_timing(self, session_id: str) -> SessionTimingState:
        """Get or create timing state for a session."""
        if session_id not in self._session_timing:
            self._session_timing[session_id] = SessionTimingState()
        return self._session_timing[session_id]

    # --- State reading ---

    def read_state(self) -> Optional[CadenceState]:
        """Read cadence/state.env as plain key=value file.

        Returns None if file is missing or unreadable (fail-open).
        Unknown USER_STATE values map to UNKNOWN (not an error).
        """
        try:
            text = self.state_env_path.read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError, OSError) as exc:
            logger.debug("cadence_bridge: cannot read %s: %s", self.state_env_path, exc)
            return None

        state = CadenceState()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if key == "USER_STATE":
                try:
                    state.user_state = CadenceUserState(value)
                except ValueError:
                    state.user_state = CadenceUserState.UNKNOWN
            elif key == "ANOMALY_SCORE":
                try:
                    state.anomaly_score = float(value)
                except ValueError:
                    pass
            elif key == "ERT_SECONDS":
                try:
                    state.ert_seconds = float(value)
                except ValueError:
                    pass
            elif key == "LAST_DIRECTION":
                state.last_direction = value
            elif key == "LAST_TOKENS":
                try:
                    state.last_tokens = int(value)
                except ValueError:
                    pass

        return state

    # --- Main check entry point ---

    def check(
        self,
        session_id: str,
        tool_name: str,
        tool_class: str,
        is_tainted: bool,
    ) -> list[CadenceSignal]:
        """Run all detection checks. Returns list of signals (may be empty).

        Fail-open: if state.env is missing/corrupt, returns empty list.
        """
        cadence_state = self.read_state()
        if cadence_state is None:
            return []

        now = time.time()
        timing = self._get_timing(session_id)

        # Record this check's timestamp
        timing.check_timestamps.append(now)

        # Record actuator timestamps
        if tool_class in ("actuator", "unknown_actuator"):
            timing.actuator_timestamps.append(now)

        signals: list[CadenceSignal] = []

        # Run each detection scenario
        s1 = self._check_away_machine_speed(cadence_state, timing, now)
        if s1:
            signals.append(s1)

        s2 = self._check_zero_variance(timing, now)
        if s2:
            signals.append(s2)

        s3 = self._check_reading_rapid_actuator(cadence_state, timing, now)
        if s3:
            signals.append(s3)

        return signals

    # --- Taint clear callback ---

    def check_taint_clear(
        self,
        session_id: str,
        was_tainted: bool,
        is_tainted: bool,
    ) -> None:
        """Fire callback on taint→clear transition.

        Swallows callback exceptions (best-effort pulse logging).
        """
        if was_tainted and not is_tainted and self.on_taint_clear is not None:
            try:
                self.on_taint_clear(session_id)
            except Exception as exc:
                logger.debug(
                    "cadence_bridge: on_taint_clear callback failed for %s: %s",
                    session_id, exc,
                )

    # --- Scenario 1: AWAY + machine speed ---

    def _check_away_machine_speed(
        self,
        cadence_state: CadenceState,
        timing: SessionTimingState,
        now: float,
    ) -> Optional[CadenceSignal]:
        """Scenario 1: USER_STATE=AWAY but checks arrive faster than human speed."""
        if cadence_state.user_state != CadenceUserState.AWAY:
            return None

        cfg = self.config
        timestamps = list(timing.check_timestamps)
        if len(timestamps) < cfg.away_speed_min_checks:
            return None

        # Compute average interval over last N checks
        recent = timestamps[-cfg.away_speed_min_checks:]
        intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < cfg.away_speed_threshold_seconds:
            return CadenceSignal(
                anomaly_type=TemporalAnomalyType.AWAY_MACHINE_SPEED,
                should_amber=True,
                should_escalate_taint=True,
                taint_escalation_source="cadence_bridge:away_machine_speed",
                amber_reason=(
                    f"Temporal anomaly: user is AWAY but tool calls arriving at "
                    f"machine speed (avg {avg_interval:.2f}s between checks, "
                    f"threshold {cfg.away_speed_threshold_seconds}s)"
                ),
                details={
                    "avg_interval": avg_interval,
                    "threshold": cfg.away_speed_threshold_seconds,
                    "check_count": len(timestamps),
                },
            )
        return None

    # --- Scenario 2: Zero-variance timing ---

    def _check_zero_variance(
        self,
        timing: SessionTimingState,
        now: float,
    ) -> Optional[CadenceSignal]:
        """Scenario 2: inter-check intervals have near-zero coefficient of variation."""
        cfg = self.config
        timestamps = list(timing.check_timestamps)

        # Use sliding window
        window = timestamps[-cfg.zero_variance_window_size:]
        if len(window) < cfg.zero_variance_min_intervals + 1:
            return None

        intervals = [window[i + 1] - window[i] for i in range(len(window) - 1)]
        if len(intervals) < cfg.zero_variance_min_intervals:
            return None

        mean = statistics.mean(intervals)
        if mean <= 0:
            return None

        try:
            stdev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            return None

        cv = stdev / mean  # coefficient of variation

        if cv < cfg.zero_variance_cv_threshold:
            return CadenceSignal(
                anomaly_type=TemporalAnomalyType.ZERO_VARIANCE,
                should_amber=True,
                should_escalate_taint=True,
                taint_escalation_source="cadence_bridge:zero_variance",
                amber_reason=(
                    f"Temporal anomaly: tool call timing is suspiciously regular "
                    f"(CV={cv:.4f}, threshold {cfg.zero_variance_cv_threshold}). "
                    f"Human input typically has higher variance."
                ),
                details={
                    "cv": cv,
                    "threshold": cfg.zero_variance_cv_threshold,
                    "mean_interval": mean,
                    "stdev": stdev,
                    "interval_count": len(intervals),
                },
            )
        return None

    # --- Scenario 3: READING + rapid actuators ---

    def _check_reading_rapid_actuator(
        self,
        cadence_state: CadenceState,
        timing: SessionTimingState,
        now: float,
    ) -> Optional[CadenceSignal]:
        """Scenario 3: USER_STATE=READING with rapid actuator calls."""
        if cadence_state.user_state != CadenceUserState.READING:
            return None

        cfg = self.config

        # Must have enough tokens (user is actually reading)
        if cadence_state.last_tokens < cfg.reading_actuator_min_tokens:
            return None

        # Filter actuator timestamps within the window
        cutoff = now - cfg.reading_actuator_window_seconds
        recent_actuators = [t for t in timing.actuator_timestamps if t >= cutoff]

        if len(recent_actuators) < cfg.reading_actuator_min_calls:
            return None

        # Compute average gap between actuator calls
        recent_actuators.sort()
        gaps = [
            recent_actuators[i + 1] - recent_actuators[i]
            for i in range(len(recent_actuators) - 1)
        ]
        if not gaps:
            return None

        avg_gap = sum(gaps) / len(gaps)

        if avg_gap < cfg.reading_actuator_threshold_seconds:
            return CadenceSignal(
                anomaly_type=TemporalAnomalyType.READING_RAPID_ACTUATOR,
                should_amber=True,
                should_escalate_taint=False,  # No taint escalation for this scenario
                amber_reason=(
                    f"Temporal anomaly: user is READING ({cadence_state.last_tokens} tokens) "
                    f"but rapid actuator calls detected ({len(recent_actuators)} calls "
                    f"in {cfg.reading_actuator_window_seconds}s, avg gap {avg_gap:.2f}s)"
                ),
                details={
                    "avg_gap": avg_gap,
                    "threshold": cfg.reading_actuator_threshold_seconds,
                    "actuator_count": len(recent_actuators),
                    "window_seconds": cfg.reading_actuator_window_seconds,
                    "last_tokens": cadence_state.last_tokens,
                },
            )
        return None
