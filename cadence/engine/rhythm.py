"""Rhythm Engine — EMA-based temporal state inference.

Computes per-time-of-day-bin Exponential Moving Averages of instruction
gaps and emits discrete temporal states (FLOW / READING / DEEP_WORK / AWAY).

All timestamps come from the OS clock (datetime.now(timezone.utc)).
The LLM never provides timestamps.
"""

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class TemporalState(Enum):
    FLOW = "FLOW"
    READING = "READING"
    DEEP_WORK = "DEEP_WORK"
    AWAY = "AWAY"


class TimeBin(Enum):
    MORNING = "morning"      # 06:00-12:00
    AFTERNOON = "afternoon"  # 12:00-18:00
    EVENING = "evening"      # 18:00-23:00
    NIGHT = "night"          # 23:00-06:00


# Default bin boundaries (hour of day, local time)
BIN_BOUNDARIES = {
    TimeBin.MORNING: (6, 12),
    TimeBin.AFTERNOON: (12, 18),
    TimeBin.EVENING: (18, 23),
    TimeBin.NIGHT: (23, 6),  # wraps midnight
}


@dataclass
class BinState:
    """EMA state for a single time-of-day bin."""
    ema_seconds: float = 0.0
    observation_count: int = 0

    def update(self, gap_seconds: float, alpha: float) -> None:
        """Update EMA with a new observation."""
        if self.observation_count == 0:
            self.ema_seconds = gap_seconds
        else:
            self.ema_seconds = alpha * gap_seconds + (1 - alpha) * self.ema_seconds
        self.observation_count += 1

    @property
    def is_confident(self) -> bool:
        """Whether we have enough observations for confident inference."""
        return self.observation_count >= 5

    def to_dict(self) -> dict:
        return {
            "ema_seconds": round(self.ema_seconds, 2),
            "observation_count": self.observation_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BinState":
        return cls(
            ema_seconds=d.get("ema_seconds", 0.0),
            observation_count=d.get("observation_count", 0),
        )


@dataclass
class RhythmConfig:
    """Tuneable parameters for the rhythm engine."""
    alpha: float = 0.3                   # EMA smoothing factor
    flow_threshold_seconds: float = 120  # < 2 min = FLOW
    deep_work_min_seconds: float = 900   # 15 min
    deep_work_max_seconds: float = 2700  # 45 min
    away_multiplier: float = 3.0         # gap > 3x EMA = AWAY
    reading_ema_low: float = 1.0         # gap >= 1x EMA
    reading_ema_high: float = 2.0        # gap <= 2x EMA
    reading_token_threshold: int = 200   # last agent output > 200 tokens
    min_observations: int = 5            # per bin before confident


@dataclass
class StateResult:
    """Result of a rhythm state inference."""
    state: TemporalState
    confidence: float
    ert_seconds: float
    anomaly_score: float
    bin: TimeBin
    gap_seconds: float


class RhythmEngine:
    """EMA-based rhythm engine with per-time-of-day bins."""

    def __init__(self, config: Optional[RhythmConfig] = None, utc_offset_hours: float = 0.0):
        self.config = config or RhythmConfig()
        self.utc_offset_hours = utc_offset_hours
        self.bins: dict[TimeBin, BinState] = {b: BinState() for b in TimeBin}
        self._last_event_time: Optional[datetime] = None
        self._last_out_tokens: int = 0

    def _get_bin(self, utc_time: datetime) -> TimeBin:
        """Determine time-of-day bin for a UTC timestamp."""
        local_hour = (utc_time.hour + self.utc_offset_hours) % 24
        for bin_type, (start, end) in BIN_BOUNDARIES.items():
            if bin_type == TimeBin.NIGHT:
                if local_hour >= start or local_hour < end:
                    return bin_type
            else:
                if start <= local_hour < end:
                    return bin_type
        return TimeBin.NIGHT  # fallback

    def _compute_anomaly_score(self, gap_seconds: float, bin_state: BinState) -> float:
        """How anomalous is this gap relative to the bin EMA.

        Returns 0.0 (perfectly normal) to 1.0 (extreme anomaly).
        """
        if not bin_state.is_confident or bin_state.ema_seconds <= 0:
            return 0.5  # uncertain
        ratio = gap_seconds / bin_state.ema_seconds
        # Sigmoid-like mapping: ratio=1 → ~0, ratio=3 → ~0.75, ratio=5+ → ~0.95
        score = 1.0 - (1.0 / (1.0 + (ratio - 1.0) ** 2)) if ratio > 1.0 else 0.0
        return min(1.0, max(0.0, score))

    def _compute_confidence(self, bin_state: BinState) -> float:
        """Confidence in the inferred state based on observation count."""
        if bin_state.observation_count == 0:
            return 0.1
        # Ramp from 0.3 to 0.95 over min_observations
        ratio = min(bin_state.observation_count / self.config.min_observations, 1.0)
        return 0.3 + 0.65 * ratio

    def record_event(
        self,
        direction: str,
        token_count: int,
        timestamp: Optional[datetime] = None,
    ) -> Optional[StateResult]:
        """Record an interaction event and infer temporal state.

        Args:
            direction: "in" (user message) or "out" (agent response)
            token_count: approximate token count of the message
            timestamp: UTC timestamp (defaults to now)

        Returns:
            StateResult if a state can be inferred (requires at least 2 events),
            None on the very first event.
        """
        now = timestamp or datetime.now(timezone.utc)

        if direction == "out":
            self._last_out_tokens = token_count
            self._last_event_time = now
            return None

        # direction == "in" — user message, compute gap
        if self._last_event_time is None:
            self._last_event_time = now
            return None

        gap_seconds = max(0.0, (now - self._last_event_time).total_seconds())
        current_bin = self._get_bin(now)
        bin_state = self.bins[current_bin]

        # Infer state BEFORE updating EMA — compare gap against prior norm,
        # not the norm after this gap has been absorbed.
        ert = self._compute_ert(bin_state.ema_seconds)
        state = self._infer_state(gap_seconds, ert, bin_state)
        confidence = self._compute_confidence(bin_state)
        anomaly = self._compute_anomaly_score(gap_seconds, bin_state)

        # Update EMA after inference
        bin_state.update(gap_seconds, self.config.alpha)

        self._last_event_time = now

        return StateResult(
            state=state,
            confidence=confidence,
            ert_seconds=round(ert, 2),
            anomaly_score=round(anomaly, 4),
            bin=current_bin,
            gap_seconds=round(gap_seconds, 2),
        )

    def _compute_ert(self, base_ema: float) -> float:
        """Compute Expected Response Time with Cognitive Load Offset.

        ERT stretches proportionally to how much the agent last output.
        If the agent sent a 400-line script, the user needs more reading time.
        """
        threshold = self.config.reading_token_threshold
        if self._last_out_tokens <= threshold or threshold <= 0:
            return base_ema
        # Logarithmic scaling: doubles ERT when output is 4x threshold
        ratio = self._last_out_tokens / threshold
        return base_ema * (1.0 + math.log2(ratio))

    def _infer_state(
        self,
        gap_seconds: float,
        ert_seconds: float,
        bin_state: BinState,
    ) -> TemporalState:
        """Infer temporal state from gap, ERT, and bin state."""
        cfg = self.config

        # FLOW: rapid back-and-forth
        if gap_seconds < cfg.flow_threshold_seconds:
            return TemporalState.FLOW

        # AWAY: gap far exceeds norm
        if bin_state.is_confident and gap_seconds > bin_state.ema_seconds * cfg.away_multiplier:
            return TemporalState.AWAY

        # READING: gap within normal range AND last agent output was substantial
        if self._last_out_tokens > cfg.reading_token_threshold:
            if bin_state.is_confident:
                low = bin_state.ema_seconds * cfg.reading_ema_low
                high = bin_state.ema_seconds * cfg.reading_ema_high
                if low <= gap_seconds <= high:
                    return TemporalState.READING
            elif gap_seconds <= ert_seconds * 2:
                # Cold start: if we sent a lot of tokens and gap is reasonable
                return TemporalState.READING

        # DEEP_WORK: sustained gap within expected range
        if cfg.deep_work_min_seconds <= gap_seconds <= cfg.deep_work_max_seconds:
            return TemporalState.DEEP_WORK

        # AWAY fallback for very long gaps without confident EMA
        if gap_seconds > cfg.deep_work_max_seconds:
            return TemporalState.AWAY

        # Default to FLOW for short gaps
        return TemporalState.FLOW

    def get_current_ert(self, utc_time: Optional[datetime] = None) -> float:
        """Get the current ERT for the active time bin."""
        now = utc_time or datetime.now(timezone.utc)
        current_bin = self._get_bin(now)
        base = self.bins[current_bin].ema_seconds
        return self._compute_ert(base)

    def to_dict(self) -> dict:
        """Serialize engine state for persistence."""
        return {
            "utc_offset_hours": self.utc_offset_hours,
            "bins": {b.value: self.bins[b].to_dict() for b in TimeBin},
            "last_out_tokens": self._last_out_tokens,
            "last_event_time": self._last_event_time.isoformat() if self._last_event_time else None,
        }

    @classmethod
    def from_dict(cls, d: dict, config: Optional[RhythmConfig] = None) -> "RhythmEngine":
        """Restore engine state from persistence."""
        engine = cls(config=config, utc_offset_hours=d.get("utc_offset_hours", 0.0))
        for bin_name, bin_data in d.get("bins", {}).items():
            try:
                bin_type = TimeBin(bin_name)
                engine.bins[bin_type] = BinState.from_dict(bin_data)
            except ValueError:
                pass
        engine._last_out_tokens = d.get("last_out_tokens", 0)
        ts = d.get("last_event_time")
        if ts:
            engine._last_event_time = datetime.fromisoformat(ts)
        return engine
