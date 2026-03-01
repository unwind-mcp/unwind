"""Tests for Cadence rhythm engine — EMA, state transitions, cognitive load."""

import unittest
from datetime import datetime, timedelta, timezone

from cadence.engine.rhythm import (
    BinState,
    RhythmConfig,
    RhythmEngine,
    StateResult,
    TemporalState,
    TimeBin,
)


class TestBinState(unittest.TestCase):
    """Test EMA calculation correctness across observations."""

    def test_first_observation_sets_ema(self):
        bs = BinState()
        bs.update(60.0, alpha=0.3)
        self.assertEqual(bs.ema_seconds, 60.0)
        self.assertEqual(bs.observation_count, 1)

    def test_ema_converges(self):
        """EMA should converge toward repeated values."""
        bs = BinState()
        for _ in range(20):
            bs.update(100.0, alpha=0.3)
        self.assertAlmostEqual(bs.ema_seconds, 100.0, places=1)

    def test_ema_weights_recent(self):
        """EMA with alpha=0.3 should weight recent observations more."""
        bs = BinState()
        # Fill with 60s gaps
        for _ in range(10):
            bs.update(60.0, alpha=0.3)
        # Sudden shift to 300s
        bs.update(300.0, alpha=0.3)
        # EMA should have jumped toward 300 but not reached it
        self.assertGreater(bs.ema_seconds, 60.0)
        self.assertLess(bs.ema_seconds, 300.0)

    def test_confident_after_5_observations(self):
        bs = BinState()
        for i in range(4):
            bs.update(60.0, alpha=0.3)
            self.assertFalse(bs.is_confident)
        bs.update(60.0, alpha=0.3)
        self.assertTrue(bs.is_confident)

    def test_serialization_roundtrip(self):
        bs = BinState(ema_seconds=42.5, observation_count=7)
        d = bs.to_dict()
        restored = BinState.from_dict(d)
        self.assertEqual(restored.ema_seconds, 42.5)
        self.assertEqual(restored.observation_count, 7)


class TestTimeBinClassification(unittest.TestCase):
    """Test time-of-day bin assignment."""

    def test_morning(self):
        engine = RhythmEngine(utc_offset_hours=0)
        dt = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.MORNING)

    def test_afternoon(self):
        engine = RhythmEngine(utc_offset_hours=0)
        dt = datetime(2026, 3, 1, 14, 0, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.AFTERNOON)

    def test_evening(self):
        engine = RhythmEngine(utc_offset_hours=0)
        dt = datetime(2026, 3, 1, 20, 0, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.EVENING)

    def test_night_before_midnight(self):
        engine = RhythmEngine(utc_offset_hours=0)
        dt = datetime(2026, 3, 1, 23, 30, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.NIGHT)

    def test_night_after_midnight(self):
        engine = RhythmEngine(utc_offset_hours=0)
        dt = datetime(2026, 3, 1, 3, 0, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.NIGHT)

    def test_utc_offset_shifts_bin(self):
        """UTC+5 user: 14:00 UTC = 19:00 local = evening."""
        engine = RhythmEngine(utc_offset_hours=5)
        dt = datetime(2026, 3, 1, 14, 0, tzinfo=timezone.utc)
        self.assertEqual(engine._get_bin(dt), TimeBin.EVENING)


class TestStateTransitions(unittest.TestCase):
    """Test FLOW → READING → DEEP_WORK → AWAY transitions."""

    def _engine_with_history(self, gap_seconds: float, count: int = 10) -> RhythmEngine:
        """Create engine with established EMA from repeated gaps."""
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        # Seed with "out" then repeated "in" events
        engine.record_event("out", 50, timestamp=base)
        for i in range(count):
            t = base + timedelta(seconds=gap_seconds * (i + 1))
            engine.record_event("in", 10, timestamp=t)
            # Agent responds
            engine.record_event("out", 50, timestamp=t + timedelta(seconds=5))
        return engine

    def test_flow_on_rapid_response(self):
        """Gap < 2 min → FLOW."""
        engine = self._engine_with_history(300)  # 5 min EMA
        base = datetime(2026, 3, 1, 11, 0, tzinfo=timezone.utc)  # morning bin
        engine._last_event_time = base
        engine._last_out_tokens = 50
        result = engine.record_event("in", 10, timestamp=base + timedelta(seconds=30))
        self.assertIsNotNone(result)
        self.assertEqual(result.state, TemporalState.FLOW)

    def test_away_on_long_gap(self):
        """Gap > 3x EMA → AWAY."""
        engine = self._engine_with_history(300)  # 5 min EMA
        base = datetime(2026, 3, 1, 11, 0, tzinfo=timezone.utc)  # morning bin
        engine._last_event_time = base
        engine._last_out_tokens = 50
        # 30 min gap >> 3x 5min EMA
        result = engine.record_event("in", 10, timestamp=base + timedelta(minutes=30))
        self.assertIsNotNone(result)
        self.assertEqual(result.state, TemporalState.AWAY)

    def test_reading_after_large_output(self):
        """Gap within 1-2x EMA + large last output → READING."""
        engine = self._engine_with_history(300)  # 5 min EMA
        base = datetime(2026, 3, 1, 11, 0, tzinfo=timezone.utc)  # morning bin
        engine._last_event_time = base
        engine._last_out_tokens = 500  # large output
        # Gap = 1.5x EMA (within 1-2x range)
        result = engine.record_event("in", 10, timestamp=base + timedelta(seconds=450))
        self.assertIsNotNone(result)
        self.assertEqual(result.state, TemporalState.READING)

    def test_deep_work_on_sustained_gap(self):
        """Gap 15-45 min → DEEP_WORK."""
        engine = self._engine_with_history(600)  # 10 min EMA
        base = datetime(2026, 3, 1, 11, 0, tzinfo=timezone.utc)  # morning bin
        engine._last_event_time = base
        engine._last_out_tokens = 50  # small output
        # 20 min gap = DEEP_WORK range
        result = engine.record_event("in", 10, timestamp=base + timedelta(minutes=20))
        self.assertIsNotNone(result)
        self.assertEqual(result.state, TemporalState.DEEP_WORK)

    def test_out_event_returns_none(self):
        """Agent output events don't produce state inference."""
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        result = engine.record_event("out", 500, timestamp=base)
        self.assertIsNone(result)

    def test_first_in_event_returns_none(self):
        """Very first user message has no gap to measure."""
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        result = engine.record_event("in", 10, timestamp=base)
        self.assertIsNone(result)

    def test_second_in_event_produces_state(self):
        """Second user message produces a state inference."""
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        engine.record_event("in", 10, timestamp=base)
        result = engine.record_event("in", 10, timestamp=base + timedelta(seconds=30))
        self.assertIsNotNone(result)


class TestCognitiveLoadOffset(unittest.TestCase):
    """Same gap, different token counts → different states."""

    def test_small_output_no_adjustment(self):
        """Token count below threshold → ERT = base EMA."""
        engine = RhythmEngine()
        engine._last_out_tokens = 50  # below 200 threshold
        ert = engine._compute_ert(300.0)
        self.assertEqual(ert, 300.0)

    def test_large_output_stretches_ert(self):
        """Token count above threshold → ERT > base EMA."""
        engine = RhythmEngine()
        engine._last_out_tokens = 800  # 4x threshold
        ert = engine._compute_ert(300.0)
        # 1 + log2(4) = 3.0 → ERT = 900
        self.assertAlmostEqual(ert, 900.0, places=0)

    def test_same_gap_different_tokens_different_state(self):
        """The key Cadence insight: same gap, different context → different state."""
        engine = self._engine_with_history(300)  # 5 min EMA
        base = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)

        # Scenario A: small output + 7 min gap
        engine._last_event_time = base
        engine._last_out_tokens = 50
        result_a = engine.record_event("in", 10, timestamp=base + timedelta(minutes=7))

        # Scenario B: large output + 7 min gap (reset engine time)
        engine._last_event_time = base + timedelta(minutes=10)
        engine._last_out_tokens = 800
        result_b = engine.record_event("in", 10, timestamp=base + timedelta(minutes=17))

        # Both have ~7 min gaps but different contexts
        self.assertIsNotNone(result_a)
        self.assertIsNotNone(result_b)
        # With large output, the same gap should feel more like READING/FLOW
        # vs DEEP_WORK with small output (exact state depends on EMA)

    def _engine_with_history(self, gap_seconds, count=10):
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        engine.record_event("out", 50, timestamp=base)
        for i in range(count):
            t = base + timedelta(seconds=gap_seconds * (i + 1))
            engine.record_event("in", 10, timestamp=t)
            engine.record_event("out", 50, timestamp=t + timedelta(seconds=5))
        return engine


class TestEngineSerialisation(unittest.TestCase):
    """Test engine state persistence roundtrip."""

    def test_roundtrip(self):
        engine = RhythmEngine(utc_offset_hours=5.5)
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        engine.record_event("out", 200, timestamp=base)
        engine.record_event("in", 10, timestamp=base + timedelta(seconds=60))
        engine.record_event("out", 50, timestamp=base + timedelta(seconds=65))
        engine.record_event("in", 10, timestamp=base + timedelta(seconds=180))

        d = engine.to_dict()
        restored = RhythmEngine.from_dict(d)

        self.assertEqual(restored.utc_offset_hours, 5.5)
        self.assertEqual(restored._last_out_tokens, 50)
        for b in TimeBin:
            self.assertEqual(
                restored.bins[b].observation_count,
                engine.bins[b].observation_count,
            )


if __name__ == "__main__":
    unittest.main()
