"""Tests for graduated taint decay system.

Covers:
- TaintLevel ordering and comparisons
- TaintState escalation mechanics
- Time-based decay
- Operation-based decay
- Cooldown behaviour
- Amber threshold checking
- Edge cases and boundary conditions
- Integration with pipeline taint check
"""

import time
from unittest.mock import patch

import pytest

from unwind.enforcement.taint_decay import (
    AMBER_TAINT_THRESHOLD,
    TaintDecayConfig,
    TaintLevel,
    TaintState,
)


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def config():
    """Default decay config for tests (dwell=0 for pre-P2-8 compat)."""
    return TaintDecayConfig(
        decay_interval_seconds=60.0,
        clean_ops_per_decay=10,
        retaint_cooldown_seconds=5.0,
        single_event_max=TaintLevel.HIGH,
        amber_threshold=TaintLevel.HIGH,
        min_dwell_seconds=0.0,  # Disabled for existing tests
    )


@pytest.fixture
def fast_config():
    """Fast-decay config for time-based tests."""
    return TaintDecayConfig(
        decay_interval_seconds=1.0,
        clean_ops_per_decay=3,
        retaint_cooldown_seconds=0.1,
        single_event_max=TaintLevel.HIGH,
        amber_threshold=TaintLevel.HIGH,
        min_dwell_seconds=0.0,  # Disabled for existing tests
    )


@pytest.fixture
def state():
    """Fresh taint state."""
    return TaintState()


# ─────────────────────────────────────────────────────
# TaintLevel tests
# ─────────────────────────────────────────────────────

class TestTaintLevel:
    def test_ordering(self):
        assert TaintLevel.NONE < TaintLevel.LOW < TaintLevel.MEDIUM < TaintLevel.HIGH < TaintLevel.CRITICAL

    def test_int_values(self):
        assert int(TaintLevel.NONE) == 0
        assert int(TaintLevel.CRITICAL) == 4

    def test_comparison_with_threshold(self):
        assert TaintLevel.HIGH >= AMBER_TAINT_THRESHOLD
        assert TaintLevel.CRITICAL >= AMBER_TAINT_THRESHOLD
        assert TaintLevel.MEDIUM < AMBER_TAINT_THRESHOLD
        assert TaintLevel.LOW < AMBER_TAINT_THRESHOLD

    def test_constructable_from_int(self):
        assert TaintLevel(0) == TaintLevel.NONE
        assert TaintLevel(4) == TaintLevel.CRITICAL


# ─────────────────────────────────────────────────────
# Fresh state tests
# ─────────────────────────────────────────────────────

class TestFreshState:
    def test_starts_at_none(self, state):
        assert state.level == TaintLevel.NONE
        assert not state.is_tainted
        assert not state.amber_worthy

    def test_no_decay_needed(self, state, config):
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE

    def test_clean_op_on_fresh_is_noop(self, state, config):
        result = state.apply_clean_op(config)
        assert result == TaintLevel.NONE

    def test_summary_clean(self, state):
        s = state.summary()
        assert s["level"] == "NONE"
        assert s["is_tainted"] is False
        assert s["amber_worthy"] is False
        assert s["taint_events"] == 0


# ─────────────────────────────────────────────────────
# Taint escalation tests
# ─────────────────────────────────────────────────────

class TestTaintEscalation:
    def test_first_taint_jumps_to_medium(self, state, config):
        """First taint event should skip LOW and go to MEDIUM."""
        result = state.apply_taint("search_web", config)
        assert result == TaintLevel.MEDIUM
        assert state.is_tainted
        assert not state.amber_worthy  # MEDIUM < HIGH

    def test_second_taint_raises_to_high(self, state, config):
        """Second taint event (after cooldown) should raise to HIGH."""
        state.apply_taint("search_web", config)
        # Move past cooldown
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        result = state.apply_taint("fetch_url", config)
        assert result == TaintLevel.HIGH
        assert state.amber_worthy

    def test_third_taint_raises_to_critical(self, state, config):
        """Third taint event should raise to CRITICAL."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        result = state.apply_taint("read_email", config)
        assert result == TaintLevel.CRITICAL

    def test_single_event_max_caps_at_high(self, state, config):
        """A single sensor call can't go beyond HIGH on its own."""
        # Config says single_event_max = HIGH
        state.level = TaintLevel.MEDIUM
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        result = state.apply_taint("search_web", config)
        assert result == TaintLevel.HIGH
        # Even though we could go higher, single event caps at HIGH
        # (need taint_event_count >= 2 for CRITICAL)

    def test_source_tracking(self, state, config):
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert "search_web" in state.taint_sources
        assert "fetch_url" in state.taint_sources
        assert len(state.taint_sources) == 2

    def test_duplicate_source_not_added_twice(self, state, config):
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("search_web", config)
        assert state.taint_sources.count("search_web") == 1

    def test_taint_event_count(self, state, config):
        state.apply_taint("search_web", config)
        assert state.taint_event_count == 1
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.taint_event_count == 2


# ─────────────────────────────────────────────────────
# Cooldown tests
# ─────────────────────────────────────────────────────

class TestCooldown:
    def test_rapid_taint_within_cooldown_no_escalation(self, state, config):
        """Rapid sensor calls within cooldown should NOT escalate past current level."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Immediate second call (within cooldown)
        result = state.apply_taint("fetch_url", config)
        assert result == TaintLevel.MEDIUM  # No escalation

    def test_rapid_taint_refreshes_timestamp(self, state, config):
        """Even within cooldown, timestamp should refresh."""
        state.apply_taint("search_web", config)
        first_time = state.last_taint_event

        # Tiny sleep to ensure time difference
        state.apply_taint("fetch_url", config)
        assert state.last_taint_event >= first_time

    def test_cooldown_tracks_unique_sources(self, state, config):
        """Source tracking works even during cooldown."""
        state.apply_taint("search_web", config)
        state.apply_taint("fetch_url", config)  # Within cooldown
        assert "fetch_url" in state.taint_sources

    def test_after_cooldown_escalation_resumes(self, state, config):
        """After cooldown expires, escalation continues."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Move past cooldown
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        result = state.apply_taint("fetch_url", config)
        assert result == TaintLevel.HIGH


# ─────────────────────────────────────────────────────
# Time-based decay tests
# ─────────────────────────────────────────────────────

class TestTimeDecay:
    def test_no_decay_before_interval(self, state, config):
        """Taint should not decay before interval elapses."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Barely any time passed
        result = state.apply_decay(config)
        assert result == TaintLevel.MEDIUM

    def test_one_interval_drops_one_level(self, state, config):
        """After one decay interval, taint drops by one level."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Simulate time passing (one interval)
        state.last_taint_event = time.time() - config.decay_interval_seconds - 1
        result = state.apply_decay(config)
        assert result == TaintLevel.LOW

    def test_two_intervals_drops_two_levels(self, state, config):
        """After two intervals, taint drops by two levels."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH

        # Simulate 2 intervals
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 2) - 1
        result = state.apply_decay(config)
        assert result == TaintLevel.LOW  # HIGH(3) - 2 = LOW(1)

    def test_full_decay_to_none(self, state, config):
        """Enough time should fully decay to NONE."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM  # level 2

        # Simulate enough time for full decay
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE
        assert not state.is_tainted

    def test_full_decay_resets_state(self, state, config):
        """Full decay should reset all internal counters."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)

        assert state.taint_event_count == 0
        assert state.taint_sources == []
        assert state.clean_ops_since_taint == 0

    def test_decay_never_goes_below_none(self, state, config):
        """Decay should clamp at NONE, not go negative."""
        state.level = TaintLevel.LOW
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 100)
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE

    def test_decay_on_none_is_noop(self, state, config):
        """Decay on NONE state should be a fast no-op."""
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE


# ─────────────────────────────────────────────────────
# Operation-based decay tests
# ─────────────────────────────────────────────────────

class TestOperationDecay:
    def test_clean_ops_count_towards_decay(self, state, config):
        """Clean operations should accumulate towards decay."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        for i in range(config.clean_ops_per_decay - 1):
            state.apply_clean_op(config)

        # Not enough yet
        assert state.level == TaintLevel.MEDIUM

        # One more triggers decay
        result = state.apply_clean_op(config)
        assert result == TaintLevel.LOW

    def test_clean_ops_counter_resets_after_decay(self, state, config):
        """Counter should reset after each level drop."""
        state.apply_taint("search_web", config)

        # Decay from MEDIUM to LOW
        for _ in range(config.clean_ops_per_decay):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW

        # Need another full set for LOW to NONE
        for _ in range(config.clean_ops_per_decay - 1):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW  # Not yet

        state.apply_clean_op(config)
        assert state.level == TaintLevel.NONE

    def test_taint_resets_clean_counter(self, state, config):
        """New taint event should reset the clean op counter."""
        state.apply_taint("search_web", config)

        # Accumulate some clean ops
        for _ in range(config.clean_ops_per_decay - 1):
            state.apply_clean_op(config)

        # New taint resets the counter
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.clean_ops_since_taint == 0

    def test_clean_op_on_none_is_noop(self, state, config):
        """Clean ops on NONE state should be a fast no-op."""
        for _ in range(100):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.NONE

    def test_combined_time_and_op_decay(self, state, config):
        """Time decay and op decay can both contribute."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH  # level 3

        # Time decays one level
        state.last_taint_event = time.time() - config.decay_interval_seconds - 1
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM  # level 2

        # Ops decay another level
        for _ in range(config.clean_ops_per_decay):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW  # level 1


# ─────────────────────────────────────────────────────
# Amber threshold tests
# ─────────────────────────────────────────────────────

class TestAmberThreshold:
    def test_none_not_amber(self, state, config):
        assert not state.should_amber(config)

    def test_low_not_amber(self, state, config):
        state.level = TaintLevel.LOW
        assert not state.should_amber(config)

    def test_medium_not_amber(self, state, config):
        state.level = TaintLevel.MEDIUM
        assert not state.should_amber(config)

    def test_high_triggers_amber(self, state, config):
        state.level = TaintLevel.HIGH
        assert state.should_amber(config)

    def test_critical_triggers_amber(self, state, config):
        state.level = TaintLevel.CRITICAL
        assert state.should_amber(config)

    def test_custom_threshold(self):
        """Custom threshold should be respected."""
        config = TaintDecayConfig(amber_threshold=TaintLevel.MEDIUM)
        state = TaintState(level=TaintLevel.MEDIUM)
        assert state.should_amber(config)

    def test_amber_worthy_property(self, state):
        """The amber_worthy property uses the module-level threshold."""
        state.level = TaintLevel.HIGH
        assert state.amber_worthy
        state.level = TaintLevel.MEDIUM
        assert not state.amber_worthy


# ─────────────────────────────────────────────────────
# Real-world scenario tests
# ─────────────────────────────────────────────────────

class TestRealWorldScenarios:
    def test_search_then_15_writes_no_fatigue(self, state, config):
        """The amber fatigue scenario: search_web then 15 fs_writes.

        With graduated decay, only the first few writes should trigger amber
        (while at HIGH), then ops-based decay should drop to MEDIUM.
        """
        # Agent does search_web → MEDIUM
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)  # MEDIUM < HIGH threshold

        # 15 writes are all clean ops — they decay taint, not trigger amber
        for i in range(15):
            state.apply_clean_op(config)

        # After 15 clean ops (> clean_ops_per_decay=10), should have decayed
        assert state.level == TaintLevel.LOW

    def test_multi_sensor_then_writes_triggers_amber(self, state, config):
        """Multiple sensor calls (search + fetch results) should escalate
        to HIGH and trigger amber on actuators."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH
        assert state.should_amber(config)

        # First few writes should still be amber-worthy
        state.apply_clean_op(config)
        assert state.should_amber(config)  # Still HIGH

    def test_sentinel_cron_high_throughput(self, state):
        """SENTINEL cron runs: many sensor calls in rapid succession.

        With cooldown, rapid calls don't over-escalate.
        Uses tight cooldown for autonomous principals.
        """
        config = TaintDecayConfig(
            retaint_cooldown_seconds=2.0,
            clean_ops_per_decay=5,
        )

        # SENTINEL reads 10 data sources rapidly
        state.apply_taint("read_rss", config)
        for i in range(9):
            state.apply_taint(f"fetch_url_{i}", config)

        # Should be at MEDIUM (cooldown prevents escalation)
        assert state.level == TaintLevel.MEDIUM

    def test_gradual_escalation_with_pauses(self, state, config):
        """Spaced-out sensor calls should escalate properly."""
        # First sensor
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Wait past cooldown, second sensor
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("read_email", config)
        assert state.level == TaintLevel.HIGH

        # Wait past cooldown, third sensor
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("read_slack", config)
        assert state.level == TaintLevel.CRITICAL

    def test_taint_decay_and_retaint_cycle(self, state, config):
        """Taint → decay → retaint should work correctly."""
        # Taint to MEDIUM
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Decay to NONE via time
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)
        assert state.level == TaintLevel.NONE
        assert state.taint_event_count == 0  # Reset

        # Retaint — should start fresh
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.MEDIUM
        assert state.taint_event_count == 1

    def test_backward_compat_is_tainted(self, state, config):
        """The is_tainted property should work for old code."""
        assert not state.is_tainted
        state.apply_taint("search_web", config)
        assert state.is_tainted
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)
        assert not state.is_tainted


# ─────────────────────────────────────────────────────
# Summary / audit tests
# ─────────────────────────────────────────────────────

class TestSummary:
    def test_summary_structure(self, state, config):
        state.apply_taint("search_web", config)
        s = state.summary()
        assert "level" in s
        assert "level_value" in s
        assert "is_tainted" in s
        assert "amber_worthy" in s
        assert "clean_ops" in s
        assert "taint_events" in s
        assert "sources" in s

    def test_summary_values(self, state, config):
        state.apply_taint("search_web", config)
        s = state.summary()
        assert s["level"] == "MEDIUM"
        assert s["level_value"] == 2
        assert s["is_tainted"] is True
        assert s["amber_worthy"] is False
        assert s["taint_events"] == 1
        assert s["sources"] == ["search_web"]


# ─────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────

class TestEdgeCases:
    def test_critical_needs_multiple_events(self, state, config):
        """Cannot reach CRITICAL from a single taint chain within cooldown."""
        state.apply_taint("search_web", config)
        # Within cooldown, spam more taints
        for i in range(10):
            state.apply_taint(f"sensor_{i}", config)
        # Should still be MEDIUM (cooldown blocks escalation)
        assert state.level == TaintLevel.MEDIUM

    def test_manual_level_set_respected(self, state, config):
        """Directly setting level should work (for admin overrides)."""
        state.level = TaintLevel.CRITICAL
        assert state.amber_worthy
        assert state.is_tainted

    def test_decay_from_critical(self, state, config):
        """CRITICAL should decay through all levels."""
        state.level = TaintLevel.CRITICAL
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 4) - 1
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE

    def test_very_large_time_gap(self, state, config):
        """Huge time gap should not cause overflow or errors."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - 999999
        result = state.apply_decay(config)
        assert result == TaintLevel.NONE

    def test_concurrent_time_and_op_decay_both_fire(self, state, config):
        """If both time and op thresholds are met, level drops appropriately."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        # HIGH

        # Time drops one level
        state.last_taint_event = time.time() - config.decay_interval_seconds - 1
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM

        # Immediately 10 clean ops drops another
        for _ in range(config.clean_ops_per_decay):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW


# ─────────────────────────────────────────────────────
# P2-8: Tightened decay + minimum dwell time tests
# ─────────────────────────────────────────────────────

class TestP28TightenedDefaults:
    """P2-8: Verify the new default values."""

    def test_default_decay_interval_120(self):
        """Default decay interval should be 120s (was 60s)."""
        cfg = TaintDecayConfig()
        assert cfg.decay_interval_seconds == 120.0

    def test_default_clean_ops_20(self):
        """Default clean ops per decay should be 20 (was 10)."""
        cfg = TaintDecayConfig()
        assert cfg.clean_ops_per_decay == 20

    def test_default_min_dwell_30(self):
        """Default minimum dwell time should be 30s."""
        cfg = TaintDecayConfig()
        assert cfg.min_dwell_seconds == 30.0


class TestMinimumDwellTime:
    """P2-8: Minimum dwell time prevents rapid taint wash attacks."""

    def test_time_decay_blocked_during_dwell(self):
        """Time-based decay should not fire within dwell period."""
        cfg = TaintDecayConfig(
            decay_interval_seconds=10.0,
            min_dwell_seconds=30.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)
        assert state.level == TaintLevel.MEDIUM

        # Even if decay_interval has passed (10s), dwell (30s) blocks decay
        state.last_taint_event = time.time() - 15  # 15s ago (past interval, within dwell)
        result = state.apply_decay(cfg)
        assert result == TaintLevel.MEDIUM  # No decay

    def test_time_decay_allowed_after_dwell(self):
        """Time-based decay should fire after dwell period expires.

        With dwell=30s and interval=60s, we need >30s for dwell,
        and elapsed/interval determines levels dropped.
        At 65s: past dwell, elapsed/60 = 1 level → MEDIUM(2) - 1 = LOW.
        """
        cfg = TaintDecayConfig(
            decay_interval_seconds=60.0,
            min_dwell_seconds=30.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)
        assert state.level == TaintLevel.MEDIUM

        # 65s ago — past dwell (30s), elapsed/60 = 1 level
        state.last_taint_event = time.time() - 65
        result = state.apply_decay(cfg)
        assert result == TaintLevel.LOW

    def test_op_decay_blocked_during_dwell(self):
        """Op-based decay should not fire within dwell period."""
        cfg = TaintDecayConfig(
            clean_ops_per_decay=5,
            min_dwell_seconds=30.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)

        # Spam 20 clean ops immediately — dwell blocks all decay
        for _ in range(20):
            state.apply_clean_op(cfg)
        assert state.level == TaintLevel.MEDIUM  # No decay despite 20 ops

    def test_op_decay_allowed_after_dwell(self):
        """Op-based decay fires after dwell period."""
        cfg = TaintDecayConfig(
            clean_ops_per_decay=5,
            min_dwell_seconds=30.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)

        # Move past dwell
        state.last_taint_event = time.time() - 31

        # Now clean ops should work
        for _ in range(5):
            state.apply_clean_op(cfg)
        assert state.level == TaintLevel.LOW

    def test_ops_still_counted_during_dwell(self):
        """Clean ops are counted during dwell, even though they don't trigger decay."""
        cfg = TaintDecayConfig(
            clean_ops_per_decay=5,
            min_dwell_seconds=30.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)

        # 3 ops during dwell
        for _ in range(3):
            state.apply_clean_op(cfg)
        assert state.clean_ops_since_taint == 3

    def test_dwell_zero_disables(self):
        """min_dwell_seconds=0 should disable the dwell check (backwards compat)."""
        cfg = TaintDecayConfig(
            clean_ops_per_decay=5,
            min_dwell_seconds=0.0,
        )
        state = TaintState()
        state.apply_taint("search_web", cfg)

        for _ in range(5):
            state.apply_clean_op(cfg)
        assert state.level == TaintLevel.LOW  # Immediate decay allowed


class TestTaintWashAttack:
    """P2-8: Proves the taint wash attack is defeated."""

    def test_40_rapid_ops_no_longer_clears_taint(self):
        """The original attack: 40 clean ops in rapid succession.

        Before P2-8: 40 ops / 10 per level = 4 levels of decay → NONE
        After P2-8: Dwell time blocks ALL op-based decay during first 30s.
        """
        cfg = TaintDecayConfig()  # Use defaults (P2-8 values)
        state = TaintState()

        # Taint to CRITICAL
        state.apply_taint("search_web", cfg)
        state.last_taint_event = time.time() - cfg.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", cfg)
        state.last_taint_event = time.time() - cfg.retaint_cooldown_seconds - 1
        state.apply_taint("read_email", cfg)
        assert state.level == TaintLevel.CRITICAL

        # Attacker fires 100 rapid clean ops
        for _ in range(100):
            state.apply_clean_op(cfg)

        # Taint should NOT have decayed — dwell time blocks it
        assert state.level == TaintLevel.CRITICAL

    def test_4_minutes_wait_does_clear_critical(self):
        """Legitimate decay: 4+ minutes from CRITICAL should clear.

        CRITICAL=4, decay_interval=120s, dwell=30s
        Need 4 * 120s = 480s (8 minutes) for full time-based decay.
        """
        cfg = TaintDecayConfig()  # P2-8 defaults
        state = TaintState()

        state.level = TaintLevel.CRITICAL
        state.last_taint_event = time.time() - 500  # 500s ago (past dwell + 4 intervals)
        result = state.apply_decay(cfg)
        assert result == TaintLevel.NONE

    def test_120s_from_high_drops_one_level(self):
        """With P2-8 defaults: 120s interval drops HIGH to MEDIUM."""
        cfg = TaintDecayConfig()  # P2-8 defaults
        state = TaintState()
        state.level = TaintLevel.HIGH
        state.last_taint_event = time.time() - 130  # Past dwell (30) and interval (120)

        result = state.apply_decay(cfg)
        assert result == TaintLevel.MEDIUM
