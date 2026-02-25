"""Tests for rubber-stamp detection system.

Covers:
- RSS formula: each indicator scored correctly
- RSS thresholds: correct level assignment
- Action mapping: correct friction per level
- Streak tracking: approve/reject behaviour
- Burst detection: rapid approvals in time window
- Pattern change detection
- Ratio alerting over sliding window
- Lockout mechanics
- Real-world scenarios

NOTE: In tests, all approvals happen within milliseconds, so the burst
indicator (10 pts) fires whenever count >= burst_count (default 8).
Tests must account for this.
"""

import time

import pytest

from unwind.enforcement.rubber_stamp import (
    RSSLevel,
    RubberStampConfig,
    RubberStampState,
)


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def config():
    return RubberStampConfig()


@pytest.fixture
def state():
    return RubberStampState()


@pytest.fixture
def fast_config():
    """Config with smaller windows for testing."""
    return RubberStampConfig(
        consecutive_approve_streak=3,
        ratio_window_size=5,
        burst_count=3,
        burst_window_seconds=10.0,
    )


# ─────────────────────────────────────────────────────
# RSS Formula — Individual Indicators
# ─────────────────────────────────────────────────────

class TestRSSIndicators:
    def test_fast_approve_under_2s(self, state, config):
        """Latency < 2s = 30 points."""
        state.record_decision(approved=True, latency_seconds=1.5, pattern_hash="p1")
        rss = state.compute_rss(1.5, "p1", config)
        assert rss == 30  # fast only (1 approval < burst threshold 8)

    def test_very_fast_approve_under_1s(self, state, config):
        """Latency < 1s = 30 + 15 = 45 points."""
        state.record_decision(approved=True, latency_seconds=0.5, pattern_hash="p1")
        rss = state.compute_rss(0.5, "p1", config)
        assert rss == 45  # fast(30) + very_fast(15)

    def test_slow_approve_no_points(self, state, config):
        """Latency >= 2s = 0 points from speed indicators."""
        state.record_decision(approved=True, latency_seconds=3.0, pattern_hash="p1")
        rss = state.compute_rss(3.0, "p1", config)
        assert rss == 0

    def test_streak_indicator(self, state, config):
        """12+ consecutive approvals = 20 points (+ burst 10 if ≥8 in window)."""
        for i in range(12):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", config)
        # streak(20) + burst(10, 12 ≥ 8 in 60s) = 30
        assert rss == 30

    def test_streak_broken_by_reject(self, state, config):
        """Rejection resets streak."""
        for i in range(11):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=5.0, pattern_hash="p1")
        assert state.approve_streak == 0
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", config)
        # streak=1 (no), burst=12 approvals in window (≥8 → 10)
        assert rss == 10

    def test_ratio_indicator(self, state, config):
        """Approve ratio > 0.98 over 50 decisions = 15 points."""
        for i in range(50):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", config)
        # streak=50 (≥12 → 20) + ratio>0.98 (15) + burst(50 ≥8 → 10) = 45
        assert rss == 45

    def test_ratio_below_threshold(self, state, config):
        """Ratio ≤ 0.98 = no ratio points."""
        # 48 approvals, 2 rejections = 0.96
        for i in range(48):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=5.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=5.0, pattern_hash="p1")
        # Streak broken by rejections (streak=0), ratio=0.96 (no)
        # Burst: 48 approvals in window (≥8 → 10)
        rss = state.compute_rss(5.0, "p1", config)
        assert rss == 10  # Only burst

    def test_pattern_change_indicator(self, state, config):
        """Pattern changed but approved = 20 points."""
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="pattern_A")
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="pattern_B")
        # pattern_changed_on_last_approve should be True
        rss = state.compute_rss(5.0, "pattern_B", config)
        assert rss == 20  # Pattern change fires

    def test_same_pattern_no_change_points(self, state, config):
        """Same pattern = no change points."""
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="pattern_A")
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="pattern_A")
        rss = state.compute_rss(5.0, "pattern_A", config)
        assert rss == 0

    def test_burst_indicator(self, state, config):
        """8+ approvals in 60s = 10 points."""
        for i in range(8):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", config)
        assert rss == 10  # Only burst fires (streak=8 < 12)

    def test_burst_outside_window_no_points(self, state, config):
        """Approvals outside 60s window don't count."""
        for i in range(7):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        # Move burst timestamps to 61 seconds ago
        old_time = time.time() - 61
        state.burst_timestamps = [old_time] * 7

        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", config)
        assert rss == 0  # Only 1 in window, need 8


class TestRSSCombinations:
    def test_fast_plus_streak(self, state, config):
        """Fast approval + long streak + burst."""
        for i in range(12):
            state.record_decision(approved=True, latency_seconds=1.5, pattern_hash="p1")
        rss = state.compute_rss(1.5, "p1", config)
        # fast(30) + streak(20) + burst(10) = 60
        assert rss == 60

    def test_very_fast_plus_streak_plus_pattern_change(self, state, config):
        """Sub-second + streak + pattern change + burst = very high."""
        for i in range(12):
            state.record_decision(approved=True, latency_seconds=0.5, pattern_hash="p1")
        state.record_decision(approved=True, latency_seconds=0.5, pattern_hash="p2")
        rss = state.compute_rss(0.5, "p2", config)
        # fast(30) + very_fast(15) + streak(20) + pattern_change(20) + burst(10) = 95
        assert rss == 95

    def test_maximum_rss_score(self, state, config):
        """All indicators firing should clamp at 100."""
        for i in range(50):
            state.record_decision(
                approved=True, latency_seconds=0.5, pattern_hash="p1"
            )
        state.record_decision(approved=True, latency_seconds=0.5, pattern_hash="p2")
        rss = state.compute_rss(0.5, "p2", config)
        # fast(30) + very_fast(15) + streak(20) + ratio(15) + pattern(20) + burst(10) = 110 → 100
        assert rss == 100

    def test_score_clamped_at_zero(self, state, config):
        """Score never goes below zero."""
        rss = state.compute_rss(10.0, "", config)
        assert rss == 0


# ─────────────────────────────────────────────────────
# RSS Level Assignment
# ─────────────────────────────────────────────────────

class TestRSSLevels:
    def test_none_level(self, state, config):
        assert state.get_rss_level(0, config) == RSSLevel.NONE
        assert state.get_rss_level(34, config) == RSSLevel.NONE

    def test_medium_level(self, state, config):
        assert state.get_rss_level(35, config) == RSSLevel.MEDIUM
        assert state.get_rss_level(54, config) == RSSLevel.MEDIUM

    def test_high_level(self, state, config):
        assert state.get_rss_level(55, config) == RSSLevel.HIGH
        assert state.get_rss_level(74, config) == RSSLevel.HIGH

    def test_very_high_level(self, state, config):
        assert state.get_rss_level(75, config) == RSSLevel.VERY_HIGH
        assert state.get_rss_level(100, config) == RSSLevel.VERY_HIGH


# ─────────────────────────────────────────────────────
# Action Mapping
# ─────────────────────────────────────────────────────

class TestRSSActions:
    def test_none_no_actions(self, state, config):
        result = state.apply_rss_actions(20, config)
        assert result["level"] == RSSLevel.NONE
        assert result["actions"] == []
        assert result["hold_seconds"] == 0.0
        assert result["windows_disabled"] is False

    def test_medium_actions(self, state, config):
        result = state.apply_rss_actions(40, config)
        assert result["level"] == RSSLevel.MEDIUM
        assert "require_reason_code" in result["actions"]
        assert "show_condensed_risk_delta" in result["actions"]
        assert result["hold_seconds"] == 0.0

    def test_high_actions(self, state, config):
        result = state.apply_rss_actions(60, config)
        assert result["level"] == RSSLevel.HIGH
        assert "force_expanded_diff_view" in result["actions"]
        assert "disable_low_window_auto_issue" in result["actions"]
        assert result["hold_seconds"] == 5.0
        assert "require_reason_code" in result["actions"]

    def test_very_high_actions(self, state, config):
        result = state.apply_rss_actions(80, config)
        assert result["level"] == RSSLevel.VERY_HIGH
        assert "disable_all_approval_windows" in result["actions"]
        assert "require_step_up_for_high_and_critical" in result["actions"]
        assert "notify_soc" in result["actions"]
        assert result["windows_disabled"] is True
        assert result["lockout_until"] is not None
        assert "require_reason_code" in result["actions"]
        assert "force_expanded_diff_view" in result["actions"]

    def test_very_high_sets_lockout(self, state, config):
        state.apply_rss_actions(80, config)
        assert state.is_locked_out()


# ─────────────────────────────────────────────────────
# Lockout Mechanics
# ─────────────────────────────────────────────────────

class TestLockout:
    def test_not_locked_by_default(self, state):
        assert not state.is_locked_out()

    def test_lockout_set_by_very_high(self, state, config):
        state.apply_rss_actions(80, config)
        assert state.is_locked_out()

    def test_lockout_expires(self, state, config):
        state.apply_rss_actions(80, config)
        state.lockout_until = time.time() - 1
        assert not state.is_locked_out()
        assert state.lockout_until is None

    def test_manual_clear_lockout(self, state, config):
        state.apply_rss_actions(80, config)
        state.clear_lockout()
        assert not state.is_locked_out()

    def test_lockout_duration_matches_config(self, state, config):
        before = time.time()
        state.apply_rss_actions(80, config)
        after = time.time()
        expected_min = before + config.very_high_lockout_seconds
        expected_max = after + config.very_high_lockout_seconds
        assert expected_min <= state.lockout_until <= expected_max


# ─────────────────────────────────────────────────────
# Decision Recording
# ─────────────────────────────────────────────────────

class TestDecisionRecording:
    def test_approval_increments_streak(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert state.approve_streak == 1
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert state.approve_streak == 2

    def test_rejection_resets_streak(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=1.0, pattern_hash="p1")
        assert state.approve_streak == 0

    def test_approval_adds_to_burst(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert len(state.burst_timestamps) == 1

    def test_rejection_does_not_add_to_burst(self, state):
        state.record_decision(approved=False, latency_seconds=1.0, pattern_hash="p1")
        assert len(state.burst_timestamps) == 0

    def test_total_counters(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert state.total_approvals == 2
        assert state.total_rejections == 1

    def test_decision_window_capped(self, state):
        for i in range(100):
            state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert len(state.decisions) == 50

    def test_pattern_change_flag_set(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        assert not state.pattern_changed_on_last_approve
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p2")
        assert state.pattern_changed_on_last_approve

    def test_pattern_change_flag_cleared_on_same(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p2")
        assert state.pattern_changed_on_last_approve
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p2")
        assert not state.pattern_changed_on_last_approve


# ─────────────────────────────────────────────────────
# Real-World Scenarios
# ─────────────────────────────────────────────────────

class TestRealWorldScenarios:
    def test_careful_operator(self, state, config):
        """An operator who reads carefully (5-15s) on same pattern.

        20 approvals at 8s each, same pattern: streak=20 (≥12→20), burst=20 (≥8→10).
        Total 30, below MEDIUM threshold of 35.
        """
        for i in range(20):
            state.record_decision(
                approved=True, latency_seconds=8.0, pattern_hash="same_pattern"
            )
        rss = state.compute_rss(8.0, "same_pattern", config)
        # streak(20) + burst(10) = 30 < 35 (MEDIUM threshold)
        assert rss == 30
        assert state.get_rss_level(rss, config) == RSSLevel.NONE

    def test_fatigued_operator_gradual_speedup(self, state, config):
        """Operator starts careful then speeds up — escalates.

        10 careful + 3 fast: streak=13 (≥12→20), fast(30), burst=13 (≥8→10) = 60 → HIGH
        """
        for i in range(10):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        for i in range(3):
            state.record_decision(approved=True, latency_seconds=1.5, pattern_hash="p1")
        rss = state.compute_rss(1.5, "p1", config)
        # fast(30) + streak(20) + burst(10) = 60
        assert rss == 60
        assert state.get_rss_level(rss, config) == RSSLevel.HIGH

    def test_rubber_stamping_operator(self, state, config):
        """Operator clicking approve immediately without reading."""
        for i in range(15):
            state.record_decision(approved=True, latency_seconds=0.3, pattern_hash="p1")
        state.record_decision(approved=True, latency_seconds=0.3, pattern_hash="p2")
        rss = state.compute_rss(0.3, "p2", config)
        # fast(30) + very_fast(15) + streak(20) + pattern_change(20) + burst(10) = 95
        assert rss == 95
        assert state.get_rss_level(rss, config) == RSSLevel.VERY_HIGH

    def test_mixed_approve_reject_healthy(self, state, config):
        """Operator who regularly rejects = healthy.

        20 decisions, reject every 5th. Streak broken. 16 approvals in burst.
        """
        for i in range(20):
            if i % 5 == 0:
                state.record_decision(approved=False, latency_seconds=4.0, pattern_hash="p1")
            else:
                state.record_decision(approved=True, latency_seconds=4.0, pattern_hash="p1")
        rss = state.compute_rss(4.0, "p1", config)
        # No speed, streak broken (max 4 between rejects), burst=16 (≥8→10)
        assert rss == 10
        assert state.get_rss_level(rss, config) == RSSLevel.NONE

    def test_autonomous_session_no_operator(self, state, config):
        """Autonomous sessions have no operator — RSS should be minimal."""
        rss = state.compute_rss(0.0, "", config)
        assert rss <= 45

    def test_fs_write_15_files_scenario(self, state, config):
        """The classic fatigue scenario: 15 rapid approvals for fs_write.

        Sub-second clicking through 15 identical prompts.
        """
        for i in range(15):
            state.record_decision(
                approved=True,
                latency_seconds=0.8,
                pattern_hash="fs_write_workspace",
            )
        rss = state.compute_rss(0.8, "fs_write_workspace", config)
        # fast(30) + very_fast(15) + streak(15≥12→20) + burst(15≥8→10) = 75
        assert rss == 75
        assert state.get_rss_level(rss, config) == RSSLevel.VERY_HIGH

        actions = state.apply_rss_actions(rss, config)
        assert actions["windows_disabled"] is True


# ─────────────────────────────────────────────────────
# Reset and Summary
# ─────────────────────────────────────────────────────

class TestResetAndSummary:
    def test_reset_clears_all(self, state, config):
        for i in range(5):
            state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.apply_rss_actions(80, config)
        state.reset()
        assert state.approve_streak == 0
        assert state.total_approvals == 0
        assert state.total_rejections == 0
        assert not state.is_locked_out()
        assert len(state.decisions) == 0
        assert len(state.burst_timestamps) == 0
        assert not state.pattern_changed_on_last_approve

    def test_summary_structure(self, state, config):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        s = state.summary()
        assert "approve_streak" in s
        assert "approve_ratio" in s
        assert "total_approvals" in s
        assert "total_rejections" in s
        assert "decisions_in_window" in s
        assert "burst_count" in s
        assert "is_locked_out" in s
        assert "peak_rss" in s

    def test_peak_rss_tracked(self, state, config):
        state.record_decision(approved=True, latency_seconds=0.5, pattern_hash="p1")
        rss1 = state.compute_rss(0.5, "p1", config)
        state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss2 = state.compute_rss(5.0, "p1", config)
        assert state.peak_rss == max(rss1, rss2)

    def test_approve_ratio_property(self, state):
        state.record_decision(approved=True, latency_seconds=1.0, pattern_hash="p1")
        state.record_decision(approved=False, latency_seconds=1.0, pattern_hash="p1")
        assert state.approve_ratio == 0.5

    def test_approve_ratio_empty(self, state):
        assert state.approve_ratio == 0.0


# ─────────────────────────────────────────────────────
# Fast Config Tests (smaller windows)
# ─────────────────────────────────────────────────────

class TestFastConfig:
    def test_small_streak_threshold(self, state, fast_config):
        """With streak=3 and burst=3, three approvals fire both."""
        for i in range(3):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", fast_config)
        # streak(20) + burst(10) = 30
        assert rss == 30

    def test_small_ratio_window(self, state, fast_config):
        """With window=5, 5 approvals fire ratio + streak + burst."""
        for i in range(5):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", fast_config)
        # streak(5≥3→20) + ratio(5/5=1.0→15) + burst(5≥3→10) = 45
        assert rss == 45

    def test_small_burst_threshold(self, state, fast_config):
        """With burst=3, three rapid approvals fire burst."""
        for i in range(3):
            state.record_decision(approved=True, latency_seconds=5.0, pattern_hash="p1")
        rss = state.compute_rss(5.0, "p1", fast_config)
        # streak(3≥3→20) + burst(3≥3→10) = 30
        assert rss >= 10  # At least burst fires
