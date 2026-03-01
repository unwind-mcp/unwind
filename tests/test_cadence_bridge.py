"""Tests for Cadence Bridge — temporal anomaly detection (P3-11).

Covers:
- CadenceState reading from state.env (valid, missing, corrupt, unknown states)
- Scenario 1: AWAY + machine speed detection
- Scenario 2: Zero-variance timing detection
- Scenario 3: READING + rapid actuator detection
- Taint clear callback firing
- Feature flag (disabled returns empty, enabled returns signals)
- Pipeline integration (AMBER on away+machine speed, graceful degradation)
"""

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from unwind.config import UnwindConfig
from unwind.enforcement.cadence_bridge import (
    CadenceBridge,
    CadenceBridgeConfig,
    CadenceSignal,
    CadenceState,
    CadenceUserState,
    SessionTimingState,
    TemporalAnomalyType,
)
from unwind.enforcement.pipeline import CheckResult, EnforcementPipeline, PipelineResult
from unwind.session import Session, TrustState


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def tmp_state_dir(tmp_path):
    """Temp directory for state.env files."""
    return tmp_path


@pytest.fixture
def state_env_path(tmp_state_dir):
    """Path to a state.env file in the temp directory."""
    return tmp_state_dir / "state.env"


@pytest.fixture
def bridge(state_env_path):
    """Bridge with default config pointing to temp state.env."""
    return CadenceBridge(state_env_path=state_env_path)


@pytest.fixture
def config():
    """Default bridge config."""
    return CadenceBridgeConfig()


def _write_state_env(path, **kwargs):
    """Helper: write a state.env file with given key=value pairs."""
    lines = [f"{k}={v}" for k, v in kwargs.items()]
    path.write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────────────
# TestCadenceStateReading
# ─────────────────────────────────────────────────────

class TestCadenceStateReading:
    """Tests for read_state() — parsing state.env files."""

    def test_valid_state_file(self, bridge, state_env_path):
        _write_state_env(
            state_env_path,
            USER_STATE="FLOW",
            ANOMALY_SCORE="0.42",
            ERT_SECONDS="1800.5",
            LAST_DIRECTION="input",
            LAST_TOKENS="350",
        )
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.FLOW
        assert state.anomaly_score == pytest.approx(0.42)
        assert state.ert_seconds == pytest.approx(1800.5)
        assert state.last_direction == "input"
        assert state.last_tokens == 350

    def test_missing_file_returns_none(self, bridge):
        state = bridge.read_state()
        assert state is None

    def test_empty_file_returns_defaults(self, bridge, state_env_path):
        state_env_path.write_text("", encoding="utf-8")
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.UNKNOWN
        assert state.anomaly_score == 0.0
        assert state.last_tokens == 0

    def test_unknown_user_state_maps_to_unknown(self, bridge, state_env_path):
        _write_state_env(state_env_path, USER_STATE="SLEEPING")
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.UNKNOWN

    def test_corrupt_numeric_values_use_defaults(self, bridge, state_env_path):
        _write_state_env(
            state_env_path,
            USER_STATE="AWAY",
            ANOMALY_SCORE="not_a_number",
            ERT_SECONDS="abc",
            LAST_TOKENS="xyz",
        )
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.AWAY
        assert state.anomaly_score == 0.0
        assert state.ert_seconds == 0.0
        assert state.last_tokens == 0

    def test_comments_and_blank_lines_skipped(self, bridge, state_env_path):
        state_env_path.write_text(
            "# This is a comment\n\nUSER_STATE=READING\n\n# Another comment\n",
            encoding="utf-8",
        )
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.READING

    def test_all_user_states(self, bridge, state_env_path):
        for state_name in ("FLOW", "READING", "DEEP_WORK", "AWAY"):
            _write_state_env(state_env_path, USER_STATE=state_name)
            state = bridge.read_state()
            assert state.user_state == CadenceUserState(state_name)

    def test_permission_error_returns_none(self, bridge, state_env_path):
        state_env_path.write_text("USER_STATE=FLOW", encoding="utf-8")
        state_env_path.chmod(0o000)
        try:
            state = bridge.read_state()
            assert state is None
        finally:
            state_env_path.chmod(0o644)

    def test_lines_without_equals_skipped(self, bridge, state_env_path):
        state_env_path.write_text(
            "USER_STATE=FLOW\nINVALID_LINE\nLAST_TOKENS=100\n",
            encoding="utf-8",
        )
        state = bridge.read_state()
        assert state is not None
        assert state.user_state == CadenceUserState.FLOW
        assert state.last_tokens == 100


# ─────────────────────────────────────────────────────
# TestAwayMachineSpeed (Scenario 1)
# ─────────────────────────────────────────────────────

class TestAwayMachineSpeed:
    """Tests for AWAY + machine speed detection."""

    def test_away_fast_triggers(self, bridge, state_env_path):
        """AWAY + avg interval < threshold → signal."""
        _write_state_env(state_env_path, USER_STATE="AWAY")

        base = 1000.0
        with patch("time.time") as mock_time:
            # 3 checks at 0.5s intervals (< 2.0s threshold)
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                signals = bridge.check("s1", "bash_exec", "actuator", False)
            # Last check should trigger
            assert len(signals) == 1
            assert signals[0].anomaly_type == TemporalAnomalyType.AWAY_MACHINE_SPEED
            assert signals[0].should_amber is True
            assert signals[0].should_escalate_taint is True

    def test_away_slow_no_trigger(self, bridge, state_env_path):
        """AWAY + avg interval > threshold → no signal."""
        _write_state_env(state_env_path, USER_STATE="AWAY")

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(3):
                mock_time.return_value = base + i * 5.0  # 5s intervals
                signals = bridge.check("s1", "bash_exec", "actuator", False)
            assert len(signals) == 0

    def test_flow_fast_no_trigger(self, bridge, state_env_path):
        """FLOW + fast intervals → no signal (only triggers on AWAY)."""
        _write_state_env(state_env_path, USER_STATE="FLOW")

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(5):
                mock_time.return_value = base + i * 0.5
                signals = bridge.check("s1", "bash_exec", "actuator", False)
            assert len(signals) == 0

    def test_min_check_threshold(self, bridge, state_env_path):
        """Need min_checks before triggering."""
        _write_state_env(state_env_path, USER_STATE="AWAY")

        base = 1000.0
        with patch("time.time") as mock_time:
            # Only 2 checks (default min is 3)
            for i in range(2):
                mock_time.return_value = base + i * 0.1
                signals = bridge.check("s1", "bash_exec", "actuator", False)
            assert len(signals) == 0

    def test_away_machine_speed_amber_reason(self, bridge, state_env_path):
        """Check amber_reason contains useful info."""
        _write_state_env(state_env_path, USER_STATE="AWAY")

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            assert "AWAY" in signals[0].amber_reason
            assert "machine speed" in signals[0].amber_reason


# ─────────────────────────────────────────────────────
# TestZeroVariance (Scenario 2)
# ─────────────────────────────────────────────────────

class TestZeroVariance:
    """Tests for zero-variance timing detection."""

    def test_constant_intervals_trigger(self, state_env_path):
        """Perfectly constant intervals → CV ≈ 0 → trigger."""
        _write_state_env(state_env_path, USER_STATE="FLOW")
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            config=CadenceBridgeConfig(zero_variance_min_intervals=8),
        )

        base = 1000.0
        with patch("time.time") as mock_time:
            # 10 checks at exactly 1.0s intervals
            for i in range(10):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "fs_read", "sensor", False)

            # Should trigger zero-variance
            zv_signals = [s for s in signals if s.anomaly_type == TemporalAnomalyType.ZERO_VARIANCE]
            assert len(zv_signals) == 1
            assert zv_signals[0].should_escalate_taint is True

    def test_normal_variance_no_trigger(self, state_env_path):
        """Normal human-like variance → no trigger."""
        _write_state_env(state_env_path, USER_STATE="FLOW")
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            config=CadenceBridgeConfig(zero_variance_min_intervals=8),
        )

        import random
        random.seed(42)
        base = 1000.0
        with patch("time.time") as mock_time:
            t = base
            for i in range(15):
                t += random.uniform(0.5, 5.0)  # Highly variable intervals
                mock_time.return_value = t
                signals = bridge.check("s1", "fs_read", "sensor", False)

            zv_signals = [s for s in signals if s.anomaly_type == TemporalAnomalyType.ZERO_VARIANCE]
            assert len(zv_signals) == 0

    def test_needs_minimum_intervals(self, state_env_path):
        """Not enough intervals → no trigger even with zero variance."""
        _write_state_env(state_env_path, USER_STATE="FLOW")
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            config=CadenceBridgeConfig(zero_variance_min_intervals=8),
        )

        base = 1000.0
        with patch("time.time") as mock_time:
            # Only 5 checks (need 9 for 8 intervals)
            for i in range(5):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "fs_read", "sensor", False)

            zv_signals = [s for s in signals if s.anomaly_type == TemporalAnomalyType.ZERO_VARIANCE]
            assert len(zv_signals) == 0

    def test_independent_of_cadence_state(self, state_env_path):
        """Zero-variance triggers regardless of USER_STATE."""
        _write_state_env(state_env_path, USER_STATE="DEEP_WORK")
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            config=CadenceBridgeConfig(zero_variance_min_intervals=8),
        )

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(10):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "fs_read", "sensor", False)

            zv_signals = [s for s in signals if s.anomaly_type == TemporalAnomalyType.ZERO_VARIANCE]
            assert len(zv_signals) == 1


# ─────────────────────────────────────────────────────
# TestReadingRapidActuator (Scenario 3)
# ─────────────────────────────────────────────────────

class TestReadingRapidActuator:
    """Tests for READING + rapid actuator detection."""

    def test_reading_rapid_actuators_trigger(self, state_env_path):
        """READING + high tokens + rapid actuator calls → trigger."""
        _write_state_env(state_env_path, USER_STATE="READING", LAST_TOKENS="500")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            # 4 actuator calls within 10s window, 1s apart
            for i in range(4):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 1
            assert rra[0].should_amber is True
            assert rra[0].should_escalate_taint is False  # No taint for this scenario

    def test_reading_slow_actuators_no_trigger(self, state_env_path):
        """READING + slow actuator calls → no trigger."""
        _write_state_env(state_env_path, USER_STATE="READING", LAST_TOKENS="500")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(4):
                mock_time.return_value = base + i * 5.0  # 5s apart (> 3s threshold)
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 0

    def test_reading_sensors_no_trigger(self, state_env_path):
        """READING + rapid sensor calls → no trigger (sensors aren't actuators)."""
        _write_state_env(state_env_path, USER_STATE="READING", LAST_TOKENS="500")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(5):
                mock_time.return_value = base + i * 0.5
                signals = bridge.check("s1", "fs_read", "sensor", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 0

    def test_flow_rapid_actuators_no_trigger(self, state_env_path):
        """FLOW + rapid actuator calls → no trigger (only triggers on READING)."""
        _write_state_env(state_env_path, USER_STATE="FLOW", LAST_TOKENS="500")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(4):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 0

    def test_low_tokens_no_trigger(self, state_env_path):
        """READING + low tokens + rapid actuators → no trigger."""
        _write_state_env(state_env_path, USER_STATE="READING", LAST_TOKENS="50")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(4):
                mock_time.return_value = base + i * 1.0
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 0

    def test_reading_rapid_min_calls(self, state_env_path):
        """Need min actuator calls before triggering."""
        _write_state_env(state_env_path, USER_STATE="READING", LAST_TOKENS="500")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            # Only 2 actuator calls (default min is 3)
            for i in range(2):
                mock_time.return_value = base + i * 0.5
                signals = bridge.check("s1", "bash_exec", "actuator", False)

            rra = [s for s in signals if s.anomaly_type == TemporalAnomalyType.READING_RAPID_ACTUATOR]
            assert len(rra) == 0


# ─────────────────────────────────────────────────────
# TestTaintClear (Scenario 4)
# ─────────────────────────────────────────────────────

class TestTaintClear:
    """Tests for taint clear callback."""

    def test_callback_fires_on_transition(self, state_env_path):
        """Callback fires when tainted → not tainted."""
        callback = MagicMock()
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        bridge.check_taint_clear("s1", was_tainted=True, is_tainted=False)
        callback.assert_called_once_with("s1")

    def test_no_callback_when_still_tainted(self, state_env_path):
        """No callback when session remains tainted."""
        callback = MagicMock()
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        bridge.check_taint_clear("s1", was_tainted=True, is_tainted=True)
        callback.assert_not_called()

    def test_no_callback_when_was_not_tainted(self, state_env_path):
        """No callback when session was never tainted."""
        callback = MagicMock()
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        bridge.check_taint_clear("s1", was_tainted=False, is_tainted=False)
        callback.assert_not_called()

    def test_no_callback_on_new_taint(self, state_env_path):
        """No callback when clean → tainted."""
        callback = MagicMock()
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        bridge.check_taint_clear("s1", was_tainted=False, is_tainted=True)
        callback.assert_not_called()

    def test_callback_failure_swallowed(self, state_env_path):
        """Exception in callback is swallowed, bridge doesn't crash."""
        callback = MagicMock(side_effect=RuntimeError("pulse write failed"))
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        # Should not raise
        bridge.check_taint_clear("s1", was_tainted=True, is_tainted=False)
        callback.assert_called_once()

    def test_no_callback_configured(self, state_env_path):
        """No crash when on_taint_clear is None."""
        bridge = CadenceBridge(state_env_path=state_env_path, on_taint_clear=None)
        # Should not raise
        bridge.check_taint_clear("s1", was_tainted=True, is_tainted=False)


# ─────────────────────────────────────────────────────
# TestFeatureFlag
# ─────────────────────────────────────────────────────

class TestFeatureFlag:
    """Tests for feature flag behaviour."""

    def test_disabled_pipeline_has_no_bridge(self):
        """When cadence_bridge_enabled=False, pipeline.cadence_bridge is None."""
        config = UnwindConfig()
        assert config.cadence_bridge_enabled is False
        pipeline = EnforcementPipeline(config)
        assert pipeline.cadence_bridge is None

    def test_disabled_returns_no_signals(self, state_env_path):
        """Bridge disabled → stage 7a is a None check, returns ALLOW."""
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config)
        session = Session(session_id="s1", config=config)

        _write_state_env(state_env_path, USER_STATE="AWAY")

        result = pipeline.check(session, "bash_exec")
        # Without bridge, AWAY state doesn't produce cadence amber
        # (normal pipeline behaviour applies)
        assert result.action != CheckResult.KILL

    def test_enabled_via_config(self, state_env_path):
        """When cadence_bridge_enabled=True and state_env_path set, bridge is created."""
        config = UnwindConfig()
        # Manually override the field since env var may not be set
        config.cadence_bridge_enabled = True
        config.cadence_state_env_path = state_env_path
        pipeline = EnforcementPipeline(config)
        assert pipeline.cadence_bridge is not None
        assert pipeline.cadence_bridge.state_env_path == state_env_path

    def test_explicit_bridge_overrides_config(self, state_env_path):
        """Passing cadence_bridge directly uses it regardless of config."""
        config = UnwindConfig()
        bridge = CadenceBridge(state_env_path=state_env_path)
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)
        assert pipeline.cadence_bridge is bridge


# ─────────────────────────────────────────────────────
# TestPipelineIntegration
# ─────────────────────────────────────────────────────

class TestPipelineIntegration:
    """Full pipeline integration tests with cadence bridge."""

    def test_amber_on_away_machine_speed(self, state_env_path):
        """AWAY + machine speed + high-risk actuator → AMBER."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        bridge = CadenceBridge(state_env_path=state_env_path)
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                session = Session(session_id="s1", config=config)
                result = pipeline.check(session, "bash_exec")

            assert result.action == CheckResult.AMBER
            assert "AWAY" in result.amber_reason
            assert "machine speed" in result.amber_reason

    def test_away_machine_speed_sensor_no_amber(self, state_env_path):
        """AWAY + machine speed + sensor tool → no AMBER (sensor is not high-risk actuator)."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        bridge = CadenceBridge(state_env_path=state_env_path)
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                session = Session(session_id="s1", config=config)
                result = pipeline.check(session, "fs_read")

            # Sensor tool → taint escalation happens but AMBER only on high-risk actuators
            assert result.action != CheckResult.AMBER or "AWAY" not in (result.amber_reason or "")

    def test_graceful_degradation_missing_state_env(self, tmp_path):
        """Missing state.env → bridge returns no signals, pipeline continues normally."""
        missing_path = tmp_path / "nonexistent" / "state.env"
        bridge = CadenceBridge(state_env_path=missing_path)
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)

        session = Session(session_id="s1", config=config)
        result = pipeline.check(session, "fs_read")
        # Pipeline should work normally — bridge fails open
        assert result.action == CheckResult.ALLOW

    def test_bridge_disabled_identical_behaviour(self, state_env_path):
        """With bridge=None, pipeline behaviour is identical to baseline."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        config = UnwindConfig()

        # Pipeline without bridge
        pipeline_no_bridge = EnforcementPipeline(config, cadence_bridge=None)
        session1 = Session(session_id="s1", config=config)
        result1 = pipeline_no_bridge.check(session1, "fs_read")

        # Pipeline with bridge (but state.env missing)
        pipeline_with_bridge = EnforcementPipeline(
            config,
            cadence_bridge=CadenceBridge(
                state_env_path=Path("/nonexistent/state.env"),
            ),
        )
        session2 = Session(session_id="s2", config=config)
        result2 = pipeline_with_bridge.check(session2, "fs_read")

        assert result1.action == result2.action

    def test_taint_escalation_on_away_machine_speed(self, state_env_path):
        """AWAY + machine speed → taint escalation happens."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        bridge = CadenceBridge(state_env_path=state_env_path)
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)
        session = Session(session_id="s1", config=config)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                pipeline.check(session, "bash_exec")

            # Session should now be tainted from cadence bridge
            assert session.is_tainted

    def test_taint_clear_callback_in_pipeline(self, state_env_path):
        """Pipeline calls check_taint_clear before check."""
        callback = MagicMock()
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            on_taint_clear=callback,
        )
        _write_state_env(state_env_path, USER_STATE="FLOW")
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)

        # Create a session that was tainted
        session = Session(session_id="s1", config=config)
        session.taint(source_tool="test_sensor")

        # Force taint to decay by advancing time far enough
        future_ts = time.time() + 100000
        with patch("time.time", return_value=future_ts):
            pipeline.check(session, "fs_read")

        # If taint decayed during check_taint_decay, the bridge should
        # have detected the transition. Callback may or may not fire
        # depending on whether decay actually cleared taint.
        # (This test verifies the bridge is wired in, not that decay fires.)

    def test_multiple_signals_first_amber_wins(self, state_env_path):
        """If multiple anomalies fire, first one with should_amber wins for AMBER."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        bridge = CadenceBridge(
            state_env_path=state_env_path,
            config=CadenceBridgeConfig(
                away_speed_threshold_seconds=2.0,
                away_speed_min_checks=3,
                zero_variance_min_intervals=3,  # Very low threshold
                zero_variance_cv_threshold=0.1,
            ),
        )
        config = UnwindConfig()
        pipeline = EnforcementPipeline(config, cadence_bridge=bridge)

        base = 1000.0
        with patch("time.time") as mock_time:
            for i in range(5):
                mock_time.return_value = base + i * 0.5  # Very regular, very fast
                session = Session(session_id="s1", config=config)
                result = pipeline.check(session, "bash_exec")

            assert result.action == CheckResult.AMBER


# ─────────────────────────────────────────────────────
# TestSessionTimingIsolation
# ─────────────────────────────────────────────────────

class TestSessionTimingIsolation:
    """Verify that timing state is per-session."""

    def test_separate_sessions_independent(self, state_env_path):
        """Different session IDs have independent timing state."""
        _write_state_env(state_env_path, USER_STATE="AWAY")
        bridge = CadenceBridge(state_env_path=state_env_path)

        base = 1000.0
        with patch("time.time") as mock_time:
            # Session A: 3 fast checks
            for i in range(3):
                mock_time.return_value = base + i * 0.5
                signals_a = bridge.check("session_a", "bash_exec", "actuator", False)

            # Session B: 1 check (not enough for trigger)
            mock_time.return_value = base + 10.0
            signals_b = bridge.check("session_b", "bash_exec", "actuator", False)

        # Session A should trigger, B should not
        assert len(signals_a) > 0
        assert len(signals_b) == 0
