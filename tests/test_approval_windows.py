"""Tests for approval windows — time-limited pre-authorisation.

Covers: window lifecycle, TTL calculation, threat mode multipliers,
freshness rechecks, burst auto-escalation, one-time-use HIGH windows,
context hashing, and cleanup.
"""

import time
import pytest

from unwind.enforcement.approval_windows import (
    ApprovalWindow,
    ApprovalWindowConfig,
    ApprovalWindowService,
    BurstTracker,
    RiskBand,
    TelemetryEvent,
    TelemetryEventType,
    ThreatMode,
)


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def config():
    return ApprovalWindowConfig()


@pytest.fixture
def service(config):
    return ApprovalWindowService(config=config)


@pytest.fixture
def fast_config():
    """Config with short TTLs for time-sensitive tests."""
    return ApprovalWindowConfig(
        base_ttl_low=2.0,
        base_ttl_high=1.0,
        burst_deny_window_seconds=5.0,
        burst_pivot_window_seconds=5.0,
        burst_prompt_window_seconds=5.0,
        freeze_duration_seconds=2.0,
    )


@pytest.fixture
def fast_service(fast_config):
    return ApprovalWindowService(config=fast_config)


# ──────────────────────────────────────────────
# RiskBand and ThreatMode enums
# ──────────────────────────────────────────────

class TestEnums:
    def test_risk_band_ordering(self):
        assert RiskBand.AMBER_LOW < RiskBand.AMBER_HIGH < RiskBand.AMBER_CRITICAL

    def test_threat_mode_ordering(self):
        assert ThreatMode.NORMAL < ThreatMode.ELEVATED < ThreatMode.ACTIVE_EXPLOITATION


# ──────────────────────────────────────────────
# Context hashing
# ──────────────────────────────────────────────

class TestContextHash:
    def test_same_inputs_same_hash(self):
        h1 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-1")
        h2 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-1")
        assert h1 == h2

    def test_different_tool_different_hash(self):
        h1 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-1")
        h2 = ApprovalWindowService.compute_context_hash("fs_read", "path:str", "sess-1")
        assert h1 != h2

    def test_different_session_different_hash(self):
        h1 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-1")
        h2 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-2")
        assert h1 != h2

    def test_different_args_different_hash(self):
        h1 = ApprovalWindowService.compute_context_hash("fs_write", "path:str", "sess-1")
        h2 = ApprovalWindowService.compute_context_hash("fs_write", "path:str,content:str", "sess-1")
        assert h1 != h2

    def test_hash_is_16_chars(self):
        h = ApprovalWindowService.compute_context_hash("tool", "args", "sess")
        assert len(h) == 16


# ──────────────────────────────────────────────
# Window creation
# ──────────────────────────────────────────────

class TestWindowCreation:
    def test_create_low_window(self, service):
        w = service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        assert w is not None
        assert w.risk_band == RiskBand.AMBER_LOW
        assert w.session_id == "sess-1"
        assert w.operator_id == "op-1"
        assert w.is_valid
        assert w.max_uses == 5  # default max_ops_low_normal

    def test_create_high_window(self, service):
        w = service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_HIGH)
        assert w is not None
        assert w.risk_band == RiskBand.AMBER_HIGH
        assert w.max_uses == 1  # one-time-use

    def test_critical_returns_none(self, service):
        """CRITICAL band never gets a window."""
        w = service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_CRITICAL)
        assert w is None

    def test_window_id_increments(self, service):
        w1 = service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        w2 = service.create_window("sess-1", "op-1", "tool_b", "args", RiskBand.AMBER_LOW)
        assert w1.window_id != w2.window_id

    def test_create_replaces_existing(self, service):
        """Creating a window for the same context replaces the old one."""
        w1 = service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        w2 = service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        assert w1.window_id != w2.window_id
        # The service should have the new window
        current = service.get_window("sess-1", "fs_write", "path:str")
        assert current.window_id == w2.window_id


# ──────────────────────────────────────────────
# TTL calculation
# ──────────────────────────────────────────────

class TestTTL:
    def test_low_band_normal_ttl(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        # 300s * 1.0 = 300s
        assert abs(w.remaining_seconds - 300.0) < 1.0

    def test_high_band_normal_ttl(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        # 120s * 1.0 = 120s
        assert abs(w.remaining_seconds - 120.0) < 1.0

    def test_low_band_elevated_ttl(self, service):
        service.set_threat_mode(ThreatMode.ELEVATED)
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        # 300s * 0.6 = 180s
        assert abs(w.remaining_seconds - 180.0) < 1.0

    def test_high_band_elevated_ttl(self, service):
        service.set_threat_mode(ThreatMode.ELEVATED)
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        # 120s * 0.6 = 72s
        assert abs(w.remaining_seconds - 72.0) < 1.0

    def test_low_band_active_exploitation_ttl(self, service):
        service.set_threat_mode(ThreatMode.ACTIVE_EXPLOITATION)
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        # 300s * 0.4 = 120s
        assert abs(w.remaining_seconds - 120.0) < 1.0

    def test_high_band_active_exploitation_ttl(self, service):
        service.set_threat_mode(ThreatMode.ACTIVE_EXPLOITATION)
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        # 120s * 0.4 = 48s
        assert abs(w.remaining_seconds - 48.0) < 1.0


# ──────────────────────────────────────────────
# Window consumption
# ──────────────────────────────────────────────

class TestWindowConsumption:
    def test_consume_low_window(self, service):
        service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        assert service.consume_window("sess-1", "fs_write", "path:str") is True
        # Check use count
        w = service.get_window("sess-1", "fs_write", "path:str")
        assert w.use_count == 1

    def test_low_window_multiple_uses(self, service):
        """LOW windows allow multiple uses (default 5)."""
        service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        for i in range(5):
            assert service.consume_window("sess-1", "fs_write", "path:str") is True
        # 6th use should fail (exhausted)
        assert service.consume_window("sess-1", "fs_write", "path:str") is False

    def test_high_window_one_time_use(self, service):
        """HIGH windows are consumed after single use."""
        service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_HIGH)
        assert service.consume_window("sess-1", "fs_write", "path:str") is True
        assert service.consume_window("sess-1", "fs_write", "path:str") is False

    def test_consume_nonexistent_window(self, service):
        assert service.consume_window("sess-1", "no_tool", "args") is False

    def test_consume_wrong_session(self, service):
        """Window for sess-1 can't be used by sess-2."""
        service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        assert service.consume_window("sess-2", "fs_write", "path:str") is False

    def test_consume_updates_last_used(self, service):
        service.create_window("sess-1", "op-1", "fs_write", "path:str", RiskBand.AMBER_LOW)
        before = time.time()
        service.consume_window("sess-1", "fs_write", "path:str")
        w = service.get_window("sess-1", "fs_write", "path:str")
        assert w.last_used_at is not None
        assert w.last_used_at >= before


# ──────────────────────────────────────────────
# Freshness rechecks
# ──────────────────────────────────────────────

class TestFreshness:
    def test_high_window_stale_rss_rejected(self, service):
        """HIGH window requires RSS < 5s old."""
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        # Fresh data — should return window
        w = service.check_window("sess-1", "tool", "args", current_rss_age=2.0, current_taint_age=2.0)
        assert w is not None
        # Stale RSS — should reject
        w = service.check_window("sess-1", "tool", "args", current_rss_age=10.0, current_taint_age=2.0)
        assert w is None

    def test_high_window_stale_taint_rejected(self, service):
        """HIGH window requires taint < 5s old."""
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        w = service.check_window("sess-1", "tool", "args", current_rss_age=2.0, current_taint_age=10.0)
        assert w is None

    def test_low_window_longer_freshness(self, service):
        """LOW window allows RSS/taint up to 15s old."""
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        # 10s old — OK for LOW
        w = service.check_window("sess-1", "tool", "args", current_rss_age=10.0, current_taint_age=10.0)
        assert w is not None
        # 20s old — stale even for LOW
        w = service.check_window("sess-1", "tool", "args", current_rss_age=20.0, current_taint_age=2.0)
        assert w is None

    def test_zero_age_always_fresh(self, service):
        """Default age=0 means data was just computed — always fresh."""
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        w = service.check_window("sess-1", "tool", "args")
        assert w is not None


# ──────────────────────────────────────────────
# Window invalidation
# ──────────────────────────────────────────────

class TestInvalidation:
    def test_invalidate_specific_window(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        w.invalidate("test reason")
        assert not w.is_valid
        assert w.invalidation_reason == "test reason"

    def test_invalidate_session_windows(self, service):
        service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        service.create_window("sess-1", "op-1", "tool_b", "args", RiskBand.AMBER_HIGH)
        count = service.invalidate_session_windows("sess-1", "taint escalation")
        assert count == 2
        assert service.active_window_count("sess-1") == 0

    def test_invalidate_high_only(self, service):
        service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        service.create_window("sess-1", "op-1", "tool_b", "args", RiskBand.AMBER_HIGH)
        count = service.invalidate_high_windows("sess-1", "moderate escalation")
        assert count == 1
        assert service.active_window_count("sess-1") == 1
        # LOW should still be valid
        w = service.get_window("sess-1", "tool_a", "args")
        assert w.is_valid

    def test_invalidate_other_session_unaffected(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        service.create_window("sess-2", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        service.invalidate_session_windows("sess-1")
        assert service.active_window_count("sess-2") == 1

    def test_invalidated_window_not_consumable(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        service.invalidate_session_windows("sess-1")
        assert service.consume_window("sess-1", "tool", "args") is False


# ──────────────────────────────────────────────
# Threat mode escalation
# ──────────────────────────────────────────────

class TestThreatEscalation:
    def test_escalation_invalidates_high_windows(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        service.set_threat_mode(ThreatMode.ELEVATED)
        w = service.get_window("sess-1", "tool", "args")
        assert w.invalidated

    def test_escalation_compresses_low_ttl(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        original_expires = w.expires_at
        service.set_threat_mode(ThreatMode.ELEVATED)
        # 300 * 0.6 = 180s from creation, which is less than original 300s
        assert w.expires_at < original_expires

    def test_double_escalation(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        service.set_threat_mode(ThreatMode.ELEVATED)
        mid_expires = w.expires_at
        service.set_threat_mode(ThreatMode.ACTIVE_EXPLOITATION)
        # 300 * 0.4 = 120s from creation, less than elevated's 180s
        assert w.expires_at < mid_expires

    def test_threat_mode_property(self, service):
        assert service.threat_mode == ThreatMode.NORMAL
        service.set_threat_mode(ThreatMode.ELEVATED)
        assert service.threat_mode == ThreatMode.ELEVATED

    def test_max_ops_reduced_at_elevated(self, service):
        """LOW windows get fewer max_uses under elevated threat."""
        service.set_threat_mode(ThreatMode.ELEVATED)
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        assert w.max_uses == 3  # max_ops_low_elevated


# ──────────────────────────────────────────────
# Burst auto-escalation
# ──────────────────────────────────────────────

class TestBurstEscalation:
    def test_deny_burst_triggers_freeze(self, service):
        """3 deny+retries in 45s triggers principal freeze."""
        for _ in range(3):
            action = service.record_deny_retry("sess-1")
        assert action == "freeze_principal"
        assert service.is_session_frozen("sess-1")

    def test_freeze_blocks_window_creation(self, service):
        for _ in range(3):
            service.record_deny_retry("sess-1")
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        assert w is None

    def test_pivot_burst_triggers_quarantine(self, service):
        """2 tainted high-risk pivots in 20s triggers quarantine."""
        for _ in range(2):
            action = service.record_tainted_pivot("sess-1")
        assert action == "quarantine_session"

    def test_prompt_burst_triggers_disable(self, service):
        """8 approval prompts in 60s disables windows."""
        for _ in range(8):
            action = service.record_approval_prompt("sess-1")
        assert action == "disable_windows"

    def test_deny_burst_invalidates_windows(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        for _ in range(3):
            service.record_deny_retry("sess-1")
        assert service.active_window_count("sess-1") == 0

    def test_freeze_expires(self, fast_service):
        """Freeze auto-expires after duration."""
        for _ in range(3):
            fast_service.record_deny_retry("sess-1")
        assert fast_service.is_session_frozen("sess-1")
        # Simulate time passing
        tracker = fast_service._burst_trackers["sess-1"]
        tracker.frozen_until = time.time() - 1  # Already expired
        assert not fast_service.is_session_frozen("sess-1")

    def test_freeze_remaining_seconds(self, service):
        for _ in range(3):
            service.record_deny_retry("sess-1")
        remaining = service.get_freeze_remaining("sess-1")
        assert remaining > 590  # ~600s freeze

    def test_no_freeze_returns_zero(self, service):
        assert service.get_freeze_remaining("sess-1") == 0.0

    def test_below_threshold_no_action(self, service):
        """2 denies (below 3 threshold) — no freeze."""
        for _ in range(2):
            action = service.record_deny_retry("sess-1")
        assert action is None
        assert not service.is_session_frozen("sess-1")

    def test_separate_sessions_separate_burst(self, service):
        """Burst tracking is per-session."""
        service.record_deny_retry("sess-1")
        service.record_deny_retry("sess-1")
        action = service.record_deny_retry("sess-2")  # Only 1 for sess-2
        assert action is None
        assert not service.is_session_frozen("sess-2")


# ──────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────

class TestCleanup:
    def test_cleanup_expired_windows(self, service):
        w = service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        # Force expiry
        w.expires_at = time.time() - 1
        count = service.cleanup_expired()
        assert count == 1
        assert service.active_window_count("sess-1") == 0

    def test_cleanup_invalidated_windows(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        service.invalidate_session_windows("sess-1")
        count = service.cleanup_expired()
        assert count == 1

    def test_cleanup_keeps_valid_windows(self, service):
        service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        w2 = service.create_window("sess-1", "op-1", "tool_b", "args", RiskBand.AMBER_HIGH)
        w2.expires_at = time.time() - 1  # Only expire one
        count = service.cleanup_expired()
        assert count == 1
        assert service.active_window_count("sess-1") == 1


# ──────────────────────────────────────────────
# ApprovalWindow dataclass
# ──────────────────────────────────────────────

class TestApprovalWindowDataclass:
    def test_is_expired(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time() - 400, expires_at=time.time() - 100,
            threat_mode=ThreatMode.NORMAL,
        )
        assert w.is_expired

    def test_is_not_expired(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time(), expires_at=time.time() + 300,
            threat_mode=ThreatMode.NORMAL,
        )
        assert not w.is_expired

    def test_is_exhausted(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_HIGH,
            created_at=time.time(), expires_at=time.time() + 120,
            threat_mode=ThreatMode.NORMAL, max_uses=1, use_count=1,
        )
        assert w.is_exhausted

    def test_unlimited_not_exhausted(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time(), expires_at=time.time() + 300,
            threat_mode=ThreatMode.NORMAL, max_uses=0, use_count=100,
        )
        assert not w.is_exhausted

    def test_consume_valid(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time(), expires_at=time.time() + 300,
            threat_mode=ThreatMode.NORMAL, max_uses=5,
        )
        assert w.consume() is True
        assert w.use_count == 1

    def test_consume_expired_fails(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time() - 400, expires_at=time.time() - 1,
            threat_mode=ThreatMode.NORMAL,
        )
        assert w.consume() is False

    def test_invalidate(self):
        w = ApprovalWindow(
            window_id="aw-1", session_id="s", operator_id="o",
            context_hash="h", risk_band=RiskBand.AMBER_LOW,
            created_at=time.time(), expires_at=time.time() + 300,
            threat_mode=ThreatMode.NORMAL,
        )
        w.invalidate("test")
        assert not w.is_valid
        assert w.consume() is False


# ──────────────────────────────────────────────
# BurstTracker standalone
# ──────────────────────────────────────────────

class TestBurstTracker:
    def test_is_frozen_default(self):
        tracker = BurstTracker()
        assert not tracker.is_frozen

    def test_freeze_remaining_default(self):
        tracker = BurstTracker()
        assert tracker.freeze_remaining == 0.0

    def test_record_deny(self):
        tracker = BurstTracker()
        tracker.record_deny()
        assert len(tracker.deny_timestamps) == 1

    def test_record_pivot(self):
        tracker = BurstTracker()
        tracker.record_tainted_pivot()
        assert len(tracker.pivot_timestamps) == 1

    def test_record_prompt(self):
        tracker = BurstTracker()
        tracker.record_prompt()
        assert len(tracker.prompt_timestamps) == 1

    def test_burst_trims_old_timestamps(self):
        config = ApprovalWindowConfig(burst_deny_window_seconds=5.0)
        tracker = BurstTracker()
        tracker.deny_timestamps = [time.time() - 100, time.time() - 50]
        tracker.check_burst(config)
        assert len(tracker.deny_timestamps) == 0


# ──────────────────────────────────────────────
# Summary / audit
# ──────────────────────────────────────────────

class TestSummary:
    def test_session_summary(self, service):
        service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        s = service.summary("sess-1")
        assert s["active_windows"] == 1
        assert s["threat_mode"] == "NORMAL"
        assert s["is_frozen"] is False

    def test_global_summary(self, service):
        service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        service.create_window("sess-2", "op-1", "tool_b", "args", RiskBand.AMBER_HIGH)
        s = service.summary()
        assert s["total_sessions"] == 2
        assert s["total_active_windows"] == 2

    def test_active_window_count_filters_invalid(self, service):
        service.create_window("sess-1", "op-1", "tool_a", "args", RiskBand.AMBER_LOW)
        w = service.create_window("sess-1", "op-1", "tool_b", "args", RiskBand.AMBER_HIGH)
        w.invalidate("test")
        assert service.active_window_count("sess-1") == 1


# ──────────────────────────────────────────────
# Telemetry (shadow mode)
# ──────────────────────────────────────────────

class TestTelemetry:
    """Test structured telemetry events are emitted for all lifecycle transitions."""

    @pytest.fixture
    def tel_events(self):
        """Collected telemetry events."""
        return []

    @pytest.fixture
    def tel_service(self, tel_events):
        """Service with telemetry callback that collects events."""
        def callback(event: TelemetryEvent):
            tel_events.append(event)
        return ApprovalWindowService(
            config=ApprovalWindowConfig(),
            telemetry_callback=callback,
        )

    def test_window_created_event(self, tel_service, tel_events):
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        created = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_CREATED]
        assert len(created) == 1
        assert created[0].session_id == "sess-1"
        assert created[0].tool_name == "tool"
        assert created[0].risk_band == "AMBER_LOW"
        assert created[0].ttl_effective == 300.0

    def test_window_consumed_event(self, tel_service, tel_events):
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        tel_service.consume_window("sess-1", "tool", "args")
        consumed = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_CONSUMED]
        assert len(consumed) == 1
        assert consumed[0].uses_remaining == 4  # 5 max - 1 used

    def test_high_window_consumed_shows_zero_remaining(self, tel_service, tel_events):
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        tel_service.consume_window("sess-1", "tool", "args")
        consumed = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_CONSUMED]
        assert consumed[0].uses_remaining == 0  # 1 max - 1 used

    def test_window_invalidated_event(self, tel_service, tel_events):
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        tel_service.invalidate_session_windows("sess-1", "taint spike")
        invalidated = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_INVALIDATED]
        assert len(invalidated) == 1
        assert invalidated[0].reason == "taint spike"

    def test_threat_mode_changed_event(self, tel_service, tel_events):
        tel_service.set_threat_mode(ThreatMode.ELEVATED)
        changed = [e for e in tel_events if e.event_type == TelemetryEventType.THREAT_MODE_CHANGED]
        assert len(changed) == 1
        assert changed[0].threat_mode == "ELEVATED"
        assert "NORMAL" in changed[0].reason

    def test_burst_triggered_event(self, tel_service, tel_events):
        for _ in range(3):
            tel_service.record_deny_retry("sess-1")
        burst = [e for e in tel_events if e.event_type == TelemetryEventType.BURST_TRIGGERED]
        assert len(burst) == 1
        assert burst[0].burst_type == "deny_retry"
        assert "freeze_principal" in burst[0].reason

    def test_freshness_rejected_event(self, tel_service, tel_events):
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_HIGH)
        # Stale RSS
        result = tel_service.check_window(
            "sess-1", "tool", "args", current_rss_age=10.0, current_taint_age=0.0
        )
        assert result is None
        rejected = [e for e in tel_events if e.event_type == TelemetryEventType.FRESHNESS_REJECTED]
        assert len(rejected) == 1
        assert "RSS age" in rejected[0].reason

    def test_telemetry_log_accumulates(self, tel_service, tel_events):
        """Service internal log matches callback emissions."""
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        tel_service.consume_window("sess-1", "tool", "args")
        assert len(tel_service.telemetry_log) == 2
        assert len(tel_events) == 2

    def test_telemetry_event_to_dict(self):
        event = TelemetryEvent(
            event_type=TelemetryEventType.WINDOW_CREATED,
            timestamp=1000.0,
            session_id="sess-1",
            window_id="aw-000001",
            tool_name="fs_write",
        )
        d = event.to_dict()
        assert d["event_type"] == "window_created"
        assert d["timestamp"] == 1000.0
        assert d["session_id"] == "sess-1"
        assert "risk_band" not in d  # Empty string omitted

    def test_no_telemetry_for_critical_band(self, tel_service, tel_events):
        """CRITICAL band returns None — no created event."""
        result = tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_CRITICAL)
        assert result is None
        created = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_CREATED]
        assert len(created) == 0

    def test_invalidation_during_burst_emits_both(self, tel_service, tel_events):
        """Burst trigger that invalidates windows should emit both burst and invalidation events."""
        tel_service.create_window("sess-1", "op-1", "tool", "args", RiskBand.AMBER_LOW)
        for _ in range(3):
            tel_service.record_deny_retry("sess-1")
        burst = [e for e in tel_events if e.event_type == TelemetryEventType.BURST_TRIGGERED]
        invalidated = [e for e in tel_events if e.event_type == TelemetryEventType.WINDOW_INVALIDATED]
        assert len(burst) == 1
        assert len(invalidated) == 1
