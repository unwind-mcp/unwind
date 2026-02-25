"""Tests for Amber Mediator Telemetry (GO-09) and Rollout Guard (GO-10).

GO-09: Telemetry chain complete for every decision path.
GO-10: Safe rollout guard with config gate + shadow parity test.
"""

import unittest

from unwind.enforcement.amber_telemetry import (
    AmberTelemetry,
    AmberTelemetryEvent,
    AmberEventName,
    AmberReasonCode,
)
from unwind.enforcement.amber_rollout import (
    AmberMediatorMode,
    DEFAULT_MODE,
    CONFIG_KEY,
    parse_mode,
    ShadowDecision,
    ShadowParityResult,
    run_shadow_parity_test,
    THRESHOLDS,
    MIN_EVENTS_TOTAL,
    MIN_EVENTS_PER_TIER,
    MIN_OBSERVATION_HOURS,
)


# ─── GO-09: Telemetry Chain Tests ────────────────────────────────

class TestAmberTelemetryIssue(unittest.TestCase):
    """Issue event tests."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_issue_event_emitted(self):
        """Issue emits correct event name and fields."""
        self.tel.emit_issue(
            request_id="req_1",
            session_id="sess_1",
            event_id="evt_1",
            pattern_id="pat_abc",
            risk_tier="AMBER_HIGH",
            challenge_nonce="nonce_xyz",
            challenge_seq=1,
            challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="act_def",
            batch_group_key="grp_1",
            batchable=True,
            batch_max_size=5,
            risk_capsule_hash="cap_hash",
        )
        self.assertEqual(len(self.tel.event_log), 1)
        evt = self.tel.event_log[0]
        self.assertEqual(evt.event_name, AmberEventName.ISSUE)
        self.assertEqual(evt.reason_code, AmberReasonCode.AMBER_EVENT_ISSUED)
        self.assertEqual(evt.decision, "none")
        self.assertEqual(evt.challenge_seq, 1)
        self.assertTrue(evt.timestamp.endswith("Z"))

    def test_issue_required_fields_present(self):
        """All GO-09 required fields for issue are present in to_dict()."""
        self.tel.emit_issue(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="act_def", batch_group_key="grp_1",
            batchable=True, batch_max_size=5, risk_capsule_hash="cap_hash",
        )
        d = self.tel.event_log[0].to_dict()
        required = [
            "event_name", "timestamp", "request_id", "session_id",
            "principal_id", "event_id", "pattern_id", "risk_tier",
            "challenge_nonce", "challenge_seq", "challenge_expires_at",
            "action_hash", "batch_group_key", "batchable",
            "batch_max_size", "risk_capsule_hash", "reason_code", "decision",
        ]
        for f in required:
            self.assertIn(f, d, f"Missing required field: {f}")


class TestAmberTelemetryReceived(unittest.TestCase):
    """Received event tests."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_received_event_emitted(self):
        self.tel.emit_received(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_1",
        )
        evt = self.tel.event_log[0]
        self.assertEqual(evt.event_name, AmberEventName.RECEIVED)
        self.assertEqual(evt.reason_code, AmberReasonCode.AMBER_DECISION_RECEIVED)
        self.assertEqual(evt.token_jti, "jti_1")
        self.assertEqual(evt.validation_result, "pass")


class TestAmberTelemetryApplied(unittest.TestCase):
    """Applied event tests."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_applied_event_emitted(self):
        self.tel.emit_applied(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_1",
            enforcement_outcome="approved_applied", decision="approve",
        )
        evt = self.tel.event_log[0]
        self.assertEqual(evt.event_name, AmberEventName.APPLIED)
        self.assertEqual(evt.enforcement_outcome, "approved_applied")
        self.assertEqual(evt.validation_result, "pass")
        self.assertEqual(evt.decision, "approve")


class TestAmberTelemetryRejected(unittest.TestCase):
    """Rejected event tests."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_rejected_event_emitted(self):
        self.tel.emit_rejected(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_1",
            reject_stage="binding",
            reason_code=AmberReasonCode.MEDIATOR_TOKEN_ACTION_HASH_MISMATCH,
        )
        evt = self.tel.event_log[0]
        self.assertEqual(evt.event_name, AmberEventName.REJECTED)
        self.assertEqual(evt.validation_result, "fail")
        self.assertEqual(evt.reject_stage, "binding")


class TestAmberTelemetryReplayBlocked(unittest.TestCase):
    """Replay blocked event tests."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_replay_blocked_emitted(self):
        self.tel.emit_replay_blocked(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            token_jti="jti_1", replay_source="duplicate_jti",
        )
        evt = self.tel.event_log[0]
        self.assertEqual(evt.event_name, AmberEventName.REPLAY_BLOCKED)
        self.assertEqual(evt.reason_code, AmberReasonCode.MEDIATOR_TOKEN_REPLAY)
        self.assertEqual(evt.replay_source, "duplicate_jti")

    def test_replay_blocked_required_fields_in_dict(self):
        """GO-09 required fields survive to_dict() even for replay events."""
        self.tel.emit_replay_blocked(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            token_jti="jti_1", replay_source="duplicate_jti",
        )
        d = self.tel.event_log[0].to_dict()
        # All GO-09 common required fields must be present
        for f in ["event_name", "timestamp", "request_id", "session_id",
                   "principal_id", "event_id", "pattern_id", "risk_tier",
                   "reason_code", "decision"]:
            self.assertIn(f, d, f"Required field '{f}' dropped by to_dict()")


class TestAmberTelemetryChainReconstruction(unittest.TestCase):
    """Chain reconstruction: request_id → event_id → token_jti."""

    def setUp(self):
        self.tel = AmberTelemetry()

    def test_full_chain_issue_to_applied(self):
        """Complete chain: issue → received → applied."""
        self.tel.emit_issue(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="act_def", batch_group_key="grp_1",
            batchable=True, batch_max_size=5, risk_capsule_hash="cap_hash",
        )
        self.tel.emit_received(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_1",
        )
        self.tel.emit_applied(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_1",
            enforcement_outcome="approved_applied", decision="approve",
        )
        chain = self.tel.chain_for_event("evt_1")
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].event_name, AmberEventName.ISSUE)
        self.assertEqual(chain[1].event_name, AmberEventName.RECEIVED)
        self.assertEqual(chain[2].event_name, AmberEventName.APPLIED)

    def test_chain_issue_to_rejected(self):
        """Rejection chain: issue → received → rejected."""
        self.tel.emit_issue(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="act_def", batch_group_key="grp_1",
            batchable=True, batch_max_size=5, risk_capsule_hash="cap_hash",
        )
        self.tel.emit_rejected(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            action_hash="act_def", token_jti="jti_bad",
            reject_stage="expiry",
            reason_code=AmberReasonCode.MEDIATOR_TOKEN_EXPIRED,
        )
        chain = self.tel.chain_for_event("evt_1")
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[1].event_name, AmberEventName.REJECTED)

    def test_chain_by_request_id(self):
        """request_id links across event_ids."""
        self.tel.emit_issue(
            request_id="req_X", session_id="sess_1", event_id="evt_1",
            pattern_id="pat_abc", risk_tier="AMBER_HIGH",
            challenge_nonce="nonce", challenge_seq=1,
            challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="act_def", batch_group_key="grp_1",
            batchable=True, batch_max_size=5, risk_capsule_hash="cap_hash",
        )
        chain = self.tel.chain_for_request("req_X")
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0].request_id, "req_X")

    def test_summary_counts(self):
        """Summary counts events by type."""
        self.tel.emit_issue(
            request_id="req_1", session_id="sess_1", event_id="evt_1",
            pattern_id="p", risk_tier="AMBER_HIGH", challenge_nonce="n",
            challenge_seq=1, challenge_expires_at="2026-02-22T20:00:00Z",
            action_hash="a", batch_group_key="g", batchable=True,
            batch_max_size=5, risk_capsule_hash="c",
        )
        self.tel.emit_replay_blocked(
            request_id="req_2", session_id="sess_1", event_id="evt_1",
            pattern_id="p", risk_tier="AMBER_HIGH",
            token_jti="jti_dup", replay_source="duplicate_jti",
        )
        s = self.tel.summary()
        self.assertEqual(s["total_events"], 2)
        self.assertEqual(s["by_name"][AmberEventName.ISSUE], 1)
        self.assertEqual(s["by_name"][AmberEventName.REPLAY_BLOCKED], 1)


# ─── GO-10: Rollout Guard Tests ─────────────────────────────────

class TestConfigGate(unittest.TestCase):
    """Config gate: amber.mediator.mode."""

    def test_default_is_off(self):
        """Default mode is OFF (safe by default)."""
        self.assertEqual(DEFAULT_MODE, AmberMediatorMode.OFF)

    def test_config_key_name(self):
        """Config key matches spec."""
        self.assertEqual(CONFIG_KEY, "amber.mediator.mode")

    def test_parse_valid_modes(self):
        """All three valid modes parse correctly."""
        self.assertEqual(parse_mode("off"), AmberMediatorMode.OFF)
        self.assertEqual(parse_mode("shadow"), AmberMediatorMode.SHADOW)
        self.assertEqual(parse_mode("enforce"), AmberMediatorMode.ENFORCE)

    def test_parse_case_insensitive(self):
        """Mode parsing is case-insensitive."""
        self.assertEqual(parse_mode("OFF"), AmberMediatorMode.OFF)
        self.assertEqual(parse_mode("Shadow"), AmberMediatorMode.SHADOW)
        self.assertEqual(parse_mode("ENFORCE"), AmberMediatorMode.ENFORCE)

    def test_parse_unknown_defaults_off(self):
        """Unrecognised value defaults to OFF (fail-closed)."""
        self.assertEqual(parse_mode("yolo"), AmberMediatorMode.OFF)
        self.assertEqual(parse_mode(""), AmberMediatorMode.OFF)

    def test_mode_enum_values(self):
        """Enum string values match spec."""
        self.assertEqual(AmberMediatorMode.OFF.value, "off")
        self.assertEqual(AmberMediatorMode.SHADOW.value, "shadow")
        self.assertEqual(AmberMediatorMode.ENFORCE.value, "enforce")


class TestShadowParityThresholds(unittest.TestCase):
    """Shadow parity test with GO-10 thresholds."""

    def _make_decisions(self, n, tier="AMBER_HIGH", match=True, unsafe=False, overblock=False, replay=False):
        """Generate n shadow decisions."""
        decisions = []
        for i in range(n):
            baseline = "amber"
            shadow = "amber" if match else ("allow" if unsafe else ("deny" if overblock else "amber"))
            decisions.append(ShadowDecision(
                event_id=f"evt_{i}",
                risk_tier=tier,
                baseline_decision=baseline if not unsafe else "amber",
                baseline_reason_code="TAINT_PIVOT",
                shadow_decision=shadow,
                shadow_reason_code="TAINT_PIVOT" if match else "DIFFERENT",
                telemetry_fields_present=7,
                telemetry_fields_required=7,
                replay_accepted=replay,
            ))
        return decisions

    def test_perfect_parity_passes(self):
        """100% match rate with sufficient sample passes."""
        decisions = (
            self._make_decisions(1700, tier="AMBER_HIGH")
            + self._make_decisions(250, tier="AMBER_LOW")
            + self._make_decisions(50, tier="AMBER_CRITICAL")
        )
        result = run_shadow_parity_test(decisions, observation_hours=25)
        self.assertTrue(result.sample_sufficient)
        self.assertTrue(result.all_thresholds_pass)
        self.assertTrue(result.promote_safe)
        self.assertEqual(len(result.failures), 0)

    def test_insufficient_sample_fails(self):
        """Too few events → sample insufficient."""
        decisions = self._make_decisions(100)
        result = run_shadow_parity_test(decisions, observation_hours=25)
        self.assertFalse(result.sample_sufficient)
        self.assertFalse(result.promote_safe)

    def test_insufficient_hours_fails(self):
        """Too few hours → sample insufficient."""
        decisions = (
            self._make_decisions(1700, tier="AMBER_HIGH")
            + self._make_decisions(250, tier="AMBER_LOW")
            + self._make_decisions(50, tier="AMBER_CRITICAL")
        )
        result = run_shadow_parity_test(decisions, observation_hours=12)
        self.assertFalse(result.sample_sufficient)

    def test_unsafe_allow_drift_hard_fails(self):
        """Any unsafe allow drift → hard fail."""
        good = (
            self._make_decisions(1699, tier="AMBER_HIGH")
            + self._make_decisions(250, tier="AMBER_LOW")
            + self._make_decisions(50, tier="AMBER_CRITICAL")
        )
        # One unsafe allow
        bad = [ShadowDecision(
            event_id="evt_bad", risk_tier="AMBER_HIGH",
            baseline_decision="amber", baseline_reason_code="TAINT_PIVOT",
            shadow_decision="allow", shadow_reason_code="TAINT_PIVOT",
            telemetry_fields_present=7, telemetry_fields_required=7,
        )]
        result = run_shadow_parity_test(good + bad, observation_hours=25)
        self.assertFalse(result.all_thresholds_pass)
        self.assertFalse(result.promote_safe)
        any_unsafe = any("unsafe_allow" in f for f in result.failures)
        self.assertTrue(any_unsafe)

    def test_replay_acceptance_hard_fails(self):
        """Any replay accepted → hard fail."""
        decisions = (
            self._make_decisions(1699, tier="AMBER_HIGH")
            + self._make_decisions(250, tier="AMBER_LOW")
            + self._make_decisions(50, tier="AMBER_CRITICAL")
        )
        # One replay accepted
        decisions.append(ShadowDecision(
            event_id="evt_replay", risk_tier="AMBER_HIGH",
            baseline_decision="amber", baseline_reason_code="TAINT_PIVOT",
            shadow_decision="amber", shadow_reason_code="TAINT_PIVOT",
            telemetry_fields_present=7, telemetry_fields_required=7,
            replay_accepted=True,
        ))
        result = run_shadow_parity_test(decisions, observation_hours=25)
        self.assertFalse(result.all_thresholds_pass)
        any_replay = any("replay_acceptance" in f for f in result.failures)
        self.assertTrue(any_replay)

    def test_telemetry_incomplete_fails(self):
        """Missing telemetry fields → hard fail."""
        decisions = []
        for i in range(2000):
            decisions.append(ShadowDecision(
                event_id=f"evt_{i}",
                risk_tier="AMBER_HIGH" if i < 1700 else ("AMBER_LOW" if i < 1950 else "AMBER_CRITICAL"),
                baseline_decision="amber",
                baseline_reason_code="TAINT_PIVOT",
                shadow_decision="amber",
                shadow_reason_code="TAINT_PIVOT",
                telemetry_fields_present=6,  # Missing 1 of 7
                telemetry_fields_required=7,
            ))
        result = run_shadow_parity_test(decisions, observation_hours=25)
        self.assertFalse(result.all_thresholds_pass)
        any_telemetry = any("telemetry_chain" in f for f in result.failures)
        self.assertTrue(any_telemetry)

    def test_overblock_within_tolerance(self):
        """Overblock rate <= 0.1% passes."""
        # 2000 events, 2 overblocks = 0.1% exactly
        decisions = []
        for i in range(2000):
            tier = "AMBER_HIGH" if i < 1700 else ("AMBER_LOW" if i < 1950 else "AMBER_CRITICAL")
            if i < 2:
                # Overblocks
                decisions.append(ShadowDecision(
                    event_id=f"evt_{i}", risk_tier=tier,
                    baseline_decision="allow", baseline_reason_code="CLEAN",
                    shadow_decision="deny", shadow_reason_code="FALSE_POS",
                    telemetry_fields_present=7, telemetry_fields_required=7,
                ))
            else:
                decisions.append(ShadowDecision(
                    event_id=f"evt_{i}", risk_tier=tier,
                    baseline_decision="amber", baseline_reason_code="TAINT",
                    shadow_decision="amber", shadow_reason_code="TAINT",
                    telemetry_fields_present=7, telemetry_fields_required=7,
                ))
        result = run_shadow_parity_test(decisions, observation_hours=25)
        # 0.1% exactly should pass (threshold is <= 0.1%)
        self.assertLessEqual(result.overblock_drift_rate, 0.001)

    def test_empty_decisions_fails(self):
        """Empty decision set fails gracefully."""
        result = run_shadow_parity_test([], observation_hours=0)
        self.assertFalse(result.promote_safe)
        self.assertIn("no_events", result.failures)


if __name__ == "__main__":
    unittest.main()
