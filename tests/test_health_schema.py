"""Unit tests for unwind.sidecar.health_schema.

Covers: key derivation, sign/verify round-trip, canonical form, freshness,
sequence tracker, and enum values.
"""

import copy
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Pre-register unwind.sidecar as a plain namespace package so importing
# unwind.sidecar.health_schema does NOT trigger unwind/sidecar/__init__.py
# (which eagerly imports server.py → fastapi, unusable on Mac/Py3.9).
if "unwind.sidecar" not in sys.modules:
    _pkg = types.ModuleType("unwind.sidecar")
    _pkg.__path__ = [str(Path(__file__).resolve().parent.parent / "unwind" / "sidecar")]
    _pkg.__package__ = "unwind.sidecar"
    sys.modules["unwind.sidecar"] = _pkg

from unwind.sidecar.health_schema import (
    SCHEMA_VERSION,
    HealthState,
    ReasonCode,
    SequenceTracker,
    check_freshness,
    derive_health_signing_key,
    get_instance_id,
    kid_for_now,
    sign_health_payload,
    verify_health_signature,
    _canonical_for_signing,
)


# ── Fixtures ──────────────────────────────────────────────────────────


def _make_payload(**overrides):
    """Build a minimal valid health payload for testing."""
    now = datetime.now(timezone.utc)
    payload = {
        "version": SCHEMA_VERSION,
        "instance_id": "test-host",
        "emitted_at": now.isoformat(),
        "fresh_until": (now + timedelta(seconds=60)).isoformat(),
        "ttl_sec": 60,
        "seq": 1,
        "state": "green",
        "reason_code": "OK",
        "detail": "All checks passed",
        "checks": {
            "sidecar_link": "ok",
            "adapter_auth": "ok",
            "watchdog_stale": False,
            "pipeline_enforcement": "ok",
            "audit_chain": "ok",
        },
        "sig": {
            "alg": "HMAC-SHA256",
            "kid": "unwind-health-2026-03",
            "value": "",
        },
        "status": "up",
        "uptimeMs": 60000,
        "engineVersion": "0.1.0-alpha",
    }
    payload.update(overrides)
    return payload


# ── Key derivation ────────────────────────────────────────────────────


class TestKeyDerivation(unittest.TestCase):

    def test_deterministic(self):
        k1 = derive_health_signing_key("secret-one")
        k2 = derive_health_signing_key("secret-one")
        self.assertEqual(k1, k2)

    def test_different_secrets_different_keys(self):
        k1 = derive_health_signing_key("secret-one")
        k2 = derive_health_signing_key("secret-two")
        self.assertNotEqual(k1, k2)

    def test_key_length_32_bytes(self):
        k = derive_health_signing_key("test-secret")
        self.assertEqual(len(k), 32)

    def test_empty_secret_still_produces_key(self):
        k = derive_health_signing_key("")
        self.assertIsInstance(k, bytes)
        self.assertEqual(len(k), 32)


# ── Signing & verification ───────────────────────────────────────────


class TestSignAndVerify(unittest.TestCase):

    def setUp(self):
        self.key = derive_health_signing_key("test-secret")
        self.payload = _make_payload()

    def test_round_trip(self):
        sig_value = sign_health_payload(self.payload, self.key)
        self.payload["sig"]["value"] = sig_value
        self.assertTrue(verify_health_signature(self.payload, self.key))

    def test_tampered_field_fails(self):
        sig_value = sign_health_payload(self.payload, self.key)
        self.payload["sig"]["value"] = sig_value
        self.payload["state"] = "red"
        self.assertFalse(verify_health_signature(self.payload, self.key))

    def test_tampered_check_field_fails(self):
        sig_value = sign_health_payload(self.payload, self.key)
        self.payload["sig"]["value"] = sig_value
        self.payload["checks"]["pipeline_enforcement"] = "fail"
        self.assertFalse(verify_health_signature(self.payload, self.key))

    def test_wrong_key_fails(self):
        sig_value = sign_health_payload(self.payload, self.key)
        self.payload["sig"]["value"] = sig_value
        wrong_key = derive_health_signing_key("wrong-secret")
        self.assertFalse(verify_health_signature(self.payload, wrong_key))

    def test_missing_sig_fails(self):
        payload = _make_payload()
        del payload["sig"]
        self.assertFalse(verify_health_signature(payload, self.key))

    def test_empty_sig_value_fails(self):
        payload = _make_payload()
        payload["sig"]["value"] = ""
        self.assertFalse(verify_health_signature(payload, self.key))

    def test_malformed_sig_value_fails(self):
        payload = _make_payload()
        payload["sig"]["value"] = "not-valid-base64url!@#$"
        self.assertFalse(verify_health_signature(payload, self.key))

    def test_sig_valid_field_excluded_from_canonical(self):
        """Adding sig_valid to the payload should not affect verification."""
        sig_value = sign_health_payload(self.payload, self.key)
        self.payload["sig"]["value"] = sig_value
        self.payload["sig_valid"] = True
        self.assertTrue(verify_health_signature(self.payload, self.key))


# ── Canonical form ────────────────────────────────────────────────────


class TestCanonicalForm(unittest.TestCase):

    def test_excludes_sig_value(self):
        payload = _make_payload()
        payload["sig"]["value"] = "should-be-stripped"
        canonical = _canonical_for_signing(payload)
        self.assertNotIn(b"should-be-stripped", canonical)

    def test_excludes_sig_valid(self):
        payload = _make_payload()
        payload["sig_valid"] = True
        canonical = _canonical_for_signing(payload)
        self.assertNotIn(b"sig_valid", canonical)

    def test_preserves_sig_alg_and_kid(self):
        payload = _make_payload()
        canonical = _canonical_for_signing(payload)
        self.assertIn(b"HMAC-SHA256", canonical)
        self.assertIn(b"unwind-health-2026-03", canonical)

    def test_deterministic(self):
        payload = _make_payload()
        c1 = _canonical_for_signing(payload)
        c2 = _canonical_for_signing(payload)
        self.assertEqual(c1, c2)

    def test_does_not_mutate_original(self):
        payload = _make_payload()
        payload["sig"]["value"] = "original"
        original_copy = copy.deepcopy(payload)
        _canonical_for_signing(payload)
        self.assertEqual(payload, original_copy)


# ── Freshness ─────────────────────────────────────────────────────────


class TestFreshness(unittest.TestCase):

    def test_future_deadline_is_fresh(self):
        future = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
        payload = {"fresh_until": future}
        self.assertTrue(check_freshness(payload))

    def test_past_deadline_is_stale(self):
        past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        payload = {"fresh_until": past}
        self.assertFalse(check_freshness(payload))

    def test_missing_fresh_until_is_stale(self):
        self.assertFalse(check_freshness({}))

    def test_non_string_fresh_until_is_stale(self):
        self.assertFalse(check_freshness({"fresh_until": 12345}))

    def test_malformed_timestamp_is_stale(self):
        self.assertFalse(check_freshness({"fresh_until": "not-a-date"}))


# ── Sequence tracker ──────────────────────────────────────────────────


class TestSequenceTracker(unittest.TestCase):

    def setUp(self):
        self.tracker = SequenceTracker()

    def test_first_seq_always_valid(self):
        valid, restart = self.tracker.check_and_update("host-a", 42)
        self.assertTrue(valid)
        self.assertFalse(restart)

    def test_increasing_seq_valid(self):
        self.tracker.check_and_update("host-a", 1)
        valid, restart = self.tracker.check_and_update("host-a", 2)
        self.assertTrue(valid)
        self.assertFalse(restart)

    def test_same_seq_invalid(self):
        self.tracker.check_and_update("host-a", 5)
        valid, restart = self.tracker.check_and_update("host-a", 5)
        self.assertFalse(valid)
        self.assertFalse(restart)

    def test_lower_seq_invalid(self):
        self.tracker.check_and_update("host-a", 10)
        valid, restart = self.tracker.check_and_update("host-a", 8)
        self.assertFalse(valid)
        self.assertFalse(restart)

    def test_seq_1_after_higher_is_restart(self):
        self.tracker.check_and_update("host-a", 100)
        valid, restart = self.tracker.check_and_update("host-a", 1)
        self.assertTrue(valid)
        self.assertTrue(restart)

    def test_seq_1_after_1_is_replay_not_restart(self):
        self.tracker.check_and_update("host-a", 1)
        valid, restart = self.tracker.check_and_update("host-a", 1)
        self.assertFalse(valid)
        self.assertFalse(restart)

    def test_independent_instances(self):
        self.tracker.check_and_update("host-a", 10)
        valid_b, _ = self.tracker.check_and_update("host-b", 1)
        self.assertTrue(valid_b)
        # host-a still tracks independently
        valid_a, _ = self.tracker.check_and_update("host-a", 11)
        self.assertTrue(valid_a)

    def test_reset_clears_all(self):
        self.tracker.check_and_update("host-a", 10)
        self.tracker.reset()
        valid, restart = self.tracker.check_and_update("host-a", 1)
        self.assertTrue(valid)
        self.assertFalse(restart)  # No prior state → not a restart


# ── Enum values ───────────────────────────────────────────────────────


class TestEnumValues(unittest.TestCase):

    def test_health_states(self):
        self.assertEqual(HealthState.GREEN.value, "green")
        self.assertEqual(HealthState.AMBER.value, "amber")
        self.assertEqual(HealthState.RED.value, "red")

    def test_reason_codes_match_spec(self):
        expected = {
            "OK", "UNKNOWN_SOURCE", "SIGNATURE_INVALID", "PAYLOAD_STALE",
            "SEQ_REPLAY_OR_ROLLBACK", "SIDECAR_UNREACHABLE", "GATEWAY_UNHEALTHY",
            "ADAPTER_AUTH_FAIL_401", "WATCHDOG_STALE", "PIPELINE_INVARIANT_FAIL",
            "AUDIT_CHAIN_DEGRADED",
        }
        actual = {rc.value for rc in ReasonCode}
        self.assertEqual(expected, actual)


# ── Helpers ───────────────────────────────────────────────────────────


class TestHelpers(unittest.TestCase):

    def test_get_instance_id_returns_string(self):
        iid = get_instance_id()
        self.assertIsInstance(iid, str)
        self.assertTrue(len(iid) > 0)

    def test_kid_for_now_format(self):
        kid = kid_for_now()
        self.assertTrue(kid.startswith("unwind-health-"))
        # Should be like "unwind-health-2026-03"
        parts = kid.split("-")
        self.assertEqual(len(parts), 4)

    def test_schema_version_constant(self):
        self.assertEqual(SCHEMA_VERSION, "unwind.system_health.v1")


if __name__ == "__main__":
    unittest.main()
