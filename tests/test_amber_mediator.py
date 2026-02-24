"""Tests for the Amber Mediator Protocol (R-AMBER-MED-001).

Verifies pattern ID stability, batch hint construction, challenge nonce
generation, action hash binding, and risk capsule integrity.
"""

import unittest
import time

from unwind.enforcement.amber_mediator import (
    build_pattern_id,
    build_batch_hint,
    new_challenge_nonce,
    challenge_expires_at,
    compute_action_hash,
    derive_destination_scope,
    build_risk_capsule,
    hash_risk_capsule,
    AMBER_BATCH_CAPS,
    CHALLENGE_NONCE_BYTES,
)


class TestPatternId(unittest.TestCase):
    """Pattern ID generation tests."""

    def test_deterministic(self):
        """Same inputs produce same pattern_id."""
        pid1 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./docs/",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
        )
        pid2 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./docs/",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
        )
        self.assertEqual(pid1, pid2)

    def test_different_tool_different_id(self):
        """Different tool names produce different pattern IDs."""
        pid1 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
        )
        pid2 = build_pattern_id(
            tool_name="send_email",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
        )
        self.assertNotEqual(pid1, pid2)

    def test_different_scope_different_id(self):
        """Different destination scopes produce different pattern IDs."""
        pid1 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./docs/",
            risk_tier="AMBER_HIGH",
        )
        pid2 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./src/",
            risk_tier="AMBER_HIGH",
        )
        self.assertNotEqual(pid1, pid2)

    def test_prefix(self):
        """Pattern ID starts with 'pat_'."""
        pid = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
        )
        self.assertTrue(pid.startswith("pat_"))

    def test_reason_codes_order_independent(self):
        """Reason codes are sorted for stable hashing."""
        pid1 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            reason_codes=["TAINT_HIGH", "SENSOR_PIVOT"],
        )
        pid2 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            reason_codes=["SENSOR_PIVOT", "TAINT_HIGH"],
        )
        self.assertEqual(pid1, pid2)

    def test_case_normalization(self):
        """Risk tier and taint level are normalized to upper case."""
        pid1 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="amber_high",
            taint_level="high",
        )
        pid2 = build_pattern_id(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
        )
        self.assertEqual(pid1, pid2)


class TestBatchHint(unittest.TestCase):
    """Batch hint construction tests."""

    def test_batch_caps_low(self):
        """AMBER_LOW gets max_batch_size=20, batchable=True."""
        hint = build_batch_hint(
            session_id="sess_1",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_LOW",
            pattern_id="pat_abc",
        )
        self.assertEqual(hint["max_batch_size"], 20)
        self.assertTrue(hint["batchable"])

    def test_batch_caps_high(self):
        """AMBER_HIGH gets max_batch_size=5, batchable=True."""
        hint = build_batch_hint(
            session_id="sess_1",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            pattern_id="pat_abc",
        )
        self.assertEqual(hint["max_batch_size"], 5)
        self.assertTrue(hint["batchable"])

    def test_batch_caps_critical(self):
        """AMBER_CRITICAL gets max_batch_size=1, batchable=False."""
        hint = build_batch_hint(
            session_id="sess_1",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_CRITICAL",
            pattern_id="pat_abc",
        )
        self.assertEqual(hint["max_batch_size"], 1)
        self.assertFalse(hint["batchable"])

    def test_group_key_prefix(self):
        """Group key starts with 'grp_'."""
        hint = build_batch_hint(
            session_id="sess_1",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            pattern_id="pat_abc",
        )
        self.assertTrue(hint["group_key"].startswith("grp_"))

    def test_different_sessions_different_groups(self):
        """Different sessions produce different group keys."""
        hint1 = build_batch_hint(
            session_id="sess_1",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            pattern_id="pat_abc",
        )
        hint2 = build_batch_hint(
            session_id="sess_2",
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            pattern_id="pat_abc",
        )
        self.assertNotEqual(hint1["group_key"], hint2["group_key"])


class TestChallengeNonce(unittest.TestCase):
    """Challenge nonce generation tests."""

    def test_length(self):
        """Nonce should be ~32 chars (24 bytes base64url)."""
        nonce = new_challenge_nonce()
        self.assertGreaterEqual(len(nonce), 30)
        self.assertLessEqual(len(nonce), 36)

    def test_uniqueness(self):
        """Two nonces should never be the same."""
        n1 = new_challenge_nonce()
        n2 = new_challenge_nonce()
        self.assertNotEqual(n1, n2)

    def test_no_padding(self):
        """Nonce should not contain base64 padding characters."""
        nonce = new_challenge_nonce()
        self.assertNotIn("=", nonce)

    def test_url_safe(self):
        """Nonce should only contain base64url characters."""
        import re
        nonce = new_challenge_nonce()
        self.assertRegex(nonce, r"^[A-Za-z0-9_-]+$")


class TestChallengeExpiry(unittest.TestCase):
    """Challenge expiry timestamp tests."""

    def test_format(self):
        """Expiry should be ISO 8601 UTC with Z suffix."""
        exp = challenge_expires_at()
        self.assertTrue(exp.endswith("Z"))

    def test_future(self):
        """Expiry should be in the future."""
        from datetime import datetime, timezone
        exp = challenge_expires_at()
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        self.assertGreater(exp_dt, now)


class TestActionHash(unittest.TestCase):
    """Action hash binding tests."""

    def test_deterministic(self):
        """Same tool+args produce same hash."""
        h1 = compute_action_hash("fs_write", {"path": "./test.txt", "content": "hello"})
        h2 = compute_action_hash("fs_write", {"path": "./test.txt", "content": "hello"})
        self.assertEqual(h1, h2)

    def test_canonical_json_key_order_independent(self):
        """Dict insertion order does not affect hash (canonical JSON regression).

        This is the AMBER-GO-01 regression test: proves sort_keys=True
        produces identical bytes regardless of Python dict ordering.
        """
        import collections
        # Build two dicts with different insertion orders
        args_a = collections.OrderedDict([("path", "./x.txt"), ("content", "data"), ("mode", "w")])
        args_b = collections.OrderedDict([("mode", "w"), ("content", "data"), ("path", "./x.txt")])
        h_a = compute_action_hash("fs_write", dict(args_a))
        h_b = compute_action_hash("fs_write", dict(args_b))
        self.assertEqual(h_a, h_b, "action_hash must be key-order independent (canonical JSON)")

    def test_canonical_json_bytes_match(self):
        """Verify the exact canonical serialisation matches expected bytes.

        Regression test: if the serialisation method ever changes,
        existing action_hash values would break token bindings.
        """
        import hashlib as hl, json as j
        tool = "fs_write"
        args = {"path": "./test.txt", "content": "hello"}
        # Manually compute what _stable_json_hash should produce
        material = {"tool_name": tool, "arguments": args}
        expected_blob = j.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_hex = hl.sha256(expected_blob).hexdigest()[:32]
        expected_hash = f"act_{expected_hex}"
        actual = compute_action_hash(tool, args)
        self.assertEqual(actual, expected_hash, "action_hash must match manual canonical computation")

    def test_different_args_different_hash(self):
        """Different args produce different hash."""
        h1 = compute_action_hash("fs_write", {"path": "./a.txt"})
        h2 = compute_action_hash("fs_write", {"path": "./b.txt"})
        self.assertNotEqual(h1, h2)

    def test_prefix(self):
        """Action hash starts with 'act_'."""
        h = compute_action_hash("fs_write", {"path": "./test.txt"})
        self.assertTrue(h.startswith("act_"))

    def test_parameter_drift_detected(self):
        """Changing content produces different hash (confused deputy protection)."""
        h1 = compute_action_hash("fs_write", {"path": "./test.txt", "content": "safe"})
        h2 = compute_action_hash("fs_write", {"path": "./test.txt", "content": "MALICIOUS"})
        self.assertNotEqual(h1, h2)


class TestDestinationScope(unittest.TestCase):
    """Destination scope derivation tests."""

    def test_file_scope_uses_parent(self):
        """File path scope is the parent directory."""
        scope = derive_destination_scope("fs_write", {"path": "./docs/report.md"})
        self.assertEqual(scope, "./docs/")

    def test_file_scope_root(self):
        """File in current dir gets './' scope."""
        scope = derive_destination_scope("fs_write", {"path": "test.txt"})
        self.assertEqual(scope, "./")

    def test_email_scope_uses_domain(self):
        """Email scope is the recipient domain."""
        scope = derive_destination_scope("send_email", {"to": "user@example.com"})
        self.assertEqual(scope, "example.com")

    def test_unknown_scope(self):
        """No recognizable args produces 'unknown_scope'."""
        scope = derive_destination_scope("mystery_tool", {"foo": "bar"})
        self.assertEqual(scope, "unknown_scope")

    def test_none_args(self):
        """None arguments produce 'unknown_scope'."""
        scope = derive_destination_scope("fs_write", None)
        self.assertEqual(scope, "unknown_scope")


class TestRiskCapsule(unittest.TestCase):
    """Risk capsule integrity tests."""

    def test_capsule_contains_required_fields(self):
        """Risk capsule has all required fields."""
        capsule = build_risk_capsule(
            tool_name="fs_write",
            destination_scope="./docs/",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
            reason_codes=["TAINT_PIVOT"],
            amber_reason="Tainted session attempting write",
        )
        self.assertIn("tool_name", capsule)
        self.assertIn("destination_scope", capsule)
        self.assertIn("risk_tier", capsule)
        self.assertIn("taint_level", capsule)
        self.assertIn("reason_codes", capsule)
        self.assertIn("human_summary", capsule)

    def test_capsule_hash_deterministic(self):
        """Same capsule produces same hash."""
        capsule = build_risk_capsule(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
        )
        h1 = hash_risk_capsule(capsule)
        h2 = hash_risk_capsule(capsule)
        self.assertEqual(h1, h2)

    def test_capsule_hash_prefix(self):
        """Capsule hash starts with 'cap_'."""
        capsule = build_risk_capsule(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
        )
        h = hash_risk_capsule(capsule)
        self.assertTrue(h.startswith("cap_"))

    def test_tampered_capsule_different_hash(self):
        """Modifying capsule changes the hash (tamper detection)."""
        capsule = build_risk_capsule(
            tool_name="fs_write",
            destination_scope="./",
            risk_tier="AMBER_HIGH",
            taint_level="HIGH",
            amber_reason="Real danger warning",
        )
        h1 = hash_risk_capsule(capsule)

        # Mediator tries to downplay the risk
        tampered = dict(capsule)
        tampered["human_summary"] = "Everything is fine, just approve"
        h2 = hash_risk_capsule(tampered)

        self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
