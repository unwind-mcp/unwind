"""Tests for startup config validator.

Every validation case is tested: valid config passes, each invalid
config field triggers a specific error with a fix hint.
"""

import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.startup_validator import validate_config, validate_and_enforce


class TestValidConfigPasses(unittest.TestCase):
    """Default config must pass all validation."""

    def test_default_config_is_valid(self):
        config = UnwindConfig()
        result = validate_config(config)
        self.assertTrue(result.valid, f"Default config failed: {result.format_errors()}")

    def test_valid_result_has_no_errors(self):
        config = UnwindConfig()
        result = validate_config(config)
        self.assertEqual(len(result.errors), 0)


class TestDLPEntropyThreshold(unittest.TestCase):
    """dlp_entropy_threshold must be positive and ≤ 8.0."""

    def test_zero_threshold_fails(self):
        config = UnwindConfig(dlp_entropy_threshold=0.0)
        result = validate_config(config)
        self.assertFalse(result.valid)
        self.assertTrue(any("dlp_entropy_threshold" in e.field_name for e in result.errors))

    def test_negative_threshold_fails(self):
        config = UnwindConfig(dlp_entropy_threshold=-1.0)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_over_8_fails(self):
        config = UnwindConfig(dlp_entropy_threshold=8.5)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_valid_threshold_passes(self):
        config = UnwindConfig(dlp_entropy_threshold=5.7)
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "dlp_entropy_threshold"]
        self.assertEqual(len(errors), 0)


class TestCircuitBreakerLimits(unittest.TestCase):
    """circuit_breaker_max_calls must be ≥ 1, window must be positive."""

    def test_zero_calls_fails(self):
        config = UnwindConfig(circuit_breaker_max_calls=0)
        result = validate_config(config)
        self.assertFalse(result.valid)
        self.assertTrue(any("circuit_breaker_max_calls" in e.field_name for e in result.errors))

    def test_negative_calls_fails(self):
        config = UnwindConfig(circuit_breaker_max_calls=-5)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_zero_window_fails(self):
        config = UnwindConfig(circuit_breaker_window_seconds=0.0)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_negative_window_fails(self):
        config = UnwindConfig(circuit_breaker_window_seconds=-1.0)
        result = validate_config(config)
        self.assertFalse(result.valid)


class TestDLPScanBytes(unittest.TestCase):
    """dlp_scan_bytes must be 256–10MB."""

    def test_too_small_fails(self):
        config = UnwindConfig(dlp_scan_bytes=100)
        result = validate_config(config)
        self.assertFalse(result.valid)
        self.assertTrue(any("dlp_scan_bytes" in e.field_name for e in result.errors))

    def test_too_large_fails(self):
        config = UnwindConfig(dlp_scan_bytes=20 * 1024 * 1024)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_valid_size_passes(self):
        config = UnwindConfig(dlp_scan_bytes=8192)
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "dlp_scan_bytes"]
        self.assertEqual(len(errors), 0)


class TestGhostNetworkPolicy(unittest.TestCase):
    """ghost_network_policy must be isolate, ask, or filtered."""

    def test_invalid_policy_fails(self):
        config = UnwindConfig(ghost_network_policy="block_all")
        result = validate_config(config)
        self.assertFalse(result.valid)
        self.assertTrue(any("ghost_network_policy" in e.field_name for e in result.errors))

    def test_typo_fails(self):
        config = UnwindConfig(ghost_network_policy="isolat")
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_isolate_passes(self):
        config = UnwindConfig(ghost_network_policy="isolate")
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "ghost_network_policy"]
        self.assertEqual(len(errors), 0)

    def test_ask_passes(self):
        config = UnwindConfig(ghost_network_policy="ask")
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "ghost_network_policy"]
        self.assertEqual(len(errors), 0)

    def test_filtered_passes(self):
        config = UnwindConfig(ghost_network_policy="filtered")
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "ghost_network_policy"]
        self.assertEqual(len(errors), 0)


class TestGhostAllowlistTTL(unittest.TestCase):
    """ghost_network_allowlist_ttl_seconds must be non-negative."""

    def test_negative_ttl_fails(self):
        config = UnwindConfig(ghost_network_allowlist_ttl_seconds=-1.0)
        result = validate_config(config)
        self.assertFalse(result.valid)

    def test_zero_passes(self):
        config = UnwindConfig(ghost_network_allowlist_ttl_seconds=0.0)
        result = validate_config(config)
        errors = [e for e in result.errors if e.field_name == "ghost_network_allowlist_ttl_seconds"]
        self.assertEqual(len(errors), 0)


class TestCanaryTools(unittest.TestCase):
    """Canary tool set must not be empty."""

    def test_empty_canary_fails(self):
        config = UnwindConfig(canary_tools=frozenset())
        result = validate_config(config)
        self.assertFalse(result.valid)
        self.assertTrue(any("canary_tools" in e.field_name for e in result.errors))


class TestToolClassificationSets(unittest.TestCase):
    """Critical tool classification sets must not be empty."""

    def test_empty_network_tools_fails(self):
        config = UnwindConfig(network_tools=frozenset())
        result = validate_config(config)
        self.assertTrue(any("network_tools" in e.field_name for e in result.errors))

    def test_empty_sensor_tools_fails(self):
        config = UnwindConfig(sensor_tools=frozenset())
        result = validate_config(config)
        self.assertTrue(any("sensor_tools" in e.field_name for e in result.errors))

    def test_empty_state_modifying_fails(self):
        config = UnwindConfig(state_modifying_tools=frozenset())
        result = validate_config(config)
        self.assertTrue(any("state_modifying_tools" in e.field_name for e in result.errors))

    def test_empty_ghost_egress_fails(self):
        config = UnwindConfig(ghost_egress_tools=frozenset())
        result = validate_config(config)
        self.assertTrue(any("ghost_egress_tools" in e.field_name for e in result.errors))


class TestPermissionTier(unittest.TestCase):
    """default_permission_tier must be 1-4."""

    def test_zero_fails(self):
        config = UnwindConfig(default_permission_tier=0)
        result = validate_config(config)
        self.assertTrue(any("default_permission_tier" in e.field_name for e in result.errors))

    def test_five_fails(self):
        config = UnwindConfig(default_permission_tier=5)
        result = validate_config(config)
        self.assertTrue(any("default_permission_tier" in e.field_name for e in result.errors))


class TestUnknownToolPolicy(unittest.TestCase):
    """unknown_tool_policy must be hide, tier1, or show."""

    def test_invalid_fails(self):
        config = UnwindConfig(unknown_tool_policy="allow")
        result = validate_config(config)
        self.assertTrue(any("unknown_tool_policy" in e.field_name for e in result.errors))


class TestSSRFCIDRList(unittest.TestCase):
    """SSRF blocked CIDR list must not be empty."""

    def test_empty_cidrs_fails(self):
        config = UnwindConfig(ssrf_blocked_cidrs=[])
        result = validate_config(config)
        self.assertTrue(any("ssrf_blocked_cidrs" in e.field_name for e in result.errors))


class TestTaintDecaySeconds(unittest.TestCase):
    """taint_decay_seconds must be non-negative."""

    def test_negative_fails(self):
        config = UnwindConfig(taint_decay_seconds=-10.0)
        result = validate_config(config)
        self.assertTrue(any("taint_decay_seconds" in e.field_name for e in result.errors))


class TestSnapshotRetention(unittest.TestCase):
    """snapshot_retention_days must be ≥ 1, storage ≥ 1MB."""

    def test_zero_days_fails(self):
        config = UnwindConfig(snapshot_retention_days=0)
        result = validate_config(config)
        self.assertTrue(any("snapshot_retention_days" in e.field_name for e in result.errors))

    def test_tiny_storage_fails(self):
        config = UnwindConfig(snapshot_max_storage_bytes=1000)
        result = validate_config(config)
        self.assertTrue(any("snapshot_max_storage_bytes" in e.field_name for e in result.errors))


class TestValidateAndEnforce(unittest.TestCase):
    """validate_and_enforce must raise SystemExit on invalid config."""

    def test_valid_config_does_not_exit(self):
        config = UnwindConfig()
        # Should not raise
        validate_and_enforce(config)

    def test_invalid_config_raises_system_exit(self):
        config = UnwindConfig(dlp_entropy_threshold=-1.0)
        with self.assertRaises(SystemExit) as ctx:
            validate_and_enforce(config)
        self.assertEqual(ctx.exception.code, 1)


class TestErrorFormatting(unittest.TestCase):
    """Error output must be plain English with fix hints."""

    def test_format_includes_field_name(self):
        config = UnwindConfig(dlp_entropy_threshold=-1.0)
        result = validate_config(config)
        output = result.format_errors()
        self.assertIn("dlp_entropy_threshold", output)

    def test_format_includes_fix_hint(self):
        config = UnwindConfig(ghost_network_policy="typo")
        result = validate_config(config)
        output = result.format_errors()
        self.assertIn("Fix:", output)
        self.assertIn("isolate", output)

    def test_format_includes_refusal_message(self):
        config = UnwindConfig(circuit_breaker_max_calls=0)
        result = validate_config(config)
        output = result.format_errors()
        self.assertIn("UNWIND will not start", output)

    def test_multiple_errors_all_shown(self):
        config = UnwindConfig(
            dlp_entropy_threshold=-1.0,
            circuit_breaker_max_calls=0,
            ghost_network_policy="invalid",
        )
        result = validate_config(config)
        self.assertGreaterEqual(len(result.errors), 3)
        output = result.format_errors()
        self.assertIn("[1]", output)
        self.assertIn("[2]", output)
        self.assertIn("[3]", output)


if __name__ == "__main__":
    unittest.main()
