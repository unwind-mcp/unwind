"""Tests for DNS Pinning (R-NET-004) — defeat DNS rebinding attacks.

DNS rebinding attack: attacker controls DNS for evil.com.
First resolve: evil.com → 1.2.3.4 (public, passes SSRF check)
Second resolve: evil.com → 192.168.0.1 (private, bypasses SSRF)

UNWIND pins the first resolution and rejects if IPs change within the TTL window.
"""

import time
import unittest
from unittest.mock import patch

from tests.test_enforcement import TestConfig
from unwind.enforcement.ssrf_shield import SSRFShieldCheck


class TestDNSPinning(unittest.TestCase):
    """Test DNS pinning cache behaviour."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = SSRFShieldCheck(self.config)

    def test_first_resolve_pins_ips(self):
        """First resolve should pin hostname → IPs."""
        result = self.check._check_dns_pin("example.com", ["93.184.216.34"])
        self.assertIsNone(result)  # No error
        self.assertIn("example.com", self.check._dns_pins)
        pinned_ips, _ = self.check._dns_pins["example.com"]
        self.assertEqual(pinned_ips, frozenset({"93.184.216.34"}))

    def test_same_ips_accepted(self):
        """Subsequent resolve with same IPs should pass."""
        self.check._check_dns_pin("example.com", ["93.184.216.34"])
        result = self.check._check_dns_pin("example.com", ["93.184.216.34"])
        self.assertIsNone(result)

    def test_same_ips_different_order(self):
        """Same IPs in different order should pass (frozenset comparison)."""
        self.check._check_dns_pin("example.com", ["1.2.3.4", "5.6.7.8"])
        result = self.check._check_dns_pin("example.com", ["5.6.7.8", "1.2.3.4"])
        self.assertIsNone(result)

    def test_different_ips_rejected(self):
        """Changed IPs within TTL should be rejected (DNS rebinding)."""
        self.check._check_dns_pin("evil.com", ["1.2.3.4"])
        result = self.check._check_dns_pin("evil.com", ["192.168.1.1"])
        self.assertIsNotNone(result)
        self.assertIn("DNS pin violation", result)
        self.assertIn("R-NET-004", result)

    def test_added_ip_rejected(self):
        """Adding new IPs to existing pin should be rejected."""
        self.check._check_dns_pin("tricky.com", ["1.2.3.4"])
        result = self.check._check_dns_pin("tricky.com", ["1.2.3.4", "10.0.0.1"])
        self.assertIsNotNone(result)
        self.assertIn("DNS pin violation", result)

    def test_removed_ip_rejected(self):
        """Removing IPs from existing pin should be rejected."""
        self.check._check_dns_pin("flaky.com", ["1.2.3.4", "5.6.7.8"])
        result = self.check._check_dns_pin("flaky.com", ["1.2.3.4"])
        self.assertIsNotNone(result)
        self.assertIn("DNS pin violation", result)

    def test_different_hostnames_independent(self):
        """Pins for different hostnames must be independent."""
        self.check._check_dns_pin("alpha.com", ["1.1.1.1"])
        self.check._check_dns_pin("beta.com", ["2.2.2.2"])

        # Each should still validate against its own pin
        result_alpha = self.check._check_dns_pin("alpha.com", ["1.1.1.1"])
        result_beta = self.check._check_dns_pin("beta.com", ["2.2.2.2"])
        self.assertIsNone(result_alpha)
        self.assertIsNone(result_beta)

        # Cross-check should fail
        result_cross = self.check._check_dns_pin("alpha.com", ["2.2.2.2"])
        self.assertIsNotNone(result_cross)

    def test_ttl_expiry_allows_repin(self):
        """After TTL expires, re-resolve with new IPs should be accepted."""
        self.check._dns_pin_ttl = 0.1  # 100ms TTL for testing

        self.check._check_dns_pin("rotating.com", ["1.2.3.4"])
        time.sleep(0.15)  # Wait for TTL to expire

        # New IPs should now be accepted (re-pin)
        result = self.check._check_dns_pin("rotating.com", ["5.6.7.8"])
        self.assertIsNone(result)

        # Verify re-pinned
        pinned_ips, _ = self.check._dns_pins["rotating.com"]
        self.assertEqual(pinned_ips, frozenset({"5.6.7.8"}))

    def test_ttl_not_expired_rejects(self):
        """Within TTL, changed IPs should still be rejected."""
        self.check._dns_pin_ttl = 10.0  # Long TTL

        self.check._check_dns_pin("stable.com", ["1.2.3.4"])
        result = self.check._check_dns_pin("stable.com", ["9.9.9.9"])
        self.assertIsNotNone(result)

    def test_clear_pins(self):
        """clear_dns_pins should wipe all pins."""
        self.check._check_dns_pin("a.com", ["1.1.1.1"])
        self.check._check_dns_pin("b.com", ["2.2.2.2"])
        self.assertEqual(len(self.check._dns_pins), 2)

        self.check.clear_dns_pins()
        self.assertEqual(len(self.check._dns_pins), 0)

    def test_clear_pins_allows_new_resolution(self):
        """After clearing, the same hostname can pin to different IPs."""
        self.check._check_dns_pin("cleared.com", ["1.2.3.4"])
        self.check.clear_dns_pins()

        result = self.check._check_dns_pin("cleared.com", ["9.8.7.6"])
        self.assertIsNone(result)

    def test_error_message_contains_old_and_new_ips(self):
        """Error message should show both pinned and current IPs for debugging."""
        self.check._check_dns_pin("debug.com", ["1.2.3.4"])
        result = self.check._check_dns_pin("debug.com", ["10.0.0.1"])
        self.assertIn("1.2.3.4", result)
        self.assertIn("10.0.0.1", result)


class TestDNSPinningIntegration(unittest.TestCase):
    """Test DNS pinning through the full SSRF check() flow."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = SSRFShieldCheck(self.config)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_rebinding_attack_blocked(self, mock_resolve):
        """Simulate DNS rebinding: first resolve public, second resolve different public."""
        # First request: resolves to public IP → allowed
        mock_resolve.return_value = ["93.184.216.34"]
        result1 = self.check.check("https://evil.com/api")
        self.assertIsNone(result1)

        # Second request: DNS rebinds to different public IP → blocked by pin
        mock_resolve.return_value = ["104.18.32.7"]
        result2 = self.check.check("https://evil.com/api")
        self.assertIsNotNone(result2)
        self.assertIn("DNS pin violation", result2)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_rebinding_to_private_caught_by_cidr(self, mock_resolve):
        """Rebinding to private IP is caught by CIDR check before pin check."""
        mock_resolve.return_value = ["93.184.216.34"]
        self.check.check("https://evil.com/warmup")

        # Rebind to private — CIDR catches it first (correct behaviour)
        mock_resolve.return_value = ["192.168.1.1"]
        result = self.check.check("https://evil.com/steal")
        self.assertIsNotNone(result)
        self.assertIn("blocked IP", result)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_stable_dns_passes(self, mock_resolve):
        """Stable DNS (same IPs) should pass pin check."""
        mock_resolve.return_value = ["93.184.216.34"]
        result1 = self.check.check("https://stable.com/api")
        self.assertIsNone(result1)

        result2 = self.check.check("https://stable.com/api")
        self.assertIsNone(result2)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_rebinding_to_metadata_blocked(self, mock_resolve):
        """Rebinding to cloud metadata IP should be blocked by CIDR check first."""
        mock_resolve.return_value = ["93.184.216.34"]
        self.check.check("https://attacker.com/setup")

        # Rebind to metadata
        mock_resolve.return_value = ["169.254.169.254"]
        result = self.check.check("https://attacker.com/steal-creds")
        self.assertIsNotNone(result)
        # Could be caught by CIDR check OR pin violation — both are valid
        self.assertIn("SSRF Shield", result)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_rebinding_to_localhost_blocked(self, mock_resolve):
        """Rebinding to localhost should be blocked."""
        mock_resolve.return_value = ["203.0.113.1"]
        self.check.check("https://evil.com/warmup")

        mock_resolve.return_value = ["127.0.0.1"]
        result = self.check.check("https://evil.com/pwn")
        self.assertIsNotNone(result)

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_ip_literal_bypasses_pinning(self, mock_resolve):
        """Direct IP URLs don't need DNS pinning (no DNS to rebind)."""
        # IP literals go through the IP block check directly, not DNS resolve
        result = self.check.check("https://93.184.216.34/api")
        self.assertIsNone(result)
        mock_resolve.assert_not_called()

    @patch.object(SSRFShieldCheck, '_resolve_hostname')
    def test_multiple_hosts_pinned_independently(self, mock_resolve):
        """Different hostnames should have independent pins."""
        mock_resolve.return_value = ["1.1.1.1"]
        self.check.check("https://one.com/")

        mock_resolve.return_value = ["2.2.2.2"]
        self.check.check("https://two.com/")

        # Verify one.com still pinned to 1.1.1.1
        mock_resolve.return_value = ["9.9.9.9"]
        result = self.check.check("https://one.com/steal")
        self.assertIsNotNone(result)
        self.assertIn("DNS pin violation", result)


if __name__ == "__main__":
    unittest.main()
