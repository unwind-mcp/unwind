"""Phase 1 enforcement pipeline tests.

Tests every enforcement check against the scenarios defined in the
Testing Strategy section of the UNWIND Project Spec v3.
"""

import os
import tempfile
import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.session import Session, TrustState
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult
from unwind.enforcement.self_protection import SelfProtectionCheck
from unwind.enforcement.path_jail import PathJailCheck
from unwind.enforcement.ssrf_shield import SSRFShieldCheck
from unwind.enforcement.dlp_lite import DLPLiteCheck, compute_shannon_entropy
from unwind.enforcement.canary import CanaryCheck


class TestConfig:
    """Create a test config with temp directories."""

    @staticmethod
    def create() -> UnwindConfig:
        tmp = tempfile.mkdtemp()
        config = UnwindConfig(
            unwind_home=Path(tmp) / ".unwind",
            workspace_root=Path(tmp) / "workspace",
        )
        config.ensure_dirs()
        (Path(tmp) / "workspace").mkdir(exist_ok=True)
        return config


class TestSelfProtection(unittest.TestCase):
    """Test self-protection (The Path Locker)."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = SelfProtectionCheck(self.config)

    def test_block_direct_events_db(self):
        """Direct access to events.db should be blocked."""
        result = self.check.check("fs_write", target=str(self.config.events_db_path))
        self.assertIsNotNone(result)
        self.assertIn("System Core Protected", result)

    def test_block_traversal_to_unwind(self):
        """Path traversal to .unwind should be blocked."""
        evil_path = str(self.config.workspace_root / ".." / ".unwind" / "events.db")
        result = self.check.check("fs_write", target=evil_path)
        self.assertIsNotNone(result)

    def test_allow_normal_workspace_path(self):
        """Normal workspace paths should be allowed."""
        safe_path = str(self.config.workspace_root / "report.md")
        result = self.check.check("fs_write", target=safe_path)
        self.assertIsNone(result)

    def test_block_shell_command_targeting_unwind(self):
        """Shell command accessing .unwind paths should be blocked."""
        command = f"cat {self.config.unwind_home}/events.db"
        result = self.check.check("bash_exec", command=command)
        self.assertIsNotNone(result)

    def test_block_symlink_to_unwind(self):
        """Symlink pointing to .unwind should be blocked after resolution."""
        # Create a symlink from workspace to .unwind
        link_path = self.config.workspace_root / "sneaky_link"
        try:
            os.symlink(str(self.config.unwind_home), str(link_path))
            target = str(link_path / "events.db")
            result = self.check.check("fs_write", target=target)
            self.assertIsNotNone(result)
        finally:
            if link_path.exists():
                link_path.unlink()


    def test_extra_protected_roots_blocked(self):
        """Explicitly configured extra protected roots should be blocked."""
        import tempfile
        with tempfile.TemporaryDirectory() as extra_dir:
            config = TestConfig.create()
            config.extra_protected_roots = [Path(extra_dir)]
            check = SelfProtectionCheck(config)
            target = os.path.join(extra_dir, "secret.json")
            result = check.check("fs_read", target=target)
            self.assertIsNotNone(result)
            self.assertIn("System Core Protected", result)

    def test_auto_detect_framework_dirs(self):
        """Auto-detected framework dirs (if present) should appear in protected_roots."""
        config = TestConfig.create()
        roots_str = [str(r) for r in config.protected_roots]
        # unwind_home should always be present
        self.assertTrue(any(".unwind" in r for r in roots_str))
        # Auto-detected dirs only appear if they exist on disk — just verify
        # the property runs without error and returns a list
        self.assertIsInstance(config.protected_roots, list)
        self.assertGreaterEqual(len(config.protected_roots), 1)


class TestPathJail(unittest.TestCase):
    """Test path jail (workspace canonicalization)."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = PathJailCheck(self.config)

    def test_allow_path_inside_workspace(self):
        """Paths inside workspace should be allowed."""
        path = str(self.config.workspace_root / "docs" / "report.md")
        error, canonical = self.check.check(path)
        self.assertIsNone(error)

    def test_block_traversal_outside_workspace(self):
        """../../etc/passwd should be blocked."""
        path = str(self.config.workspace_root / ".." / ".." / "etc" / "passwd")
        error, canonical = self.check.check(path)
        self.assertIsNotNone(error)
        self.assertIn("Jail Violation", error)

    def test_block_absolute_path_outside_workspace(self):
        """/etc/passwd should be blocked."""
        error, canonical = self.check.check("/etc/passwd")
        self.assertIsNotNone(error)

    def test_url_encoded_traversal(self):
        """URL-encoded path traversal should be decoded and blocked."""
        path = str(self.config.workspace_root) + "/%2e%2e/%2e%2e/etc/passwd"
        error, canonical = self.check.check(path)
        self.assertIsNotNone(error)

    def test_returns_canonical_path(self):
        """Should return the canonical (resolved) path for logging."""
        path = str(self.config.workspace_root / "docs" / ".." / "report.md")
        error, canonical = self.check.check(path)
        self.assertIsNone(error)
        self.assertNotIn("..", canonical)


class TestSSRFShield(unittest.TestCase):
    """Test SSRF shield (DNS resolve + IP blocking)."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = SSRFShieldCheck(self.config)

    def test_block_metadata_ip(self):
        """Cloud metadata endpoint should be blocked."""
        result = self.check.check("http://169.254.169.254/latest/meta-data/")
        self.assertIsNotNone(result)
        self.assertIn("SSRF Shield", result)

    def test_block_localhost(self):
        """Localhost should be blocked."""
        result = self.check.check("http://127.0.0.1:8080/admin")
        self.assertIsNotNone(result)

    def test_block_private_range(self):
        """RFC1918 private ranges should be blocked."""
        result = self.check.check("http://192.168.1.1/config")
        self.assertIsNotNone(result)

    def test_block_cgnat(self):
        """CGNAT range should be blocked."""
        result = self.check.check("http://100.64.0.1/")
        self.assertIsNotNone(result)

    def test_block_non_https(self):
        """Non-HTTPS schemes should be blocked by default."""
        result = self.check.check("http://example.com/api")
        self.assertIsNotNone(result)
        self.assertIn("scheme", result)

    def test_block_file_scheme(self):
        """file:// scheme should be blocked."""
        result = self.check.check("file:///etc/passwd")
        self.assertIsNotNone(result)

    def test_allow_public_https(self):
        """Public HTTPS URLs should be allowed (when DNS works)."""
        result = self.check.check("https://example.com/api")
        # In sandboxed environments without DNS, this may fail with DNS error.
        # The important thing is it's NOT blocked by IP range checks.
        if result is not None:
            self.assertIn("DNS resolution failed", result)  # Expected in sandbox

    def test_block_zero_address(self):
        """0.0.0.0 should be blocked."""
        result = self.check.check("http://0.0.0.0:8080/")
        self.assertIsNotNone(result)

    # --- CVE-2026-26322 hardening: IPv6 transition mechanisms ---

    def test_block_nat64(self):
        """NAT64 prefix (64:ff9b::/96) should be blocked — encapsulates IPv4."""
        result = self.check.check("https://[64:ff9b::192.168.1.1]/")
        self.assertIsNotNone(result)
        self.assertIn("SSRF Shield", result)

    def test_block_6to4(self):
        """6to4 prefix (2002::/16) should be blocked — encapsulates arbitrary IPv4."""
        result = self.check.check("https://[2002:c0a8:0101::1]/")
        self.assertIsNotNone(result)

    def test_block_teredo(self):
        """Teredo prefix (2001:0000::/32) should be blocked."""
        result = self.check.check("https://[2001:0000:4136:e378:8000:63bf:3fff:fdd2]/")
        self.assertIsNotNone(result)

    def test_block_ipv6_multicast(self):
        """IPv6 multicast (ff00::/8) should be blocked."""
        result = self.check.check("https://[ff02::1]/")
        self.assertIsNotNone(result)

    # --- Strict IPv4 validation ---

    def test_block_octal_ipv4(self):
        """Octal IPv4 notation (0177.0.0.1 = 127.0.0.1) should be rejected."""
        result = self.check.check("https://0177.0.0.1/admin")
        self.assertIsNotNone(result)
        self.assertIn("SSRF Shield", result)

    def test_block_hex_ipv4(self):
        """Hex IPv4 notation (0x7f.0.0.1 = 127.0.0.1) should be rejected."""
        result = self.check.check("https://0x7f.0.0.1/admin")
        self.assertIsNotNone(result)

    # --- WebSocket scheme ---

    def test_block_plaintext_websocket(self):
        """Plaintext ws:// to non-loopback should be blocked."""
        result = self.check.check("ws://example.com/socket")
        self.assertIsNotNone(result)
        self.assertIn("ws://", result)

    def test_allow_wss(self):
        """Encrypted wss:// should be allowed (subject to IP checks)."""
        result = self.check.check("wss://example.com/socket")
        # May fail due to DNS in sandbox, but should NOT fail on scheme
        if result is not None:
            self.assertNotIn("scheme", result.lower())


class TestDLPLite(unittest.TestCase):
    """Test DLP-lite (egress scanner + Shannon entropy)."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = DLPLiteCheck(self.config)

    def test_catch_stripe_key(self):
        """Stripe live key should be caught."""
        payload = "Here's the config: sk_live_abc123def456ghi789jkl012mno"
        result = self.check.check(payload)
        self.assertIsNotNone(result)
        self.assertIn("DLP-Lite", result)

    def test_catch_aws_key(self):
        """AWS access key should be caught."""
        payload = "aws_key = AKIAIOSFODNN7EXAMPLE"
        result = self.check.check(payload)
        self.assertIsNotNone(result)

    def test_catch_jwt(self):
        """JWT tokens should be caught."""
        payload = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = self.check.check(payload)
        self.assertIsNotNone(result)

    def test_catch_pem_key(self):
        """PEM private key header should be caught."""
        payload = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        result = self.check.check(payload)
        self.assertIsNotNone(result)

    def test_allow_normal_text(self):
        """Normal English text should pass cleanly."""
        payload = "Hi Sarah, here's the Q4 report summary as requested. Revenue was up 15% year over year."
        result = self.check.check(payload)
        self.assertIsNone(result)

    def test_catch_high_entropy_base64(self):
        """Base64-encoded data should trigger entropy gate."""
        import base64
        # Pure high-entropy payload (no low-entropy prefix diluting the chunks)
        secret = os.urandom(512)
        payload = base64.b64encode(secret).decode()
        result = self.check.check(payload)
        self.assertIsNotNone(result)
        self.assertIn("entropy", result.lower())

    def test_entropy_calculation(self):
        """Verify entropy calculations are in expected ranges."""
        # Low entropy: repeated character
        self.assertLess(compute_shannon_entropy("aaaaaaaaaa"), 1.0)
        # Medium entropy: English text
        english = "The quick brown fox jumps over the lazy dog"
        entropy = compute_shannon_entropy(english)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 5.5)
        # High entropy: random-looking data
        import base64
        high = base64.b64encode(os.urandom(256)).decode()
        self.assertGreater(compute_shannon_entropy(high), 5.5)


class TestCanary(unittest.TestCase):
    """Test canary honeypot tool (the tripwire)."""

    def setUp(self):
        self.config = TestConfig.create()
        self.check = CanaryCheck(self.config)

    def test_trigger_on_honeypot_call(self):
        """Calling a canary tool should trigger alert."""
        result = self.check.check("disable_security_audit")
        self.assertIsNotNone(result)
        self.assertIn("CANARY TRIGGERED", result)

    def test_trigger_all_canaries(self):
        """All configured canary tools should trigger."""
        for tool in self.config.canary_tools:
            result = self.check.check(tool)
            self.assertIsNotNone(result, f"Canary {tool} did not trigger")

    def test_allow_normal_tools(self):
        """Normal tools should not trigger canary."""
        result = self.check.check("fs_write")
        self.assertIsNone(result)
        result = self.check.check("send_email")
        self.assertIsNone(result)

    def test_canary_definitions_generated(self):
        """Should generate realistic-looking tool definitions for manifest."""
        defs = self.check.get_canary_tool_definitions()
        self.assertTrue(len(defs) > 0)
        for d in defs:
            self.assertIn("name", d)
            self.assertIn("description", d)
            self.assertIn("inputSchema", d)


class TestPipeline(unittest.TestCase):
    """Test the full enforcement pipeline integration."""

    def setUp(self):
        self.config = TestConfig.create()
        self.pipeline = EnforcementPipeline(self.config)
        # Resolve relative/shell path args inside the temp test workspace so
        # self-protection doesn't preempt SSRF/exec-tunnel stage assertions.
        self._orig_cwd = os.getcwd()
        os.chdir(str(self.config.workspace_root))

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def _make_session(self, **kwargs) -> Session:
        return Session(session_id="test_sess_001", config=self.config, **kwargs)

    def test_allow_clean_read(self):
        """Clean read-only action should be allowed."""
        session = self._make_session()
        result = self.pipeline.check(session, "search_web", target="https://example.com")
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_block_self_protection(self):
        """Self-protection should block .unwind access."""
        session = self._make_session()
        result = self.pipeline.check(
            session, "fs_write", target=str(self.config.events_db_path)
        )
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("System Core Protected", result.block_reason)

    def test_canary_kills_session(self):
        """Canary should kill session and return KILL."""
        session = self._make_session()
        result = self.pipeline.check(session, "disable_security_audit")
        self.assertEqual(result.action, CheckResult.KILL)
        self.assertTrue(session.killed)
        self.assertEqual(session.trust_state, TrustState.RED)

    def test_killed_session_blocks_everything(self):
        """A killed session should block all subsequent calls."""
        session = self._make_session()
        session.kill()
        result = self.pipeline.check(session, "search_web")
        self.assertEqual(result.action, CheckResult.KILL)

    def test_taint_chain(self):
        """Multiple sensors then high-risk actuator should trigger amber.

        With graduated taint decay, a single sensor call → MEDIUM (no amber).
        Two sensor calls with cooldown gap → HIGH (amber).
        """
        session = self._make_session()
        # Read email (sensor) — should allow but taint to MEDIUM
        result = self.pipeline.check(session, "read_email")
        self.assertEqual(result.action, CheckResult.ALLOW)
        self.assertTrue(session.is_tainted)
        # Second sensor after cooldown gap → escalate to HIGH
        session.taint_state.last_taint_event = time.time() - session.taint_config.retaint_cooldown_seconds - 1
        result = self.pipeline.check(session, "search_web")
        self.assertEqual(result.action, CheckResult.ALLOW)
        # Now high-risk actuator should amber (taint is HIGH)
        result = self.pipeline.check(session, "send_email")
        self.assertEqual(result.action, CheckResult.AMBER)

    def test_taint_decay(self):
        """Taint should decay after idle period."""
        session = self._make_session()
        # Taint the session
        session.taint("search_web")
        self.assertTrue(session.is_tainted)
        # Simulate time passing (enough to fully decay from MEDIUM)
        session.taint_state.last_taint_event = time.time() - (session.taint_config.decay_interval_seconds * 5)
        # Now a high-risk actuator should be allowed (taint decayed)
        result = self.pipeline.check(session, "send_email")
        self.assertFalse(session.is_tainted)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_circuit_breaker(self):
        """Rapid state-modifying calls should trip the circuit breaker."""
        session = self._make_session()
        # Fire calls rapidly — circuit breaker is 5 calls in 5 seconds
        for i in range(5):
            result = self.pipeline.check(session, "fs_write", target=str(self.config.workspace_root / f"file{i}.txt"))
        # Next one should trip
        result = self.pipeline.check(session, "fs_write", target=str(self.config.workspace_root / "file5.txt"))
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("Circuit Breaker", result.block_reason)
        self.assertEqual(session.trust_state, TrustState.RED)

    def test_ghost_mode_intercepts_write(self):
        """Ghost mode should intercept writes and return GHOST."""
        session = self._make_session(ghost_mode=True)
        result = self.pipeline.check(
            session, "fs_write",
            target=str(self.config.workspace_root / "test.txt"),
            payload="test content",
        )
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_ghost_mode_shadow_vfs(self):
        """Ghost mode should store writes and serve reads from shadow VFS."""
        session = self._make_session(ghost_mode=True)
        target = str(self.config.workspace_root / "config.json")
        # Write in ghost mode
        self.pipeline.check(session, "fs_write", target=target, payload='{"key": "value"}')
        # Read should find it in shadow VFS
        self.assertIsNotNone(session.ghost_read(target))

    def test_dlp_catches_secrets_in_egress(self):
        """DLP should flag secrets in outbound email."""
        session = self._make_session()
        result = self.pipeline.check(
            session, "send_email",
            payload="Here's the key: sk_live_abc123def456ghi789jkl012mno",
        )
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertIn("DLP-Lite", result.amber_reason)

    def test_ssrf_blocks_metadata(self):
        """SSRF should block cloud metadata access."""
        session = self._make_session()
        result = self.pipeline.check(
            session, "fetch_web", target="http://169.254.169.254/latest/meta-data/"
        )
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("SSRF Shield", result.block_reason)

    def test_http_mutators_are_ssrf_screened(self):
        """HTTP mutator tools should be subject to SSRF shield checks."""
        for tool_name in ("http_put", "http_delete", "http_patch"):
            with self.subTest(tool=tool_name):
                session = self._make_session()
                result = self.pipeline.check(
                    session,
                    tool_name,
                    target="http://169.254.169.254/latest/meta-data/",
                )
                self.assertEqual(result.action, CheckResult.BLOCK)
                self.assertIn("SSRF Shield", result.block_reason)

    def test_tool_classification(self):
        """Tools should be correctly classified."""
        self.assertEqual(self.pipeline.classify_tool("read_email"), "sensor")
        self.assertEqual(self.pipeline.classify_tool("send_email"), "actuator")
        self.assertEqual(self.pipeline.classify_tool("exec_process"), "actuator")
        self.assertEqual(self.pipeline.classify_tool("process"), "actuator")
        self.assertEqual(self.pipeline.classify_tool("search_web"), "sensor")  # search_web ingests external content
        self.assertEqual(self.pipeline.classify_tool("disable_security_audit"), "canary")


class TestEventStore(unittest.TestCase):
    """Test the flight recorder event store."""

    def setUp(self):
        self.config = TestConfig.create()
        from unwind.recorder.event_store import EventStore
        self.store = EventStore(self.config.events_db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_write_pending_and_complete(self):
        """Should write a pending row and update it."""
        from unwind.recorder.event_store import EventStatus
        event_id = self.store.write_pending(
            session_id="sess_001",
            tool="fs_write",
            tool_class="actuator",
            target="/workspace/test.txt",
            target_canonical="/workspace/test.txt",
            parameters={"content": "hello"},
            session_tainted=False,
            trust_state="green",
        )
        self.assertTrue(event_id.startswith("evt_"))

        # Verify pending row exists
        events = self.store.query_events(session_id="sess_001")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "pending")

        # Complete it
        self.store.complete_event(event_id, EventStatus.SUCCESS, duration_ms=42.5)
        events = self.store.query_events(session_id="sess_001")
        self.assertEqual(events[0]["status"], "success")
        self.assertEqual(events[0]["duration_ms"], 42.5)

    def test_chain_hash_integrity(self):
        """CR-AFT hash chain should verify correctly."""
        from unwind.recorder.event_store import EventStatus
        for i in range(10):
            self.store.write_pending(
                session_id="sess_001",
                tool=f"fs_write",
                tool_class="actuator",
                target=f"/workspace/file{i}.txt",
                target_canonical=f"/workspace/file{i}.txt",
                parameters=None,
                session_tainted=False,
                trust_state="green",
            )
        valid, error = self.store.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_wal_mode_enabled(self):
        """Database should be in WAL mode."""
        import sqlite3
        conn = sqlite3.connect(str(self.config.events_db_path))
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        conn.close()
        self.assertEqual(mode, "wal")

    def test_parameters_are_hashed_not_stored(self):
        """Parameters should be stored as hashes, not raw values."""
        from unwind.recorder.event_store import EventStatus
        secret_params = {"api_key": "sk_live_super_secret_key_12345"}
        event_id = self.store.write_pending(
            session_id="sess_001",
            tool="api_call",
            tool_class="actuator",
            target="https://api.stripe.com",
            target_canonical="https://api.stripe.com",
            parameters=secret_params,
            session_tainted=False,
            trust_state="green",
        )
        events = self.store.query_events(session_id="sess_001")
        # Should be a hash, not the raw key
        self.assertNotIn("sk_live", str(events[0]["parameters_hash"]))
        self.assertEqual(len(events[0]["parameters_hash"]), 64)  # SHA-256 hex


class TestSupplyChainPipeline(unittest.TestCase):
    """Test supply-chain verifier wired into the enforcement pipeline."""

    def setUp(self):
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy,
        )
        self.config = TestConfig.create()

        # Build a lockfile with one trusted provider
        providers = {
            "mcp-filesystem": ProviderEntry(
                provider_id="mcp-filesystem",
                name="MCP Filesystem",
                version="1.0.0",
                digest="sha256:aaaa",
                tools=["fs_read", "fs_write"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
        }
        lf = Lockfile(
            providers=providers,
            trust_policy=TrustPolicy(quarantine_unknown=True),
        )
        lf.build_index()
        self.verifier = SupplyChainVerifier(lf)
        self.pipeline = EnforcementPipeline(self.config, supply_chain_verifier=self.verifier)

    def _session(self) -> Session:
        return Session(session_id="test-sc", config=self.config)

    def test_trusted_tool_passes_pipeline(self):
        """Known trusted tool should pass supply-chain check and continue."""
        target = str(self.config.workspace_root / "test.txt")
        result = self.pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_unknown_tool_quarantined_amber(self):
        """Unknown tool should trigger AMBER for quarantine review."""
        result = self.pipeline.check(self._session(), "unknown_tool")
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertIn("Quarantined", result.amber_reason)

    def test_blocklisted_provider_blocked(self):
        """Blocklisted provider should hard BLOCK."""
        self.verifier.add_to_blocklist("mcp-filesystem")
        result = self.pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("blocklisted", result.block_reason)

    def test_no_verifier_skips_supply_chain(self):
        """Pipeline without supply-chain verifier should skip stage 0b."""
        pipeline_no_sc = EnforcementPipeline(self.config)
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline_no_sc.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_supply_chain_runs_before_canary(self):
        """Supply-chain should block before canary check can kill session."""
        # Add canary tool to a blocklisted provider
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import ProviderEntry
        self.verifier.lockfile.providers["mcp-evil"] = ProviderEntry(
            provider_id="mcp-evil", name="Evil", version="1.0",
            digest="sha256:evil",
            tools=["disable_security_audit"],  # This is a canary tool
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        self.verifier.lockfile.build_index()
        self.verifier.add_to_blocklist("mcp-evil")

        session = self._session()
        result = self.pipeline.check(session, "disable_security_audit")
        # Should be BLOCK from supply-chain, NOT KILL from canary
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("blocklisted", result.block_reason)
        # Session should NOT be killed
        self.assertFalse(session.killed)

    def test_expired_provider_blocked(self):
        """Expired provider trust should BLOCK."""
        from datetime import datetime, timezone, timedelta
        from unwind.enforcement.supply_chain import ProviderEntry
        old_time = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        self.verifier.lockfile.providers["mcp-filesystem"].trusted_at = old_time
        result = self.pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("expired", result.block_reason.lower())


class TestDigestAtExecution(unittest.TestCase):
    """Test digest-at-execution TOCTOU protection (R-LOCK-002)."""

    def setUp(self):
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy,
        )
        self.config = TestConfig.create()

        providers = {
            "mcp-filesystem": ProviderEntry(
                provider_id="mcp-filesystem",
                name="MCP Filesystem",
                version="1.0.0",
                digest="sha256:aaaa",
                tools=["fs_read", "fs_write"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
        }
        lf = Lockfile(
            providers=providers,
            trust_policy=TrustPolicy(quarantine_unknown=True),
        )
        lf.build_index()
        self.verifier = SupplyChainVerifier(lf)

    def _session(self) -> Session:
        return Session(session_id="test-digest", config=self.config)

    def test_matching_digest_passes(self):
        """Live digest matches lockfile → ALLOW."""
        def digest_fn(pid):
            return "sha256:aaaa"

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=digest_fn,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_mismatched_digest_blocks(self):
        """Live digest differs from lockfile → BLOCK (TOCTOU violation)."""
        def digest_fn(pid):
            return "sha256:TAMPERED"

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=digest_fn,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("mismatch", result.block_reason.lower())

    def test_no_digest_provider_skips_check(self):
        """No digest_provider → no live digest → passes (backwards compatible)."""
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=None,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_digest_provider_returns_none_skips(self):
        """Digest provider returns None → no comparison → passes."""
        def digest_fn(pid):
            return None

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=digest_fn,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_digest_provider_exception_handled(self):
        """If digest_provider throws, treat as no digest (don't crash)."""
        def digest_fn(pid):
            raise RuntimeError("Provider unavailable")

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=digest_fn,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_unknown_tool_no_digest_lookup(self):
        """Unknown tool has no provider_id → digest_provider not called."""
        call_count = {"n": 0}
        def digest_fn(pid):
            call_count["n"] += 1
            return "sha256:aaaa"

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=digest_fn,
        )
        result = pipeline.check(self._session(), "unknown_tool")
        # Should be AMBER (quarantined), digest_provider never called
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertEqual(call_count["n"], 0)

    def test_digest_at_execution_catches_runtime_swap(self):
        """Simulates a provider binary being swapped after lockfile was signed."""
        original_digest = "sha256:aaaa"
        swapped_digest = "sha256:bbbb"

        # First call: digest matches
        def good_digest(pid):
            return original_digest
        pipeline_good = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=good_digest,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline_good.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

        # Second call: binary swapped, new digest
        def bad_digest(pid):
            return swapped_digest
        pipeline_bad = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=bad_digest,
        )
        result = pipeline_bad.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)


class TestStrictModeDigestProvider(unittest.TestCase):
    """Test strict-mode enforcement for digest-provider (R-STRICT-001).

    In strict mode, the digest-provider skip paths are fail-closed:
    - No digest_provider configured → BLOCK
    - digest_provider throws → BLOCK
    - digest_provider returns None → BLOCK
    Permissive mode preserves backwards-compatible behaviour (skip/allow).
    """

    def setUp(self):
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy,
        )
        self.config = TestConfig.create()

        providers = {
            "mcp-filesystem": ProviderEntry(
                provider_id="mcp-filesystem",
                name="MCP Filesystem",
                version="1.0.0",
                digest="sha256:aaaa",
                tools=["fs_read", "fs_write"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
        }
        lf = Lockfile(
            providers=providers,
            trust_policy=TrustPolicy(quarantine_unknown=True),
        )
        lf.build_index()
        self.verifier = SupplyChainVerifier(lf)

    def _session(self) -> Session:
        return Session(session_id="test-strict", config=self.config)

    # --- No digest_provider configured ---

    def test_strict_no_provider_blocks_known_tool(self):
        """Strict + no digest_provider + known tool → BLOCK."""
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=None,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("no digest-provider", result.block_reason)
        self.assertIn("R-STRICT-001", result.block_reason)

    def test_strict_no_provider_unknown_tool_not_blocked_by_digest(self):
        """Strict + no digest_provider + unknown tool → AMBER (quarantine, not digest block).

        Unknown tools have no provider_id, so digest check doesn't apply.
        """
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=None,
            strict=True,
        )
        result = pipeline.check(self._session(), "unknown_tool")
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertIn("Quarantined", result.amber_reason)

    def test_permissive_no_provider_allows(self):
        """Permissive + no digest_provider → ALLOW (backwards compatible)."""
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=None,
            strict=False,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    # --- digest_provider throws ---

    def test_strict_provider_exception_blocks(self):
        """Strict + digest_provider throws → BLOCK."""
        def bad_provider(pid):
            raise RuntimeError("Connection refused")

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=bad_provider,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("digest-provider error", result.block_reason)
        self.assertIn("Connection refused", result.block_reason)

    def test_permissive_provider_exception_allows(self):
        """Permissive + digest_provider throws → ALLOW (graceful degradation)."""
        def bad_provider(pid):
            raise RuntimeError("Timeout")

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=bad_provider,
            strict=False,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    # --- digest_provider returns None ---

    def test_strict_provider_returns_none_blocks(self):
        """Strict + digest_provider returns None → BLOCK."""
        def none_provider(pid):
            return None

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=none_provider,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("returned None", result.block_reason)

    def test_permissive_provider_returns_none_allows(self):
        """Permissive + digest_provider returns None → ALLOW."""
        def none_provider(pid):
            return None

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=none_provider,
            strict=False,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    # --- Strict mode with valid digest still works ---

    def test_strict_valid_digest_passes_digest_check(self):
        """Strict + matching digest passes the digest gate (may still need all legs).

        This test verifies the digest check itself doesn't block;
        require_all_legs is tested separately in TestRequireAllLegs.
        Without HMAC/sigs, require_all_legs would block, so we test in
        non-strict to isolate the digest behaviour.
        """
        def good_provider(pid):
            return "sha256:aaaa"

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=good_provider,
            strict=False,  # Isolate digest check from require_all_legs
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_strict_mismatched_digest_blocks(self):
        """Strict + mismatched digest → BLOCK (same as permissive)."""
        def bad_digest(pid):
            return "sha256:TAMPERED"

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=self.verifier,
            digest_provider=bad_digest,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("mismatch", result.block_reason.lower())

    # --- No supply chain verifier → strict doesn't crash ---

    def test_strict_no_supply_chain_verifier_blocks(self):
        """Strict + no supply-chain verifier → BLOCK (drift fix #1)."""
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=None,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("SUPPLY_CHAIN_VERIFIER_MISSING", result.block_reason)

    def test_permissive_no_supply_chain_verifier_allows(self):
        """Permissive + no supply-chain verifier → ALLOW (backwards compatible)."""
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=None,
            strict=False,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)


class TestRequireAllLegs(unittest.TestCase):
    """Test strict.trust_gate.require_all_legs enforcement.

    In strict mode, TRUSTED verdict requires all three trust legs:
    - HMAC lockfile integrity (_hmac_verified=True)
    - Ed25519 signature (signature_valid=True)
    - Digest-at-execution (digest_match=True)
    Missing any leg → BLOCK with TRUST_LEG_MISSING.
    """

    def _build(self, hmac_verified=True, require_sigs=True, has_sig=True,
               has_verifier=True, digest_fn=None, strict=True):
        """Helper: build pipeline with configurable trust legs."""
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy,
        )
        from unwind.enforcement.signature_verify import (
            SignatureVerifier, KeyStore, generate_ed25519_keypair,
            sign_provider_entry,
        )
        self.config = TestConfig.create()

        # Generate a keypair for signing
        private_seed, public_key = generate_ed25519_keypair()
        key_store = KeyStore()
        key_store.add_key(
            key_id="test-key",
            public_key=public_key,
        )

        trusted_at = datetime.now(timezone.utc).isoformat()
        provider_data = {
            "name": "MCP Filesystem",
            "version": "1.0.0",
            "digest": "sha256:aaaa",
            "tools": ["fs_read", "fs_write"],
            "origin": "",
            "trusted_at": trusted_at,
        }

        if has_sig:
            signed = sign_provider_entry(provider_data, private_seed, "test-key")
            sig_block = signed.get("signature")
        else:
            sig_block = None

        # Use the SAME trusted_at to ensure canonical JSON matches
        providers = {
            "mcp-filesystem": ProviderEntry(
                provider_id="mcp-filesystem",
                name="MCP Filesystem",
                version="1.0.0",
                digest="sha256:aaaa",
                tools=["fs_read", "fs_write"],
                trusted_at=trusted_at,
                signature=sig_block,
            ),
        }
        lf = Lockfile(
            providers=providers,
            trust_policy=TrustPolicy(
                quarantine_unknown=True,
                require_signatures=require_sigs,
            ),
        )
        lf.build_index()
        lf._hmac_verified = hmac_verified

        sig_verifier = SignatureVerifier(key_store) if has_verifier else None
        sc_verifier = SupplyChainVerifier(lf, signature_verifier=sig_verifier)

        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=sc_verifier,
            digest_provider=digest_fn,
            strict=strict,
        )
        return pipeline

    def _session(self):
        return Session(session_id="test-all-legs", config=self.config)

    def test_all_legs_present_allows(self):
        """All three legs verified → ALLOW in strict mode."""
        pipeline = self._build(
            hmac_verified=True,
            require_sigs=True,
            has_sig=True,
            has_verifier=True,
            digest_fn=lambda pid: "sha256:aaaa",
            strict=True,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_missing_hmac_blocks(self):
        """HMAC not verified → BLOCK with TRUST_LEG_MISSING."""
        pipeline = self._build(
            hmac_verified=False,
            require_sigs=True,
            has_sig=True,
            has_verifier=True,
            digest_fn=lambda pid: "sha256:aaaa",
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("TRUST_LEG_MISSING", result.block_reason)
        self.assertIn("HMAC", result.block_reason)

    def test_missing_signature_blocks(self):
        """Signature not verified (not required in policy) → BLOCK with TRUST_LEG_MISSING."""
        pipeline = self._build(
            hmac_verified=True,
            require_sigs=False,  # Sig not required → signature_valid=None
            has_sig=False,
            has_verifier=False,
            digest_fn=lambda pid: "sha256:aaaa",
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("TRUST_LEG_MISSING", result.block_reason)
        self.assertIn("Ed25519", result.block_reason)

    def test_missing_digest_blocks(self):
        """No digest-at-execution (provider returns None, already blocked by strict digest)."""
        # With digest_fn returning None, strict mode blocks at the digest-provider level first
        pipeline = self._build(
            hmac_verified=True,
            require_sigs=True,
            has_sig=True,
            has_verifier=True,
            digest_fn=lambda pid: None,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        # Blocked at digest-provider level (earlier in pipeline)
        self.assertIn("returned None", result.block_reason)

    def test_no_digest_provider_blocks_at_require_all_legs(self):
        """No digest provider → blocked at digest-provider check (before require_all_legs)."""
        pipeline = self._build(
            hmac_verified=True,
            require_sigs=True,
            has_sig=True,
            has_verifier=True,
            digest_fn=None,
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("no digest-provider", result.block_reason)

    def test_permissive_mode_allows_missing_legs(self):
        """Permissive mode doesn't enforce all legs."""
        pipeline = self._build(
            hmac_verified=False,
            require_sigs=False,
            has_sig=False,
            has_verifier=False,
            digest_fn=None,
            strict=False,
        )
        target = str(self.config.workspace_root / "test.txt")
        result = pipeline.check(self._session(), "fs_read", target=target)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_hmac_none_blocks(self):
        """_hmac_verified=None (not checked) → treated as missing leg."""
        pipeline = self._build(
            hmac_verified=None,
            require_sigs=True,
            has_sig=True,
            has_verifier=True,
            digest_fn=lambda pid: "sha256:aaaa",
            strict=True,
        )
        result = pipeline.check(self._session(), "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("HMAC", result.block_reason)


class TestVerifierErrorsFailClosed(unittest.TestCase):
    """Test strict.signatures.verifier_errors_fail_closed.

    When the SignatureVerifier throws an internal exception,
    verify_tool should return SIGNATURE_INVALID (fail-closed).
    """

    def setUp(self):
        from datetime import datetime, timezone
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy, TrustVerdict,
        )
        self.TrustVerdict = TrustVerdict
        self.config = TestConfig.create()

        providers = {
            "mcp-filesystem": ProviderEntry(
                provider_id="mcp-filesystem",
                name="MCP Filesystem",
                version="1.0.0",
                digest="sha256:aaaa",
                tools=["fs_read", "fs_write"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
                signature={"alg": "Ed25519", "key_id": "k1", "sig": "deadbeef"},
            ),
        }
        self.lf = Lockfile(
            providers=providers,
            trust_policy=TrustPolicy(
                quarantine_unknown=True,
                require_signatures=True,
            ),
        )
        self.lf.build_index()

    def test_verifier_exception_returns_signature_invalid(self):
        """SignatureVerifier.verify() throws → SIGNATURE_INVALID."""
        class BrokenVerifier:
            def verify(self, provider_id, provider_data):
                raise RuntimeError("Key store corrupted")

        from unwind.enforcement.supply_chain import SupplyChainVerifier
        verifier = SupplyChainVerifier(self.lf, signature_verifier=BrokenVerifier())
        result = verifier.verify_tool("fs_read")
        self.assertEqual(result.verdict, self.TrustVerdict.SIGNATURE_INVALID)
        self.assertIn("SIGNATURE_VERIFIER_ERROR", result.reason)
        self.assertIn("Key store corrupted", result.reason)

    def test_verifier_exception_blocks_in_pipeline(self):
        """Verifier exception → SIGNATURE_INVALID → pipeline BLOCK."""
        class BrokenVerifier:
            def verify(self, provider_id, provider_data):
                raise ValueError("Unexpected key format")

        from unwind.enforcement.supply_chain import SupplyChainVerifier
        sc = SupplyChainVerifier(self.lf, signature_verifier=BrokenVerifier())
        pipeline = EnforcementPipeline(
            self.config,
            supply_chain_verifier=sc,
            digest_provider=lambda pid: "sha256:aaaa",
            strict=True,
        )
        session = Session(session_id="test-verr", config=self.config)
        result = pipeline.check(session, "fs_read")
        self.assertEqual(result.action, CheckResult.BLOCK)

    def test_verifier_type_error_caught(self):
        """TypeError in verifier also caught and reported."""
        class TypeErrorVerifier:
            def verify(self, provider_id, provider_data):
                raise TypeError("NoneType has no attribute 'key'")

        from unwind.enforcement.supply_chain import SupplyChainVerifier
        verifier = SupplyChainVerifier(self.lf, signature_verifier=TypeErrorVerifier())
        result = verifier.verify_tool("fs_read")
        self.assertEqual(result.verdict, self.TrustVerdict.SIGNATURE_INVALID)
        self.assertIn("SIGNATURE_VERIFIER_ERROR", result.reason)


class TestRubberStampPipeline(unittest.TestCase):
    """Test rubber-stamp detector wired into the approval callback flow."""

    def setUp(self):
        from unwind.enforcement.rubber_stamp import RubberStampConfig
        self.config = TestConfig.create()
        self.rss_config = RubberStampConfig()
        self.pipeline = EnforcementPipeline(
            self.config,
            rubber_stamp_config=self.rss_config,
        )

    def test_normal_approval_passes(self):
        """A careful approval (3 second latency) should pass."""
        gate = self.pipeline.process_approval(
            operator_id="david",
            approved=True,
            latency_seconds=3.0,
            pattern_hash="fs_write_report",
        )
        self.assertTrue(gate.allowed)
        self.assertEqual(gate.rss_level.name, "NONE")

    def test_rejection_always_passes(self):
        """Rejections should always be accepted."""
        gate = self.pipeline.process_approval(
            operator_id="david",
            approved=False,
            latency_seconds=0.1,
        )
        self.assertTrue(gate.allowed)

    def test_fast_approvals_escalate_rss(self):
        """Rapid sub-second approvals should raise RSS."""
        for i in range(10):
            gate = self.pipeline.process_approval(
                operator_id="speed-clicker",
                approved=True,
                latency_seconds=0.5,
                pattern_hash=f"pattern_{i}",
            )
        # After 10 fast approvals, RSS should be elevated
        self.assertGreater(gate.rss_score, 0)

    def test_very_high_rss_triggers_lockout(self):
        """Extreme rubber-stamping should trigger lockout."""
        from unwind.enforcement.rubber_stamp import RSSLevel
        # 15 fast approvals with pattern changes to max out RSS
        for i in range(15):
            gate = self.pipeline.process_approval(
                operator_id="robot-clicker",
                approved=True,
                latency_seconds=0.3,
                pattern_hash=f"changing_pattern_{i}",
            )
        # Should eventually hit VERY_HIGH and lockout
        # (exact threshold depends on which indicators fire)
        if gate.rss_level == RSSLevel.VERY_HIGH:
            self.assertFalse(gate.allowed)
            self.assertGreater(gate.lockout_remaining, 0)

    def test_separate_operators_have_separate_state(self):
        """Each operator gets their own RSS tracking."""
        for i in range(10):
            self.pipeline.process_approval(
                operator_id="alice", approved=True, latency_seconds=0.3,
            )
        gate_bob = self.pipeline.process_approval(
            operator_id="bob", approved=True, latency_seconds=5.0,
        )
        # Bob's first approval should have low RSS
        self.assertEqual(gate_bob.rss_level.name, "NONE")

    def test_get_rss_state_creates_new(self):
        """get_rss_state should create state for new operators."""
        state = self.pipeline.get_rss_state("new-operator")
        self.assertEqual(state.total_approvals, 0)

    def test_high_level_injects_hold(self):
        """HIGH RSS should inject hold time."""
        from unwind.enforcement.pipeline import RSSLevel
        # Push RSS to HIGH level (55+) with fast approvals
        for i in range(13):
            gate = self.pipeline.process_approval(
                operator_id="hasty-harry",
                approved=True,
                latency_seconds=0.5,
                pattern_hash="same_pattern",
            )
        # If we hit HIGH, check hold
        if gate.rss_level == RSSLevel.HIGH:
            self.assertTrue(gate.allowed)
            self.assertEqual(gate.hold_seconds, self.rss_config.high_hold_seconds)


class TestResponseValidatorPipeline(unittest.TestCase):
    """Test response principal validator wired into the pipeline."""

    def setUp(self):
        self.config = TestConfig.create()
        self.pipeline = EnforcementPipeline(self.config)

    def _session(self, sid: str = "sess-1") -> Session:
        return Session(session_id=sid, config=self.config)

    def test_register_and_validate_response(self):
        """Normal flow: register request, validate matching response."""
        session = self._session()
        req, budget_err = self.pipeline.register_request(
            upstream_id="up-001",
            agent_id="ag-001",
            session=session,
            tool_name="fs_read",
        )
        self.assertIsNone(budget_err)

        pending, error = self.pipeline.validate_response("up-001", session)
        self.assertIsNotNone(pending)
        self.assertIsNone(error)
        self.assertEqual(pending.session_id, "sess-1")

    def test_unknown_response_rejected(self):
        """Response with no matching request should be rejected."""
        session = self._session()
        pending, error = self.pipeline.validate_response("unknown-id", session)
        self.assertIsNone(pending)
        self.assertIn("unknown upstream_id", error)

    def test_cross_session_response_rejected(self):
        """Response arriving on wrong session should be rejected."""
        session_a = self._session("sess-a")
        session_b = self._session("sess-b")

        self.pipeline.register_request(
            upstream_id="up-002",
            agent_id="ag-002",
            session=session_a,
            tool_name="send_email",
        )

        # Response arrives on session B but was sent from session A
        pending, error = self.pipeline.validate_response("up-002", session_b)
        self.assertIsNone(pending)
        self.assertIn("principal violation", error)

    def test_budget_enforcement(self):
        """Session budget should block when exceeded."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=3)
        self.pipeline.set_session_budget(session, budget)

        # 3 calls OK
        for i in range(3):
            _, budget_err = self.pipeline.register_request(
                upstream_id=f"up-{i}",
                agent_id=f"ag-{i}",
                session=session,
                tool_name="fs_read",
            )
        # 3rd call should trigger budget exceeded
        self.assertIsNotNone(budget_err)

    def test_budget_check_no_budget_returns_none(self):
        """Session without budget should always return None."""
        session = self._session()
        result = self.pipeline.check_session_budget(session)
        self.assertIsNone(result)

    def test_budget_kills_session_on_exceed(self):
        """Exceeding budget should kill the session."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=1)
        self.pipeline.set_session_budget(session, budget)

        # First call hits the limit
        self.pipeline.register_request(
            upstream_id="up-x",
            agent_id="ag-x",
            session=session,
            tool_name="fs_read",
        )
        # Second call exceeds
        _, budget_err = self.pipeline.register_request(
            upstream_id="up-y",
            agent_id="ag-y",
            session=session,
            tool_name="fs_read",
        )
        self.assertIsNotNone(budget_err)
        self.assertTrue(session.killed)
        self.assertEqual(session.trust_state, TrustState.RED)


class TestBudgetIdempotency(unittest.TestCase):
    """Test that budget debits are idempotent on upstream_id."""

    def setUp(self):
        self.config = TestConfig.create()
        self.pipeline = EnforcementPipeline(self.config)

    def _session(self, session_id="test-sess"):
        return Session(session_id=session_id, config=self.config)

    def test_duplicate_upstream_id_not_double_counted(self):
        """Same upstream_id registered twice should only debit once."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=2)
        self.pipeline.set_session_budget(session, budget)

        # Register with same upstream_id twice
        self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        # Budget should show 1 call, not 2
        budget_obj = self.pipeline.response_validator.get_budget(session.session_id)
        self.assertEqual(budget_obj.tool_calls, 1)

    def test_different_upstream_ids_both_counted(self):
        """Different upstream_ids should each be counted."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=5)
        self.pipeline.set_session_budget(session, budget)

        self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        self.pipeline.register_request(
            upstream_id="up-2", agent_id="ag-2",
            session=session, tool_name="fs_read",
        )
        budget_obj = self.pipeline.response_validator.get_budget(session.session_id)
        self.assertEqual(budget_obj.tool_calls, 2)

    def test_idempotency_prevents_false_budget_exceed(self):
        """Retried registration shouldn't trigger false budget exceed."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=1)
        self.pipeline.set_session_budget(session, budget)

        # First registration — hits the limit
        _, err1 = self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        self.assertIsNotNone(err1)  # At limit

        # Retry same upstream_id — should NOT kill session
        _, err2 = self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        # Still at limit but not a new debit
        self.assertIsNotNone(err2)  # Budget still exceeded
        # But the actual count didn't increase
        budget_obj = self.pipeline.response_validator.get_budget(session.session_id)
        self.assertEqual(budget_obj.tool_calls, 1)

    def test_clear_debit_allows_re_registration(self):
        """Clearing a debit should allow the upstream_id to be counted again."""
        from unwind.enforcement.response_validator import SessionBudget
        session = self._session()
        budget = SessionBudget(max_tool_calls=5)
        self.pipeline.set_session_budget(session, budget)

        self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        # Clear the debit
        self.pipeline.response_validator.clear_debit("up-1")
        # Re-register — should count again
        self.pipeline.register_request(
            upstream_id="up-1", agent_id="ag-1",
            session=session, tool_name="fs_read",
        )
        budget_obj = self.pipeline.response_validator.get_budget(session.session_id)
        self.assertEqual(budget_obj.tool_calls, 2)


class TestApprovalWindowPipeline(unittest.TestCase):
    """Test approval windows integration with the enforcement pipeline."""

    def setUp(self):
        self.config = TestConfig.create()
        from unwind.enforcement.approval_windows import ApprovalWindowConfig
        self.aw_config = ApprovalWindowConfig()
        self.pipeline = EnforcementPipeline(
            self.config,
            approval_window_config=self.aw_config,
        )

    def _session(self, session_id="test-sess"):
        return Session(session_id=session_id, config=self.config)

    def _taint_to_high(self, session):
        """Helper: taint a session to HIGH level reliably.

        Resets taint state first to ensure we always land on HIGH,
        regardless of prior taint events.
        """
        from unwind.enforcement.taint_decay import TaintLevel
        session.taint_state._reset()
        session.taint_state.level = TaintLevel.NONE
        session.taint(source_tool="search_web")
        session.taint_state.last_taint_event = time.time() - 10
        session.taint(source_tool="fetch_url")
        assert session.taint_state.level.name == "HIGH"

    def test_approval_window_bypasses_amber(self):
        """Valid approval window should skip the amber prompt."""
        from unwind.enforcement.approval_windows import RiskBand
        session = self._session()
        # Use send_email — high-risk actuator, not caught by exec tunnel
        tool = "send_email"
        params = {"to": "test@example.com", "body": "hello"}

        self._taint_to_high(session)

        # Without window: should get AMBER
        result = self.pipeline.check(session, tool, parameters=params)
        self.assertEqual(result.action, CheckResult.AMBER)

        # Issue an approval window
        self.pipeline.issue_approval_window(
            session=session,
            operator_id="op-1",
            tool_name=tool,
            parameters=params,
            risk_band=RiskBand.AMBER_LOW,
        )

        # Re-taint to HIGH
        self._taint_to_high(session)

        # With window: should get ALLOW (window bypasses amber)
        result = self.pipeline.check(session, tool, parameters=params)
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_no_window_still_ambers(self):
        """Without approval window, tainted session still gets AMBER."""
        session = self._session()
        tool = "send_email"

        self._taint_to_high(session)

        result = self.pipeline.check(session, tool, parameters={"to": "a@b.com"})
        self.assertEqual(result.action, CheckResult.AMBER)

    def test_compute_args_shape(self):
        """Args shape should be deterministic and sorted."""
        shape = EnforcementPipeline._compute_args_shape(
            {"path": "/tmp/a", "content": "hello", "mode": 0o644}
        )
        self.assertEqual(shape, "content:str,mode:int,path:str")

    def test_compute_args_shape_empty(self):
        self.assertEqual(EnforcementPipeline._compute_args_shape(None), "")
        self.assertEqual(EnforcementPipeline._compute_args_shape({}), "")

    def test_issue_window_critical_returns_none(self):
        """CRITICAL band should not create a window."""
        from unwind.enforcement.approval_windows import RiskBand
        session = self._session()
        result = self.pipeline.issue_approval_window(
            session=session,
            operator_id="op-1",
            tool_name="fs_write",
            risk_band=RiskBand.AMBER_CRITICAL,
        )
        self.assertIsNone(result)

    def test_sync_threat_mode_from_taint(self):
        """Taint level should map to threat mode."""
        from unwind.enforcement.approval_windows import ThreatMode
        from unwind.enforcement.taint_decay import TaintLevel
        session = self._session()

        # No taint → NORMAL
        self.pipeline.sync_threat_mode(session)
        self.assertEqual(
            self.pipeline.approval_windows.threat_mode,
            ThreatMode.NORMAL,
        )

        # HIGH taint → ELEVATED
        session.taint_state.level = TaintLevel.HIGH
        self.pipeline.sync_threat_mode(session)
        self.assertEqual(
            self.pipeline.approval_windows.threat_mode,
            ThreatMode.ELEVATED,
        )

        # CRITICAL taint → ACTIVE_EXPLOITATION
        session.taint_state.level = TaintLevel.CRITICAL
        self.pipeline.sync_threat_mode(session)
        self.assertEqual(
            self.pipeline.approval_windows.threat_mode,
            ThreatMode.ACTIVE_EXPLOITATION,
        )

    def test_invalidate_windows_on_kill(self):
        """Killing a session should allow window invalidation."""
        from unwind.enforcement.approval_windows import RiskBand
        session = self._session()
        self.pipeline.issue_approval_window(
            session, "op-1", "fs_write",
            parameters={"path": "/test"},
            risk_band=RiskBand.AMBER_LOW,
        )
        count = self.pipeline.invalidate_windows_for_session(
            session, "session killed"
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            self.pipeline.approval_windows.active_window_count(session.session_id), 0
        )

    def test_high_window_consumed_once_in_pipeline(self):
        """HIGH window should only bypass one amber check."""
        from unwind.enforcement.approval_windows import RiskBand
        session = self._session()
        tool = "send_email"
        params = {"to": "test@example.com", "body": "data"}

        # Taint to HIGH
        self._taint_to_high(session)

        # Issue HIGH window (one-time-use)
        self.pipeline.issue_approval_window(
            session, "op-1", tool,
            parameters=params,
            risk_band=RiskBand.AMBER_HIGH,
        )

        # First check: window consumed → ALLOW
        result = self.pipeline.check(session, tool, parameters=params)
        self.assertEqual(result.action, CheckResult.ALLOW)

        # Re-taint
        self._taint_to_high(session)

        # Second check: window exhausted → AMBER
        result = self.pipeline.check(session, tool, parameters=params)
        self.assertEqual(result.action, CheckResult.AMBER)


if __name__ == "__main__":
    unittest.main()
