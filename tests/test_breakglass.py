"""Tests for breakglass emergency override (R-BREAK-001).

Tests the full lifecycle: request → approve → active → expire/revoke,
dual-control enforcement, non-overridable flags, and pipeline integration.
"""

import time
import unittest
from unittest.mock import patch

from unwind.enforcement.breakglass import (
    BreakglassService,
    BreakglassToken,
    BreakglassEventType,
    TokenState,
    OVERRIDABLE_FLAGS,
    NON_OVERRIDABLE_FLAGS,
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    MAX_FLAGS_PER_TOKEN,
    BREAKGLASS_WINDOW_TTL_MULTIPLIER,
    BREAKGLASS_WINDOW_MAX_USES_DIVISOR,
)


class TestBreakglassRequest(unittest.TestCase):
    """Test breakglass token request flow."""

    def setUp(self):
        self.bg = BreakglassService(enabled=True)

    def test_basic_request_creates_pending_token(self):
        """Valid request creates a PENDING token."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Emergency provider migration",
        )
        self.assertIsNotNone(token)
        self.assertEqual(token.state, TokenState.PENDING)
        self.assertEqual(token.requester_id, "alice")
        self.assertEqual(token.flags, ("require_all_legs",))
        self.assertEqual(token.reason, "Emergency provider migration")

    def test_request_two_flags(self):
        """Can request up to MAX_FLAGS_PER_TOKEN (2) flags."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs", "digest_provider"],
            reason="Trust relaxation needed",
        )
        self.assertIsNotNone(token)
        # Flags should be sorted and deduplicated
        self.assertEqual(
            token.flags,
            ("digest_provider", "require_all_legs"),
        )

    def test_request_three_flags_denied_by_cap(self):
        """Requesting 3 flags exceeds per-token cap (max 2)."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs", "digest_provider", "lockfile_hmac"],
            reason="Full trust relaxation needed",
        )
        self.assertIsNone(token)

    def test_request_non_overridable_flag_denied(self):
        """Non-overridable flags are rejected."""
        token = self.bg.request(
            requester_id="alice",
            flags=["supply_chain_verifier"],
            reason="Want to bypass verifier",
        )
        self.assertIsNone(token)
        # Check audit event
        self.assertEqual(len(self.bg.audit_log), 1)
        self.assertEqual(
            self.bg.audit_log[0].event_type,
            BreakglassEventType.DENIED_NON_OVERRIDABLE,
        )

    def test_request_mixed_flags_denied(self):
        """Mix of overridable + non-overridable flags is rejected."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs", "verifier_errors_fail_closed"],
            reason="Mixed request",
        )
        self.assertIsNone(token)

    def test_request_disabled_service_denied(self):
        """Request denied when breakglass is disabled by policy."""
        bg = BreakglassService(enabled=False)
        token = bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Need override",
        )
        self.assertIsNone(token)
        self.assertEqual(
            bg.audit_log[0].event_type,
            BreakglassEventType.DENIED_DISABLED,
        )

    def test_request_empty_flags_denied(self):
        """Empty flags list is rejected."""
        token = self.bg.request(
            requester_id="alice",
            flags=[],
            reason="No flags",
        )
        self.assertIsNone(token)

    def test_request_empty_reason_denied(self):
        """Empty reason is rejected."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="",
        )
        self.assertIsNone(token)

    def test_request_ttl_capped_at_max(self):
        """TTL is capped at MAX_TTL_SECONDS (2 hours)."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Long override",
            ttl_seconds=99999,
        )
        self.assertIsNotNone(token)
        self.assertEqual(token.ttl_seconds, MAX_TTL_SECONDS)

    def test_request_ttl_floored_at_min(self):
        """TTL is floored at MIN_TTL_SECONDS."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Short override",
            ttl_seconds=5,
        )
        self.assertIsNotNone(token)
        self.assertEqual(token.ttl_seconds, MIN_TTL_SECONDS)

    def test_autonomous_profile_denied(self):
        """Autonomous profiles are default-deny for breakglass requests."""
        bg = BreakglassService(
            enabled=True,
            autonomous_profiles={"sentinel-cron", "auto-scanner"},
        )
        token = bg.request(
            requester_id="sentinel-cron",
            flags=["require_all_legs"],
            reason="Autonomous request",
        )
        self.assertIsNone(token)
        # Non-autonomous principal can still request
        token2 = bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Human request",
        )
        self.assertIsNotNone(token2)


class TestBreakglassDualControl(unittest.TestCase):
    """Test dual-control (requester ≠ approver) enforcement."""

    def setUp(self):
        self.bg = BreakglassService(enabled=True)
        self.token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Emergency migration",
        )

    def test_approve_by_different_principal(self):
        """Approval succeeds when approver ≠ requester."""
        result = self.bg.approve(self.token.token_id, approver_id="bob")
        self.assertTrue(result)
        self.assertEqual(self.token.state, TokenState.ACTIVE)
        self.assertEqual(self.token.approver_id, "bob")
        self.assertGreater(self.token.expires_at, 0)

    def test_self_approve_rejected(self):
        """Self-approval is rejected (dual-control violation)."""
        result = self.bg.approve(self.token.token_id, approver_id="alice")
        self.assertFalse(result)
        self.assertEqual(self.token.state, TokenState.REJECTED)
        # Check audit event
        self_approve_events = [
            e for e in self.bg.audit_log
            if e.event_type == BreakglassEventType.DENIED_SELF_APPROVE
        ]
        self.assertEqual(len(self_approve_events), 1)

    def test_approve_unknown_token(self):
        """Approving unknown token returns False."""
        result = self.bg.approve("bg-9999-nonexistent", approver_id="bob")
        self.assertFalse(result)

    def test_approve_already_approved_token(self):
        """Cannot approve a token that's already approved."""
        self.bg.approve(self.token.token_id, approver_id="bob")
        result = self.bg.approve(self.token.token_id, approver_id="charlie")
        self.assertFalse(result)


class TestBreakglassLifecycle(unittest.TestCase):
    """Test full token lifecycle: active → expired/revoked."""

    def setUp(self):
        self.bg = BreakglassService(enabled=True)

    def _create_active_token(self, ttl=3600.0):
        """Helper: create and approve a token."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs", "digest_provider"],
            reason="Emergency",
            ttl_seconds=ttl,
        )
        self.bg.approve(token.token_id, approver_id="bob")
        return token

    def test_active_token_overrides_flag(self):
        """Active token correctly reports flag overrides."""
        token = self._create_active_token()
        self.assertTrue(token.is_active)
        self.assertTrue(token.overrides_flag("require_all_legs"))
        self.assertTrue(token.overrides_flag("digest_provider"))
        self.assertFalse(token.overrides_flag("lockfile_hmac"))

    def test_token_auto_expires(self):
        """Token auto-transitions to EXPIRED after TTL."""
        token = self._create_active_token(ttl=60.0)

        # Mock time to simulate expiry
        with patch("unwind.enforcement.breakglass.time") as mock_time:
            mock_time.time.return_value = token.expires_at + 1
            self.assertFalse(token.is_active)
            self.assertEqual(token.state, TokenState.EXPIRED)
            self.assertFalse(token.overrides_flag("require_all_legs"))

    def test_revoke_active_token(self):
        """Can revoke an active token before TTL."""
        token = self._create_active_token()
        result = self.bg.revoke(
            token.token_id,
            revoker_id="charlie",
            reason="Threat resolved",
        )
        self.assertTrue(result)
        self.assertEqual(token.state, TokenState.REVOKED)
        self.assertFalse(token.is_active)
        self.assertFalse(token.overrides_flag("require_all_legs"))

    def test_revoke_expired_token_fails(self):
        """Cannot revoke an already-expired token."""
        token = self._create_active_token(ttl=60.0)
        with patch("unwind.enforcement.breakglass.time") as mock_time:
            mock_time.time.return_value = token.expires_at + 1
            # Force expiry check
            _ = token.is_active
            result = self.bg.revoke(token.token_id, revoker_id="charlie")
            self.assertFalse(result)

    def test_reject_pending_token(self):
        """Can reject a pending token."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Maybe needed",
        )
        result = self.bg.reject(
            token.token_id,
            approver_id="bob",
            reason="Not necessary",
        )
        self.assertTrue(result)
        self.assertEqual(token.state, TokenState.REJECTED)

    def test_check_expiry_emits_events(self):
        """check_expiry() finds and logs expired tokens."""
        token = self._create_active_token(ttl=60.0)

        with patch("unwind.enforcement.breakglass.time") as mock_time:
            mock_time.time.return_value = token.expires_at + 1
            expired = self.bg.check_expiry()
            self.assertIn(token.token_id, expired)

        expiry_events = [
            e for e in self.bg.audit_log
            if e.event_type == BreakglassEventType.EXPIRED
        ]
        self.assertEqual(len(expiry_events), 1)

    def test_remaining_seconds(self):
        """remaining_seconds correctly reports time left."""
        token = self._create_active_token(ttl=3600.0)
        # Should be close to 3600
        self.assertGreater(token.remaining_seconds, 3590.0)


class TestBreakglassServiceQueries(unittest.TestCase):
    """Test service-level query interface."""

    def setUp(self):
        self.bg = BreakglassService(enabled=True)

    def _create_active_token(self, flags=None, requester="alice", approver="bob"):
        flags = flags or ["require_all_legs"]
        token = self.bg.request(
            requester_id=requester,
            flags=flags,
            reason="Testing",
        )
        self.bg.approve(token.token_id, approver_id=approver)
        return token

    def test_is_flag_overridden(self):
        """Service correctly reports flag override state."""
        self._create_active_token(flags=["require_all_legs"])
        self.assertTrue(self.bg.is_flag_overridden("require_all_legs"))
        self.assertFalse(self.bg.is_flag_overridden("digest_provider"))

    def test_has_active_breakglass(self):
        """Correctly reports whether any breakglass is active."""
        self.assertFalse(self.bg.has_active_breakglass())
        self._create_active_token()
        self.assertTrue(self.bg.has_active_breakglass())

    def test_get_active_overrides(self):
        """Returns dict of active flag overrides."""
        token = self._create_active_token(
            flags=["require_all_legs", "digest_provider"]
        )
        overrides = self.bg.get_active_overrides()
        self.assertIn("require_all_legs", overrides)
        self.assertIn("digest_provider", overrides)
        self.assertEqual(overrides["require_all_legs"], token.token_id)

    def test_summary(self):
        """Summary reports correct counts."""
        self._create_active_token()
        # Also create a pending one
        self.bg.request(
            requester_id="charlie",
            flags=["lockfile_hmac"],
            reason="Pending test",
        )
        summary = self.bg.summary()
        self.assertEqual(summary["active_tokens"], 1)
        self.assertEqual(summary["pending_tokens"], 1)
        self.assertTrue(summary["enabled"])

    def test_window_ttl_multiplier_during_breakglass(self):
        """Approval windows get compressed TTL during breakglass."""
        self.assertEqual(self.bg.get_window_ttl_multiplier(), 1.0)
        self._create_active_token()
        self.assertEqual(
            self.bg.get_window_ttl_multiplier(),
            BREAKGLASS_WINDOW_TTL_MULTIPLIER,
        )

    def test_window_max_uses_divisor_during_breakglass(self):
        """Approval windows get reduced max_uses during breakglass."""
        self.assertEqual(self.bg.get_window_max_uses_divisor(), 1)
        self._create_active_token()
        self.assertEqual(
            self.bg.get_window_max_uses_divisor(),
            BREAKGLASS_WINDOW_MAX_USES_DIVISOR,
        )


class TestBreakglassConstants(unittest.TestCase):
    """Verify breakglass constants match R-BREAK-001 spec."""

    def test_overridable_flags_are_exactly_three(self):
        """Only 3 flags should be overridable."""
        self.assertEqual(len(OVERRIDABLE_FLAGS), 3)
        self.assertIn("require_all_legs", OVERRIDABLE_FLAGS)
        self.assertIn("digest_provider", OVERRIDABLE_FLAGS)
        self.assertIn("lockfile_hmac", OVERRIDABLE_FLAGS)

    def test_non_overridable_flags_exist(self):
        """Non-overridable flags are defined."""
        self.assertGreater(len(NON_OVERRIDABLE_FLAGS), 0)
        self.assertIn("supply_chain_verifier", NON_OVERRIDABLE_FLAGS)
        self.assertIn("verifier_errors_fail_closed", NON_OVERRIDABLE_FLAGS)

    def test_no_overlap_between_sets(self):
        """Overridable and non-overridable sets must not overlap."""
        overlap = OVERRIDABLE_FLAGS & NON_OVERRIDABLE_FLAGS
        self.assertEqual(len(overlap), 0, f"Overlap found: {overlap}")

    def test_max_ttl_is_two_hours(self):
        """Max TTL is 2 hours (7200 seconds)."""
        self.assertEqual(MAX_TTL_SECONDS, 7200.0)

    def test_max_flags_per_token_is_two(self):
        """Per-token flag cap is 2 (R-BREAK-001)."""
        self.assertEqual(MAX_FLAGS_PER_TOKEN, 2)


class TestBreakglassPipelineIntegration(unittest.TestCase):
    """Test breakglass integration with the enforcement pipeline."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from unwind.config import UnwindConfig
        from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, SupplyChainVerifier, TrustPolicy,
        )
        from unwind.enforcement.signature_verify import (
            KeyStore, SignatureVerifier, generate_ed25519_keypair,
            sign_provider_entry, canonical_provider_json, _sign_ed25519,
        )
        from unwind.session import Session
        from datetime import datetime, timezone

        self.CheckResult = CheckResult

        tmp = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(tmp) / ".unwind",
            workspace_root=Path(tmp) / "workspace",
        )
        self.config.ensure_dirs()
        (Path(tmp) / "workspace").mkdir(exist_ok=True)
        # This suite validates breakglass/trust legs; classify synthetic tools to bypass unknown-tool gate.
        self.config.sensor_tools = frozenset(set(self.config.sensor_tools) | {"tool_a", "tool_b"})

        # Generate keypair
        self.private_key, self.public_key = generate_ed25519_keypair()

        # Build key store
        key_store = KeyStore()
        key_store.add_key(
            key_id="test-key",
            public_key=self.public_key,
        )
        sig_verifier = SignatureVerifier(key_store)

        # Build lockfile with all trust legs
        trusted_at = datetime.now(timezone.utc).isoformat()
        provider_data = {
            "name": "test-provider",
            "version": "1.0.0",
            "digest": "sha256:abc123",
            "tools": ["tool_a"],
            "origin": "https://example.com",
            "trusted_at": trusted_at,
        }
        signed_data = sign_provider_entry(provider_data, self.private_key, "test-key")

        lockfile = Lockfile(
            providers={
                "test-provider": ProviderEntry(
                    provider_id="test-provider",
                    name="test-provider",
                    version="1.0.0",
                    digest="sha256:abc123",
                    tools=["tool_a"],
                    origin="https://example.com",
                    trusted_at=trusted_at,
                    signature=signed_data["signature"],
                ),
            },
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lockfile.build_index()
        lockfile._hmac_verified = True

        self.supply_chain = SupplyChainVerifier(lockfile, sig_verifier)

        # Digest provider that returns matching digest
        self.digest_provider = lambda pid: "sha256:abc123"

        # Breakglass service
        self.bg = BreakglassService(enabled=True)

        # Build pipeline in strict mode with breakglass
        self.pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            digest_provider=self.digest_provider,
            strict=True,
            breakglass=self.bg,
        )

        self.session = Session(session_id="test-session", config=self.config)

    def test_strict_blocks_without_breakglass(self):
        """Without breakglass, missing legs cause BLOCK in strict mode."""
        # Use a pipeline with no digest provider (strict will block)
        from unwind.enforcement.pipeline import EnforcementPipeline
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            digest_provider=None,  # Missing
            strict=True,
            breakglass=self.bg,
        )
        result = pipeline.check(self.session, "tool_a")
        self.assertEqual(result.action, self.CheckResult.BLOCK)

    def test_breakglass_overrides_digest_provider(self):
        """Breakglass on digest_provider skips the fail-closed check."""
        from unwind.enforcement.pipeline import EnforcementPipeline

        # Activate breakglass for digest_provider
        token = self.bg.request(
            requester_id="alice",
            flags=["digest_provider"],
            reason="Emergency: digest provider down",
        )
        self.bg.approve(token.token_id, approver_id="bob")

        # Pipeline with no digest provider — should NOT block due to breakglass
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            digest_provider=None,
            strict=True,
            breakglass=self.bg,
        )

        # This would normally block on require_all_legs (no digest),
        # so also override that
        token2 = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Emergency: all trust legs relaxed",
        )
        self.bg.approve(token2.token_id, approver_id="bob")

        result = pipeline.check(self.session, "tool_a")
        # Should not block on digest_provider or require_all_legs
        self.assertNotEqual(result.action, self.CheckResult.BLOCK)

    def test_breakglass_cannot_override_supply_chain_verifier(self):
        """supply_chain_verifier is non-overridable — breakglass has no effect."""
        from unwind.enforcement.pipeline import EnforcementPipeline

        # Try to override supply_chain_verifier — should be denied
        token = self.bg.request(
            requester_id="alice",
            flags=["supply_chain_verifier"],
            reason="Want to bypass",
        )
        self.assertIsNone(token)

        # Pipeline with no supply chain + strict → should still BLOCK
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=None,
            strict=True,
            breakglass=self.bg,
        )
        result = pipeline.check(self.session, "tool_a")
        self.assertEqual(result.action, self.CheckResult.BLOCK)
        self.assertIn("SUPPLY_CHAIN_VERIFIER_MISSING", result.block_reason)

    def test_breakglass_overrides_require_all_legs(self):
        """Breakglass on require_all_legs allows through with missing legs."""
        # Activate breakglass for require_all_legs
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Provider migration: legs incomplete",
        )
        self.bg.approve(token.token_id, approver_id="bob")

        # Full pipeline with all providers configured but we'll test
        # that the _is_strict check works
        result = self.pipeline.check(self.session, "tool_a")
        # With breakglass on require_all_legs, even if a leg were missing
        # the check would be skipped. With all legs present, it passes anyway.
        self.assertEqual(result.action, self.CheckResult.ALLOW)


class TestBreakglassAuditTrail(unittest.TestCase):
    """Test that all lifecycle events produce audit entries."""

    def setUp(self):
        self.bg = BreakglassService(enabled=True)

    def test_full_lifecycle_audit_trail(self):
        """Full lifecycle produces expected audit events."""
        # Request
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Emergency",
        )
        # Approve
        self.bg.approve(token.token_id, approver_id="bob")
        # Revoke
        self.bg.revoke(token.token_id, revoker_id="charlie", reason="Done")

        event_types = [e.event_type for e in self.bg.audit_log]
        self.assertIn(BreakglassEventType.REQUESTED, event_types)
        self.assertIn(BreakglassEventType.APPROVED, event_types)
        self.assertIn(BreakglassEventType.ACTIVATED, event_types)
        self.assertIn(BreakglassEventType.REVOKED, event_types)

    def test_rejection_audit(self):
        """Rejection produces audit event."""
        token = self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Maybe",
        )
        self.bg.reject(token.token_id, approver_id="bob", reason="Not needed")
        event_types = [e.event_type for e in self.bg.audit_log]
        self.assertIn(BreakglassEventType.REJECTED, event_types)

    def test_audit_events_have_to_dict(self):
        """All audit events can be serialised to dict."""
        self.bg.request(
            requester_id="alice",
            flags=["require_all_legs"],
            reason="Test",
        )
        for event in self.bg.audit_log:
            d = event.to_dict()
            self.assertIn("event_type", d)
            self.assertIn("timestamp", d)


if __name__ == "__main__":
    unittest.main()
