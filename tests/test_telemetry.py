"""Tests for enforcement telemetry wiring (Punch #1) and budget idempotency telemetry (Punch #2).

Validates that:
- Trust gate decisions emit structured telemetry events
- Strict-mode blocks emit events with reason codes
- Breakglass overrides emit events
- Budget debit idempotency emits budget_debit_skipped_duplicate
- Budget debit emits budget_debit on first debit
- Budget exceeded emits budget_exceeded
- End-to-end: can reconstruct an incident from telemetry events
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult
from unwind.enforcement.supply_chain import (
    Lockfile,
    ProviderEntry,
    SupplyChainVerifier,
    TrustPolicy,
)
from unwind.enforcement.signature_verify import (
    KeyStore,
    SignatureVerifier,
    generate_ed25519_keypair,
    sign_provider_entry,
)
from unwind.enforcement.breakglass import BreakglassService
from unwind.enforcement.response_validator import ResponseValidator, SessionBudget
from unwind.enforcement.telemetry import (
    EnforcementTelemetry,
    EventType,
)
from unwind.session import Session


class TestHelpers:
    """Shared test fixtures."""

    @staticmethod
    def create_config():
        tmp = tempfile.mkdtemp()
        config = UnwindConfig(
            unwind_home=Path(tmp) / ".unwind",
            workspace_root=Path(tmp) / "workspace",
        )
        config.ensure_dirs()
        (Path(tmp) / "workspace").mkdir(exist_ok=True)
        # Tests in this module exercise trust/telemetry logic, not unknown-tool gating.
        config.sensor_tools = frozenset(set(config.sensor_tools) | {"tool_a", "tool_b"})
        return config

    @staticmethod
    def create_signed_lockfile():
        """Create a lockfile with all trust legs for testing."""
        private_key, public_key = generate_ed25519_keypair()

        key_store = KeyStore()
        key_store.add_key(key_id="test-key", public_key=public_key)
        sig_verifier = SignatureVerifier(key_store)

        trusted_at = datetime.now(timezone.utc).isoformat()
        provider_data = {
            "name": "test-provider",
            "version": "1.0.0",
            "digest": "sha256:abc123",
            "tools": ["tool_a", "tool_b"],
            "origin": "https://example.com",
            "trusted_at": trusted_at,
        }
        signed_data = sign_provider_entry(provider_data, private_key, "test-key")

        lockfile = Lockfile(
            providers={
                "test-provider": ProviderEntry(
                    provider_id="test-provider",
                    name="test-provider",
                    version="1.0.0",
                    digest="sha256:abc123",
                    tools=["tool_a", "tool_b"],
                    origin="https://example.com",
                    trusted_at=trusted_at,
                    signature=signed_data["signature"],
                ),
            },
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lockfile.build_index()
        lockfile._hmac_verified = True

        return lockfile, sig_verifier, private_key


class TestTrustGateTelemetry(unittest.TestCase):
    """Test that trust gate decisions emit telemetry events."""

    def setUp(self):
        self.config = TestHelpers.create_config()
        self.telemetry = EnforcementTelemetry()
        lockfile, sig_verifier, _ = TestHelpers.create_signed_lockfile()
        self.supply_chain = SupplyChainVerifier(lockfile, sig_verifier)

    def test_trusted_emits_event(self):
        """TRUSTED verdict emits trust_gate_trusted event."""
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            digest_provider=lambda pid: "sha256:abc123",
            strict=True,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s1", config=self.config)
        result = pipeline.check(session, "tool_a")
        self.assertEqual(result.action, CheckResult.ALLOW)

        trust_events = self.telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED)
        self.assertEqual(len(trust_events), 1)
        self.assertEqual(trust_events[0].session_id, "s1")
        self.assertEqual(trust_events[0].tool_name, "tool_a")
        self.assertEqual(trust_events[0].trust_verdict, "trusted")

    def test_blocked_provider_emits_event(self):
        """BLOCKED verdict emits trust_gate_blocked event."""
        # Add provider to blocklist
        self.supply_chain.add_to_blocklist("test-provider")

        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s2", config=self.config)
        result = pipeline.check(session, "tool_a")
        self.assertEqual(result.action, CheckResult.BLOCK)

        blocked_events = self.telemetry.events_by_type(EventType.TRUST_GATE_BLOCKED)
        self.assertEqual(len(blocked_events), 1)
        self.assertEqual(blocked_events[0].reason_code, "PROVIDER_BLOCKLISTED")
        self.assertEqual(blocked_events[0].provider_name, "test-provider")

    def test_quarantined_emits_event(self):
        """QUARANTINED verdict emits trust_gate_quarantined event."""
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=self.supply_chain,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s3", config=self.config)
        # Unknown tool → quarantined
        result = pipeline.check(session, "unknown_tool")
        self.assertEqual(result.action, CheckResult.AMBER)

        quarantine_events = self.telemetry.events_by_type(EventType.TRUST_GATE_QUARANTINED)
        self.assertEqual(len(quarantine_events), 1)
        self.assertEqual(quarantine_events[0].reason_code, "PROVIDER_QUARANTINED")


class TestStrictModeTelemetry(unittest.TestCase):
    """Test that strict-mode blocks emit telemetry with reason codes."""

    def setUp(self):
        self.config = TestHelpers.create_config()
        self.telemetry = EnforcementTelemetry()

    def test_supply_chain_verifier_missing_emits(self):
        """SUPPLY_CHAIN_VERIFIER_MISSING strict block emits telemetry."""
        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=None,
            strict=True,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s4", config=self.config)
        result = pipeline.check(session, "tool_a")
        self.assertEqual(result.action, CheckResult.BLOCK)

        strict_events = self.telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)
        self.assertEqual(len(strict_events), 1)
        self.assertEqual(strict_events[0].strict_flag, "supply_chain_verifier")
        self.assertEqual(strict_events[0].reason_code, "SUPPLY_CHAIN_VERIFIER_MISSING")

    def test_trust_leg_missing_emits(self):
        """TRUST_LEG_MISSING strict block emits telemetry."""
        lockfile, sig_verifier, _ = TestHelpers.create_signed_lockfile()
        supply_chain = SupplyChainVerifier(lockfile, sig_verifier)

        # No digest provider → all_legs check will fail on digest leg
        # But we also need to not block on digest_provider strict check
        # So use permissive digest_provider, but missing HMAC
        lockfile._hmac_verified = False  # Break HMAC leg

        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=supply_chain,
            digest_provider=lambda pid: "sha256:abc123",
            strict=True,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s5", config=self.config)
        result = pipeline.check(session, "tool_a")
        self.assertEqual(result.action, CheckResult.BLOCK)

        strict_events = self.telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)
        self.assertEqual(len(strict_events), 1)
        self.assertEqual(strict_events[0].reason_code, "TRUST_LEG_MISSING")


class TestBreakglassTelemetry(unittest.TestCase):
    """Test that breakglass overrides emit telemetry events."""

    def setUp(self):
        self.config = TestHelpers.create_config()
        self.telemetry = EnforcementTelemetry()
        self.bg = BreakglassService(enabled=True)

    def test_breakglass_override_emits_event(self):
        """Using a breakglass override emits STRICT_MODE_BREAKGLASS_OVERRIDE."""
        lockfile, sig_verifier, _ = TestHelpers.create_signed_lockfile()
        supply_chain = SupplyChainVerifier(lockfile, sig_verifier)

        # Activate breakglass for digest_provider and require_all_legs
        token = self.bg.request(
            requester_id="alice",
            flags=["digest_provider", "require_all_legs"],
            reason="Emergency migration",
        )
        self.bg.approve(token.token_id, approver_id="bob")

        pipeline = EnforcementPipeline(
            config=self.config,
            supply_chain_verifier=supply_chain,
            digest_provider=None,  # Missing — but overridden by breakglass
            strict=True,
            breakglass=self.bg,
            telemetry=self.telemetry,
        )
        session = Session(session_id="s6", config=self.config)
        result = pipeline.check(session, "tool_a")

        # Should have breakglass override events
        override_events = self.telemetry.events_by_type(
            EventType.STRICT_MODE_BREAKGLASS_OVERRIDE
        )
        self.assertGreater(len(override_events), 0)
        # Check that the token ID is recorded
        self.assertEqual(override_events[0].breakglass_token_id, token.token_id)


class TestBudgetIdempotencyTelemetry(unittest.TestCase):
    """Test that budget debit idempotency emits proper telemetry (Punch #2)."""

    def setUp(self):
        self.telemetry = EnforcementTelemetry()
        self.validator = ResponseValidator(telemetry=self.telemetry)

    def test_first_debit_emits_budget_debit(self):
        """First debit emits budget_debit event."""
        budget = SessionBudget(max_tool_calls=10)
        self.validator.set_budget("s1", budget)

        self.validator.record_tool_call("s1", upstream_id="req-001")

        debit_events = self.telemetry.events_by_type(EventType.BUDGET_DEBIT)
        self.assertEqual(len(debit_events), 1)
        self.assertEqual(debit_events[0].session_id, "s1")
        self.assertEqual(debit_events[0].upstream_id, "req-001")
        self.assertEqual(debit_events[0].budget_tool_calls, 1)

    def test_duplicate_debit_emits_skipped_duplicate(self):
        """Duplicate debit emits budget_debit_skipped_duplicate event."""
        budget = SessionBudget(max_tool_calls=10)
        self.validator.set_budget("s1", budget)

        # First debit
        self.validator.record_tool_call("s1", upstream_id="req-001")
        # Duplicate
        self.validator.record_tool_call("s1", upstream_id="req-001")

        skip_events = self.telemetry.events_by_type(
            EventType.BUDGET_DEBIT_SKIPPED_DUPLICATE
        )
        self.assertEqual(len(skip_events), 1)
        self.assertEqual(skip_events[0].session_id, "s1")
        self.assertEqual(skip_events[0].upstream_id, "req-001")
        self.assertEqual(skip_events[0].reason_code, "BUDGET_DEBIT_SKIPPED_DUPLICATE")

    def test_duplicate_does_not_inflate_count(self):
        """Duplicate debit doesn't inflate the tool call count."""
        budget = SessionBudget(max_tool_calls=10)
        self.validator.set_budget("s1", budget)

        self.validator.record_tool_call("s1", upstream_id="req-001")
        self.validator.record_tool_call("s1", upstream_id="req-001")
        self.validator.record_tool_call("s1", upstream_id="req-001")

        self.assertEqual(budget.tool_calls, 1)  # Only counted once

    def test_budget_exceeded_emits_event(self):
        """Budget exceeded emits budget_exceeded event."""
        budget = SessionBudget(max_tool_calls=2)
        self.validator.set_budget("s1", budget)

        self.validator.record_tool_call("s1", upstream_id="req-001")
        result = self.validator.record_tool_call("s1", upstream_id="req-002")

        self.assertIsNotNone(result)  # Budget exceeded string

        exceeded_events = self.telemetry.events_by_type(EventType.BUDGET_EXCEEDED)
        self.assertEqual(len(exceeded_events), 1)
        self.assertEqual(exceeded_events[0].reason_code, "BUDGET_EXCEEDED")

    def test_concurrent_dedup_keys(self):
        """Different upstream_ids are debited independently."""
        budget = SessionBudget(max_tool_calls=10)
        self.validator.set_budget("s1", budget)

        self.validator.record_tool_call("s1", upstream_id="req-001")
        self.validator.record_tool_call("s1", upstream_id="req-002")
        self.validator.record_tool_call("s1", upstream_id="req-001")  # Duplicate

        self.assertEqual(budget.tool_calls, 2)  # Two unique debits

        debit_events = self.telemetry.events_by_type(EventType.BUDGET_DEBIT)
        self.assertEqual(len(debit_events), 2)

        skip_events = self.telemetry.events_by_type(
            EventType.BUDGET_DEBIT_SKIPPED_DUPLICATE
        )
        self.assertEqual(len(skip_events), 1)


class TestEndToEndTelemetryReplay(unittest.TestCase):
    """Test that telemetry can reconstruct an incident end-to-end."""

    def test_incident_reconstruction(self):
        """Full pipeline run produces enough telemetry to reconstruct the decision."""
        config = TestHelpers.create_config()
        telemetry = EnforcementTelemetry()

        lockfile, sig_verifier, _ = TestHelpers.create_signed_lockfile()
        supply_chain = SupplyChainVerifier(lockfile, sig_verifier)

        pipeline = EnforcementPipeline(
            config=config,
            supply_chain_verifier=supply_chain,
            digest_provider=lambda pid: "sha256:abc123",
            strict=True,
            telemetry=telemetry,
        )

        session = Session(session_id="incident-001", config=config)

        # Successful call
        result = pipeline.check(session, "tool_a")
        self.assertEqual(result.action, CheckResult.ALLOW)

        # Query session events
        session_events = telemetry.events_for_session("incident-001")
        self.assertGreater(len(session_events), 0)

        # Should have at least a TRUSTED event
        event_types = [e.event_type for e in session_events]
        self.assertIn(EventType.TRUST_GATE_TRUSTED, event_types)

        # Verify we can get a summary
        summary = telemetry.summary()
        self.assertGreater(summary["total_events"], 0)
        self.assertIn(EventType.TRUST_GATE_TRUSTED, summary["by_type"])


class TestTelemetryEventSerialization(unittest.TestCase):
    """Test that telemetry events serialize properly."""

    def test_to_dict_omits_defaults(self):
        """to_dict omits empty/default fields."""
        telemetry = EnforcementTelemetry()
        telemetry.emit_trust_gate(
            event_type=EventType.TRUST_GATE_TRUSTED,
            session_id="s1",
            tool_name="tool_a",
            provider_id="p1",
            trust_verdict="trusted",
        )
        event = telemetry.event_log[0]
        d = event.to_dict()

        # Required fields present
        self.assertIn("event_type", d)
        self.assertIn("timestamp", d)
        self.assertIn("session_id", d)

        # Default/empty fields omitted
        self.assertNotIn("breakglass_token_id", d)
        self.assertNotIn("budget_tool_calls", d)

    def test_summary_counts_by_type(self):
        """summary() counts events by type."""
        telemetry = EnforcementTelemetry()
        telemetry.emit_trust_gate(
            event_type=EventType.TRUST_GATE_TRUSTED,
            session_id="s1",
        )
        telemetry.emit_trust_gate(
            event_type=EventType.TRUST_GATE_TRUSTED,
            session_id="s2",
        )
        telemetry.emit_trust_gate(
            event_type=EventType.TRUST_GATE_BLOCKED,
            session_id="s3",
        )

        summary = telemetry.summary()
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["by_type"][EventType.TRUST_GATE_TRUSTED], 2)
        self.assertEqual(summary["by_type"][EventType.TRUST_GATE_BLOCKED], 1)


if __name__ == "__main__":
    unittest.main()
