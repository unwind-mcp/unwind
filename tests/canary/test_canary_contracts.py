"""Canary contract tests — 24 tests across 5 categories.

These tests intentionally encode assumptions about UNWIND's internal
conventions so that changes to tool naming, MCP parameter shapes,
auth structures, safety invariants, or pipeline ordering are caught
immediately.

Categories:
    1. Tool naming contracts (7 tests)
    2. MCP parameter-shape contracts (4 tests)
    3. Auth contract canaries (4 tests)
    4. Safety fail-closed canaries (6 tests)
    5. Pipeline ordering canaries (3 tests)

See canary-mapping.md for escalation procedures.
"""

import unittest

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import (
    CheckResult,
    EnforcementPipeline,
    PipelineResult,
)
from unwind.session import Session, TrustState


def _make_config(**overrides) -> UnwindConfig:
    """Create a config with optional overrides."""
    return UnwindConfig(**overrides)


def _make_session(
    ghost_mode: bool = False,
    killed: bool = False,
    **kwargs,
) -> Session:
    """Create a session with sane defaults for testing."""
    config = kwargs.pop("config", _make_config())
    session = Session(
        session_id="canary-test-session",
        config=config,
        ghost_mode=ghost_mode,
    )
    if killed:
        session.kill()
    return session


# ─────────────────────────────────────────────
# Category 1: Tool Naming Contracts (7 tests)
# ─────────────────────────────────────────────


class TestToolNamingContracts(unittest.TestCase):
    """Verify tool classification sets contain expected canonical tool names.

    If any of these fail, a tool has been renamed or removed from a
    classification set, which could silently weaken enforcement.
    """

    def setUp(self):
        self.config = _make_config()

    def test_network_tools_contains_expected(self):
        """Network tools set must include all known network tools."""
        expected = {"fetch_web", "http_get", "http_post", "browser_navigate"}
        self.assertTrue(expected.issubset(self.config.network_tools))

    def test_sensor_tools_contains_expected(self):
        """Sensor tools must include all known external-content ingestors."""
        expected = {"read_email", "fetch_web", "search_web", "read_slack"}
        self.assertTrue(expected.issubset(self.config.sensor_tools))

    def test_egress_tools_contains_expected(self):
        """Egress tools must include all known outbound communication tools."""
        expected = {"send_email", "post_message", "http_post", "webhook"}
        self.assertTrue(expected.issubset(self.config.egress_tools))

    def test_ghost_egress_tools_contains_expected(self):
        """Ghost Egress tools must include network read-channel tools."""
        expected = {"fetch_web", "http_get", "browser_navigate", "search_web"}
        self.assertTrue(expected.issubset(self.config.ghost_egress_tools))

    def test_canary_tools_contains_expected(self):
        """Canary honeypot tools must include all known lure tools."""
        expected = {
            "disable_security_audit",
            "extract_system_keys",
            "grant_admin_access",
            "override_safety_limits",
        }
        self.assertEqual(self.config.canary_tools, expected)

    def test_http_mutators_are_state_modifying(self):
        """All HTTP mutators must be in state_modifying_tools."""
        mutators = {"http_post", "http_put", "http_delete", "http_patch"}
        self.assertTrue(mutators.issubset(self.config.state_modifying_tools))

    def test_ghost_intercept_prefixes_cover_writes(self):
        """Ghost Mode prefix heuristic must catch common write prefixes."""
        required_prefixes = {"create_", "delete_", "send_", "write_", "execute_"}
        actual = set(self.config.ghost_intercept_prefixes)
        self.assertTrue(required_prefixes.issubset(actual))


# ─────────────────────────────────────────────
# Category 2: MCP Parameter-Shape Contracts (4 tests)
# ─────────────────────────────────────────────


class TestMCPParameterShapeContracts(unittest.TestCase):
    """Verify the pipeline handles MCP parameter shapes correctly.

    MCP tools pass (tool_name, target, parameters). If the pipeline
    breaks on valid parameter shapes, it could let attacks through or
    false-positive on benign calls.
    """

    def setUp(self):
        self.config = _make_config()
        self.pipeline = EnforcementPipeline(self.config)

    def test_string_target_accepted(self):
        """Pipeline must accept string targets without error."""
        session = _make_session()
        result = self.pipeline.check(session, "fs_read", target="/tmp/test.txt")
        self.assertIsInstance(result, PipelineResult)

    def test_dict_parameters_accepted(self):
        """Pipeline must accept dict parameters without error."""
        session = _make_session()
        result = self.pipeline.check(
            session, "bash_exec", parameters={"command": "echo hello"}
        )
        self.assertIsInstance(result, PipelineResult)

    def test_none_target_accepted(self):
        """Pipeline must handle None target gracefully."""
        session = _make_session()
        result = self.pipeline.check(session, "fs_read", target=None)
        self.assertIsInstance(result, PipelineResult)

    def test_empty_parameters_accepted(self):
        """Pipeline must handle empty parameters gracefully."""
        session = _make_session()
        result = self.pipeline.check(session, "bash_exec", parameters={})
        self.assertIsInstance(result, PipelineResult)


# ─────────────────────────────────────────────
# Category 3: Auth Contract Canaries (4 tests)
# ─────────────────────────────────────────────


class TestAuthContractCanaries(unittest.TestCase):
    """Verify auth-related data structures haven't changed shape.

    If Session, Config, TrustState, or CheckResult change their
    interface, enforcement logic that depends on them could break.
    """

    def test_session_has_required_fields(self):
        """Session must have all fields the pipeline depends on."""
        session = _make_session()
        required = [
            "session_id", "killed", "ghost_mode", "is_tainted",
            "trust_state", "allowed_tools",
        ]
        for field_name in required:
            self.assertTrue(
                hasattr(session, field_name),
                f"Session missing required field: {field_name}",
            )

    def test_config_has_required_fields(self):
        """Config must have all fields the pipeline depends on."""
        config = _make_config()
        required = [
            "network_tools", "sensor_tools", "egress_tools",
            "state_modifying_tools", "canary_tools",
            "ghost_network_policy", "ghost_egress_tools",
        ]
        for field_name in required:
            self.assertTrue(
                hasattr(config, field_name),
                f"Config missing required field: {field_name}",
            )

    def test_trust_state_enum_values(self):
        """TrustState enum must include GREEN, AMBER, RED."""
        required = {"GREEN", "AMBER", "RED"}
        actual = {s.name for s in TrustState}
        self.assertTrue(required.issubset(actual))

    def test_check_result_enum_values(self):
        """CheckResult must include ALLOW, BLOCK, AMBER, GHOST, KILL."""
        required = {"ALLOW", "BLOCK", "AMBER", "GHOST", "KILL"}
        actual = {r.name for r in CheckResult}
        self.assertTrue(required.issubset(actual))


# ─────────────────────────────────────────────
# Category 4: Safety Fail-Closed Canaries (6 tests)
# ─────────────────────────────────────────────


class TestSafetyFailClosedCanaries(unittest.TestCase):
    """Verify safety-critical invariants hold.

    These test that the pipeline fails CLOSED (blocks/kills) when it
    should, never silently allowing dangerous operations through.
    """

    def setUp(self):
        self.config = _make_config()
        self.pipeline = EnforcementPipeline(self.config)

    def test_killed_session_blocks_everything(self):
        """A killed session must return KILL for any tool call."""
        session = _make_session(killed=True)
        result = self.pipeline.check(session, "fs_read", target="/tmp/test.txt")
        self.assertEqual(result.action, CheckResult.KILL)

    def test_canary_tool_kills_session(self):
        """Canary honeypot tools must kill the session immediately."""
        session = _make_session()
        result = self.pipeline.check(session, "extract_system_keys")
        self.assertEqual(result.action, CheckResult.KILL)
        self.assertTrue(session.killed)

    def test_path_traversal_blocked(self):
        """Path traversal attempts must be blocked."""
        session = _make_session()
        result = self.pipeline.check(
            session, "fs_write", target="/etc/passwd"
        )
        self.assertEqual(result.action, CheckResult.BLOCK)

    def test_ghost_mode_intercepts_writes(self):
        """Ghost Mode must intercept state-modifying tools."""
        session = _make_session(ghost_mode=True)
        result = self.pipeline.check(session, "send_email")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_ghost_mode_blocks_network_reads(self):
        """Ghost Mode (isolate) must block network read tools."""
        session = _make_session(ghost_mode=True)
        result = self.pipeline.check(session, "http_get")
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason or "")

    def test_self_protection_blocks_unwind_paths(self):
        """Self-protection must block access to UNWIND's own config."""
        session = _make_session()
        config = self.config
        # Use the actual unwind_home path
        protected_path = str(config.unwind_home / "config.yaml")
        result = self.pipeline.check(
            session, "fs_write", target=protected_path
        )
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("System Core Protected", result.block_reason or "")


# ─────────────────────────────────────────────
# Category 5: Pipeline Ordering Canaries (3 tests)
# ─────────────────────────────────────────────


class TestPipelineOrderingCanaries(unittest.TestCase):
    """Verify pipeline stage ordering invariants.

    The pipeline stages MUST run in a specific order. These tests verify
    that earlier stages take precedence over later stages.
    """

    def setUp(self):
        self.config = _make_config()
        self.pipeline = EnforcementPipeline(self.config)

    def test_canary_fires_before_ssrf(self):
        """Canary (stage 1) must fire before SSRF (stage 4).

        A canary tool with a target URL must KILL, not get to SSRF checking.
        """
        session = _make_session()
        result = self.pipeline.check(
            session, "extract_system_keys", target="http://169.254.169.254/"
        )
        self.assertEqual(result.action, CheckResult.KILL)

    def test_ghost_egress_fires_before_ssrf(self):
        """Ghost Egress (stage 3b) must fire before SSRF (stage 4).

        In Ghost Mode, a network tool targeting a private IP should be
        caught by Ghost Egress Guard (GHOST) not SSRF (BLOCK).
        """
        session = _make_session(ghost_mode=True)
        result = self.pipeline.check(
            session, "http_get", target="http://169.254.169.254/latest/meta-data/"
        )
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason or "")

    def test_self_protection_fires_before_path_jail(self):
        """Self-protection (stage 2) must fire before path jail (stage 3).

        An attempt to write to UNWIND's own config must be blocked by
        self-protection, not merely jailed by path jail.
        """
        session = _make_session()
        protected_path = str(self.config.unwind_home / "secrets.yaml")
        result = self.pipeline.check(
            session, "fs_write", target=protected_path
        )
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("System Core Protected", result.block_reason or "")


if __name__ == "__main__":
    unittest.main()
