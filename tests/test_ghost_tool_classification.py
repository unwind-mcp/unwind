"""Tests for Ghost Mode tool classification in the enforcement pipeline.

Verifies that:
1. All HTTP mutators (PUT, DELETE, PATCH) are intercepted
2. Database write operations are intercepted
3. Git state-modifying operations are intercepted
4. Shell exec tools are intercepted
5. Prefix heuristic catches unlisted tools
6. Read-only tools pass through Ghost Mode
7. GET-as-mutation limitation is documented (http_get is NOT intercepted)
8. Pipeline's state_modifying_tools and ghost_intercept are aligned
"""

import os
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import (
    CheckResult,
    EnforcementPipeline,
    PipelineResult,
)
from unwind.session import Session, TrustState


class TestGhostModeToolSets(unittest.TestCase):
    """Verify tool set membership without running the full pipeline."""

    def setUp(self):
        self.config = UnwindConfig()

    # ── Explicit state_modifying_tools membership ──

    def test_http_mutators_in_state_modifying(self):
        """All HTTP write methods must be in state_modifying_tools."""
        for tool in ("http_post", "http_put", "http_delete", "http_patch"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_db_write_ops_in_state_modifying(self):
        """Database write operations must be state-modifying."""
        for tool in ("db_insert", "db_update", "db_delete", "db_execute",
                      "sql_execute", "query_execute"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_git_write_ops_in_state_modifying(self):
        """Git state-modifying ops must be in state_modifying_tools."""
        for tool in ("git_commit", "git_push", "git_checkout", "git_merge"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_shell_exec_in_state_modifying(self):
        """Shell execution tools must be state-modifying."""
        for tool in ("bash_exec", "shell_exec", "run_command", "execute_command"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_filesystem_ops_in_state_modifying(self):
        """Filesystem write operations must be state-modifying."""
        for tool in ("fs_write", "fs_delete", "fs_rename", "fs_mkdir",
                      "fs_move", "fs_copy", "write_file", "delete_file",
                      "rename_file", "move_file", "create_directory"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_communication_in_state_modifying(self):
        """Communication tools must be state-modifying."""
        for tool in ("send_email", "post_message", "send_message", "reply_email"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    def test_package_mgmt_in_state_modifying(self):
        """Package management tools must be state-modifying."""
        for tool in ("install_package", "pip_install", "npm_install"):
            self.assertIn(tool, self.config.state_modifying_tools, f"{tool} missing")

    # ── is_ghost_intercepted ──

    def test_all_state_modifying_are_ghost_intercepted(self):
        """Everything in state_modifying_tools must be ghost-intercepted."""
        for tool in self.config.state_modifying_tools:
            self.assertTrue(
                self.config.is_ghost_intercepted(tool),
                f"{tool} in state_modifying but NOT ghost-intercepted",
            )

    def test_prefix_heuristic_catches_unlisted_tools(self):
        """Prefix heuristic catches tools not in explicit list."""
        for tool in (
            "create_ticket", "delete_record", "remove_user",
            "update_profile", "modify_settings", "send_notification",
            "post_comment", "put_data", "write_config", "set_value",
            "insert_row", "drop_table", "execute_query", "run_script",
            "install_plugin", "push_changes",
        ):
            self.assertTrue(
                self.config.is_ghost_intercepted(tool),
                f"Prefix heuristic should catch '{tool}'",
            )

    def test_read_tools_not_ghost_intercepted(self):
        """Read-only tools must NOT be ghost-intercepted."""
        for tool in (
            "fs_read", "fs_list", "http_get", "fetch_web",
            "search_web", "read_email", "read_document",
            "list_directory", "get_status", "read_config",
            "search_docs", "browse_web", "query_data",
        ):
            self.assertFalse(
                self.config.is_ghost_intercepted(tool),
                f"Read tool '{tool}' should NOT be ghost-intercepted",
            )

    def test_http_get_not_intercepted_known_limitation(self):
        """http_get is NOT intercepted — documented limitation.

        GET-as-mutation (e.g. GET /api/delete?id=5) is a known gap.
        We can't block all GETs without breaking read operations.
        """
        self.assertFalse(self.config.is_ghost_intercepted("http_get"))
        self.assertNotIn("http_get", self.config.state_modifying_tools)
        # But it IS in network_tools (SSRF protection still applies)
        self.assertIn("http_get", self.config.network_tools)

    # ── High-risk actuator alignment ──

    def test_high_risk_subset_of_state_modifying(self):
        """high_risk_actuator_tools must be a subset of state_modifying_tools."""
        diff = self.config.high_risk_actuator_tools - self.config.state_modifying_tools
        self.assertEqual(
            diff, set(),
            f"High-risk tools not in state_modifying: {diff}",
        )

    def test_high_risk_includes_http_mutators(self):
        """HTTP mutators should be high-risk (taint gating applies)."""
        for tool in ("http_post", "http_put", "http_delete", "http_patch"):
            self.assertIn(tool, self.config.high_risk_actuator_tools, f"{tool} missing")

    # ── Egress tool alignment ──

    def test_egress_includes_http_mutators(self):
        """HTTP mutators should be subject to DLP scanning."""
        for tool in ("http_post", "http_put", "http_delete", "http_patch"):
            self.assertIn(tool, self.config.egress_tools, f"{tool} missing from egress")

    # ── Parity with standalone Ghost Mode proxy ──

    def test_parity_with_standalone_proxy(self):
        """Pipeline should intercept everything the standalone proxy does."""
        from ghostmode.proxy import DEFAULT_WRITE_TOOLS
        for tool in DEFAULT_WRITE_TOOLS:
            self.assertTrue(
                self.config.is_ghost_intercepted(tool),
                f"Standalone proxy intercepts '{tool}' but pipeline does not",
            )


class TestGhostModePipelineGate(unittest.TestCase):
    """Integration tests: verify Ghost Mode gate in the actual pipeline."""

    def setUp(self):
        self.config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
        )
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.pipeline = EnforcementPipeline(self.config)
        self._orig_cwd = os.getcwd()
        os.chdir(str(self.config.workspace_root))

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def _make_session(self, ghost_mode=True):
        session = Session(
            session_id="test-ghost-gate",
            config=self.config,
        )
        session.ghost_mode = ghost_mode
        return session

    def test_http_put_intercepted_in_ghost_mode(self):
        session = self._make_session()
        # Omit target to avoid SSRF/egress stages (tested separately)
        result = self.pipeline.check(session, "http_put")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_http_delete_intercepted_in_ghost_mode(self):
        session = self._make_session()
        result = self.pipeline.check(session, "http_delete")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_http_patch_intercepted_in_ghost_mode(self):
        session = self._make_session()
        result = self.pipeline.check(session, "http_patch")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_db_execute_intercepted_in_ghost_mode(self):
        session = self._make_session()
        result = self.pipeline.check(session, "db_execute")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_git_push_intercepted_in_ghost_mode(self):
        session = self._make_session()
        result = self.pipeline.check(session, "git_push")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_shell_exec_intercepted_in_ghost_mode(self):
        session = self._make_session()
        result = self.pipeline.check(session, "shell_exec")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_webhook_intercepted_in_ghost_mode(self):
        """webhook is ghost-intercepted. Omit target to avoid SSRF stage."""
        session = self._make_session()
        result = self.pipeline.check(session, "webhook")
        self.assertEqual(result.action, CheckResult.GHOST)

    def test_prefix_heuristic_unknown_tool_gets_amber_gate(self):
        """Unknown unlisted tool is fail-closed to AMBER before ghost stages."""
        session = self._make_session()
        result = self.pipeline.check(session, "create_jira_ticket")
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertIn("Unknown tool", result.amber_reason or "")

    def test_prefix_heuristic_delete_variant_unknown_gets_amber(self):
        session = self._make_session()
        result = self.pipeline.check(session, "delete_s3_object")
        self.assertEqual(result.action, CheckResult.AMBER)
        self.assertIn("Unknown tool", result.amber_reason or "")

    def test_http_get_ghosted_by_egress_guard(self):
        """http_get is caught by Ghost Egress Guard (stage 3b) in Ghost Mode.

        Even though http_get is not in state_modifying_tools, the Ghost Egress
        Guard blocks network-capable tools to prevent read-channel exfiltration.
        """
        session = self._make_session()
        result = self.pipeline.check(session, "http_get")
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("GHOST_MODE_NETWORK_BLOCKED", result.block_reason or "")

    def test_fs_read_passes_in_ghost_mode(self):
        """fs_read should pass through even in Ghost Mode."""
        session = self._make_session()
        result = self.pipeline.check(session, "fs_read", target="/tmp/test-workspace/file.txt")
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_non_ghost_session_allows_writes(self):
        """With ghost_mode=False, writes should ALLOW (not GHOST)."""
        session = self._make_session(ghost_mode=False)
        # Omit target to isolate ghost gate behavior from SSRF/DNS checks.
        result = self.pipeline.check(session, "http_put")
        self.assertEqual(result.action, CheckResult.ALLOW)

    def test_write_file_stores_in_shadow_vfs(self):
        """write_file (alternative name) should also store in shadow VFS."""
        session = self._make_session()
        target = str(self.config.workspace_root / "output.txt")
        result = self.pipeline.check(
            session, "write_file",
            target=target,
            payload="hello from ghost",
        )
        self.assertEqual(result.action, CheckResult.GHOST)
        # Verify shadow VFS has the content
        content = session.ghost_read(target)
        self.assertEqual(content, "hello from ghost")


class TestCircuitBreakerAlignment(unittest.TestCase):
    """Verify circuit breaker uses state_modifying_tools correctly."""

    def setUp(self):
        self.config = UnwindConfig(
            workspace_root=Path("/tmp/test-workspace"),
            circuit_breaker_max_calls=3,
            circuit_breaker_window_seconds=5.0,
        )
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.pipeline = EnforcementPipeline(self.config)
        self._orig_cwd = os.getcwd()
        os.chdir(str(self.config.workspace_root))

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def _make_session(self):
        return Session(
            session_id="test-circuit-breaker",
            config=self.config,
        )

    def test_http_put_triggers_circuit_breaker(self):
        """New HTTP mutators should count towards circuit breaker."""
        session = self._make_session()
        # Omit target to isolate circuit-breaker behavior from SSRF/DNS checks.
        for _ in range(3):
            self.pipeline.check(session, "http_put")
        result = self.pipeline.check(session, "http_put")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("Circuit Breaker", result.block_reason)

    def test_db_execute_triggers_circuit_breaker(self):
        """Database executes should count towards circuit breaker."""
        session = self._make_session()
        for _ in range(3):
            self.pipeline.check(session, "db_execute")
        result = self.pipeline.check(session, "db_execute")
        self.assertEqual(result.action, CheckResult.BLOCK)
        self.assertIn("Circuit Breaker", result.block_reason)


if __name__ == "__main__":
    unittest.main()
