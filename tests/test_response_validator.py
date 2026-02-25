"""Tests for Response Principal Validation (R-SESS-003/004) and Session Budgets (R-SEN-003)."""

import time
import unittest
from unittest.mock import MagicMock

from unwind.enforcement.response_validator import (
    ResponseValidator,
    SessionBudget,
    PendingRequest,
)


class TestResponseValidation(unittest.TestCase):
    """Test response→session principal matching."""

    def setUp(self):
        self.validator = ResponseValidator()

    def test_valid_response_matches(self):
        """Response for correct session should pass."""
        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_A", tool_name="search_web"
        )
        req, error = self.validator.validate_response(1, expected_session_id="sess_A")
        self.assertIsNotNone(req)
        self.assertIsNone(error)
        self.assertEqual(req.session_id, "sess_A")

    def test_unknown_upstream_id_rejected(self):
        """Response with unknown upstream_id should be rejected."""
        req, error = self.validator.validate_response(999)
        self.assertIsNone(req)
        self.assertIn("unknown upstream_id", error)

    def test_session_mismatch_rejected(self):
        """Response arriving on wrong session should be rejected (R-SESS-003)."""
        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_A", tool_name="fs_write"
        )
        req, error = self.validator.validate_response(1, expected_session_id="sess_B")
        self.assertIsNone(req)
        self.assertIn("principal violation", error)
        self.assertIn("R-SESS-003", error)

    def test_no_expected_session_skips_check(self):
        """Without expected_session_id, only checks upstream_id exists."""
        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_A"
        )
        req, error = self.validator.validate_response(1, expected_session_id=None)
        self.assertIsNotNone(req)
        self.assertIsNone(error)

    def test_response_consumed_once(self):
        """Each response should only be consumable once (prevents replay)."""
        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_A"
        )
        req1, _ = self.validator.validate_response(1)
        self.assertIsNotNone(req1)

        # Second attempt should fail — already consumed
        req2, error = self.validator.validate_response(1)
        self.assertIsNone(req2)
        self.assertIn("unknown upstream_id", error)

    def test_multiple_pending_requests(self):
        """Multiple requests from different sessions should track independently."""
        self.validator.register_request(upstream_id=1, agent_id=100, session_id="sess_A")
        self.validator.register_request(upstream_id=2, agent_id=200, session_id="sess_B")
        self.validator.register_request(upstream_id=3, agent_id=300, session_id="sess_A")

        self.assertEqual(self.validator.pending_count(), 3)

        # Validate each
        req_a, _ = self.validator.validate_response(1, "sess_A")
        self.assertEqual(req_a.agent_id, 100)

        req_b, _ = self.validator.validate_response(2, "sess_B")
        self.assertEqual(req_b.agent_id, 200)

        req_a2, _ = self.validator.validate_response(3, "sess_A")
        self.assertEqual(req_a2.agent_id, 300)

        self.assertEqual(self.validator.pending_count(), 0)

    def test_cross_session_attack_blocked(self):
        """Attacker session B should not receive session A's response."""
        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_victim"
        )
        # Attacker tries to claim the response
        req, error = self.validator.validate_response(1, expected_session_id="sess_attacker")
        self.assertIsNone(req)
        self.assertIn("principal violation", error)

    def test_pending_request_metadata(self):
        """Pending requests should preserve all metadata."""
        self.validator.register_request(
            upstream_id=42, agent_id=7, session_id="sess_X",
            tool_name="git_push", tag="tool_result"
        )
        req, _ = self.validator.validate_response(42)
        self.assertEqual(req.tool_name, "git_push")
        self.assertEqual(req.tag, "tool_result")
        self.assertIsNotNone(req.timestamp)


class TestSessionCancellation(unittest.TestCase):
    """Test cancelling all pending requests for a killed session."""

    def setUp(self):
        self.validator = ResponseValidator()

    def test_cancel_session_removes_all_requests(self):
        """Cancelling a session should remove all its pending requests."""
        self.validator.register_request(upstream_id=1, agent_id=100, session_id="sess_dead")
        self.validator.register_request(upstream_id=2, agent_id=200, session_id="sess_dead")
        self.validator.register_request(upstream_id=3, agent_id=300, session_id="sess_alive")

        cancelled = self.validator.cancel_session("sess_dead")
        self.assertEqual(cancelled, 2)
        self.assertEqual(self.validator.pending_count(), 1)

        # Alive session's request should still work
        req, _ = self.validator.validate_response(3, "sess_alive")
        self.assertIsNotNone(req)

    def test_cancel_resolves_futures(self):
        """Cancelling should resolve any asyncio futures with error."""
        import asyncio
        loop = asyncio.new_event_loop()
        future = loop.create_future()

        self.validator.register_request(
            upstream_id=1, agent_id=100, session_id="sess_kill",
            future=future
        )
        self.validator.cancel_session("sess_kill")
        self.assertTrue(future.done())
        self.assertIn("cancelled", future.result()["error"])
        loop.close()

    def test_cancel_nonexistent_session(self):
        """Cancelling a session with no requests should return 0."""
        cancelled = self.validator.cancel_session("sess_ghost")
        self.assertEqual(cancelled, 0)

    def test_pending_for_session(self):
        """Should return only requests for the specified session."""
        self.validator.register_request(upstream_id=1, agent_id=100, session_id="sess_A")
        self.validator.register_request(upstream_id=2, agent_id=200, session_id="sess_B")
        self.validator.register_request(upstream_id=3, agent_id=300, session_id="sess_A")

        pending_a = self.validator.pending_for_session("sess_A")
        self.assertEqual(len(pending_a), 2)
        self.assertTrue(all(r.session_id == "sess_A" for r in pending_a))


class TestSessionBudget(unittest.TestCase):
    """Test per-session resource budgets (R-SEN-003)."""

    def test_unlimited_budget_always_passes(self):
        """Budget with all zeros (unlimited) should never fail."""
        budget = SessionBudget()
        for _ in range(100):
            budget.record_tool_call()
        self.assertIsNone(budget.check_budget())

    def test_tool_call_limit(self):
        """Should fail when tool call limit is reached."""
        budget = SessionBudget(max_tool_calls=5)
        for _ in range(4):
            budget.record_tool_call()
            self.assertIsNone(budget.check_budget())

        budget.record_tool_call()  # 5th call
        result = budget.check_budget()
        self.assertIsNotNone(result)
        self.assertIn("tool calls", result)
        self.assertIn("R-SEN-003", result)

    def test_runtime_limit(self):
        """Should fail when runtime limit is exceeded."""
        budget = SessionBudget(max_runtime_seconds=0.1)
        self.assertIsNone(budget.check_budget())
        time.sleep(0.15)
        result = budget.check_budget()
        self.assertIsNotNone(result)
        self.assertIn("runtime", result)

    def test_output_bytes_limit(self):
        """Should fail when output bytes limit is exceeded."""
        budget = SessionBudget(max_output_bytes=1000)
        budget.record_output(500)
        self.assertIsNone(budget.check_budget())
        budget.record_output(600)
        result = budget.check_budget()
        self.assertIsNotNone(result)
        self.assertIn("output bytes", result)

    def test_write_bytes_limit(self):
        """Should fail when write bytes limit is exceeded."""
        budget = SessionBudget(max_write_bytes=512)
        budget.record_write(256)
        self.assertIsNone(budget.check_budget())
        budget.record_write(300)
        result = budget.check_budget()
        self.assertIsNotNone(result)
        self.assertIn("write bytes", result)

    def test_warning_threshold(self):
        """Should warn at 80% of budget."""
        budget = SessionBudget(max_tool_calls=10)
        for _ in range(7):
            budget.record_tool_call()
        self.assertIsNone(budget.check_warning_threshold())  # 70% OK

        budget.record_tool_call()  # 80%
        warning = budget.check_warning_threshold()
        self.assertIsNotNone(warning)
        self.assertIn("80%", warning)

    def test_custom_warning_threshold(self):
        """Should support custom warning threshold."""
        budget = SessionBudget(max_tool_calls=10)
        for _ in range(9):
            budget.record_tool_call()
        warning = budget.check_warning_threshold(threshold=0.9)
        self.assertIsNotNone(warning)

    def test_reset_clears_counters(self):
        """Reset should clear all counters for new cron invocation."""
        budget = SessionBudget(max_tool_calls=5)
        for _ in range(4):
            budget.record_tool_call()
        budget.record_output(1000)
        budget.record_write(500)

        budget.reset()
        self.assertEqual(budget.tool_calls, 0)
        self.assertEqual(budget.output_bytes, 0)
        self.assertEqual(budget.write_bytes, 0)
        self.assertIsNone(budget.check_budget())

    def test_sentinel_budget_values(self):
        """Test with SENTINEL's actual budget values from policy v0.2."""
        budget = SessionBudget(
            max_tool_calls=40,
            max_runtime_seconds=180,
            max_output_bytes=2097152,    # 2MB
            max_write_bytes=524288,      # 512KB
        )
        # Should pass initially
        self.assertIsNone(budget.check_budget())

        # 39 calls OK, 40th triggers
        for _ in range(39):
            budget.record_tool_call()
        self.assertIsNone(budget.check_budget())
        budget.record_tool_call()
        result = budget.check_budget()
        self.assertIsNotNone(result)
        self.assertIn("40/40", result)


class TestBudgetIntegration(unittest.TestCase):
    """Test budget management through ResponseValidator."""

    def setUp(self):
        self.validator = ResponseValidator()

    def test_set_and_check_budget(self):
        """Should set and check budgets per session."""
        budget = SessionBudget(max_tool_calls=3)
        self.validator.set_budget("sess_cron", budget)

        # First two calls OK
        self.assertIsNone(self.validator.record_tool_call("sess_cron"))
        self.assertIsNone(self.validator.record_tool_call("sess_cron"))

        # Third call hits limit
        result = self.validator.record_tool_call("sess_cron")
        self.assertIsNotNone(result)

    def test_no_budget_means_unlimited(self):
        """Sessions without a budget should be unlimited."""
        result = self.validator.record_tool_call("sess_interactive")
        self.assertIsNone(result)

    def test_budget_per_session(self):
        """Budgets should be independent per session."""
        self.validator.set_budget("sess_cron_a", SessionBudget(max_tool_calls=2))
        self.validator.set_budget("sess_cron_b", SessionBudget(max_tool_calls=5))

        # Exhaust A's budget
        self.validator.record_tool_call("sess_cron_a")
        self.validator.record_tool_call("sess_cron_a")

        # A should be blocked
        self.assertIsNotNone(self.validator.check_budget("sess_cron_a"))
        # B should still be fine
        self.assertIsNone(self.validator.check_budget("sess_cron_b"))

    def test_get_budget_returns_none_for_unset(self):
        """Getting budget for session with no budget returns None."""
        self.assertIsNone(self.validator.get_budget("sess_nobody"))


if __name__ == "__main__":
    unittest.main()
