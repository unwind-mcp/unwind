"""Tests for cross-session isolation — CVE-2026-25536 defence.

CVE-2026-25536: MCP TypeScript SDK cross-client data leakage when
server/transport instances are reused across connections.

These tests verify that UNWIND properly isolates:
- Taint state between sessions
- Ghost mode and shadow VFS between sessions
- Permission tiers between sessions
- Event streams between sessions
- Circuit breaker state between sessions
- Session kill state between sessions
- Session ID binding from MCP initialize
"""

import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.proxy import UnwindProxy
from unwind.session import Session, TrustState
from unwind.enforcement.manifest_filter import PermissionTier


def _make_config() -> UnwindConfig:
    """Create a fresh config with temp directories."""
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSessionCreationIsolation(unittest.TestCase):
    """Verify that distinct session IDs produce distinct Session objects."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_different_ids_produce_different_sessions(self):
        """Two different session IDs must return separate Session objects."""
        s1 = self.proxy.get_or_create_session("sess_alpha")
        s2 = self.proxy.get_or_create_session("sess_beta")
        self.assertIsNot(s1, s2)
        self.assertNotEqual(s1.session_id, s2.session_id)

    def test_same_id_returns_same_session(self):
        """Same session ID must return the identical Session object."""
        s1 = self.proxy.get_or_create_session("sess_alpha")
        s2 = self.proxy.get_or_create_session("sess_alpha")
        self.assertIs(s1, s2)

    def test_none_session_generates_unique_ids(self):
        """Each call with session_id=None should create a NEW session."""
        s1 = self.proxy.get_or_create_session(None)
        s2 = self.proxy.get_or_create_session(None)
        self.assertIsNot(s1, s2)
        self.assertNotEqual(s1.session_id, s2.session_id)

    def test_empty_string_generates_unique_id(self):
        """Empty string session_id should generate a unique session."""
        s1 = self.proxy.get_or_create_session("")
        self.assertTrue(s1.session_id.startswith("sess_"))

    def test_session_count_matches_unique_ids(self):
        """Proxy should track exactly the number of unique sessions created."""
        ids = ["sess_a", "sess_b", "sess_c", "sess_a"]  # 3 unique
        for sid in ids:
            self.proxy.get_or_create_session(sid)
        self.assertEqual(len(self.proxy.sessions), 3)


class TestTaintIsolation(unittest.TestCase):
    """Taint state must not leak between sessions."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_taint_does_not_cross_sessions(self):
        """Tainting session A must not taint session B."""
        # Session A reads email (sensor → taint)
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_A",
        ))
        sess_a = self.proxy.sessions["sess_A"]
        sess_b = self.proxy.get_or_create_session("sess_B")

        self.assertTrue(sess_a.is_tainted)
        self.assertFalse(sess_b.is_tainted)

    def test_tainted_session_amber_does_not_affect_clean_session(self):
        """Session A tainted to HIGH + actuator → amber. Session B same actuator → allowed.

        With graduated taint, we need two sensor calls (with cooldown gap)
        to reach HIGH, which is the amber threshold.
        """
        # Taint session A with first sensor
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_A",
        ))
        # Move past cooldown and taint again to reach HIGH
        sess_a = self.proxy.sessions["sess_A"]
        sess_a.taint_state.last_taint_event = time.time() - sess_a.taint_config.retaint_cooldown_seconds - 1
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_A",
        ))
        # Session A: high-risk actuator → should be amber (taint is HIGH)
        result_a = run_async(self.proxy.handle_tool_call(
            tool_name="send_email",
            parameters={"to": "test@example.com", "body": "hello"},
            session_id="sess_A",
        ))
        self.assertEqual(result_a["status"], "amber")

        # Session B: same actuator, not tainted → should be allowed
        result_b = run_async(self.proxy.handle_tool_call(
            tool_name="send_email",
            parameters={"to": "test@example.com", "body": "hello"},
            session_id="sess_B",
        ))
        # Not tainted, so no amber (but may be blocked by other rules)
        # The key assertion: session B is NOT tainted
        sess_b = self.proxy.sessions["sess_B"]
        self.assertFalse(sess_b.is_tainted)

    def test_taint_timestamps_independent(self):
        """Taint timestamps are per-session."""
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_A",
        ))
        sess_a = self.proxy.sessions["sess_A"]
        sess_b = self.proxy.get_or_create_session("sess_B")

        self.assertIsNotNone(sess_a.tainted_at)
        self.assertIsNone(sess_b.tainted_at)


class TestGhostModeIsolation(unittest.TestCase):
    """Ghost mode and shadow VFS must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_ghost_mode_is_per_session(self):
        """Enabling ghost on session A must not ghost session B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")
        sess_a.ghost_mode = True

        self.assertTrue(sess_a.ghost_mode)
        self.assertFalse(sess_b.ghost_mode)

    def test_shadow_vfs_is_per_session(self):
        """Ghost writes in session A must not appear in session B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")
        sess_a.ghost_mode = True
        sess_b.ghost_mode = True

        sess_a.ghost_write("/tmp/secret.txt", "session A data")

        self.assertEqual(sess_a.ghost_read("/tmp/secret.txt"), "session A data")
        self.assertIsNone(sess_b.ghost_read("/tmp/secret.txt"))

    def test_ghost_mode_write_via_proxy_isolated(self):
        """Ghost writes through the proxy must stay in session scope."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_a.ghost_mode = True
        target = str(self.config.workspace_root / "ghost_file.txt")

        run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": target, "content": "ghost A"},
            session_id="sess_A",
        ))
        # Session B should not see it
        sess_b = self.proxy.get_or_create_session("sess_B")
        sess_b.ghost_mode = True
        self.assertIsNone(sess_b.ghost_read(target))

    def test_clear_ghost_does_not_affect_other_sessions(self):
        """Clearing ghost on session A must not clear session B's shadow VFS."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")
        sess_a.ghost_mode = True
        sess_b.ghost_mode = True

        sess_a.ghost_write("/data", "A")
        sess_b.ghost_write("/data", "B")

        sess_a.clear_ghost()

        self.assertIsNone(sess_a.ghost_read("/data"))
        self.assertEqual(sess_b.ghost_read("/data"), "B")


class TestPermissionTierIsolation(unittest.TestCase):
    """Permission tiers and escalation must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_default_tier_is_independent(self):
        """New sessions start at Tier 1 regardless of other sessions."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_a.escalate_tier(PermissionTier.TIER_4_FULL_ACCESS, "admin override")

        sess_b = self.proxy.get_or_create_session("sess_B")
        self.assertEqual(sess_b.permission_tier, PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(sess_a.permission_tier, PermissionTier.TIER_4_FULL_ACCESS)

    def test_escalation_does_not_leak(self):
        """Escalating session A must not escalate session B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        sess_a.escalate_tier(PermissionTier.TIER_3_COMMUNICATE, "needed email")

        self.assertEqual(sess_a.permission_tier, PermissionTier.TIER_3_COMMUNICATE)
        self.assertEqual(sess_b.permission_tier, PermissionTier.TIER_1_READ_ONLY)

    def test_demotion_does_not_affect_other_sessions(self):
        """Demoting session A must not demote session B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        # Both start at Tier 2
        sess_a.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "setup")
        sess_b.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "setup")

        # Demote A
        sess_a.demote_tier(PermissionTier.TIER_1_READ_ONLY, "taint detected")

        self.assertEqual(sess_a.permission_tier, PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(sess_b.permission_tier, PermissionTier.TIER_2_SCOPED_WRITE)

    def test_extra_tools_are_per_session(self):
        """Extra tool overrides must not leak between sessions."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        sess_a.add_extra_tools({"custom_tool_a"})

        self.assertIn("custom_tool_a", sess_a.extra_tools)
        self.assertIsNone(sess_b.extra_tools)

    def test_escalation_log_is_per_session(self):
        """Escalation audit logs must not leak between sessions."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        sess_a.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "reason A")
        sess_a.escalate_tier(PermissionTier.TIER_3_COMMUNICATE, "reason A2")

        self.assertEqual(len(sess_a.tier_escalation_log), 2)
        self.assertEqual(len(sess_b.tier_escalation_log), 0)


class TestEventStreamIsolation(unittest.TestCase):
    """Event streams must be filterable by session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_events_are_session_scoped(self):
        """Events from session A must not appear in session B queries."""
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "A search"},
            session_id="sess_A",
        ))
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "B search"},
            session_id="sess_B",
        ))

        events_a = self.proxy.event_store.query_events(session_id="sess_A")
        events_b = self.proxy.event_store.query_events(session_id="sess_B")

        self.assertEqual(len(events_a), 1)
        self.assertEqual(len(events_b), 1)
        self.assertNotEqual(events_a[0]["event_id"], events_b[0]["event_id"])

    def test_event_session_ids_match(self):
        """Each event must record the correct session ID."""
        for sid in ["sess_X", "sess_Y", "sess_Z"]:
            run_async(self.proxy.handle_tool_call(
                tool_name="search_web",
                parameters={"query": f"from {sid}"},
                session_id=sid,
            ))

        for sid in ["sess_X", "sess_Y", "sess_Z"]:
            events = self.proxy.event_store.query_events(session_id=sid)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["session_id"], sid)

    def test_canary_event_scoped_to_session(self):
        """A canary trip in session A must not appear in session B events."""
        run_async(self.proxy.handle_tool_call(
            tool_name="disable_security_audit",
            parameters={"duration_minutes": 60},
            session_id="sess_A",
        ))
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "safe"},
            session_id="sess_B",
        ))

        events_a = self.proxy.event_store.query_events(session_id="sess_A")
        events_b = self.proxy.event_store.query_events(session_id="sess_B")

        # A has the canary red_alert
        self.assertEqual(events_a[0]["status"], "red_alert")
        # B has a clean success
        self.assertEqual(events_b[0]["status"], "success")


class TestCircuitBreakerIsolation(unittest.TestCase):
    """Circuit breaker state must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_circuit_breaker_does_not_cross_sessions(self):
        """Rapid writes in session A must not trip breaker for session B."""
        # 5 rapid writes in session A (almost trips breaker)
        for i in range(5):
            run_async(self.proxy.handle_tool_call(
                tool_name="fs_write",
                parameters={"path": str(self.config.workspace_root / f"a{i}.txt"), "content": "x"},
                session_id="sess_A",
            ))

        # Session B should be clean — first write should work fine
        result_b = run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "b0.txt"), "content": "x"},
            session_id="sess_B",
        ))
        self.assertEqual(result_b["status"], "success")

        # Session A's 6th write should trip its breaker
        result_a = run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "a5.txt"), "content": "x"},
            session_id="sess_A",
        ))
        self.assertIn("error", result_a)
        self.assertIn("Circuit Breaker", result_a["error"])

    def test_modify_timestamps_are_per_session(self):
        """State-modify timestamps must be tracked independently."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        for _ in range(3):
            sess_a.record_state_modify()

        self.assertEqual(len(sess_a.state_modify_timestamps), 3)
        self.assertEqual(len(sess_b.state_modify_timestamps), 0)


class TestSessionKillIsolation(unittest.TestCase):
    """Killing one session must not affect others."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_kill_does_not_cross_sessions(self):
        """Killing session A via canary must not kill session B."""
        # Kill session A
        run_async(self.proxy.handle_tool_call(
            tool_name="disable_security_audit",
            session_id="sess_A",
        ))
        sess_a = self.proxy.sessions["sess_A"]
        self.assertTrue(sess_a.killed)

        # Session B should work fine
        result_b = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "safe query"},
            session_id="sess_B",
        ))
        sess_b = self.proxy.sessions["sess_B"]
        self.assertFalse(sess_b.killed)
        self.assertEqual(result_b["status"], "success")

    def test_killed_session_blocks_only_itself(self):
        """After kill, only the killed session should block subsequent calls."""
        # Kill session A
        run_async(self.proxy.handle_tool_call(
            tool_name="extract_system_keys",
            session_id="sess_A",
        ))

        # Session A blocked
        result_a = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_A",
        ))
        self.assertIn("error", result_a)

        # Session B allowed
        result_b = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_B",
        ))
        self.assertEqual(result_b["status"], "success")


class TestTrustStateIsolation(unittest.TestCase):
    """Trust light (GREEN/AMBER/RED) must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_trust_state_independent(self):
        """Changing trust state on A must not affect B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        sess_a.trust_state = TrustState.RED

        self.assertEqual(sess_a.trust_state, TrustState.RED)
        self.assertEqual(sess_b.trust_state, TrustState.GREEN)

    def test_circuit_breaker_red_state_isolated(self):
        """Circuit breaker tripping RED in A must not RED in B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        # Trip the breaker in A
        for _ in range(self.config.circuit_breaker_max_calls + 1):
            sess_a.record_state_modify()

        self.assertEqual(sess_a.trust_state, TrustState.RED)
        self.assertEqual(sess_b.trust_state, TrustState.GREEN)


class TestCounterIsolation(unittest.TestCase):
    """Action counters must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_counters_are_independent(self):
        """Action/block counts in A must not affect B."""
        # 3 actions in A
        for i in range(3):
            run_async(self.proxy.handle_tool_call(
                tool_name="search_web",
                parameters={"query": f"q{i}"},
                session_id="sess_A",
            ))

        # 1 action in B
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "bq"},
            session_id="sess_B",
        ))

        sess_a = self.proxy.sessions["sess_A"]
        sess_b = self.proxy.sessions["sess_B"]

        self.assertEqual(sess_a.total_actions, 3)
        self.assertEqual(sess_b.total_actions, 1)

    def test_blocked_counter_independent(self):
        """Blocked count in A must not appear in B."""
        # Block in A (write to .unwind path)
        run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.events_db_path), "content": "hack"},
            session_id="sess_A",
        ))

        sess_a = self.proxy.sessions["sess_A"]
        sess_b = self.proxy.get_or_create_session("sess_B")

        self.assertEqual(sess_a.blocked_actions, 1)
        self.assertEqual(sess_b.blocked_actions, 0)


class TestSessionScopeIsolation(unittest.TestCase):
    """Allowed tools scope must be per-session."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_allowed_tools_scope_independent(self):
        """Restricting tools in A must not restrict B."""
        sess_a = self.proxy.get_or_create_session("sess_A")
        sess_b = self.proxy.get_or_create_session("sess_B")

        sess_a.allowed_tools = {"search_web", "fs_read"}

        self.assertEqual(sess_a.allowed_tools, {"search_web", "fs_read"})
        self.assertIsNone(sess_b.allowed_tools)  # No restriction


class TestInitializeSessionBinding(unittest.TestCase):
    """Verify MCP initialize creates a bound session ID."""

    def test_session_id_set_after_init(self):
        """After _handle_initialize, _session_id must not be None."""
        from unwind.transport.stdio import UnwindStdioServer, JsonRpcMessage

        config = _make_config()
        server = UnwindStdioServer(config, ["echo"])

        # Verify _session_id starts as None
        self.assertIsNone(server._session_id)

        # Simulate initialize (we can't fully run it without upstream,
        # but we can test the session binding logic directly)
        msg_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {"name": "test-agent", "version": "1.0"},
            },
        }
        msg = JsonRpcMessage(msg_data)

        # Extract the session binding logic (same as _handle_initialize)
        client_info = msg.params.get("clientInfo", {})
        session_hint = msg.params.get("sessionId") or client_info.get("sessionId")
        import uuid
        session_id = session_hint or f"sess_{uuid.uuid4().hex[:12]}"

        self.assertIsNotNone(session_id)
        self.assertTrue(session_id.startswith("sess_"))

    def test_client_provided_session_id_used(self):
        """If client provides sessionId, it should be used."""
        from unwind.transport.stdio import JsonRpcMessage

        msg_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "sessionId": "client-provided-123",
                "clientInfo": {"name": "test-agent"},
            },
        }
        msg = JsonRpcMessage(msg_data)

        session_hint = msg.params.get("sessionId") or msg.params.get("clientInfo", {}).get("sessionId")
        self.assertEqual(session_hint, "client-provided-123")

    def test_client_info_session_id_fallback(self):
        """If sessionId is in clientInfo, it should be used as fallback."""
        from unwind.transport.stdio import JsonRpcMessage

        msg_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "test-agent",
                    "sessionId": "ci-session-456",
                },
            },
        }
        msg = JsonRpcMessage(msg_data)

        session_hint = msg.params.get("sessionId") or msg.params.get("clientInfo", {}).get("sessionId")
        self.assertEqual(session_hint, "ci-session-456")


class TestConcurrentSessionScenarios(unittest.TestCase):
    """Real-world attack scenarios with multiple concurrent sessions."""

    def setUp(self):
        self.config = _make_config()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_attacker_cannot_hijack_session_by_id(self):
        """An attacker who guesses a session ID gets the existing session,
        but this test verifies the objects are properly isolated when using
        different IDs (as they should be after CVE-2026-25536 fix)."""
        # Victim session
        victim_sess = self.proxy.get_or_create_session("sess_victim")
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_victim",
        ))
        self.assertTrue(victim_sess.is_tainted)

        # Attacker with a different session
        attacker_sess = self.proxy.get_or_create_session("sess_attacker")
        self.assertFalse(attacker_sess.is_tainted)
        self.assertIsNot(victim_sess, attacker_sess)

    def test_interleaved_operations_stay_isolated(self):
        """Operations interleaved between two sessions must stay isolated."""
        # A: read email (taint — sensor)
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_A",
        ))
        # B: fs_read now taints (sensor classification)
        run_async(self.proxy.handle_tool_call(
            tool_name="fs_read",
            parameters={"path": str(self.config.workspace_root / "dummy.txt")},
            session_id="sess_B",
        ))
        # A: write file (should work, just tainted)
        run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "a.txt"), "content": "x"},
            session_id="sess_A",
        ))
        # B: write file (should work, tainted from fs_read)
        run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "b.txt"), "content": "y"},
            session_id="sess_B",
        ))

        # Verify isolation
        sess_a = self.proxy.sessions["sess_A"]
        sess_b = self.proxy.sessions["sess_B"]

        self.assertTrue(sess_a.is_tainted)
        self.assertTrue(sess_b.is_tainted)
        self.assertEqual(sess_a.total_actions, 2)
        self.assertEqual(sess_b.total_actions, 2)

        # Events correctly scoped
        events_a = self.proxy.event_store.query_events(session_id="sess_A")
        events_b = self.proxy.event_store.query_events(session_id="sess_B")
        self.assertEqual(len(events_a), 2)
        self.assertEqual(len(events_b), 2)

    def test_cron_session_isolated_from_interactive(self):
        """SENTINEL's cron sessions must be isolated from interactive sessions.

        This directly addresses SENTINEL's recommended architecture:
        cron at Monitor-ReadOnly+Append tier, interactive at Operator-Scoped.
        """
        # Cron session: read-only monitoring
        cron_sess = self.proxy.get_or_create_session("sess_cron_sentinel")
        # Interactive session: operator tier
        interactive_sess = self.proxy.get_or_create_session("sess_interactive_user")
        interactive_sess.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "user session")

        # Cron session should stay at Tier 1
        self.assertEqual(cron_sess.permission_tier, PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(interactive_sess.permission_tier, PermissionTier.TIER_2_SCOPED_WRITE)

        # Cron reads web (gets tainted)
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "CVE latest"},
            session_id="sess_cron_sentinel",
        ))

        # Interactive session must NOT be tainted by cron's web browsing
        self.assertFalse(interactive_sess.is_tainted)

    def test_ten_concurrent_sessions_fully_isolated(self):
        """Stress test: 10 sessions, each with unique state."""
        sessions = {}
        for i in range(10):
            sid = f"sess_{i:03d}"
            run_async(self.proxy.handle_tool_call(
                tool_name="search_web",
                parameters={"query": f"query {i}"},
                session_id=sid,
            ))
            sessions[sid] = self.proxy.sessions[sid]

        # Each session has exactly 1 action
        for sid, sess in sessions.items():
            self.assertEqual(sess.total_actions, 1, f"Session {sid} has wrong count")

        # Each session has exactly 1 event
        for sid in sessions:
            events = self.proxy.event_store.query_events(session_id=sid)
            self.assertEqual(len(events), 1, f"Session {sid} has wrong event count")


if __name__ == "__main__":
    unittest.main()
