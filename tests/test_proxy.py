"""Tests for the UNWIND proxy core and CLI."""

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.proxy import UnwindProxy
from unwind.session import TrustState


class TestConfig:
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


def run_async(coro):
    """Helper to run async test methods."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestProxy(unittest.TestCase):
    """Test the UNWIND proxy core."""

    def setUp(self):
        self.config = TestConfig.create()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    def test_startup_creates_dirs(self):
        """Startup should create required directories."""
        self.assertTrue(self.config.unwind_home.exists())
        self.assertTrue(self.config.snapshots_dir.exists())
        self.assertTrue(self.config.events_db_path.exists())

    def test_session_creation(self):
        """Should create sessions on demand."""
        session = self.proxy.get_or_create_session("test_sess")
        self.assertEqual(session.session_id, "test_sess")
        # Same ID returns same session
        session2 = self.proxy.get_or_create_session("test_sess")
        self.assertIs(session, session2)

    def test_auto_session_id(self):
        """Should generate session ID if none provided."""
        session = self.proxy.get_or_create_session()
        self.assertTrue(session.session_id.startswith("sess_"))

    def test_allow_clean_action(self):
        """Clean read action should be allowed and logged."""
        result = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "weather today"},
            session_id="sess_001",
        ))
        self.assertEqual(result["status"], "success")
        # Verify event was logged
        events = self.proxy.event_store.query_events(session_id="sess_001")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tool"], "search_web")
        self.assertEqual(events[0]["status"], "success")

    def test_block_self_protection(self):
        """Access to .unwind paths should be blocked and logged."""
        result = run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.events_db_path), "content": "hacked"},
            session_id="sess_001",
        ))
        self.assertIn("error", result)
        self.assertIn("Permission Denied", result["error"])
        # Verify blocked event was logged
        events = self.proxy.event_store.query_events(session_id="sess_001")
        self.assertEqual(events[0]["status"], "blocked")

    def test_canary_kills_session(self):
        """Canary tool call should kill session and log RED alert."""
        result = run_async(self.proxy.handle_tool_call(
            tool_name="disable_security_audit",
            parameters={"duration_minutes": 60},
            session_id="sess_001",
        ))
        self.assertIn("error", result)
        self.assertIn("CANARY", result["error"])
        # Session should be killed
        session = self.proxy.sessions["sess_001"]
        self.assertTrue(session.killed)
        # Event should be red_alert
        events = self.proxy.event_store.query_events(session_id="sess_001")
        self.assertEqual(events[0]["status"], "red_alert")

    def test_taint_chain_produces_amber(self):
        """Multiple sensors then high-risk actuator should produce amber.

        With graduated taint, need two sensor calls (with cooldown gap)
        to reach HIGH → amber threshold.
        """
        # First sensor call → MEDIUM
        run_async(self.proxy.handle_tool_call(
            tool_name="read_email",
            parameters={"inbox": "primary"},
            session_id="sess_001",
        ))
        # Move past cooldown, second sensor → HIGH
        sess = self.proxy.sessions["sess_001"]
        sess.taint_state.last_taint_event = time.time() - sess.taint_config.retaint_cooldown_seconds - 1
        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_001",
        ))
        # High-risk actuator → should amber at HIGH
        result = run_async(self.proxy.handle_tool_call(
            tool_name="send_email",
            parameters={"to": "test@example.com", "body": "hello"},
            session_id="sess_001",
        ))
        self.assertEqual(result["status"], "amber")
        self.assertTrue(result["requires_confirmation"])

    def test_ghost_mode(self):
        """Ghost mode should intercept writes and return success."""
        session = self.proxy.get_or_create_session("sess_ghost")
        session.ghost_mode = True

        result = run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "test.txt"), "content": "ghost data"},
            session_id="sess_ghost",
        ))
        self.assertEqual(result["status"], "success")
        # File should NOT exist on disk
        self.assertFalse((self.config.workspace_root / "test.txt").exists())
        # Event should be ghost_success
        events = self.proxy.event_store.query_events(session_id="sess_ghost")
        self.assertEqual(events[0]["status"], "ghost_success")

    def test_ghost_mode_shadow_vfs_read(self):
        """Ghost mode should serve shadow VFS content on reads."""
        session = self.proxy.get_or_create_session("sess_ghost")
        session.ghost_mode = True
        target = str(self.config.workspace_root / "config.json")

        # Write in ghost mode
        run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": target, "content": '{"key": "value"}'},
            session_id="sess_ghost",
        ))
        # Read should return shadow content
        result = run_async(self.proxy.handle_tool_call(
            tool_name="fs_read",
            parameters={"path": target},
            session_id="sess_ghost",
        ))
        self.assertEqual(result["content"], '{"key": "value"}')

    def test_circuit_breaker(self):
        """Rapid state-modifying calls should trip the breaker."""
        for i in range(5):
            run_async(self.proxy.handle_tool_call(
                tool_name="fs_write",
                parameters={"path": str(self.config.workspace_root / f"f{i}.txt"), "content": "x"},
                session_id="sess_001",
            ))
        # 6th call should be blocked
        result = run_async(self.proxy.handle_tool_call(
            tool_name="fs_write",
            parameters={"path": str(self.config.workspace_root / "f5.txt"), "content": "x"},
            session_id="sess_001",
        ))
        self.assertIn("error", result)
        self.assertIn("Circuit Breaker", result["error"])

    def test_dlp_catches_secrets(self):
        """Credential exposure (stage 2c) catches secrets in params before DLP.

        Previously DLP-Lite at stage 5 caught this. Now the credential_exposure
        check at stage 2c fires first because send_email is an untrusted sink,
        so it returns BLOCK (not AMBER).
        """
        result = run_async(self.proxy.handle_tool_call(
            tool_name="send_email",
            parameters={
                "to": "test@example.com",
                "body": "Here are the creds: sk_live_abc123def456ghi789jkl",
            },
            session_id="sess_001",
        ))
        # Credential exposure fires at stage 2c and BLOCKs for untrusted sinks
        self.assertIn("error", result)
        self.assertIn("Credential Exposure", result["error"])

    def test_upstream_forwarding(self):
        """Should forward to upstream handler and log result."""
        async def mock_upstream(tool_name, params, token):
            # Verify bearer token is passed
            assert token == self.config.upstream_token
            return {"status": "success", "data": "upstream response"}

        result = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_001",
            upstream_handler=mock_upstream,
        ))
        self.assertEqual(result["data"], "upstream response")

    def test_upstream_token_verification(self):
        """Upstream handler should receive the bearer token."""
        received_tokens = []

        async def mock_upstream(tool_name, params, token):
            received_tokens.append(token)
            return {"status": "success"}

        run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "test"},
            session_id="sess_001",
            upstream_handler=mock_upstream,
        ))
        self.assertEqual(len(received_tokens), 1)
        self.assertEqual(received_tokens[0], self.config.upstream_token)

    def test_canary_tool_definitions(self):
        """Should generate canary tool definitions for the manifest."""
        tools = self.proxy.get_tool_list()
        self.assertTrue(len(tools) > 0)
        names = {t["name"] for t in tools}
        self.assertIn("disable_security_audit", names)
        self.assertIn("extract_system_keys", names)

    def test_killed_session_blocks_all(self):
        """A killed session should block all subsequent calls."""
        # Kill the session
        run_async(self.proxy.handle_tool_call(
            tool_name="disable_security_audit",
            session_id="sess_001",
        ))
        # Any subsequent call should be blocked
        result = run_async(self.proxy.handle_tool_call(
            tool_name="search_web",
            parameters={"query": "innocent"},
            session_id="sess_001",
        ))
        self.assertIn("error", result)
        self.assertIn("killed", result["error"].lower())

    def test_multiple_events_logged(self):
        """Multiple actions should all be logged with chain hashes."""
        for i in range(5):
            run_async(self.proxy.handle_tool_call(
                tool_name="search_web",
                parameters={"query": f"search {i}"},
                session_id="sess_001",
            ))
        events = self.proxy.event_store.query_events(session_id="sess_001")
        self.assertEqual(len(events), 5)
        # All should have chain hashes
        for e in events:
            self.assertIsNotNone(e["chain_hash"])
        # Chain should verify
        valid, _ = self.proxy.event_store.verify_chain()
        self.assertTrue(valid)


class TestCraftProxyIntegration(unittest.TestCase):
    """Smoke tests for CRAFT integration scaffolding on UnwindProxy."""

    def setUp(self):
        self.config = TestConfig.create()
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

    def tearDown(self):
        self.proxy.shutdown()

    @staticmethod
    def _signed_env(craft, seq: int) -> dict:
        from unwind.craft.canonical import mac_input_bytes
        from unwind.craft.crypto import b64url_encode, hmac_sha256

        env = {
            "v": 4,
            "epoch": craft.current_epoch,
            "session_id": craft.session_id,
            "account_id": craft.account_id,
            "channel_id": craft.channel_id,
            "conversation_id": craft.conversation_id,
            "context_type": craft.context_type,
            "seq": str(seq),
            "ts_ms": 1739999999123,
            "state_commit": "",
            "msg_type": "user_instruction",
            "direction": "c2p",
            "payload": {"text": f"msg-{seq}", "meta": {}},
            "mac": "",
        }
        raw_mac = hmac_sha256(craft.keys_c2p.k_msg, mac_input_bytes(env))
        env["mac"] = b64url_encode(raw_mac)
        prev = craft.last_state_commit["c2p"]
        commit = hmac_sha256(craft.keys_c2p.k_state, prev + raw_mac)
        env["state_commit"] = b64url_encode(commit)
        return env

    def test_craft_create_and_verify(self):
        craft = self.proxy.create_craft_session(
            session_id="sess_craft",
            account_id="acct_main",
            channel_id="chan_main",
            conversation_id="conv_main",
            context_type="dm",
            ikm=b"i" * 32,
            salt0=b"s" * 32,
            server_secret=b"k" * 32,
            epoch=0,
        )

        env = self._signed_env(craft, 1)
        out = self.proxy.verify_craft_envelope(session_id="sess_craft", envelope=env)

        self.assertTrue(out["accepted"])
        self.assertIsNone(out["error"])

    def test_craft_rekey_and_teardown(self):
        self.proxy.create_craft_session(
            session_id="sess_craft2",
            account_id="acct_main",
            channel_id="chan_main",
            conversation_id="conv_main",
            context_type="dm",
            ikm=b"i" * 32,
            salt0=b"s" * 32,
            server_secret=b"k" * 32,
            epoch=0,
        )
        prep = self.proxy.craft_rekey_prepare("sess_craft2")
        self.assertEqual(prep["action"], "rekey_prepare")

        applied = self.proxy.craft_rekey_apply("sess_craft2", prep)
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["epoch"], 1)

        td = self.proxy.craft_teardown("sess_craft2")
        self.assertTrue(td["ok"])
        self.assertIsNotNone(td["tombstoned_until_ms"])


class TestCLITimeParsing(unittest.TestCase):
    """Test CLI time parsing utility."""

    def test_parse_hours(self):
        from unwind.cli.main import parse_since
        result = parse_since("2h")
        expected = time.time() - 7200
        self.assertAlmostEqual(result, expected, delta=2)

    def test_parse_minutes(self):
        from unwind.cli.main import parse_since
        result = parse_since("30m")
        expected = time.time() - 1800
        self.assertAlmostEqual(result, expected, delta=2)

    def test_parse_days(self):
        from unwind.cli.main import parse_since
        result = parse_since("1d")
        expected = time.time() - 86400
        self.assertAlmostEqual(result, expected, delta=2)


if __name__ == "__main__":
    unittest.main()
