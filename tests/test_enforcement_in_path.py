"""P0-2: Enforcement-in-path verification tests.

Proves that UNWIND is actually mediating tool calls, not just
sitting idle while calls bypass it.

Sidecar tests (TC-IP-SC-*):
  SC-001: Health reports mediation_active=False before any policy check
  SC-002: After policy check, mediation_active=True and counter > 0
  SC-003: Counter increments with each policy check

Stdio tests (TC-IP-ST-*):
  ST-001: Mediation nonce exists and is non-empty at startup
  ST-002: Mediation nonce injected into initialize response
  ST-003: Tool call counter increments through enforcement
"""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from unwind.config import UnwindConfig
from unwind.sidecar.server import create_app, ENGINE_VERSION
from unwind.transport.stdio import UnwindStdioServer, JsonRpcMessage, make_response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_SECRET = "test-secret-for-unit-tests"


def _make_config() -> UnwindConfig:
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


def _make_client(config=None, shared_secret=TEST_SECRET) -> TestClient:
    if config is None:
        config = _make_config()
    app = create_app(config=config, shared_secret=shared_secret)
    return TestClient(app)


def _headers(secret=TEST_SECRET):
    return {
        "Authorization": f"Bearer {secret}",
        "X-UNWIND-API-Version": "1",
    }


def _valid_policy_body():
    return {
        "toolName": "fs_read",
        "params": {"path": "/workspace/readme.md"},
        "agentId": "agent-001",
        "sessionKey": "sess-001",
    }


# ═══════════════════════════════════════════════════════════════
# TC-IP-SC: Sidecar enforcement-in-path
# ═══════════════════════════════════════════════════════════════


class TestSidecarMediationInactive(unittest.TestCase):
    """TC-IP-SC-001: Before any policy check, mediation is inactive."""

    def test_mediation_false_before_policy_check(self):
        client = _make_client()
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertFalse(data["mediationActive"])
        self.assertEqual(data["toolCallsProcessed"], 0)

    def test_mediation_fields_present_in_health(self):
        client = _make_client()
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertIn("mediationActive", data)
        self.assertIn("toolCallsProcessed", data)


class TestSidecarMediationActive(unittest.TestCase):
    """TC-IP-SC-002: After policy check, mediation is active."""

    def test_mediation_true_after_policy_check(self):
        client = _make_client()
        # Do a policy check
        client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        # Check health
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertTrue(data["mediationActive"])
        self.assertEqual(data["toolCallsProcessed"], 1)

    def test_mediation_stays_active(self):
        """Once mediation is active, it stays active."""
        client = _make_client()
        client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        # Multiple health checks — still active
        for _ in range(3):
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertTrue(data["mediationActive"])


class TestSidecarMediationCounter(unittest.TestCase):
    """TC-IP-SC-003: Counter increments with each policy check."""

    def test_counter_increments(self):
        client = _make_client()
        for i in range(5):
            client.post(
                "/v1/policy/check",
                json=_valid_policy_body(),
                headers=_headers(),
            )
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["toolCallsProcessed"], 5)

    def test_counter_increments_even_on_block(self):
        """Blocked calls still count — enforcement DID run."""
        client = _make_client()
        # Use a dangerous tool that gets blocked
        body = _valid_policy_body()
        body["toolName"] = "disable_security_audit"  # canary → block
        client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["toolCallsProcessed"], 1)
        self.assertTrue(data["mediationActive"])

    def test_malformed_request_does_not_increment(self):
        """422 errors (bad request) don't increment — enforcement didn't run."""
        client = _make_client()
        # Missing required field
        client.post(
            "/v1/policy/check",
            json={"params": {}},
            headers=_headers(),
        )
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["toolCallsProcessed"], 0)
        self.assertFalse(data["mediationActive"])


# ═══════════════════════════════════════════════════════════════
# TC-IP-ST: Stdio enforcement-in-path
# ═══════════════════════════════════════════════════════════════


class TestStdioMediationNonce(unittest.TestCase):
    """TC-IP-ST-001: Mediation nonce exists and is non-empty at startup."""

    def test_nonce_exists_at_construction(self):
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertIsNotNone(server.mediation_nonce)
        self.assertTrue(len(server.mediation_nonce) > 0)
        self.assertTrue(server.mediation_nonce.startswith("unwind_"))

    def test_nonce_is_unique_per_instance(self):
        config = _make_config()
        server1 = UnwindStdioServer(config, ["echo", "test"])
        server2 = UnwindStdioServer(config, ["echo", "test"])
        self.assertNotEqual(server1.mediation_nonce, server2.mediation_nonce)


class TestStdioMediationProperties(unittest.TestCase):
    """TC-IP-ST-002: Mediation properties accessible."""

    def test_tool_calls_starts_at_zero(self):
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertEqual(server.tool_calls_processed, 0)
        self.assertFalse(server.mediation_active)

    def test_mediation_active_property(self):
        """mediation_active is True iff tool_calls_processed > 0."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertFalse(server.mediation_active)
        # Simulate incrementing
        server._tool_calls_processed = 1
        self.assertTrue(server.mediation_active)


class TestStdioNonceInInitialize(unittest.TestCase):
    """TC-IP-ST-003: Nonce injected into initialize response."""

    def test_initialize_tagged_for_nonce_injection(self):
        """The initialize handler should tag the pending request."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.upstream = MagicMock()
        server.upstream.send = AsyncMock()
        server._session_id = "test-session"

        # Mock proxy
        server.proxy = MagicMock()
        server.proxy.get_or_create_session = MagicMock(return_value=MagicMock())

        # Create an initialize message
        msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "test", "version": "1.0"}},
        })

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._handle_initialize(msg))
        finally:
            loop.close()

        # Check the pending request is tagged as "initialize"
        pending_values = list(server._pending_requests.values())
        self.assertEqual(len(pending_values), 1)
        tag, original_id = pending_values[0]
        self.assertEqual(tag, "initialize")
        self.assertEqual(original_id, 1)

    def test_upstream_initialize_response_gets_nonce(self):
        """When upstream responds to initialize, nonce is injected."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.agent_transport.write_message = AsyncMock()

        # Set up the pending request as tagged initialize
        server._pending_requests[1] = ("initialize", 42)

        # Simulate upstream initialize response
        upstream_msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-server", "version": "1.0"},
            },
        })

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._handle_upstream_message(upstream_msg))
        finally:
            loop.close()

        # Verify the response was sent to agent with nonce injected
        server.agent_transport.write_message.assert_called_once()
        sent_msg = server.agent_transport.write_message.call_args[0][0]
        self.assertEqual(sent_msg["id"], 42)
        self.assertIn("result", sent_msg)
        self.assertIn("_unwind_mediation_nonce", sent_msg["result"])
        self.assertEqual(
            sent_msg["result"]["_unwind_mediation_nonce"],
            server.mediation_nonce,
        )
        # Original fields preserved
        self.assertEqual(sent_msg["result"]["protocolVersion"], "2024-11-05")


if __name__ == "__main__":
    unittest.main()
