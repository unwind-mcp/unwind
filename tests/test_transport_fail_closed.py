"""P0-3: Transport fail-closed contract tests.

Proves that UNWIND never silently passes through on errors —
exceptions, crashes, and disconnects all result in blocks or
explicit errors, never allows.

Sidecar invariants (TC-FC-SC-*):
  SC-001: Pipeline exception → BLOCK decision (never 500)
  SC-002: Pipeline returning unknown action → BLOCK
  SC-003: Policy source failure → BLOCK all requests

Stdio invariants (TC-FC-ST-*):
  ST-001: Handler exception → JSON-RPC error to agent (never passthrough)
  ST-002: Upstream disconnect → agent gets EOF/error (never reconnect)
  ST-003: Malformed upstream response → logged and discarded (no crash)
  ST-004: Tool call with dead upstream → timeout error to agent
  ST-005: No auto-reconnect after upstream dies
"""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from fastapi.testclient import TestClient

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult, PipelineResult
from unwind.sidecar.server import create_app, ENGINE_VERSION
from unwind.transport.stdio import (
    UnwindStdioServer,
    JsonRpcMessage,
    StdioTransport,
    make_error,
)


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


def _make_client(config=None, pipeline=None, shared_secret=TEST_SECRET) -> TestClient:
    if config is None:
        config = _make_config()
    app = create_app(config=config, pipeline=pipeline, shared_secret=shared_secret)
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
# TC-FC-SC: Sidecar fail-closed
# ═══════════════════════════════════════════════════════════════


class TestSidecarPipelineException(unittest.TestCase):
    """TC-FC-SC-001: Pipeline exception → BLOCK decision (never 500)."""

    def test_pipeline_exception_returns_block_not_500(self):
        """If the enforcement pipeline throws, sidecar returns BLOCK at 200."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        pipeline.check.side_effect = RuntimeError("Pipeline exploded")
        client = _make_client(config=config, pipeline=pipeline)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")
        self.assertIn("SIDECAR_INTERNAL_ERROR", data.get("blockReason", ""))

    def test_pipeline_exception_never_returns_allow(self):
        """Exception must NEVER result in an allow decision."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        pipeline.check.side_effect = Exception("Unexpected error")
        client = _make_client(config=config, pipeline=pipeline)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        data = resp.json()
        self.assertNotEqual(data["decision"], "allow")

    def test_various_exception_types_all_block(self):
        """Different exception types all result in BLOCK."""
        exceptions = [
            ValueError("bad value"),
            TypeError("wrong type"),
            KeyError("missing key"),
            RuntimeError("runtime failure"),
            MemoryError("out of memory"),
        ]
        for exc in exceptions:
            config = _make_config()
            pipeline = MagicMock(spec=EnforcementPipeline)
            pipeline.check.side_effect = exc
            client = _make_client(config=config, pipeline=pipeline)

            resp = client.post(
                "/v1/policy/check",
                json=_valid_policy_body(),
                headers=_headers(),
            )
            self.assertEqual(resp.status_code, 200, f"500 on {type(exc).__name__}")
            data = resp.json()
            self.assertEqual(
                data["decision"], "block",
                f"Expected block on {type(exc).__name__}, got {data['decision']}",
            )


class TestSidecarUnknownAction(unittest.TestCase):
    """TC-FC-SC-002: Pipeline returning unknown action → BLOCK."""

    def test_unknown_action_returns_block(self):
        """If pipeline returns an unrecognised CheckResult, sidecar blocks."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        # Create a mock result with an unrecognised action value
        mock_result = MagicMock()
        mock_result.action = "UNKNOWN_NEW_ACTION"
        mock_result.block_reason = None
        pipeline.check.return_value = mock_result
        client = _make_client(config=config, pipeline=pipeline)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        data = resp.json()
        self.assertEqual(data["decision"], "block")
        self.assertIn("UNKNOWN_PIPELINE_ACTION", data.get("blockReason", ""))


class TestSidecarPolicySourceFailure(unittest.TestCase):
    """TC-FC-SC-003: Policy source failure → BLOCK all requests."""

    def test_policy_load_failure_blocks_all(self):
        """If policy source fails to load, ALL policy checks are blocked."""
        config = _make_config()
        # Create a mock policy source that fails
        mock_source = MagicMock()
        mock_load_result = MagicMock()
        mock_load_result.success = False
        mock_load_result.error = "POLICY_FILE_CORRUPT"
        mock_source.initial_load.return_value = mock_load_result

        app = create_app(
            config=config,
            shared_secret=TEST_SECRET,
            policy_source=mock_source,
        )
        client = TestClient(app)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")
        self.assertIn("POLICY_SOURCE_FAILED", data.get("blockReason", ""))

    def test_policy_load_failure_health_degraded(self):
        """Health endpoint shows degraded when policy fails."""
        config = _make_config()
        mock_source = MagicMock()
        mock_load_result = MagicMock()
        mock_load_result.success = False
        mock_load_result.error = "POLICY_FILE_CORRUPT"
        mock_source.initial_load.return_value = mock_load_result

        app = create_app(
            config=config,
            shared_secret=TEST_SECRET,
            policy_source=mock_source,
        )
        client = TestClient(app)

        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["status"], "degraded")


# ═══════════════════════════════════════════════════════════════
# TC-FC-ST: Stdio fail-closed
# ═══════════════════════════════════════════════════════════════


class TestStdioHandlerException(unittest.TestCase):
    """TC-FC-ST-001: Handler exception → JSON-RPC error to agent."""

    def test_agent_gets_error_on_handler_exception(self):
        """If _handle_agent_message throws, agent gets a JSON-RPC error."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.agent_transport.write_message = AsyncMock()
        server.agent_transport.read_message = AsyncMock()

        # Make the handler throw
        msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "fs_read", "arguments": {}},
        })

        # Mock proxy to throw
        server.proxy = MagicMock()
        server.proxy.handle_tool_call = AsyncMock(
            side_effect=RuntimeError("Enforcement crashed")
        )

        loop = asyncio.new_event_loop()
        try:
            # Simulate the agent reader loop handling one message
            # We call _handle_agent_message → _handle_tool_call → exception
            # The exception should be caught in _agent_reader_loop
            # and an error sent back

            # First message: the one that throws
            server.agent_transport.read_message = AsyncMock(
                side_effect=[msg, None]  # msg then EOF to stop loop
            )
            loop.run_until_complete(server._agent_reader_loop())
        finally:
            loop.close()

        # Verify agent got an error response (not silence, not passthrough)
        server.agent_transport.write_message.assert_called()
        sent = server.agent_transport.write_message.call_args[0][0]
        self.assertIn("error", sent)
        self.assertEqual(sent["id"], 42)

    def test_error_response_is_json_rpc_format(self):
        """Error responses must be valid JSON-RPC 2.0 errors."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.agent_transport.write_message = AsyncMock()

        msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "bad_tool", "arguments": {}},
        })

        server.proxy = MagicMock()
        server.proxy.handle_tool_call = AsyncMock(
            side_effect=ValueError("Bad tool config")
        )

        server.agent_transport.read_message = AsyncMock(
            side_effect=[msg, None]
        )

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._agent_reader_loop())
        finally:
            loop.close()

        sent = server.agent_transport.write_message.call_args[0][0]
        # JSON-RPC 2.0 error format
        self.assertEqual(sent["jsonrpc"], "2.0")
        self.assertEqual(sent["id"], 99)
        self.assertIn("error", sent)
        self.assertIn("code", sent["error"])
        self.assertIn("message", sent["error"])
        self.assertEqual(sent["error"]["code"], -32603)  # Internal error


class TestStdioUpstreamDisconnect(unittest.TestCase):
    """TC-FC-ST-002: Upstream disconnect → shutdown (no silent pass)."""

    def test_upstream_eof_triggers_shutdown(self):
        """When upstream returns None (EOF), server shuts down."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.upstream = MagicMock()
        server.upstream.receive = AsyncMock(return_value=None)
        server.agent_transport = MagicMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._upstream_reader_loop())
        finally:
            loop.close()

        self.assertTrue(server._shutdown)


class TestStdioMalformedUpstream(unittest.TestCase):
    """TC-FC-ST-003: Malformed upstream response → logged, not crash."""

    def test_unexpected_response_id_is_discarded(self):
        """Response with unknown ID is logged and discarded (no crash)."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.agent_transport.write_message = AsyncMock()

        # Upstream response with an ID we never sent
        msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 999,
            "result": {"tools": []},
        })

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._handle_upstream_message(msg))
        finally:
            loop.close()

        # Agent should NOT have received anything
        server.agent_transport.write_message.assert_not_called()


class TestStdioDeadUpstreamTimeout(unittest.TestCase):
    """TC-FC-ST-004: Tool call with dead upstream → timeout error."""

    def test_upstream_timeout_returns_error(self):
        """If upstream never responds, agent gets timeout error."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.agent_transport = MagicMock()
        server.agent_transport.write_message = AsyncMock()
        server._session_id = "test-session"

        # Mock upstream that accepts sends but never responds
        server.upstream = MagicMock()
        server.upstream.send = AsyncMock()

        # Mock proxy.handle_tool_call to use a real upstream_handler
        # that will timeout because no response arrives
        async def mock_handle_tool_call(tool_name, parameters, session_id, upstream_handler):
            # Call the upstream handler — it will send and wait for response
            # but we'll make the wait_for timeout very short
            result = await upstream_handler(tool_name, parameters, "token")
            return result

        server.proxy = MagicMock()
        server.proxy.handle_tool_call = mock_handle_tool_call

        msg = JsonRpcMessage({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "fs_read", "arguments": {"path": "/test"}},
        })

        # Patch the timeout to be very short for testing
        loop = asyncio.new_event_loop()
        try:
            with patch("unwind.transport.stdio.asyncio.wait_for",
                       side_effect=asyncio.TimeoutError()):
                loop.run_until_complete(server._handle_tool_call(msg))
        finally:
            loop.close()

        # Agent should have received an error response
        server.agent_transport.write_message.assert_called()
        sent = server.agent_transport.write_message.call_args[0][0]
        result = sent.get("result", {})
        # The timeout returns {"error": "Upstream timeout (30s)"} which
        # gets mapped to an isError tool result
        content = result.get("content", [{}])
        if content:
            text = content[0].get("text", "")
            self.assertTrue(
                "timeout" in text.lower() or "error" in text.lower(),
                f"Expected timeout/error in response, got: {text}",
            )


class TestStdioNoAutoReconnect(unittest.TestCase):
    """TC-FC-ST-005: No auto-reconnect after upstream dies."""

    def test_shutdown_flag_prevents_reconnect(self):
        """After upstream EOF, _shutdown flag is set — no reconnect."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.upstream = MagicMock()
        server.upstream.receive = AsyncMock(return_value=None)
        server.agent_transport = MagicMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._upstream_reader_loop())
        finally:
            loop.close()

        # Shutdown is set
        self.assertTrue(server._shutdown)

        # Agent reader loop should exit immediately on shutdown
        server.agent_transport.read_message = AsyncMock(return_value=None)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._agent_reader_loop())
        finally:
            loop.close()

        # No reconnect attempt — upstream.start() never called again
        if hasattr(server.upstream, 'start'):
            server.upstream.start.assert_not_called()

    def test_no_reconnect_mechanism_exists(self):
        """UnwindStdioServer has no reconnect/restart method."""
        config = _make_config()
        server = UnwindStdioServer(config, ["echo", "test"])
        # Verify there's no reconnect, restart, or retry method
        self.assertFalse(hasattr(server, 'reconnect'))
        self.assertFalse(hasattr(server, 'restart_upstream'))
        self.assertFalse(hasattr(server, 'retry'))


# ═══════════════════════════════════════════════════════════════
# Cross-transport invariants
# ═══════════════════════════════════════════════════════════════


class TestFailClosedInvariants(unittest.TestCase):
    """Cross-cutting fail-closed guarantees."""

    def test_sidecar_never_returns_500(self):
        """Policy check MUST return 200 even on internal errors."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        pipeline.check.side_effect = Exception("Catastrophic failure")
        client = _make_client(config=config, pipeline=pipeline)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        # NEVER 500 — always 200 with block decision
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["decision"], "block")

    def test_sidecar_block_has_reason(self):
        """Fail-closed block decisions must include a reason."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        pipeline.check.side_effect = RuntimeError("Engine crashed")
        client = _make_client(config=config, pipeline=pipeline)

        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        data = resp.json()
        self.assertIn("blockReason", data)
        self.assertTrue(len(data["blockReason"]) > 0)

    def test_malformed_json_returns_422_not_500(self):
        """Non-JSON body → 422, not 500."""
        config = _make_config()
        client = _make_client(config=config)

        resp = client.post(
            "/v1/policy/check",
            content=b"this is not json",
            headers={
                **_headers(),
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(resp.status_code, 422)

    def test_null_json_body_returns_422(self):
        """null JSON body → 422, not 500."""
        config = _make_config()
        client = _make_client(config=config)

        resp = client.post(
            "/v1/policy/check",
            content=b"null",
            headers={
                **_headers(),
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(resp.status_code, 422)

    def test_array_json_body_returns_422(self):
        """Array JSON body → 422, not 500."""
        config = _make_config()
        client = _make_client(config=config)

        resp = client.post(
            "/v1/policy/check",
            content=b'["not", "an", "object"]',
            headers={
                **_headers(),
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
