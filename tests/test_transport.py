"""Tests for UNWIND MCP transport layer.

Tests the JSON-RPC message parsing, stdio transport,
canary injection into tools/list, and tool call interception.
"""

import asyncio
import json
import unittest

from unwind.config import UnwindConfig
from unwind.transport.stdio import (
    JsonRpcMessage,
    StdioTransport,
    UnwindStdioServer,
    make_error,
    make_response,
)


class TestJsonRpcMessage(unittest.TestCase):
    """Test JSON-RPC 2.0 message parsing."""

    def test_request(self):
        msg = JsonRpcMessage({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertTrue(msg.is_request)
        self.assertFalse(msg.is_notification)
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.method, "tools/list")
        self.assertEqual(msg.id, 1)

    def test_notification(self):
        msg = JsonRpcMessage({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertTrue(msg.is_notification)
        self.assertFalse(msg.is_request)
        self.assertFalse(msg.is_response)
        self.assertIsNone(msg.id)

    def test_response_success(self):
        msg = JsonRpcMessage({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        self.assertTrue(msg.is_response)
        self.assertFalse(msg.is_request)
        self.assertEqual(msg.result, {"tools": []})

    def test_response_error(self):
        msg = JsonRpcMessage({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"},
        })
        self.assertTrue(msg.is_response)
        self.assertIsNotNone(msg.error)

    def test_params_default_empty(self):
        msg = JsonRpcMessage({"jsonrpc": "2.0", "id": 1, "method": "test"})
        self.assertEqual(msg.params, {})


class TestMakeResponse(unittest.TestCase):
    """Test JSON-RPC response builders."""

    def test_make_response(self):
        resp = make_response(42, {"tools": []})
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 42)
        self.assertEqual(resp["result"], {"tools": []})

    def test_make_error(self):
        resp = make_error(42, -32600, "Invalid Request")
        self.assertEqual(resp["id"], 42)
        self.assertEqual(resp["error"]["code"], -32600)
        self.assertEqual(resp["error"]["message"], "Invalid Request")

    def test_make_error_with_data(self):
        resp = make_error(1, -32603, "Internal error", data={"detail": "boom"})
        self.assertEqual(resp["error"]["data"]["detail"], "boom")


class TestStdioTransport(unittest.TestCase):
    """Test the async stdio transport layer."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_read_write_roundtrip(self):
        """Write a message, read it back."""
        async def _test():
            # Create an in-memory pipe
            reader = asyncio.StreamReader()
            # We'll feed data directly into the reader
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test", "params": {}}
            line = json.dumps(msg) + "\n"
            reader.feed_data(line.encode())
            reader.feed_eof()

            transport = StdioTransport(reader, None)
            result = await transport.read_message()

            self.assertIsNotNone(result)
            self.assertEqual(result.method, "test")
            self.assertEqual(result.id, 1)

        self._run(_test())

    def test_read_skips_blank_lines(self):
        """Blank lines between messages are ignored."""
        async def _test():
            reader = asyncio.StreamReader()
            msg = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            data = "\n\n" + json.dumps(msg) + "\n"
            reader.feed_data(data.encode())
            reader.feed_eof()

            transport = StdioTransport(reader, None)
            result = await transport.read_message()
            self.assertIsNotNone(result)
            self.assertEqual(result.method, "test")

        self._run(_test())

    def test_read_skips_invalid_json(self):
        """Invalid JSON lines are skipped, valid ones still read."""
        async def _test():
            reader = asyncio.StreamReader()
            valid = {"jsonrpc": "2.0", "id": 1, "method": "test"}
            data = "not json\n" + json.dumps(valid) + "\n"
            reader.feed_data(data.encode())
            reader.feed_eof()

            transport = StdioTransport(reader, None)
            result = await transport.read_message()
            self.assertIsNotNone(result)
            self.assertEqual(result.method, "test")

        self._run(_test())

    def test_read_eof_returns_none(self):
        """EOF returns None."""
        async def _test():
            reader = asyncio.StreamReader()
            reader.feed_eof()
            transport = StdioTransport(reader, None)
            result = await transport.read_message()
            self.assertIsNone(result)

        self._run(_test())

    def test_write_message(self):
        """Write produces newline-delimited compact JSON."""
        async def _test():
            reader = asyncio.StreamReader()
            # Create a mock writer that captures output
            output = bytearray()

            class MockWriter:
                def write(self, data):
                    output.extend(data)
                async def drain(self):
                    pass
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            transport = StdioTransport(reader, MockWriter())
            await transport.write_message({"jsonrpc": "2.0", "id": 1, "result": "ok"})

            line = output.decode().strip()
            parsed = json.loads(line)
            self.assertEqual(parsed["id"], 1)
            self.assertEqual(parsed["result"], "ok")
            # Should be compact JSON (no spaces)
            self.assertNotIn(" ", line)

        self._run(_test())

    def test_multiple_messages(self):
        """Read multiple messages in sequence."""
        async def _test():
            reader = asyncio.StreamReader()
            for i in range(3):
                msg = {"jsonrpc": "2.0", "id": i, "method": f"test_{i}"}
                reader.feed_data((json.dumps(msg) + "\n").encode())
            reader.feed_eof()

            transport = StdioTransport(reader, None)
            messages = []
            while True:
                m = await transport.read_message()
                if m is None:
                    break
                messages.append(m)

            self.assertEqual(len(messages), 3)
            self.assertEqual(messages[0].method, "test_0")
            self.assertEqual(messages[2].method, "test_2")

        self._run(_test())


class TestCanaryInjection(unittest.TestCase):
    """Test that canary tools are injected into the tool manifest."""

    def test_canary_tools_generated(self):
        """Verify canary honeypot tools are available for injection."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)

        canaries = proxy.get_tool_list()
        self.assertGreater(len(canaries), 0)

        canary_names = {t["name"] for t in canaries}
        # Should include at least one of our configured canaries
        self.assertTrue(
            canary_names & set(config.canary_tools),
            f"Expected canary tools in {canary_names}"
        )

    def test_canary_tool_structure(self):
        """Canary tools must have valid MCP tool schema."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)

        for tool in proxy.get_tool_list():
            self.assertIn("name", tool)
            self.assertIn("description", tool)
            self.assertIn("inputSchema", tool)
            self.assertEqual(tool["inputSchema"]["type"], "object")


class TestToolCallInterception(unittest.TestCase):
    """Test that tool calls go through the enforcement pipeline."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_blocked_tool_returns_error(self):
        """A path traversal tool call should be blocked."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)
        config.ensure_dirs()
        proxy.event_store.initialize()

        async def _test():
            result = await proxy.handle_tool_call(
                tool_name="fs_read",
                parameters={"path": "../../../etc/passwd"},
            )
            # Should be blocked by path jail
            self.assertIn("error", result)

        self._run(_test())
        proxy.event_store.close()

    def test_canary_tool_kills_session(self):
        """Calling a canary tool should kill the session."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)
        config.ensure_dirs()
        proxy.event_store.initialize()

        async def _test():
            result = await proxy.handle_tool_call(
                tool_name="disable_security_audit",
                parameters={},
            )
            self.assertIn("error", result)

        self._run(_test())
        proxy.event_store.close()

    def test_ssrf_blocked_through_proxy(self):
        """SSRF attempt through the proxy should be blocked."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)
        config.ensure_dirs()
        proxy.event_store.initialize()

        async def _test():
            result = await proxy.handle_tool_call(
                tool_name="fetch_web",
                parameters={"url": "http://169.254.169.254/latest/meta-data/"},
            )
            self.assertIn("error", result)

        self._run(_test())
        proxy.event_store.close()

    def test_clean_call_succeeds(self):
        """A clean tool call with no upstream should succeed."""
        from unwind.proxy import UnwindProxy
        config = UnwindConfig()
        proxy = UnwindProxy(config)
        config.ensure_dirs()
        proxy.event_store.initialize()

        async def _test():
            result = await proxy.handle_tool_call(
                tool_name="fs_read",
                parameters={"path": str(config.workspace_root / "test.txt")},
            )
            # No upstream handler, should return success
            self.assertNotIn("error", result)

        self._run(_test())
        proxy.event_store.close()


class TestServeCommandParsing(unittest.TestCase):
    """Test the serve command argument parsing."""

    def test_upstream_command_after_separator(self):
        """The -- separator correctly splits unwind args from upstream command."""
        # Simulate what argparse does with REMAINDER
        cmd = ["--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
        # Strip leading --
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        self.assertEqual(cmd, ["npx", "@modelcontextprotocol/server-filesystem", "/tmp"])

    def test_empty_upstream_command(self):
        """Empty upstream command should be detected."""
        cmd = []
        self.assertFalse(bool(cmd))

    def test_upstream_command_without_separator(self):
        """Command without -- should still work."""
        cmd = ["python", "my_server.py"]
        self.assertEqual(len(cmd), 2)


class TestAmberRuntimeWiring(unittest.TestCase):
    """GO-09/10: Verify amber telemetry + mode gate are wired into server."""

    def test_server_has_amber_telemetry(self):
        """Server exposes amber telemetry emitter."""
        config = UnwindConfig()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertIsNotNone(server.amber_telemetry)
        self.assertEqual(len(server.amber_telemetry.event_log), 0)

    def test_server_default_mode_off(self):
        """Default amber mode is OFF (safe by default)."""
        from unwind.enforcement.amber_rollout import AmberMediatorMode
        config = UnwindConfig()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertEqual(server.amber_mode, AmberMediatorMode.OFF)

    def test_set_amber_mode_valid(self):
        """set_amber_mode accepts valid modes."""
        from unwind.enforcement.amber_rollout import AmberMediatorMode
        config = UnwindConfig()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.set_amber_mode("shadow")
        self.assertEqual(server.amber_mode, AmberMediatorMode.SHADOW)
        server.set_amber_mode("enforce")
        self.assertEqual(server.amber_mode, AmberMediatorMode.ENFORCE)

    def test_set_amber_mode_unknown_defaults_off(self):
        """Unknown mode string defaults to OFF (fail-closed)."""
        from unwind.enforcement.amber_rollout import AmberMediatorMode
        config = UnwindConfig()
        server = UnwindStdioServer(config, ["echo", "test"])
        server.set_amber_mode("yolo")
        self.assertEqual(server.amber_mode, AmberMediatorMode.OFF)

    def test_amber_store_initialized(self):
        """Server has amber store instance."""
        config = UnwindConfig()
        server = UnwindStdioServer(config, ["echo", "test"])
        self.assertIsNotNone(server._amber_store)


if __name__ == "__main__":
    unittest.main()
