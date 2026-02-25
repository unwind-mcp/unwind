"""P3-10: Ghost Mode status, approve, and discard.

Tests cover:
  - Session.ghost_status() — empty, populated, size calculation
  - UnwindProxy.ghost_status() — session not found, ghost off, ghost with files
  - UnwindProxy.ghost_approve() — commits files, clears shadow, path jail block
  - UnwindProxy.ghost_discard() — clears without writing, event logging
  - Sidecar endpoints — GET /v1/ghost/status, POST /v1/ghost/approve, POST /v1/ghost/discard
  - Edge cases — approve with no buffer, approve/discard when ghost off
"""

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from unwind.config import UnwindConfig
from unwind.session import Session
from unwind.enforcement.taint_decay import TaintDecayConfig


# -----------------------------------------------------------------------
# Session.ghost_status() unit tests
# -----------------------------------------------------------------------

class TestSessionGhostStatus(unittest.TestCase):
    """Test Session.ghost_status() method."""

    def _make_session(self, ghost_mode: bool = False) -> Session:
        config = UnwindConfig()
        return Session(
            session_id="test-sess",
            config=config,
            ghost_mode=ghost_mode,
            taint_config=TaintDecayConfig(min_dwell_seconds=0.0),
        )

    def test_ghost_off_returns_inactive(self):
        """Ghost status when ghost mode is disabled."""
        session = self._make_session(ghost_mode=False)
        status = session.ghost_status()
        self.assertFalse(status["ghost_mode"])
        self.assertEqual(status["files_buffered"], 0)
        self.assertEqual(status["paths"], [])
        self.assertEqual(status["total_size_bytes"], 0)

    def test_ghost_on_empty_vfs(self):
        """Ghost status when ghost mode is on but nothing buffered."""
        session = self._make_session(ghost_mode=True)
        status = session.ghost_status()
        self.assertTrue(status["ghost_mode"])
        self.assertEqual(status["files_buffered"], 0)
        self.assertEqual(status["paths"], [])
        self.assertEqual(status["total_size_bytes"], 0)

    def test_ghost_on_with_files(self):
        """Ghost status with buffered files — count, paths, size."""
        session = self._make_session(ghost_mode=True)
        session.ghost_write("/workspace/a.txt", "hello")       # 5 bytes
        session.ghost_write("/workspace/b.txt", "world!!")      # 7 bytes
        status = session.ghost_status()
        self.assertTrue(status["ghost_mode"])
        self.assertEqual(status["files_buffered"], 2)
        self.assertEqual(status["paths"], ["/workspace/a.txt", "/workspace/b.txt"])
        self.assertEqual(status["total_size_bytes"], 12)

    def test_ghost_on_with_bytes_content(self):
        """Ghost status correctly sizes binary content."""
        session = self._make_session(ghost_mode=True)
        session.ghost_write("/workspace/bin.dat", b"\x00\x01\x02\x03")  # 4 bytes
        status = session.ghost_status()
        self.assertEqual(status["files_buffered"], 1)
        self.assertEqual(status["total_size_bytes"], 4)

    def test_paths_sorted(self):
        """Ghost status returns paths in sorted order."""
        session = self._make_session(ghost_mode=True)
        session.ghost_write("/workspace/z.txt", "z")
        session.ghost_write("/workspace/a.txt", "a")
        session.ghost_write("/workspace/m.txt", "m")
        status = session.ghost_status()
        self.assertEqual(
            status["paths"],
            ["/workspace/a.txt", "/workspace/m.txt", "/workspace/z.txt"],
        )


# -----------------------------------------------------------------------
# UnwindProxy ghost methods — unit tests
# -----------------------------------------------------------------------

class TestProxyGhostStatus(unittest.TestCase):
    """Test UnwindProxy.ghost_status()."""

    def _make_proxy(self, workspace_root: str = "/tmp/test-workspace"):
        config = UnwindConfig(workspace_root=Path(workspace_root))
        from unwind.proxy import UnwindProxy
        proxy = UnwindProxy(config)
        return proxy

    def test_session_not_found(self):
        proxy = self._make_proxy()
        result = proxy.ghost_status("nonexistent")
        self.assertIn("error", result)
        self.assertIn("Session not found", result["error"])

    def test_ghost_off(self):
        proxy = self._make_proxy()
        session = proxy.get_or_create_session("s1")
        session.ghost_mode = False
        result = proxy.ghost_status("s1")
        self.assertFalse(result["ghost_mode"])

    def test_ghost_on_with_files(self):
        proxy = self._make_proxy()
        session = proxy.get_or_create_session("s1")
        session.ghost_mode = True
        session.ghost_write("/tmp/test-workspace/f.txt", "data")
        result = proxy.ghost_status("s1")
        self.assertTrue(result["ghost_mode"])
        self.assertEqual(result["files_buffered"], 1)


class TestProxyGhostApprove(unittest.TestCase):
    """Test UnwindProxy.ghost_approve()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(workspace_root=Path(self.tmpdir))
        from unwind.proxy import UnwindProxy
        self.proxy = UnwindProxy(self.config)
        # Mock event store to avoid DB dependency
        self.proxy.event_store = MagicMock()
        self.proxy.event_store.write_pending = MagicMock(return_value="evt-1")
        self.proxy.event_store.complete_event_async = AsyncMock()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_session_not_found(self):
        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("nonexistent")
        )
        self.assertIn("error", result)

    def test_ghost_not_active(self):
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = False
        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )
        self.assertIn("error", result)
        self.assertIn("not active", result["error"])

    def test_empty_buffer(self):
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )
        self.assertIn("error", result)
        self.assertIn("Nothing buffered", result["error"])

    def test_approve_writes_files(self):
        """Approve commits shadow writes to the real filesystem."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        file_path = os.path.join(self.tmpdir, "approved.txt")
        session.ghost_write(file_path, "approved content")

        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )

        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["files_written"], 1)
        # File should now exist on disk
        self.assertTrue(os.path.exists(file_path))
        with open(file_path) as f:
            self.assertEqual(f.read(), "approved content")
        # Shadow VFS should be cleared
        self.assertEqual(len(session.shadow_vfs), 0)

    def test_approve_writes_binary(self):
        """Approve handles binary content correctly."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        file_path = os.path.join(self.tmpdir, "binary.dat")
        session.ghost_write(file_path, b"\x89PNG\r\n")

        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )

        self.assertEqual(result["files_written"], 1)
        with open(file_path, "rb") as f:
            self.assertEqual(f.read(), b"\x89PNG\r\n")

    def test_approve_creates_subdirectories(self):
        """Approve creates parent directories if they don't exist."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        file_path = os.path.join(self.tmpdir, "sub", "dir", "deep.txt")
        session.ghost_write(file_path, "deep content")

        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )

        self.assertEqual(result["files_written"], 1)
        self.assertTrue(os.path.exists(file_path))

    def test_approve_path_jail_violation(self):
        """Approve refuses if any path escapes workspace_root."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        # Path outside workspace
        session.ghost_write("/etc/evil.conf", "pwned")

        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )

        self.assertIn("error", result)
        self.assertIn("jail violation", result["error"])
        self.assertIn("/etc/evil.conf", result["violations"])
        # Shadow VFS should NOT be cleared (nothing was committed)
        self.assertEqual(len(session.shadow_vfs), 1)

    def test_approve_logs_event(self):
        """Approve writes an event to the event store."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        file_path = os.path.join(self.tmpdir, "logged.txt")
        session.ghost_write(file_path, "log me")

        asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_approve("s1")
        )

        self.proxy.event_store.write_pending.assert_called_once()
        self.proxy.event_store.complete_event_async.assert_called_once()


class TestProxyGhostDiscard(unittest.TestCase):
    """Test UnwindProxy.ghost_discard()."""

    def setUp(self):
        self.config = UnwindConfig()
        from unwind.proxy import UnwindProxy
        self.proxy = UnwindProxy(self.config)
        self.proxy.event_store = MagicMock()
        self.proxy.event_store.write_pending = MagicMock(return_value="evt-1")
        self.proxy.event_store.complete_event_async = AsyncMock()

    def test_session_not_found(self):
        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_discard("nonexistent")
        )
        self.assertIn("error", result)

    def test_ghost_not_active(self):
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = False
        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_discard("s1")
        )
        self.assertIn("error", result)

    def test_discard_clears_vfs(self):
        """Discard clears shadow VFS without writing to disk."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        session.ghost_write("/workspace/doomed.txt", "will be discarded")

        result = asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_discard("s1")
        )

        self.assertEqual(result["status"], "discarded")
        self.assertEqual(result["files_discarded"], 1)
        self.assertEqual(len(session.shadow_vfs), 0)

    def test_discard_logs_event(self):
        """Discard writes an event to the event store."""
        session = self.proxy.get_or_create_session("s1")
        session.ghost_mode = True
        session.ghost_write("/workspace/f.txt", "data")

        asyncio.get_event_loop().run_until_complete(
            self.proxy.ghost_discard("s1")
        )

        self.proxy.event_store.write_pending.assert_called_once()
        self.proxy.event_store.complete_event_async.assert_called_once()


# -----------------------------------------------------------------------
# Sidecar endpoint tests
# -----------------------------------------------------------------------

class TestSidecarGhostEndpoints(unittest.TestCase):
    """Test sidecar HTTP endpoints for ghost status/approve/discard."""

    @classmethod
    def setUpClass(cls):
        """Create a test app with a known shared secret."""
        from fastapi.testclient import TestClient
        from unwind.sidecar.server import create_app

        cls.tmpdir = tempfile.mkdtemp()
        cls.config = UnwindConfig(workspace_root=Path(cls.tmpdir))
        cls.secret = "test-secret-42"
        cls.app = create_app(config=cls.config, shared_secret=cls.secret)
        cls.client = TestClient(cls.app)
        cls.headers = {
            "Authorization": f"Bearer {cls.secret}",
            "X-UNWIND-API-Version": "1",
        }

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _create_session(self, session_key: str, ghost_mode: bool = True):
        """Helper: create a session in the sidecar's session store via a policy check."""
        # Issue a policy check to create the session
        self.client.post("/v1/policy/check", json={
            "toolName": "fs_read",
            "params": {"path": "/tmp/test"},
            "agentId": "agent-1",
            "sessionKey": session_key,
        }, headers=self.headers)

        # Access the app's internal session store to set ghost mode
        # We need to reach into the app's closure — use a policy check to create it,
        # then we'll access via the ghost/status endpoint
        # For testing, we directly manipulate via the server module's session dict
        # This is a test helper, not production code
        return session_key

    def test_ghost_status_missing_session_key(self):
        resp = self.client.get("/v1/ghost/status", headers=self.headers)
        self.assertEqual(resp.status_code, 400)

    def test_ghost_status_session_not_found(self):
        resp = self.client.get(
            "/v1/ghost/status?sessionKey=nonexistent",
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)

    def test_ghost_status_returns_data(self):
        """Create a session via policy check, then query ghost status."""
        session_key = "ghost-status-test"
        self._create_session(session_key)
        resp = self.client.get(
            f"/v1/ghost/status?sessionKey={session_key}",
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ghostMode", data)
        self.assertIn("filesBuffered", data)

    def test_ghost_approve_missing_session_key(self):
        resp = self.client.post(
            "/v1/ghost/approve",
            json={},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)

    def test_ghost_approve_session_not_found(self):
        resp = self.client.post(
            "/v1/ghost/approve",
            json={"sessionKey": "nonexistent"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)

    def test_ghost_approve_not_active(self):
        """Approve when ghost mode is off returns 409."""
        session_key = "approve-not-active"
        self._create_session(session_key, ghost_mode=False)
        resp = self.client.post(
            "/v1/ghost/approve",
            json={"sessionKey": session_key},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)

    def test_ghost_discard_missing_session_key(self):
        resp = self.client.post(
            "/v1/ghost/discard",
            json={},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)

    def test_ghost_discard_session_not_found(self):
        resp = self.client.post(
            "/v1/ghost/discard",
            json={"sessionKey": "nonexistent"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)

    def test_ghost_discard_not_active(self):
        """Discard when ghost mode is off returns 409."""
        session_key = "discard-not-active"
        self._create_session(session_key, ghost_mode=False)
        resp = self.client.post(
            "/v1/ghost/discard",
            json={"sessionKey": session_key},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)

    def test_ghost_endpoints_require_auth(self):
        """All ghost endpoints require bearer auth."""
        no_auth_headers = {"X-UNWIND-API-Version": "1"}

        resp = self.client.get("/v1/ghost/status?sessionKey=x", headers=no_auth_headers)
        self.assertEqual(resp.status_code, 401)

        resp = self.client.post("/v1/ghost/approve", json={"sessionKey": "x"}, headers=no_auth_headers)
        self.assertEqual(resp.status_code, 401)

        resp = self.client.post("/v1/ghost/discard", json={"sessionKey": "x"}, headers=no_auth_headers)
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
