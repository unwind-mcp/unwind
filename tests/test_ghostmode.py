"""Tests for Ghost Mode standalone package.

Tests the shadow VFS, event log, tool classification,
and proxy interception logic.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from ghostmode.shadow_vfs import ShadowVFS
from ghostmode.event_log import GhostEventLog, GhostEvent
from ghostmode.proxy import is_write_tool, DEFAULT_WRITE_TOOLS


# ── Shadow VFS Tests ────────────────────────────────────────────

class TestShadowVFS(unittest.TestCase):
    """Test the in-memory virtual filesystem overlay."""

    def setUp(self):
        self.vfs = ShadowVFS()

    def test_write_and_read(self):
        self.vfs.write("/tmp/test.txt", "hello world")
        self.assertEqual(self.vfs.read("/tmp/test.txt"), "hello world")

    def test_read_nonexistent_returns_none(self):
        self.assertIsNone(self.vfs.read("/does/not/exist"))

    def test_delete(self):
        self.vfs.write("/tmp/test.txt", "content")
        self.vfs.delete("/tmp/test.txt")
        # Deleted file returns empty string (file exists but is "gone")
        self.assertEqual(self.vfs.read("/tmp/test.txt"), "")
        self.assertTrue(self.vfs.has("/tmp/test.txt"))

    def test_delete_without_prior_write(self):
        self.vfs.delete("/tmp/other.txt")
        self.assertTrue(self.vfs.has("/tmp/other.txt"))
        self.assertEqual(self.vfs.read("/tmp/other.txt"), "")

    def test_rename(self):
        self.vfs.write("/tmp/old.txt", "content")
        self.vfs.rename("/tmp/old.txt", "/tmp/new.txt")
        self.assertEqual(self.vfs.read("/tmp/new.txt"), "content")
        self.assertTrue(self.vfs.has("/tmp/old.txt"))  # old path tracked as deleted

    def test_has(self):
        self.assertFalse(self.vfs.has("/tmp/test.txt"))
        self.vfs.write("/tmp/test.txt", "content")
        self.assertTrue(self.vfs.has("/tmp/test.txt"))

    def test_write_count(self):
        self.assertEqual(self.vfs.write_count, 0)
        self.vfs.write("/a", "1")
        self.vfs.write("/b", "2")
        self.assertEqual(self.vfs.write_count, 2)

    def test_delete_count(self):
        self.assertEqual(self.vfs.delete_count, 0)
        self.vfs.delete("/a")
        self.assertEqual(self.vfs.delete_count, 1)

    def test_clear(self):
        self.vfs.write("/a", "1")
        self.vfs.delete("/b")
        self.vfs.clear()
        self.assertEqual(self.vfs.write_count, 0)
        self.assertEqual(self.vfs.delete_count, 0)

    def test_summary(self):
        self.vfs.write("/a", "1")
        self.vfs.delete("/b")
        summary = self.vfs.summary()
        self.assertIn("/a", summary["files_written"])
        self.assertIn("/b", summary["files_deleted"])
        self.assertEqual(summary["write_count"], 1)
        self.assertEqual(summary["delete_count"], 1)

    def test_overwrite(self):
        self.vfs.write("/a", "first")
        self.vfs.write("/a", "second")
        self.assertEqual(self.vfs.read("/a"), "second")
        self.assertEqual(self.vfs.write_count, 1)

    def test_bytes_content(self):
        self.vfs.write("/binary", b"\x00\x01\x02")
        self.assertEqual(self.vfs.read("/binary"), b"\x00\x01\x02")


# ── Event Log Tests ─────────────────────────────────────────────

class TestGhostEventLog(unittest.TestCase):
    """Test the Ghost Mode event log."""

    def setUp(self):
        self.log = GhostEventLog()

    def test_log_intercept(self):
        event = self.log.log_intercept("fs_write", "/tmp/test.txt", "blocked write")
        self.assertEqual(event.tool, "fs_write")
        self.assertEqual(event.action, "intercepted")
        self.assertEqual(event.target, "/tmp/test.txt")
        self.assertEqual(self.log.intercepted_count, 1)

    def test_log_passthrough(self):
        self.log.log_passthrough("fs_read", "/tmp/test.txt")
        self.assertEqual(self.log.passthrough_count, 1)

    def test_log_shadow_read(self):
        self.log.log_shadow_read("fs_read", "/tmp/ghost.txt")
        self.assertEqual(self.log.shadow_read_count, 1)

    def test_summary(self):
        self.log.log_intercept("fs_write")
        self.log.log_intercept("send_email")
        self.log.log_passthrough("fs_read")
        self.log.log_shadow_read("fs_read", "/tmp/x")

        summary = self.log.summary()
        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(summary["intercepted"], 2)
        self.assertEqual(summary["passed_through"], 1)
        self.assertEqual(summary["shadow_reads"], 1)
        self.assertGreaterEqual(summary["duration_seconds"], 0)

    def test_format_timeline_empty(self):
        result = self.log.format_timeline()
        self.assertIn("No events", result)

    def test_format_timeline_with_events(self):
        self.log.log_intercept("fs_write", "/tmp/test.txt")
        self.log.log_passthrough("fs_read")
        timeline = self.log.format_timeline()
        self.assertIn("BLOCKED", timeline)
        self.assertIn("PASSED", timeline)
        self.assertIn("fs_write", timeline)

    def test_export_json(self):
        self.log.log_intercept("fs_write", "/tmp/a")
        self.log.log_passthrough("fs_read")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        count = self.log.export_json(path)
        self.assertEqual(count, 2)

        data = json.loads(path.read_text())
        self.assertEqual(data["ghostmode_version"], "0.1.0")
        self.assertEqual(len(data["events"]), 2)
        self.assertEqual(data["events"][0]["tool"], "fs_write")
        path.unlink()

    def test_export_jsonl(self):
        self.log.log_intercept("fs_write")
        self.log.log_passthrough("fs_read")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)

        count = self.log.export_jsonl(path)
        self.assertEqual(count, 2)

        lines = path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["action"], "intercepted")
        path.unlink()

    def test_timestamps_are_reasonable(self):
        before = time.time()
        event = self.log.log_intercept("test")
        after = time.time()
        self.assertGreaterEqual(event.timestamp, before)
        self.assertLessEqual(event.timestamp, after)


# ── Tool Classification Tests ────────────────────────────────────

class TestToolClassification(unittest.TestCase):
    """Test the write tool detection logic."""

    def test_explicit_write_tools(self):
        for tool in ["fs_write", "fs_delete", "send_email", "bash_exec",
                      "http_post", "upload_file", "git_push"]:
            self.assertTrue(is_write_tool(tool), f"{tool} should be classified as write")

    def test_read_tools_pass(self):
        for tool in ["fs_read", "fs_list", "search_web", "read_email",
                      "fetch_web", "list_directory"]:
            self.assertFalse(is_write_tool(tool), f"{tool} should not be classified as write")

    def test_prefix_heuristic(self):
        # These aren't in the explicit list but match prefixes
        self.assertTrue(is_write_tool("create_ticket"))
        self.assertTrue(is_write_tool("delete_record"))
        self.assertTrue(is_write_tool("send_notification"))
        self.assertTrue(is_write_tool("write_config"))
        self.assertTrue(is_write_tool("execute_query"))
        self.assertTrue(is_write_tool("install_plugin"))

    def test_prefix_heuristic_negatives(self):
        # These have read-like prefixes
        self.assertFalse(is_write_tool("get_status"))
        self.assertFalse(is_write_tool("read_config"))
        self.assertFalse(is_write_tool("list_files"))
        self.assertFalse(is_write_tool("search_docs"))
        self.assertFalse(is_write_tool("fetch_data"))

    def test_custom_write_tools(self):
        custom = frozenset({"my_special_tool", "another_tool"})
        self.assertTrue(is_write_tool("my_special_tool", custom))
        self.assertFalse(is_write_tool("normal_read", custom))

    def test_default_write_tools_not_empty(self):
        self.assertGreater(len(DEFAULT_WRITE_TOOLS), 20)


# ── Integration-Level Tests ──────────────────────────────────────

class TestGhostModeIntegration(unittest.TestCase):
    """Test the Ghost Mode proxy logic at a higher level."""

    def test_shadow_vfs_read_after_write(self):
        """Core ghost mode flow: write intercepted, subsequent read served from shadow."""
        vfs = ShadowVFS()
        log = GhostEventLog()

        # Agent "writes" a file
        vfs.write("/workspace/report.md", "# My Report\n\nContent here.")
        log.log_intercept("fs_write", "/workspace/report.md")

        # Agent reads it back — should come from shadow
        content = vfs.read("/workspace/report.md")
        self.assertEqual(content, "# My Report\n\nContent here.")
        log.log_shadow_read("fs_read", "/workspace/report.md")

        # Summary reflects the flow
        summary = log.summary()
        self.assertEqual(summary["intercepted"], 1)
        self.assertEqual(summary["shadow_reads"], 1)

    def test_delete_then_read(self):
        """Deleted files should return empty from shadow."""
        vfs = ShadowVFS()
        vfs.delete("/workspace/old.txt")
        self.assertEqual(vfs.read("/workspace/old.txt"), "")

    def test_rename_preserves_content(self):
        """Renamed files move content in shadow."""
        vfs = ShadowVFS()
        vfs.write("/a.txt", "content")
        vfs.rename("/a.txt", "/b.txt")
        self.assertEqual(vfs.read("/b.txt"), "content")
        # Old path is in the deleted set, so read returns empty (not None)
        self.assertEqual(vfs.read("/a.txt"), "")
        self.assertTrue(vfs.has("/a.txt"))

    def test_full_session_scenario(self):
        """Simulate a realistic agent session."""
        vfs = ShadowVFS()
        log = GhostEventLog()

        # Agent reads some files (pass through)
        log.log_passthrough("fs_read", "/docs/notes.txt")
        log.log_passthrough("fs_list", "/docs/")

        # Agent writes a new file (intercepted)
        vfs.write("/docs/summary.md", "# Summary\n\n- Point 1\n- Point 2")
        log.log_intercept("fs_write", "/docs/summary.md", "Would have created summary.md")

        # Agent reads back what it wrote (shadow)
        content = vfs.read("/docs/summary.md")
        self.assertIn("Point 1", content)
        log.log_shadow_read("fs_read", "/docs/summary.md")

        # Agent tries to send email (intercepted)
        log.log_intercept("send_email", None, "Would have sent email")

        # Agent reads more files (pass through)
        log.log_passthrough("fs_read", "/docs/config.json")

        # Check final state
        summary = log.summary()
        self.assertEqual(summary["total_events"], 6)
        self.assertEqual(summary["intercepted"], 2)
        self.assertEqual(summary["passed_through"], 3)
        self.assertEqual(summary["shadow_reads"], 1)

        # Timeline should be readable
        timeline = log.format_timeline()
        self.assertIn("BLOCKED", timeline)
        self.assertIn("PASSED", timeline)
        self.assertIn("SHADOW", timeline)


if __name__ == "__main__":
    unittest.main()
