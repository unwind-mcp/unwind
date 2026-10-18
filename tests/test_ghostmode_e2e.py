"""End-to-end tests: run the real ghostmode CLI against a fake MCP server.

Covers what users hit in practice: the session summary on every kind of
shutdown, a consistent shadow filesystem, and unknown tools being blocked.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ghostmode.shadow_vfs import EditNotFound, ShadowVFS, apply_edits

HERE = Path(__file__).resolve().parent
FAKE_SERVER = HERE / "ghostmode_fake_server.py"


class GhostSession:
    """Drive ghostmode over stdio like an MCP client would."""

    def __init__(self, root: Path, run_dir: Path, *extra_args: str):
        env = dict(os.environ, PYTHONPATH=str(HERE.parent))
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "ghostmode.cli", "--export", str(run_dir / "log.json"),
             *extra_args, "--", sys.executable, str(FAKE_SERVER), str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=run_dir, env=env, text=True,
        )
        self._id = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "1"}})
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0",
                                          "method": "notifications/initialized"}) + "\n")
        self.request("tools/list", {})

    def request(self, method, params):
        self._id += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self._id,
                                          "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError("ghostmode closed stdout")
            msg = json.loads(line)
            if msg.get("id") == self._id:
                return msg

    def call(self, name, **arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        return "\n".join(c["text"] for c in result["content"]), bool(result.get("isError"))

    def finish(self, how="eof", timeout=10):
        if how == "eof":
            self.proc.stdin.close()
        else:
            self.proc.send_signal(how)
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise AssertionError(f"ghostmode did not exit after {how}")
        return self.proc.stderr.read()


class ProxyTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name).resolve()
        self.root = base / "docs"
        self.run_dir = base / "run"
        self.root.mkdir()
        self.run_dir.mkdir()
        (self.root / "notes.txt").write_text("hello original\n")
        (self.root / "sub").mkdir()
        self.before = self.snapshot()
        self.session = None

    def tearDown(self):
        if self.session and self.session.proc.poll() is None:
            self.session.proc.kill()
            self.session.proc.wait()
        if self.session:
            for stream in (self.session.proc.stdin, self.session.proc.stdout,
                           self.session.proc.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
        self._tmp.cleanup()

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_text() if p.is_file() else "<dir>")
                for p in sorted(self.root.rglob("*"))}

    def start(self, *args):
        self.session = GhostSession(self.root, self.run_dir, *args)
        return self.session

    def p(self, name):
        return str(self.root / name)


class TestShutdown(ProxyTestCase):
    """The summary and export must be written however the session ends."""

    def _check_summary_written(self, how):
        s = self.start()
        s.call("write_file", path=self.p("report.md"), content="# report")
        stderr = s.finish(how)
        summary = (self.run_dir / "ghostmode-summary.txt").read_text()
        self.assertIn("report.md", summary)
        self.assertIn("1 write(s) were blocked", summary)
        self.assertIn("GHOST MODE SESSION SUMMARY", stderr)
        events = json.loads((self.run_dir / "log.json").read_text())["events"]
        self.assertEqual(events[0]["tool"], "write_file")
        self.assertEqual(self.snapshot(), self.before)

    def test_client_disconnect(self):
        self._check_summary_written("eof")

    @unittest.skipIf(os.name != "posix", "POSIX signals")
    def test_sigterm(self):
        self._check_summary_written(signal.SIGTERM)

    @unittest.skipIf(os.name != "posix", "POSIX signals")
    def test_sigint(self):
        self._check_summary_written(signal.SIGINT)


class TestShadowConsistency(ProxyTestCase):
    """What the agent sees must agree with what it 'did'."""

    def tearDown(self):
        if self.session and self.session.proc.poll() is None:
            self.session.finish()
        self.assertEqual(self.snapshot(), self.before, "real files were modified")
        super().tearDown()

    def test_write_then_list_and_search(self):
        s = self.start()
        s.call("write_file", path=self.p("report.md"), content="# report")
        listing, _ = s.call("list_directory", path=str(self.root))
        self.assertIn("[FILE] report.md", listing)
        self.assertIn("[FILE] notes.txt", listing)
        found, _ = s.call("search_files", path=str(self.root), pattern="report")
        self.assertIn(self.p("report.md"), found)
        tree, _ = s.call("directory_tree", path=str(self.root))
        self.assertIn("report.md", [e["name"] for e in json.loads(tree)])

    def test_edit_real_file_then_read(self):
        s = self.start()
        diff, err = s.call("edit_file", path=self.p("notes.txt"),
                           edits=[{"oldText": "original", "newText": "EDITED"}])
        self.assertFalse(err)
        self.assertIn("+hello EDITED", diff)
        content, _ = s.call("read_text_file", path=self.p("notes.txt"))
        self.assertEqual(content, "hello EDITED\n")
        both, _ = s.call("read_multiple_files", paths=[self.p("notes.txt")])
        self.assertIn("hello EDITED", both)

    def test_edit_with_missing_text_fails_like_real_server(self):
        s = self.start()
        _, err = s.call("edit_file", path=self.p("notes.txt"),
                        edits=[{"oldText": "not there", "newText": "x"}])
        self.assertTrue(err)

    def test_dry_run_edit_does_not_change_shadow(self):
        s = self.start()
        s.call("edit_file", path=self.p("notes.txt"), dryRun=True,
               edits=[{"oldText": "original", "newText": "EDITED"}])
        content, _ = s.call("read_text_file", path=self.p("notes.txt"))
        self.assertEqual(content, "hello original\n")

    def test_move_real_file(self):
        s = self.start()
        _, err = s.call("move_file", source=self.p("notes.txt"), destination=self.p("moved.txt"))
        self.assertFalse(err)
        content, _ = s.call("read_text_file", path=self.p("moved.txt"))
        self.assertEqual(content, "hello original\n")
        _, err = s.call("read_text_file", path=self.p("notes.txt"))
        self.assertTrue(err, "old path should no longer exist")
        listing, _ = s.call("list_directory", path=str(self.root))
        self.assertIn("[FILE] moved.txt", listing)
        self.assertNotIn("notes.txt", listing)

    def test_create_directory_then_write_inside(self):
        s = self.start()
        s.call("create_directory", path=self.p("newdir"))
        s.call("write_file", path=self.p("newdir/a.txt"), content="a")
        listing, _ = s.call("list_directory", path=str(self.root))
        self.assertIn("[DIR] newdir", listing)
        inner, err = s.call("list_directory", path=self.p("newdir"))
        self.assertFalse(err)
        self.assertEqual(inner, "[FILE] a.txt")
        info, _ = s.call("get_file_info", path=self.p("newdir"))
        self.assertIn("isDirectory: true", info)

    def test_file_info_on_ghost_file_is_metadata(self):
        s = self.start()
        s.call("write_file", path=self.p("report.md"), content="# report")
        info, _ = s.call("get_file_info", path=self.p("report.md"))
        self.assertIn("size: 8", info)
        self.assertNotIn("# report", info)

    def test_read_multiple_files_mixes_shadow_and_real(self):
        s = self.start()
        s.call("write_file", path=self.p("report.md"), content="# report")
        out, _ = s.call("read_multiple_files", paths=[self.p("report.md"), self.p("notes.txt")])
        self.assertIn("# report", out)
        self.assertIn("hello original", out)


class TestUnknownTools(ProxyTestCase):
    def test_unknown_tool_blocked_and_reported(self):
        s = self.start()
        s.call("mystery_tool")
        s.finish()
        self.assertFalse((self.root / "MYSTERY_RAN").exists())
        summary = (self.run_dir / "ghostmode-summary.txt").read_text()
        self.assertIn("mystery_tool", summary)
        self.assertIn("--allow", summary)

    def test_allow_passes_unknown_tool(self):
        s = self.start("--allow", "mystery_tool")
        out, _ = s.call("mystery_tool")
        s.finish()
        self.assertEqual(out, "mystery done")
        (self.root / "MYSTERY_RAN").unlink()

    def test_read_only_annotated_tool_passes(self):
        # get_file_info is read-only by name; list_directory by annotation too
        s = self.start()
        out, err = s.call("get_file_info", path=self.p("notes.txt"))
        s.finish()
        self.assertFalse(err)
        self.assertIn("size: 15", out)


class TestShadowVFSHelpers(unittest.TestCase):
    def test_paths_are_normalised(self):
        vfs = ShadowVFS()
        vfs.write("/a/b/../c.txt", "x")
        self.assertEqual(vfs.read("/a/c.txt"), "x")

    def test_children_include_implied_dirs(self):
        vfs = ShadowVFS()
        vfs.write("/a/new/deep/file.txt", "x")
        added, _ = vfs.children("/a")
        self.assertEqual(added, {"new": "dir"})

    def test_deleted_dir_hides_children(self):
        vfs = ShadowVFS()
        vfs.delete("/a/gone")
        self.assertTrue(vfs.is_deleted("/a/gone/file.txt"))
        self.assertFalse(vfs.is_deleted("/a/other.txt"))

    def test_rename_directory_moves_contents(self):
        vfs = ShadowVFS()
        vfs.mkdir("/a/d")
        vfs.write("/a/d/f.txt", "x")
        vfs.rename("/a/d", "/a/e")
        self.assertEqual(vfs.read("/a/e/f.txt"), "x")
        self.assertTrue(vfs.is_deleted("/a/d/f.txt"))

    def test_apply_edits(self):
        self.assertEqual(apply_edits("a b c", [{"oldText": "b", "newText": "B"}]), "a B c")
        with self.assertRaises(EditNotFound):
            apply_edits("a b c", [{"oldText": "z", "newText": "Z"}])

    def test_apply_edits_whitespace_insensitive(self):
        src = "def f():\n    return 1\n"
        out = apply_edits(src, [{"oldText": "return 1", "newText": "return 2"}])
        self.assertEqual(out, "def f():\n    return 2\n")
        out = apply_edits("  x = 1\n  y = 2\n",
                          [{"oldText": "x = 1\ny = 2", "newText": "x = 3\ny = 4"}])
        self.assertEqual(out, "  x = 3\n  y = 4\n")


if __name__ == "__main__":
    unittest.main()
