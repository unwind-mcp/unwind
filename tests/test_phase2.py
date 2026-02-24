"""Phase 2 Tests — Snapshots, Rollback, Read Collapsing, Proxy Integration.

Test coverage:
- SnapshotManager: file write, file delete, config change, size cap, new file
- RollbackEngine: single rollback, conflict detection, force, batch, atomic move undo
- EventStore: snapshot storage/retrieval, rollback marking, read collapsing
- Proxy Integration: snapshot creation during tool forwarding
"""

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from unwind.config import UnwindConfig
from unwind.session import Session, TrustState
from unwind.proxy import UnwindProxy
from unwind.recorder.event_store import EventStore, EventStatus
from unwind.snapshots.manager import SnapshotManager, Snapshot, SnapshotType
from unwind.snapshots.rollback import RollbackEngine, RollbackStatus


class TestSnapshotManager(unittest.TestCase):
    """Tests for the smart snapshot manager."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.manager = SnapshotManager(self.config)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_snapshot_new_file(self):
        """Snapshotting a non-existent file records it as CONTENT_ONLY."""
        target = os.path.join(self.tmpdir, "workspace", "new.txt")
        snap = self.manager.snapshot_file_write("evt_001", target)
        self.assertEqual(snap.snapshot_type, SnapshotType.CONTENT_ONLY.value)
        self.assertTrue(snap.restorable)
        self.assertIsNone(snap.snapshot_path)
        meta = json.loads(snap.metadata)
        self.assertFalse(meta["existed"])

    def test_snapshot_existing_file(self):
        """Snapshotting an existing file creates a FILE_COPY."""
        target = os.path.join(self.tmpdir, "workspace", "existing.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("original content")

        snap = self.manager.snapshot_file_write("evt_002", target)
        self.assertEqual(snap.snapshot_type, SnapshotType.FILE_COPY.value)
        self.assertTrue(snap.restorable)
        self.assertIsNotNone(snap.snapshot_path)
        self.assertTrue(os.path.exists(snap.snapshot_path))
        # Verify snapshot content matches original
        with open(snap.snapshot_path) as f:
            self.assertEqual(f.read(), "original content")

    def test_snapshot_size_cap(self):
        """Files exceeding the size cap are skipped."""
        target = os.path.join(self.tmpdir, "workspace", "big.bin")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        # Write a file larger than the cap (set cap to 1KB for testing)
        self.config.snapshot_max_file_bytes = 1024
        with open(target, "wb") as f:
            f.write(b"x" * 2048)

        snap = self.manager.snapshot_file_write("evt_003", target)
        self.assertEqual(snap.snapshot_type, SnapshotType.SKIPPED_TOO_LARGE.value)
        self.assertFalse(snap.restorable)

    def test_snapshot_file_hash(self):
        """Snapshot records SHA-256 of the original file."""
        target = os.path.join(self.tmpdir, "workspace", "hashme.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        content = b"hash this content"
        with open(target, "wb") as f:
            f.write(content)

        snap = self.manager.snapshot_file_write("evt_004", target)
        expected_hash = hashlib.sha256(content).hexdigest()
        self.assertEqual(snap.original_hash, expected_hash)

    def test_snapshot_file_delete_atomic_move(self):
        """Deleting a file performs an atomic move to trash."""
        target = os.path.join(self.tmpdir, "workspace", "deleteme.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("to be deleted")

        snap = self.manager.snapshot_file_delete("evt_005", target)
        self.assertEqual(snap.snapshot_type, SnapshotType.ATOMIC_MOVE.value)
        self.assertTrue(snap.restorable)
        # Original file should be gone (moved to trash)
        self.assertFalse(os.path.exists(target))
        # Trash should have the file
        self.assertTrue(os.path.exists(snap.snapshot_path))
        with open(snap.snapshot_path) as f:
            self.assertEqual(f.read(), "to be deleted")

    def test_snapshot_delete_nonexistent(self):
        """Deleting a non-existent file records file_not_found."""
        target = os.path.join(self.tmpdir, "workspace", "nope.txt")
        snap = self.manager.snapshot_file_delete("evt_006", target)
        self.assertEqual(snap.snapshot_type, SnapshotType.ATOMIC_MOVE.value)
        self.assertFalse(snap.restorable)

    def test_snapshot_config_change(self):
        """Config changes are stored as JSON diffs."""
        before = {"theme": "light", "timeout": 30}
        after = {"theme": "dark", "timeout": 30}
        snap = self.manager.snapshot_config_change("evt_007", before, after)
        self.assertEqual(snap.snapshot_type, SnapshotType.JSON_DIFF.value)
        self.assertTrue(snap.restorable)
        diff = json.loads(snap.metadata)
        self.assertEqual(diff["before"]["theme"], "light")
        self.assertEqual(diff["after"]["theme"], "dark")


class TestRollbackEngine(unittest.TestCase):
    """Tests for the rollback engine."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rollback_file_write(self):
        """Rolling back a file write restores original content."""
        target = os.path.join(self.tmpdir, "workspace", "modified.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("original")

        # Snapshot before modification
        snap = self.manager.snapshot_file_write("evt_010", target)

        # Simulate the modification
        with open(target, "w") as f:
            f.write("modified by agent")

        # Rollback
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        with open(target) as f:
            self.assertEqual(f.read(), "original")

    def test_rollback_new_file_creation(self):
        """Rolling back a new file creation deletes the file."""
        target = os.path.join(self.tmpdir, "workspace", "created.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)

        # Snapshot before creation (file doesn't exist)
        snap = self.manager.snapshot_file_write("evt_011", target)

        # Simulate file creation
        with open(target, "w") as f:
            f.write("new content")

        # Rollback should delete it
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertFalse(os.path.exists(target))

    def test_rollback_new_file_already_gone(self):
        """Rolling back a creation where file is already gone = already_rolled_back."""
        target = os.path.join(self.tmpdir, "workspace", "gone.txt")
        snap = self.manager.snapshot_file_write("evt_012", target)
        # File was never actually created
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.ALREADY_ROLLED_BACK)

    def test_rollback_atomic_move(self):
        """Rolling back a deletion restores the file from trash."""
        target = os.path.join(self.tmpdir, "workspace", "trashed.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("precious data")

        # Snapshot (moves file to trash)
        snap = self.manager.snapshot_file_delete("evt_013", target)
        self.assertFalse(os.path.exists(target))

        # Rollback (moves back)
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertTrue(os.path.exists(target))
        with open(target) as f:
            self.assertEqual(f.read(), "precious data")

    def test_rollback_conflict_detection_atomic_move(self):
        """Conflict is detected when a new file exists at the deleted file's path."""
        target = os.path.join(self.tmpdir, "workspace", "conflict.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("original content")

        # Snapshot-delete moves file to trash
        snap = self.manager.snapshot_file_delete("evt_014", target)
        self.assertFalse(os.path.exists(target))

        # Someone creates a NEW different file at the same path
        with open(target, "w") as f:
            f.write("brand new file by another process")

        # Rollback should detect conflict — new file at target path
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.CONFLICT)

    def test_rollback_force_ignores_conflict(self):
        """Force flag overrides conflict detection."""
        target = os.path.join(self.tmpdir, "workspace", "force.txt")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as f:
            f.write("original")

        snap = self.manager.snapshot_file_write("evt_015", target)

        with open(target, "w") as f:
            f.write("changed twice")

        result = self.engine.rollback_single(snap, force=True)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        with open(target) as f:
            self.assertEqual(f.read(), "original")

    def test_rollback_not_restorable(self):
        """Skipped snapshots cannot be rolled back."""
        snap = Snapshot(
            snapshot_id="snap_evt_016",
            event_id="evt_016",
            timestamp=time.time(),
            snapshot_type=SnapshotType.SKIPPED_TOO_LARGE.value,
            original_path="/some/big/file",
            snapshot_path=None,
            original_size=100_000_000,
            original_hash=None,
            metadata=json.dumps({"type": "skipped"}),
            restorable=False,
        )
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.NOT_RESTORABLE)

    def test_rollback_missing_snapshot_file(self):
        """Missing snapshot file on disk returns SNAPSHOT_MISSING."""
        snap = Snapshot(
            snapshot_id="snap_evt_017",
            event_id="evt_017",
            timestamp=time.time(),
            snapshot_type=SnapshotType.FILE_COPY.value,
            original_path="/some/file.txt",
            snapshot_path="/nonexistent/snapshot.txt",
            original_size=100,
            original_hash="abc123",
            metadata=json.dumps({"method": "copy"}),
            restorable=True,
        )
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SNAPSHOT_MISSING)

    def test_rollback_config_change(self):
        """Config change rollback returns the before state."""
        snap = self.manager.snapshot_config_change(
            "evt_018",
            before={"key": "old_value"},
            after={"key": "new_value"},
        )
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertIn("old_value", result.message)

    def test_rollback_batch_stops_on_conflict(self):
        """Batch rollback stops at first conflict (unless forced)."""
        workspace = os.path.join(self.tmpdir, "workspace")
        os.makedirs(workspace, exist_ok=True)

        # Delete file A (atomic move to trash)
        file_a = os.path.join(workspace, "a.txt")
        with open(file_a, "w") as f:
            f.write("A original")
        snap_a = self.manager.snapshot_file_delete("evt_020", file_a)

        # Delete file B (atomic move to trash)
        file_b = os.path.join(workspace, "b.txt")
        with open(file_b, "w") as f:
            f.write("B original")
        snap_b = self.manager.snapshot_file_delete("evt_021", file_b)

        # Put new different files at both paths (creates conflicts)
        with open(file_a, "w") as f:
            f.write("A new version by someone else")
        with open(file_b, "w") as f:
            f.write("B new version by someone else")

        # Batch: newest first (B, then A)
        results = self.engine.rollback_batch([snap_b, snap_a], force=False)
        # First one (B) has conflict, batch should stop
        self.assertEqual(results[0].status, RollbackStatus.CONFLICT)
        self.assertEqual(len(results), 1)  # Stopped at first conflict

    def test_rollback_batch_force(self):
        """Forced batch rollback continues through conflicts."""
        workspace = os.path.join(self.tmpdir, "workspace2")
        os.makedirs(workspace, exist_ok=True)

        # Delete two files
        file_a = os.path.join(workspace, "a.txt")
        with open(file_a, "w") as f:
            f.write("A original")
        snap_a = self.manager.snapshot_file_delete("evt_022", file_a)

        file_b = os.path.join(workspace, "b.txt")
        with open(file_b, "w") as f:
            f.write("B original")
        snap_b = self.manager.snapshot_file_delete("evt_023", file_b)

        # Put new conflicting files at both paths
        with open(file_a, "w") as f:
            f.write("A new")
        with open(file_b, "w") as f:
            f.write("B new")

        # Force should override conflicts and restore originals
        results = self.engine.rollback_batch([snap_b, snap_a], force=True)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.status == RollbackStatus.SUCCESS for r in results))
        with open(file_a) as f:
            self.assertEqual(f.read(), "A original")
        with open(file_b) as f:
            self.assertEqual(f.read(), "B original")


class TestEventStoreSnapshots(unittest.TestCase):
    """Tests for snapshot metadata in the event store."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.store = EventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_event(self, event_suffix="001", tool="fs_write") -> str:
        """Helper to create a test event."""
        return self.store.write_pending(
            session_id="test_session",
            tool=tool,
            tool_class="actuator",
            target="/workspace/test.txt",
            target_canonical="/workspace/test.txt",
            parameters={"path": "/workspace/test.txt"},
            session_tainted=False,
            trust_state="green",
        )

    def test_store_and_retrieve_snapshot(self):
        """Store snapshot metadata and retrieve by event_id."""
        event_id = self._write_event()
        self.store.store_snapshot(
            snapshot_id=f"snap_{event_id}",
            event_id=event_id,
            timestamp=time.time(),
            snapshot_type="file_copy",
            original_path="/workspace/test.txt",
            snapshot_path="/snapshots/snap_001.txt",
            original_size=1024,
            original_hash="abc123",
            metadata=json.dumps({"method": "copy"}),
            restorable=True,
        )

        row = self.store.get_snapshot_for_event(event_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["original_path"], "/workspace/test.txt")
        self.assertEqual(row["snapshot_type"], "file_copy")
        self.assertTrue(row["restorable"])

    def test_get_restorable_snapshots(self):
        """Retrieve restorable snapshots filtered by various criteria."""
        # Create 3 events with snapshots
        for i in range(3):
            eid = self._write_event(event_suffix=str(i))
            self.store.store_snapshot(
                snapshot_id=f"snap_{eid}",
                event_id=eid,
                timestamp=time.time() + i,
                snapshot_type="file_copy",
                original_path=f"/workspace/file{i}.txt",
                snapshot_path=f"/snapshots/file{i}.txt",
                original_size=100,
                original_hash=None,
                metadata=None,
                restorable=True,
            )

        # Create one non-restorable
        eid = self._write_event(event_suffix="3")
        self.store.store_snapshot(
            snapshot_id=f"snap_{eid}",
            event_id=eid,
            timestamp=time.time() + 3,
            snapshot_type="skipped",
            original_path="/workspace/big.bin",
            snapshot_path=None,
            original_size=100_000_000,
            original_hash=None,
            metadata=None,
            restorable=False,
        )

        snaps = self.store.get_restorable_snapshots()
        self.assertEqual(len(snaps), 3)  # Only restorable ones

    def test_get_last_restorable(self):
        """Get the most recent restorable snapshot."""
        eid1 = self._write_event(event_suffix="a")
        self.store.store_snapshot(
            snapshot_id=f"snap_{eid1}",
            event_id=eid1,
            timestamp=time.time(),
            snapshot_type="file_copy",
            original_path="/workspace/first.txt",
            snapshot_path="/snapshots/first.txt",
            original_size=100,
            original_hash=None,
            metadata=None,
            restorable=True,
        )

        time.sleep(0.01)  # Ensure different timestamp
        eid2 = self._write_event(event_suffix="b")
        self.store.store_snapshot(
            snapshot_id=f"snap_{eid2}",
            event_id=eid2,
            timestamp=time.time(),
            snapshot_type="file_copy",
            original_path="/workspace/second.txt",
            snapshot_path="/snapshots/second.txt",
            original_size=200,
            original_hash=None,
            metadata=None,
            restorable=True,
        )

        last = self.store.get_last_restorable_snapshot()
        self.assertIsNotNone(last)
        self.assertEqual(last["original_path"], "/workspace/second.txt")

    def test_mark_rolled_back(self):
        """Marking a snapshot as rolled back excludes it from future queries."""
        eid = self._write_event()
        snap_id = f"snap_{eid}"
        self.store.store_snapshot(
            snapshot_id=snap_id,
            event_id=eid,
            timestamp=time.time(),
            snapshot_type="file_copy",
            original_path="/workspace/rolled.txt",
            snapshot_path="/snapshots/rolled.txt",
            original_size=100,
            original_hash=None,
            metadata=None,
            restorable=True,
        )

        self.store.mark_rolled_back(snap_id)

        # Should no longer appear in restorable queries
        snaps = self.store.get_restorable_snapshots()
        self.assertEqual(len(snaps), 0)

        last = self.store.get_last_restorable_snapshot()
        self.assertIsNone(last)

    def test_snapshots_table_exists(self):
        """Verify the snapshots table was created."""
        rows = self.store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots'"
        ).fetchall()
        self.assertEqual(len(rows), 1)


class TestReadCollapsing(unittest.TestCase):
    """Tests for aggregate read collapsing in the flight recorder."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.store = EventStore(self.db_path, read_collapse_seconds=60.0)
        self.store.initialize()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_read_not_collapsed(self):
        """First read in a session creates a new event (not collapsed)."""
        result = self.store.should_collapse_read("sess1", "fs_read", "read")
        self.assertIsNone(result)

    def test_sequential_reads_collapse(self):
        """Sequential reads of the same tool in the same session collapse."""
        # Start a window
        self.store.should_collapse_read("sess1", "fs_read", "read")
        self.store.start_read_collapse("sess1", "evt_100", "fs_read")

        # Second read should collapse into the first
        result = self.store.should_collapse_read("sess1", "fs_read", "read")
        self.assertEqual(result, "evt_100")

    def test_non_read_flushes_collapse(self):
        """A non-read tool call flushes any pending collapse."""
        self.store.should_collapse_read("sess1", "fs_read", "read")
        self.store.start_read_collapse("sess1", "evt_101", "fs_read")
        self.store.should_collapse_read("sess1", "fs_read", "read")  # +1

        # Non-read flushes
        result = self.store.should_collapse_read("sess1", "fs_write", "actuator")
        self.assertIsNone(result)
        # Window should be cleared
        self.assertNotIn("sess1", self.store._read_collapse_window)

    def test_different_tool_starts_new_window(self):
        """Different read tool starts a new collapse window."""
        self.store.should_collapse_read("sess1", "fs_read", "read")
        self.store.start_read_collapse("sess1", "evt_102", "fs_read")

        # Different tool
        result = self.store.should_collapse_read("sess1", "read_document", "read")
        self.assertIsNone(result)  # New window needed


class TestProxySnapshotIntegration(unittest.TestCase):
    """Tests for snapshot integration in the proxy."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.proxy = UnwindProxy(self.config)
        self.proxy.startup()

        # Create workspace
        workspace = Path(self.tmpdir) / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.proxy.shutdown()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_async(self, coro):
        """Helper to run async code in tests."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_snapshot_created_on_fs_write(self):
        """Proxy creates a snapshot when forwarding fs_write."""
        target = os.path.join(self.tmpdir, "workspace", "snapped.txt")
        with open(target, "w") as f:
            f.write("before edit")

        result = self._run_async(
            self.proxy.handle_tool_call(
                "fs_write",
                parameters={"path": target, "content": "after edit"},
                session_id="test_sess",
            )
        )
        self.assertEqual(result["status"], "success")

        # Check snapshot was stored in DB
        snap = self.proxy.event_store.get_last_restorable_snapshot()
        self.assertIsNotNone(snap)
        self.assertEqual(snap["original_path"], target)
        self.assertEqual(snap["snapshot_type"], "file_copy")

    def test_snapshot_created_on_fs_delete(self):
        """Proxy creates a snapshot when forwarding fs_delete."""
        target = os.path.join(self.tmpdir, "workspace", "to_delete.txt")
        with open(target, "w") as f:
            f.write("delete me")

        result = self._run_async(
            self.proxy.handle_tool_call(
                "fs_delete",
                parameters={"path": target},
                session_id="test_sess",
            )
        )
        self.assertEqual(result["status"], "success")

        snap = self.proxy.event_store.get_last_restorable_snapshot()
        self.assertIsNotNone(snap)
        self.assertEqual(snap["snapshot_type"], "atomic_move")

    def test_no_snapshot_for_non_file_tools(self):
        """Non-file state-modifying tools (without targets) don't create snapshots."""
        result = self._run_async(
            self.proxy.handle_tool_call(
                "send_email",
                parameters={"to": "test@example.com", "body": "hello"},
                session_id="test_sess",
            )
        )

        # send_email requires taint + high-risk check, but without taint
        # it passes through. No file target = no snapshot.
        snap = self.proxy.event_store.get_last_restorable_snapshot()
        self.assertIsNone(snap)

    def test_snapshot_new_file_creation(self):
        """Snapshotting a write to a non-existent file records it correctly."""
        target = os.path.join(self.tmpdir, "workspace", "brand_new.txt")
        # Don't create the file — it's new

        result = self._run_async(
            self.proxy.handle_tool_call(
                "fs_write",
                parameters={"path": target, "content": "new content"},
                session_id="test_sess",
            )
        )
        self.assertEqual(result["status"], "success")

        snap = self.proxy.event_store.get_last_restorable_snapshot()
        self.assertIsNotNone(snap)
        self.assertEqual(snap["snapshot_type"], "content_only")


if __name__ == "__main__":
    unittest.main()
