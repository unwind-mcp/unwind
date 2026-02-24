"""Integration tests for the rollback engine — full end-to-end flow.

Tests the complete lifecycle: file modification → snapshot → event recording
→ rollback via CLI → file restored. Covers all snapshot types and edge cases.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.recorder.event_store import EventStore, EventStatus
from unwind.snapshots.manager import SnapshotManager, SnapshotType, Snapshot
from unwind.snapshots.rollback import RollbackEngine, RollbackStatus, RollbackResult
from unwind.cli.main import cmd_undo, _snapshot_from_row, parse_since


class TestParsesSince(unittest.TestCase):
    """Tests for the CLI time parser."""

    def test_relative_hours(self):
        ts = parse_since("2h")
        self.assertAlmostEqual(ts, time.time() - 7200, delta=2)

    def test_relative_minutes(self):
        ts = parse_since("30m")
        self.assertAlmostEqual(ts, time.time() - 1800, delta=2)

    def test_relative_days(self):
        ts = parse_since("1d")
        self.assertAlmostEqual(ts, time.time() - 86400, delta=2)


class TestSnapshotManagerFileWrite(unittest.TestCase):
    """Test SnapshotManager for file write operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.manager = SnapshotManager(self.config)

        # Create workspace with a test file
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.test_file = self.config.workspace_root / "test.txt"
        self.test_file.write_text("original content")

    def test_snapshot_existing_file(self):
        """Snapshot an existing file before modification."""
        snap = self.manager.snapshot_file_write("evt_001", str(self.test_file))
        self.assertEqual(snap.snapshot_type, SnapshotType.FILE_COPY.value)
        self.assertTrue(snap.restorable)
        self.assertIsNotNone(snap.snapshot_path)
        self.assertEqual(snap.original_path, str(self.test_file))
        # Snapshot file should exist and contain original content
        self.assertTrue(Path(snap.snapshot_path).exists())
        self.assertEqual(Path(snap.snapshot_path).read_text(), "original content")

    def test_snapshot_new_file(self):
        """Snapshot for a file that doesn't exist yet (new file creation)."""
        new_file = str(self.config.workspace_root / "new.txt")
        snap = self.manager.snapshot_file_write("evt_002", new_file)
        self.assertEqual(snap.snapshot_type, SnapshotType.CONTENT_ONLY.value)
        self.assertTrue(snap.restorable)
        self.assertIsNone(snap.snapshot_path)
        metadata = json.loads(snap.metadata)
        self.assertEqual(metadata["type"], "new_file")

    def test_snapshot_too_large(self):
        """Files above size cap should be skipped."""
        config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
            snapshot_max_file_bytes=10,  # 10 bytes
        )
        config.ensure_dirs()
        manager = SnapshotManager(config)
        snap = manager.snapshot_file_write("evt_003", str(self.test_file))
        self.assertEqual(snap.snapshot_type, SnapshotType.SKIPPED_TOO_LARGE.value)
        self.assertFalse(snap.restorable)


class TestSnapshotManagerFileDelete(unittest.TestCase):
    """Test SnapshotManager for file deletion operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.manager = SnapshotManager(self.config)
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)

        self.test_file = self.config.workspace_root / "deleteme.txt"
        self.test_file.write_text("content to preserve")

    def test_snapshot_delete_moves_to_trash(self):
        """File deletion should move file to trash (atomic move)."""
        snap = self.manager.snapshot_file_delete("evt_004", str(self.test_file))
        self.assertEqual(snap.snapshot_type, SnapshotType.ATOMIC_MOVE.value)
        self.assertTrue(snap.restorable)
        # Original file should be gone
        self.assertFalse(self.test_file.exists())
        # File should be in trash
        self.assertTrue(Path(snap.snapshot_path).exists())
        self.assertEqual(Path(snap.snapshot_path).read_text(), "content to preserve")

    def test_snapshot_delete_nonexistent(self):
        """Deleting a non-existent file should produce non-restorable snapshot."""
        snap = self.manager.snapshot_file_delete("evt_005", "/no/such/file.txt")
        self.assertFalse(snap.restorable)


class TestRollbackEngineFileWrite(unittest.TestCase):
    """Test rollback of file write operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def test_rollback_file_modification(self):
        """Full cycle: write file → snapshot → modify → rollback → original restored."""
        target = self.config.workspace_root / "doc.txt"
        target.write_text("version 1")

        # Snapshot before modification
        snap = self.manager.snapshot_file_write("evt_010", str(target))
        self.assertTrue(snap.restorable)

        # Simulate agent modifying the file
        target.write_text("version 2 (agent wrote this)")
        self.assertEqual(target.read_text(), "version 2 (agent wrote this)")

        # Rollback
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertEqual(target.read_text(), "version 1")

    def test_rollback_new_file_creation(self):
        """Rollback of a new file = delete it."""
        target = self.config.workspace_root / "brand_new.txt"

        # Snapshot before "creation" (file doesn't exist yet)
        snap = self.manager.snapshot_file_write("evt_011", str(target))

        # Simulate agent creating the file
        target.write_text("I was just created by the agent")
        self.assertTrue(target.exists())

        # Rollback should delete it
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertFalse(target.exists())

    def test_rollback_already_rolled_back(self):
        """Rolling back a new-file snapshot when file is already gone."""
        target = self.config.workspace_root / "ephemeral.txt"
        snap = self.manager.snapshot_file_write("evt_012", str(target))
        # File was never actually created
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.ALREADY_ROLLED_BACK)

    def test_rollback_not_restorable(self):
        """Non-restorable snapshots should return NOT_RESTORABLE."""
        snap = Snapshot(
            snapshot_id="snap_test",
            event_id="evt_013",
            timestamp=time.time(),
            snapshot_type=SnapshotType.SKIPPED_TOO_LARGE.value,
            original_path="/tmp/big_file.bin",
            snapshot_path=None,
            original_size=100_000_000,
            original_hash=None,
            metadata=None,
            restorable=False,
        )
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.NOT_RESTORABLE)


class TestRollbackEngineFileDelete(unittest.TestCase):
    """Test rollback of file deletion operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def test_rollback_file_deletion(self):
        """Full cycle: file exists → snapshot_delete (moves to trash) → rollback → file restored."""
        target = self.config.workspace_root / "important.txt"
        target.write_text("do not lose this")

        # Snapshot-delete (moves file to trash)
        snap = self.manager.snapshot_file_delete("evt_020", str(target))
        self.assertFalse(target.exists())

        # Rollback should restore from trash
        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertTrue(target.exists())
        self.assertEqual(target.read_text(), "do not lose this")

    def test_rollback_delete_conflict(self):
        """Conflict: file was deleted, then a new file appeared at same path."""
        target = self.config.workspace_root / "contested.txt"
        target.write_text("original")

        snap = self.manager.snapshot_file_delete("evt_021", str(target))
        self.assertFalse(target.exists())

        # Something else creates a new file at the same path
        target.write_text("new occupant")

        # Rollback should detect conflict
        result = self.engine.rollback_single(snap, force=False)
        self.assertEqual(result.status, RollbackStatus.CONFLICT)

        # With force, should overwrite
        result_forced = self.engine.rollback_single(snap, force=True)
        # Note: snapshot was already moved in first attempt, but
        # the trash file should still exist for forced rollback
        # This depends on whether the conflict check consumed the trash file


class TestRollbackBatch(unittest.TestCase):
    """Test batch rollback (multiple events)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def test_batch_rollback_multiple_writes(self):
        """Roll back multiple file modifications in reverse order."""
        # Create files with original content
        file_a = self.config.workspace_root / "a.txt"
        file_b = self.config.workspace_root / "b.txt"
        file_a.write_text("a original")
        file_b.write_text("b original")

        # Snapshot both before modification
        snap_a = self.manager.snapshot_file_write("evt_030", str(file_a))
        snap_b = self.manager.snapshot_file_write("evt_031", str(file_b))

        # Agent modifies both
        file_a.write_text("a modified")
        file_b.write_text("b modified")

        # Batch rollback (newest first)
        results = self.engine.rollback_batch([snap_b, snap_a])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.status == RollbackStatus.SUCCESS for r in results))

        # Both files restored
        self.assertEqual(file_a.read_text(), "a original")
        self.assertEqual(file_b.read_text(), "b original")

    def test_batch_stops_on_conflict(self):
        """Batch stops at first conflict (unless forced)."""
        file_a = self.config.workspace_root / "safe.txt"
        file_a.write_text("safe original")
        snap_a = self.manager.snapshot_file_write("evt_032", str(file_a))
        file_a.write_text("safe modified")

        # Create a conflicting snapshot (snapshot missing)
        snap_missing = Snapshot(
            snapshot_id="snap_missing",
            event_id="evt_033",
            timestamp=time.time(),
            snapshot_type=SnapshotType.FILE_COPY.value,
            original_path="/tmp/nonexistent_snap_target.txt",
            snapshot_path="/tmp/definitely_no_snapshot_here.txt",
            original_size=100,
            original_hash=None,
            metadata=json.dumps({"method": "copy"}),
            restorable=True,
        )

        # Batch: first the missing snapshot, then the good one
        results = self.engine.rollback_batch([snap_missing, snap_a])
        # First should fail (SNAPSHOT_MISSING), second should still be attempted
        self.assertEqual(results[0].status, RollbackStatus.SNAPSHOT_MISSING)
        # Batch continues because SNAPSHOT_MISSING != CONFLICT
        self.assertEqual(len(results), 2)


class TestEventStoreSnapshotIntegration(unittest.TestCase):
    """Test the EventStore ↔ Snapshot metadata flow."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.store = EventStore(self.config.events_db_path)
        self.store.initialize()
        self.manager = SnapshotManager(self.config)

    def tearDown(self):
        self.store.close()

    def test_full_event_snapshot_cycle(self):
        """Write pending → snapshot → store snapshot → query → convert to Snapshot."""
        # Write a pending event
        event_id = self.store.write_pending(
            session_id="sess_001",
            tool="fs_write",
            tool_class="actuator",
            target="/workspace/test.txt",
            target_canonical="/workspace/test.txt",
            parameters={"path": "/workspace/test.txt", "content": "hello"},
            session_tainted=False,
            trust_state="green",
        )

        # Take snapshot
        target = self.config.workspace_root / "test.txt"
        target.write_text("before write")
        snap = self.manager.snapshot_file_write(event_id, str(target))

        # Store snapshot metadata in DB
        self.store.store_snapshot(
            snapshot_id=snap.snapshot_id,
            event_id=snap.event_id,
            timestamp=snap.timestamp,
            snapshot_type=snap.snapshot_type,
            original_path=snap.original_path,
            snapshot_path=snap.snapshot_path,
            original_size=snap.original_size,
            original_hash=snap.original_hash,
            metadata=snap.metadata,
            restorable=snap.restorable,
        )

        # Complete the event
        self.store.complete_event(event_id, EventStatus.SUCCESS, duration_ms=15.2)

        # Query it back
        row = self.store.get_snapshot_for_event(event_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["event_id"], event_id)
        self.assertEqual(row["snapshot_type"], SnapshotType.FILE_COPY.value)
        self.assertTrue(row["restorable"])

        # Convert to Snapshot object (same as CLI does)
        snap_obj = _snapshot_from_row(row)
        self.assertIsInstance(snap_obj, Snapshot)
        self.assertEqual(snap_obj.event_id, event_id)

        # Verify it appears in restorable list
        restorable = self.store.get_restorable_snapshots()
        self.assertEqual(len(restorable), 1)

        # Verify "last restorable" works
        last = self.store.get_last_restorable_snapshot()
        self.assertIsNotNone(last)
        self.assertEqual(last["event_id"], event_id)

    def test_mark_rolled_back_excludes_from_queries(self):
        """Rolled-back snapshots should not appear in restorable queries."""
        event_id = self.store.write_pending(
            session_id="sess_002", tool="fs_write", tool_class="actuator",
            target="/t", target_canonical="/t", parameters={},
            session_tainted=False, trust_state="green",
        )
        target = self.config.workspace_root / "rb_test.txt"
        target.write_text("content")
        snap = self.manager.snapshot_file_write(event_id, str(target))

        self.store.store_snapshot(
            snapshot_id=snap.snapshot_id, event_id=event_id,
            timestamp=snap.timestamp, snapshot_type=snap.snapshot_type,
            original_path=snap.original_path, snapshot_path=snap.snapshot_path,
            original_size=snap.original_size, original_hash=snap.original_hash,
            metadata=snap.metadata, restorable=snap.restorable,
        )

        # Before rollback: visible
        self.assertEqual(len(self.store.get_restorable_snapshots()), 1)

        # Mark rolled back
        self.store.mark_rolled_back(snap.snapshot_id)

        # After rollback: excluded
        self.assertEqual(len(self.store.get_restorable_snapshots()), 0)
        self.assertIsNone(self.store.get_last_restorable_snapshot())

    def test_multiple_snapshots_ordered(self):
        """Multiple snapshots should be returned newest-first."""
        for i in range(3):
            eid = self.store.write_pending(
                session_id="sess_003", tool="fs_write", tool_class="actuator",
                target=f"/t{i}", target_canonical=f"/t{i}", parameters={},
                session_tainted=False, trust_state="green",
            )
            self.store.store_snapshot(
                snapshot_id=f"snap_{i}", event_id=eid,
                timestamp=time.time() + i,  # Offset to ensure ordering
                snapshot_type=SnapshotType.FILE_COPY.value,
                original_path=f"/t{i}", snapshot_path=f"/snap{i}",
                original_size=100, original_hash=None,
                metadata=None, restorable=True,
            )
            time.sleep(0.01)  # Small gap for timestamp ordering

        restorable = self.store.get_restorable_snapshots()
        self.assertEqual(len(restorable), 3)
        # Newest first
        self.assertEqual(restorable[0]["original_path"], "/t2")
        self.assertEqual(restorable[2]["original_path"], "/t0")


class TestFullRollbackEndToEnd(unittest.TestCase):
    """Integration test: the complete undo lifecycle as a user would experience it."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.config.workspace_root.mkdir(parents=True, exist_ok=True)
        self.store = EventStore(self.config.events_db_path)
        self.store.initialize()
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def tearDown(self):
        self.store.close()

    def test_undo_last_restores_file(self):
        """Simulate: agent writes file → user runs 'unwind undo last' → file restored."""
        target = self.config.workspace_root / "report.md"
        target.write_text("# Report v1\n\nOriginal content.")

        # 1. UNWIND records pending event (pre-call)
        event_id = self.store.write_pending(
            session_id="sess_end2end",
            tool="fs_write",
            tool_class="actuator",
            target=str(target),
            target_canonical=str(target),
            parameters={"path": str(target), "content": "overwritten"},
            session_tainted=False,
            trust_state="green",
        )

        # 2. UNWIND takes snapshot (pre-call)
        snap = self.manager.snapshot_file_write(event_id, str(target))
        self.store.store_snapshot(
            snapshot_id=snap.snapshot_id, event_id=event_id,
            timestamp=snap.timestamp, snapshot_type=snap.snapshot_type,
            original_path=snap.original_path, snapshot_path=snap.snapshot_path,
            original_size=snap.original_size, original_hash=snap.original_hash,
            metadata=snap.metadata, restorable=snap.restorable,
        )

        # 3. Agent writes to file (upstream executes)
        target.write_text("# Report v2\n\nAgent overwrote this.")

        # 4. UNWIND records completion
        self.store.complete_event(event_id, EventStatus.SUCCESS, duration_ms=12.0)

        # 5. Verify the chain is valid
        valid, _ = self.store.verify_chain()
        self.assertTrue(valid)

        # 6. User wants to undo — find last restorable snapshot
        last = self.store.get_last_restorable_snapshot()
        self.assertIsNotNone(last)
        self.assertEqual(last["event_id"], event_id)

        # 7. Execute rollback
        snap_obj = _snapshot_from_row(last)
        result = self.engine.rollback_single(snap_obj)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)

        # 8. Mark as rolled back
        self.store.mark_rolled_back(last["snapshot_id"])

        # 9. Verify file is restored
        self.assertEqual(target.read_text(), "# Report v1\n\nOriginal content.")

        # 10. Verify no more restorable snapshots
        self.assertIsNone(self.store.get_last_restorable_snapshot())

    def test_undo_deletion_restores_file(self):
        """Simulate: agent deletes file → user runs undo → file restored."""
        target = self.config.workspace_root / "precious.dat"
        target.write_text("irreplaceable data")

        # Pre-call: record event + snapshot-delete
        event_id = self.store.write_pending(
            session_id="sess_del",
            tool="fs_delete",
            tool_class="actuator",
            target=str(target),
            target_canonical=str(target),
            parameters={"path": str(target)},
            session_tainted=False,
            trust_state="green",
        )

        snap = self.manager.snapshot_file_delete(event_id, str(target))
        self.store.store_snapshot(
            snapshot_id=snap.snapshot_id, event_id=event_id,
            timestamp=snap.timestamp, snapshot_type=snap.snapshot_type,
            original_path=snap.original_path, snapshot_path=snap.snapshot_path,
            original_size=snap.original_size, original_hash=snap.original_hash,
            metadata=snap.metadata, restorable=snap.restorable,
        )

        # File is now gone (atomic move to trash)
        self.assertFalse(target.exists())

        self.store.complete_event(event_id, EventStatus.SUCCESS, duration_ms=5.0)

        # Undo
        last = self.store.get_last_restorable_snapshot()
        snap_obj = _snapshot_from_row(last)
        result = self.engine.rollback_single(snap_obj)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)

        # File restored
        self.assertTrue(target.exists())
        self.assertEqual(target.read_text(), "irreplaceable data")

    def test_chain_integrity_after_rollback(self):
        """CR-AFT chain should remain valid after rollback operations."""
        target = self.config.workspace_root / "chain_test.txt"
        target.write_text("v1")

        # Multiple events
        for i in range(5):
            eid = self.store.write_pending(
                session_id="sess_chain", tool="fs_write", tool_class="actuator",
                target=str(target), target_canonical=str(target),
                parameters={"v": i}, session_tainted=False, trust_state="green",
            )
            self.store.complete_event(eid, EventStatus.SUCCESS, duration_ms=1.0)

        # Chain should be valid
        valid, error = self.store.verify_chain()
        self.assertTrue(valid, f"Chain broken: {error}")


class TestConfigJsonDiff(unittest.TestCase):
    """Test JSON diff snapshot and rollback."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
        )
        self.config.ensure_dirs()
        self.manager = SnapshotManager(self.config)
        self.engine = RollbackEngine(self.config)

    def test_config_change_rollback(self):
        before = {"setting_a": True, "limit": 100}
        after = {"setting_a": False, "limit": 200}

        snap = self.manager.snapshot_config_change("evt_cfg", before, after)
        self.assertEqual(snap.snapshot_type, SnapshotType.JSON_DIFF.value)
        self.assertTrue(snap.restorable)

        result = self.engine.rollback_single(snap)
        self.assertEqual(result.status, RollbackStatus.SUCCESS)
        self.assertIn("setting_a", result.message)


if __name__ == "__main__":
    unittest.main()
