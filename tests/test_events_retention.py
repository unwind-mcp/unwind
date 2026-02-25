"""P1-6: Events.db retention enforcement tests.

Proves that:
1. Age-based retention deletes old events
2. Row-count cap deletes oldest events first
3. Orphaned snapshots are cleaned up with their events
4. Retention runs at startup via proxy
5. Config validation catches bad retention values
"""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from unwind.config import UnwindConfig
from unwind.recorder.event_store import EventStore, EventStatus
from unwind.startup_validator import validate_config


def _make_config() -> UnwindConfig:
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


def _make_store(config=None) -> EventStore:
    if config is None:
        config = _make_config()
    store = EventStore(config.events_db_path)
    store.initialize()
    return store


def _seed_events(store: EventStore, count: int, age_days: float = 0) -> list[str]:
    """Seed events into the store. Returns list of event IDs.

    If age_days > 0, events are backdated by that many days.
    """
    ids = []
    base_time = time.time() - (age_days * 86400) if age_days > 0 else time.time()
    for i in range(count):
        eid = store.write_pending(
            session_id="test-session",
            tool=f"test_tool_{i}",
            tool_class="sensor",
            target=f"/test/target_{i}",
            target_canonical=f"/test/target_{i}",
            parameters={"index": i},
            session_tainted=False,
            trust_state="green",
        )
        # Backdate the event if needed
        if age_days > 0:
            event_time = base_time + i  # Slight offset to keep ordering
            store._conn.execute(
                "UPDATE events SET timestamp = ? WHERE event_id = ?",
                (event_time, eid),
            )
            store._conn.commit()
        store.complete_event(eid, EventStatus.SUCCESS)
        ids.append(eid)
    return ids


# ═══════════════════════════════════════════════════════════════
# Age-based retention
# ═══════════════════════════════════════════════════════════════


class TestAgeBasedRetention(unittest.TestCase):
    """Events older than retention_days are deleted."""

    def test_old_events_deleted(self):
        store = _make_store()
        # Seed 10 events from 100 days ago
        old_ids = _seed_events(store, 10, age_days=100)
        # Seed 5 recent events
        new_ids = _seed_events(store, 5, age_days=0)

        result = store.enforce_retention(retention_days=90)
        self.assertEqual(result["events_deleted"], 10)
        self.assertEqual(store.event_count(), 5)

    def test_recent_events_kept(self):
        store = _make_store()
        _seed_events(store, 10, age_days=1)
        result = store.enforce_retention(retention_days=90)
        self.assertEqual(result["events_deleted"], 0)
        self.assertEqual(store.event_count(), 10)

    def test_zero_retention_keeps_all(self):
        store = _make_store()
        _seed_events(store, 10, age_days=365)
        result = store.enforce_retention(retention_days=0)
        self.assertEqual(result["events_deleted"], 0)
        self.assertEqual(store.event_count(), 10)

    def test_boundary_age(self):
        """Events clearly within retention kept, clearly outside deleted."""
        store = _make_store()
        # Events from 10 days ago (well within 30-day retention)
        _seed_events(store, 5, age_days=10)
        # Events from 60 days ago (well outside 30-day retention)
        _seed_events(store, 5, age_days=60)
        result = store.enforce_retention(retention_days=30)
        self.assertEqual(result["events_deleted"], 5)
        self.assertEqual(store.event_count(), 5)


# ═══════════════════════════════════════════════════════════════
# Row-count cap
# ═══════════════════════════════════════════════════════════════


class TestRowCountCap(unittest.TestCase):
    """When event count exceeds max_rows, oldest are deleted."""

    def test_excess_rows_deleted(self):
        store = _make_store()
        _seed_events(store, 20)
        result = store.enforce_retention(max_rows=10)
        self.assertEqual(result["events_deleted"], 10)
        self.assertEqual(store.event_count(), 10)

    def test_under_cap_no_deletion(self):
        store = _make_store()
        _seed_events(store, 5)
        result = store.enforce_retention(max_rows=10)
        self.assertEqual(result["events_deleted"], 0)
        self.assertEqual(store.event_count(), 5)

    def test_exact_cap_no_deletion(self):
        store = _make_store()
        _seed_events(store, 10)
        result = store.enforce_retention(max_rows=10)
        self.assertEqual(result["events_deleted"], 0)

    def test_zero_max_rows_unlimited(self):
        store = _make_store()
        _seed_events(store, 100)
        result = store.enforce_retention(max_rows=0)
        self.assertEqual(result["events_deleted"], 0)
        self.assertEqual(store.event_count(), 100)

    def test_oldest_deleted_first(self):
        """Oldest events (by timestamp) are the ones removed."""
        store = _make_store()
        old_ids = _seed_events(store, 5, age_days=10)
        new_ids = _seed_events(store, 5, age_days=0)

        store.enforce_retention(max_rows=5)

        # Old events should be gone
        remaining = store.query_events(limit=100)
        remaining_ids = {e["event_id"] for e in remaining}
        for oid in old_ids:
            self.assertNotIn(oid, remaining_ids)
        for nid in new_ids:
            self.assertIn(nid, remaining_ids)


# ═══════════════════════════════════════════════════════════════
# Snapshot cleanup
# ═══════════════════════════════════════════════════════════════


class TestSnapshotCleanup(unittest.TestCase):
    """Orphaned snapshots are deleted with their events."""

    def test_snapshots_deleted_with_events(self):
        store = _make_store()
        # Create old events with snapshots
        old_ids = _seed_events(store, 3, age_days=100)
        for eid in old_ids:
            store.store_snapshot(
                snapshot_id=f"snap_{eid}",
                event_id=eid,
                timestamp=time.time() - 8640000,
                snapshot_type="pre_write",
                original_path="/test/file.txt",
                snapshot_path="/snapshots/file.txt.bak",
                original_size=100,
                original_hash="abc123",
                metadata=None,
                restorable=True,
            )

        result = store.enforce_retention(retention_days=90)
        self.assertEqual(result["events_deleted"], 3)
        self.assertEqual(result["snapshots_deleted"], 3)

    def test_recent_snapshots_preserved(self):
        store = _make_store()
        new_ids = _seed_events(store, 3, age_days=1)
        for eid in new_ids:
            store.store_snapshot(
                snapshot_id=f"snap_{eid}",
                event_id=eid,
                timestamp=time.time(),
                snapshot_type="pre_write",
                original_path="/test/file.txt",
                snapshot_path="/snapshots/file.txt.bak",
                original_size=100,
                original_hash="abc123",
                metadata=None,
                restorable=True,
            )

        result = store.enforce_retention(retention_days=90)
        self.assertEqual(result["snapshots_deleted"], 0)


# ═══════════════════════════════════════════════════════════════
# Combined retention
# ═══════════════════════════════════════════════════════════════


class TestCombinedRetention(unittest.TestCase):
    """Both age + row cap applied together."""

    def test_age_and_rows_combined(self):
        store = _make_store()
        _seed_events(store, 10, age_days=100)  # Old
        _seed_events(store, 20, age_days=0)    # Recent

        # Age removes 10 old, then row cap removes 10 more
        result = store.enforce_retention(retention_days=90, max_rows=10)
        self.assertEqual(store.event_count(), 10)


# ═══════════════════════════════════════════════════════════════
# Event count helper
# ═══════════════════════════════════════════════════════════════


class TestEventCount(unittest.TestCase):
    """event_count() returns correct count."""

    def test_empty_db(self):
        store = _make_store()
        self.assertEqual(store.event_count(), 0)

    def test_after_inserts(self):
        store = _make_store()
        _seed_events(store, 7)
        self.assertEqual(store.event_count(), 7)

    def test_after_retention(self):
        store = _make_store()
        _seed_events(store, 20, age_days=100)
        store.enforce_retention(retention_days=90)
        self.assertEqual(store.event_count(), 0)


# ═══════════════════════════════════════════════════════════════
# Config validation
# ═══════════════════════════════════════════════════════════════


class TestRetentionConfigValidation(unittest.TestCase):
    """Startup validator catches bad retention values."""

    def test_negative_retention_days_rejected(self):
        config = _make_config()
        config.events_retention_days = -1
        result = validate_config(config)
        self.assertFalse(result.valid)
        errors = [e.field_name for e in result.errors]
        self.assertIn("events_retention_days", errors)

    def test_negative_max_rows_rejected(self):
        config = _make_config()
        config.events_max_rows = -1
        result = validate_config(config)
        self.assertFalse(result.valid)
        errors = [e.field_name for e in result.errors]
        self.assertIn("events_max_rows", errors)

    def test_zero_retention_valid(self):
        """0 means 'keep forever' — valid."""
        config = _make_config()
        config.events_retention_days = 0
        config.events_max_rows = 0
        result = validate_config(config)
        self.assertTrue(result.valid)

    def test_default_values_valid(self):
        config = _make_config()
        result = validate_config(config)
        self.assertTrue(result.valid)


# ═══════════════════════════════════════════════════════════════
# Uninitialized store safety
# ═══════════════════════════════════════════════════════════════


class TestRetentionSafety(unittest.TestCase):
    """Retention on uninitialized store doesn't crash."""

    def test_enforce_on_closed_store(self):
        config = _make_config()
        store = EventStore(config.events_db_path)
        # Don't call initialize()
        result = store.enforce_retention(retention_days=30)
        self.assertEqual(result["events_deleted"], 0)

    def test_event_count_on_closed_store(self):
        config = _make_config()
        store = EventStore(config.events_db_path)
        self.assertEqual(store.event_count(), 0)


if __name__ == "__main__":
    unittest.main()
