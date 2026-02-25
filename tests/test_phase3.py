"""Phase 3 Tests — Dashboard API, Away Mode Summary, Trust Light.

Test coverage:
- Dashboard Flask API endpoints (trust-state, events, verify, snapshots, undo, away-summary, sessions)
- Away Mode summary generation
- Dashboard app creation
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.recorder.event_store import EventStore, EventStatus
from unwind.dashboard.away_mode import generate_away_summary, _format_duration
from unwind.dashboard.app import create_app


class TestAwaySummary(unittest.TestCase):
    """Tests for the Away Mode summary generator."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.store = EventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_event(self, tool, tool_class="actuator", status="success",
                     tainted=False, trust="green", ghost=False):
        """Helper to create a test event."""
        eid = self.store.write_pending(
            session_id="test_session",
            tool=tool,
            tool_class=tool_class,
            target=f"/workspace/{tool}_target",
            target_canonical=f"/workspace/{tool}_target",
            parameters=None,
            session_tainted=tainted,
            trust_state=trust,
            ghost_mode=ghost,
        )
        self.store.complete_event(eid, EventStatus(status))
        return eid

    def test_empty_summary(self):
        """Summary with no events returns zeros."""
        summary = generate_away_summary(self.store, time.time() - 3600)
        self.assertEqual(summary.total_actions, 0)
        self.assertEqual(summary.trust_state, "green")

    def test_counts_emails_sent(self):
        """Counts emails correctly."""
        self._write_event("send_email")
        self._write_event("send_email")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.emails_sent, 2)

    def test_counts_blocked_actions(self):
        """Counts blocked actions."""
        self._write_event("bash_exec", status="blocked", trust="red")
        self._write_event("fs_write", status="success")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.blocked_actions, 1)
        self.assertEqual(summary.red_events, 1)

    def test_counts_ghost_actions(self):
        """Counts ghost mode actions."""
        self._write_event("fs_write", status="ghost_success", ghost=True)
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.ghost_actions, 1)

    def test_worst_trust_state_propagates(self):
        """Trust state reflects the worst state seen."""
        self._write_event("fs_read", tool_class="read")
        self._write_event("send_email", trust="amber")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.trust_state, "amber")

    def test_red_overrides_amber(self):
        """Red trust state overrides amber."""
        self._write_event("send_email", trust="amber")
        self._write_event("bash_exec", status="blocked", trust="red")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.trust_state, "red")

    def test_review_items_for_blocked_actuators(self):
        """Blocked actuator actions appear in review items."""
        self._write_event("bash_exec", status="blocked", trust="red")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(len(summary.review_items), 1)
        self.assertEqual(summary.review_items[0]["tool"], "bash_exec")

    def test_categorises_file_operations(self):
        """Correctly categorises file operations."""
        self._write_event("fs_write")
        self._write_event("fs_delete")
        self._write_event("fs_mkdir")
        summary = generate_away_summary(self.store, time.time() - 60)
        self.assertEqual(summary.files_modified, 1)
        self.assertEqual(summary.files_deleted, 1)
        self.assertEqual(summary.files_created, 1)

    def test_categorises_reads(self):
        """Read operations are counted."""
        self._write_event("fs_read", tool_class="read")
        self._write_event("read_email", tool_class="sensor")
        summary = generate_away_summary(self.store, time.time() - 60)
        # fs_read is classified as "read"
        self.assertGreaterEqual(summary.reads, 1)

    def test_to_dict(self):
        """Summary can be serialised to dict."""
        self._write_event("send_email")
        summary = generate_away_summary(self.store, time.time() - 60)
        d = summary.to_dict()
        self.assertIn("emails_sent", d)
        self.assertIn("trust_state", d)
        self.assertEqual(d["emails_sent"], 1)

    def test_format_duration(self):
        """Duration formatting works correctly."""
        self.assertEqual(_format_duration(30), "30s")
        self.assertEqual(_format_duration(120), "2m")
        self.assertEqual(_format_duration(3600), "1h")
        self.assertEqual(_format_duration(5400), "1h 30m")


class TestDashboardAPI(unittest.TestCase):
    """Tests for the Flask dashboard API endpoints."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.app = create_app(self.config)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_test_event(self, tool="fs_write", status="success", trust="green"):
        """Helper to create an event via the store."""
        store = EventStore(self.config.events_db_path)
        store.initialize()
        eid = store.write_pending(
            session_id="test_sess",
            tool=tool,
            tool_class="actuator",
            target="/workspace/test.txt",
            target_canonical="/workspace/test.txt",
            parameters=None,
            session_tainted=False,
            trust_state=trust,
        )
        store.complete_event(eid, EventStatus(status))
        store.close()
        return eid

    def test_index_returns_html(self):
        """Root route returns the dashboard HTML."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"UNWIND", resp.data)
        self.assertIn(b"Trust Dashboard", resp.data)

    def test_trust_state_api(self):
        """Trust state API returns correct structure."""
        resp = self.client.get("/api/trust-state")
        data = json.loads(resp.data)
        self.assertIn("trust_state", data)
        self.assertIn("last_hour", data)
        self.assertIn("total", data["last_hour"])

    def test_events_api_empty(self):
        """Events API returns empty list when no events."""
        resp = self.client.get("/api/events")
        data = json.loads(resp.data)
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["events"], [])

    def test_events_api_with_data(self):
        """Events API returns events after creation."""
        self._create_test_event()
        resp = self.client.get("/api/events")
        data = json.loads(resp.data)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["events"][0]["tool"], "fs_write")

    def test_events_api_limit(self):
        """Events API respects limit parameter."""
        for _ in range(5):
            self._create_test_event()
        resp = self.client.get("/api/events?limit=3")
        data = json.loads(resp.data)
        self.assertEqual(data["count"], 3)

    def test_verify_api(self):
        """Verify API returns chain integrity status."""
        self._create_test_event()
        resp = self.client.get("/api/verify")
        data = json.loads(resp.data)
        self.assertTrue(data["valid"])
        self.assertIsNone(data["error"])

    def test_away_summary_api(self):
        """Away summary API returns structured data."""
        self._create_test_event("send_email")
        self._create_test_event("fs_write")
        resp = self.client.get(f"/api/away-summary?since={time.time() - 60}")
        data = json.loads(resp.data)
        self.assertEqual(data["total_actions"], 2)
        self.assertEqual(data["emails_sent"], 1)

    def test_sessions_api(self):
        """Sessions API returns session list."""
        self._create_test_event()
        resp = self.client.get("/api/sessions")
        data = json.loads(resp.data)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["sessions"][0]["session_id"], "test_sess")

    def test_snapshots_api_empty(self):
        """Snapshots API returns empty when none exist."""
        resp = self.client.get("/api/snapshots")
        data = json.loads(resp.data)
        self.assertEqual(data["count"], 0)

    def test_undo_last_no_snapshots(self):
        """Undo last returns 404 when no snapshots."""
        resp = self.client.post("/api/undo/last", json={})
        self.assertEqual(resp.status_code, 404)

    def test_undo_event_not_found(self):
        """Undo specific event returns 404 when not found."""
        resp = self.client.post("/api/undo/evt_nonexistent", json={})
        self.assertEqual(resp.status_code, 404)

    def test_event_detail_not_found(self):
        """Event detail returns 404 for unknown event."""
        resp = self.client.get("/api/events/evt_nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_event_detail_found(self):
        """Event detail returns event data."""
        eid = self._create_test_event()
        resp = self.client.get(f"/api/events/{eid}")
        data = json.loads(resp.data)
        self.assertIn("event", data)
        self.assertEqual(data["event"]["tool"], "fs_write")

    def test_trust_state_reflects_red(self):
        """Trust state API reflects red events."""
        self._create_test_event("bash_exec", status="blocked", trust="red")
        resp = self.client.get("/api/trust-state")
        data = json.loads(resp.data)
        self.assertEqual(data["trust_state"], "red")
        self.assertEqual(data["last_hour"]["blocked"], 1)


if __name__ == "__main__":
    unittest.main()
