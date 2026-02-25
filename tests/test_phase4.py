"""Phase 4 Tests — CR-AFT Anchoring, Conversational Interface, Export.

Test coverage:
- ChainAnchoring: anchor creation, chain export, tamper detection, external verification
- Conversational query: intent detection, time parsing, response generation
- Export: JSON, JSONL, HTML report
- Dashboard API: ask endpoint, tamper-check endpoint
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
from unwind.anchoring.chain_export import ChainAnchoring
from unwind.conversational.query import (
    process_query, _extract_intent, _extract_time_range, _extract_tool_filter,
)
from unwind.export.exporter import export_json, export_jsonl, export_html_report
from unwind.dashboard.app import create_app


class BaseTestCase(unittest.TestCase):
    """Shared setUp/tearDown for Phase 4 tests."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.store = EventStore(self.config.events_db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_event(self, tool="fs_write", tool_class="actuator",
                     status="success", tainted=False, trust="green",
                     ghost=False, target=None):
        target = target or f"/workspace/{tool}_file"
        eid = self.store.write_pending(
            session_id="test_session",
            tool=tool,
            tool_class=tool_class,
            target=target,
            target_canonical=target,
            parameters={"path": target},
            session_tainted=tainted,
            trust_state=trust,
            ghost_mode=ghost,
        )
        self.store.complete_event(eid, EventStatus(status))
        return eid


class TestChainAnchoring(BaseTestCase):
    """Tests for CR-AFT external anchoring."""

    def test_create_anchor(self):
        """Create an anchor checkpoint."""
        self._write_event()
        self._write_event("send_email")
        anchoring = ChainAnchoring(self.config)
        anchor = anchoring.create_anchor(self.store)

        self.assertEqual(anchor.event_count, 2)
        self.assertTrue(anchor.anchor_id.startswith("anchor_"))
        self.assertIsNotNone(anchor.chain_digest)
        self.assertIsNotNone(anchor.last_chain_hash)

    def test_anchor_saved_to_disk(self):
        """Anchor is persisted as JSON file."""
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        anchor = anchoring.create_anchor(self.store)

        anchor_file = anchoring.anchors_dir / f"{anchor.anchor_id}.json"
        self.assertTrue(anchor_file.exists())
        with open(anchor_file) as f:
            data = json.load(f)
        self.assertEqual(data["anchor_id"], anchor.anchor_id)

    def test_create_anchor_no_events(self):
        """Anchor creation fails gracefully with no events."""
        anchoring = ChainAnchoring(self.config)
        with self.assertRaises(ValueError):
            anchoring.create_anchor(self.store)

    def test_export_chain(self):
        """Export full chain for audit."""
        self._write_event()
        self._write_event("send_email")
        anchoring = ChainAnchoring(self.config)
        export = anchoring.export_chain(self.store)

        self.assertEqual(export.event_count, 2)
        self.assertTrue(export.chain_valid)
        self.assertIsNotNone(export.chain_digest)
        # Verify privacy: no target or parameters in export
        for e in export.events:
            self.assertNotIn("target", e)
            self.assertNotIn("parameters_hash", e)
            self.assertIn("chain_hash", e)

    def test_export_chain_to_file(self):
        """Export chain to JSON file."""
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        output = Path(self.tmpdir) / "chain_export.json"
        export = anchoring.export_chain_to_file(self.store, output)

        self.assertTrue(output.exists())
        with open(output) as f:
            data = json.load(f)
        self.assertEqual(data["event_count"], 1)

    def test_verify_external_chain(self):
        """Verify an external chain dump."""
        for _ in range(5):
            self._write_event()
        anchoring = ChainAnchoring(self.config)

        # Create anchor first
        anchoring.create_anchor(self.store)

        # Export
        export = anchoring.export_chain(self.store)
        from dataclasses import asdict
        chain_data = asdict(export)

        # Verify
        valid, error = anchoring.verify_external_chain(chain_data)
        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_verify_external_chain_tampered_digest(self):
        """Detect tampered chain digest."""
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        export = anchoring.export_chain(self.store)
        from dataclasses import asdict
        chain_data = asdict(export)
        chain_data["chain_digest"] = "tampered_digest"

        valid, error = anchoring.verify_external_chain(chain_data)
        self.assertFalse(valid)
        self.assertIn("digest mismatch", error)

    def test_tamper_detection_clean(self):
        """Tamper detection on clean chain."""
        self._write_event()
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        report = anchoring.detect_tampering(self.store)

        self.assertTrue(report["chain_valid"])
        self.assertEqual(report["event_count"], 2)
        self.assertEqual(len(report["gaps"]), 0)
        self.assertEqual(len(report["suspicious_events"]), 0)

    def test_tamper_detection_with_anchor(self):
        """Tamper detection verifies anchors."""
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        anchoring.create_anchor(self.store)
        self._write_event()

        report = anchoring.detect_tampering(self.store)
        self.assertTrue(report["chain_valid"])
        self.assertEqual(report["anchor_count"], 1)
        self.assertEqual(len(report["anchor_drift"]), 0)

    def test_get_anchors(self):
        """Load anchors from disk."""
        self._write_event()
        anchoring = ChainAnchoring(self.config)
        anchoring.create_anchor(self.store)
        self._write_event()
        anchoring.create_anchor(self.store)

        anchors = anchoring.get_anchors()
        self.assertEqual(len(anchors), 2)


class TestConversationalQuery(BaseTestCase):
    """Tests for the natural language query engine."""

    def test_intent_summary(self):
        self.assertEqual(_extract_intent("what did you do today?"), "summary")
        self.assertEqual(_extract_intent("show me what happened"), "summary")

    def test_intent_blocked(self):
        self.assertEqual(_extract_intent("show me blocked actions"), "blocked")

    def test_intent_security(self):
        self.assertEqual(_extract_intent("any security issues?"), "security")

    def test_intent_count(self):
        self.assertEqual(_extract_intent("how many emails were sent?"), "count")

    def test_intent_status(self):
        self.assertEqual(_extract_intent("what is the current status?"), "status")

    def test_intent_ghost(self):
        self.assertEqual(_extract_intent("show ghost mode actions"), "ghost")

    def test_intent_undo(self):
        self.assertEqual(_extract_intent("what can I undo?"), "undo_info")

    def test_time_range_today(self):
        start, end = _extract_time_range("what happened today")
        self.assertIsNotNone(start)
        self.assertIsNotNone(end)
        # Start should be today at midnight
        self.assertGreater(end, start)

    def test_time_range_last_hour(self):
        start, end = _extract_time_range("show me the last hour")
        self.assertIsNotNone(start)
        now = time.time()
        self.assertAlmostEqual(start, now - 3600, delta=5)

    def test_time_range_last_n_hours(self):
        start, end = _extract_time_range("events in the last 3 hours")
        self.assertIsNotNone(start)
        now = time.time()
        self.assertAlmostEqual(start, now - 10800, delta=5)

    def test_tool_filter_emails(self):
        tools = _extract_tool_filter("how many emails")
        self.assertIn("send_email", tools)
        self.assertIn("read_email", tools)

    def test_tool_filter_files(self):
        tools = _extract_tool_filter("show file operations")
        self.assertIn("fs_write", tools)

    def test_tool_filter_none(self):
        tools = _extract_tool_filter("what happened?")
        self.assertIsNone(tools)

    def test_query_no_events(self):
        """Query with no events returns appropriate message."""
        response = process_query("what happened today?", self.config)
        self.assertIn("No events", response)

    def test_query_with_events(self):
        """Query with events returns summary."""
        self._write_event("send_email")
        self._write_event("fs_write")
        response = process_query("what happened today?", self.config)
        self.assertIn("action(s)", response)

    def test_query_blocked(self):
        """Blocked query filters correctly."""
        self._write_event("bash_exec", status="blocked", trust="red")
        self._write_event("fs_write")
        response = process_query("show blocked actions", self.config)
        self.assertIn("blocked", response.lower())

    def test_query_status(self):
        """Status query returns trust state."""
        self._write_event()
        response = process_query("what is the status?", self.config)
        self.assertIn("trust state", response.lower())

    def test_query_count_emails(self):
        """Count query for emails."""
        self._write_event("send_email")
        self._write_event("send_email")
        self._write_event("fs_write")
        response = process_query("how many emails?", self.config)
        self.assertIn("2", response)

    def test_query_security(self):
        """Security query reports issues."""
        self._write_event("bash_exec", status="blocked", trust="red")
        response = process_query("any security issues?", self.config)
        self.assertIn("RED", response)


class TestExport(BaseTestCase):
    """Tests for the export system."""

    def test_export_json(self):
        """Export events as JSON."""
        self._write_event("send_email")
        self._write_event("fs_write")
        output = Path(self.tmpdir) / "export.json"
        count = export_json(self.store, output)

        self.assertEqual(count, 2)
        self.assertTrue(output.exists())
        with open(output) as f:
            data = json.load(f)
        self.assertEqual(data["event_count"], 2)
        self.assertIn("chain_valid", data)
        self.assertEqual(len(data["events"]), 2)

    def test_export_json_filtered(self):
        """Export with session filter."""
        self._write_event()
        output = Path(self.tmpdir) / "filtered.json"
        count = export_json(self.store, output, session_id="test_session")
        self.assertEqual(count, 1)

    def test_export_jsonl(self):
        """Export events as JSONL."""
        self._write_event()
        self._write_event("send_email")
        output = Path(self.tmpdir) / "export.jsonl"
        count = export_jsonl(self.store, output)

        self.assertEqual(count, 2)
        with open(output) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        # Each line is valid JSON
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("event_id", parsed)

    def test_export_html(self):
        """Export events as HTML report."""
        self._write_event("send_email")
        self._write_event("bash_exec", status="blocked", trust="red")
        output = Path(self.tmpdir) / "report.html"
        count = export_html_report(self.store, output)

        self.assertEqual(count, 2)
        self.assertTrue(output.exists())
        with open(output) as f:
            html = f.read()
        self.assertIn("UNWIND Audit Report", html)
        self.assertIn("send_email", html)
        self.assertTrue("BROKEN" in html or "VALID" in html)

    def test_export_html_with_title(self):
        """Export HTML with custom title."""
        self._write_event()
        output = Path(self.tmpdir) / "custom.html"
        export_html_report(self.store, output, title="Custom Report")
        with open(output) as f:
            html = f.read()
        self.assertIn("Custom Report", html)

    def test_export_empty(self):
        """Export with no events produces empty output."""
        output = Path(self.tmpdir) / "empty.json"
        count = export_json(self.store, output)
        self.assertEqual(count, 0)


class TestDashboardPhase4API(BaseTestCase):
    """Tests for Phase 4 dashboard API endpoints."""

    def setUp(self):
        super().setUp()
        self.app = create_app(self.config)
        self.app.testing = True
        self.client = self.app.test_client()

    def test_ask_endpoint(self):
        """Conversational ask endpoint works."""
        self._write_event("send_email")
        resp = self.client.get("/api/ask?q=what+happened+today")
        data = json.loads(resp.data)
        self.assertIn("response", data)
        self.assertIn("question", data)

    def test_ask_endpoint_missing_query(self):
        """Ask endpoint returns 400 without query."""
        resp = self.client.get("/api/ask")
        self.assertEqual(resp.status_code, 400)

    def test_tamper_check_endpoint(self):
        """Tamper check endpoint returns report."""
        self._write_event()
        resp = self.client.get("/api/tamper-check")
        data = json.loads(resp.data)
        self.assertIn("chain_valid", data)
        self.assertIn("event_count", data)
        self.assertTrue(data["chain_valid"])


if __name__ == "__main__":
    unittest.main()
