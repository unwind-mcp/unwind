"""Tests for Cadence storage — pulse.jsonl, state.env, profile.md."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cadence.engine.rhythm import (
    RhythmEngine,
    StateResult,
    TemporalState,
    TimeBin,
)
from cadence.protocol.crip import (
    CRIP_EVENT_CONSENT_CHANGED,
    CRIP_EVENT_DATA_DELETED,
    CRIP_EVENT_DATA_RESET,
    CRIPHeaders,
    ConsentScope,
    RetentionPolicy,
)
from cadence.storage.pulse import PulseLog
from cadence.storage.state import StateFile
from cadence.storage.profile import ProfileWriter


class TestPulseLog(unittest.TestCase):
    """Test pulse.jsonl append-only rhythm event store."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pulse_path = Path(self.tmpdir) / "cadence" / "pulse.jsonl"
        self.pulse = PulseLog(self.pulse_path)

    def test_write_event_creates_file(self):
        self.assertFalse(self.pulse_path.exists())
        self.pulse.write_event("in", 42, None)
        self.assertTrue(self.pulse_path.exists())

    def test_write_event_appends(self):
        self.pulse.write_event("in", 42, None)
        self.pulse.write_event("out", 200, None)
        events = self.pulse.read_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["direction"], "in")
        self.assertEqual(events[1]["direction"], "out")

    def test_crip_headers_on_every_write(self):
        """CRIP contract: every event has consent headers."""
        self.pulse.write_event("in", 42, None)
        events = self.pulse.read_events()
        self.assertEqual(len(events), 1)
        self.assertIn("consent_scope", events[0])
        self.assertIn("crip_version", events[0])
        self.assertEqual(events[0]["consent_scope"], "local_only")
        self.assertEqual(events[0]["crip_version"], "v1")

    def test_custom_crip_headers(self):
        crip = CRIPHeaders(consent_scope=ConsentScope.PRIVATE_CLOUD)
        pulse = PulseLog(self.pulse_path, crip=crip)
        pulse.write_event("in", 42, None)
        events = pulse.read_events()
        self.assertEqual(events[0]["consent_scope"], "private_cloud")

    def test_write_with_state_result(self):
        result = StateResult(
            state=TemporalState.READING,
            confidence=0.85,
            ert_seconds=360.0,
            anomaly_score=0.12,
            bin=TimeBin.MORNING,
            gap_seconds=300.0,
        )
        self.pulse.write_event("in", 42, result)
        events = self.pulse.read_events()
        self.assertEqual(events[0]["inferred_state"], "READING")
        self.assertEqual(events[0]["confidence"], 0.85)
        self.assertEqual(events[0]["ert_seconds"], 360.0)

    def test_write_taint_clear(self):
        event = self.pulse.write_taint_clear()
        self.assertEqual(event["event_type"], "TAINT_CLEAR")
        self.assertNotIn("direction", event)  # system events don't use direction
        self.assertIn("consent_scope", event)

    def test_write_system_event(self):
        event = self.pulse.write_system_event(
            CRIP_EVENT_CONSENT_CHANGED,
            {"old": "local_only", "new": "private_cloud"},
        )
        self.assertEqual(event["event_type"], "CONSENT_CHANGED")
        self.assertIn("details", event)
        self.assertNotIn("direction", event)

    def test_forget_before(self):
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        for i in range(5):
            t = base + timedelta(hours=i)
            self.pulse.write_event("in", 10, None, timestamp=t)

        # Forget events before hour 3
        cutoff = base + timedelta(hours=3)
        removed = self.pulse.forget_before(cutoff)
        self.assertEqual(removed, 3)

        events = self.pulse.read_events()
        # 2 kept + 1 DATA_DELETED system event
        kept_real = [e for e in events if "event_type" not in e]
        self.assertEqual(len(kept_real), 2)

    def test_reset(self):
        for i in range(5):
            self.pulse.write_event("in", 10, None)
        count = self.pulse.reset()
        self.assertEqual(count, 5)
        # After reset, only the DATA_RESET system event remains
        events = self.pulse.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "DATA_RESET")

    def test_read_limit(self):
        for i in range(10):
            self.pulse.write_event("in", i, None)
        events = self.pulse.read_events(limit=3)
        self.assertEqual(len(events), 3)
        # Should be the last 3
        self.assertEqual(events[0]["token_count"], 7)

    def test_event_count(self):
        self.assertEqual(self.pulse.event_count(), 0)
        for i in range(5):
            self.pulse.write_event("in", 10, None)
        self.assertEqual(self.pulse.event_count(), 5)

    def test_timestamp_always_utc_z(self):
        """Timestamps must always end with Z, never +00:00."""
        self.pulse.write_event("in", 42, None)
        events = self.pulse.read_events()
        self.assertTrue(events[0]["timestamp"].endswith("Z"))
        self.assertNotIn("+00:00", events[0]["timestamp"])

    def test_session_id_optional(self):
        """session_id included when set, absent when not."""
        # Default: no session_id
        self.pulse.write_event("in", 10, None)
        events = self.pulse.read_events()
        self.assertNotIn("session_id", events[0])

        # With session_id
        pulse2 = PulseLog(self.pulse_path, session_id="sess-abc123")
        pulse2.write_event("in", 10, None)
        events = self.pulse.read_events()
        self.assertEqual(events[-1]["session_id"], "sess-abc123")

    def test_source_optional(self):
        """source included when set, absent when not."""
        # Default: no source
        self.pulse.write_event("in", 10, None)
        events = self.pulse.read_events()
        self.assertNotIn("source", events[0])

        # With source
        pulse2 = PulseLog(self.pulse_path, source="openclaw")
        pulse2.write_event("in", 10, None)
        events = self.pulse.read_events()
        self.assertEqual(events[-1]["source"], "openclaw")

    def test_system_event_has_no_direction(self):
        """System events use event_type, never direction."""
        event = self.pulse.write_system_event("TEST_EVENT")
        self.assertIn("event_type", event)
        self.assertNotIn("direction", event)

    def test_interaction_event_has_no_event_type(self):
        """Interaction events use direction, never event_type."""
        event = self.pulse.write_event("in", 42, None)
        self.assertIn("direction", event)
        self.assertNotIn("event_type", event)


class TestStateFile(unittest.TestCase):
    """Test state.env atomic write/read."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_path = Path(self.tmpdir) / "cadence" / "state.env"
        self.state = StateFile(self.state_path)

    def test_write_creates_file(self):
        self.assertFalse(self.state_path.exists())
        self.state.write(None)
        self.assertTrue(self.state_path.exists())

    def test_write_default_state(self):
        self.state.write(None)
        content = self.state.read()
        self.assertEqual(content["USER_STATE"], "FLOW")
        self.assertEqual(content["CONSENT"], "local_only")
        self.assertEqual(content["RETENTION"], "rolling_7d")
        self.assertEqual(content["AUDIT"], "v1")

    def test_write_with_state_result(self):
        result = StateResult(
            state=TemporalState.AWAY,
            confidence=0.92,
            ert_seconds=600.0,
            anomaly_score=0.87,
            bin=TimeBin.EVENING,
            gap_seconds=1800.0,
        )
        self.state.write(result, last_direction="out", last_tokens=500)
        content = self.state.read()
        self.assertEqual(content["USER_STATE"], "AWAY")
        self.assertEqual(content["ANOMALY_SCORE"], "0.8700")
        self.assertEqual(content["ERT_SECONDS"], "600")
        self.assertEqual(content["LAST_DIRECTION"], "out")
        self.assertEqual(content["LAST_TOKENS"], "500")

    def test_atomic_write_no_partial_reads(self):
        """Write should be atomic — no temp file left behind."""
        self.state.write(None)
        tmp_path = self.state_path.with_suffix(".env.tmp")
        self.assertFalse(tmp_path.exists())
        self.assertTrue(self.state_path.exists())

    def test_read_nonexistent_returns_none(self):
        self.assertIsNone(self.state.read())

    def test_read_user_state(self):
        self.state.write(None)
        self.assertEqual(self.state.read_user_state(), "FLOW")

    def test_read_user_state_nonexistent(self):
        self.assertIsNone(self.state.read_user_state())

    def test_clear(self):
        self.state.write(None)
        self.assertTrue(self.state_path.exists())
        self.state.clear()
        self.assertFalse(self.state_path.exists())

    def test_shell_sourceable(self):
        """state.env should be source-able by shell."""
        self.state.write(None, last_direction="in", last_tokens=42)
        with open(self.state_path) as f:
            content = f.read()
        # Every line should be KEY=VALUE
        for line in content.strip().split("\n"):
            self.assertIn("=", line)
            key, _, value = line.partition("=")
            self.assertTrue(key.strip())
            self.assertTrue(value.strip())


class TestProfileWriter(unittest.TestCase):
    """Test profile.md rhythm summary."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.profile_path = Path(self.tmpdir) / "cadence" / "profile.md"
        self.writer = ProfileWriter(self.profile_path)

    def test_update_creates_file(self):
        engine = RhythmEngine()
        self.assertFalse(self.profile_path.exists())
        self.writer.update(engine)
        self.assertTrue(self.profile_path.exists())

    def test_update_contains_all_bins(self):
        engine = RhythmEngine()
        self.writer.update(engine)
        content = self.profile_path.read_text()
        self.assertIn("Morning", content)
        self.assertIn("Afternoon", content)
        self.assertIn("Evening", content)
        self.assertIn("Night", content)

    def test_update_shows_no_data(self):
        engine = RhythmEngine()
        self.writer.update(engine)
        content = self.profile_path.read_text()
        self.assertIn("no data yet", content)

    def test_update_shows_observations(self):
        engine = RhythmEngine()
        base = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
        engine.record_event("out", 50, timestamp=base)
        for i in range(6):
            t = base + timedelta(seconds=300 * (i + 1))
            engine.record_event("in", 10, timestamp=t)
            engine.record_event("out", 50, timestamp=t + timedelta(seconds=5))

        self.writer.update(engine)
        content = self.profile_path.read_text()
        self.assertIn("observations", content)
        self.assertIn("confident", content)

    def test_archived_thread(self):
        engine = RhythmEngine()
        self.writer.update(engine)
        self.writer.add_archived_thread("2026-02-26", "Kitchen app — CSS grid discussion")
        content = self.profile_path.read_text()
        self.assertIn("Archived Threads", content)
        self.assertIn("Kitchen app", content)

    def test_archived_threads_preserved_on_update(self):
        engine = RhythmEngine()
        self.writer.update(engine)
        self.writer.add_archived_thread("2026-02-26", "Old thread")
        # Update again — archived section should survive
        self.writer.update(engine)
        content = self.profile_path.read_text()
        self.assertIn("Old thread", content)


if __name__ == "__main__":
    unittest.main()
