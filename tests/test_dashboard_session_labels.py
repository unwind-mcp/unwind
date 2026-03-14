"""Dashboard event enrichment: approval UX + scheduled task labels."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from unwind.config import UnwindConfig
from unwind.dashboard.app import create_app
from unwind.recorder.event_store import EventStore, EventStatus


class TestDashboardEventEnrichment(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_event(
        self,
        *,
        session_id: str,
        status: EventStatus = EventStatus.SUCCESS,
        trust_state: str = "green",
        result_summary: str = "OK (sidecar)",
    ) -> str:
        store = EventStore(self.config.events_db_path)
        store.initialize()
        event_id = store.write_pending(
            session_id=session_id,
            tool="exec",
            tool_class="actuator",
            target="",
            target_canonical="",
            parameters=None,
            session_tainted=False,
            trust_state=trust_state,
        )
        store.complete_event(event_id, status=status, result_summary=result_summary)
        store.close()
        return event_id

    def test_api_events_resolves_scheduled_job_name_from_openclaw_registry(self):
        cron_jobs_path = Path(self.tmpdir) / "jobs.json"
        cron_jobs_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "jobs": [
                        {
                            "id": "job-123",
                            "name": "sentinel:eng-coverage",
                        }
                    ],
                }
            )
        )

        self._write_event(session_id="agent:main:cron:job-123")

        with patch.dict(os.environ, {"UNWIND_DASHBOARD_CRON_JOBS_PATH": str(cron_jobs_path)}):
            app = create_app(self.config)
            app.testing = True
            client = app.test_client()
            resp = client.get("/api/events")

        self.assertEqual(resp.status_code, 200)
        body = json.loads(resp.data)
        self.assertEqual(body["count"], 1)
        ev = body["events"][0]
        self.assertEqual(ev["session_source"], "scheduled")
        self.assertEqual(ev["scheduled_job_id"], "job-123")
        self.assertEqual(ev["scheduled_job_name"], "sentinel:eng-coverage")
        self.assertEqual(ev["session_source_short"], "sentinel:eng-coverage")

    def test_api_events_flags_approval_required_for_amber_challenge(self):
        self._write_event(
            session_id="agent:main:cron:job-unknown",
            status=EventStatus.BLOCKED,
            trust_state="amber",
            result_summary="AMBER: Review before execution",
        )

        app = create_app(self.config)
        app.testing = True
        client = app.test_client()
        resp = client.get("/api/events")
        self.assertEqual(resp.status_code, 200)

        body = json.loads(resp.data)
        ev = body["events"][0]
        self.assertTrue(ev["approval_required"])
        self.assertEqual(ev["session_source"], "scheduled")
        self.assertEqual(ev["session_source_short"], "scheduled")


if __name__ == "__main__":
    unittest.main()
