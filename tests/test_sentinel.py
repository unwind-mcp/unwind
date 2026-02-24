"""Tests for SENTINEL task runner and all task implementations.

All tasks are tested in dry_run mode (no network calls).
Tests verify: task registration, execution, result structure,
finding generation, state persistence, report generation, and CLI.
"""

import json
import tempfile
import unittest
from pathlib import Path

from sentinel.runner import (
    SentinelRunner, TaskContext, TaskResult, TaskStatus,
    Finding, Severity, RegisteredTask,
)
from sentinel.tasks.cve_watcher import cve_watcher
from sentinel.tasks.mcp_spec_tracker import mcp_spec_tracker
from sentinel.tasks.safety_news import safety_news
from sentinel.tasks.test_runner import run_tests
from sentinel.cli import create_runner


class TestFinding(unittest.TestCase):
    """Tests for Finding dataclass."""

    def test_create_finding(self):
        f = Finding(
            title="Test CVE",
            severity=Severity.HIGH,
            category="cve",
            detail="A test finding",
        )
        self.assertEqual(f.title, "Test CVE")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertFalse(f.action_required)

    def test_finding_to_dict(self):
        f = Finding(
            title="Test",
            severity=Severity.CRITICAL,
            category="cve",
            action_required=True,
            action_description="Fix it",
            tags=["ssrf", "ipv6"],
        )
        d = f.to_dict()
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["tags"], ["ssrf", "ipv6"])
        self.assertTrue(d["action_required"])

    def test_finding_defaults(self):
        f = Finding(title="X", severity=Severity.INFO, category="test")
        self.assertEqual(f.detail, "")
        self.assertEqual(f.source_url, "")
        self.assertEqual(f.tags, [])


class TestTaskResult(unittest.TestCase):
    """Tests for TaskResult dataclass."""

    def test_empty_result(self):
        r = TaskResult(task_name="test", status=TaskStatus.SUCCESS)
        self.assertEqual(r.finding_count, 0)
        self.assertEqual(r.action_items, [])
        self.assertIsNone(r.highest_severity)

    def test_result_with_findings(self):
        r = TaskResult(
            task_name="test",
            status=TaskStatus.WARNING,
            findings=[
                Finding("A", Severity.LOW, "cve"),
                Finding("B", Severity.HIGH, "cve", action_required=True,
                        action_description="Fix B"),
                Finding("C", Severity.MEDIUM, "cve"),
            ],
        )
        self.assertEqual(r.finding_count, 3)
        self.assertEqual(len(r.action_items), 1)
        self.assertEqual(r.highest_severity, Severity.HIGH)

    def test_result_to_dict(self):
        r = TaskResult(
            task_name="test",
            status=TaskStatus.SUCCESS,
            summary="All good",
            duration_seconds=1.5,
        )
        d = r.to_dict()
        self.assertEqual(d["status"], "success")
        self.assertEqual(d["task_name"], "test")
        self.assertEqual(d["duration_seconds"], 1.5)


class TestTaskContext(unittest.TestCase):
    """Tests for TaskContext state management."""

    def test_state_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = TaskContext(
                task_name="test",
                data_dir=Path(tmpdir) / "data",
                reports_dir=Path(tmpdir) / "reports",
            )

            # Save state
            ctx.save_state("test.json", {"count": 42, "items": ["a", "b"]})

            # Load state
            loaded = ctx.load_state("test.json")
            self.assertEqual(loaded["count"], 42)
            self.assertEqual(loaded["items"], ["a", "b"])

    def test_load_missing_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = TaskContext(
                task_name="test",
                data_dir=Path(tmpdir) / "data",
                reports_dir=Path(tmpdir) / "reports",
            )
            result = ctx.load_state("nonexistent.json")
            self.assertEqual(result, {})

    def test_load_missing_state_with_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = TaskContext(
                task_name="test",
                data_dir=Path(tmpdir) / "data",
                reports_dir=Path(tmpdir) / "reports",
            )
            result = ctx.load_state("missing.json", default={"x": 1})
            self.assertEqual(result, {"x": 1})


class TestSentinelRunner(unittest.TestCase):
    """Tests for the task runner engine."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.runner = SentinelRunner(self.tmpdir)

    def test_register_task(self):
        self.runner.register("test_task", lambda ctx: TaskResult(
            task_name="test_task", status=TaskStatus.SUCCESS
        ), cadence="daily", description="A test")
        self.assertIn("test_task", self.runner.tasks)
        self.assertEqual(self.runner.tasks["test_task"].cadence, "daily")

    def test_run_unknown_task(self):
        result = self.runner.run_task("nonexistent")
        self.assertEqual(result.status, TaskStatus.ERROR)
        self.assertIn("Unknown task", result.error_message)

    def test_run_task_success(self):
        self.runner.register("good_task", lambda ctx: TaskResult(
            task_name="good_task", status=TaskStatus.SUCCESS, summary="OK"
        ))
        result = self.runner.run_task("good_task")
        self.assertEqual(result.status, TaskStatus.SUCCESS)
        self.assertNotEqual(result.started_at, "")
        self.assertNotEqual(result.finished_at, "")
        self.assertGreaterEqual(result.duration_seconds, 0)

    def test_run_task_exception(self):
        def bad_task(ctx):
            raise ValueError("something broke")

        self.runner.register("bad_task", bad_task)
        result = self.runner.run_task("bad_task")
        self.assertEqual(result.status, TaskStatus.ERROR)
        self.assertIn("ValueError", result.error_message)

    def test_run_cadence(self):
        self.runner.register("daily1", lambda ctx: TaskResult(
            task_name="daily1", status=TaskStatus.SUCCESS), cadence="daily")
        self.runner.register("daily2", lambda ctx: TaskResult(
            task_name="daily2", status=TaskStatus.SUCCESS), cadence="daily")
        self.runner.register("weekly1", lambda ctx: TaskResult(
            task_name="weekly1", status=TaskStatus.SUCCESS), cadence="weekly")

        results = self.runner.run_cadence("daily")
        self.assertEqual(len(results), 2)

        results = self.runner.run_cadence("weekly")
        self.assertEqual(len(results), 1)

    def test_run_all(self):
        for i in range(3):
            self.runner.register(f"task{i}", lambda ctx: TaskResult(
                task_name=ctx.task_name, status=TaskStatus.SUCCESS), cadence="daily")
        results = self.runner.run_all()
        self.assertEqual(len(results), 3)

    def test_generate_report(self):
        self.runner.register("test", lambda ctx: TaskResult(
            task_name="test", status=TaskStatus.SUCCESS, summary="All good"))
        self.runner.run_task("test")
        report = self.runner.generate_report()
        self.assertIn("SENTINEL REPORT", report)
        self.assertIn("test", report)
        self.assertIn("All good", report)

    def test_generate_report_with_findings(self):
        def task_with_findings(ctx):
            return TaskResult(
                task_name="finder",
                status=TaskStatus.WARNING,
                findings=[
                    Finding("CVE Found", Severity.HIGH, "cve",
                            action_required=True, action_description="Fix it"),
                ],
            )

        self.runner.register("finder", task_with_findings)
        self.runner.run_task("finder")
        report = self.runner.generate_report()
        self.assertIn("CVE Found", report)
        self.assertIn("ACTION", report)

    def test_export_json(self):
        self.runner.register("test", lambda ctx: TaskResult(
            task_name="test", status=TaskStatus.SUCCESS))
        self.runner.run_task("test")
        json_str = self.runner.export_json()
        data = json.loads(json_str)
        self.assertEqual(data["task_count"], 1)
        self.assertEqual(data["results"][0]["status"], "success")

    def test_save_report_creates_files(self):
        self.runner.register("test", lambda ctx: TaskResult(
            task_name="test", status=TaskStatus.SUCCESS))
        self.runner.run_task("test")
        text_path, json_path = self.runner.save_report()
        self.assertTrue(text_path.exists())
        self.assertTrue(json_path.exists())

    def test_empty_report(self):
        report = self.runner.generate_report()
        self.assertIn("No tasks", report)


class TestCVEWatcher(unittest.TestCase):
    """Tests for CVE watcher task in dry_run mode."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ctx = TaskContext(
            task_name="cve_watcher",
            data_dir=Path(self.tmpdir) / "data",
            reports_dir=Path(self.tmpdir) / "reports",
            dry_run=True,
        )

    def test_dry_run_returns_findings(self):
        result = cve_watcher(self.ctx)
        self.assertEqual(result.task_name, "cve_watcher")
        self.assertEqual(result.status, TaskStatus.WARNING)
        self.assertGreater(result.finding_count, 0)

    def test_dry_run_findings_have_required_fields(self):
        result = cve_watcher(self.ctx)
        for finding in result.findings:
            self.assertIsInstance(finding.title, str)
            self.assertIsInstance(finding.severity, Severity)
            self.assertIsInstance(finding.category, str)
            self.assertNotEqual(finding.title, "")
            self.assertNotEqual(finding.category, "")

    def test_dry_run_has_action_items(self):
        result = cve_watcher(self.ctx)
        self.assertGreater(len(result.action_items), 0)

    def test_dry_run_categories(self):
        result = cve_watcher(self.ctx)
        categories = {f.category for f in result.findings}
        # Should have findings from multiple sources
        self.assertTrue(len(categories) >= 2)


class TestMCPSpecTracker(unittest.TestCase):
    """Tests for MCP spec tracker in dry_run mode."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ctx = TaskContext(
            task_name="mcp_spec_tracker",
            data_dir=Path(self.tmpdir) / "data",
            reports_dir=Path(self.tmpdir) / "reports",
            dry_run=True,
        )

    def test_dry_run_returns_findings(self):
        result = mcp_spec_tracker(self.ctx)
        self.assertIn(result.status, (TaskStatus.SUCCESS, TaskStatus.WARNING))
        self.assertGreater(result.finding_count, 0)

    def test_dry_run_finding_structure(self):
        result = mcp_spec_tracker(self.ctx)
        for finding in result.findings:
            self.assertIn(finding.category, ("mcp-spec", "mcp-sdk"))
            self.assertIn("mcp", finding.tags)

    def test_dry_run_has_spec_and_sdk_findings(self):
        result = mcp_spec_tracker(self.ctx)
        categories = {f.category for f in result.findings}
        self.assertIn("mcp-spec", categories)
        self.assertIn("mcp-sdk", categories)


class TestSafetyNews(unittest.TestCase):
    """Tests for AI safety news digest in dry_run mode."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ctx = TaskContext(
            task_name="safety_news",
            data_dir=Path(self.tmpdir) / "data",
            reports_dir=Path(self.tmpdir) / "reports",
            dry_run=True,
        )

    def test_dry_run_returns_findings(self):
        result = safety_news(self.ctx)
        self.assertGreater(result.finding_count, 0)

    def test_dry_run_finding_categories(self):
        result = safety_news(self.ctx)
        categories = {f.category for f in result.findings}
        self.assertIn("ai-safety", categories)

    def test_dry_run_has_multiple_sources(self):
        result = safety_news(self.ctx)
        # Should have findings from repos, arxiv, and HN
        tags = set()
        for f in result.findings:
            tags.update(f.tags)
        self.assertTrue(len(tags) >= 3)


class TestTestRunner(unittest.TestCase):
    """Tests for the test runner task in dry_run mode."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ctx = TaskContext(
            task_name="test_runner",
            data_dir=Path(self.tmpdir) / "data",
            reports_dir=Path(self.tmpdir) / "reports",
            dry_run=True,
        )

    def test_dry_run_returns_success(self):
        result = run_tests(self.ctx)
        self.assertEqual(result.status, TaskStatus.SUCCESS)
        self.assertIn("220", result.summary)

    def test_dry_run_has_metadata(self):
        result = run_tests(self.ctx)
        self.assertIn("passed", result.metadata)
        self.assertEqual(result.metadata["passed"], 220)
        self.assertEqual(result.metadata["failed"], 0)


class TestCreateRunner(unittest.TestCase):
    """Tests for the CLI runner factory."""

    def test_create_runner_registers_all_tasks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = create_runner(tmpdir)
            self.assertIn("cve_watcher", runner.tasks)
            self.assertIn("mcp_spec_tracker", runner.tasks)
            self.assertIn("safety_news", runner.tasks)
            self.assertIn("test_runner", runner.tasks)

    def test_all_tasks_are_daily(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = create_runner(tmpdir)
            for task in runner.tasks.values():
                self.assertEqual(task.cadence, "daily")

    def test_dry_run_all_tasks(self):
        """Integration test: run all tasks in dry_run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = create_runner(tmpdir)
            results = runner.run_all(dry_run=True)
            self.assertEqual(len(results), 4)
            for result in results:
                self.assertNotEqual(result.status, TaskStatus.ERROR,
                                    f"Task {result.task_name} failed: {result.error_message}")

    def test_full_report_generation(self):
        """Integration test: run all, generate report, export JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = create_runner(tmpdir)
            results = runner.run_all(dry_run=True)

            report = runner.generate_report(results)
            self.assertIn("SENTINEL REPORT", report)

            json_str = runner.export_json(results)
            data = json.loads(json_str)
            self.assertEqual(data["task_count"], 4)

            text_path, json_path = runner.save_report(results)
            self.assertTrue(text_path.exists())
            self.assertTrue(json_path.exists())


class TestSeverityOrdering(unittest.TestCase):
    """Test that severity comparison works correctly."""

    def test_highest_severity_is_critical(self):
        r = TaskResult(
            task_name="test",
            status=TaskStatus.WARNING,
            findings=[
                Finding("A", Severity.LOW, "test"),
                Finding("B", Severity.CRITICAL, "test"),
                Finding("C", Severity.MEDIUM, "test"),
            ],
        )
        self.assertEqual(r.highest_severity, Severity.CRITICAL)

    def test_highest_severity_single(self):
        r = TaskResult(
            task_name="test",
            status=TaskStatus.WARNING,
            findings=[Finding("A", Severity.MEDIUM, "test")],
        )
        self.assertEqual(r.highest_severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
