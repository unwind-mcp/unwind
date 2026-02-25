"""SENTINEL task runner — executes tasks and captures structured output.

Each task is a callable that returns a TaskResult. The runner handles
scheduling, error recovery, output formatting, and report generation.
"""

from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Optional


class Severity(Enum):
    """Finding severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    """Task execution status."""
    SUCCESS = "success"
    WARNING = "warning"       # Completed with findings
    ERROR = "error"           # Task failed to execute
    SKIPPED = "skipped"       # Precondition not met


@dataclass
class Finding:
    """A single discovery from a task — CVE, spec change, news item, etc."""
    title: str
    severity: Severity
    category: str                         # e.g. "cve", "mcp-spec", "ai-safety", "test-failure"
    detail: str = ""
    source_url: str = ""
    action_required: bool = False
    action_description: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class TaskResult:
    """The output of a single SENTINEL task run."""
    task_name: str
    status: TaskStatus
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    error_message: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def action_items(self) -> list[Finding]:
        return [f for f in self.findings if f.action_required]

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.findings, key=lambda f: order.index(f.severity)).severity

    def to_dict(self) -> dict:
        return {
            "task_name": self.task_name,
            "status": self.status.value,
            "summary": self.summary,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "finding_count": self.finding_count,
            "action_item_count": len(self.action_items),
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


# Type alias for task functions
TaskFn = Callable[["TaskContext"], TaskResult]


@dataclass
class TaskContext:
    """Provides context and utilities to running tasks."""
    task_name: str
    data_dir: Path                       # Where this task stores persistent state
    reports_dir: Path                    # Where reports get written
    config: dict = field(default_factory=dict)
    dry_run: bool = False                # For testing — skip network calls

    def state_path(self, filename: str) -> Path:
        """Get a path in this task's persistent state directory."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / filename

    def load_state(self, filename: str, default=None):
        """Load JSON state from a previous run."""
        path = self.state_path(filename)
        if path.exists():
            return json.loads(path.read_text())
        return default if default is not None else {}

    def save_state(self, filename: str, data) -> None:
        """Save JSON state for the next run."""
        path = self.state_path(filename)
        path.write_text(json.dumps(data, indent=2, default=str))


@dataclass
class RegisteredTask:
    """A task registered with the runner."""
    name: str
    fn: TaskFn
    cadence: str                         # "daily", "weekly", "monthly", etc.
    description: str = ""
    day_of_week: Optional[int] = None    # 0=Monday for weekly tasks
    day_of_month: Optional[int] = None   # For monthly tasks


class SentinelRunner:
    """Executes SENTINEL tasks and produces reports."""

    def __init__(self, base_dir: Path | str):
        self.base_dir = Path(base_dir)
        self.data_dir = self.base_dir / "data"
        self.reports_dir = self.base_dir / "reports"
        self.tasks: dict[str, RegisteredTask] = {}
        self._results: list[TaskResult] = []

    def register(self, name: str, fn: TaskFn, cadence: str = "daily",
                 description: str = "", **kwargs) -> None:
        """Register a task with the runner."""
        self.tasks[name] = RegisteredTask(
            name=name, fn=fn, cadence=cadence,
            description=description, **kwargs
        )

    def run_task(self, name: str, config: dict | None = None,
                 dry_run: bool = False) -> TaskResult:
        """Execute a single task by name."""
        if name not in self.tasks:
            return TaskResult(
                task_name=name,
                status=TaskStatus.ERROR,
                error_message=f"Unknown task: {name}",
            )

        task = self.tasks[name]
        ctx = TaskContext(
            task_name=name,
            data_dir=self.data_dir / name,
            reports_dir=self.reports_dir,
            config=config or {},
            dry_run=dry_run,
        )

        start = time.time()
        started_at = datetime.now(timezone.utc).isoformat()

        try:
            result = task.fn(ctx)
            result.started_at = started_at
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.duration_seconds = round(time.time() - start, 2)
        except Exception as e:
            result = TaskResult(
                task_name=name,
                status=TaskStatus.ERROR,
                error_message=f"{type(e).__name__}: {e}",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(time.time() - start, 2),
            )

        self._results.append(result)
        return result

    def run_cadence(self, cadence: str, config: dict | None = None,
                    dry_run: bool = False) -> list[TaskResult]:
        """Run all tasks registered for a given cadence."""
        results = []
        for name, task in self.tasks.items():
            if task.cadence == cadence:
                result = self.run_task(name, config=config, dry_run=dry_run)
                results.append(result)
        return results

    def run_all(self, config: dict | None = None,
                dry_run: bool = False) -> list[TaskResult]:
        """Run every registered task."""
        results = []
        for name in self.tasks:
            result = self.run_task(name, config=config, dry_run=dry_run)
            results.append(result)
        return results

    def generate_report(self, results: list[TaskResult] | None = None) -> str:
        """Generate a human-readable summary report."""
        results = results or self._results
        if not results:
            return "No tasks have been run."

        lines = [
            "=" * 60,
            "  SENTINEL REPORT",
            f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "=" * 60,
            "",
        ]

        # Summary stats
        total = len(results)
        success = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
        warnings = sum(1 for r in results if r.status == TaskStatus.WARNING)
        errors = sum(1 for r in results if r.status == TaskStatus.ERROR)
        total_findings = sum(r.finding_count for r in results)
        total_actions = sum(len(r.action_items) for r in results)
        total_duration = sum(r.duration_seconds for r in results)

        lines.append(f"  Tasks run:     {total}")
        lines.append(f"  Succeeded:     {success}")
        if warnings:
            lines.append(f"  With findings: {warnings}")
        if errors:
            lines.append(f"  Errors:        {errors}")
        lines.append(f"  Total findings: {total_findings}")
        if total_actions:
            lines.append(f"  Action items:  {total_actions}")
        lines.append(f"  Duration:      {total_duration:.1f}s")
        lines.append("")

        # Per-task detail
        for result in results:
            icon = {
                TaskStatus.SUCCESS: "✅",
                TaskStatus.WARNING: "⚠️",
                TaskStatus.ERROR: "❌",
                TaskStatus.SKIPPED: "⏭️",
            }.get(result.status, "?")

            lines.append(f"  {icon} {result.task_name} ({result.status.value})")
            if result.summary:
                lines.append(f"     {result.summary}")
            if result.error_message:
                lines.append(f"     ERROR: {result.error_message}")

            for finding in result.findings:
                sev_icon = {
                    Severity.INFO: "ℹ️",
                    Severity.LOW: "🔵",
                    Severity.MEDIUM: "🟡",
                    Severity.HIGH: "🟠",
                    Severity.CRITICAL: "🔴",
                }.get(finding.severity, "?")
                lines.append(f"     {sev_icon} [{finding.severity.value.upper()}] {finding.title}")
                if finding.action_required:
                    lines.append(f"        → ACTION: {finding.action_description}")

            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def export_json(self, results: list[TaskResult] | None = None,
                    path: Path | str | None = None) -> str:
        """Export results as JSON. Returns the JSON string."""
        results = results or self._results
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "task_count": len(results),
            "results": [r.to_dict() for r in results],
        }
        json_str = json.dumps(data, indent=2, default=str)

        if path:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str)

        return json_str

    def save_report(self, results: list[TaskResult] | None = None,
                    prefix: str = "sentinel") -> tuple[Path, Path]:
        """Save both human-readable and JSON reports to the reports directory."""
        results = results or self._results
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        text_path = self.reports_dir / f"{prefix}-{date_str}.txt"
        json_path = self.reports_dir / f"{prefix}-{date_str}.json"

        text_path.write_text(self.generate_report(results))
        self.export_json(results, json_path)

        return text_path, json_path
