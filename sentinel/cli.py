"""SENTINEL CLI — run maintenance tasks from the command line.

Usage:
    sentinel daily                Run all daily tasks
    sentinel weekly               Run all weekly tasks
    sentinel run cve_watcher      Run a specific task
    sentinel run --all            Run every registered task
    sentinel list                 List all registered tasks

Options:
    --dry-run                     Use mock data (no network calls)
    --json                        Output as JSON instead of human-readable
    --data-dir DIR                Override the data directory
    --report-dir DIR              Override the report directory
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel.runner import SentinelRunner
from sentinel.tasks.cve_watcher import cve_watcher
from sentinel.tasks.mcp_spec_tracker import mcp_spec_tracker
from sentinel.tasks.safety_news import safety_news
from sentinel.tasks.test_runner import run_tests


def create_runner(base_dir: Path | str | None = None) -> SentinelRunner:
    """Create a runner with all tasks registered."""
    if base_dir is None:
        # Default to ~/.sentinel
        base_dir = Path.home() / ".sentinel"

    runner = SentinelRunner(base_dir)

    # Daily tasks
    runner.register("cve_watcher", cve_watcher, cadence="daily",
                    description="Monitor NVD, GitHub advisories, and OpenClaw for CVEs")
    runner.register("mcp_spec_tracker", mcp_spec_tracker, cadence="daily",
                    description="Track MCP spec changes and SDK releases")
    runner.register("safety_news", safety_news, cadence="daily",
                    description="AI safety news digest from arXiv, HN, and GitHub")
    runner.register("test_runner", run_tests, cadence="daily",
                    description="Run UNWIND and Ghost Mode test suites")

    return runner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — UNWIND maintenance agent task runner",
    )
    parser.add_argument("command", choices=["daily", "weekly", "monthly", "run", "list"],
                        help="Command to execute")
    parser.add_argument("task_name", nargs="?", default=None,
                        help="Task name (for 'run' command)")
    parser.add_argument("--all", action="store_true",
                        help="Run all tasks (for 'run' command)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Use mock data, no network calls")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--data-dir", type=str, default=None,
                        help="Override data directory")
    parser.add_argument("--report-dir", type=str, default=None,
                        help="Override report directory")
    parser.add_argument("--project-dir", type=str, default=None,
                        help="UNWIND project directory (for test_runner)")

    args = parser.parse_args(argv)

    # Create runner
    base_dir = Path(args.data_dir) if args.data_dir else None
    runner = create_runner(base_dir)

    if args.report_dir:
        runner.reports_dir = Path(args.report_dir)

    config = {}
    if args.project_dir:
        config["project_dir"] = args.project_dir

    # Execute command
    if args.command == "list":
        for name, task in runner.tasks.items():
            print(f"  {name:25s} [{task.cadence:8s}]  {task.description}")
        return 0

    if args.command == "run":
        if args.all:
            results = runner.run_all(config=config, dry_run=args.dry_run)
        elif args.task_name:
            result = runner.run_task(args.task_name, config=config, dry_run=args.dry_run)
            results = [result]
        else:
            print("Error: specify a task name or --all", file=sys.stderr)
            return 1
    else:
        # Cadence-based execution
        results = runner.run_cadence(args.command, config=config, dry_run=args.dry_run)

    # Output
    if args.json:
        print(runner.export_json(results))
    else:
        print(runner.generate_report(results))

    # Save reports
    runner.save_report(results, prefix=f"sentinel-{args.command}")

    # Return non-zero if any task failed
    from sentinel.runner import TaskStatus
    if any(r.status == TaskStatus.ERROR for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
