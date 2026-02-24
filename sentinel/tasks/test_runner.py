"""UNWIND & Ghost Mode Test Runner — SENTINEL daily task.

Runs the full test suite for both packages, captures results,
detects regressions, and tracks test count over time.

This is the CI health check from the SENTINEL runbook,
adapted to run as a scheduled task on the remote server.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sentinel.runner import (
    TaskContext, TaskResult, TaskStatus, Finding, Severity,
)


def _run_pytest(project_dir: Path, timeout: int = 300) -> dict:
    """Run pytest and capture structured results.

    Returns dict with: passed, failed, errors, total, duration,
    output (stdout+stderr), returncode.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-q"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = result.stdout + result.stderr

        # Parse pytest summary line: "X passed, Y failed in Z.ZZs"
        passed = failed = errors = 0
        duration = 0.0

        for line in output.split("\n"):
            line_stripped = line.strip()
            if "passed" in line_stripped or "failed" in line_stripped or "error" in line_stripped:
                # Look for patterns like "220 passed in 3.63s"
                import re
                p = re.search(r'(\d+) passed', line_stripped)
                f = re.search(r'(\d+) failed', line_stripped)
                e = re.search(r'(\d+) error', line_stripped)
                d = re.search(r'in ([\d.]+)s', line_stripped)
                if p:
                    passed = int(p.group(1))
                if f:
                    failed = int(f.group(1))
                if e:
                    errors = int(e.group(1))
                if d:
                    duration = float(d.group(1))

        return {
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "total": passed + failed + errors,
            "duration": duration,
            "output": output[-2000:],  # Last 2000 chars to keep report manageable
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "passed": 0, "failed": 0, "errors": 0, "total": 0,
            "duration": timeout, "output": "TIMEOUT: Test suite exceeded time limit",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "passed": 0, "failed": 0, "errors": 0, "total": 0,
            "duration": 0, "output": "ERROR: pytest not found",
            "returncode": -1,
        }


def run_tests(ctx: TaskContext) -> TaskResult:
    """Run UNWIND and Ghost Mode test suites, detect regressions."""
    findings = []

    # Determine project directory
    project_dir = ctx.config.get("project_dir", "")
    if not project_dir:
        # Default: assume we're in the UNWIND repo
        # Walk up from sentinel/ to find project root
        candidate = Path(__file__).parent.parent.parent
        if (candidate / "tests").exists():
            project_dir = str(candidate)
        else:
            return TaskResult(
                task_name="test_runner",
                status=TaskStatus.ERROR,
                error_message="Cannot find project directory. Set config['project_dir'].",
            )

    project_path = Path(project_dir)

    if ctx.dry_run:
        # Return mock results
        return TaskResult(
            task_name="test_runner",
            status=TaskStatus.SUCCESS,
            findings=[
                Finding(
                    title="Test suite: 220 passed, 0 failed (3.5s)",
                    severity=Severity.INFO,
                    category="test-result",
                    detail="All tests passing. No regressions detected.",
                    tags=["tests", "ci"],
                ),
            ],
            summary="220 tests passed, 0 failed (3.5s)",
            metadata={"passed": 220, "failed": 0, "duration": 3.5},
        )

    # Run the actual test suite
    results = _run_pytest(project_path)

    # Load previous run for regression detection
    prev = ctx.load_state("last_run.json", {
        "passed": 0, "failed": 0, "total": 0,
    })

    passed = results["passed"]
    failed = results["failed"]
    errors = results["errors"]
    total = results["total"]
    duration = results["duration"]
    prev_total = prev.get("total", 0)
    prev_passed = prev.get("passed", 0)

    # Main result finding
    if failed == 0 and errors == 0:
        findings.append(Finding(
            title=f"Test suite: {passed} passed, 0 failed ({duration:.1f}s)",
            severity=Severity.INFO,
            category="test-result",
            detail="All tests passing.",
            tags=["tests", "ci"],
        ))
    else:
        findings.append(Finding(
            title=f"Test suite: {passed} passed, {failed} failed, {errors} error(s) ({duration:.1f}s)",
            severity=Severity.HIGH if failed > 0 else Severity.MEDIUM,
            category="test-result",
            detail=results["output"][-500:],
            action_required=True,
            action_description="Fix failing tests before next release",
            tags=["tests", "ci", "regression"],
        ))

    # Regression detection
    if prev_total > 0:
        if total < prev_total:
            findings.append(Finding(
                title=f"Test count decreased: {prev_total} → {total} ({prev_total - total} removed)",
                severity=Severity.MEDIUM,
                category="test-regression",
                detail="Tests may have been accidentally deleted or disabled.",
                action_required=True,
                action_description="Verify test removal was intentional",
                tags=["tests", "regression"],
            ))

        if passed < prev_passed and failed > 0:
            findings.append(Finding(
                title=f"Regression: {prev_passed - passed} previously-passing test(s) now failing",
                severity=Severity.HIGH,
                category="test-regression",
                detail="New failures detected compared to previous run.",
                action_required=True,
                action_description="Investigate regression immediately",
                tags=["tests", "regression"],
            ))

        if total > prev_total:
            delta = total - prev_total
            findings.append(Finding(
                title=f"Test count increased: {prev_total} → {total} (+{delta})",
                severity=Severity.INFO,
                category="test-progress",
                detail="New tests added since last run.",
                tags=["tests", "progress"],
            ))

    # Save state for next run
    ctx.save_state("last_run.json", {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "total": total,
        "duration": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # Determine overall status
    if failed > 0 or errors > 0:
        status = TaskStatus.WARNING
        summary = f"{passed} passed, {failed} failed, {errors} error(s) ({duration:.1f}s)"
    else:
        status = TaskStatus.SUCCESS
        summary = f"{passed} passed, 0 failed ({duration:.1f}s)"

    return TaskResult(
        task_name="test_runner",
        status=status,
        findings=findings,
        summary=summary,
        metadata={"passed": passed, "failed": failed, "errors": errors,
                  "total": total, "duration": duration},
    )
