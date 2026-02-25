#!/usr/bin/env python3
"""
UNWIND Canary Monitor (R-GO-CERT-001 §G4)

Watches telemetry during canary deployment and enforces abort thresholds
from the GO certificate.

Modes:
    --live       Poll a JSONL telemetry log file (production on Pi)
    --dry-run    Replay a synthetic scenario to validate threshold logic
    --replay F   Replay events from a JSONL file

Thresholds (from R-GO-CERT-001 / SENTINEL):
    strict_mode_block_rate_unexpected: >1.0% sustained 5m  → ABORT
    signature_invalid_spike:           >10/min sustained 3m → ABORT
    budget_exceeded_anomaly:           >5/min sustained 5m  → ABORT

Usage:
    # Dry-run (synthetic traffic, validates logic):
    python tools/canary_monitor.py --dry-run

    # Live on Pi (reads telemetry JSONL log):
    python tools/canary_monitor.py --live --log-file /path/to/telemetry.jsonl

    # Replay a captured log:
    python tools/canary_monitor.py --replay telemetry_capture.jsonl
"""

import argparse
import json
import os
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Project imports (for dry-run mode)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


# ---------------------------------------------------------------------------
# GO Certificate Thresholds (SENTINEL-defined)
# ---------------------------------------------------------------------------

@dataclass
class CanaryThresholds:
    """Abort thresholds from R-GO-CERT-001."""
    # strict_mode_block_rate_unexpected: abort if >1.0% sustained 5m
    block_rate_pct: float = 1.0
    block_rate_window_s: float = 300.0  # 5 minutes

    # signature_invalid_spike: abort if >10/min sustained 3m
    sig_invalid_per_min: float = 10.0
    sig_invalid_window_s: float = 180.0  # 3 minutes

    # budget_exceeded_anomaly: abort if >5/min sustained 5m
    budget_exceeded_per_min: float = 5.0
    budget_exceeded_window_s: float = 300.0  # 5 minutes


@dataclass
class CanaryScope:
    """Canary scope from R-GO-CERT-001."""
    traffic_pct: float = 10.0
    duration_min: float = 120.0
    in_scope_categories: tuple = ("sensor", "read", "low_risk_actuator")
    excluded_categories: tuple = ("high_risk_actuator", "policy_or_rbac_mutation", "breakglass_admin")


# ---------------------------------------------------------------------------
# Rolling window metric
# ---------------------------------------------------------------------------

class RollingWindow:
    """Fixed-duration rolling window for event counting."""

    def __init__(self, window_seconds: float):
        self.window_s = window_seconds
        self._events: deque[float] = deque()

    def add(self, timestamp: float):
        self._events.append(timestamp)
        self._expire(timestamp)

    def count(self, now: float) -> int:
        self._expire(now)
        return len(self._events)

    def rate_per_minute(self, now: float) -> float:
        c = self.count(now)
        minutes = self.window_s / 60.0
        return c / minutes if minutes > 0 else 0.0

    def _expire(self, now: float):
        cutoff = now - self.window_s
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


# ---------------------------------------------------------------------------
# Canary Monitor
# ---------------------------------------------------------------------------

@dataclass
class MetricSnapshot:
    timestamp: float
    total_requests: int
    unexpected_blocks: int
    block_rate_pct: float
    sig_invalid_per_min: float
    budget_exceeded_per_min: float
    status: str  # OK | WARN | ABORT_RECOMMENDED


class CanaryMonitor:
    """Watches telemetry events and evaluates GO certificate thresholds."""

    # Event types we care about
    TRUST_GATE_TRUSTED = "trust_gate_trusted"
    TRUST_GATE_BLOCKED = "trust_gate_blocked"
    TRUST_GATE_SIG_INVALID = "trust_gate_signature_invalid"
    TRUST_GATE_UNTRUSTED = "trust_gate_untrusted"
    STRICT_MODE_BLOCK = "strict_mode_block"
    PIPELINE_ALLOW = "pipeline_allow"
    PIPELINE_BLOCK = "pipeline_block"
    BUDGET_EXCEEDED = "budget_exceeded"

    # "Expected" block types (not unexpected)
    EXPECTED_BLOCK_REASONS = {
        "CANARY_TOOL",           # honeypot tools should block
        "SELF_PROTECTION",       # self-protection should block
        "PATH_JAIL",             # path jail should block
        "SSRF_BLOCKED",          # SSRF shield should block
        "DLP_BLOCKED",           # DLP should block
        "CIRCUIT_BREAKER",       # rate limiting expected
    }

    def __init__(self, thresholds: Optional[CanaryThresholds] = None):
        self.thresholds = thresholds or CanaryThresholds()
        self.started_at = time.time()

        # Counters
        self.total_requests = 0
        self.total_allows = 0
        self.total_blocks = 0
        self.unexpected_blocks = 0

        # Rolling windows
        self._block_window = RollingWindow(self.thresholds.block_rate_window_s)
        self._request_window = RollingWindow(self.thresholds.block_rate_window_s)
        self._sig_invalid_window = RollingWindow(self.thresholds.sig_invalid_window_s)
        self._budget_exceeded_window = RollingWindow(self.thresholds.budget_exceeded_window_s)

        # State
        self._abort_recommended = False
        self._abort_reason = ""
        self._warn_active = False
        self._snapshots: list[MetricSnapshot] = []
        self._events_processed = 0
        self._timeline: list[dict] = []

    def process_event(self, event: dict) -> Optional[str]:
        """Process a single telemetry event. Returns status: OK/WARN/ABORT_RECOMMENDED or None."""
        event_type = event.get("event_type", "")
        ts = event.get("timestamp", time.time())
        reason_code = event.get("reason_code", "")

        self._events_processed += 1

        # Track total requests (pipeline verdicts)
        if event_type in (self.PIPELINE_ALLOW, self.PIPELINE_BLOCK):
            self.total_requests += 1
            self._request_window.add(ts)

        # Track allows
        if event_type == self.PIPELINE_ALLOW:
            self.total_allows += 1

        # Track blocks
        if event_type == self.PIPELINE_BLOCK:
            self.total_blocks += 1
            # Is this an "unexpected" block?
            if reason_code not in self.EXPECTED_BLOCK_REASONS:
                self.unexpected_blocks += 1
                self._block_window.add(ts)

        # Track signature invalid (SENTINEL: strictly SIGNATURE_INVALID only,
        # not UNTRUSTED — avoids over-triggering aborts)
        if event_type == self.TRUST_GATE_SIG_INVALID:
            self._sig_invalid_window.add(ts)

        # Track budget exceeded
        if event_type == self.BUDGET_EXCEEDED:
            self._budget_exceeded_window.add(ts)

        # Track strict mode blocks as unexpected blocks
        if event_type == self.STRICT_MODE_BLOCK:
            if reason_code not in self.EXPECTED_BLOCK_REASONS:
                self.unexpected_blocks += 1
                self._block_window.add(ts)

        # Evaluate thresholds
        return self._evaluate(ts)

    def _evaluate(self, now: float) -> str:
        """Evaluate current metrics against thresholds."""
        # --- Metric 1: Unexpected block rate ---
        req_count = self._request_window.count(now)
        block_count = self._block_window.count(now)
        block_rate = (block_count / req_count * 100.0) if req_count > 0 else 0.0

        # --- Metric 2: Signature invalid rate ---
        sig_rate = self._sig_invalid_window.rate_per_minute(now)

        # --- Metric 3: Budget exceeded rate ---
        budget_rate = self._budget_exceeded_window.rate_per_minute(now)

        # --- Check thresholds ---
        status = "OK"
        reasons = []

        if block_rate > self.thresholds.block_rate_pct and req_count >= 10:
            reasons.append(
                f"unexpected_block_rate={block_rate:.1f}% > {self.thresholds.block_rate_pct}% "
                f"({block_count}/{req_count} in {self.thresholds.block_rate_window_s/60:.0f}m)"
            )

        if sig_rate > self.thresholds.sig_invalid_per_min:
            reasons.append(
                f"signature_invalid={sig_rate:.1f}/min > {self.thresholds.sig_invalid_per_min}/min "
                f"(in {self.thresholds.sig_invalid_window_s/60:.0f}m window)"
            )

        if budget_rate > self.thresholds.budget_exceeded_per_min:
            reasons.append(
                f"budget_exceeded={budget_rate:.1f}/min > {self.thresholds.budget_exceeded_per_min}/min "
                f"(in {self.thresholds.budget_exceeded_window_s/60:.0f}m window)"
            )

        if reasons:
            status = "ABORT_RECOMMENDED"
            self._abort_recommended = True
            self._abort_reason = "; ".join(reasons)
        elif block_rate > self.thresholds.block_rate_pct * 0.5 and req_count >= 10:
            status = "WARN"
            self._warn_active = True
        elif sig_rate > self.thresholds.sig_invalid_per_min * 0.5:
            status = "WARN"
            self._warn_active = True
        elif budget_rate > self.thresholds.budget_exceeded_per_min * 0.5:
            status = "WARN"
            self._warn_active = True

        # Record snapshot
        snap = MetricSnapshot(
            timestamp=now,
            total_requests=self.total_requests,
            unexpected_blocks=self.unexpected_blocks,
            block_rate_pct=round(block_rate, 2),
            sig_invalid_per_min=round(sig_rate, 2),
            budget_exceeded_per_min=round(budget_rate, 2),
            status=status,
        )
        self._snapshots.append(snap)

        return status

    def report(self) -> dict:
        """Generate end-of-canary report."""
        elapsed = time.time() - self.started_at
        final_status = "ABORT_RECOMMENDED" if self._abort_recommended else "CANARY_PASS"

        # Peak metrics
        peak_block = max((s.block_rate_pct for s in self._snapshots), default=0.0)
        peak_sig = max((s.sig_invalid_per_min for s in self._snapshots), default=0.0)
        peak_budget = max((s.budget_exceeded_per_min for s in self._snapshots), default=0.0)

        return {
            "canary_monitor": {
                "id": "R-GO-CERT-001-CANARY",
                "started_at": datetime.fromtimestamp(self.started_at, tz=timezone.utc).isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(elapsed, 1),
            },
            "scope": {
                "traffic_pct": CanaryScope.traffic_pct,
                "duration_min": CanaryScope.duration_min,
                "in_scope": list(CanaryScope.in_scope_categories),
                "excluded": list(CanaryScope.excluded_categories),
            },
            "thresholds": {
                "block_rate_pct": self.thresholds.block_rate_pct,
                "block_rate_window_s": self.thresholds.block_rate_window_s,
                "sig_invalid_per_min": self.thresholds.sig_invalid_per_min,
                "sig_invalid_window_s": self.thresholds.sig_invalid_window_s,
                "budget_exceeded_per_min": self.thresholds.budget_exceeded_per_min,
                "budget_exceeded_window_s": self.thresholds.budget_exceeded_window_s,
            },
            "summary": {
                "verdict": final_status,
                "events_processed": self._events_processed,
                "total_requests": self.total_requests,
                "total_allows": self.total_allows,
                "total_blocks": self.total_blocks,
                "unexpected_blocks": self.unexpected_blocks,
                "abort_recommended": self._abort_recommended,
                "abort_reason": self._abort_reason,
            },
            "peak_metrics": {
                "block_rate_pct": peak_block,
                "sig_invalid_per_min": peak_sig,
                "budget_exceeded_per_min": peak_budget,
            },
            "snapshots_count": len(self._snapshots),
        }


# ---------------------------------------------------------------------------
# Dry-run: synthetic scenario
# ---------------------------------------------------------------------------

def run_dry_run():
    """Run a synthetic scenario to validate threshold logic."""
    print(f"\n{BOLD}{'═'*64}")
    print(f"  CANARY MONITOR — DRY RUN")
    print(f"{'═'*64}{RESET}")
    print(f"  Validating threshold logic with synthetic events\n")

    monitor = CanaryMonitor()
    base_time = time.time()
    checks_passed = 0
    checks_total = 0

    def check(desc: str, condition: bool):
        nonlocal checks_passed, checks_total
        checks_total += 1
        if condition:
            checks_passed += 1
            print(f"    {GREEN}✓ PASS{RESET} {desc}")
        else:
            print(f"    {RED}✗ FAIL{RESET} {desc}")

    # --- Phase 1: Normal traffic (should be OK) ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 1: Normal traffic{RESET}")
    for i in range(100):
        t = base_time + i * 0.5
        status = monitor.process_event({
            "event_type": "pipeline_allow",
            "timestamp": t,
        })

    check("Normal traffic: status OK", status == "OK")
    check("100 requests, 0 unexpected blocks", monitor.unexpected_blocks == 0)

    # --- Phase 2: Some expected blocks (canary tools, SSRF) — should stay OK ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 2: Expected blocks (canary, SSRF){RESET}")
    for i in range(5):
        t = base_time + 50 + i
        monitor.process_event({
            "event_type": "pipeline_block",
            "timestamp": t,
            "reason_code": "CANARY_TOOL",
        })
    status = monitor._evaluate(base_time + 55)
    check("Expected blocks don't trigger alert", status == "OK")
    check("Unexpected blocks still 0", monitor.unexpected_blocks == 0)

    # --- Phase 3: Unexpected block spike (>1% of requests) ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 3: Unexpected block spike{RESET}")
    # Add more normal requests to fill the window
    for i in range(100):
        t = base_time + 60 + i * 0.3
        monitor.process_event({
            "event_type": "pipeline_allow",
            "timestamp": t,
        })

    # Now inject unexpected blocks: need >1% of request window
    # Window has ~200 requests. Need >2 unexpected blocks.
    for i in range(5):
        t = base_time + 90 + i * 0.1
        monitor.process_event({
            "event_type": "pipeline_block",
            "timestamp": t,
            "reason_code": "TRUST_LEG_MISSING",  # unexpected
        })

    status = monitor._evaluate(base_time + 91)
    check(f"Unexpected block spike: status={status}", status in ("WARN", "ABORT_RECOMMENDED"))

    # --- Phase 4: Signature invalid spike ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 4: Signature invalid spike{RESET}")
    monitor2 = CanaryMonitor()
    base2 = time.time()
    # Normal baseline
    for i in range(50):
        monitor2.process_event({"event_type": "pipeline_allow", "timestamp": base2 + i})

    # Spike: >10/min for 3m = >30 events in 3 minutes
    for i in range(35):
        t = base2 + 60 + i * 5  # 35 events over ~175s (in 3m window)
        monitor2.process_event({
            "event_type": "trust_gate_signature_invalid",
            "timestamp": t,
        })

    status2 = monitor2._evaluate(base2 + 240)
    check(f"Sig invalid spike: rate={monitor2._sig_invalid_window.rate_per_minute(base2+240):.1f}/min",
          status2 == "ABORT_RECOMMENDED")

    # --- Phase 5: Budget exceeded spike ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 5: Budget exceeded spike{RESET}")
    monitor3 = CanaryMonitor()
    base3 = time.time()
    for i in range(50):
        monitor3.process_event({"event_type": "pipeline_allow", "timestamp": base3 + i})

    # >5/min for 5m = >25 events in 5 minutes
    for i in range(30):
        t = base3 + 30 + i * 9  # 30 events over ~270s (in 5m window)
        monitor3.process_event({
            "event_type": "budget_exceeded",
            "timestamp": t,
        })

    status3 = monitor3._evaluate(base3 + 300)
    check(f"Budget exceeded spike: rate={monitor3._budget_exceeded_window.rate_per_minute(base3+300):.1f}/min",
          status3 == "ABORT_RECOMMENDED")

    # --- Phase 6: Clean canary (no threshold breaches) ---
    print(f"\n{BOLD}{MAGENTA}═══ Phase 6: Clean canary simulation{RESET}")
    clean = CanaryMonitor()
    base_clean = time.time()
    for i in range(500):
        t = base_clean + i * 1.0  # 500 requests over ~8 min
        clean.process_event({"event_type": "pipeline_allow", "timestamp": t})
    # 2 unexpected blocks out of 500 = 0.4% (below 1%)
    for i in range(2):
        t = base_clean + 200 + i
        clean.process_event({
            "event_type": "pipeline_block",
            "timestamp": t,
            "reason_code": "DIGEST_PROVIDER_ERROR",
        })

    final_status = clean._evaluate(base_clean + 500)
    report = clean.report()
    check(f"Clean canary: verdict={report['summary']['verdict']}", report["summary"]["verdict"] == "CANARY_PASS")
    check(f"Clean canary: peak block rate={report['peak_metrics']['block_rate_pct']}%",
          report["peak_metrics"]["block_rate_pct"] < 1.0)

    # --- Summary ---
    print(f"\n{BOLD}{'═'*64}")
    print(f"  DRY RUN RESULTS")
    print(f"{'═'*64}{RESET}")
    print(f"  Checks: {checks_passed}/{checks_total}")

    if checks_passed == checks_total:
        print(f"  {GREEN}{BOLD}ALL CHECKS PASSED ✓{RESET}")
    else:
        print(f"  {RED}{BOLD}{checks_total - checks_passed} CHECKS FAILED{RESET}")

    # Write dry-run report
    out = PROJECT_ROOT / "canary_monitor_dryrun.json"
    with open(out, "w") as f:
        json.dump({
            "mode": "dry_run",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_passed": checks_passed,
            "checks_total": checks_total,
            "verdict": "PASS" if checks_passed == checks_total else "FAIL",
        }, f, indent=2)
    print(f"  Report: {out}\n")

    return 0 if checks_passed == checks_total else 1


# ---------------------------------------------------------------------------
# Live mode: tail a JSONL log file
# ---------------------------------------------------------------------------

def run_live(log_file: str, duration_min: float = 120.0):
    """Monitor a live JSONL telemetry log."""
    print(f"\n{BOLD}{'═'*64}")
    print(f"  CANARY MONITOR — LIVE")
    print(f"{'═'*64}{RESET}")
    print(f"  Log file:  {log_file}")
    print(f"  Duration:  {duration_min} min")
    print(f"  Thresholds: block >1%/5m, sig_invalid >10/min/3m, budget >5/min/5m")
    print()

    monitor = CanaryMonitor()
    deadline = time.time() + (duration_min * 60)
    log_path = Path(log_file)
    last_size = 0
    tick = 0

    try:
        while time.time() < deadline:
            if log_path.exists():
                current_size = log_path.stat().st_size
                if current_size > last_size:
                    with open(log_path, "r") as f:
                        f.seek(last_size)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            status = monitor.process_event(event)
                            if status == "ABORT_RECOMMENDED":
                                elapsed = time.time() - monitor.started_at
                                print(f"\n    {RED}{BOLD}⚠ ABORT RECOMMENDED at T+{elapsed:.0f}s{RESET}")
                                print(f"    Reason: {monitor._abort_reason}")
                                print(f"    Action: Roll back immediately per R-GO-CERT-001 §G4")
                            elif status == "WARN":
                                elapsed = time.time() - monitor.started_at
                                print(f"    {YELLOW}⚠ WARN at T+{elapsed:.0f}s — approaching threshold{RESET}")
                    last_size = current_size

            # Periodic status (every 30s)
            tick += 1
            if tick % 6 == 0:
                elapsed = time.time() - monitor.started_at
                remaining = deadline - time.time()
                snap = monitor._snapshots[-1] if monitor._snapshots else None
                if snap:
                    print(
                        f"    {DIM}[T+{elapsed:.0f}s] "
                        f"reqs={monitor.total_requests} "
                        f"blocks={monitor.unexpected_blocks} "
                        f"rate={snap.block_rate_pct}% "
                        f"sig={snap.sig_invalid_per_min}/m "
                        f"budget={snap.budget_exceeded_per_min}/m "
                        f"remaining={remaining/60:.0f}m "
                        f"[{snap.status}]{RESET}"
                    )

            time.sleep(5)

    except KeyboardInterrupt:
        print(f"\n    {YELLOW}Monitor interrupted by user{RESET}")

    # Final report
    report = monitor.report()
    verdict = report["summary"]["verdict"]
    verdict_color = GREEN if verdict == "CANARY_PASS" else RED

    print(f"\n{BOLD}{'═'*64}")
    print(f"  CANARY COMPLETE")
    print(f"{'═'*64}{RESET}")
    print(f"  Events processed: {report['summary']['events_processed']}")
    print(f"  Total requests:   {report['summary']['total_requests']}")
    print(f"  Unexpected blocks: {report['summary']['unexpected_blocks']}")
    print(f"  Peak block rate:  {report['peak_metrics']['block_rate_pct']}%")
    print(f"  Peak sig invalid: {report['peak_metrics']['sig_invalid_per_min']}/min")
    print(f"  Peak budget exc:  {report['peak_metrics']['budget_exceeded_per_min']}/min")
    print(f"\n  {verdict_color}{BOLD}{verdict}{RESET}")

    if report["summary"]["abort_recommended"]:
        print(f"  {RED}Abort reason: {report['summary']['abort_reason']}{RESET}")

    # Save report
    out = PROJECT_ROOT / "canary_report.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report: {out}\n")

    return 0 if verdict == "CANARY_PASS" else 1


# ---------------------------------------------------------------------------
# Replay mode: read completed JSONL log
# ---------------------------------------------------------------------------

def run_replay(log_file: str):
    """Replay events from a JSONL file (post-hoc analysis)."""
    print(f"\n{BOLD}{'═'*64}")
    print(f"  CANARY MONITOR — REPLAY")
    print(f"{'═'*64}{RESET}")
    print(f"  Replaying: {log_file}\n")

    monitor = CanaryMonitor()
    events_loaded = 0

    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events_loaded += 1
            status = monitor.process_event(event)
            if status == "ABORT_RECOMMENDED":
                elapsed = event.get("timestamp", 0) - monitor.started_at
                print(f"    {RED}⚠ ABORT at event #{events_loaded}: {monitor._abort_reason}{RESET}")

    report = monitor.report()
    verdict = report["summary"]["verdict"]
    verdict_color = GREEN if verdict == "CANARY_PASS" else RED

    print(f"\n  Events replayed:   {events_loaded}")
    print(f"  Total requests:    {report['summary']['total_requests']}")
    print(f"  Unexpected blocks: {report['summary']['unexpected_blocks']}")
    print(f"\n  {verdict_color}{BOLD}{verdict}{RESET}")

    out = PROJECT_ROOT / "canary_report_replay.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report: {out}\n")

    return 0 if verdict == "CANARY_PASS" else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="UNWIND Canary Monitor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Run synthetic scenario")
    group.add_argument("--live", action="store_true", help="Monitor live telemetry log")
    group.add_argument("--replay", metavar="FILE", help="Replay JSONL log file")

    parser.add_argument("--log-file", help="JSONL telemetry log path (for --live mode)")
    parser.add_argument("--duration", type=float, default=120.0, help="Canary duration in minutes (default: 120)")

    args = parser.parse_args()

    if args.dry_run:
        return run_dry_run()
    elif args.live:
        if not args.log_file:
            parser.error("--live requires --log-file")
        return run_live(args.log_file, args.duration)
    elif args.replay:
        return run_replay(args.replay)

    return 1


if __name__ == "__main__":
    sys.exit(main())
