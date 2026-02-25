#!/usr/bin/env python3
"""
UNWIND MCP Stdio Probe (Stage 1 — Integration Test)

Spawns UNWIND as a stdio proxy with a mock upstream MCP server,
sends JSON-RPC 2.0 traffic through it, and validates enforcement.

Modes:
    --mode happy      Normal tool calls that should succeed
    --mode negative   Blocked calls, malformed payloads, policy violations
    --mode full       Both happy + negative (default)

Evidence outputs:
    --out FILE.json   Probe results in JSON
    Stdout/stderr capture per execution checklist R-EXEC-PIPE-001

Usage:
    python tools/mcp_stdio_probe.py --mode full --out stage1_full.json
"""

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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


# ---------------------------------------------------------------------------
# Mock upstream MCP server
# ---------------------------------------------------------------------------
# This is a minimal MCP server that responds to initialize, tools/list,
# and tools/call over stdio.  Written as a standalone script string that
# UNWIND will spawn as a subprocess.

MOCK_UPSTREAM_SCRIPT = r'''
import json, sys

# Mock tool manifest
TOOLS = [
    {"name": "fs_read", "description": "Read a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "fs_write", "description": "Write a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
    {"name": "fetch_web", "description": "Fetch a URL", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    {"name": "send_email", "description": "Send an email", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "bash_exec", "description": "Execute a bash command", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
]

def respond(id, result):
    msg = json.dumps({"jsonrpc": "2.0", "id": id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

def error(id, code, message):
    msg = json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue

    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params", {})

    if method == "initialize":
        respond(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-upstream", "version": "1.0.0"},
        })
    elif method == "tools/list":
        respond(req_id, {"tools": TOOLS})
    elif method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        if tool_name == "fs_read":
            respond(req_id, {"content": [{"type": "text", "text": f"Contents of {args.get('path', '?')}"}]})
        elif tool_name == "fs_write":
            respond(req_id, {"content": [{"type": "text", "text": f"Wrote to {args.get('path', '?')}"}]})
        elif tool_name == "fetch_web":
            respond(req_id, {"content": [{"type": "text", "text": f"Fetched {args.get('url', '?')}"}]})
        elif tool_name == "send_email":
            respond(req_id, {"content": [{"type": "text", "text": f"Sent to {args.get('to', '?')}"}]})
        elif tool_name == "bash_exec":
            respond(req_id, {"content": [{"type": "text", "text": f"Executed: {args.get('command', '?')}"}]})
        else:
            error(req_id, -32601, f"Unknown tool: {tool_name}")
    elif method == "notifications/initialized":
        pass  # Notification, no response needed
    else:
        if req_id is not None:
            error(req_id, -32601, f"Method not found: {method}")
'''


# ---------------------------------------------------------------------------
# Probe result tracking
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    test_id: str
    description: str
    passed: bool
    request: dict = field(default_factory=dict)
    response: Optional[dict] = None
    expected: str = ""
    actual: str = ""
    elapsed_ms: float = 0.0


@dataclass
class ProbeReport:
    mode: str
    results: list[ProbeResult] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    def add(self, result: ProbeResult):
        self.results.append(result)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)


# ---------------------------------------------------------------------------
# Probe client
# ---------------------------------------------------------------------------

class StdioProbeClient:
    """Client that talks JSON-RPC to UNWIND's stdin/stdout."""

    def __init__(self, process: asyncio.subprocess.Process):
        self.process = process
        self._id_counter = 0

    def _next_id(self) -> int:
        self._id_counter += 1
        return self._id_counter

    async def send_request(self, method: str, params: dict = None, timeout: float = 10.0) -> Optional[dict]:
        """Send a JSON-RPC request and wait for response."""
        req_id = self._next_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params:
            msg["params"] = params

        line = json.dumps(msg) + "\n"
        self.process.stdin.write(line.encode())
        await self.process.stdin.drain()

        # Read response (may need to skip notifications)
        start = time.time()
        while True:
            if time.time() - start > timeout:
                return None

            try:
                resp_line = await asyncio.wait_for(
                    self.process.stdout.readline(), timeout=timeout
                )
            except asyncio.TimeoutError:
                return None

            if not resp_line:
                return None

            resp_line = resp_line.strip()
            if not resp_line:
                continue

            try:
                resp = json.loads(resp_line)
            except json.JSONDecodeError:
                continue

            # Check if it's our response
            if resp.get("id") == req_id:
                return resp

            # Could be a notification or response to different id — skip

    async def send_notification(self, method: str, params: dict = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        msg = {"jsonrpc": "2.0", "method": method}
        if params:
            msg["params"] = params
        line = json.dumps(msg) + "\n"
        self.process.stdin.write(line.encode())
        await self.process.stdin.drain()

    async def send_raw(self, data: str) -> Optional[dict]:
        """Send raw data (for malformed payload tests)."""
        self.process.stdin.write((data + "\n").encode())
        await self.process.stdin.drain()
        # Wait briefly for any response
        try:
            resp_line = await asyncio.wait_for(
                self.process.stdout.readline(), timeout=2.0
            )
            if resp_line:
                return json.loads(resp_line.strip())
        except (asyncio.TimeoutError, json.JSONDecodeError):
            pass
        return None


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

async def run_happy_path(client: StdioProbeClient, report: ProbeReport):
    """Happy-path tests — valid MCP tool calls that should succeed."""

    print(f"\n{BOLD}{MAGENTA}═══ HAPPY PATH{RESET}")

    # H1: Initialize handshake
    resp = await client.send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "probe-client", "version": "1.0.0"},
    })
    passed = resp is not None and "result" in resp
    report.add(ProbeResult(
        test_id="H1", description="Initialize handshake",
        passed=passed, response=resp,
        expected="result with serverInfo", actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} H1 Initialize handshake")

    # Send initialized notification
    await client.send_notification("notifications/initialized")
    await asyncio.sleep(0.2)

    # H2: tools/list returns tools + canaries
    resp = await client.send_request("tools/list")
    tools = []
    if resp and "result" in resp and "tools" in resp["result"]:
        tools = resp["result"]["tools"]
    has_upstream = any(t["name"] == "fs_read" for t in tools)
    has_canary = any(t["name"] in (
        "disable_security_audit", "extract_system_keys",
        "grant_admin_access", "override_safety_limits",
    ) for t in tools)
    passed = has_upstream and has_canary
    report.add(ProbeResult(
        test_id="H2", description="tools/list returns upstream + canaries",
        passed=passed,
        expected="upstream tools + canary honeypots",
        actual=f"{len(tools)} tools, upstream={has_upstream}, canary={has_canary}",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} H2 tools/list ({len(tools)} tools, canaries={'yes' if has_canary else 'no'})")

    # H3: Normal fs_read call (within workspace)
    resp = await client.send_request("tools/call", {
        "name": "fs_read",
        "arguments": {"path": "./README.md"},
    })
    passed = resp is not None and "result" in resp
    is_error = False
    if passed and isinstance(resp["result"], dict):
        is_error = resp["result"].get("isError", False)
    report.add(ProbeResult(
        test_id="H3", description="fs_read within workspace",
        passed=passed and not is_error,
        expected="successful read",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed and not is_error else '✗ FAIL'} H3 fs_read within workspace")

    # H4: Passthrough of unknown method (transparent proxy)
    resp = await client.send_request("resources/list")
    # Should get forwarded to upstream (which returns method not found)
    passed = resp is not None and ("result" in resp or "error" in resp)
    report.add(ProbeResult(
        test_id="H4", description="Passthrough of non-intercepted method",
        passed=passed,
        expected="forwarded to upstream (result or error)",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} H4 Passthrough of resources/list")


async def run_negative_path(client: StdioProbeClient, report: ProbeReport):
    """Negative-path tests — blocked calls and policy violations."""

    print(f"\n{BOLD}{MAGENTA}═══ NEGATIVE PATH{RESET}")

    # Ensure initialized
    resp = await client.send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "probe-client", "version": "1.0.0"},
    })
    await client.send_notification("notifications/initialized")
    await asyncio.sleep(0.2)

    # N1: Canary honeypot trigger
    resp = await client.send_request("tools/call", {
        "name": "disable_security_audit",
        "arguments": {},
    })
    is_error = False
    if resp and "result" in resp and isinstance(resp["result"], dict):
        is_error = resp["result"].get("isError", False)
    passed = resp is not None and is_error
    report.add(ProbeResult(
        test_id="N1", description="Canary honeypot triggers KILL",
        passed=passed,
        expected="isError=True (blocked/killed)",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} N1 Canary honeypot (disable_security_audit)")

    # N2: SSRF — fetch internal metadata URL
    resp = await client.send_request("tools/call", {
        "name": "fetch_web",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
    })
    is_error = False
    if resp and "result" in resp and isinstance(resp["result"], dict):
        is_error = resp["result"].get("isError", False)
    passed = resp is not None and is_error
    report.add(ProbeResult(
        test_id="N2", description="SSRF blocked (cloud metadata URL)",
        passed=passed,
        expected="isError=True (SSRF blocked)",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} N2 SSRF shield (169.254.169.254)")

    # N3: Path jail violation
    resp = await client.send_request("tools/call", {
        "name": "fs_read",
        "arguments": {"path": "../../../etc/passwd"},
    })
    is_error = False
    if resp and "result" in resp and isinstance(resp["result"], dict):
        is_error = resp["result"].get("isError", False)
    passed = resp is not None and is_error
    report.add(ProbeResult(
        test_id="N3", description="Path jail violation blocked",
        passed=passed,
        expected="isError=True (path jail)",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} N3 Path jail (../../../etc/passwd)")

    # N4: Malformed JSON-RPC (should not crash proxy)
    resp = await client.send_raw("this is not json")
    # Proxy should survive — test by sending a valid request after
    resp_after = await client.send_request("tools/list")
    survived = resp_after is not None and "result" in resp_after
    report.add(ProbeResult(
        test_id="N4", description="Malformed JSON doesn't crash proxy",
        passed=survived,
        expected="proxy survives, subsequent requests work",
        actual=f"post-malformed tools/list: {'OK' if survived else 'FAILED'}",
    ))
    print(f"    {'✓ PASS' if survived else '✗ FAIL'} N4 Malformed JSON survival")

    # N5: Self-protection — attempt to read UNWIND's own config
    resp = await client.send_request("tools/call", {
        "name": "fs_read",
        "arguments": {"path": "~/.unwind/events.db"},
    })
    is_error = False
    if resp and "result" in resp and isinstance(resp["result"], dict):
        is_error = resp["result"].get("isError", False)
    passed = resp is not None and is_error
    report.add(ProbeResult(
        test_id="N5", description="Self-protection blocks access to .unwind/",
        passed=passed,
        expected="isError=True (self-protection)",
        actual=str(resp)[:200] if resp else "TIMEOUT",
    ))
    print(f"    {'✓ PASS' if passed else '✗ FAIL'} N5 Self-protection (.unwind/events.db)")

    # N6: Circuit breaker — rapid-fire calls
    # NOTE: This must run on a FRESH session because N1 kills the current session.
    # We skip it here and run it as a separate phase below.
    pass


async def run_circuit_breaker_test(report: ProbeReport, mock_path: Path):
    """N6: Circuit breaker test — needs its own UNWIND instance.

    The canary test (N1) kills the session, so all subsequent calls return KILL
    without reaching the circuit breaker. We spawn a fresh UNWIND process to
    test the breaker in isolation.
    """
    print(f"\n{BOLD}{MAGENTA}═══ CIRCUIT BREAKER (isolated){RESET}")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "unwind.cli.main", "serve",
        "--workspace", str(PROJECT_ROOT),
        "--",
        sys.executable, str(mock_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )
    await asyncio.sleep(1.0)

    if proc.returncode is not None:
        report.add(ProbeResult(
            test_id="N6", description="Circuit breaker triggers on rapid calls",
            passed=False, expected="UNWIND starts", actual="process exited early",
        ))
        print(f"    ✗ FAIL N6 Circuit breaker (UNWIND failed to start)")
        return

    client = StdioProbeClient(proc)

    try:
        # Initialize
        resp = await client.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "probe-circuit-breaker", "version": "1.0.0"},
        })
        await client.send_notification("notifications/initialized")
        await asyncio.sleep(0.2)

        # Fire rapid bash_exec calls — breaker should trip after 6 (config: max 5)
        breaker_triggered = False
        for i in range(10):
            resp = await client.send_request("tools/call", {
                "name": "bash_exec",
                "arguments": {"command": f"echo test{i}"},
            })
            if resp and "result" in resp and isinstance(resp["result"], dict):
                if resp["result"].get("isError", False):
                    text = resp["result"].get("content", [{}])
                    if isinstance(text, list) and text:
                        txt = text[0].get("text", "")
                        if "circuit" in txt.lower() or "rate" in txt.lower():
                            breaker_triggered = True
                            break

        report.add(ProbeResult(
            test_id="N6", description="Circuit breaker triggers on rapid calls",
            passed=breaker_triggered,
            expected="circuit breaker block within 10 rapid calls",
            actual=f"triggered={'yes' if breaker_triggered else 'no'} (last resp: {str(resp)[:150]})",
        ))
        print(f"    {'✓ PASS' if breaker_triggered else '✗ FAIL'} N6 Circuit breaker (10 rapid bash_exec)")
    finally:
        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run_probe(mode: str, out_file: Optional[str] = None):
    """Run the probe against UNWIND."""
    report = ProbeReport(mode=mode, started_at=datetime.now(timezone.utc).isoformat())

    print(f"{BOLD}{'═'*64}")
    print(f"  UNWIND MCP STDIO PROBE")
    print(f"{'═'*64}{RESET}")
    print(f"  Mode: {mode}")
    print(f"  Timestamp: {report.started_at}")

    # Write mock upstream to temp file
    mock_path = PROJECT_ROOT / "tools" / "_mock_upstream.py"
    mock_path.write_text(MOCK_UPSTREAM_SCRIPT)

    # Spawn UNWIND with mock upstream
    # Use --workspace . so path jail matches the project root (where README.md lives)
    print(f"\n  Starting UNWIND proxy with mock upstream...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "unwind.cli.main", "serve",
        "--workspace", str(PROJECT_ROOT),
        "--",
        sys.executable, str(mock_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )

    # Wait for startup
    await asyncio.sleep(1.0)

    if proc.returncode is not None:
        stderr = await proc.stderr.read()
        print(f"  {RED}UNWIND failed to start!{RESET}")
        print(f"  stderr: {stderr.decode()[:500]}")
        return 1

    client = StdioProbeClient(proc)

    try:
        if mode in ("happy", "full"):
            await run_happy_path(client, report)

        if mode in ("negative", "full"):
            await run_negative_path(client, report)
    except Exception as e:
        print(f"\n  {RED}Probe error: {e}{RESET}")
        import traceback
        traceback.print_exc()
    finally:
        # Shutdown
        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    # N6: Circuit breaker needs a fresh UNWIND instance (N1 kills the session)
    if mode in ("negative", "full"):
        try:
            await run_circuit_breaker_test(report, mock_path)
        except Exception as e:
            print(f"\n  {RED}N6 error: {e}{RESET}")
            import traceback
            traceback.print_exc()

    # Clean up mock
    try:
        if mock_path.exists():
            mock_path.unlink()
    except OSError:
        pass  # Sandbox may prevent deletion

    report.completed_at = datetime.now(timezone.utc).isoformat()

    # --- Summary ---
    print(f"\n{BOLD}{'═'*64}")
    print(f"  PROBE RESULTS")
    print(f"{'═'*64}{RESET}")
    print(f"  Total:  {report.total}")
    print(f"  Passed: {GREEN}{report.passed}{RESET}")
    print(f"  Failed: {RED}{report.failed}{RESET}")

    if report.failed == 0:
        print(f"\n  {GREEN}{BOLD}ALL PROBES PASSED ✓{RESET}")
    else:
        print(f"\n  {RED}{BOLD}{report.failed} PROBES FAILED{RESET}")
        for r in report.results:
            if not r.passed:
                print(f"    • {r.test_id}: {r.description}")
                print(f"      Expected: {r.expected}")
                print(f"      Actual:   {r.actual}")

    # Write report
    if out_file:
        out_path = Path(out_file)
    else:
        out_path = PROJECT_ROOT / f"stage1_{mode}.json"

    out_data = {
        "probe": "mcp_stdio_probe",
        "mode": mode,
        "started_at": report.started_at,
        "completed_at": report.completed_at,
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "verdict": "PASS" if report.failed == 0 else "FAIL",
        "results": [
            {
                "test_id": r.test_id,
                "description": r.description,
                "passed": r.passed,
                "expected": r.expected,
                "actual": r.actual,
            }
            for r in report.results
        ],
    }
    with open(out_path, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"\n  Report: {out_path}")
    print()

    return 0 if report.failed == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="UNWIND MCP Stdio Probe")
    parser.add_argument("--mode", choices=["happy", "negative", "full"], default="full")
    parser.add_argument("--out", help="Output JSON report path")
    args = parser.parse_args()

    rc = asyncio.run(run_probe(args.mode, args.out))
    sys.exit(rc)


if __name__ == "__main__":
    main()
