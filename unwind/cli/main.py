"""UNWIND CLI — command-line interface.

Commands:
  unwind status              — Current trust state + last 5 high-risk events
  unwind log                 — Show recent events
  unwind log --since "2h"    — Show events since a time
  unwind log --session ID    — Show events for a session
  unwind verify              — Verify CR-AFT hash chain integrity
  unwind undo last           — Undo the most recent state-modifying action
  unwind undo <event_id>     — Undo a specific event
  unwind undo --since "3pm"  — Undo all state changes since a time
  unwind undo --force        — Ignore conflicts and force rollback
  unwind dashboard           — Launch web dashboard
  unwind ask "question"      — Natural language query
  unwind export <format>     — Export events (json, jsonl, html)
  unwind anchor              — Create CR-AFT chain anchor
  unwind tamper-check        — Run tamper detection
  unwind ghost on|off        — Toggle Ghost Mode
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from ..config import UnwindConfig
from ..recorder.event_store import EventStore
from ..snapshots.manager import Snapshot
from ..snapshots.rollback import RollbackEngine, RollbackStatus




def _sidecar_headers() -> dict[str, str]:
    """Build auth/version headers for sidecar API calls."""
    headers = {"X-UNWIND-API-Version": "1"}
    secret = os.environ.get("UNWIND_SIDECAR_SHARED_SECRET", "").strip()
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    return headers


def parse_since(since_str: str) -> float:
    """Parse a human-readable time string into a Unix timestamp.

    Supports: "2h", "30m", "1d", "3pm", "15:00", ISO format
    """
    since_str = since_str.strip().lower()

    # Relative: "2h", "30m", "1d"
    if since_str.endswith("h"):
        hours = float(since_str[:-1])
        return time.time() - (hours * 3600)
    if since_str.endswith("m"):
        minutes = float(since_str[:-1])
        return time.time() - (minutes * 60)
    if since_str.endswith("d"):
        days = float(since_str[:-1])
        return time.time() - (days * 86400)

    # Time of day: "3pm", "15:00"
    now = datetime.now()
    try:
        if "pm" in since_str or "am" in since_str:
            t = datetime.strptime(since_str, "%I%p" if ":" not in since_str else "%I:%M%p")
        elif ":" in since_str:
            t = datetime.strptime(since_str, "%H:%M")
        else:
            # Try ISO format
            t = datetime.fromisoformat(since_str)
            return t.timestamp()

        target = now.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
        if target > now:
            target -= timedelta(days=1)
        return target.timestamp()
    except ValueError:
        pass

    # Fallback: try as ISO timestamp
    try:
        return datetime.fromisoformat(since_str).timestamp()
    except ValueError:
        print(f"Could not parse time: '{since_str}'. Use formats like: 2h, 30m, 1d, 3pm, 15:00")
        sys.exit(1)


def format_timestamp(ts: float) -> str:
    """Format a Unix timestamp for display."""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def format_event(event: dict) -> str:
    """Format a single event for CLI display."""
    ts = format_timestamp(event["timestamp"])
    tool = event["tool"]
    status = event["status"]
    target = event["target_canonical"] or event["target"] or ""
    ghost = event["ghost_mode"]
    tainted = event["session_tainted"]
    trust = event["trust_state"]

    # Status icon
    if status == "blocked":
        icon = "\u274c"  # red X
    elif status == "red_alert":
        icon = "\U0001f6a8"  # siren
    elif status == "ghost_success":
        icon = "\U0001f47b"  # ghost
    elif status == "pending":
        icon = "\u23f3"  # hourglass
    elif trust == "amber":
        icon = "\U0001f7e1"  # yellow circle
    else:
        icon = "\u2705"  # green check

    # Tool class icon
    tool_class = event.get("tool_class", "")
    if tool_class == "sensor":
        tool_icon = "\U0001f50d"  # magnifying glass
    elif tool_class == "actuator":
        tool_icon = "\u26a1"  # lightning
    elif tool_class == "canary":
        tool_icon = "\U0001f6a8"  # siren
    else:
        tool_icon = "\u2022"  # bullet

    # Truncate target for display
    if len(target) > 50:
        target = "..." + target[-47:]

    line = f"  {icon} {ts}  {tool_icon} {tool:<24} {target}"

    # Add result summary if present
    summary = event.get("result_summary", "")
    if summary and status in ("blocked", "red_alert"):
        line += f"\n{'':>14}\u2514\u2500 {summary[:80]}"

    return line


def cmd_status(config: UnwindConfig) -> None:
    """Show current status and last 5 high-risk events."""
    store = EventStore(config.events_db_path)

    if not config.events_db_path.exists():
        print("UNWIND: No event database found. Has UNWIND been started?")
        return

    store.initialize()

    # Get recent events
    events = store.query_events(limit=100)

    if not events:
        print("\U0001f7e2 UNWIND Status: No events recorded yet")
        store.close()
        return

    # Compute summary
    total = len(events)
    blocked = sum(1 for e in events if e["status"] == "blocked")
    red = sum(1 for e in events if e["status"] == "red_alert")
    ghost = sum(1 for e in events if e["status"] == "ghost_success")
    pending = sum(1 for e in events if e["status"] == "pending")

    # Current trust state (from most recent event)
    latest_trust = events[0]["trust_state"] if events else "green"
    if red > 0:
        trust_icon = "\U0001f534"  # red
        trust_label = "ALERT"
    elif blocked > 0:
        trust_icon = "\U0001f7e1"  # yellow
        trust_label = "ATTENTION"
    else:
        trust_icon = "\U0001f7e2"  # green
        trust_label = "ALL CLEAR"

    print(f"\n  {trust_icon} UNWIND Status: {trust_label}")
    print(f"  {'='*45}")
    print(f"  Last 100 events: {total} total, {blocked} blocked, {red} red alerts, {ghost} ghost")
    if pending > 0:
        print(f"  \u26a0\ufe0f  {pending} events still pending (possible crash recovery)")

    # Show last 5 high-risk events
    high_risk = [
        e for e in events
        if e["status"] in ("blocked", "red_alert") or e["trust_state"] in ("amber", "red")
    ][:5]

    if high_risk:
        print(f"\n  Recent high-risk events:")
        for event in high_risk:
            print(format_event(event))
    else:
        print(f"\n  No high-risk events in recent history")

    # Chain integrity
    valid, error = store.verify_chain()
    if valid:
        print(f"\n  \U0001f512 CR-AFT chain: verified ({total} events)")
    else:
        print(f"\n  \u26a0\ufe0f  CR-AFT chain: BROKEN — {error}")

    print()
    store.close()


def cmd_log(config: UnwindConfig, since: str = None, session_id: str = None, limit: int = 50) -> None:
    """Show event log."""
    store = EventStore(config.events_db_path)

    if not config.events_db_path.exists():
        print("UNWIND: No event database found.")
        return

    store.initialize()

    since_ts = parse_since(since) if since else None

    events = store.query_events(
        session_id=session_id,
        since=since_ts,
        limit=limit,
    )

    if not events:
        print("  No events found")
        store.close()
        return

    # Header
    if since:
        print(f"\n  UNWIND Timeline — since {since}")
    elif session_id:
        print(f"\n  UNWIND Timeline — session {session_id}")
    else:
        print(f"\n  UNWIND Timeline — last {limit} events")
    print(f"  {'='*50}")

    # Events are returned newest-first; display newest-first
    for event in events:
        print(format_event(event))

    print(f"\n  {len(events)} events shown")
    print()
    store.close()


def cmd_verify(config: UnwindConfig) -> None:
    """Verify CR-AFT hash chain integrity."""
    store = EventStore(config.events_db_path)

    if not config.events_db_path.exists():
        print("UNWIND: No event database found.")
        return

    store.initialize()

    print("  Verifying CR-AFT hash chain...")
    valid, error = store.verify_chain()

    events = store.query_events(limit=999999)
    count = len(events)

    if valid:
        print(f"  \u2705 Chain integrity verified: {count} events, all hashes valid")
    else:
        print(f"  \u274c Chain integrity FAILED: {error}")
        print(f"  The event log may have been tampered with.")

    store.close()


def _snapshot_from_row(row: dict) -> Snapshot:
    """Convert a DB snapshot row to a Snapshot dataclass."""
    return Snapshot(
        snapshot_id=row["snapshot_id"],
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        snapshot_type=row["snapshot_type"],
        original_path=row["original_path"],
        snapshot_path=row.get("snapshot_path"),
        original_size=row["original_size"],
        original_hash=row.get("original_hash"),
        metadata=row.get("metadata"),
        restorable=bool(row["restorable"]),
    )


def _format_rollback_result(result) -> str:
    """Format a single rollback result for display."""
    status_icons = {
        RollbackStatus.SUCCESS: "\u2705",
        RollbackStatus.CONFLICT: "\u26a0\ufe0f ",
        RollbackStatus.SNAPSHOT_MISSING: "\u274c",
        RollbackStatus.NOT_RESTORABLE: "\u274c",
        RollbackStatus.ALREADY_ROLLED_BACK: "\U0001f504",
        RollbackStatus.ERROR: "\u274c",
    }
    icon = status_icons.get(result.status, "\u2022")
    path = result.original_path
    if len(path) > 50:
        path = "..." + path[-47:]

    line = f"  {icon} {result.event_id}  {path}"
    line += f"\n{'':>6}\u2514\u2500 {result.message}"
    if result.conflict_detail:
        line += f"\n{'':>6}   Use --force to override"
    return line


def cmd_undo(
    config: UnwindConfig,
    target: str = None,
    since: str = None,
    session_id: str = None,
    force: bool = False,
) -> None:
    """Undo state-modifying actions using stored snapshots."""
    store = EventStore(config.events_db_path)

    if not config.events_db_path.exists():
        print("UNWIND: No event database found.")
        return

    store.initialize()
    engine = RollbackEngine(config)

    snapshots_to_undo = []

    if target == "last":
        # Undo the most recent restorable action
        row = store.get_last_restorable_snapshot()
        if not row:
            print("  No restorable snapshots found")
            store.close()
            return
        snapshots_to_undo = [row]

    elif target and target.startswith("evt_"):
        # Undo a specific event
        row = store.get_snapshot_for_event(target)
        if not row:
            print(f"  No snapshot found for event {target}")
            store.close()
            return
        snapshots_to_undo = [row]

    elif since:
        # Undo all since a time
        since_ts = parse_since(since)
        snapshots_to_undo = store.get_restorable_snapshots(since=since_ts, limit=500)
        if not snapshots_to_undo:
            print(f"  No restorable snapshots found since {since}")
            store.close()
            return

    elif session_id:
        # Undo all in a session
        snapshots_to_undo = store.get_restorable_snapshots(session_id=session_id, limit=500)
        if not snapshots_to_undo:
            print(f"  No restorable snapshots found for session {session_id}")
            store.close()
            return

    else:
        print("  Usage: unwind undo last | unwind undo <event_id> | unwind undo --since <time>")
        store.close()
        return

    # Convert rows to Snapshot objects
    snapshot_objects = [_snapshot_from_row(row) for row in snapshots_to_undo]

    # Show what we're about to do
    print(f"\n  UNWIND Rollback — {len(snapshot_objects)} action(s)")
    print(f"  {'='*50}")

    if not force and len(snapshot_objects) > 1:
        print(f"  \u26a0\ufe0f  Rolling back {len(snapshot_objects)} actions (newest first)")
        print(f"  Add --force to skip conflict checks\n")

    # Execute rollback
    results = engine.rollback_batch(snapshot_objects, force=force)

    success_count = 0
    conflict_count = 0
    error_count = 0

    for result in results:
        print(_format_rollback_result(result))

        if result.status == RollbackStatus.SUCCESS:
            success_count += 1
            # Mark as rolled back in DB
            matching = [s for s in snapshots_to_undo if s["event_id"] == result.event_id]
            if matching:
                store.mark_rolled_back(matching[0]["snapshot_id"])
        elif result.status == RollbackStatus.CONFLICT:
            conflict_count += 1
        elif result.status in (RollbackStatus.ERROR, RollbackStatus.SNAPSHOT_MISSING):
            error_count += 1

    print(f"\n  Summary: {success_count} restored, {conflict_count} conflicts, {error_count} errors")
    print()
    store.close()


def cmd_export(
    config: UnwindConfig,
    fmt: str,
    output: str = None,
    since: str = None,
    session_id: str = None,
) -> None:
    """Export events in various formats."""
    from ..export.exporter import export_json, export_jsonl, export_html_report

    store = EventStore(config.events_db_path)
    if not config.events_db_path.exists():
        print("  No event database found.")
        return

    store.initialize()
    since_ts = parse_since(since) if since else None

    if not output:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output = f"unwind_export_{ts}.{fmt}"

    output_path = Path(output)

    if fmt == "json":
        count = export_json(store, output_path, since=since_ts, session_id=session_id)
    elif fmt == "jsonl":
        count = export_jsonl(store, output_path, since=since_ts, session_id=session_id)
    elif fmt == "html":
        count = export_html_report(store, output_path, since=since_ts, session_id=session_id)
    else:
        print(f"  Unknown format: {fmt}")
        store.close()
        return

    print(f"\n  Exported {count} events to {output_path}")
    print(f"  Format: {fmt.upper()}\n")
    store.close()


def cmd_anchor(config: UnwindConfig) -> None:
    """Create a CR-AFT chain anchor."""
    from ..anchoring.chain_export import ChainAnchoring

    store = EventStore(config.events_db_path)
    if not config.events_db_path.exists():
        print("  No event database found.")
        return

    store.initialize()
    anchoring = ChainAnchoring(config)

    try:
        anchor = anchoring.create_anchor(store)
        print(f"\n  CR-AFT Anchor Created")
        print(f"  {'='*40}")
        print(f"  Anchor ID:    {anchor.anchor_id}")
        print(f"  Events:       {anchor.event_count}")
        print(f"  Chain tip:    {anchor.last_chain_hash[:24]}...")
        print(f"  Digest:       {anchor.chain_digest[:24]}...")
        print(f"  Saved to:     {config.unwind_home / 'anchors' / (anchor.anchor_id + '.json')}")
        print()
    except ValueError as e:
        print(f"  Error: {e}")
    finally:
        store.close()


def cmd_tamper_check(config: UnwindConfig) -> None:
    """Run tamper detection checks."""
    from ..anchoring.chain_export import ChainAnchoring

    store = EventStore(config.events_db_path)
    if not config.events_db_path.exists():
        print("  No event database found.")
        return

    store.initialize()
    anchoring = ChainAnchoring(config)
    report = anchoring.detect_tampering(store)

    print(f"\n  UNWIND Tamper Detection Report")
    print(f"  {'='*40}")
    print(f"  Events scanned:  {report['event_count']}")

    if report['chain_valid']:
        print(f"  Chain integrity: VALID")
    else:
        print(f"  Chain integrity: BROKEN")
        print(f"  Error: {report['chain_error']}")

    print(f"  Anchors:         {report['anchor_count']}")
    if report['anchor_drift']:
        print(f"  Anchor drift:    {', '.join(report['anchor_drift'])}")
    else:
        print(f"  Anchor drift:    None")

    if report['gaps']:
        print(f"  Time gaps (>1h): {len(report['gaps'])}")
        for gap in report['gaps'][:5]:
            hours = gap['gap_seconds'] / 3600
            print(f"    {gap['after_event']} -> {gap['before_event']} ({hours:.1f}h)")
    else:
        print(f"  Time gaps:       None")

    if report['suspicious_events']:
        print(f"  Missing hashes:  {len(report['suspicious_events'])}")
    else:
        print(f"  Missing hashes:  None")

    print()
    store.close()


def cmd_serve(config: UnwindConfig, args) -> None:
    """Start UNWIND as a stdio MCP proxy."""
    import asyncio
    import logging as _logging

    # Parse upstream command (strip leading --)
    upstream_cmd = args.upstream_command
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]

    if not upstream_cmd:
        print("  Error: No upstream command specified.")
        print("  Usage: unwind serve -- npx @modelcontextprotocol/server-filesystem /path")
        print()
        print("  Example:")
        print("    unwind serve -- npx @modelcontextprotocol/server-filesystem ~/Documents")
        print("    unwind serve -- python my_mcp_server.py")
        print("    unwind serve --ghost -- npx @modelcontextprotocol/server-everything")
        sys.exit(1)

    # Configure workspace if specified
    if args.workspace:
        config.workspace_root = Path(args.workspace).expanduser().resolve()

    # Set up logging to stderr (stdout is the MCP transport)
    level = _logging.DEBUG if args.verbose else _logging.INFO
    handler = _logging.StreamHandler(sys.stderr)
    handler.setFormatter(_logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    _logging.root.addHandler(handler)
    _logging.root.setLevel(level)

    logger = _logging.getLogger("unwind")

    # Banner (to stderr, not stdout)
    print(
        "\n  UNWIND v0.1.0 — See Everything. Undo Anything. Test Anything Safely.\n"
        f"  Upstream: {' '.join(upstream_cmd)}\n"
        f"  Workspace: {config.workspace_root}\n"
        f"  Ghost Mode: {'ON' if args.ghost else 'OFF'}\n"
        f"  Dashboard: http://127.0.0.1:9001 (run 'unwind dashboard' separately)\n",
        file=sys.stderr,
    )

    from ..transport.stdio import run_stdio_proxy
    asyncio.run(run_stdio_proxy(config, upstream_cmd, ghost=args.ghost))


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="unwind",
        description="UNWIND — See Everything. Undo Anything. Test Anything Safely.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # unwind status
    subparsers.add_parser("status", help="Show current trust state and recent high-risk events")

    # unwind log
    log_parser = subparsers.add_parser("log", help="Show event timeline")
    log_parser.add_argument("--since", help="Show events since time (e.g., 2h, 30m, 3pm)")
    log_parser.add_argument("--session", help="Filter by session ID")
    log_parser.add_argument("--limit", type=int, default=50, help="Max events to show")

    # unwind verify
    subparsers.add_parser("verify", help="Verify CR-AFT hash chain integrity")

    # unwind undo
    undo_parser = subparsers.add_parser("undo", help="Undo state-modifying actions")
    undo_parser.add_argument("target", nargs="?", help="'last' or an event_id")
    undo_parser.add_argument("--since", help="Undo all changes since time (e.g., 2h, 30m, 3pm)")
    undo_parser.add_argument("--session", help="Undo all changes in a session")
    undo_parser.add_argument("--force", action="store_true", help="Ignore conflicts and force rollback")

    # unwind dashboard
    dash_parser = subparsers.add_parser("dashboard", help="Launch the web dashboard")
    dash_parser.add_argument("--port", type=int, default=9001, help="Port to run on (default: 9001)")
    dash_parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    # unwind ask
    ask_parser = subparsers.add_parser("ask", help="Natural language query about events")
    ask_parser.add_argument("question", nargs="+", help="Your question (e.g., 'what did you do today?')")

    # unwind export
    export_parser = subparsers.add_parser("export", help="Export events")
    export_parser.add_argument("format", choices=["json", "jsonl", "html"], help="Export format")
    export_parser.add_argument("-o", "--output", help="Output file path")
    export_parser.add_argument("--since", help="Export events since time")
    export_parser.add_argument("--session", help="Export events for a session")

    # unwind anchor
    subparsers.add_parser("anchor", help="Create a CR-AFT chain anchor checkpoint")

    # unwind tamper-check
    subparsers.add_parser("tamper-check", help="Run tamper detection checks")

    # unwind sidecar serve
    sidecar_parser = subparsers.add_parser(
        "sidecar",
        help="Manage the UNWIND sidecar policy server",
    )
    sidecar_sub = sidecar_parser.add_subparsers(dest="sidecar_command")
    sidecar_serve = sidecar_sub.add_parser("serve", help="Start the sidecar policy server")
    sidecar_serve.add_argument("--port", type=int, default=9100, help="Listen port (default: 9100)")
    sidecar_serve.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    sidecar_serve.add_argument("--uds", help="Unix domain socket path (overrides host/port)")
    sidecar_serve.add_argument("--log-level", default="info", help="Log level (default: info)")

    # unwind ghost on|off
    ghost_parser = subparsers.add_parser("ghost", help="Toggle Ghost Mode")
    ghost_parser.add_argument("action", choices=["on", "off"], help="Enable or disable Ghost Mode")

    # unwind serve -- <upstream command>
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start UNWIND as a stdio MCP proxy in front of an upstream server",
    )
    serve_parser.add_argument(
        "upstream_command",
        nargs=argparse.REMAINDER,
        help="The upstream MCP server command (e.g., -- npx @modelcontextprotocol/server-filesystem /path)",
    )
    serve_parser.add_argument(
        "--workspace", "-w",
        help="Workspace root for path jail (default: ~/agent-workspace)",
    )
    serve_parser.add_argument(
        "--ghost", action="store_true",
        help="Start in Ghost Mode (all writes are dry-run)",
    )
    serve_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging to stderr",
    )

    args = parser.parse_args()
    config = UnwindConfig()

    # --- Startup validation: refuse to start on misconfigured values ---
    from ..startup_validator import validate_and_enforce
    validate_and_enforce(config)

    if args.command == "status":
        cmd_status(config)
    elif args.command == "log":
        cmd_log(config, since=args.since, session_id=args.session, limit=args.limit)
    elif args.command == "verify":
        cmd_verify(config)
    elif args.command == "undo":
        cmd_undo(
            config,
            target=args.target,
            since=args.since,
            session_id=args.session,
            force=args.force,
        )
    elif args.command == "dashboard":
        from ..dashboard.app import run_dashboard
        run_dashboard(config, port=args.port, debug=args.debug)
    elif args.command == "ask":
        from ..conversational.query import process_query
        question = " ".join(args.question)
        response = process_query(question, config)
        print(f"\n  UNWIND:\n")
        for line in response.split("\n"):
            print(f"  {line}")
        print()
    elif args.command == "export":
        cmd_export(config, args.format, args.output, args.since, args.session)
    elif args.command == "anchor":
        cmd_anchor(config)
    elif args.command == "tamper-check":
        cmd_tamper_check(config)
    elif args.command == "sidecar":
        if getattr(args, "sidecar_command", None) == "serve":
            from ..sidecar import serve as sidecar_serve
            sidecar_serve(
                host=args.host,
                port=args.port,
                config=config,
                log_level=args.log_level,
                uds=args.uds,
            )
        else:
            sidecar_parser.print_help()
    elif args.command == "ghost":
        import httpx
        action = args.action
        enabled = action == "on"
        # Toggle ghost mode via sidecar API if running
        try:
            resp = httpx.post(
                "http://127.0.0.1:9100/v1/ghost/toggle",
                json={"enabled": enabled},
                headers=_sidecar_headers(),
                timeout=3.0,
            )
            if resp.status_code == 200:
                print(f"  Ghost Mode: {'ON' if enabled else 'OFF'}")
            elif resp.status_code == 401:
                print("  Sidecar auth failed (401). Set UNWIND_SIDECAR_SHARED_SECRET in your environment.")
            else:
                print(f"  Sidecar returned {resp.status_code}: {resp.text}")
        except httpx.ConnectError:
            print(f"  Cannot reach sidecar at 127.0.0.1:9100.")
            print(f"  Start it first: unwind sidecar serve")
            print(f"  Or use: unwind serve --ghost -- <upstream command>")
    elif args.command == "serve":
        cmd_serve(config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
