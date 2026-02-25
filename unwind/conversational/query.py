"""Conversational Query Engine — natural language interface to event log.

Parses questions like:
  "what did you do this morning?"
  "how many emails were sent today?"
  "show me blocked actions"
  "what happened since 3pm?"
  "any security issues?"
  "summarise the last session"

No LLM in the hot path — uses pattern matching and templates.
"""

import re
import time
from datetime import datetime, timedelta
from typing import Optional

from ..config import UnwindConfig
from ..recorder.event_store import EventStore
from ..dashboard.away_mode import generate_away_summary, _format_duration


# ─── Helper Functions (must be defined before TIME_PATTERNS) ──


def _today_at(hour: int, minute: int) -> float:
    """Get timestamp for today at given hour:minute."""
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return target.timestamp()


def _yesterday_at(hour: int, minute: int) -> float:
    """Get timestamp for yesterday at given hour:minute."""
    now = datetime.now() - timedelta(days=1)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return target.timestamp()


def _parse_since_time(match_or_none=None) -> float:
    """Parse 'since 3pm' or 'since 15:00' into a timestamp."""
    if match_or_none is None:
        return time.time() - 3600  # fallback: last hour

    hour = int(match_or_none.group(1))
    minute = int(match_or_none.group(2) or 0)
    ampm = match_or_none.group(3)

    if ampm:
        if ampm.lower() == "pm" and hour != 12:
            hour += 12
        elif ampm.lower() == "am" and hour == 12:
            hour = 0

    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target > now:
        target -= timedelta(days=1)
    return target.timestamp()


# ─── Time Pattern Parsing ────────────────────────────────

TIME_PATTERNS = [
    # "this morning" / "today" / "this afternoon" / "tonight"
    (r'\bthis\s+morning\b', lambda: _today_at(6, 0), lambda: _today_at(12, 0)),
    (r'\bthis\s+afternoon\b', lambda: _today_at(12, 0), lambda: _today_at(18, 0)),
    (r'\btonight\b', lambda: _today_at(18, 0), lambda: time.time()),
    (r'\btoday\b', lambda: _today_at(0, 0), lambda: time.time()),
    (r'\byesterday\b', lambda: _yesterday_at(0, 0), lambda: _yesterday_at(23, 59)),
    # "last hour" / "last 2 hours" / "last N minutes"
    (r'\blast\s+(\d+)\s+hours?\b', lambda m: time.time() - int(m.group(1)) * 3600, lambda: time.time()),
    (r'\blast\s+(\d+)\s+minutes?\b', lambda m: time.time() - int(m.group(1)) * 60, lambda: time.time()),
    (r'\blast\s+hour\b', lambda: time.time() - 3600, lambda: time.time()),
    # "since 3pm" / "since 15:00"
    (r'\bsince\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b', _parse_since_time, lambda: time.time()),
]

TOOL_ALIASES = {
    "email": ["send_email", "read_email"],
    "emails": ["send_email", "read_email"],
    "message": ["post_message", "read_slack"],
    "messages": ["post_message", "read_slack"],
    "file": ["fs_write", "fs_read", "fs_delete", "fs_rename", "fs_mkdir"],
    "files": ["fs_write", "fs_read", "fs_delete", "fs_rename", "fs_mkdir"],
    "calendar": ["create_calendar_event", "modify_calendar_event", "read_calendar"],
    "search": ["search_web", "fetch_web"],
    "searches": ["search_web", "fetch_web"],
    "web": ["search_web", "fetch_web", "http_post", "http_get"],
}


def _extract_time_range(query: str) -> tuple[Optional[float], Optional[float]]:
    """Extract a time range from a natural language query."""
    query_lower = query.lower()
    for pattern, start_fn, end_fn in TIME_PATTERNS:
        match = re.search(pattern, query_lower)
        if match:
            try:
                start = start_fn(match) if callable(start_fn) and _takes_match(start_fn) else start_fn()
            except TypeError:
                start = start_fn()
            try:
                end = end_fn(match) if callable(end_fn) and _takes_match(end_fn) else end_fn()
            except TypeError:
                end = end_fn()
            return start, end
    return None, None


def _takes_match(fn) -> bool:
    """Check if a function expects a match argument."""
    try:
        import inspect
        params = inspect.signature(fn).parameters
        return len(params) > 0
    except (ValueError, TypeError):
        return False


def _extract_tool_filter(query: str) -> Optional[list[str]]:
    """Extract tool filter from query."""
    query_lower = query.lower()
    for alias, tools in TOOL_ALIASES.items():
        if alias in query_lower:
            return tools
    return None


def _extract_intent(query: str) -> str:
    """Classify the query intent."""
    q = query.lower()

    if any(w in q for w in ["block", "blocked", "denied", "stopped", "prevented"]):
        return "blocked"
    if any(w in q for w in ["security", "alert", "red", "suspicious", "threat", "danger"]):
        return "security"
    if any(w in q for w in ["ghost", "sandbox", "test"]):
        return "ghost"
    if any(w in q for w in ["how many", "count", "total", "number of"]):
        return "count"
    if any(w in q for w in ["what did", "what has", "what happened", "show me", "list", "summary", "summarise", "summarize"]):
        return "summary"
    if any(w in q for w in ["status", "state", "trust", "ok", "safe"]):
        return "status"
    if any(w in q for w in ["undo", "rollback", "revert", "restore"]):
        return "undo_info"

    return "summary"  # default


# ─── Response Generation ─────────────────────────────────

def _format_event_line(event: dict) -> str:
    """Format a single event as a readable line."""
    ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M")
    tool = event["tool"]
    target = event.get("target", "")
    if target and len(target) > 40:
        target = "..." + target[-37:]
    status = event.get("status", "")
    ghost = " [ghost]" if event.get("ghost_mode") else ""

    status_marker = ""
    if status == "blocked":
        status_marker = " BLOCKED"
    elif status == "red_alert":
        status_marker = " RED ALERT"

    return f"  {ts}  {tool} {target}{ghost}{status_marker}"


def _build_summary_response(events: list[dict], time_desc: str) -> str:
    """Build a summary response from events."""
    if not events:
        return f"No events found {time_desc}."

    total = len(events)
    by_tool = {}
    blocked = 0
    ghost = 0
    tainted = 0
    worst_trust = "green"

    for e in events:
        tool = e["tool"]
        by_tool[tool] = by_tool.get(tool, 0) + 1
        if e.get("status") == "blocked":
            blocked += 1
        if e.get("ghost_mode"):
            ghost += 1
        if e.get("session_tainted"):
            tainted += 1
        if e.get("trust_state") == "red":
            worst_trust = "red"
        elif e.get("trust_state") == "amber" and worst_trust != "red":
            worst_trust = "amber"

    trust_icons = {"green": "All clear", "amber": "Attention", "red": "Alert"}

    lines = [f"{time_desc}, your agent performed {total} action(s):"]

    # Group by category
    categories = {
        "emails sent": sum(by_tool.get(t, 0) for t in ["send_email"]),
        "emails read": sum(by_tool.get(t, 0) for t in ["read_email"]),
        "messages": sum(by_tool.get(t, 0) for t in ["post_message", "read_slack"]),
        "file operations": sum(by_tool.get(t, 0) for t in ["fs_write", "fs_read", "fs_delete", "fs_rename", "fs_mkdir"]),
        "web searches": sum(by_tool.get(t, 0) for t in ["search_web", "fetch_web"]),
        "calendar actions": sum(by_tool.get(t, 0) for t in ["create_calendar_event", "modify_calendar_event", "read_calendar"]),
        "shell commands": sum(by_tool.get(t, 0) for t in ["bash_exec"]),
    }

    for cat, count in categories.items():
        if count > 0:
            lines.append(f"  - {count} {cat}")

    # Other tools not in categories
    categorised_tools = set()
    for tools in TOOL_ALIASES.values():
        categorised_tools.update(tools)
    other = {t: c for t, c in by_tool.items() if t not in categorised_tools}
    for tool, count in other.items():
        lines.append(f"  - {count} x {tool}")

    lines.append("")
    lines.append(f"Trust state: {trust_icons.get(worst_trust, worst_trust)}")

    if tainted:
        lines.append(f"Session tainted {tainted} time(s) (external content ingested).")
    if blocked:
        lines.append(f"{blocked} action(s) blocked by enforcement.")
    if ghost:
        lines.append(f"{ghost} action(s) executed in Ghost Mode (not applied).")

    return "\n".join(lines)


def _build_count_response(events: list[dict], query: str, time_desc: str) -> str:
    """Build a count response."""
    tools = _extract_tool_filter(query)
    if tools:
        filtered = [e for e in events if e["tool"] in tools]
        tool_name = next((k for k, v in TOOL_ALIASES.items() if v == tools), "matching")
        return f"{len(filtered)} {tool_name} action(s) {time_desc} (out of {len(events)} total)."
    return f"{len(events)} action(s) {time_desc}."


def _build_blocked_response(events: list[dict], time_desc: str) -> str:
    """Build a response about blocked actions."""
    blocked = [e for e in events if e.get("status") == "blocked"]
    if not blocked:
        return f"No actions were blocked {time_desc}."

    lines = [f"{len(blocked)} action(s) blocked {time_desc}:"]
    for e in blocked[-10:]:  # Show last 10
        lines.append(_format_event_line(e))
    if len(blocked) > 10:
        lines.append(f"  ... and {len(blocked) - 10} more")
    return "\n".join(lines)


def _build_security_response(events: list[dict], time_desc: str) -> str:
    """Build a security-focused response."""
    issues = [e for e in events if e.get("trust_state") in ("amber", "red") or e.get("status") == "blocked"]
    if not issues:
        return f"No security issues detected {time_desc}. Trust state: All clear."

    red = [e for e in issues if e.get("trust_state") == "red"]
    amber = [e for e in issues if e.get("trust_state") == "amber"]
    blocked = [e for e in issues if e.get("status") == "blocked"]

    lines = [f"Security report {time_desc}:"]
    if red:
        lines.append(f"  RED alerts: {len(red)}")
    if amber:
        lines.append(f"  AMBER warnings: {len(amber)}")
    if blocked:
        lines.append(f"  Blocked actions: {len(blocked)}")

    lines.append("")
    lines.append("Recent issues:")
    for e in issues[-5:]:
        lines.append(_format_event_line(e))

    return "\n".join(lines)


def _build_status_response(events: list[dict]) -> str:
    """Build a current status response."""
    if not events:
        return "No events recorded. Agent appears idle."

    latest = events[0]  # newest first
    trust = latest.get("trust_state", "green")
    trust_labels = {"green": "All clear", "amber": "Attention required", "red": "Alert"}

    last_time = datetime.fromtimestamp(latest["timestamp"]).strftime("%H:%M")

    return (
        f"Current trust state: {trust_labels.get(trust, trust)}\n"
        f"Last action: {latest['tool']} at {last_time}\n"
        f"Status: {latest.get('status', 'unknown')}"
    )


# ─── Main Query Function ─────────────────────────────────

def process_query(query: str, config: UnwindConfig) -> str:
    """Process a natural language query about the event log.

    This is the main entry point for the conversational interface.
    No LLM in the path — pattern matching and templates only.

    Args:
        query: Natural language question
        config: UNWIND configuration

    Returns:
        Human-readable response string
    """
    store = EventStore(config.events_db_path)

    if not config.events_db_path.exists():
        return "No event database found. UNWIND hasn't recorded any events yet."

    store.initialize()

    try:
        intent = _extract_intent(query)
        since, until = _extract_time_range(query)

        # Default: last 24 hours
        if since is None:
            since = time.time() - 86400

        events = store.query_events(since=since, limit=10000)

        # Build time description
        if until:
            time_desc = f"between {datetime.fromtimestamp(since).strftime('%H:%M')} and {datetime.fromtimestamp(until).strftime('%H:%M')}"
        else:
            time_desc = f"since {datetime.fromtimestamp(since).strftime('%H:%M')}"

        # Filter by tool if present
        tool_filter = _extract_tool_filter(query)
        if tool_filter and intent not in ("count",):
            events = [e for e in events if e["tool"] in tool_filter]

        # Reverse to chronological for processing
        events_chrono = list(reversed(events))

        if intent == "summary":
            return _build_summary_response(events_chrono, time_desc)
        elif intent == "count":
            return _build_count_response(events_chrono, query, time_desc)
        elif intent == "blocked":
            return _build_blocked_response(events_chrono, time_desc)
        elif intent == "security":
            return _build_security_response(events_chrono, time_desc)
        elif intent == "ghost":
            ghost_events = [e for e in events_chrono if e.get("ghost_mode")]
            if not ghost_events:
                return f"No Ghost Mode actions {time_desc}."
            lines = [f"{len(ghost_events)} Ghost Mode action(s) {time_desc}:"]
            for e in ghost_events[-10:]:
                lines.append(_format_event_line(e))
            return "\n".join(lines)
        elif intent == "status":
            return _build_status_response(events)
        elif intent == "undo_info":
            snaps = store.get_restorable_snapshots(since=since)
            if not snaps:
                return f"No undoable actions {time_desc}."
            return f"{len(snaps)} action(s) can be undone {time_desc}. Use 'unwind undo last' or the dashboard."
        else:
            return _build_summary_response(events_chrono, time_desc)

    finally:
        store.close()
