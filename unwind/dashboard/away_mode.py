"""Away Mode Summary — generates a human-readable summary of agent activity.

When the user returns after a period of agent autonomy, this module
compiles a structured summary of what happened, what was blocked,
and what needs review.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

from ..recorder.event_store import EventStore


@dataclass
class AwaySummary:
    """Structured summary of agent activity during away period."""
    duration_seconds: float
    duration_human: str
    trust_state: str          # "green", "amber", "red"
    total_actions: int
    blocked_actions: int
    ghost_actions: int
    taint_events: int
    red_events: int

    # Categorised action counts
    emails_sent: int = 0
    messages_sent: int = 0
    files_modified: int = 0
    files_created: int = 0
    files_deleted: int = 0
    calendar_events: int = 0
    web_searches: int = 0
    reads: int = 0

    # Items needing review
    review_items: list[dict] = field(default_factory=list)
    # High-risk events
    high_risk_events: list[dict] = field(default_factory=list)
    # Snapshots available for undo
    undoable_count: int = 0

    def to_dict(self) -> dict:
        return {
            "duration_seconds": self.duration_seconds,
            "duration_human": self.duration_human,
            "trust_state": self.trust_state,
            "total_actions": self.total_actions,
            "blocked_actions": self.blocked_actions,
            "ghost_actions": self.ghost_actions,
            "taint_events": self.taint_events,
            "red_events": self.red_events,
            "emails_sent": self.emails_sent,
            "messages_sent": self.messages_sent,
            "files_modified": self.files_modified,
            "files_created": self.files_created,
            "files_deleted": self.files_deleted,
            "calendar_events": self.calendar_events,
            "web_searches": self.web_searches,
            "reads": self.reads,
            "review_items": self.review_items,
            "high_risk_events": self.high_risk_events,
            "undoable_count": self.undoable_count,
        }


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds / 60)
        return f"{mins}m"
    else:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        if mins > 0:
            return f"{hours}h {mins}m"
        return f"{hours}h"


def _classify_action(tool: str) -> str:
    """Classify a tool into a human-readable action category."""
    if tool in ("send_email",):
        return "email_sent"
    elif tool in ("post_message",):
        return "message_sent"
    elif tool in ("fs_write",):
        return "file_modified"
    elif tool in ("fs_mkdir",):
        return "file_created"
    elif tool in ("fs_delete",):
        return "file_deleted"
    elif tool in ("create_calendar_event", "modify_calendar_event"):
        return "calendar"
    elif tool in ("search_web", "fetch_web"):
        return "web_search"
    elif tool in ("fs_read", "read_document", "read_email", "read_calendar", "read_slack"):
        return "read"
    return "other"


def generate_away_summary(store: EventStore, since: float) -> AwaySummary:
    """Generate an away mode summary for activity since a given timestamp.

    Args:
        store: The event store to query
        since: Unix timestamp of when the user went away

    Returns:
        AwaySummary with categorised counts and review items
    """
    now = time.time()
    events = store.query_events(since=since, limit=10000)

    # Events come newest-first, reverse for chronological processing
    events.reverse()

    summary = AwaySummary(
        duration_seconds=now - since,
        duration_human=_format_duration(now - since),
        trust_state="green",
        total_actions=len(events),
        blocked_actions=0,
        ghost_actions=0,
        taint_events=0,
        red_events=0,
    )

    worst_state = "green"

    for event in events:
        status = event.get("status", "")
        trust = event.get("trust_state", "green")
        tool = event.get("tool", "")
        tool_class = event.get("tool_class", "")
        ghost = event.get("ghost_mode", False)

        # Track worst trust state seen
        if trust == "red":
            worst_state = "red"
            summary.red_events += 1
        elif trust == "amber" and worst_state != "red":
            worst_state = "amber"

        # Count blocked / ghost
        if status == "blocked":
            summary.blocked_actions += 1
        if status == "ghost_success":
            summary.ghost_actions += 1

        # Count taint events
        if event.get("session_tainted"):
            summary.taint_events += 1

        # Categorise by tool
        category = _classify_action(tool)
        if category == "email_sent" and status != "blocked":
            summary.emails_sent += 1
        elif category == "message_sent" and status != "blocked":
            summary.messages_sent += 1
        elif category == "file_modified" and status != "blocked":
            summary.files_modified += 1
        elif category == "file_created" and status != "blocked":
            summary.files_created += 1
        elif category == "file_deleted" and status != "blocked":
            summary.files_deleted += 1
        elif category == "calendar" and status != "blocked":
            summary.calendar_events += 1
        elif category == "web_search":
            summary.web_searches += 1
        elif category == "read":
            summary.reads += 1

        # Flag high-risk events for review
        if status == "blocked" or trust == "red":
            summary.high_risk_events.append({
                "event_id": event.get("event_id"),
                "tool": tool,
                "target": event.get("target", ""),
                "status": status,
                "trust_state": trust,
                "result_summary": event.get("result_summary", ""),
                "timestamp": event.get("timestamp", 0),
            })

        # Items needing explicit review (blocked high-risk actuators)
        if status == "blocked" and tool_class == "actuator":
            # Extract challenge_id from result_summary if present.
            # result_summary may be None in historical events.
            _rs = event.get("result_summary") or ""
            _cid_match = None
            if "|challenge_id=" in _rs:
                _cid_match = _rs.split("|challenge_id=")[-1].split()[0]
            summary.review_items.append({
                "event_id": event.get("event_id"),
                "tool": tool,
                "target": event.get("target", ""),
                "reason": _rs or "Action blocked",
                "challenge_id": _cid_match,
            })

    summary.trust_state = worst_state

    # Count undoable snapshots
    try:
        snaps = store.get_restorable_snapshots(since=since)
        summary.undoable_count = len(snaps)
    except Exception:
        summary.undoable_count = 0

    return summary
