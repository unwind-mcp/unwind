"""Ghost Mode event log — lightweight action recorder.

A minimal event log that records what the agent tried to do.
No SQLite, no hash chains — just an in-memory list with optional
file export. This is the "See Everything" without the security
infrastructure.

For the full flight recorder with CR-AFT hash chains, tamper
detection, and rollback, upgrade to UNWIND.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class GhostEvent:
    """A single intercepted action."""
    timestamp: float
    tool: str
    action: str          # "intercepted", "passed_through", "shadow_read"
    target: Optional[str] = None
    parameters_summary: Optional[str] = None  # Brief summary, not full params
    detail: Optional[str] = None


class GhostEventLog:
    """In-memory event log for Ghost Mode sessions."""

    def __init__(self):
        self.events: list[GhostEvent] = []
        self._start_time: float = time.time()

    def log_intercept(self, tool: str, target: Optional[str] = None,
                      detail: Optional[str] = None) -> GhostEvent:
        """Log an intercepted (blocked) write action."""
        event = GhostEvent(
            timestamp=time.time(),
            tool=tool,
            action="intercepted",
            target=target,
            detail=detail,
        )
        self.events.append(event)
        return event

    def log_passthrough(self, tool: str, target: Optional[str] = None) -> GhostEvent:
        """Log a read-only action that was passed through."""
        event = GhostEvent(
            timestamp=time.time(),
            tool=tool,
            action="passed_through",
            target=target,
        )
        self.events.append(event)
        return event

    def log_shadow_read(self, tool: str, target: str) -> GhostEvent:
        """Log a read served from the shadow VFS."""
        event = GhostEvent(
            timestamp=time.time(),
            tool=tool,
            action="shadow_read",
            target=target,
            detail="Content served from shadow VFS (ghost-written earlier)",
        )
        self.events.append(event)
        return event

    @property
    def intercepted_count(self) -> int:
        return sum(1 for e in self.events if e.action == "intercepted")

    @property
    def passthrough_count(self) -> int:
        return sum(1 for e in self.events if e.action == "passed_through")

    @property
    def shadow_read_count(self) -> int:
        return sum(1 for e in self.events if e.action == "shadow_read")

    @property
    def duration_seconds(self) -> float:
        return time.time() - self._start_time

    def summary(self) -> dict:
        """Return a session summary."""
        return {
            "duration_seconds": round(self.duration_seconds, 1),
            "total_events": len(self.events),
            "intercepted": self.intercepted_count,
            "passed_through": self.passthrough_count,
            "shadow_reads": self.shadow_read_count,
        }

    def format_timeline(self) -> str:
        """Format events as a human-readable timeline."""
        if not self.events:
            return "  No events recorded."

        lines = []
        for event in self.events:
            ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            target_str = f" → {event.target}" if event.target else ""

            if event.action == "intercepted":
                icon = "\U0001f6ab"  # no entry
                label = "BLOCKED"
            elif event.action == "shadow_read":
                icon = "\U0001f47b"  # ghost
                label = "SHADOW"
            else:
                icon = "\u2705"  # check
                label = "PASSED"

            lines.append(f"  {icon} {ts}  [{label}]  {event.tool}{target_str}")

            if event.detail:
                lines.append(f"{'':>14}\u2514\u2500 {event.detail}")

        return "\n".join(lines)

    def export_json(self, path: Path) -> int:
        """Export the event log to a JSON file."""
        data = {
            "ghostmode_version": "0.1.0",
            "session_summary": self.summary(),
            "events": [asdict(e) for e in self.events],
        }
        path.write_text(json.dumps(data, indent=2))
        return len(self.events)

    def export_jsonl(self, path: Path) -> int:
        """Export events as newline-delimited JSON."""
        with open(path, "w") as f:
            for event in self.events:
                f.write(json.dumps(asdict(event)) + "\n")
        return len(self.events)
