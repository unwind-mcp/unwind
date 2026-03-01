"""Pulse log — append-only rhythm event store.

Writes to cadence/pulse.jsonl with CRIP consent headers on every entry.

Schema v1 fields (required):
  timestamp, direction, token_count, inferred_state, confidence,
  ert_seconds, consent_scope, crip_version

Optional (reserved v1):
  session_id  — ephemeral per-run ID for cold-start segmentation
  source      — surface origin ("openclaw", "mcp", "cli", "ide")
  event_type  — system event classifier (only on system events)

Contract:
  - direction is strictly "in" or "out" for interaction events
  - system events use event_type field, direction remains absent
  - timestamps are always UTC with Z suffix (never local offsets)
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..engine.rhythm import StateResult, TemporalState
from ..protocol.crip import (
    CRIP_EVENT_CONSENT_CHANGED,
    CRIP_EVENT_DATA_DELETED,
    CRIP_EVENT_DATA_RESET,
    CRIPHeaders,
)


def _utc_z(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with Z suffix. Always UTC."""
    # Ensure UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    # Replace +00:00 with Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class PulseLog:
    """Append-only rhythm event log."""

    def __init__(
        self,
        path: Path,
        crip: Optional[CRIPHeaders] = None,
        session_id: Optional[str] = None,
        source: Optional[str] = None,
    ):
        self.path = path
        self.crip = crip or CRIPHeaders()
        self.session_id = session_id
        self.source = source

    def _base_event(self, timestamp: Optional[datetime] = None) -> dict:
        """Build base event dict with timestamp and optional fields."""
        now = timestamp or datetime.now(timezone.utc)
        event: dict = {"timestamp": _utc_z(now)}
        if self.session_id is not None:
            event["session_id"] = self.session_id
        if self.source is not None:
            event["source"] = self.source
        return event

    def write_event(
        self,
        direction: str,
        token_count: int,
        state_result: Optional[StateResult],
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """Append a rhythm event to pulse.jsonl.

        Args:
            direction: "in" or "out" (strictly interaction events)
            token_count: approximate token count
            state_result: inference result (may be None for first event or "out" events)
            timestamp: UTC timestamp (defaults to now)

        Returns:
            The event dict that was written.
        """
        event = self._base_event(timestamp)
        event.update({
            "direction": direction,
            "token_count": token_count,
            "inferred_state": state_result.state.value if state_result else TemporalState.FLOW.value,
            "confidence": round(state_result.confidence, 4) if state_result else 0.0,
            "ert_seconds": state_result.ert_seconds if state_result else 0.0,
        })
        event.update(self.crip.to_pulse_dict())

        self._append(event)
        return event

    def write_system_event(self, event_type: str, details: Optional[dict] = None) -> dict:
        """Write a system event (CRIP lifecycle, taint, bridge signals).

        System events use event_type instead of direction.
        direction is strictly "in"/"out" for interaction events.
        """
        event = self._base_event()
        event.update({
            "event_type": event_type,
            "token_count": 0,
            "inferred_state": "SYSTEM",
            "confidence": 1.0,
            "ert_seconds": 0.0,
        })
        if details:
            event["details"] = details
        event.update(self.crip.to_pulse_dict())

        self._append(event)
        return event

    def write_taint_clear(self) -> dict:
        """Write a TAINT_CLEAR event before taint decay clears.

        Called by the UNWIND bridge to create forensic brackets
        around potentially compromised activity.
        """
        return self.write_system_event("TAINT_CLEAR")

    def _append(self, event: dict) -> None:
        """Append a JSON line to the pulse log."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def read_events(self, limit: int = 0) -> list[dict]:
        """Read events from the pulse log.

        Args:
            limit: max events to return (0 = all). Returns most recent.
        """
        if not self.path.exists():
            return []
        events = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if limit > 0:
            return events[-limit:]
        return events

    def forget_before(self, before: datetime) -> int:
        """Remove events older than the given timestamp.

        Returns the number of events removed.
        """
        if not self.path.exists():
            return 0

        events = self.read_events()
        cutoff_z = _utc_z(before)
        kept = [e for e in events if e.get("timestamp", "") >= cutoff_z]
        removed = len(events) - len(kept)

        if removed > 0:
            # Rewrite file with remaining events
            tmp = self.path.with_suffix(".jsonl.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                for event in kept:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            os.replace(str(tmp), str(self.path))

            # Log the deletion
            self.write_system_event(
                CRIP_EVENT_DATA_DELETED,
                {"removed_count": removed, "before": cutoff_z},
            )

        return removed

    def reset(self) -> int:
        """Delete all events. Returns count of events removed."""
        count = 0
        if self.path.exists():
            count = len(self.read_events())
            os.remove(self.path)

        # Write reset event to fresh log
        self.write_system_event(
            CRIP_EVENT_DATA_RESET,
            {"removed_count": count},
        )
        return count

    def event_count(self) -> int:
        """Count events in the pulse log."""
        if not self.path.exists():
            return 0
        count = 0
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
