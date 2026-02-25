"""UNWIND Flight Recorder — append-only SQLite event store.

Key design decisions:
- WAL mode eliminates lock contention under concurrent writes
- Synchronous pre-call pending row ensures crash resilience
- Async result update keeps agent latency minimal
- Append-only: events are never modified or deleted by the application
- Snapshot metadata stored alongside events for rollback capability
"""

import asyncio
import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class EventStatus(Enum):
    PENDING = "pending"
    SUCCESS = "success"
    BLOCKED = "blocked"
    GHOST_SUCCESS = "ghost_success"
    ERROR = "error"
    RED_ALERT = "red_alert"


@dataclass
class Event:
    """A single flight recorder event."""
    event_id: str
    timestamp: float
    session_id: str
    tool: str
    tool_class: str  # "sensor", "actuator", "read", "canary"
    target: Optional[str]
    target_canonical: Optional[str]
    parameters_hash: Optional[str]
    session_tainted: bool
    trust_state: str  # "green", "amber", "red"
    status: str  # EventStatus value
    duration_ms: Optional[float]
    result_summary: Optional[str]
    ghost_mode: bool
    chain_hash: Optional[str] = None


class EventStore:
    """Append-only SQLite flight recorder with WAL mode and pending rows."""

    def __init__(self, db_path: Path, read_collapse_seconds: float = 300.0):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._last_chain_hash: Optional[str] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Read collapsing: aggregate rapid sequential reads into single entries
        self._read_collapse_seconds = read_collapse_seconds
        self._read_collapse_window: dict[str, dict] = {}  # session_id -> {tool, first_ts, count, targets}

    def initialize(self) -> None:
        """Create DB, enable WAL mode, create tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # CRITICAL: WAL mode — eliminates lock contention for concurrent writes
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")  # Safe with WAL

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                session_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                tool_class TEXT NOT NULL,
                target TEXT,
                target_canonical TEXT,
                parameters_hash TEXT,
                session_tainted INTEGER NOT NULL DEFAULT 0,
                trust_state TEXT NOT NULL DEFAULT 'green',
                status TEXT NOT NULL,
                duration_ms REAL,
                result_summary TEXT,
                ghost_mode INTEGER NOT NULL DEFAULT 0,
                chain_hash TEXT,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
            )
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_session
            ON events(session_id, timestamp)
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_tool
            ON events(tool)
        """)

        # --- Snapshots metadata table ---
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                snapshot_type TEXT NOT NULL,
                original_path TEXT NOT NULL,
                snapshot_path TEXT,
                original_size INTEGER NOT NULL DEFAULT 0,
                original_hash TEXT,
                metadata TEXT,
                restorable INTEGER NOT NULL DEFAULT 1,
                rolled_back INTEGER NOT NULL DEFAULT 0,
                rolled_back_at REAL,
                FOREIGN KEY (event_id) REFERENCES events(event_id)
            )
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_snapshots_event
            ON snapshots(event_id)
        """)

        self._conn.commit()

        # Load the last chain hash for CR-AFT continuity
        row = self._conn.execute(
            "SELECT chain_hash FROM events ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        if row and row["chain_hash"]:
            self._last_chain_hash = row["chain_hash"]

    def _generate_event_id(self) -> str:
        """Generate a unique event ID: evt_YYYYMMDD_HHMMSS_NNN."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        suffix = uuid.uuid4().hex[:6]
        return f"evt_{ts}_{suffix}"

    def _compute_chain_hash(self, event_id: str, timestamp: float, action_hash: str) -> str:
        """Compute CR-AFT chain hash: SHA-256(prev_hash + event_id + timestamp + action_hash)."""
        prev = self._last_chain_hash or "genesis"
        data = f"{prev}:{event_id}:{timestamp}:{action_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _hash_parameters(self, params: Optional[dict]) -> Optional[str]:
        """Hash tool parameters for storage (never store raw params by default)."""
        if params is None:
            return None
        raw = json.dumps(params, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def write_pending(
        self,
        session_id: str,
        tool: str,
        tool_class: str,
        target: Optional[str],
        target_canonical: Optional[str],
        parameters: Optional[dict],
        session_tainted: bool,
        trust_state: str,
        ghost_mode: bool = False,
    ) -> str:
        """Write a synchronous pre-call pending row. Returns the event_id.

        This MUST be called before forwarding the tool call to upstream.
        It ensures that even if the process crashes mid-flight, the event
        exists in the database as evidence.
        """
        event_id = self._generate_event_id()
        timestamp = time.time()
        params_hash = self._hash_parameters(parameters)

        # Compute chain hash
        action_data = f"{tool}:{target_canonical or ''}:{params_hash or ''}"
        action_hash = hashlib.sha256(action_data.encode()).hexdigest()
        chain_hash = self._compute_chain_hash(event_id, timestamp, action_hash)
        self._last_chain_hash = chain_hash

        self._conn.execute(
            """INSERT INTO events
               (event_id, timestamp, session_id, tool, tool_class, target,
                target_canonical, parameters_hash, session_tainted, trust_state,
                status, ghost_mode, chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id, timestamp, session_id, tool, tool_class, target,
                target_canonical, params_hash, int(session_tainted), trust_state,
                EventStatus.PENDING.value, int(ghost_mode), chain_hash,
            ),
        )
        self._conn.commit()  # Synchronous — this is the crash-resilience guarantee
        return event_id

    def complete_event(
        self,
        event_id: str,
        status: EventStatus,
        duration_ms: Optional[float] = None,
        result_summary: Optional[str] = None,
    ) -> None:
        """Update a pending event with its result. Can be called async."""
        self._conn.execute(
            """UPDATE events
               SET status = ?, duration_ms = ?, result_summary = ?
               WHERE event_id = ?""",
            (status.value, duration_ms, result_summary, event_id),
        )
        self._conn.commit()

    async def complete_event_async(
        self,
        event_id: str,
        status: EventStatus,
        duration_ms: Optional[float] = None,
        result_summary: Optional[str] = None,
    ) -> None:
        """Async wrapper for complete_event — runs in thread pool."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self.complete_event, event_id, status, duration_ms, result_summary
        )

    def query_events(
        self,
        session_id: Optional[str] = None,
        since: Optional[float] = None,
        tool: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query events with optional filters."""
        conditions = []
        params = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_session_summary(self, session_id: str) -> dict:
        """Get aggregate summary of a session."""
        row = self._conn.execute(
            """SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN status = 'ghost_success' THEN 1 ELSE 0 END) as ghost,
                SUM(CASE WHEN trust_state = 'red' THEN 1 ELSE 0 END) as red_events,
                MIN(timestamp) as first_event,
                MAX(timestamp) as last_event
            FROM events WHERE session_id = ?""",
            (session_id,),
        ).fetchone()
        return dict(row) if row else {}

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Verify the CR-AFT hash chain integrity. Returns (valid, error_message)."""
        rows = self._conn.execute(
            "SELECT event_id, timestamp, tool, target_canonical, parameters_hash, chain_hash "
            "FROM events ORDER BY timestamp ASC"
        ).fetchall()

        prev_hash = None
        for row in rows:
            action_data = f"{row['tool']}:{row['target_canonical'] or ''}:{row['parameters_hash'] or ''}"
            action_hash = hashlib.sha256(action_data.encode()).hexdigest()

            prev = prev_hash or "genesis"
            expected = hashlib.sha256(
                f"{prev}:{row['event_id']}:{row['timestamp']}:{action_hash}".encode()
            ).hexdigest()

            if row["chain_hash"] != expected:
                return False, f"Chain broken at {row['event_id']}: expected {expected[:16]}..., got {row['chain_hash'][:16]}..."

            prev_hash = row["chain_hash"]

        return True, None

    # --- Read Collapsing ---

    def should_collapse_read(self, session_id: str, tool: str, tool_class: str) -> Optional[str]:
        """Check if this read event should be collapsed into a prior one.

        Returns the event_id of the existing collapsed event to update,
        or None if this should be a new event.
        """
        if tool_class != "read":
            # Flush any pending collapse for this session
            self._flush_read_collapse(session_id)
            return None

        now = time.time()
        window = self._read_collapse_window.get(session_id)

        if window and (now - window["last_ts"]) < self._read_collapse_seconds and window["tool"] == tool:
            # Extend the existing window
            window["count"] += 1
            window["last_ts"] = now
            return window["event_id"]

        # Start a new window (flush the old one first)
        self._flush_read_collapse(session_id)
        return None

    def start_read_collapse(self, session_id: str, event_id: str, tool: str) -> None:
        """Start a new read collapse window."""
        self._read_collapse_window[session_id] = {
            "event_id": event_id,
            "tool": tool,
            "first_ts": time.time(),
            "last_ts": time.time(),
            "count": 1,
            "targets": [],
        }

    def add_read_collapse_target(self, session_id: str, target: Optional[str]) -> None:
        """Add a target to the current read collapse window."""
        window = self._read_collapse_window.get(session_id)
        if window and target:
            window["targets"].append(target)

    def _flush_read_collapse(self, session_id: str) -> None:
        """Flush the read collapse window — update the event summary."""
        window = self._read_collapse_window.pop(session_id, None)
        if window and window["count"] > 1:
            summary = f"Collapsed {window['count']} reads"
            if window["targets"]:
                summary += f" ({len(window['targets'])} targets)"
            self.complete_event(
                window["event_id"],
                EventStatus.SUCCESS,
                result_summary=summary,
            )

    # --- Snapshot metadata operations ---

    def store_snapshot(
        self,
        snapshot_id: str,
        event_id: str,
        timestamp: float,
        snapshot_type: str,
        original_path: str,
        snapshot_path: Optional[str],
        original_size: int,
        original_hash: Optional[str],
        metadata: Optional[str],
        restorable: bool,
    ) -> None:
        """Store snapshot metadata in the database."""
        self._conn.execute(
            """INSERT INTO snapshots
               (snapshot_id, event_id, timestamp, snapshot_type, original_path,
                snapshot_path, original_size, original_hash, metadata, restorable)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot_id, event_id, timestamp, snapshot_type, original_path,
                snapshot_path, original_size, original_hash, metadata,
                int(restorable),
            ),
        )
        self._conn.commit()

    def get_snapshot_for_event(self, event_id: str) -> Optional[dict]:
        """Get the snapshot record for a given event."""
        row = self._conn.execute(
            "SELECT * FROM snapshots WHERE event_id = ?", (event_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_restorable_snapshots(
        self,
        session_id: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get restorable snapshots, optionally filtered by session or time.

        Joins with events table to get session info. Returns newest-first.
        """
        conditions = ["s.restorable = 1", "s.rolled_back = 0"]
        params: list = []

        if session_id:
            conditions.append("e.session_id = ?")
            params.append(session_id)
        if since:
            conditions.append("s.timestamp >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(conditions)}"
        query = f"""
            SELECT s.*, e.session_id, e.tool, e.tool_class, e.status as event_status
            FROM snapshots s
            JOIN events e ON s.event_id = e.event_id
            {where}
            ORDER BY s.timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_last_restorable_snapshot(self) -> Optional[dict]:
        """Get the most recent restorable, non-rolled-back snapshot."""
        row = self._conn.execute(
            """SELECT s.*, e.session_id, e.tool, e.tool_class
               FROM snapshots s
               JOIN events e ON s.event_id = e.event_id
               WHERE s.restorable = 1 AND s.rolled_back = 0
               ORDER BY s.timestamp DESC LIMIT 1"""
        ).fetchone()
        return dict(row) if row else None

    def mark_rolled_back(self, snapshot_id: str) -> None:
        """Mark a snapshot as rolled back."""
        self._conn.execute(
            "UPDATE snapshots SET rolled_back = 1, rolled_back_at = ? WHERE snapshot_id = ?",
            (time.time(), snapshot_id),
        )
        self._conn.commit()

    # --- P1-6: Retention enforcement ---

    def enforce_retention(
        self,
        retention_days: int = 0,
        max_rows: int = 0,
    ) -> dict:
        """Enforce retention policy on events and orphaned snapshots.

        Args:
            retention_days: Delete events older than this many days (0 = no age limit).
            max_rows: Keep at most this many events (0 = no row limit).
                      When exceeded, oldest events are deleted first.

        Returns:
            Dict with counts: events_deleted, snapshots_deleted, db_size_after.
        """
        if not self._conn:
            return {"events_deleted": 0, "snapshots_deleted": 0, "db_size_after": 0}

        events_deleted = 0
        snapshots_deleted = 0

        # --- 1. Age-based retention ---
        if retention_days > 0:
            cutoff = time.time() - (retention_days * 86400)

            # Delete orphaned snapshots for events that will be deleted
            snap_result = self._conn.execute(
                """DELETE FROM snapshots WHERE event_id IN
                   (SELECT event_id FROM events WHERE timestamp < ?)""",
                (cutoff,),
            )
            snapshots_deleted += snap_result.rowcount

            # Delete old events
            evt_result = self._conn.execute(
                "DELETE FROM events WHERE timestamp < ?",
                (cutoff,),
            )
            events_deleted += evt_result.rowcount
            self._conn.commit()

        # --- 2. Row-count cap ---
        if max_rows > 0:
            count_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM events"
            ).fetchone()
            current_count = count_row["cnt"] if count_row else 0

            if current_count > max_rows:
                excess = current_count - max_rows
                # Get the IDs of the oldest excess events
                oldest = self._conn.execute(
                    "SELECT event_id FROM events ORDER BY timestamp ASC LIMIT ?",
                    (excess,),
                ).fetchall()
                oldest_ids = [row["event_id"] for row in oldest]

                if oldest_ids:
                    placeholders = ",".join("?" * len(oldest_ids))
                    # Delete their snapshots first
                    snap_result = self._conn.execute(
                        f"DELETE FROM snapshots WHERE event_id IN ({placeholders})",
                        oldest_ids,
                    )
                    snapshots_deleted += snap_result.rowcount

                    # Delete the events
                    evt_result = self._conn.execute(
                        f"DELETE FROM events WHERE event_id IN ({placeholders})",
                        oldest_ids,
                    )
                    events_deleted += evt_result.rowcount
                    self._conn.commit()

        # --- 3. Reclaim space ---
        if events_deleted > 0 or snapshots_deleted > 0:
            self._conn.execute("PRAGMA incremental_vacuum;")

        # --- 4. Report ---
        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "events_deleted": events_deleted,
            "snapshots_deleted": snapshots_deleted,
            "db_size_after": db_size,
        }

    def event_count(self) -> int:
        """Return the current number of events in the database."""
        if not self._conn:
            return 0
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
        return row["cnt"] if row else 0

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
