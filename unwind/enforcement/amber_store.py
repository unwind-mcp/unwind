"""Amber Mediator Event Store — persistence layer for R-AMBER-MED-001.

Provides:
  - pending_amber_events table (GO-02): stores issued amber challenges
  - used_mediator_tokens table (GO-03): replay defence via jti uniqueness
  - Issuance persistence (GO-04): exact wire values stored at emit time
  - Approval validation (GO-05/06): exact-match, expiry, sequence checks
  - Replay defence (GO-07): jti uniqueness, survives restart
  - Atomic state transitions (GO-08): resolve + record in one transaction

Uses the same SQLite DB as the flight recorder EventStore (WAL mode).
Tables are created alongside existing tables — no migration needed for
fresh installs.  For upgrades, tables are CREATE IF NOT EXISTS.

Framework-agnostic: stores raw values, no OpenClaw-specific logic.
"""

import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Rejection reason codes (per R-AMBER-MED-001 §5)
# ---------------------------------------------------------------------------

class AmberRejectReason:
    """Canonical rejection reason codes per R-AMBER-MED-001 protocol.

    All codes use the MEDIATOR_TOKEN_* namespace to align with the
    protocol spec and GO-09 telemetry schema.
    """
    EVENT_NOT_FOUND = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    EVENT_ALREADY_RESOLVED = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    FIELD_MISMATCH_EVENT_ID = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    FIELD_MISMATCH_PATTERN_ID = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    FIELD_MISMATCH_NONCE = "MEDIATOR_TOKEN_NONCE_MISMATCH"
    FIELD_MISMATCH_SEQ = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    FIELD_MISMATCH_ACTION_HASH = "MEDIATOR_TOKEN_ACTION_HASH_MISMATCH"
    FIELD_MISMATCH_RISK_TIER = "MEDIATOR_TOKEN_RISK_TIER_MISMATCH"
    FIELD_MISMATCH_CAPSULE_HASH = "MEDIATOR_TOKEN_CAPSULE_HASH_MISMATCH"
    CHALLENGE_EXPIRED = "MEDIATOR_TOKEN_EXPIRED"
    SEQUENCE_STALE = "MEDIATOR_TOKEN_EXPIRED"
    SEQUENCE_DUPLICATE = "MEDIATOR_TOKEN_REPLAY"
    REPLAY_DETECTED = "MEDIATOR_TOKEN_REPLAY"
    SESSION_KILLED = "MEDIATOR_TOKEN_EVENT_MISMATCH"


# ---------------------------------------------------------------------------
# Amber Event Store
# ---------------------------------------------------------------------------

class AmberEventStore:
    """SQLite persistence for amber mediator challenges and approvals.

    Shares the same WAL-mode database as the flight recorder.
    All public methods are synchronous (call from thread pool for async).
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def initialize(self) -> None:
        """Create tables and indexes.  Idempotent (CREATE IF NOT EXISTS)."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # Match flight recorder pragmas
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")

        # ── GO-02: pending_amber_events ──────────────────────────
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_amber_events (
                event_id            TEXT PRIMARY KEY,
                session_id          TEXT NOT NULL,
                principal_id        TEXT NOT NULL DEFAULT 'default',
                request_id          TEXT NOT NULL,
                pattern_id          TEXT NOT NULL,
                action_hash         TEXT NOT NULL,
                challenge_nonce     TEXT NOT NULL,
                challenge_seq       INTEGER NOT NULL,
                challenge_expires_at TEXT NOT NULL,
                risk_tier           TEXT NOT NULL,
                risk_capsule_hash   TEXT NOT NULL,
                batch_group_key     TEXT NOT NULL,
                batch_max_size      INTEGER NOT NULL,
                batchable           INTEGER NOT NULL DEFAULT 1,
                tool_name           TEXT NOT NULL,
                destination_scope   TEXT NOT NULL,
                taint_level         TEXT NOT NULL DEFAULT 'NONE',
                status              TEXT NOT NULL DEFAULT 'pending',
                resolved_at         REAL,
                resolution          TEXT,
                issued_at           REAL NOT NULL,
                CONSTRAINT chk_status CHECK (status IN ('pending', 'approved', 'denied', 'expired'))
            )
        """)

        # Unique constraint: one challenge_seq per session+principal
        self._conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_amber_seq_unique
            ON pending_amber_events(session_id, principal_id, challenge_seq)
        """)

        # Lookup by pattern + risk for batch grouping queries
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_amber_pattern_risk
            ON pending_amber_events(pattern_id, risk_tier)
        """)

        # Lookup pending events by session
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_amber_session_status
            ON pending_amber_events(session_id, status)
        """)

        # ── GO-03: used_mediator_tokens (replay defence) ─────────
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS used_mediator_tokens (
                jti         TEXT PRIMARY KEY,
                event_id    TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                used_at     REAL NOT NULL,
                FOREIGN KEY (event_id) REFERENCES pending_amber_events(event_id)
            )
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tokens_session
            ON used_mediator_tokens(session_id)
        """)

        self._conn.commit()

    # ─── Sequence counter ────────────────────────────────────────

    def next_challenge_seq(self, session_id: str, principal_id: str = "default") -> int:
        """Get the next monotonic challenge_seq for a session+principal.

        Thread-safe: reads max existing seq and increments.
        """
        row = self._conn.execute(
            """SELECT MAX(challenge_seq) as max_seq
               FROM pending_amber_events
               WHERE session_id = ? AND principal_id = ?""",
            (session_id, principal_id),
        ).fetchone()
        current_max = row["max_seq"] if row and row["max_seq"] is not None else 0
        return current_max + 1

    # ─── GO-04: Issue (persist at emit time) ─────────────────────

    def issue_amber_event(
        self,
        *,
        event_id: str,
        session_id: str,
        principal_id: str = "default",
        request_id: str,
        pattern_id: str,
        action_hash: str,
        challenge_nonce: str,
        challenge_seq: int,
        challenge_expires_at: str,
        risk_tier: str,
        risk_capsule_hash: str,
        batch_group_key: str,
        batch_max_size: int,
        batchable: bool,
        tool_name: str,
        destination_scope: str,
        taint_level: str = "NONE",
    ) -> None:
        """Persist an amber challenge at the moment it is emitted on the wire.

        This is synchronous and committed immediately — crash-resilient.
        The stored fields MUST exactly match what was sent to the agent.
        """
        self._conn.execute(
            """INSERT INTO pending_amber_events
               (event_id, session_id, principal_id, request_id,
                pattern_id, action_hash, challenge_nonce, challenge_seq,
                challenge_expires_at, risk_tier, risk_capsule_hash,
                batch_group_key, batch_max_size, batchable,
                tool_name, destination_scope, taint_level,
                status, issued_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
            (
                event_id, session_id, principal_id, request_id,
                pattern_id, action_hash, challenge_nonce, challenge_seq,
                challenge_expires_at, risk_tier, risk_capsule_hash,
                batch_group_key, batch_max_size, int(batchable),
                tool_name, destination_scope, taint_level,
                time.time(),
            ),
        )
        self._conn.commit()

    # ─── GO-05/06/07/08: Validate and apply approval token ──────

    def validate_and_apply(
        self,
        *,
        jti: str,
        event_id: str,
        pattern_id: str,
        challenge_nonce: str,
        challenge_seq: int,
        action_hash: str,
        risk_tier: str,
        presented_capsule_hash: str,
        session_id: str,
        principal_id: str = "default",
    ) -> tuple[bool, Optional[str]]:
        """Validate an approval token and atomically apply it.

        Returns (accepted: bool, reject_reason: Optional[str]).

        GO-05: Exact-match validation on all bound fields
        GO-06: Expiry + sequence monotonicity checks
        GO-07: Replay defence via jti uniqueness
        GO-08: Atomic resolve + token record in single transaction

        All checks are fail-closed: any mismatch → reject.
        """
        # ── Replay check (GO-07) ──
        existing_token = self._conn.execute(
            "SELECT jti FROM used_mediator_tokens WHERE jti = ?",
            (jti,),
        ).fetchone()
        if existing_token:
            return False, AmberRejectReason.REPLAY_DETECTED

        # ── Fetch pending event ──
        row = self._conn.execute(
            "SELECT * FROM pending_amber_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()

        if row is None:
            return False, AmberRejectReason.EVENT_NOT_FOUND

        if row["status"] != "pending":
            return False, AmberRejectReason.EVENT_ALREADY_RESOLVED

        # ── GO-05: Exact-match field validation (fail-closed) ──
        field_checks = [
            (row["pattern_id"], pattern_id, AmberRejectReason.FIELD_MISMATCH_PATTERN_ID),
            (row["challenge_nonce"], challenge_nonce, AmberRejectReason.FIELD_MISMATCH_NONCE),
            (row["challenge_seq"], challenge_seq, AmberRejectReason.FIELD_MISMATCH_SEQ),
            (row["action_hash"], action_hash, AmberRejectReason.FIELD_MISMATCH_ACTION_HASH),
            (row["risk_tier"], risk_tier, AmberRejectReason.FIELD_MISMATCH_RISK_TIER),
            (row["risk_capsule_hash"], presented_capsule_hash, AmberRejectReason.FIELD_MISMATCH_CAPSULE_HASH),
        ]

        for stored_val, presented_val, reason in field_checks:
            if stored_val != presented_val:
                return False, reason

        # ── GO-06: Expiry check ──
        try:
            expires_str = row["challenge_expires_at"]
            expires_dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now > expires_dt:
                return False, AmberRejectReason.CHALLENGE_EXPIRED
        except (ValueError, TypeError):
            return False, AmberRejectReason.CHALLENGE_EXPIRED

        # ── GO-06: Sequence monotonicity ──
        # Check no higher seq has already been approved for this session+principal
        higher_approved = self._conn.execute(
            """SELECT challenge_seq FROM pending_amber_events
               WHERE session_id = ? AND principal_id = ?
                 AND challenge_seq > ? AND status = 'approved'
               LIMIT 1""",
            (session_id, principal_id, challenge_seq),
        ).fetchone()
        if higher_approved:
            return False, AmberRejectReason.SEQUENCE_STALE

        # Check this exact seq hasn't already been used (duplicate)
        same_seq_approved = self._conn.execute(
            """SELECT challenge_seq FROM pending_amber_events
               WHERE session_id = ? AND principal_id = ?
                 AND challenge_seq = ? AND status = 'approved'
                 AND event_id != ?
               LIMIT 1""",
            (session_id, principal_id, challenge_seq, event_id),
        ).fetchone()
        if same_seq_approved:
            return False, AmberRejectReason.SEQUENCE_DUPLICATE

        # ── GO-08: Atomic apply (single transaction) ──
        # Both operations in one transaction: resolve event + record token
        now_ts = time.time()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            # Re-check status under write lock to prevent race
            recheck = self._conn.execute(
                "SELECT status FROM pending_amber_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if recheck["status"] != "pending":
                self._conn.execute("ROLLBACK")
                return False, AmberRejectReason.EVENT_ALREADY_RESOLVED

            # Mark event as approved
            self._conn.execute(
                """UPDATE pending_amber_events
                   SET status = 'approved', resolved_at = ?, resolution = 'approved'
                   WHERE event_id = ?""",
                (now_ts, event_id),
            )
            # Record token use (replay defence)
            self._conn.execute(
                """INSERT INTO used_mediator_tokens (jti, event_id, session_id, used_at)
                   VALUES (?, ?, ?, ?)""",
                (jti, event_id, session_id, now_ts),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

        return True, None

    def deny_event(self, event_id: str) -> bool:
        """Deny a pending amber event.  Returns True if the event was pending."""
        now_ts = time.time()
        cursor = self._conn.execute(
            """UPDATE pending_amber_events
               SET status = 'denied', resolved_at = ?, resolution = 'denied'
               WHERE event_id = ? AND status = 'pending'""",
            (now_ts, event_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ─── Queries ─────────────────────────────────────────────────

    def get_pending_event(self, event_id: str) -> Optional[dict]:
        """Get a single amber event by ID."""
        row = self._conn.execute(
            "SELECT * FROM pending_amber_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_pending_events(self, session_id: str, status: str = "pending") -> list[dict]:
        """Get all amber events for a session with given status."""
        rows = self._conn.execute(
            """SELECT * FROM pending_amber_events
               WHERE session_id = ? AND status = ?
               ORDER BY challenge_seq ASC""",
            (session_id, status),
        ).fetchall()
        return [dict(row) for row in rows]

    def is_token_used(self, jti: str) -> bool:
        """Check if a token JTI has already been used."""
        row = self._conn.execute(
            "SELECT jti FROM used_mediator_tokens WHERE jti = ?",
            (jti,),
        ).fetchone()
        return row is not None

    def expire_stale_events(self) -> int:
        """Mark expired pending events.  Returns count of expired events."""
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        cursor = self._conn.execute(
            """UPDATE pending_amber_events
               SET status = 'expired', resolved_at = ?, resolution = 'expired'
               WHERE status = 'pending' AND challenge_expires_at < ?""",
            (time.time(), now_iso),
        )
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
