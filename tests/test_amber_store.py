"""Tests for the Amber Mediator Event Store (GO-02 through GO-08).

Covers:
  GO-02: pending_amber_events schema, NOT NULL, indexes
  GO-03: used_mediator_tokens replay table, jti uniqueness, restart durability
  GO-04: Issuance persists exact wire values
  GO-05: Approval validation exact-match + fail-closed
  GO-06: Expiry + sequence enforcement
  GO-07: Replay defence end-to-end
  GO-08: Atomic state transitions (no double-apply)
"""

import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from unwind.enforcement.amber_store import AmberEventStore, AmberRejectReason


def _future_expiry(seconds: int = 90) -> str:
    """Generate an ISO 8601 expiry in the future."""
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _past_expiry() -> str:
    """Generate an ISO 8601 expiry in the past."""
    return (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")


def _make_event_kwargs(
    event_id: str = "evt_test_001",
    session_id: str = "sess_1",
    challenge_seq: int = 1,
    challenge_expires_at: str = None,
    **overrides,
) -> dict:
    """Build a default set of kwargs for issue_amber_event."""
    defaults = dict(
        event_id=event_id,
        session_id=session_id,
        principal_id="default",
        request_id="req_001",
        pattern_id="pat_abc123",
        action_hash="act_def456",
        challenge_nonce="nonce_xyz_base64url",
        challenge_seq=challenge_seq,
        challenge_expires_at=challenge_expires_at or _future_expiry(),
        risk_tier="AMBER_HIGH",
        risk_capsule_hash="cap_hash_789",
        batch_group_key="grp_batch_001",
        batch_max_size=5,
        batchable=True,
        tool_name="fs_write",
        destination_scope="./docs/",
        taint_level="HIGH",
    )
    defaults.update(overrides)
    return defaults


def _make_approval_kwargs(event_kwargs: dict, jti: str = "jti_unique_001") -> dict:
    """Build matching approval kwargs from issued event kwargs."""
    return dict(
        jti=jti,
        event_id=event_kwargs["event_id"],
        pattern_id=event_kwargs["pattern_id"],
        challenge_nonce=event_kwargs["challenge_nonce"],
        challenge_seq=event_kwargs["challenge_seq"],
        action_hash=event_kwargs["action_hash"],
        risk_tier=event_kwargs["risk_tier"],
        presented_capsule_hash=event_kwargs["risk_capsule_hash"],
        session_id=event_kwargs["session_id"],
        principal_id=event_kwargs.get("principal_id", "default"),
    )


class TestAmberStoreSchema(unittest.TestCase):
    """GO-02 + GO-03: Schema, constraints, indexes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_tables_exist(self):
        """Both tables are created."""
        tables = self.store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        self.assertIn("pending_amber_events", table_names)
        self.assertIn("used_mediator_tokens", table_names)

    def test_pending_events_not_null_constraints(self):
        """Required fields reject NULL."""
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "INSERT INTO pending_amber_events (event_id) VALUES (?)",
                ("test",),
            )

    def test_seq_unique_index(self):
        """Unique index on (session_id, principal_id, challenge_seq)."""
        kwargs1 = _make_event_kwargs(event_id="evt_1", challenge_seq=1)
        kwargs2 = _make_event_kwargs(event_id="evt_2", challenge_seq=1)  # same seq
        self.store.issue_amber_event(**kwargs1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.issue_amber_event(**kwargs2)

    def test_different_sessions_same_seq_ok(self):
        """Different sessions can use the same challenge_seq."""
        kwargs1 = _make_event_kwargs(event_id="evt_1", session_id="sess_a", challenge_seq=1)
        kwargs2 = _make_event_kwargs(event_id="evt_2", session_id="sess_b", challenge_seq=1)
        self.store.issue_amber_event(**kwargs1)
        self.store.issue_amber_event(**kwargs2)  # Should not raise

    def test_jti_unique_constraint(self):
        """JTI uniqueness enforced at DB level."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_1")
        ok, _ = self.store.validate_and_apply(**approval)
        self.assertTrue(ok)
        # Try to insert same JTI directly
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "INSERT INTO used_mediator_tokens (jti, event_id, session_id, used_at) VALUES (?, ?, ?, ?)",
                ("jti_1", "evt_x", "sess_x", time.time()),
            )

    def test_indexes_exist(self):
        """Required indexes are present."""
        rows = self.store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        index_names = {r["name"] for r in rows}
        self.assertIn("idx_amber_seq_unique", index_names)
        self.assertIn("idx_amber_pattern_risk", index_names)
        self.assertIn("idx_amber_session_status", index_names)
        self.assertIn("idx_tokens_session", index_names)

    def test_status_check_constraint(self):
        """Status column rejects invalid values."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._conn.execute(
                "UPDATE pending_amber_events SET status = 'bogus' WHERE event_id = ?",
                (kwargs["event_id"],),
            )


class TestAmberStoreIssuance(unittest.TestCase):
    """GO-04: Issuance persists exact wire values."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_issue_persists_all_fields(self):
        """Every field matches what was issued."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        row = self.store.get_pending_event(kwargs["event_id"])
        self.assertIsNotNone(row)
        self.assertEqual(row["event_id"], kwargs["event_id"])
        self.assertEqual(row["session_id"], kwargs["session_id"])
        self.assertEqual(row["pattern_id"], kwargs["pattern_id"])
        self.assertEqual(row["action_hash"], kwargs["action_hash"])
        self.assertEqual(row["challenge_nonce"], kwargs["challenge_nonce"])
        self.assertEqual(row["challenge_seq"], kwargs["challenge_seq"])
        self.assertEqual(row["challenge_expires_at"], kwargs["challenge_expires_at"])
        self.assertEqual(row["risk_tier"], kwargs["risk_tier"])
        self.assertEqual(row["risk_capsule_hash"], kwargs["risk_capsule_hash"])
        self.assertEqual(row["batch_group_key"], kwargs["batch_group_key"])
        self.assertEqual(row["batch_max_size"], kwargs["batch_max_size"])
        self.assertEqual(row["batchable"], 1)
        self.assertEqual(row["tool_name"], kwargs["tool_name"])
        self.assertEqual(row["destination_scope"], kwargs["destination_scope"])
        self.assertEqual(row["taint_level"], kwargs["taint_level"])
        self.assertEqual(row["status"], "pending")

    def test_challenge_seq_increments(self):
        """next_challenge_seq returns monotonically increasing values."""
        self.assertEqual(self.store.next_challenge_seq("sess_1"), 1)
        kwargs1 = _make_event_kwargs(event_id="evt_1", challenge_seq=1)
        self.store.issue_amber_event(**kwargs1)
        self.assertEqual(self.store.next_challenge_seq("sess_1"), 2)
        kwargs2 = _make_event_kwargs(event_id="evt_2", challenge_seq=2)
        self.store.issue_amber_event(**kwargs2)
        self.assertEqual(self.store.next_challenge_seq("sess_1"), 3)

    def test_issue_survives_reopen(self):
        """Issued event persists across store close/reopen (durable)."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        self.store.close()
        # Reopen
        store2 = AmberEventStore(self.db_path)
        store2.initialize()
        row = store2.get_pending_event(kwargs["event_id"])
        self.assertIsNotNone(row)
        self.assertEqual(row["pattern_id"], kwargs["pattern_id"])
        store2.close()


class TestAmberStoreValidation(unittest.TestCase):
    """GO-05 + GO-06: Exact-match validation + expiry/sequence enforcement."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def _issue_and_approve(self, **event_overrides):
        """Issue an event and return matching approval kwargs."""
        kwargs = _make_event_kwargs(**event_overrides)
        self.store.issue_amber_event(**kwargs)
        return kwargs, _make_approval_kwargs(kwargs)

    def test_valid_approval_accepted(self):
        """A correctly matching token is accepted."""
        kwargs, approval = self._issue_and_approve()
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_event_marked_approved(self):
        """After approval, event status is 'approved'."""
        kwargs, approval = self._issue_and_approve()
        self.store.validate_and_apply(**approval)
        row = self.store.get_pending_event(kwargs["event_id"])
        self.assertEqual(row["status"], "approved")
        self.assertIsNotNone(row["resolved_at"])

    def test_mismatch_pattern_id(self):
        """Wrong pattern_id → reject."""
        kwargs, approval = self._issue_and_approve()
        approval["pattern_id"] = "pat_WRONG"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_PATTERN_ID)

    def test_mismatch_nonce(self):
        """Wrong challenge_nonce → reject."""
        kwargs, approval = self._issue_and_approve()
        approval["challenge_nonce"] = "WRONG_NONCE"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_NONCE)

    def test_mismatch_action_hash(self):
        """Wrong action_hash → reject (confused deputy protection)."""
        kwargs, approval = self._issue_and_approve()
        approval["action_hash"] = "act_TAMPERED"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_ACTION_HASH)

    def test_mismatch_risk_tier(self):
        """Wrong risk_tier → reject."""
        kwargs, approval = self._issue_and_approve()
        approval["risk_tier"] = "AMBER_LOW"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_RISK_TIER)

    def test_mismatch_capsule_hash(self):
        """Wrong capsule hash → reject (tamper detection)."""
        kwargs, approval = self._issue_and_approve()
        approval["presented_capsule_hash"] = "cap_TAMPERED"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_CAPSULE_HASH)

    def test_mismatch_seq(self):
        """Wrong challenge_seq → reject."""
        kwargs, approval = self._issue_and_approve()
        approval["challenge_seq"] = 999
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.FIELD_MISMATCH_SEQ)

    def test_event_not_found(self):
        """Non-existent event_id → reject."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs)
        approval["event_id"] = "evt_NONEXISTENT"
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.EVENT_NOT_FOUND)

    def test_expired_challenge_rejected(self):
        """Expired challenge → reject."""
        kwargs = _make_event_kwargs(challenge_expires_at=_past_expiry())
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs)
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.CHALLENGE_EXPIRED)

    def test_stale_sequence_rejected(self):
        """If a higher seq is already approved, lower seq is stale."""
        # Issue seq 1 and seq 2
        kwargs1 = _make_event_kwargs(event_id="evt_1", challenge_seq=1)
        kwargs2 = _make_event_kwargs(event_id="evt_2", challenge_seq=2)
        self.store.issue_amber_event(**kwargs1)
        self.store.issue_amber_event(**kwargs2)
        # Approve seq 2 first
        approval2 = _make_approval_kwargs(kwargs2, jti="jti_2")
        ok, _ = self.store.validate_and_apply(**approval2)
        self.assertTrue(ok)
        # Now try to approve seq 1 → stale
        approval1 = _make_approval_kwargs(kwargs1, jti="jti_1")
        ok, reason = self.store.validate_and_apply(**approval1)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.SEQUENCE_STALE)


class TestAmberStoreReplay(unittest.TestCase):
    """GO-07: Replay defence end-to-end."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_first_use_accepted(self):
        """First use of a JTI is accepted."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_once")
        ok, _ = self.store.validate_and_apply(**approval)
        self.assertTrue(ok)

    def test_second_use_blocked(self):
        """Second use of same JTI is blocked with REPLAY_DETECTED."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_replay")
        ok1, _ = self.store.validate_and_apply(**approval)
        self.assertTrue(ok1)
        # Second attempt — event is already approved, but replay check comes first
        ok2, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok2)
        self.assertEqual(reason, AmberRejectReason.REPLAY_DETECTED)

    def test_replay_survives_restart(self):
        """Replay block persists across store close/reopen."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_persist")
        ok, _ = self.store.validate_and_apply(**approval)
        self.assertTrue(ok)
        self.store.close()
        # Reopen
        store2 = AmberEventStore(self.db_path)
        store2.initialize()
        self.assertTrue(store2.is_token_used("jti_persist"))
        store2.close()

    def test_different_jti_for_different_events(self):
        """Different events need different JTIs."""
        kwargs1 = _make_event_kwargs(event_id="evt_1", challenge_seq=1)
        kwargs2 = _make_event_kwargs(event_id="evt_2", challenge_seq=2)
        self.store.issue_amber_event(**kwargs1)
        self.store.issue_amber_event(**kwargs2)
        # Approve evt_1 with jti_a
        ok1, _ = self.store.validate_and_apply(**_make_approval_kwargs(kwargs1, jti="jti_a"))
        self.assertTrue(ok1)
        # Try to approve evt_2 with same jti_a → replay
        ok2, reason = self.store.validate_and_apply(**_make_approval_kwargs(kwargs2, jti="jti_a"))
        self.assertFalse(ok2)
        self.assertEqual(reason, AmberRejectReason.REPLAY_DETECTED)


class TestAmberStoreAtomic(unittest.TestCase):
    """GO-08: Atomic state transitions — no double-apply."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_double_apply_rejected(self):
        """Approving an already-approved event fails."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_first")
        ok1, _ = self.store.validate_and_apply(**approval)
        self.assertTrue(ok1)
        # Second apply with different JTI
        approval2 = _make_approval_kwargs(kwargs, jti="jti_second")
        ok2, reason = self.store.validate_and_apply(**approval2)
        self.assertFalse(ok2)
        self.assertEqual(reason, AmberRejectReason.EVENT_ALREADY_RESOLVED)

    def test_deny_then_approve_rejected(self):
        """Denied events cannot be subsequently approved."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        self.store.deny_event(kwargs["event_id"])
        approval = _make_approval_kwargs(kwargs, jti="jti_after_deny")
        ok, reason = self.store.validate_and_apply(**approval)
        self.assertFalse(ok)
        self.assertEqual(reason, AmberRejectReason.EVENT_ALREADY_RESOLVED)

    def test_approve_then_deny_noop(self):
        """Denying an already-approved event is a no-op."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs)
        self.store.validate_and_apply(**approval)
        result = self.store.deny_event(kwargs["event_id"])
        self.assertFalse(result)  # No rows affected
        row = self.store.get_pending_event(kwargs["event_id"])
        self.assertEqual(row["status"], "approved")  # Still approved

    def test_token_recorded_atomically(self):
        """Token use is recorded in the same transaction as approval."""
        kwargs = _make_event_kwargs()
        self.store.issue_amber_event(**kwargs)
        approval = _make_approval_kwargs(kwargs, jti="jti_atomic")
        self.store.validate_and_apply(**approval)
        # Both should be committed
        self.assertTrue(self.store.is_token_used("jti_atomic"))
        row = self.store.get_pending_event(kwargs["event_id"])
        self.assertEqual(row["status"], "approved")


class TestAmberStoreExpiry(unittest.TestCase):
    """Additional expiry and lifecycle tests."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = Path(self.tmp) / "test_amber.db"
        self.store = AmberEventStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.store.close()

    def test_expire_stale_events(self):
        """expire_stale_events marks past-due events as expired."""
        kwargs = _make_event_kwargs(challenge_expires_at=_past_expiry())
        self.store.issue_amber_event(**kwargs)
        count = self.store.expire_stale_events()
        self.assertEqual(count, 1)
        row = self.store.get_pending_event(kwargs["event_id"])
        self.assertEqual(row["status"], "expired")

    def test_get_pending_events_filters(self):
        """get_pending_events returns only matching status."""
        kwargs1 = _make_event_kwargs(event_id="evt_1", challenge_seq=1)
        kwargs2 = _make_event_kwargs(event_id="evt_2", challenge_seq=2)
        self.store.issue_amber_event(**kwargs1)
        self.store.issue_amber_event(**kwargs2)
        # Approve evt_1
        self.store.validate_and_apply(**_make_approval_kwargs(kwargs1, jti="jti_1"))
        pending = self.store.get_pending_events("sess_1", status="pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["event_id"], "evt_2")
        approved = self.store.get_pending_events("sess_1", status="approved")
        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0]["event_id"], "evt_1")


if __name__ == "__main__":
    unittest.main()
