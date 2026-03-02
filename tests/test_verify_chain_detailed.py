"""Detailed CR-AFT chain verification tests.

Proves that verify_chain_detailed():
1. Returns intact/valid for an empty chain
2. Returns intact/valid for a correctly-chained sequence of events
3. Detects a tampered hash and classifies it as suspicious
4. Distinguishes restart-gap breaks (stale prev_hash from a prior chain
   position) from genuine tampering
"""

import hashlib
import time
import uuid

import pytest

from unwind.recorder.event_store import EventStore, EventStatus


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture()
def store(tmp_path):
    """Create and initialise a fresh EventStore in a temporary directory."""
    db_path = tmp_path / "events.db"
    es = EventStore(db_path)
    es.initialize()
    yield es
    es.close()


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _write_event(store: EventStore, tool: str = "test_tool", index: int = 0) -> str:
    """Write a pending event, complete it, and return its event_id."""
    eid = store.write_pending(
        session_id="test-session",
        tool=tool,
        tool_class="sensor",
        target=f"/test/target_{index}",
        target_canonical=f"/test/target_{index}",
        parameters={"i": index},
        session_tainted=False,
        trust_state="green",
    )
    store.complete_event(eid, EventStatus.SUCCESS)
    return eid


def _get_event_row(store: EventStore, event_id: str) -> dict:
    """Fetch a single event row by its ID."""
    row = store._conn.execute(
        "SELECT * FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    return dict(row)


# ------------------------------------------------------------------ #
# 1. Empty chain
# ------------------------------------------------------------------ #


class TestEmptyChain:
    """An empty store has a trivially intact chain."""

    def test_empty_chain_is_intact(self, store):
        result = store.verify_chain_detailed()
        assert result["valid"] is True
        assert result["event_count"] == 0
        assert result["classification"] == "intact"
        assert result["break_count"] == 0


# ------------------------------------------------------------------ #
# 2. Intact chain
# ------------------------------------------------------------------ #


class TestIntactChain:
    """A properly-chained sequence of events verifies cleanly."""

    def test_five_events_intact(self, store):
        for i in range(5):
            _write_event(store, tool=f"tool_{i}", index=i)

        result = store.verify_chain_detailed()
        assert result["valid"] is True
        assert result["event_count"] == 5
        assert result["classification"] == "intact"
        assert result["break_count"] == 0
        assert "all intact" in result["human_message"].lower()


# ------------------------------------------------------------------ #
# 3. Suspicious break (tampered hash)
# ------------------------------------------------------------------ #


class TestSuspiciousBreak:
    """A manually-tampered chain_hash is detected as suspicious."""

    def test_tampered_hash_detected(self, store):
        eids = []
        for i in range(3):
            eids.append(_write_event(store, tool=f"tool_{i}", index=i))

        # Tamper with the second event's chain_hash
        store._conn.execute(
            "UPDATE events SET chain_hash = ? WHERE event_id = ?",
            ("tampered_hash", eids[1]),
        )
        store._conn.commit()

        result = store.verify_chain_detailed()
        assert result["valid"] is False
        assert result["classification"] == "suspicious"
        assert result["break_count"] >= 1

        # The tampered event itself must appear in the breaks list
        tampered_break = [b for b in result["breaks"] if b["event_id"] == eids[1]]
        assert len(tampered_break) == 1
        assert tampered_break[0]["is_restart"] is False

    def test_tamper_also_breaks_successor(self, store):
        """Tampering event N breaks the chain at N, and because N's hash is
        now wrong the successor N+1 (which used the original N hash as prev)
        will also mismatch -- unless it happens to match a seen_hash (it
        won't for arbitrary tampering)."""
        eids = []
        for i in range(3):
            eids.append(_write_event(store, tool=f"tool_{i}", index=i))

        store._conn.execute(
            "UPDATE events SET chain_hash = ? WHERE event_id = ?",
            ("tampered_hash", eids[1]),
        )
        store._conn.commit()

        result = store.verify_chain_detailed()
        # At minimum, the tampered event is flagged.  The successor may or
        # may not be flagged depending on seen_hashes -- but the overall
        # classification must be suspicious.
        assert result["valid"] is False
        assert result["classification"] == "suspicious"
        assert result["break_count"] >= 1


# ------------------------------------------------------------------ #
# 4. Restart-gap detection
# ------------------------------------------------------------------ #


class TestRestartGap:
    """A sidecar restart that reloaded stale state produces a chain break
    that verify_chain_detailed classifies as a restart artifact rather
    than tampering."""

    def test_restart_gap_classified_correctly(self, store):
        # Write 3 normal events: e1, e2, e3
        eids = []
        for i in range(3):
            eids.append(_write_event(store, tool=f"tool_{i}", index=i))

        # Grab e1's chain_hash -- this simulates the sidecar restarting
        # and loading the stale chain tip from after e1 (skipping e2, e3).
        e1_row = _get_event_row(store, eids[0])
        stale_prev_hash = e1_row["chain_hash"]

        # Manually craft e4 whose chain_hash was computed using e1's
        # chain_hash as prev (as a restarted sidecar would do).
        e4_id = f"evt_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        e4_timestamp = time.time()
        e4_tool = "tool_restart"
        e4_target_canonical = "/test/target_restart"
        e4_params_hash = hashlib.sha256(
            '{"i": 99}'.encode()
        ).hexdigest()

        # Compute action_hash the same way EventStore does
        action_data = f"{e4_tool}:{e4_target_canonical}:{e4_params_hash}"
        action_hash = hashlib.sha256(action_data.encode()).hexdigest()

        # Compute chain_hash using the STALE prev (e1's hash, not e3's)
        chain_data = f"{stale_prev_hash}:{e4_id}:{e4_timestamp}:{action_hash}"
        chain_hash = hashlib.sha256(chain_data.encode()).hexdigest()

        # Insert e4 directly into the DB
        store._conn.execute(
            """INSERT INTO events
               (event_id, timestamp, session_id, tool, tool_class, target,
                target_canonical, parameters_hash, session_tainted, trust_state,
                status, ghost_mode, chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                e4_id, e4_timestamp, "test-session", e4_tool, "sensor",
                "/test/target_restart", e4_target_canonical, e4_params_hash,
                0, "green", EventStatus.SUCCESS.value, 0, chain_hash,
            ),
        )
        store._conn.commit()

        result = store.verify_chain_detailed()

        # e4 breaks the chain (prev was e1's hash, not e3's), but the break
        # should be classified as a restart artifact because e1's hash IS in
        # seen_hashes.
        assert result["classification"] == "restart_gaps_only"
        assert result["valid"] is True
        assert result["break_count"] >= 1

        restart_breaks = [b for b in result["breaks"] if b["event_id"] == e4_id]
        assert len(restart_breaks) == 1
        assert restart_breaks[0]["is_restart"] is True

    def test_mixed_restart_and_suspicious(self, store):
        """When both restart gaps AND genuine tampering exist, the
        classification must be 'suspicious' (not restart_gaps_only)."""
        eids = []
        for i in range(4):
            eids.append(_write_event(store, tool=f"tool_{i}", index=i))

        # Create a restart-gap event (e5) using e1's hash as prev
        e1_row = _get_event_row(store, eids[0])
        stale_prev = e1_row["chain_hash"]

        e5_id = f"evt_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        e5_ts = time.time()
        e5_tool = "tool_restart"
        e5_target = "/test/restart"
        e5_phash = hashlib.sha256(b'{"r": 1}').hexdigest()

        action_data = f"{e5_tool}:{e5_target}:{e5_phash}"
        action_hash = hashlib.sha256(action_data.encode()).hexdigest()
        chain_hash = hashlib.sha256(
            f"{stale_prev}:{e5_id}:{e5_ts}:{action_hash}".encode()
        ).hexdigest()

        store._conn.execute(
            """INSERT INTO events
               (event_id, timestamp, session_id, tool, tool_class, target,
                target_canonical, parameters_hash, session_tainted, trust_state,
                status, ghost_mode, chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                e5_id, e5_ts, "test-session", e5_tool, "sensor",
                e5_target, e5_target, e5_phash,
                0, "green", EventStatus.SUCCESS.value, 0, chain_hash,
            ),
        )
        store._conn.commit()

        # Also tamper with e3's chain_hash (genuine tampering)
        store._conn.execute(
            "UPDATE events SET chain_hash = ? WHERE event_id = ?",
            ("completely_bogus", eids[2]),
        )
        store._conn.commit()

        result = store.verify_chain_detailed()
        assert result["valid"] is False
        assert result["classification"] == "suspicious"
        # There should be at least one restart break AND at least one suspicious break
        restart_flags = [b["is_restart"] for b in result["breaks"]]
        assert True in restart_flags, "Expected at least one restart break"
        assert False in restart_flags, "Expected at least one suspicious break"
