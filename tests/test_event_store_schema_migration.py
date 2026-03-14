"""Tests for CR-AFT schema migration and mixed-version chain verification."""
import os
import tempfile
from pathlib import Path
import pytest

from unwind.recorder.event_store import EventStore
from unwind.recorder.preimage import SCHEMA_V1, SCHEMA_V2


@pytest.fixture
def tmp_store():
    """Create a fresh EventStore in a temp directory."""
    with tempfile.TemporaryDirectory() as d:
        store = EventStore(db_path=Path(d) / "events.db")
        store.initialize()
        yield store


class TestSchemaMigration:
    """DB migration adds new columns without breaking existing data."""

    def test_new_columns_exist(self, tmp_store):
        cols = {r[1] for r in tmp_store._conn.execute(
            "PRAGMA table_info(events)").fetchall()}
        assert "schema_version" in cols
        assert "host_id" in cols
        assert "location_hint" in cols

    def test_idempotent_migration(self, tmp_store):
        """Running initialize() twice must not fail."""
        tmp_store.initialize()
        cols = {r[1] for r in tmp_store._conn.execute(
            "PRAGMA table_info(events)").fetchall()}
        assert "schema_version" in cols

    def test_default_schema_version(self, tmp_store):
        eid = tmp_store.write_pending(
            session_id="s1", tool="fs_read", tool_class="sensor",
            target="/tmp/x", target_canonical="/tmp/x",
            parameters=None, session_tainted=False,
            trust_state="green",
        )
        row = tmp_store._conn.execute(
            "SELECT schema_version FROM events WHERE event_id=?", (eid,)
        ).fetchone()
        assert row["schema_version"] == SCHEMA_V1


class TestAttestationContext:
    """set_attestation_context controls new event fields."""

    def test_default_context(self, tmp_store):
        eid = tmp_store.write_pending(
            session_id="s1", tool="fs_read", tool_class="sensor",
            target="/tmp/x", target_canonical="/tmp/x",
            parameters=None, session_tainted=False,
            trust_state="green",
        )
        row = tmp_store._conn.execute(
            "SELECT schema_version, host_id, location_hint FROM events WHERE event_id=?",
            (eid,)
        ).fetchone()
        assert row["schema_version"] == 1
        assert row["host_id"] is None
        assert row["location_hint"] is None

    def test_v2_context(self, tmp_store):
        tmp_store.set_attestation_context(
            schema_version=SCHEMA_V2,
            host_id="pi5-test",
            location_hint="London, GB",
        )
        eid = tmp_store.write_pending(
            session_id="s1", tool="fs_write", tool_class="actuator",
            target="/tmp/y", target_canonical="/tmp/y",
            parameters={"content": "hello"}, session_tainted=False,
            trust_state="green",
        )
        row = tmp_store._conn.execute(
            "SELECT schema_version, host_id, location_hint FROM events WHERE event_id=?",
            (eid,)
        ).fetchone()
        assert row["schema_version"] == SCHEMA_V2
        assert row["host_id"] == "pi5-test"
        assert row["location_hint"] == "London, GB"


class TestMixedChainVerification:
    """Chains with both v1 and v2 events must verify correctly."""

    def test_v1_only_chain_verifies(self, tmp_store):
        for i in range(5):
            tmp_store.write_pending(
                session_id="s1", tool=f"tool_{i}", tool_class="sensor",
                target=f"/tmp/{i}", target_canonical=f"/tmp/{i}",
                parameters=None, session_tainted=False,
                trust_state="green",
            )
        valid, err = tmp_store.verify_chain()
        assert valid, f"v1-only chain should verify: {err}"

    def test_mixed_v1_v2_chain_verifies(self, tmp_store):
        # Write 3 v1 events
        for i in range(3):
            tmp_store.write_pending(
                session_id="s1", tool=f"tool_{i}", tool_class="sensor",
                target=f"/tmp/{i}", target_canonical=f"/tmp/{i}",
                parameters=None, session_tainted=False,
                trust_state="green",
            )
        # Switch to v2
        tmp_store.set_attestation_context(
            schema_version=SCHEMA_V2,
            host_id="testhost",
            location_hint="Test City",
        )
        # Write 3 v2 events
        for i in range(3, 6):
            tmp_store.write_pending(
                session_id="s1", tool=f"tool_{i}", tool_class="actuator",
                target=f"/tmp/{i}", target_canonical=f"/tmp/{i}",
                parameters={"data": str(i)}, session_tainted=False,
                trust_state="green",
            )
        valid, err = tmp_store.verify_chain()
        assert valid, f"Mixed chain should verify: {err}"

    def test_tampered_host_id_detected(self, tmp_store):
        tmp_store.set_attestation_context(
            schema_version=SCHEMA_V2, host_id="real-host",
        )
        eid = tmp_store.write_pending(
            session_id="s1", tool="fs_write", tool_class="actuator",
            target="/tmp/x", target_canonical="/tmp/x",
            parameters=None, session_tainted=False,
            trust_state="green",
        )
        # Tamper with host_id
        tmp_store._conn.execute(
            "UPDATE events SET host_id=? WHERE event_id=?",
            ("fake-host", eid)
        )
        tmp_store._conn.commit()
        valid, err = tmp_store.verify_chain()
        assert not valid, "Tampered host_id should break chain"

    def test_tampered_location_hint_detected(self, tmp_store):
        tmp_store.set_attestation_context(
            schema_version=SCHEMA_V2, location_hint="London",
        )
        eid = tmp_store.write_pending(
            session_id="s1", tool="fs_write", tool_class="actuator",
            target="/tmp/x", target_canonical="/tmp/x",
            parameters=None, session_tainted=False,
            trust_state="green",
        )
        # Tamper with location
        tmp_store._conn.execute(
            "UPDATE events SET location_hint=? WHERE event_id=?",
            ("Moscow", eid)
        )
        tmp_store._conn.commit()
        valid, err = tmp_store.verify_chain()
        assert not valid, "Tampered location_hint should break chain"

    def test_detailed_verify_mixed_chain(self, tmp_store):
        # v1 events
        for i in range(2):
            tmp_store.write_pending(
                session_id="s1", tool=f"tool_{i}", tool_class="sensor",
                target=f"/t/{i}", target_canonical=f"/t/{i}",
                parameters=None, session_tainted=False,
                trust_state="green",
            )
        # Switch to v2
        tmp_store.set_attestation_context(schema_version=SCHEMA_V2, host_id="h")
        for i in range(2, 4):
            tmp_store.write_pending(
                session_id="s1", tool=f"tool_{i}", tool_class="sensor",
                target=f"/t/{i}", target_canonical=f"/t/{i}",
                parameters=None, session_tainted=False,
                trust_state="green",
            )
        result = tmp_store.verify_chain_detailed()
        assert result["valid"], f"Mixed detailed verify failed: {result}"
        assert result["event_count"] == 4
        assert result["break_count"] == 0
