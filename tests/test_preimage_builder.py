"""Tests for CR-AFT pre-image builder — v1 compatibility + v2 behavior."""
import hashlib
import json
import pytest

from unwind.recorder.preimage import (
    build_action_hash,
    build_event_preimage,
    build_event_preimage_v1,
    build_event_preimage_v2,
    compute_chain_hash,
    SCHEMA_V1,
    SCHEMA_V2,
    SUPPORTED_SCHEMAS,
)


class TestActionHash:
    """Action hash must match legacy behavior exactly."""

    def test_basic(self):
        h = build_action_hash("fs_write", "/tmp/test.txt", "abc123")
        expected = hashlib.sha256("fs_write:/tmp/test.txt:abc123".encode()).hexdigest()
        assert h == expected

    def test_none_fields(self):
        h = build_action_hash("fs_write", None, None)
        expected = hashlib.sha256("fs_write::".encode()).hexdigest()
        assert h == expected

    def test_empty_strings(self):
        h = build_action_hash("fs_write", "", "")
        expected = hashlib.sha256("fs_write::".encode()).hexdigest()
        assert h == expected


class TestV1PreImage:
    """v1 must exactly reproduce legacy _compute_chain_hash behavior."""

    def test_genesis(self):
        preimage = build_event_preimage_v1(None, "evt_001", 1000.0, "ahash")
        assert preimage == b"genesis:evt_001:1000.0:ahash"

    def test_with_prev(self):
        preimage = build_event_preimage_v1("prevhash", "evt_002", 2000.5, "bhash")
        assert preimage == b"prevhash:evt_002:2000.5:bhash"

    def test_chain_hash_matches_legacy(self):
        """Ensure compute_chain_hash(v1) produces identical output to legacy code."""
        prev = "abc123"
        eid = "evt_test"
        ts = 1709000000.0
        action_hash = hashlib.sha256("fs_write:/tmp/x:phash".encode()).hexdigest()

        # Legacy formula
        legacy = hashlib.sha256(
            f"{prev}:{eid}:{ts}:{action_hash}".encode()
        ).hexdigest()

        # New builder
        result = compute_chain_hash(SCHEMA_V1, prev, eid, ts, action_hash)
        assert result == legacy

    def test_genesis_chain_hash_matches_legacy(self):
        eid = "evt_first"
        ts = 1709000000.0
        action_hash = "deadbeef"

        legacy = hashlib.sha256(
            f"genesis:{eid}:{ts}:{action_hash}".encode()
        ).hexdigest()

        result = compute_chain_hash(SCHEMA_V1, None, eid, ts, action_hash)
        assert result == legacy


class TestV2PreImage:
    """v2 uses canonical JSON with extensible fields."""

    def test_canonical_json_structure(self):
        preimage = build_event_preimage_v2(
            "prev", "evt_1", 1000.0, "ahash",
            host_id="pi5", location_hint="London, GB"
        )
        obj = json.loads(preimage)
        assert obj["schema_version"] == 2
        assert obj["prev_hash"] == "prev"
        assert obj["event_id"] == "evt_1"
        assert obj["timestamp"] == 1000.0
        assert obj["action_hash"] == "ahash"
        assert obj["host_id"] == "pi5"
        assert obj["location_hint"] == "London, GB"

    def test_null_fields_included(self):
        """Nullable fields must appear as null, not be omitted."""
        preimage = build_event_preimage_v2("prev", "evt_1", 1000.0, "ahash")
        obj = json.loads(preimage)
        assert "host_id" in obj
        assert obj["host_id"] is None
        assert "location_hint" in obj
        assert obj["location_hint"] is None

    def test_genesis(self):
        preimage = build_event_preimage_v2(None, "evt_1", 1000.0, "ahash")
        obj = json.loads(preimage)
        assert obj["prev_hash"] == "genesis"

    def test_deterministic(self):
        """Same inputs must always produce same bytes."""
        a = build_event_preimage_v2("p", "e", 1.0, "a", host_id="h", location_hint="l")
        b = build_event_preimage_v2("p", "e", 1.0, "a", host_id="h", location_hint="l")
        assert a == b

    def test_key_order_is_sorted(self):
        preimage = build_event_preimage_v2("p", "e", 1.0, "a")
        keys = list(json.loads(preimage).keys())
        assert keys == sorted(keys)

    def test_v2_differs_from_v1(self):
        """v1 and v2 must produce different hashes for same event data."""
        h1 = compute_chain_hash(SCHEMA_V1, "prev", "evt", 1000.0, "ahash")
        h2 = compute_chain_hash(SCHEMA_V2, "prev", "evt", 1000.0, "ahash")
        assert h1 != h2

    def test_host_id_changes_hash(self):
        h1 = compute_chain_hash(SCHEMA_V2, "p", "e", 1.0, "a", host_id=None)
        h2 = compute_chain_hash(SCHEMA_V2, "p", "e", 1.0, "a", host_id="myhost")
        assert h1 != h2

    def test_location_hint_changes_hash(self):
        h1 = compute_chain_hash(SCHEMA_V2, "p", "e", 1.0, "a", location_hint=None)
        h2 = compute_chain_hash(SCHEMA_V2, "p", "e", 1.0, "a", location_hint="London")
        assert h1 != h2


class TestSchemaDispatch:
    """build_event_preimage dispatches correctly by version."""

    def test_v1_dispatch(self):
        result = build_event_preimage(SCHEMA_V1, "p", "e", 1.0, "a")
        direct = build_event_preimage_v1("p", "e", 1.0, "a")
        assert result == direct

    def test_v2_dispatch(self):
        result = build_event_preimage(SCHEMA_V2, "p", "e", 1.0, "a",
                                      host_id="h", location_hint="l")
        direct = build_event_preimage_v2("p", "e", 1.0, "a",
                                         host_id="h", location_hint="l")
        assert result == direct

    def test_unknown_version_raises(self):
        with pytest.raises(ValueError, match="Unknown schema version: 99"):
            build_event_preimage(99, "p", "e", 1.0, "a")

    def test_supported_schemas_constant(self):
        assert SCHEMA_V1 in SUPPORTED_SCHEMAS
        assert SCHEMA_V2 in SUPPORTED_SCHEMAS
        assert 99 not in SUPPORTED_SCHEMAS
