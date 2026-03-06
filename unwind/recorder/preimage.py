"""CR-AFT pre-image builder — single source of truth for chain hashing.

Schema-versioned: v1 preserves legacy behavior exactly, v2+ uses
canonical JSON pre-image with extensible attestation fields.
"""
import hashlib
import json
from typing import Optional


# Supported schema versions
SCHEMA_V1 = 1
SCHEMA_V2 = 2
SUPPORTED_SCHEMAS = frozenset({SCHEMA_V1, SCHEMA_V2})


def build_action_hash(tool: str, target_canonical: Optional[str],
                      parameters_hash: Optional[str]) -> str:
    """Compute action hash from tool call fields (shared by all schema versions)."""
    data = f"{tool}:{target_canonical or ''}:{parameters_hash or ''}"
    return hashlib.sha256(data.encode()).hexdigest()


def build_event_preimage_v1(prev_hash: Optional[str], event_id: str,
                            timestamp: float, action_hash: str) -> bytes:
    """Legacy v1 pre-image: colon-separated string.

    Exactly matches the original _compute_chain_hash formula:
        SHA-256(prev_hash : event_id : timestamp : action_hash)
    """
    prev = prev_hash or "genesis"
    data = f"{prev}:{event_id}:{timestamp}:{action_hash}"
    return data.encode()


def build_event_preimage_v2(prev_hash: Optional[str], event_id: str,
                            timestamp: float, action_hash: str,
                            host_id: Optional[str] = None,
                            location_hint: Optional[str] = None) -> bytes:
    """v2 pre-image: canonical JSON with extensible attestation fields.

    Stable key order (sorted), UTF-8 encoded. Nullable fields included
    as null (not omitted) for deterministic hashing.
    """
    obj = {
        "action_hash": action_hash,
        "event_id": event_id,
        "host_id": host_id,
        "location_hint": location_hint,
        "prev_hash": prev_hash or "genesis",
        "schema_version": SCHEMA_V2,
        "timestamp": timestamp,
    }
    # Canonical: sorted keys, no whitespace, ensure_ascii for determinism
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def build_event_preimage(schema_version: int, prev_hash: Optional[str],
                         event_id: str, timestamp: float,
                         action_hash: str, **kwargs) -> bytes:
    """Dispatch to the correct pre-image builder by schema version.

    Raises ValueError for unknown schema versions.
    """
    if schema_version == SCHEMA_V1:
        return build_event_preimage_v1(prev_hash, event_id, timestamp,
                                       action_hash)
    elif schema_version == SCHEMA_V2:
        return build_event_preimage_v2(prev_hash, event_id, timestamp,
                                       action_hash,
                                       host_id=kwargs.get("host_id"),
                                       location_hint=kwargs.get("location_hint"))
    else:
        raise ValueError(f"Unknown schema version: {schema_version}. "
                         f"Supported: {sorted(SUPPORTED_SCHEMAS)}")


def compute_chain_hash(schema_version: int, prev_hash: Optional[str],
                       event_id: str, timestamp: float,
                       action_hash: str, **kwargs) -> str:
    """Compute the CR-AFT chain hash for an event.

    Returns hex SHA-256 digest.
    """
    preimage = build_event_preimage(schema_version, prev_hash, event_id,
                                    timestamp, action_hash, **kwargs)
    return hashlib.sha256(preimage).hexdigest()
