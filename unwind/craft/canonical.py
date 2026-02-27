"""Canonical encoding helpers for CRAFT.

CRAFT v4.2 Option A:
MAC_input(envelope) = UTF-8 bytes of the JCS-canonical JSON object formed by
removing `mac` and `state_commit` fields.
"""

from __future__ import annotations

import json
from typing import Any


def _normalize(value: Any) -> Any:
    """Recursively normalize values for deterministic JSON encoding.

    This is a practical deterministic encoder for Python structures.
    It enforces finite numbers and deterministic map ordering through
    json.dumps(sort_keys=True, separators=...).
    """
    if isinstance(value, dict):
        # Duplicate keys cannot be represented in Python dict; upstream JSON
        # parsers should reject duplicates before conversion.
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, tuple):
        return [_normalize(v) for v in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Non-finite float values are not allowed in CRAFT canonical encoding")
        return value
    raise TypeError(f"Unsupported type in canonical encoding: {type(value)!r}")


def canonicalize_json(value: Any) -> str:
    """Return deterministic JSON string (JCS-like practical subset)."""
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonicalize_for_mac(envelope: dict[str, Any]) -> str:
    """Build Option-A MAC object by removing `mac` and `state_commit`."""
    reduced = {k: v for k, v in envelope.items() if k not in {"mac", "state_commit"}}
    return canonicalize_json(reduced)


def mac_input_bytes(envelope: dict[str, Any]) -> bytes:
    """Return UTF-8 MAC input bytes for envelope (Option A)."""
    return canonicalize_for_mac(envelope).encode("utf-8")
