"""Signed health schema — unwind.system_health.v1.

Provides HMAC-SHA256 signing and verification for sidecar health payloads,
freshness checking (TTL), and monotonic sequence tracking to prevent replay.

Key derivation uses HKDF (key separation) so the bearer token is never used
directly as an HMAC key.
"""

from __future__ import annotations

import copy
import hmac as _hmac
import socket
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from ..craft.canonical import canonicalize_json
from ..craft.crypto import b64url_decode, b64url_encode, hkdf_expand, hkdf_extract, hmac_sha256


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HealthState(str, Enum):
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class ReasonCode(str, Enum):
    OK = "OK"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PAYLOAD_STALE = "PAYLOAD_STALE"
    SEQ_REPLAY_OR_ROLLBACK = "SEQ_REPLAY_OR_ROLLBACK"
    SIDECAR_UNREACHABLE = "SIDECAR_UNREACHABLE"
    GATEWAY_UNHEALTHY = "GATEWAY_UNHEALTHY"
    ADAPTER_AUTH_FAIL_401 = "ADAPTER_AUTH_FAIL_401"
    WATCHDOG_STALE = "WATCHDOG_STALE"
    PIPELINE_INVARIANT_FAIL = "PIPELINE_INVARIANT_FAIL"
    AUDIT_CHAIN_DEGRADED = "AUDIT_CHAIN_DEGRADED"


# Schema version constant
SCHEMA_VERSION = "unwind.system_health.v1"

# Fields stripped before canonical encoding for signature
_SIG_EXCLUDED_FIELDS = frozenset({"sig_valid"})


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_health_signing_key(shared_secret: str) -> bytes:
    """Derive a 256-bit HMAC key for health payload signing.

    Uses HKDF with a domain-specific salt/info so the bearer token is never
    used directly as an HMAC key (key separation).
    """
    prk = hkdf_extract(
        salt=b"unwind-health-v1",
        ikm=shared_secret.encode("utf-8"),
    )
    return hkdf_expand(prk, b"unwind-health-sig", 32)


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def _canonical_for_signing(payload: dict[str, Any]) -> bytes:
    """Build the canonical byte string for HMAC input.

    Strips ``sig.value`` (the signature itself) and ``sig_valid`` (a
    verification-side annotation) from a deep copy before canonicalising.
    """
    cleaned = copy.deepcopy(payload)

    # Remove verification-side fields
    for field in _SIG_EXCLUDED_FIELDS:
        cleaned.pop(field, None)

    # Remove the signature value but keep the rest of the sig envelope
    sig = cleaned.get("sig")
    if isinstance(sig, dict):
        sig.pop("value", None)

    return canonicalize_json(cleaned).encode("utf-8")


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------


def sign_health_payload(payload: dict[str, Any], key: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical payload, return base64url string."""
    canonical = _canonical_for_signing(payload)
    mac = hmac_sha256(key, canonical)
    return b64url_encode(mac)


def verify_health_signature(payload: dict[str, Any], key: bytes) -> bool:
    """Verify the HMAC-SHA256 signature in ``payload["sig"]["value"]``.

    Returns False if the signature is missing, malformed, or invalid.
    Uses constant-time comparison.
    """
    sig = payload.get("sig")
    if not isinstance(sig, dict):
        return False
    sig_value = sig.get("value")
    if not isinstance(sig_value, str) or not sig_value:
        return False

    try:
        provided_mac = b64url_decode(sig_value)
    except Exception:
        return False

    canonical = _canonical_for_signing(payload)
    expected_mac = hmac_sha256(key, canonical)
    return _hmac.compare_digest(provided_mac, expected_mac)


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


def check_freshness(payload: dict[str, Any]) -> bool:
    """Return True if the payload is still within its TTL window.

    Checks ``fresh_until`` (ISO 8601). Returns False if missing or expired.
    """
    fresh_until = payload.get("fresh_until")
    if not isinstance(fresh_until, str):
        return False
    try:
        deadline = datetime.fromisoformat(fresh_until.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return now <= deadline
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Sequence tracker
# ---------------------------------------------------------------------------


class SequenceTracker:
    """Track monotonically increasing sequence numbers per instance.

    In-memory — resets on dashboard restart (first response always passes,
    which is safe). Detects replays during normal operation.
    """

    def __init__(self) -> None:
        self._last: dict[str, int] = {}

    def check_and_update(self, instance_id: str, seq: int) -> tuple[bool, bool]:
        """Check and record a sequence number.

        Returns:
            (valid, is_restart):
            - valid=True if seq is acceptable (monotonically increasing or restart)
            - is_restart=True if seq=1 after a higher value (sidecar restarted)
        """
        last = self._last.get(instance_id)

        if last is None:
            # First response from this instance — always accept
            self._last[instance_id] = seq
            return True, False

        if seq > last:
            # Normal monotonic increase
            self._last[instance_id] = seq
            return True, False

        if seq == 1 and last > 1:
            # Restart detected: seq reset to 1 after higher value
            self._last[instance_id] = seq
            return True, True

        # Same or lower (not a restart) — replay or rollback
        return False, False

    def reset(self) -> None:
        """Clear all tracked sequences."""
        self._last.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_instance_id() -> str:
    """Return hostname as instance identifier."""
    return socket.gethostname()


def kid_for_now() -> str:
    """Return key ID string for the current month: ``unwind-health-YYYY-MM``."""
    now = datetime.now(timezone.utc)
    return f"unwind-health-{now.strftime('%Y-%m')}"
