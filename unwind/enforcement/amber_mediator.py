"""Amber Mediator Protocol (R-AMBER-MED-001).

Generates pattern IDs, batch hints, and challenge nonces for the
amber gate response. These fields enable an intelligent mediator
(the user's inference-layer brain) to batch, narrate, and manage
amber confirmations without compromising security.

Framework-agnostic: this module defines the wire format only.
How the mediator consumes these fields is the framework's concern.
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Constants (per R-AMBER-MED-001 v1.1.0)
# ---------------------------------------------------------------------------

# Batch size caps by risk tier — CRITICAL is never batchable
AMBER_BATCH_CAPS = {
    "AMBER_LOW": 20,
    "AMBER_HIGH": 5,
    "AMBER_CRITICAL": 1,
}

# Cryptographic nonce: 24 bytes (192-bit), base64url-encoded
CHALLENGE_NONCE_BYTES = 24

# Challenge TTL: must be in 60-120s window per spec
CHALLENGE_TTL_SECONDS = 90

# Pattern ID version for future-proofing hash inputs
PATTERN_ID_VERSION = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stable_json_hash(payload: dict, hex_len: int = 24) -> str:
    """Deterministic JSON hash — same inputs always produce same hash.

    Canonical JSON serialisation:
      1. Keys sorted alphabetically (sort_keys=True)
      2. Minimal separators with no whitespace: (",", ":")
      3. UTF-8 encoded bytes
      4. SHA-256 of the resulting byte string

    This guarantees: identical semantic payloads → identical byte strings
    → identical SHA-256 digests, regardless of dict insertion order or
    Python version.

    Used by compute_action_hash, build_pattern_id, build_batch_hint,
    and hash_risk_capsule to produce stable, reproducible identifiers.
    """
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:hex_len]


def _normalize_reason_codes(reason_codes: Optional[list]) -> list[str]:
    """Deduplicate and sort reason codes for stable hashing."""
    if not reason_codes:
        return []
    return sorted({str(x).strip() for x in reason_codes if str(x).strip()})


# ---------------------------------------------------------------------------
# Pattern ID
# ---------------------------------------------------------------------------

def build_pattern_id(
    *,
    tool_name: str,
    destination_scope: str,
    risk_tier: str,
    taint_level: str = "NONE",
    reason_codes: Optional[list[str]] = None,
) -> str:
    """Build a stable pattern ID for amber deduplication.

    Intentionally excludes session/principal for semantic stability across runs.
    Scope isolation is enforced separately via group_key + token claims.

    Args:
        tool_name: MCP tool name (e.g., "fs_write")
        destination_scope: Normalized target scope (e.g., "~/projects/")
        risk_tier: One of AMBER_LOW, AMBER_HIGH, AMBER_CRITICAL
        taint_level: Current session taint level
        reason_codes: Pipeline reason codes that triggered amber
    """
    material = {
        "v": PATTERN_ID_VERSION,
        "tool_name": tool_name or "unknown_tool",
        "destination_scope": destination_scope or "unknown_scope",
        "risk_tier": (risk_tier or "AMBER_HIGH").upper(),
        "taint_level": (taint_level or "NONE").upper(),
        "reason_codes": _normalize_reason_codes(reason_codes),
    }
    return f"pat_{_stable_json_hash(material, hex_len=24)}"


# ---------------------------------------------------------------------------
# Batch Hint
# ---------------------------------------------------------------------------

def build_batch_hint(
    *,
    session_id: str,
    tool_name: str,
    destination_scope: str,
    risk_tier: str,
    pattern_id: str,
    principal_id: str = "default",
) -> dict:
    """Build batch hint for amber mediator grouping.

    Group key includes session + principal for isolation.
    Batch caps enforce max grouping per risk tier.
    CRITICAL is never batchable.
    """
    rt = (risk_tier or "AMBER_HIGH").upper()
    cap = AMBER_BATCH_CAPS.get(rt, 1)
    batchable = rt != "AMBER_CRITICAL"

    group_material = {
        "session_id": session_id,
        "principal_id": principal_id,
        "tool_name": tool_name,
        "destination_scope": destination_scope,
        "risk_tier": rt,
        "pattern_id": pattern_id,
    }
    group_key = f"grp_{_stable_json_hash(group_material, hex_len=32)}"

    return {
        "group_key": group_key,
        "max_batch_size": cap,
        "batchable": batchable,
    }


# ---------------------------------------------------------------------------
# Challenge Nonce
# ---------------------------------------------------------------------------

def new_challenge_nonce() -> str:
    """Generate a cryptographic challenge nonce.

    24 random bytes → base64url string (~32 chars), no padding.
    """
    return base64.urlsafe_b64encode(
        secrets.token_bytes(CHALLENGE_NONCE_BYTES)
    ).decode("ascii").rstrip("=")


def challenge_expires_at() -> str:
    """Generate ISO 8601 UTC expiry timestamp for the challenge."""
    return (
        datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    ).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Action Hash
# ---------------------------------------------------------------------------

def compute_action_hash(tool_name: str, arguments: Optional[dict] = None) -> str:
    """Hash the exact tool call for approval token binding.

    Uses canonical JSON (sort_keys=True, fixed separators (",", ":"))
    before SHA-256.  The approval token binds to this hash — parameters
    cannot be changed between approval and execution without producing
    a different hash, which will be rejected by the validation path.
    """
    material = {
        "tool_name": tool_name or "",
        "arguments": arguments or {},
    }
    return f"act_{_stable_json_hash(material, hex_len=32)}"


# ---------------------------------------------------------------------------
# Destination Scope
# ---------------------------------------------------------------------------

def derive_destination_scope(tool_name: str, arguments: Optional[dict] = None) -> str:
    """Derive a normalized destination scope from tool arguments.

    This is the "where" of the action — a directory, host, or resource class.
    Intentionally coarse (not the exact filename) for pattern grouping.
    """
    if arguments is None:
        return "unknown_scope"

    # File tools: use parent directory as scope
    for key in ("path", "file", "target", "filename"):
        if key in arguments:
            path = str(arguments[key])
            # Use parent directory for grouping, not exact file
            parts = path.rsplit("/", 1)
            if len(parts) > 1:
                return parts[0] + "/"
            return "./"

    # Network tools: use hostname as scope
    for key in ("url", "uri", "endpoint"):
        if key in arguments:
            url = str(arguments[key])
            # Extract host from URL
            if "://" in url:
                host = url.split("://", 1)[1].split("/", 0)[0].split(":")[0]
                return host
            return url.split("/")[0]

    # Email tools: use recipient domain
    if "to" in arguments:
        to = str(arguments["to"])
        if "@" in to:
            return to.split("@")[1]
        return to

    return "unknown_scope"


# ---------------------------------------------------------------------------
# Risk Capsule
# ---------------------------------------------------------------------------

def build_risk_capsule(
    *,
    tool_name: str,
    destination_scope: str,
    risk_tier: str,
    taint_level: str,
    reason_codes: Optional[list[str]] = None,
    amber_reason: str = "",
) -> dict:
    """Build the non-editable risk capsule for human display.

    The mediator cannot alter this — UNWIND stores the hash and
    verifies on approval that the human saw the real risk.
    """
    return {
        "tool_name": tool_name,
        "destination_scope": destination_scope,
        "risk_tier": risk_tier,
        "taint_level": taint_level,
        "reason_codes": _normalize_reason_codes(reason_codes),
        "human_summary": amber_reason,
    }


def hash_risk_capsule(capsule: dict) -> str:
    """Hash the risk capsule for tamper detection."""
    return f"cap_{_stable_json_hash(capsule, hex_len=32)}"
