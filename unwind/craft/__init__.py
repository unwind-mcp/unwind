"""CRAFT protocol primitives for UNWIND.

Milestone 1 scope:
- Canonical MAC input construction (Option A)
- Session key derivation
- Ingress verifier core (verify_and_admit)

The capability subsystem is exposed via stubs for later milestones.
"""

from .canonical import canonicalize_for_mac, mac_input_bytes
from .crypto import (
    hkdf_extract,
    hkdf_expand,
    derive_session_keys,
    derive_rekey_prk,
    state_commit_0,
    b64url_encode,
    b64url_decode,
)
from .verifier import (
    CraftSessionState,
    CraftVerifier,
    VerifyResult,
    VerifyError,
)
from .capabilities import (
    CapabilityIssuer,
    CapabilityToken,
    CapabilityDecision,
    CapabilityError,
    CapabilitySubcode,
    ToolCall,
    StepUpChallenge,
)

__all__ = [
    "canonicalize_for_mac",
    "mac_input_bytes",
    "hkdf_extract",
    "hkdf_expand",
    "derive_session_keys",
    "derive_rekey_prk",
    "state_commit_0",
    "b64url_encode",
    "b64url_decode",
    "CraftSessionState",
    "CraftVerifier",
    "VerifyResult",
    "VerifyError",
    "CapabilityIssuer",
    "CapabilityToken",
    "CapabilityDecision",
    "CapabilityError",
    "CapabilitySubcode",
    "ToolCall",
    "StepUpChallenge",
]
