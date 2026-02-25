"""Ed25519 signature verification for supply-chain provider entries.

Implements R-SIG-001 from UNWIND policy v0.2.

Architecture:
    Each provider in the lockfile may carry a signature block:
        {
            "alg": "Ed25519",
            "key_id": "key-name-or-fingerprint",
            "sig": "<hex-encoded Ed25519 signature>"
        }

    The signature covers the canonical representation of the provider entry
    (deterministic JSON: sorted keys, no whitespace). This means:
    - Signature is over the provider's *content*, not the whole lockfile
    - HMAC (R-LOCK-003) protects the lockfile as a whole; signatures
      protect individual provider provenance independently

Key Store:
    A separate JSON file mapping key_id → public key (hex-encoded 32 bytes).
    Kept outside the lockfile so key management is independent.

    Format:
        {
            "version": "1.0",
            "keys": {
                "key-id-1": {
                    "public_key": "<64-char hex>",
                    "owner": "MCP Filesystem Project",
                    "added_at": "2026-02-22T12:00:00Z",
                    "revoked": false
                }
            }
        }

Performance:
    - Key store loaded once at startup (COLD)
    - Signature verification: per-provider on lockfile load (COLD)
    - Cached after first verification (no re-verify on each tool call)
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("unwind.signature_verify")

# Ed25519 constants
ED25519_PUBLIC_KEY_LENGTH = 32  # bytes
ED25519_SIGNATURE_LENGTH = 64  # bytes


class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""
    ED25519 = "Ed25519"


class SignatureVerdict(Enum):
    """Result of signature verification."""
    VALID = "valid"
    INVALID = "invalid"          # Signature doesn't match
    KEY_NOT_FOUND = "key_not_found"  # key_id not in key store
    KEY_REVOKED = "key_revoked"  # Key has been revoked
    NO_SIGNATURE = "no_signature"  # Provider has no signature block
    UNSUPPORTED_ALG = "unsupported_algorithm"
    MALFORMED = "malformed"      # Signature block is missing fields / bad format


class KeyState(Enum):
    """Lifecycle states for a signing key."""
    ACTIVE = "active"            # Key is active and accepting new signatures
    DEPRECATED = "deprecated"    # Key still verifies but shouldn't sign new entries
    REVOKED = "revoked"          # Key is revoked — verification fails immediately


@dataclass
class KeyEntry:
    """A public key entry in the key store."""
    key_id: str
    public_key: bytes  # Raw 32-byte Ed25519 public key
    owner: str = ""
    added_at: Optional[str] = None
    revoked: bool = False
    state: KeyState = KeyState.ACTIVE
    deprecated_at: Optional[str] = None
    revoked_at: Optional[str] = None


@dataclass
class KeyStore:
    """Ed25519 public key store for provider signature verification."""
    version: str = "1.0"
    keys: dict[str, KeyEntry] = field(default_factory=dict)

    def get_key(self, key_id: str) -> Optional[KeyEntry]:
        """Look up a key by ID."""
        return self.keys.get(key_id)

    def add_key(
        self,
        key_id: str,
        public_key: bytes,
        owner: str = "",
    ) -> KeyEntry:
        """Add a public key to the store."""
        if len(public_key) != ED25519_PUBLIC_KEY_LENGTH:
            raise ValueError(
                f"Ed25519 public key must be {ED25519_PUBLIC_KEY_LENGTH} bytes, "
                f"got {len(public_key)}"
            )
        entry = KeyEntry(
            key_id=key_id,
            public_key=public_key,
            owner=owner,
            added_at=datetime.now(timezone.utc).isoformat(),
        )
        self.keys[key_id] = entry
        return entry

    def deprecate_key(self, key_id: str) -> bool:
        """Mark a key as deprecated (still verifies, but no new signatures).

        Used during key rotation overlap window.
        Returns True if key existed and was active.
        """
        entry = self.keys.get(key_id)
        if entry is None:
            return False
        if entry.state != KeyState.ACTIVE:
            return False
        entry.state = KeyState.DEPRECATED
        entry.deprecated_at = datetime.now(timezone.utc).isoformat()
        logger.warning("Key deprecated: %s (owner: %s)", key_id, entry.owner)
        return True

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key. Returns True if key existed and wasn't already revoked."""
        entry = self.keys.get(key_id)
        if entry is None:
            return False
        if entry.state == KeyState.REVOKED:
            return False
        entry.revoked = True
        entry.state = KeyState.REVOKED
        entry.revoked_at = datetime.now(timezone.utc).isoformat()
        logger.warning("Key revoked: %s (owner: %s)", key_id, entry.owner)
        return True

    def is_revoked(self, key_id: str) -> bool:
        """Check if a key is revoked."""
        entry = self.keys.get(key_id)
        return entry is not None and entry.state == KeyState.REVOKED

    def is_deprecated(self, key_id: str) -> bool:
        """Check if a key is deprecated."""
        entry = self.keys.get(key_id)
        return entry is not None and entry.state == KeyState.DEPRECATED

    def active_keys(self) -> list[KeyEntry]:
        """Get all active (non-revoked, non-deprecated) keys."""
        return [e for e in self.keys.values() if e.state == KeyState.ACTIVE]

    def key_summary(self) -> dict:
        """Return summary of key states."""
        by_state: dict[str, int] = {}
        for entry in self.keys.values():
            s = entry.state.value
            by_state[s] = by_state.get(s, 0) + 1
        return {
            "total": len(self.keys),
            "by_state": by_state,
        }


@dataclass
class SignatureResult:
    """Result of verifying a provider's signature."""
    verdict: SignatureVerdict
    key_id: Optional[str] = None
    reason: str = ""


def canonical_provider_json(provider_data: dict) -> bytes:
    """Produce the canonical JSON representation of a provider entry.

    This is the content that gets signed. Uses sorted keys and no
    extra whitespace for determinism. The 'signature' field itself
    is excluded from the signed content (you can't sign your own signature).

    Args:
        provider_data: Dict of provider fields (name, version, digest, tools, etc.)

    Returns:
        UTF-8 encoded canonical JSON bytes
    """
    # Strip signature from the data before canonicalisation
    signable = {k: v for k, v in sorted(provider_data.items()) if k != "signature"}
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_ed25519(
    public_key_bytes: bytes,
    signature_bytes: bytes,
    message: bytes,
) -> bool:
    """Verify an Ed25519 signature using the cryptography library.

    Returns True if valid, False if invalid or on any error.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error("Ed25519 verification error: %s", e)
        return False


def _sign_ed25519(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private key.

    Used for testing and for signing provider entries during registration.

    Args:
        private_key_bytes: 32-byte Ed25519 private key seed
        message: The message to sign

    Returns:
        64-byte Ed25519 signature
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair.

    Returns:
        (private_key_seed, public_key_bytes) — both 32 bytes
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )

    private_key = Ed25519PrivateKey.generate()
    # Get raw 32-byte seed
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return private_bytes, public_bytes


def verify_provider_signature(
    provider_data: dict,
    key_store: KeyStore,
) -> SignatureResult:
    """Verify the signature on a provider entry.

    Args:
        provider_data: The provider dict from the lockfile (must include 'signature')
        key_store: The key store to look up public keys

    Returns:
        SignatureResult with verdict and details
    """
    sig_block = provider_data.get("signature")
    if not sig_block:
        return SignatureResult(
            verdict=SignatureVerdict.NO_SIGNATURE,
            reason="Provider has no signature block",
        )

    # Validate signature block structure
    alg = sig_block.get("alg")
    key_id = sig_block.get("key_id")
    sig_hex = sig_block.get("sig")

    if not all([alg, key_id, sig_hex]):
        return SignatureResult(
            verdict=SignatureVerdict.MALFORMED,
            key_id=key_id,
            reason=f"Signature block missing required fields (alg={alg}, key_id={key_id}, sig={'present' if sig_hex else 'missing'})",
        )

    # Check algorithm support
    if alg != SignatureAlgorithm.ED25519.value:
        return SignatureResult(
            verdict=SignatureVerdict.UNSUPPORTED_ALG,
            key_id=key_id,
            reason=f"Unsupported signature algorithm: {alg}",
        )

    # Look up key
    key_entry = key_store.get_key(key_id)
    if key_entry is None:
        return SignatureResult(
            verdict=SignatureVerdict.KEY_NOT_FOUND,
            key_id=key_id,
            reason=f"Key '{key_id}' not found in key store",
        )

    # Check revocation
    if key_entry.revoked:
        return SignatureResult(
            verdict=SignatureVerdict.KEY_REVOKED,
            key_id=key_id,
            reason=f"Key '{key_id}' has been revoked",
        )

    # Decode signature
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return SignatureResult(
            verdict=SignatureVerdict.MALFORMED,
            key_id=key_id,
            reason=f"Signature is not valid hex",
        )

    if len(sig_bytes) != ED25519_SIGNATURE_LENGTH:
        return SignatureResult(
            verdict=SignatureVerdict.MALFORMED,
            key_id=key_id,
            reason=f"Signature is {len(sig_bytes)} bytes, expected {ED25519_SIGNATURE_LENGTH}",
        )

    # Compute canonical content and verify
    canonical = canonical_provider_json(provider_data)
    if _verify_ed25519(key_entry.public_key, sig_bytes, canonical):
        return SignatureResult(
            verdict=SignatureVerdict.VALID,
            key_id=key_id,
            reason=f"Signature valid (key: {key_id}, alg: Ed25519)",
        )
    else:
        return SignatureResult(
            verdict=SignatureVerdict.INVALID,
            key_id=key_id,
            reason=f"Signature verification FAILED for key '{key_id}' (R-SIG-001)",
        )


def sign_provider_entry(
    provider_data: dict,
    private_key_bytes: bytes,
    key_id: str,
) -> dict:
    """Sign a provider entry and return the data with signature block added.

    Args:
        provider_data: Provider dict (without signature)
        private_key_bytes: 32-byte Ed25519 private key seed
        key_id: Key identifier for the signing key

    Returns:
        New dict with 'signature' field added
    """
    canonical = canonical_provider_json(provider_data)
    sig_bytes = _sign_ed25519(private_key_bytes, canonical)

    signed = dict(provider_data)
    signed["signature"] = {
        "alg": SignatureAlgorithm.ED25519.value,
        "key_id": key_id,
        "sig": sig_bytes.hex(),
    }
    return signed


# --- Key Store I/O ---

def _key_store_hmac_path(key_store_path: Path) -> Path:
    """Return the HMAC sidecar path for a key store file."""
    return key_store_path.with_suffix(key_store_path.suffix + ".hmac")


def load_key_store(
    path: Path,
    verify_integrity: bool = True,
    hmac_key: Optional[bytes] = None,
    strict: bool = False,
) -> KeyStore:
    """Load a key store from disk with optional HMAC integrity verification.

    Args:
        path: Path to the key store JSON
        verify_integrity: Whether to check HMAC sidecar
        hmac_key: HMAC key bytes (if None, uses lockfile HMAC key derivation)
        strict: If True, reject key store with missing HMAC sidecar
                (no grace period). If False, missing sidecar loads with warning.

    Returns an empty key store if file doesn't exist, is corrupt, or
    fails HMAC verification (fail-closed).
    """
    if not path.exists():
        logger.warning("Key store not found at %s — using empty key store", path)
        return KeyStore()

    try:
        raw_content = path.read_bytes()
    except OSError as e:
        logger.error("Failed to read key store %s: %s", path, e)
        return KeyStore()

    # HMAC integrity check (SENTINEL finding: key store needs protection)
    if verify_integrity:
        from .supply_chain import compute_hmac, verify_hmac, _get_hmac_key

        if hmac_key is None:
            hmac_key_info = _get_hmac_key(path)
            key = hmac_key_info.key
        else:
            key = hmac_key

        sidecar = _key_store_hmac_path(path)
        if sidecar.exists():
            try:
                stored_hmac = sidecar.read_text(encoding="utf-8").strip()
            except OSError:
                stored_hmac = ""

            if stored_hmac and not verify_hmac(raw_content, stored_hmac, key):
                logger.critical(
                    "KEY STORE TAMPER DETECTED at %s — failing closed (R-SIG-001)",
                    path,
                )
                return KeyStore()
        else:
            if strict:
                logger.error(
                    "Key store %s has no HMAC sidecar and strict mode is enabled — "
                    "rejecting unsigned key store (KEYSTORE_HMAC_INVALID)",
                    path,
                )
                return KeyStore()
            logger.warning(
                "Key store %s has no HMAC sidecar — integrity not verified. "
                "Run save_key_store() to sign it.",
                path,
            )

    try:
        data = json.loads(raw_content)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to parse key store %s: %s", path, e)
        return KeyStore()

    return parse_key_store(data)


def parse_key_store(data: dict) -> KeyStore:
    """Parse a key store from a dict."""
    keys = {}
    for kid, kdata in data.get("keys", {}).items():
        try:
            pub_key = bytes.fromhex(kdata.get("public_key", ""))
        except ValueError:
            logger.warning("Invalid public key hex for key '%s' — skipping", kid)
            continue

        if len(pub_key) != ED25519_PUBLIC_KEY_LENGTH:
            logger.warning(
                "Key '%s' has wrong length (%d bytes) — skipping",
                kid, len(pub_key),
            )
            continue

        # Parse state (backward compat: if only 'revoked' bool exists)
        state_str = kdata.get("state", "")
        revoked = kdata.get("revoked", False)
        if state_str:
            try:
                state = KeyState(state_str)
            except ValueError:
                state = KeyState.REVOKED if revoked else KeyState.ACTIVE
        else:
            state = KeyState.REVOKED if revoked else KeyState.ACTIVE

        keys[kid] = KeyEntry(
            key_id=kid,
            public_key=pub_key,
            owner=kdata.get("owner", ""),
            added_at=kdata.get("added_at"),
            revoked=revoked,
            state=state,
            deprecated_at=kdata.get("deprecated_at"),
            revoked_at=kdata.get("revoked_at"),
        )

    return KeyStore(
        version=data.get("version", "1.0"),
        keys=keys,
    )


def save_key_store(
    key_store: KeyStore,
    path: Path,
    sign: bool = True,
    hmac_key: Optional[bytes] = None,
) -> None:
    """Save a key store to disk with HMAC integrity sidecar.

    Args:
        key_store: The key store to save
        path: Destination path for the JSON file
        sign: Whether to write the HMAC sidecar (default True)
        hmac_key: HMAC key bytes (if None, uses lockfile HMAC key derivation)
    """
    data: dict[str, Any] = {
        "version": key_store.version,
        "keys": {},
    }

    for kid, entry in key_store.keys.items():
        d: dict[str, Any] = {
            "public_key": entry.public_key.hex(),
            "owner": entry.owner,
            "added_at": entry.added_at,
            "revoked": entry.revoked,
            "state": entry.state.value,
        }
        if entry.deprecated_at:
            d["deprecated_at"] = entry.deprecated_at
        if entry.revoked_at:
            d["revoked_at"] = entry.revoked_at
        data["keys"][kid] = d

    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2).encode("utf-8")
    path.write_bytes(content)

    # Write HMAC sidecar
    if sign:
        from .supply_chain import compute_hmac, _get_hmac_key

        if hmac_key is None:
            hmac_key_info = _get_hmac_key(path)
            key = hmac_key_info.key
        else:
            key = hmac_key

        sidecar = _key_store_hmac_path(path)
        sidecar.write_text(compute_hmac(content, key), encoding="utf-8")


class SignatureVerifier:
    """Provider signature verification using a key store.

    Plugs into SupplyChainVerifier to replace the signature stub.
    """

    def __init__(self, key_store: KeyStore):
        self.key_store = key_store
        # Cache: provider_id → SignatureResult (avoid re-verifying)
        self._cache: dict[str, SignatureResult] = {}

    def verify(self, provider_id: str, provider_data: dict) -> SignatureResult:
        """Verify a provider's signature, with caching.

        Args:
            provider_id: The provider's lockfile ID
            provider_data: The provider dict from the lockfile

        Returns:
            SignatureResult
        """
        if provider_id in self._cache:
            return self._cache[provider_id]

        result = verify_provider_signature(provider_data, self.key_store)
        self._cache[provider_id] = result
        return result

    def clear_cache(self) -> None:
        """Clear the verification cache (e.g. after key rotation)."""
        self._cache.clear()

    def summary(self) -> dict:
        """Return summary of signature verification state."""
        verdicts = {}
        for result in self._cache.values():
            v = result.verdict.value
            verdicts[v] = verdicts.get(v, 0) + 1
        return {
            "total_keys": len(self.key_store.keys),
            "revoked_keys": sum(1 for k in self.key_store.keys.values() if k.revoked),
            "cached_verifications": len(self._cache),
            "verdicts": verdicts,
        }
