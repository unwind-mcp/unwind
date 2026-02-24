"""Supply-chain trust — lockfile verification, signature checking, quarantine.

Implements R-SIG, R-LOCK, R-TRUST from UNWIND policy v0.2.

Architecture:
    Every MCP server/skill declares tools. UNWIND maintains a lockfile that
    pins each tool to a specific provider (skill/server), version, and SHA-256
    digest. On each tool call, the pipeline checks:

    1. Is the tool's provider in the lockfile? (R-LOCK-001)
    2. Does the provider's digest match the lockfile? (R-LOCK-002)
    3. Is the provider's signature valid? (R-SIG-001)
    4. Is the provider on the blocklist? (R-TRUST-001)
    5. Is this a new/unknown provider? → quarantine (R-TRUST-002)

Lockfile format (JSON):
    {
        "version": "1.0",
        "created": "2026-02-22T12:00:00Z",
        "providers": {
            "provider_id": {
                "name": "...",
                "version": "1.2.3",
                "digest": "sha256:abcdef...",
                "signature": { "alg": "Ed25519", "key_id": "...", "sig": "..." },
                "tools": ["tool_a", "tool_b"],
                "origin": "https://...",
                "trusted_at": "2026-02-22T12:00:00Z"
            }
        },
        "blocklist": ["blocked_provider_id"],
        "trust_policy": {
            "require_signatures": false,
            "require_known_origin": true,
            "quarantine_unknown": true,
            "max_age_days": 90
        }
    }

Performance:
    - Lockfile loaded once at startup (COLD)
    - Tool→provider lookup: dict lookup (HOT, <1ms)
    - Digest verification: on first use per session or on provider change (WARM)
    - Signature verification: on lockfile load only (COLD)
"""

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("unwind.supply_chain")


class TrustVerdict(Enum):
    """Result of supply-chain trust verification."""
    TRUSTED = "trusted"          # In lockfile, digest matches, not blocked
    UNTRUSTED = "untrusted"      # Not in lockfile or digest mismatch
    BLOCKED = "blocked"          # Explicitly on blocklist
    QUARANTINED = "quarantined"  # Unknown provider, held for review
    EXPIRED = "expired"          # Trust has aged out (max_age_days exceeded)
    SIGNATURE_INVALID = "signature_invalid"  # Signature check failed


@dataclass
class ProviderEntry:
    """A single provider (MCP server / skill) entry in the lockfile."""
    provider_id: str
    name: str
    version: str
    digest: str                    # "sha256:<hex>"
    tools: list[str]               # Tools this provider declares
    origin: str = ""               # Where the provider was fetched from
    trusted_at: Optional[str] = None  # ISO timestamp of trust grant
    signature: Optional[dict] = None  # {"alg": "...", "key_id": "...", "sig": "..."}

    def digest_algorithm(self) -> str:
        """Extract algorithm from digest string."""
        if ":" in self.digest:
            return self.digest.split(":")[0]
        return "unknown"

    def digest_value(self) -> str:
        """Extract hex hash from digest string."""
        if ":" in self.digest:
            return self.digest.split(":", 1)[1]
        return self.digest

    def is_expired(self, max_age_days: int) -> bool:
        """Check if trust has expired based on max_age_days."""
        if max_age_days <= 0 or not self.trusted_at:
            return False
        try:
            trusted_dt = datetime.fromisoformat(self.trusted_at.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - trusted_dt).days
            return age_days > max_age_days
        except (ValueError, TypeError):
            return True  # If we can't parse the date, treat as expired


@dataclass
class TrustPolicy:
    """Trust policy configuration."""
    require_signatures: bool = False
    require_known_origin: bool = True
    quarantine_unknown: bool = True
    max_age_days: int = 90


@dataclass
class Lockfile:
    """The skill/provider lockfile — source of truth for trusted versions."""
    version: str = "1.0"
    created: str = ""
    providers: dict[str, ProviderEntry] = field(default_factory=dict)
    blocklist: set[str] = field(default_factory=set)  # O(1) lookup
    trust_policy: TrustPolicy = field(default_factory=TrustPolicy)

    # --- Derived index: tool_name → provider_id (built on load) ---
    _tool_index: dict[str, str] = field(default_factory=dict, repr=False)

    def build_index(self) -> None:
        """Build tool→provider reverse index for fast lookup.

        Atomic swap: builds new index first, then replaces. Detects duplicate
        tool claims across providers and logs warnings (first-writer-wins).
        """
        new_index: dict[str, str] = {}
        for pid, entry in self.providers.items():
            for tool in entry.tools:
                if tool in new_index:
                    existing_pid = new_index[tool]
                    logger.warning(
                        "Duplicate tool claim: '%s' declared by both '%s' and '%s'. "
                        "Keeping first provider '%s'. (Possible spoofing attempt)",
                        tool, existing_pid, pid, existing_pid,
                    )
                else:
                    new_index[tool] = pid
        self._tool_index = new_index  # Atomic swap

    def provider_for_tool(self, tool_name: str) -> Optional[str]:
        """Look up which provider declares a given tool. O(1)."""
        return self._tool_index.get(tool_name)

    def get_provider(self, provider_id: str) -> Optional[ProviderEntry]:
        """Get a provider entry by ID."""
        return self.providers.get(provider_id)

    def is_blocked(self, provider_id: str) -> bool:
        """Check if a provider is on the blocklist. O(1) set lookup."""
        return provider_id in self.blocklist

    def has_duplicate_tool_claims(self) -> dict[str, list[str]]:
        """Detect tools claimed by multiple providers. For audit/security scanning."""
        tool_providers: dict[str, list[str]] = {}
        for pid, entry in self.providers.items():
            for tool in entry.tools:
                tool_providers.setdefault(tool, []).append(pid)
        return {t: pids for t, pids in tool_providers.items() if len(pids) > 1}


@dataclass
class VerificationResult:
    """Result of verifying a tool call against the lockfile."""
    verdict: TrustVerdict
    provider_id: Optional[str] = None
    provider_name: Optional[str] = None
    reason: str = ""
    digest_match: Optional[bool] = None
    signature_valid: Optional[bool] = None


def compute_digest(content: bytes, algorithm: str = "sha256") -> str:
    """Compute a digest string for content.

    Returns format: "sha256:<hex>"
    """
    if algorithm == "sha256":
        h = hashlib.sha256(content).hexdigest()
        return f"sha256:{h}"
    raise ValueError(f"Unsupported digest algorithm: {algorithm}")


# --- HMAC Lockfile Integrity (R-LOCK-003) ---

# Environment variable for the HMAC key. If not set, a deterministic
# fallback key is derived from the lockfile path using HKDF-like expansion.
HMAC_KEY_ENV = "UNWIND_LOCKFILE_KEY"

# Sentinel value: HMAC sidecar not found (distinguishes from empty/corrupt)
_NO_HMAC_SIDECAR = object()


def _hmac_sidecar_path(lockfile_path: Path) -> Path:
    """Return the path of the HMAC sidecar file for a lockfile."""
    return lockfile_path.with_suffix(lockfile_path.suffix + ".hmac")


@dataclass
class HMACKey:
    """HMAC key with provenance metadata."""
    key: bytes
    is_production: bool  # True if from env var / explicit secret
    source: str          # "env", "explicit", or "fallback"


# Minimum key entropy for production use: 16 bytes (128 bits)
MIN_KEY_LENGTH = 16


def _get_hmac_key(lockfile_path: Path) -> HMACKey:
    """Get the HMAC key for lockfile integrity.

    Priority:
        1. UNWIND_LOCKFILE_KEY environment variable (hex-encoded or passphrase)
        2. Deterministic fallback derived from lockfile path
           (SHA-256 of the canonical path with a fixed salt)

    The fallback provides tamper-detection against naive edits but NOT
    against an attacker who can read this source code and the lockfile path.
    The env-var key provides full protection.

    Returns:
        HMACKey with the key bytes and provenance information.
    """
    env_key = os.environ.get(HMAC_KEY_ENV)
    if env_key:
        try:
            key_bytes = bytes.fromhex(env_key)
        except ValueError:
            # If not valid hex, use raw bytes (allows passphrase-style keys)
            key_bytes = env_key.encode("utf-8")

        if len(key_bytes) < MIN_KEY_LENGTH:
            logger.warning(
                "UNWIND_LOCKFILE_KEY is only %d bytes — minimum %d recommended "
                "for production use (R-LOCK-003)",
                len(key_bytes), MIN_KEY_LENGTH,
            )

        return HMACKey(key=key_bytes, is_production=True, source="env")

    # Deterministic fallback: HKDF-like expansion from the canonical path
    # This protects against accidental edits but not targeted attacks
    logger.debug(
        "No UNWIND_LOCKFILE_KEY set — using path-derived fallback key "
        "(NOT suitable for production)"
    )
    salt = b"unwind-lockfile-integrity-v1"
    path_bytes = str(lockfile_path.resolve()).encode("utf-8")
    key_bytes = hashlib.sha256(salt + path_bytes).digest()
    return HMACKey(key=key_bytes, is_production=False, source="fallback")


def compute_hmac(content: bytes, key: bytes) -> str:
    """Compute HMAC-SHA256 of content, returning hex string."""
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def verify_hmac(content: bytes, expected_hmac: str, key: bytes) -> bool:
    """Verify HMAC-SHA256 of content against expected value.

    Uses constant-time comparison to prevent timing attacks.
    """
    actual = hmac.new(key, content, hashlib.sha256).hexdigest()
    return hmac.compare_digest(actual, expected_hmac)


def _save_hmac_sidecar(lockfile_path: Path, content: bytes, key: bytes) -> None:
    """Write the HMAC sidecar file for a lockfile."""
    sidecar = _hmac_sidecar_path(lockfile_path)
    mac = compute_hmac(content, key)
    sidecar.write_text(mac, encoding="utf-8")


def _load_hmac_sidecar(lockfile_path: Path) -> str:
    """Load the HMAC from the sidecar file.

    Returns the HMAC hex string, or empty string if sidecar missing/unreadable.
    """
    sidecar = _hmac_sidecar_path(lockfile_path)
    if not sidecar.exists():
        return ""
    try:
        return sidecar.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


@dataclass
class HMACVerification:
    """Result of HMAC verification on a lockfile."""
    valid: bool
    sidecar_exists: bool
    reason: str


def verify_lockfile_integrity(
    lockfile_path: Path,
    key: Optional[bytes] = None,
) -> HMACVerification:
    """Verify the HMAC integrity of a lockfile.

    Args:
        lockfile_path: Path to the lockfile JSON
        key: HMAC key bytes (if None, derived from env/fallback)

    Returns:
        HMACVerification with result and reason
    """
    if key is None:
        hmac_key_info = _get_hmac_key(lockfile_path)
        key = hmac_key_info.key

    if not lockfile_path.exists():
        return HMACVerification(
            valid=False,
            sidecar_exists=False,
            reason="Lockfile does not exist",
        )

    stored_hmac = _load_hmac_sidecar(lockfile_path)
    if not stored_hmac:
        return HMACVerification(
            valid=False,
            sidecar_exists=False,
            reason="No HMAC sidecar found — unsigned lockfile (migration grace)",
        )

    try:
        content = lockfile_path.read_bytes()
    except OSError as e:
        return HMACVerification(
            valid=False,
            sidecar_exists=True,
            reason=f"Cannot read lockfile: {e}",
        )

    if verify_hmac(content, stored_hmac, key):
        return HMACVerification(
            valid=True,
            sidecar_exists=True,
            reason="HMAC verification passed",
        )
    else:
        return HMACVerification(
            valid=False,
            sidecar_exists=True,
            reason="HMAC verification FAILED — lockfile may be tampered (R-LOCK-003)",
        )


def load_lockfile(
    path: Path,
    verify_integrity: bool = True,
    hmac_key: Optional[bytes] = None,
    strict: bool = False,
) -> Lockfile:
    """Load a lockfile from disk with optional HMAC integrity verification.

    Args:
        path: Path to the lockfile JSON
        verify_integrity: Whether to check HMAC sidecar (default True)
        hmac_key: Override HMAC key (if None, derived from env/fallback)
        strict: If True, reject unsigned lockfiles (no grace period).
                If False, unsigned lockfiles are loaded with a warning.

    Returns:
        Lockfile object. Returns empty lockfile with quarantine policy on:
        - File not found
        - Parse error
        - HMAC tamper detected (fail-closed)

    The loaded lockfile has a `_hmac_verified` attribute set to True/False/None.
    """
    if not path.exists():
        logger.warning("Lockfile not found at %s — using empty lockfile", path)
        lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
        lf.build_index()
        lf._hmac_verified = None  # type: ignore[attr-defined]
        return lf

    # Read raw bytes for both JSON parse and HMAC check
    try:
        raw_content = path.read_bytes()
    except OSError as e:
        logger.error("Failed to read lockfile %s: %s", path, e)
        lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
        lf.build_index()
        lf._hmac_verified = None  # type: ignore[attr-defined]
        return lf

    # HMAC integrity check (R-LOCK-003)
    if verify_integrity:
        # Determine key provenance for strict-mode enforcement
        if hmac_key is not None:
            effective_key = hmac_key
            key_is_production = True  # Explicit key assumed production
        else:
            hmac_key_info = _get_hmac_key(path)
            effective_key = hmac_key_info.key
            key_is_production = hmac_key_info.is_production

        # P0 SENTINEL finding: strict mode + fallback key = hard fail
        if strict and not key_is_production:
            logger.critical(
                "Lockfile %s: strict mode requires a production HMAC key "
                "(set UNWIND_LOCKFILE_KEY env var). Fallback key is NOT "
                "suitable for production — failing closed (R-LOCK-003)",
                path,
            )
            lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
            lf.build_index()
            lf._hmac_verified = False  # type: ignore[attr-defined]
            return lf

        integrity = verify_lockfile_integrity(path, key=effective_key)

        if integrity.sidecar_exists and not integrity.valid:
            # TAMPER DETECTED → fail-closed
            logger.critical(
                "LOCKFILE TAMPER DETECTED at %s: %s — failing closed",
                path, integrity.reason,
            )
            lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
            lf.build_index()
            lf._hmac_verified = False  # type: ignore[attr-defined]
            return lf

        if not integrity.sidecar_exists:
            if strict:
                logger.error(
                    "Lockfile %s has no HMAC sidecar and strict mode is enabled — "
                    "rejecting unsigned lockfile",
                    path,
                )
                lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
                lf.build_index()
                lf._hmac_verified = False  # type: ignore[attr-defined]
                return lf
            else:
                if not key_is_production:
                    logger.warning(
                        "Lockfile %s has no HMAC sidecar and using fallback key — "
                        "integrity not guaranteed. Set UNWIND_LOCKFILE_KEY for "
                        "production use. (R-LOCK-003)",
                        path,
                    )
                logger.warning(
                    "Lockfile %s has no HMAC sidecar — loading in migration grace mode. "
                    "Run save_lockfile() to sign it. (R-LOCK-003)",
                    path,
                )

    # Parse JSON
    try:
        data = json.loads(raw_content)
    except (json.JSONDecodeError, ValueError) as e:
        logger.error("Failed to parse lockfile %s: %s", path, e)
        lf = Lockfile(created=datetime.now(timezone.utc).isoformat())
        lf.build_index()
        lf._hmac_verified = None  # type: ignore[attr-defined]
        return lf

    lf = parse_lockfile(data)

    # Tag with verification status (reuse already-computed integrity result)
    if verify_integrity:
        lf._hmac_verified = integrity.valid  # type: ignore[attr-defined]
    else:
        lf._hmac_verified = None  # type: ignore[attr-defined]

    return lf


def parse_lockfile(data: dict) -> Lockfile:
    """Parse a lockfile from a dict (already loaded from JSON)."""
    trust_data = data.get("trust_policy", {})
    trust_policy = TrustPolicy(
        require_signatures=trust_data.get("require_signatures", False),
        require_known_origin=trust_data.get("require_known_origin", True),
        quarantine_unknown=trust_data.get("quarantine_unknown", True),
        max_age_days=trust_data.get("max_age_days", 90),
    )

    providers = {}
    for pid, pdata in data.get("providers", {}).items():
        providers[pid] = ProviderEntry(
            provider_id=pid,
            name=pdata.get("name", pid),
            version=pdata.get("version", "unknown"),
            digest=pdata.get("digest", ""),
            tools=pdata.get("tools", []),
            origin=pdata.get("origin", ""),
            trusted_at=pdata.get("trusted_at"),
            signature=pdata.get("signature"),
        )

    lf = Lockfile(
        version=data.get("version", "1.0"),
        created=data.get("created", ""),
        providers=providers,
        blocklist=set(data.get("blocklist", [])),
        trust_policy=trust_policy,
    )
    lf.build_index()
    return lf


def save_lockfile(
    lockfile: Lockfile,
    path: Path,
    sign: bool = True,
    hmac_key: Optional[bytes] = None,
) -> None:
    """Save a lockfile to disk with HMAC integrity sidecar.

    Args:
        lockfile: The lockfile to save
        path: Destination path for the JSON file
        sign: Whether to write the HMAC sidecar (default True)
        hmac_key: Override HMAC key (if None, derived from env/fallback)
    """
    data: dict[str, Any] = {
        "version": lockfile.version,
        "created": lockfile.created,
        "providers": {},
        "blocklist": sorted(lockfile.blocklist),  # Set → sorted list for JSON
        "trust_policy": {
            "require_signatures": lockfile.trust_policy.require_signatures,
            "require_known_origin": lockfile.trust_policy.require_known_origin,
            "quarantine_unknown": lockfile.trust_policy.quarantine_unknown,
            "max_age_days": lockfile.trust_policy.max_age_days,
        },
    }

    for pid, entry in lockfile.providers.items():
        pdata: dict[str, Any] = {
            "name": entry.name,
            "version": entry.version,
            "digest": entry.digest,
            "tools": entry.tools,
            "origin": entry.origin,
            "trusted_at": entry.trusted_at,
        }
        if entry.signature:
            pdata["signature"] = entry.signature
        data["providers"][pid] = pdata

    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2).encode("utf-8")
    path.write_bytes(content)

    # Write HMAC sidecar (R-LOCK-003)
    if sign:
        if hmac_key is None:
            hmac_key_info = _get_hmac_key(path)
            if not hmac_key_info.is_production:
                logger.warning(
                    "Signing lockfile %s with fallback key — not suitable for "
                    "production. Set UNWIND_LOCKFILE_KEY. (R-LOCK-003)",
                    path,
                )
            hmac_key = hmac_key_info.key
        _save_hmac_sidecar(path, content, hmac_key)


class SupplyChainVerifier:
    """Verifies tool calls against the lockfile.

    Used as a pipeline stage check. Loaded once at startup (COLD),
    then all verification is dict lookups (HOT).
    """

    def __init__(
        self,
        lockfile: Lockfile,
        signature_verifier: Optional[Any] = None,
    ):
        self.lockfile = lockfile
        # Optional Ed25519 signature verifier (from signature_verify.py)
        # When present, replaces the presence-only stub with real verification
        self.signature_verifier = signature_verifier
        # Cache of verified digests per session to avoid re-checking
        self._verified_providers: set[str] = set()
        # Quarantine queue: providers awaiting human review
        self._quarantine: dict[str, ProviderEntry] = {}

    def verify_tool(
        self,
        tool_name: str,
        current_digest: Optional[str] = None,
    ) -> VerificationResult:
        """Verify a tool call against the lockfile.

        Args:
            tool_name: The MCP tool being called
            current_digest: Optional live digest of the provider code
                           (for runtime integrity checking)

        Returns:
            VerificationResult with verdict and details
        """
        # 1. Look up provider for this tool
        provider_id = self.lockfile.provider_for_tool(tool_name)

        if provider_id is None:
            # Unknown tool — not in any provider's manifest
            if self.lockfile.trust_policy.quarantine_unknown:
                return VerificationResult(
                    verdict=TrustVerdict.QUARANTINED,
                    reason=f"Tool '{tool_name}' not found in any known provider. Quarantined.",
                )
            return VerificationResult(
                verdict=TrustVerdict.UNTRUSTED,
                reason=f"Tool '{tool_name}' not found in lockfile.",
            )

        entry = self.lockfile.get_provider(provider_id)
        if entry is None:
            return VerificationResult(
                verdict=TrustVerdict.UNTRUSTED,
                provider_id=provider_id,
                reason=f"Provider '{provider_id}' referenced but not found in lockfile.",
            )

        # 2. Check blocklist
        if self.lockfile.is_blocked(provider_id):
            return VerificationResult(
                verdict=TrustVerdict.BLOCKED,
                provider_id=provider_id,
                provider_name=entry.name,
                reason=f"Provider '{entry.name}' is on the blocklist.",
            )

        # 3. Check expiry
        if entry.is_expired(self.lockfile.trust_policy.max_age_days):
            return VerificationResult(
                verdict=TrustVerdict.EXPIRED,
                provider_id=provider_id,
                provider_name=entry.name,
                reason=(
                    f"Provider '{entry.name}' trust expired "
                    f"(trusted_at={entry.trusted_at}, "
                    f"max_age={self.lockfile.trust_policy.max_age_days} days)."
                ),
            )

        # 4. Check digest (if provided)
        digest_match = None
        if current_digest:
            if not entry.digest:
                # Provider has no stored digest — can't verify integrity
                logger.warning(
                    "Provider '%s' has no stored digest — cannot verify integrity",
                    entry.name,
                )
                return VerificationResult(
                    verdict=TrustVerdict.UNTRUSTED,
                    provider_id=provider_id,
                    provider_name=entry.name,
                    digest_match=False,
                    reason=f"Provider '{entry.name}' has no stored digest for integrity verification.",
                )
            digest_match = current_digest == entry.digest
            if not digest_match:
                return VerificationResult(
                    verdict=TrustVerdict.UNTRUSTED,
                    provider_id=provider_id,
                    provider_name=entry.name,
                    digest_match=False,
                    reason=(
                        f"Provider '{entry.name}' digest mismatch: "
                        f"expected={entry.digest}, got={current_digest}."
                    ),
                )

        # 5. Check signature requirement (R-SIG-001)
        signature_valid = None
        if self.lockfile.trust_policy.require_signatures:
            if not entry.signature:
                return VerificationResult(
                    verdict=TrustVerdict.SIGNATURE_INVALID,
                    provider_id=provider_id,
                    provider_name=entry.name,
                    signature_valid=False,
                    reason=f"Provider '{entry.name}' has no signature but signatures are required.",
                )

            if self.signature_verifier is not None:
                # Real Ed25519 verification via SignatureVerifier
                provider_data = self._provider_to_dict(entry)
                try:
                    sig_result = self.signature_verifier.verify(provider_id, provider_data)
                except Exception as exc:
                    # R-STRICT-001: internal verifier error
                    logger.error(
                        "SignatureVerifier internal error for '%s': %s",
                        entry.name, exc,
                    )
                    return VerificationResult(
                        verdict=TrustVerdict.SIGNATURE_INVALID,
                        provider_id=provider_id,
                        provider_name=entry.name,
                        signature_valid=False,
                        reason=(
                            f"Provider '{entry.name}': signature verifier error: {exc} "
                            f"(SIGNATURE_VERIFIER_ERROR)"
                        ),
                    )
                from .signature_verify import SignatureVerdict as SigVerdict
                if sig_result.verdict == SigVerdict.VALID:
                    signature_valid = True
                else:
                    return VerificationResult(
                        verdict=TrustVerdict.SIGNATURE_INVALID,
                        provider_id=provider_id,
                        provider_name=entry.name,
                        signature_valid=False,
                        reason=f"Provider '{entry.name}': {sig_result.reason}",
                    )
            else:
                # No signature verifier configured.
                # SENTINEL finding: when require_signatures is true, presence-only
                # fallback is NOT acceptable — reject without a real verifier.
                logger.error(
                    "Signatures required but no SignatureVerifier configured — "
                    "cannot verify provider '%s'. Wire in a key store. (R-SIG-001)",
                    entry.name,
                )
                return VerificationResult(
                    verdict=TrustVerdict.SIGNATURE_INVALID,
                    provider_id=provider_id,
                    provider_name=entry.name,
                    signature_valid=False,
                    reason=(
                        f"Provider '{entry.name}' has a signature but no "
                        f"SignatureVerifier is configured to verify it (R-SIG-001)."
                    ),
                )

        # 6. All checks passed
        self._verified_providers.add(provider_id)
        return VerificationResult(
            verdict=TrustVerdict.TRUSTED,
            provider_id=provider_id,
            provider_name=entry.name,
            digest_match=digest_match,
            signature_valid=signature_valid,
            reason=f"Provider '{entry.name}' v{entry.version} is trusted.",
        )

    @staticmethod
    def _provider_to_dict(entry: ProviderEntry) -> dict:
        """Convert a ProviderEntry to the dict format expected by signature verification."""
        d: dict[str, Any] = {
            "name": entry.name,
            "version": entry.version,
            "digest": entry.digest,
            "tools": entry.tools,
            "origin": entry.origin,
            "trusted_at": entry.trusted_at,
        }
        if entry.signature:
            d["signature"] = entry.signature
        return d

    def quarantine_provider(self, provider_id: str, entry: ProviderEntry) -> None:
        """Add a provider to the quarantine queue for human review."""
        self._quarantine[provider_id] = entry
        logger.warning("Provider quarantined: %s (%s)", provider_id, entry.name)

    def release_from_quarantine(self, provider_id: str) -> Optional[ProviderEntry]:
        """Release a provider from quarantine (human approved)."""
        return self._quarantine.pop(provider_id, None)

    def get_quarantine(self) -> dict[str, ProviderEntry]:
        """Get all quarantined providers."""
        return dict(self._quarantine)

    def add_to_blocklist(self, provider_id: str) -> None:
        """Add a provider to the blocklist."""
        self.lockfile.blocklist.add(provider_id)
        # Also remove from verified cache
        self._verified_providers.discard(provider_id)
        logger.warning("Provider blocklisted: %s", provider_id)

    def remove_from_blocklist(self, provider_id: str) -> None:
        """Remove a provider from the blocklist."""
        self.lockfile.blocklist.discard(provider_id)

    def is_provider_verified(self, provider_id: str) -> bool:
        """Check if a provider has been verified this session."""
        return provider_id in self._verified_providers

    def register_provider(
        self,
        provider_id: str,
        name: str,
        version: str,
        tools: list[str],
        content: Optional[bytes] = None,
        origin: str = "",
        signature: Optional[dict] = None,
        allow_downgrade: bool = False,
    ) -> ProviderEntry:
        """Register a new provider in the lockfile.

        Used during initial setup or when approving a quarantined provider.
        Rejects version downgrades unless explicitly allowed.

        Raises ValueError if version downgrade detected and allow_downgrade=False.
        """
        existing = self.lockfile.providers.get(provider_id)
        if existing and not allow_downgrade:
            # Simple lexicographic version comparison (semver-compatible for most cases)
            if version < existing.version:
                raise ValueError(
                    f"Version downgrade rejected for '{name}': "
                    f"{existing.version} → {version}. "
                    f"Set allow_downgrade=True to force."
                )

        digest = compute_digest(content) if content else ""
        entry = ProviderEntry(
            provider_id=provider_id,
            name=name,
            version=version,
            digest=digest,
            tools=tools,
            origin=origin,
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature=signature,
        )
        self.lockfile.providers[provider_id] = entry
        self.lockfile.build_index()
        return entry

    def summary(self) -> dict:
        """Return a summary of the supply-chain state."""
        return {
            "total_providers": len(self.lockfile.providers),
            "verified_this_session": len(self._verified_providers),
            "quarantined": len(self._quarantine),
            "blocklisted": len(self.lockfile.blocklist),
            "require_signatures": self.lockfile.trust_policy.require_signatures,
            "max_age_days": self.lockfile.trust_policy.max_age_days,
        }
