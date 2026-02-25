"""Breakglass — emergency override for strict-mode switches.

Implements R-BREAK-001 from SENTINEL spec (22 Feb 2026).

Architecture:
    Breakglass provides a controlled emergency escape hatch for strict-mode
    enforcement. When activated, it surgically overrides specific strict-mode
    flags — NOT the entire strict-mode posture.

Key design principles:
    1. SURGICAL: Only 3 of 11 strict-mode switches are overridable:
       - require_all_legs     (trust completeness)
       - digest_provider      (runtime integrity)
       - lockfile_hmac        (lockfile signing)

    2. NON-OVERRIDABLE core controls (always enforced):
       - supply_chain_verifier     (must have a verifier)
       - verifier_errors_fail_closed (errors → block)
       - require_signatures        (signature requirement)
       - blocklist enforcement     (blocklist always honoured)
       - max_age_days              (expiry always checked)

    3. DUAL-CONTROL: requester ≠ approver (two distinct principals)

    4. NON-RENEWABLE TTL: max 2 hours, cannot be extended — must
       create a new token after expiry

    5. AUDIT TRAIL: every lifecycle event is logged with full context

    6. APPROVAL WINDOW INTERACTION: during breakglass, approval windows
       are compressed (shorter TTLs, reduced max_uses)

Usage:
    # Activation (dual-control)
    bg = BreakglassService()
    token = bg.request(requester_id="ops-alice", flags=["require_all_legs"],
                       reason="Emergency provider migration", ttl_seconds=3600)
    bg.approve(token.token_id, approver_id="ops-bob")

    # Query in pipeline
    if bg.is_flag_overridden("require_all_legs"):
        # Skip require_all_legs check
        pass

    # Token auto-expires after TTL — no renewal possible
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger("unwind.enforcement.breakglass")


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# Maximum TTL for any breakglass token (2 hours)
MAX_TTL_SECONDS: float = 7200.0

# Minimum TTL (pointless if shorter than this)
MIN_TTL_SECONDS: float = 60.0

# Maximum flags per breakglass token (SENTINEL R-BREAK-001: ≤2 per request)
MAX_FLAGS_PER_TOKEN: int = 2

# Flags that CAN be overridden via breakglass
OVERRIDABLE_FLAGS: frozenset[str] = frozenset({
    "require_all_legs",
    "digest_provider",
    "lockfile_hmac",
})

# Flags that can NEVER be overridden (core security controls)
NON_OVERRIDABLE_FLAGS: frozenset[str] = frozenset({
    "supply_chain_verifier",
    "verifier_errors_fail_closed",
    "require_signatures",
    "blocklist_enforcement",
    "max_age_enforcement",
    "quarantine_unknown",
    "tofu_on_first_use",
    "breakglass_disabled",
})

# Approval window compression during breakglass
BREAKGLASS_WINDOW_TTL_MULTIPLIER: float = 0.5  # 50% of normal TTL
BREAKGLASS_WINDOW_MAX_USES_DIVISOR: int = 2    # Half the normal max_uses


# ──────────────────────────────────────────────
# Token states
# ──────────────────────────────────────────────

class TokenState(Enum):
    """Lifecycle states for a breakglass token."""
    PENDING = "pending"          # Requested, awaiting approval
    ACTIVE = "active"            # Approved and within TTL
    EXPIRED = "expired"          # TTL elapsed (auto-transition)
    REVOKED = "revoked"          # Manually revoked before TTL
    REJECTED = "rejected"        # Approval denied


# ──────────────────────────────────────────────
# Audit events
# ──────────────────────────────────────────────

class BreakglassEventType:
    """Audit event types for breakglass lifecycle."""
    REQUESTED = "breakglass_requested"
    APPROVED = "breakglass_approved"
    REJECTED = "breakglass_rejected"
    ACTIVATED = "breakglass_activated"
    EXPIRED = "breakglass_expired"
    REVOKED = "breakglass_revoked"
    FLAG_QUERIED = "breakglass_flag_queried"
    DENIED_NON_OVERRIDABLE = "breakglass_denied_non_overridable"
    DENIED_DISABLED = "breakglass_denied_disabled"
    DENIED_SELF_APPROVE = "breakglass_denied_self_approve"


@dataclass
class BreakglassEvent:
    """Structured audit event for breakglass lifecycle."""
    event_type: str
    timestamp: float
    token_id: str = ""
    requester_id: str = ""
    approver_id: str = ""
    flags: tuple[str, ...] = ()
    reason: str = ""
    ttl_seconds: float = 0.0
    remaining_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dict for logging/storage."""
        d: dict = {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
        }
        if self.token_id:
            d["token_id"] = self.token_id
        if self.requester_id:
            d["requester_id"] = self.requester_id
        if self.approver_id:
            d["approver_id"] = self.approver_id
        if self.flags:
            d["flags"] = list(self.flags)
        if self.reason:
            d["reason"] = self.reason
        if self.ttl_seconds > 0:
            d["ttl_seconds"] = self.ttl_seconds
        if self.remaining_seconds > 0:
            d["remaining_seconds"] = self.remaining_seconds
        return d


# Telemetry callback type
BreakglassCallback = Callable[[BreakglassEvent], None]


def _default_breakglass_callback(event: BreakglassEvent) -> None:
    """Default: log breakglass events at WARNING level (always visible)."""
    logger.warning("BREAKGLASS %s", event.to_dict())


# ──────────────────────────────────────────────
# Breakglass token
# ──────────────────────────────────────────────

@dataclass
class BreakglassToken:
    """A breakglass override token.

    Represents a time-limited, surgical override of specific strict-mode flags.
    Tokens are non-renewable: once expired, a new token must be created through
    the full dual-control flow.
    """
    token_id: str
    requester_id: str                    # Who requested the override
    flags: tuple[str, ...]               # Which flags are overridden
    reason: str                          # Why breakglass was needed
    ttl_seconds: float                   # Requested TTL
    created_at: float                    # When the request was made
    state: TokenState = TokenState.PENDING

    # Approval
    approver_id: str = ""                # Who approved (must ≠ requester)
    approved_at: float = 0.0             # When approval was granted
    expires_at: float = 0.0              # When the token expires (set on approval)

    # Revocation
    revoked_at: float = 0.0
    revocation_reason: str = ""
    revoker_id: str = ""

    @property
    def is_active(self) -> bool:
        """Check if token is currently active (approved + within TTL)."""
        if self.state != TokenState.ACTIVE:
            return False
        if time.time() > self.expires_at:
            # Auto-transition to expired
            self.state = TokenState.EXPIRED
            return False
        return True

    @property
    def remaining_seconds(self) -> float:
        """Seconds until this token expires. 0 if not active."""
        if not self.is_active:
            return 0.0
        return max(0.0, self.expires_at - time.time())

    def overrides_flag(self, flag_name: str) -> bool:
        """Check if this token overrides a specific flag."""
        return self.is_active and flag_name in self.flags


# ──────────────────────────────────────────────
# Breakglass service
# ──────────────────────────────────────────────

class BreakglassService:
    """Manages breakglass token lifecycle: request, approve, query, revoke.

    One instance per UNWIND proxy process. Integrates with the enforcement
    pipeline to provide surgical strict-mode overrides.
    """

    def __init__(
        self,
        enabled: bool = True,
        callback: Optional[BreakglassCallback] = None,
        autonomous_profiles: Optional[set[str]] = None,
    ):
        """Initialise breakglass service.

        Args:
            enabled: If False, all breakglass requests are denied
                     (BREAKGLASS_DISABLED). Can be set by policy.
            callback: Audit event callback (default: log at WARNING level)
            autonomous_profiles: Set of principal IDs that are autonomous
                                 (e.g. SENTINEL cron jobs). These are
                                 default-deny for breakglass requests.
        """
        self.enabled = enabled
        self._callback = callback or _default_breakglass_callback
        # Autonomous profiles: default-deny for breakglass
        self._autonomous_profiles: set[str] = autonomous_profiles or set()
        # All tokens (active + historical)
        self._tokens: dict[str, BreakglassToken] = {}
        # Token ID counter
        self._next_id: int = 0
        # Audit log (in-memory, for testing/shadow mode)
        self.audit_log: list[BreakglassEvent] = []

    def _emit(self, event: BreakglassEvent) -> None:
        """Emit an audit event."""
        self.audit_log.append(event)
        self._callback(event)

    def _generate_token_id(self) -> str:
        """Generate a unique token ID."""
        self._next_id += 1
        # Include timestamp hash for forensic uniqueness
        ts_hash = hashlib.sha256(
            f"{time.time()}-{self._next_id}".encode()
        ).hexdigest()[:8]
        return f"bg-{self._next_id:04d}-{ts_hash}"

    # --- Request flow ---

    def request(
        self,
        requester_id: str,
        flags: list[str],
        reason: str,
        ttl_seconds: float = 3600.0,
    ) -> Optional[BreakglassToken]:
        """Request a breakglass override.

        Creates a PENDING token that must be approved by a different principal.

        Args:
            requester_id: Who is requesting the override
            flags: Which strict-mode flags to override
            reason: Why breakglass is needed (mandatory)
            ttl_seconds: How long the override should last (capped at MAX_TTL)

        Returns:
            BreakglassToken in PENDING state, or None if request denied.
        """
        now = time.time()

        # Check if breakglass is enabled
        if not self.enabled:
            self._emit(BreakglassEvent(
                event_type=BreakglassEventType.DENIED_DISABLED,
                timestamp=now,
                requester_id=requester_id,
                flags=tuple(flags),
                reason="Breakglass is disabled by policy (BREAKGLASS_DISABLED)",
            ))
            logger.error(
                "Breakglass request DENIED: breakglass is disabled by policy"
            )
            return None

        # Validate flags — all must be overridable
        non_overridable = [f for f in flags if f not in OVERRIDABLE_FLAGS]
        if non_overridable:
            self._emit(BreakglassEvent(
                event_type=BreakglassEventType.DENIED_NON_OVERRIDABLE,
                timestamp=now,
                requester_id=requester_id,
                flags=tuple(flags),
                reason=(
                    f"Non-overridable flags requested: {', '.join(non_overridable)}. "
                    f"Only {', '.join(sorted(OVERRIDABLE_FLAGS))} can be overridden."
                ),
            ))
            logger.error(
                "Breakglass request DENIED: non-overridable flags: %s",
                non_overridable,
            )
            return None

        # Validate at least one flag
        if not flags:
            return None

        # Per-request flag cap (R-BREAK-001: max 2 switches per token)
        unique_flags = sorted(set(flags))
        if len(unique_flags) > MAX_FLAGS_PER_TOKEN:
            self._emit(BreakglassEvent(
                event_type=BreakglassEventType.DENIED_NON_OVERRIDABLE,
                timestamp=now,
                requester_id=requester_id,
                flags=tuple(unique_flags),
                reason=(
                    f"Too many flags requested: {len(unique_flags)} "
                    f"(max {MAX_FLAGS_PER_TOKEN} per token). "
                    f"Request separate tokens for additional flags."
                ),
            ))
            logger.error(
                "Breakglass request DENIED: %d flags exceeds cap of %d",
                len(unique_flags), MAX_FLAGS_PER_TOKEN,
            )
            return None

        # Autonomous profile check: deny if requester is autonomous
        if requester_id in self._autonomous_profiles:
            self._emit(BreakglassEvent(
                event_type=BreakglassEventType.DENIED_DISABLED,
                timestamp=now,
                requester_id=requester_id,
                flags=tuple(flags),
                reason=(
                    f"Autonomous profile '{requester_id}' cannot request "
                    f"breakglass (default deny for autonomous principals)"
                ),
            ))
            logger.error(
                "Breakglass request DENIED: autonomous profile '%s'",
                requester_id,
            )
            return None

        # Validate reason is non-empty
        if not reason.strip():
            return None

        # Cap TTL
        effective_ttl = max(MIN_TTL_SECONDS, min(ttl_seconds, MAX_TTL_SECONDS))

        token = BreakglassToken(
            token_id=self._generate_token_id(),
            requester_id=requester_id,
            flags=tuple(sorted(set(flags))),
            reason=reason,
            ttl_seconds=effective_ttl,
            created_at=now,
        )

        self._tokens[token.token_id] = token

        self._emit(BreakglassEvent(
            event_type=BreakglassEventType.REQUESTED,
            timestamp=now,
            token_id=token.token_id,
            requester_id=requester_id,
            flags=token.flags,
            reason=reason,
            ttl_seconds=effective_ttl,
        ))

        logger.warning(
            "BREAKGLASS REQUESTED: %s by %s — flags=%s ttl=%.0fs reason='%s'",
            token.token_id, requester_id, token.flags, effective_ttl, reason,
        )

        return token

    # --- Approval flow (dual-control) ---

    def approve(
        self,
        token_id: str,
        approver_id: str,
    ) -> bool:
        """Approve a pending breakglass token.

        Enforces dual-control: approver must differ from requester.

        Args:
            token_id: The token to approve
            approver_id: Who is approving (must ≠ requester)

        Returns:
            True if approved and activated, False if denied.
        """
        now = time.time()
        token = self._tokens.get(token_id)

        if token is None:
            logger.error("Breakglass approve FAILED: unknown token %s", token_id)
            return False

        if token.state != TokenState.PENDING:
            logger.error(
                "Breakglass approve FAILED: token %s is %s (not PENDING)",
                token_id, token.state.value,
            )
            return False

        # Dual-control enforcement
        if approver_id == token.requester_id:
            token.state = TokenState.REJECTED
            self._emit(BreakglassEvent(
                event_type=BreakglassEventType.DENIED_SELF_APPROVE,
                timestamp=now,
                token_id=token_id,
                requester_id=token.requester_id,
                approver_id=approver_id,
                flags=token.flags,
                reason="Dual-control violation: approver cannot be requester",
            ))
            logger.error(
                "BREAKGLASS REJECTED: %s — dual-control violation "
                "(requester=%s == approver=%s)",
                token_id, token.requester_id, approver_id,
            )
            return False

        # Activate
        token.state = TokenState.ACTIVE
        token.approver_id = approver_id
        token.approved_at = now
        token.expires_at = now + token.ttl_seconds

        self._emit(BreakglassEvent(
            event_type=BreakglassEventType.APPROVED,
            timestamp=now,
            token_id=token_id,
            requester_id=token.requester_id,
            approver_id=approver_id,
            flags=token.flags,
            reason=token.reason,
            ttl_seconds=token.ttl_seconds,
        ))

        self._emit(BreakglassEvent(
            event_type=BreakglassEventType.ACTIVATED,
            timestamp=now,
            token_id=token_id,
            requester_id=token.requester_id,
            approver_id=approver_id,
            flags=token.flags,
            ttl_seconds=token.ttl_seconds,
        ))

        logger.warning(
            "BREAKGLASS ACTIVATED: %s — flags=%s ttl=%.0fs "
            "requester=%s approver=%s reason='%s'",
            token_id, token.flags, token.ttl_seconds,
            token.requester_id, approver_id, token.reason,
        )

        return True

    # --- Rejection ---

    def reject(
        self,
        token_id: str,
        approver_id: str,
        reason: str = "",
    ) -> bool:
        """Reject a pending breakglass token.

        Args:
            token_id: The token to reject
            approver_id: Who is rejecting
            reason: Why it was rejected

        Returns:
            True if rejected, False if token not found or not PENDING.
        """
        now = time.time()
        token = self._tokens.get(token_id)

        if token is None or token.state != TokenState.PENDING:
            return False

        token.state = TokenState.REJECTED

        self._emit(BreakglassEvent(
            event_type=BreakglassEventType.REJECTED,
            timestamp=now,
            token_id=token_id,
            requester_id=token.requester_id,
            approver_id=approver_id,
            flags=token.flags,
            reason=reason or "Approval denied",
        ))

        logger.warning(
            "BREAKGLASS REJECTED: %s by %s — reason='%s'",
            token_id, approver_id, reason,
        )

        return True

    # --- Revocation ---

    def revoke(
        self,
        token_id: str,
        revoker_id: str,
        reason: str = "",
    ) -> bool:
        """Revoke an active breakglass token before its TTL expires.

        Any principal can revoke (no dual-control required for revocation).

        Args:
            token_id: The token to revoke
            revoker_id: Who is revoking
            reason: Why it was revoked

        Returns:
            True if revoked, False if token not found or not ACTIVE.
        """
        now = time.time()
        token = self._tokens.get(token_id)

        if token is None:
            return False

        # Check if it's currently active (this also handles auto-expiry)
        if not token.is_active:
            return False

        token.state = TokenState.REVOKED
        token.revoked_at = now
        token.revocation_reason = reason
        token.revoker_id = revoker_id

        self._emit(BreakglassEvent(
            event_type=BreakglassEventType.REVOKED,
            timestamp=now,
            token_id=token_id,
            requester_id=token.requester_id,
            approver_id=token.approver_id,
            flags=token.flags,
            reason=reason or "Manually revoked",
            remaining_seconds=max(0.0, token.expires_at - now),
        ))

        logger.warning(
            "BREAKGLASS REVOKED: %s by %s — remaining=%.0fs reason='%s'",
            token_id, revoker_id,
            max(0.0, token.expires_at - now), reason,
        )

        return True

    # --- Query interface (used by pipeline) ---

    def is_flag_overridden(self, flag_name: str) -> bool:
        """Check if a strict-mode flag is currently overridden by breakglass.

        This is the hot-path query called by the enforcement pipeline.
        Returns True if ANY active token overrides this flag.

        Args:
            flag_name: The strict-mode flag to check

        Returns:
            True if the flag is currently overridden, False otherwise.
        """
        for token in self._tokens.values():
            if token.overrides_flag(flag_name):
                return True
        return False

    def get_active_overrides(self) -> dict[str, str]:
        """Get all currently active flag overrides.

        Returns:
            Dict of flag_name → token_id for all active overrides.
        """
        overrides: dict[str, str] = {}
        for token in self._tokens.values():
            if token.is_active:
                for flag in token.flags:
                    overrides[flag] = token.token_id
        return overrides

    def has_active_breakglass(self) -> bool:
        """Check if any breakglass token is currently active."""
        return any(t.is_active for t in self._tokens.values())

    def get_active_tokens(self) -> list[BreakglassToken]:
        """Get all currently active tokens."""
        return [t for t in self._tokens.values() if t.is_active]

    def get_token(self, token_id: str) -> Optional[BreakglassToken]:
        """Get a token by ID (for inspection/audit)."""
        return self._tokens.get(token_id)

    # --- Expiry management ---

    def check_expiry(self) -> list[str]:
        """Check all tokens for expiry and emit events.

        Call periodically (e.g. every 30s) to ensure expiry events
        are logged promptly. Auto-expiry also happens on is_active checks.

        Returns:
            List of token IDs that expired.
        """
        now = time.time()
        expired: list[str] = []

        for token in self._tokens.values():
            if token.state == TokenState.ACTIVE and now > token.expires_at:
                token.state = TokenState.EXPIRED
                expired.append(token.token_id)

                self._emit(BreakglassEvent(
                    event_type=BreakglassEventType.EXPIRED,
                    timestamp=now,
                    token_id=token.token_id,
                    requester_id=token.requester_id,
                    approver_id=token.approver_id,
                    flags=token.flags,
                    reason="TTL elapsed (non-renewable)",
                    ttl_seconds=token.ttl_seconds,
                ))

                logger.warning(
                    "BREAKGLASS EXPIRED: %s — flags=%s ttl=%.0fs",
                    token.token_id, token.flags, token.ttl_seconds,
                )

        return expired

    # --- Approval window interaction ---

    def get_window_ttl_multiplier(self) -> float:
        """Get the TTL multiplier for approval windows during breakglass.

        When breakglass is active, approval windows are compressed
        to reduce the risk surface during the override period.
        """
        if self.has_active_breakglass():
            return BREAKGLASS_WINDOW_TTL_MULTIPLIER
        return 1.0

    def get_window_max_uses_divisor(self) -> int:
        """Get the max_uses divisor for approval windows during breakglass.

        During breakglass, approval windows get fewer uses to
        increase the frequency of human oversight.
        """
        if self.has_active_breakglass():
            return BREAKGLASS_WINDOW_MAX_USES_DIVISOR
        return 1

    # --- Summary/audit ---

    def summary(self) -> dict:
        """Return audit summary of breakglass state."""
        active = [t for t in self._tokens.values() if t.is_active]
        pending = [t for t in self._tokens.values() if t.state == TokenState.PENDING]

        return {
            "enabled": self.enabled,
            "active_tokens": len(active),
            "pending_tokens": len(pending),
            "total_tokens": len(self._tokens),
            "active_overrides": self.get_active_overrides(),
            "audit_events": len(self.audit_log),
        }
