"""Amber Mediator Telemetry — GO-09 event chain for R-AMBER-MED-001.

Emits structured events for all 5 amber mediator decision paths:
  - unwind.amber_mediator.issue          (amber challenge sent to agent)
  - unwind.amber_mediator.received       (approval token received)
  - unwind.amber_mediator.applied        (approval/denial applied)
  - unwind.amber_mediator.rejected       (token validation failed)
  - unwind.amber_mediator.replay_blocked (replay attempt blocked)

Each event carries the full field set per SENTINEL's GO-09 telemetry
chain spec (unwind-amber-go09-telemetry-chain-spec.yaml, d262b2a).

Chain reconstruction: request_id → event_id → token_jti links the
full lifecycle of a single amber challenge from issue to resolution.

Framework-agnostic: events are emitted via callback (same pattern as
EnforcementTelemetry). No OpenClaw-specific logic.
"""

import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("unwind.enforcement.amber_telemetry")


# ---------------------------------------------------------------------------
# Event names (per GO-09 spec)
# ---------------------------------------------------------------------------

class AmberEventName:
    ISSUE = "unwind.amber_mediator.issue"
    RECEIVED = "unwind.amber_mediator.received"
    APPLIED = "unwind.amber_mediator.applied"
    REJECTED = "unwind.amber_mediator.rejected"
    REPLAY_BLOCKED = "unwind.amber_mediator.replay_blocked"


# ---------------------------------------------------------------------------
# Reason codes (per GO-09 spec)
# ---------------------------------------------------------------------------

class AmberReasonCode:
    # Issue
    AMBER_EVENT_ISSUED = "AMBER_EVENT_ISSUED"
    # Received
    AMBER_DECISION_RECEIVED = "AMBER_DECISION_RECEIVED"
    # Applied
    AMBER_DECISION_APPLIED = "AMBER_DECISION_APPLIED"
    # Rejected
    MEDIATOR_TOKEN_INVALID_SIGNATURE = "MEDIATOR_TOKEN_INVALID_SIGNATURE"
    MEDIATOR_TOKEN_EXPIRED = "MEDIATOR_TOKEN_EXPIRED"
    MEDIATOR_TOKEN_REPLAY = "MEDIATOR_TOKEN_REPLAY"
    MEDIATOR_TOKEN_EVENT_MISMATCH = "MEDIATOR_TOKEN_EVENT_MISMATCH"
    MEDIATOR_TOKEN_NONCE_MISMATCH = "MEDIATOR_TOKEN_NONCE_MISMATCH"
    MEDIATOR_TOKEN_ACTION_HASH_MISMATCH = "MEDIATOR_TOKEN_ACTION_HASH_MISMATCH"
    MEDIATOR_TOKEN_RISK_TIER_MISMATCH = "MEDIATOR_TOKEN_RISK_TIER_MISMATCH"
    MEDIATOR_TOKEN_CAPSULE_HASH_MISMATCH = "MEDIATOR_TOKEN_CAPSULE_HASH_MISMATCH"


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class AmberTelemetryEvent:
    """Structured amber mediator telemetry event.

    Carries the full field set per GO-09 spec. All fields optional
    except event_name and timestamp. to_dict() omits empty/default values.
    """
    # Common required
    event_name: str = ""
    timestamp: str = ""              # RFC 3339 UTC
    request_id: str = ""
    session_id: str = ""
    principal_id: str = ""
    event_id: str = ""
    pattern_id: str = ""
    risk_tier: str = ""
    challenge_nonce: str = ""
    challenge_seq: int = 0
    action_hash: str = ""
    reason_code: str = ""
    decision: str = ""               # approve | deny | none

    # Issue-specific
    challenge_expires_at: str = ""
    batch_id: str = ""               # nullable
    batch_group_key: str = ""
    batchable: Optional[bool] = None
    batch_max_size: int = 0
    risk_capsule_hash: str = ""

    # Received/Applied/Rejected
    token_jti: str = ""
    token_kid: str = ""
    token_iat: str = ""
    token_exp: str = ""
    validation_result: str = ""      # pass | fail

    # Applied-specific
    enforcement_outcome: str = ""    # approved_applied | denied_applied

    # Rejected-specific
    reject_stage: str = ""           # schema|signature|expiry|replay|binding|state|policy

    # Replay-specific
    replay_source: str = ""          # duplicate_jti|duplicate_event_resolution|duplicate_submission

    # Fields that MUST always be present per GO-09 common_required_fields
    _ALWAYS_EMIT = frozenset({
        "event_name", "timestamp", "request_id", "session_id",
        "principal_id", "event_id", "pattern_id", "risk_tier",
        "reason_code", "decision",
    })

    def to_dict(self) -> dict:
        """Convert to dict, omitting default/empty values for clean output.

        GO-09 common required fields are ALWAYS included, even if empty,
        to guarantee telemetry chain completeness.
        """
        d: dict = {}
        for k, v in self.__dict__.items():
            if k in self._ALWAYS_EMIT:
                d[k] = v  # Always include, even if empty
            elif v == "" or v == 0 or v is None:
                continue  # Omit optional defaults
            else:
                d[k] = v
        return d


# ---------------------------------------------------------------------------
# Callback type
# ---------------------------------------------------------------------------

AmberTelemetryCallback = Callable[[AmberTelemetryEvent], None]


def _default_amber_callback(event: AmberTelemetryEvent) -> None:
    """Default: log amber events at INFO level."""
    logger.info("AMBER_MEDIATOR %s", event.to_dict())


# ---------------------------------------------------------------------------
# Telemetry emitter
# ---------------------------------------------------------------------------

def _now_rfc3339() -> str:
    """Current time as RFC 3339 UTC string."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AmberTelemetry:
    """Telemetry emitter for amber mediator decision chain.

    Provides convenience methods for each of the 5 event types.
    Maintains in-memory log for testing + shadow parity analysis.
    """

    def __init__(self, callback: Optional[AmberTelemetryCallback] = None):
        self._callback = callback or _default_amber_callback
        self.event_log: list[AmberTelemetryEvent] = []

    def emit(self, event: AmberTelemetryEvent) -> None:
        """Emit an amber telemetry event."""
        self.event_log.append(event)
        self._callback(event)

    # ─── Issue ───────────────────────────────────────────────────

    def emit_issue(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_id: str = "default",
        event_id: str,
        pattern_id: str,
        risk_tier: str,
        challenge_nonce: str,
        challenge_seq: int,
        challenge_expires_at: str,
        action_hash: str,
        batch_group_key: str,
        batchable: bool,
        batch_max_size: int,
        risk_capsule_hash: str,
        batch_id: str = "",
    ) -> None:
        """Emit an amber challenge issuance event."""
        self.emit(AmberTelemetryEvent(
            event_name=AmberEventName.ISSUE,
            timestamp=_now_rfc3339(),
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            event_id=event_id,
            pattern_id=pattern_id,
            risk_tier=risk_tier,
            challenge_nonce=challenge_nonce,
            challenge_seq=challenge_seq,
            challenge_expires_at=challenge_expires_at,
            action_hash=action_hash,
            batch_id=batch_id,
            batch_group_key=batch_group_key,
            batchable=batchable,
            batch_max_size=batch_max_size,
            risk_capsule_hash=risk_capsule_hash,
            reason_code=AmberReasonCode.AMBER_EVENT_ISSUED,
            decision="none",
        ))

    # ─── Received ────────────────────────────────────────────────

    def emit_received(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_id: str = "default",
        event_id: str,
        pattern_id: str,
        risk_tier: str,
        challenge_nonce: str,
        challenge_seq: int,
        action_hash: str,
        token_jti: str,
        token_kid: str = "",
        token_iat: str = "",
        token_exp: str = "",
        validation_result: str = "pass",
        decision: str = "approve",
    ) -> None:
        """Emit an approval token received event."""
        self.emit(AmberTelemetryEvent(
            event_name=AmberEventName.RECEIVED,
            timestamp=_now_rfc3339(),
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            event_id=event_id,
            pattern_id=pattern_id,
            risk_tier=risk_tier,
            challenge_nonce=challenge_nonce,
            challenge_seq=challenge_seq,
            action_hash=action_hash,
            token_jti=token_jti,
            token_kid=token_kid,
            token_iat=token_iat,
            token_exp=token_exp,
            validation_result=validation_result,
            reason_code=AmberReasonCode.AMBER_DECISION_RECEIVED,
            decision=decision,
        ))

    # ─── Applied ─────────────────────────────────────────────────

    def emit_applied(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_id: str = "default",
        event_id: str,
        pattern_id: str,
        risk_tier: str,
        challenge_nonce: str,
        challenge_seq: int,
        action_hash: str,
        token_jti: str,
        enforcement_outcome: str,
        decision: str,
    ) -> None:
        """Emit an approval/denial applied event."""
        self.emit(AmberTelemetryEvent(
            event_name=AmberEventName.APPLIED,
            timestamp=_now_rfc3339(),
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            event_id=event_id,
            pattern_id=pattern_id,
            risk_tier=risk_tier,
            challenge_nonce=challenge_nonce,
            challenge_seq=challenge_seq,
            action_hash=action_hash,
            token_jti=token_jti,
            validation_result="pass",
            enforcement_outcome=enforcement_outcome,
            reason_code=AmberReasonCode.AMBER_DECISION_APPLIED,
            decision=decision,
        ))

    # ─── Rejected ────────────────────────────────────────────────

    def emit_rejected(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_id: str = "default",
        event_id: str,
        pattern_id: str,
        risk_tier: str,
        challenge_nonce: str,
        challenge_seq: int,
        action_hash: str,
        token_jti: str = "",
        reject_stage: str,
        reason_code: str,
        decision: str = "deny",
    ) -> None:
        """Emit a token validation rejected event."""
        self.emit(AmberTelemetryEvent(
            event_name=AmberEventName.REJECTED,
            timestamp=_now_rfc3339(),
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            event_id=event_id,
            pattern_id=pattern_id,
            risk_tier=risk_tier,
            challenge_nonce=challenge_nonce,
            challenge_seq=challenge_seq,
            action_hash=action_hash,
            token_jti=token_jti,
            validation_result="fail",
            reject_stage=reject_stage,
            reason_code=reason_code,
            decision=decision,
        ))

    # ─── Replay Blocked ─────────────────────────────────────────

    def emit_replay_blocked(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_id: str = "default",
        event_id: str,
        pattern_id: str,
        risk_tier: str,
        token_jti: str,
        replay_source: str,
        decision: str = "deny",
    ) -> None:
        """Emit a replay attempt blocked event."""
        self.emit(AmberTelemetryEvent(
            event_name=AmberEventName.REPLAY_BLOCKED,
            timestamp=_now_rfc3339(),
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            event_id=event_id,
            pattern_id=pattern_id,
            risk_tier=risk_tier,
            token_jti=token_jti,
            replay_source=replay_source,
            reason_code=AmberReasonCode.MEDIATOR_TOKEN_REPLAY,
            decision=decision,
        ))

    # ─── Chain reconstruction queries ────────────────────────────

    def chain_for_event(self, event_id: str) -> list[AmberTelemetryEvent]:
        """Reconstruct the full decision chain for an event_id.

        Returns events in chronological order: issue → received → applied/rejected/replay.
        """
        return [e for e in self.event_log if e.event_id == event_id]

    def chain_for_request(self, request_id: str) -> list[AmberTelemetryEvent]:
        """Reconstruct events for a request_id."""
        return [e for e in self.event_log if e.request_id == request_id]

    def events_by_name(self, event_name: str) -> list[AmberTelemetryEvent]:
        """Get all events of a specific type."""
        return [e for e in self.event_log if e.event_name == event_name]

    def summary(self) -> dict:
        """Audit summary: count by event type."""
        by_name: dict[str, int] = {}
        for e in self.event_log:
            by_name[e.event_name] = by_name.get(e.event_name, 0) + 1
        return {"total_events": len(self.event_log), "by_name": by_name}
