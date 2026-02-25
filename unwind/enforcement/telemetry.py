"""Unified telemetry for the enforcement pipeline.

Provides structured event emission for all enforcement decisions — trust gate,
strict-mode blocks, breakglass overrides, budget events, and pipeline verdicts.

Architecture:
    Every enforcement decision that results in BLOCK, AMBER, KILL, or GHOST
    emits a structured TelemetryEvent through a configurable callback. This
    provides end-to-end forensic traceability per SENTINEL's telemetry schema.

    The approval_windows module has its own TelemetryEvent type — this module
    extends the pattern to cover the full pipeline. Both share the same
    structural approach: dataclass events + callback pattern + in-memory log.

Event categories:
    - TRUST_GATE:   Supply-chain verification decisions
    - STRICT_MODE:  Strict-mode flag enforcement (block/override)
    - PIPELINE:     Final pipeline verdict (allow/block/amber/kill/ghost)
    - BUDGET:       Budget debit events (debit/skip/exceeded)
    - BREAKGLASS:   Breakglass override activations in pipeline

Performance: WARM path. Event emission is fire-and-forget with no I/O
on the hot path. In-memory log for testing; production callback can
write to events.db or structured logging.
"""

import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger("unwind.enforcement.telemetry")


# ──────────────────────────────────────────────
# Event types
# ──────────────────────────────────────────────

class EventType:
    """Enforcement telemetry event types."""

    # Trust gate events
    TRUST_GATE_TRUSTED = "trust_gate_trusted"
    TRUST_GATE_BLOCKED = "trust_gate_blocked"
    TRUST_GATE_QUARANTINED = "trust_gate_quarantined"
    TRUST_GATE_EXPIRED = "trust_gate_expired"
    TRUST_GATE_SIGNATURE_INVALID = "trust_gate_signature_invalid"
    TRUST_GATE_UNTRUSTED = "trust_gate_untrusted"

    # Strict-mode enforcement events
    STRICT_MODE_BLOCK = "strict_mode_block"
    STRICT_MODE_BREAKGLASS_OVERRIDE = "strict_mode_breakglass_override"

    # Ghost Egress Guard events (stage 3b)
    GHOST_EGRESS_BLOCK = "ghost_egress_block"
    GHOST_EGRESS_ASK = "ghost_egress_ask"
    GHOST_EGRESS_ALLOW = "ghost_egress_allow"
    GHOST_EGRESS_DLP_HIT = "ghost_egress_dlp_hit"

    # Pipeline verdict events
    PIPELINE_ALLOW = "pipeline_allow"
    PIPELINE_BLOCK = "pipeline_block"
    PIPELINE_AMBER = "pipeline_amber"
    PIPELINE_KILL = "pipeline_kill"
    PIPELINE_GHOST = "pipeline_ghost"

    # Budget events
    BUDGET_DEBIT = "budget_debit"
    BUDGET_DEBIT_SKIPPED_DUPLICATE = "budget_debit_skipped_duplicate"
    BUDGET_EXCEEDED = "budget_exceeded"
    BUDGET_WARNING = "budget_warning"


# ──────────────────────────────────────────────
# Event dataclass
# ──────────────────────────────────────────────

@dataclass
class EnforcementEvent:
    """Structured enforcement telemetry event.

    Fields align with SENTINEL's unwind-telemetry-schema.yaml.
    All fields optional except event_type and timestamp.
    """
    event_type: str
    timestamp: float

    # Context
    session_id: str = ""
    request_id: str = ""          # upstream_id for correlation
    tool_name: str = ""
    tool_class: str = ""          # sensor/actuator/read/canary

    # Trust gate
    provider_id: str = ""
    provider_name: str = ""
    trust_verdict: str = ""       # trusted/blocked/quarantined/etc
    digest_match: str = ""        # true/false/none
    signature_valid: str = ""     # true/false/none

    # Strict mode
    strict_flag: str = ""         # Which flag was enforced
    reason_code: str = ""         # Machine-readable reason code
    block_reason: str = ""        # Human-readable block reason

    # Breakglass
    breakglass_token_id: str = ""
    breakglass_flags: str = ""    # Comma-separated overridden flags

    # Budget
    budget_tool_calls: int = -1   # Current count (-1 = N/A)
    budget_max_calls: int = -1    # Max allowed (-1 = N/A)
    upstream_id: str = ""         # For idempotency tracking

    # Pipeline stage
    pipeline_stage: str = ""      # Which stage emitted (0a, 0b, 1, 2, etc)

    def to_dict(self) -> dict:
        """Convert to dict, omitting default/empty values."""
        d: dict = {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
        }
        for k, v in self.__dict__.items():
            if k in ("event_type", "timestamp"):
                continue
            if v == "" or v == -1:
                continue
            d[k] = v
        return d


# ──────────────────────────────────────────────
# Callback type and default
# ──────────────────────────────────────────────

EnforcementTelemetryCallback = Callable[[EnforcementEvent], None]


def _default_enforcement_callback(event: EnforcementEvent) -> None:
    """Default: log enforcement events at INFO level."""
    logger.info("ENFORCEMENT %s", event.to_dict())


# ──────────────────────────────────────────────
# Telemetry emitter
# ──────────────────────────────────────────────

class EnforcementTelemetry:
    """Central telemetry emitter for the enforcement pipeline.

    Collects structured events from all pipeline stages and routes them
    to a configurable callback (logging, events.db, external sink, etc.).
    Maintains an in-memory log for testing and shadow-mode analysis.
    """

    def __init__(
        self,
        callback: Optional[EnforcementTelemetryCallback] = None,
    ):
        self._callback = callback or _default_enforcement_callback
        self.event_log: list[EnforcementEvent] = []

    def emit(self, event: EnforcementEvent) -> None:
        """Emit a telemetry event."""
        self.event_log.append(event)
        self._callback(event)

    # --- Convenience emitters for common patterns ---

    def emit_trust_gate(
        self,
        event_type: str,
        session_id: str = "",
        request_id: str = "",
        tool_name: str = "",
        provider_id: str = "",
        provider_name: str = "",
        trust_verdict: str = "",
        reason_code: str = "",
        block_reason: str = "",
        digest_match: str = "",
        signature_valid: str = "",
    ) -> None:
        """Emit a trust gate event."""
        self.emit(EnforcementEvent(
            event_type=event_type,
            timestamp=time.time(),
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            provider_id=provider_id,
            provider_name=provider_name,
            trust_verdict=trust_verdict,
            reason_code=reason_code,
            block_reason=block_reason,
            digest_match=digest_match,
            signature_valid=signature_valid,
            pipeline_stage="0b",
        ))

    def emit_strict_block(
        self,
        strict_flag: str,
        reason_code: str,
        block_reason: str,
        session_id: str = "",
        request_id: str = "",
        tool_name: str = "",
        pipeline_stage: str = "0b",
    ) -> None:
        """Emit a strict-mode block event."""
        self.emit(EnforcementEvent(
            event_type=EventType.STRICT_MODE_BLOCK,
            timestamp=time.time(),
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            strict_flag=strict_flag,
            reason_code=reason_code,
            block_reason=block_reason,
            pipeline_stage=pipeline_stage,
        ))

    def emit_breakglass_override(
        self,
        strict_flag: str,
        breakglass_token_id: str,
        session_id: str = "",
        request_id: str = "",
        tool_name: str = "",
    ) -> None:
        """Emit a breakglass override event (flag was bypassed)."""
        self.emit(EnforcementEvent(
            event_type=EventType.STRICT_MODE_BREAKGLASS_OVERRIDE,
            timestamp=time.time(),
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            strict_flag=strict_flag,
            breakglass_token_id=breakglass_token_id,
        ))

    def emit_pipeline_verdict(
        self,
        event_type: str,
        session_id: str = "",
        request_id: str = "",
        tool_name: str = "",
        tool_class: str = "",
        reason_code: str = "",
        block_reason: str = "",
        pipeline_stage: str = "",
    ) -> None:
        """Emit a pipeline final verdict event."""
        self.emit(EnforcementEvent(
            event_type=event_type,
            timestamp=time.time(),
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            tool_class=tool_class,
            reason_code=reason_code,
            block_reason=block_reason,
            pipeline_stage=pipeline_stage,
        ))

    def emit_budget_event(
        self,
        event_type: str,
        session_id: str,
        upstream_id: str = "",
        budget_tool_calls: int = -1,
        budget_max_calls: int = -1,
        reason_code: str = "",
    ) -> None:
        """Emit a budget-related event."""
        self.emit(EnforcementEvent(
            event_type=event_type,
            timestamp=time.time(),
            session_id=session_id,
            upstream_id=upstream_id,
            budget_tool_calls=budget_tool_calls,
            budget_max_calls=budget_max_calls,
            reason_code=reason_code,
        ))

    # --- Query/audit ---

    def events_by_type(self, event_type: str) -> list[EnforcementEvent]:
        """Get all events of a specific type."""
        return [e for e in self.event_log if e.event_type == event_type]

    def events_for_session(self, session_id: str) -> list[EnforcementEvent]:
        """Get all events for a specific session."""
        return [e for e in self.event_log if e.session_id == session_id]

    def summary(self) -> dict:
        """Return audit summary of telemetry state."""
        by_type: dict[str, int] = {}
        for e in self.event_log:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        return {
            "total_events": len(self.event_log),
            "by_type": by_type,
        }
