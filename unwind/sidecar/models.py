"""Request/response models for adapter <-> sidecar policy API.

Source: UNWIND_SIDECAR_API_SPEC.yaml
        SIDECAR_SESSION_PRINCIPAL_DESIGN.yaml

Wire contract: adapter-neutral envelope. OpenClaw-specific mapping
happens at the adapter edge, not in these models (NanoClaw guardrail).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Policy check
# ---------------------------------------------------------------------------

@dataclass
class PolicyCheckRequest:
    """Inbound request from adapter plugin."""
    tool_name: str
    params: dict
    agent_id: str
    session_key: str
    request_id: Optional[str] = None
    timestamp: Optional[str] = None


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    MUTATE = "mutate"
    CHALLENGE_REQUIRED = "challenge_required"


@dataclass
class PolicyCheckResponse:
    """Outbound policy decision to adapter plugin."""
    decision: PolicyDecision
    block_reason: Optional[str] = None
    params: Optional[dict] = None
    decision_id: Optional[str] = None
    policy_version: Optional[str] = None
    evaluated_at: Optional[str] = None
    challenge_id: Optional[str] = None

    def to_wire(self) -> dict:
        """Serialize to wire format matching SIDECAR_API_SPEC."""
        result: dict = {"decision": self.decision.value}
        if self.block_reason is not None:
            result["blockReason"] = self.block_reason
        if self.params is not None:
            result["params"] = self.params
        if self.decision_id is not None:
            result["decisionId"] = self.decision_id
        if self.policy_version is not None:
            result["policyVersion"] = self.policy_version
        if self.evaluated_at is not None:
            result["evaluatedAt"] = self.evaluated_at
        if self.challenge_id is not None:
            result["challengeId"] = self.challenge_id
        return result


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """Inbound after_tool_call telemetry from adapter."""
    tool_name: str
    params: dict
    duration_ms: int
    result: Any = None
    error: Optional[str] = None
    agent_id: Optional[str] = None
    session_key: Optional[str] = None
    event_id: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class TelemetryEventResponse:
    """Acknowledgement for telemetry."""
    status: str = "accepted"
    event_id: Optional[str] = None
    received_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )

    def to_wire(self) -> dict:
        result: dict = {"status": self.status, "receivedAt": self.received_at}
        if self.event_id:
            result["eventId"] = self.event_id
        return result


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@dataclass
class HealthResponse:
    """Sidecar health status."""
    status: str  # "up", "degraded", "down"
    uptime_ms: int
    engine_version: str
    last_policy_check_ts: Optional[str] = None
    # Watchdog fields — detect adapter/hook silence
    watchdog_stale: bool = False           # True if no policy check within threshold
    watchdog_threshold_ms: int = 0         # Configured threshold
    active_sessions: int = 0              # Number of sessions with recent activity
    # P0-2: Enforcement-in-path verification
    mediation_active: bool = False        # True after first successful policy check
    tool_calls_processed: int = 0         # Count of policy checks processed

    def to_wire(self) -> dict:
        result = {
            "status": self.status,
            "uptimeMs": self.uptime_ms,
            "engineVersion": self.engine_version,
            "lastPolicyCheckTs": self.last_policy_check_ts,
        }
        if self.watchdog_stale:
            result["watchdogStale"] = True
        result["watchdogThresholdMs"] = self.watchdog_threshold_ms
        result["activeSessions"] = self.active_sessions
        result["mediationActive"] = self.mediation_active
        result["toolCallsProcessed"] = self.tool_calls_processed
        return result


# ---------------------------------------------------------------------------
# Ghost Mode (P3-10)
# ---------------------------------------------------------------------------

@dataclass
class GhostStatusResponse:
    """Ghost mode shadow VFS status."""
    ghost_mode: bool = False
    files_buffered: int = 0
    paths: list = field(default_factory=list)
    total_size_bytes: int = 0

    def to_wire(self) -> dict:
        return {
            "ghostMode": self.ghost_mode,
            "filesBuffered": self.files_buffered,
            "paths": self.paths,
            "totalSizeBytes": self.total_size_bytes,
        }


@dataclass
class GhostActionResponse:
    """Response for ghost approve/discard actions."""
    status: str  # "approved", "discarded"
    files_count: int = 0
    errors: list = field(default_factory=list)

    def to_wire(self) -> dict:
        result: dict = {"status": self.status, "filesCount": self.files_count}
        if self.errors:
            result["errors"] = self.errors
        return result


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------

@dataclass
class ErrorResponse:
    """Standard error response."""
    code: str
    message: str
    details: Optional[dict] = None

    def to_wire(self, request_id: Optional[str] = None) -> dict:
        result: dict = {
            "error": {"code": self.code, "message": self.message},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        if self.details:
            result["error"]["details"] = self.details
        if request_id:
            result["requestId"] = request_id
        return result
