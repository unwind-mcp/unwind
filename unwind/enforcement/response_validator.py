"""Response Principal Validation (R-SESS-003/004).

Ensures that tool call responses are delivered only to the session
that originated the request. Prevents cross-session response routing
attacks where a response from one agent's request is delivered to
another agent's session.

Architecture:
  Request: agent → UNWIND → upstream (tagged with session_id + request_nonce)
  Response: upstream → UNWIND → validate(session_id matches) → agent

This module also tracks per-session request budgets (R-SEN-003)
for autonomous principals like SENTINEL cron jobs.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("unwind.enforcement.response_validator")


@dataclass
class PendingRequest:
    """Track a request in flight, bound to its originating session."""
    upstream_id: Any           # The ID sent to upstream
    agent_id: Any              # The original agent request ID
    session_id: str            # Session that sent this request
    tool_name: str             # What tool was called
    timestamp: float           # When the request was sent
    tag: Optional[str] = None  # "tools_list", "tool_result", etc.
    future: Any = None         # asyncio.Future for tool_result responses


@dataclass
class SessionBudget:
    """Per-session resource budget tracking (R-SEN-003).

    Enforces limits on autonomous sessions (SENTINEL cron, etc.)
    to prevent runaway behaviour or resource exhaustion.
    """
    max_tool_calls: int = 0         # 0 = unlimited
    max_runtime_seconds: float = 0  # 0 = unlimited
    max_output_bytes: int = 0       # 0 = unlimited
    max_write_bytes: int = 0        # 0 = unlimited

    # Counters
    tool_calls: int = 0
    start_time: float = field(default_factory=time.time)
    output_bytes: int = 0
    write_bytes: int = 0

    def check_budget(self) -> Optional[str]:
        """Check if any budget limit is exceeded.

        Returns error message if exceeded, None if within budget.
        """
        if self.max_tool_calls > 0 and self.tool_calls >= self.max_tool_calls:
            return (
                f"Session budget exceeded: {self.tool_calls}/{self.max_tool_calls} "
                f"tool calls (R-SEN-003)"
            )

        if self.max_runtime_seconds > 0:
            elapsed = time.time() - self.start_time
            if elapsed >= self.max_runtime_seconds:
                return (
                    f"Session budget exceeded: {elapsed:.0f}s/"
                    f"{self.max_runtime_seconds:.0f}s runtime (R-SEN-003)"
                )

        if self.max_output_bytes > 0 and self.output_bytes >= self.max_output_bytes:
            return (
                f"Session budget exceeded: {self.output_bytes}/{self.max_output_bytes} "
                f"output bytes (R-SEN-003)"
            )

        if self.max_write_bytes > 0 and self.write_bytes >= self.max_write_bytes:
            return (
                f"Session budget exceeded: {self.write_bytes}/{self.max_write_bytes} "
                f"write bytes (R-SEN-003)"
            )

        return None

    def check_warning_threshold(self, threshold: float = 0.8) -> Optional[str]:
        """Check if any budget is above warning threshold (default 80%).

        Returns warning message if above threshold, None if OK.
        """
        warnings = []

        if self.max_tool_calls > 0:
            ratio = self.tool_calls / self.max_tool_calls
            if ratio >= threshold:
                warnings.append(f"tool_calls {self.tool_calls}/{self.max_tool_calls}")

        if self.max_runtime_seconds > 0:
            elapsed = time.time() - self.start_time
            ratio = elapsed / self.max_runtime_seconds
            if ratio >= threshold:
                warnings.append(f"runtime {elapsed:.0f}s/{self.max_runtime_seconds:.0f}s")

        if self.max_output_bytes > 0:
            ratio = self.output_bytes / self.max_output_bytes
            if ratio >= threshold:
                warnings.append(f"output {self.output_bytes}/{self.max_output_bytes}B")

        if warnings:
            return f"Budget warning ({threshold*100:.0f}%): {', '.join(warnings)}"
        return None

    def record_tool_call(self) -> None:
        """Increment tool call counter."""
        self.tool_calls += 1

    def record_output(self, size_bytes: int) -> None:
        """Record output bytes."""
        self.output_bytes += size_bytes

    def record_write(self, size_bytes: int) -> None:
        """Record write bytes."""
        self.write_bytes += size_bytes

    def reset(self) -> None:
        """Reset counters (new cron invocation)."""
        self.tool_calls = 0
        self.start_time = time.time()
        self.output_bytes = 0
        self.write_bytes = 0


class ResponseValidator:
    """Validates that upstream responses match their originating session.

    Maintains a registry of pending requests, each bound to a session_id.
    When a response arrives, validates that:
    1. The upstream_id maps to a known pending request
    2. The originating session is still alive (not killed/expired)
    3. Response is delivered only to the correct session

    Also manages per-session budgets for autonomous principals.
    """

    def __init__(self, telemetry=None):
        self._pending: dict[Any, PendingRequest] = {}
        self._budgets: dict[str, SessionBudget] = {}
        # Idempotency: set of upstream_ids that have already been debited
        self._debited: set[Any] = set()
        # Optional telemetry emitter (from telemetry.py)
        self._telemetry = telemetry

    def register_request(
        self,
        upstream_id: Any,
        agent_id: Any,
        session_id: str,
        tool_name: str = "",
        tag: Optional[str] = None,
        future: Any = None,
    ) -> PendingRequest:
        """Register a new pending request bound to a session."""
        req = PendingRequest(
            upstream_id=upstream_id,
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            timestamp=time.time(),
            tag=tag,
            future=future,
        )
        self._pending[upstream_id] = req
        return req

    def validate_response(self, upstream_id: Any, expected_session_id: Optional[str] = None) -> tuple[Optional[PendingRequest], Optional[str]]:
        """Validate an upstream response against its pending request.

        Args:
            upstream_id: The response ID from upstream
            expected_session_id: If provided, verify session matches

        Returns:
            (PendingRequest, None) if valid
            (None, error_message) if invalid
        """
        req = self._pending.pop(upstream_id, None)

        if req is None:
            return None, f"Response principal violation: unknown upstream_id {upstream_id} (no matching request)"

        # If caller specifies expected session, verify match (R-SESS-003/004)
        if expected_session_id is not None and req.session_id != expected_session_id:
            logger.critical(
                "RESPONSE PRINCIPAL MISMATCH: response for session %s "
                "arrived on session %s (upstream_id=%s, tool=%s)",
                req.session_id, expected_session_id, upstream_id, req.tool_name,
            )
            return None, (
                f"Response principal violation: request was from session "
                f"{req.session_id} but response arrived on session "
                f"{expected_session_id} (R-SESS-003)"
            )

        # Check for stale requests (timeout guard)
        age = time.time() - req.timestamp
        if age > 60.0:  # Hard timeout: 60 seconds
            logger.warning(
                "Stale response: upstream_id=%s, age=%.1fs, tool=%s",
                upstream_id, age, req.tool_name,
            )
            # Still deliver — but log the warning

        return req, None

    def pending_count(self) -> int:
        """Number of requests still in flight."""
        return len(self._pending)

    def pending_for_session(self, session_id: str) -> list[PendingRequest]:
        """Get all pending requests for a specific session."""
        return [r for r in self._pending.values() if r.session_id == session_id]

    def cancel_session(self, session_id: str) -> int:
        """Cancel all pending requests for a killed/expired session.

        Returns the number of cancelled requests.
        """
        to_cancel = [uid for uid, req in self._pending.items() if req.session_id == session_id]
        for uid in to_cancel:
            req = self._pending.pop(uid)
            if req.future and not req.future.done():
                req.future.set_result({"error": f"Session {session_id} cancelled"})
        return len(to_cancel)

    # --- Budget Management ---

    def set_budget(self, session_id: str, budget: SessionBudget) -> None:
        """Set a resource budget for a session."""
        self._budgets[session_id] = budget

    def get_budget(self, session_id: str) -> Optional[SessionBudget]:
        """Get the budget for a session, if any."""
        return self._budgets.get(session_id)

    def check_budget(self, session_id: str) -> Optional[str]:
        """Check if a session's budget is exceeded.

        Returns error message if exceeded, None if OK or no budget set.
        """
        budget = self._budgets.get(session_id)
        if budget is None:
            return None  # No budget = unlimited
        return budget.check_budget()

    def record_tool_call(
        self, session_id: str, upstream_id: Any = None
    ) -> Optional[str]:
        """Record a tool call and check budget.

        Idempotent: if upstream_id has already been debited, skips the
        debit and returns the current budget status without double-counting.
        This prevents retry/re-registration from inflating the count.

        Args:
            session_id: The session to debit
            upstream_id: Dedupe key (typically the upstream request ID).
                         If None, a deterministic fallback is used (no dedup).

        Returns error if budget exceeded, None if OK.
        """
        budget = self._budgets.get(session_id)
        if budget is None:
            return None

        # Idempotency guard: skip debit if already counted
        if upstream_id is not None:
            if upstream_id in self._debited:
                logger.debug(
                    "Budget debit skipped (idempotent): upstream_id=%s session=%s",
                    upstream_id, session_id,
                )
                # Emit telemetry: duplicate debit skipped
                if self._telemetry is not None:
                    from .telemetry import EventType
                    self._telemetry.emit_budget_event(
                        event_type=EventType.BUDGET_DEBIT_SKIPPED_DUPLICATE,
                        session_id=session_id,
                        upstream_id=str(upstream_id),
                        budget_tool_calls=budget.tool_calls,
                        budget_max_calls=budget.max_tool_calls,
                        reason_code="BUDGET_DEBIT_SKIPPED_DUPLICATE",
                    )
                return budget.check_budget()
            self._debited.add(upstream_id)

        budget.record_tool_call()

        # Emit telemetry: successful debit
        if self._telemetry is not None:
            from .telemetry import EventType
            self._telemetry.emit_budget_event(
                event_type=EventType.BUDGET_DEBIT,
                session_id=session_id,
                upstream_id=str(upstream_id) if upstream_id is not None else "",
                budget_tool_calls=budget.tool_calls,
                budget_max_calls=budget.max_tool_calls,
            )

        exceeded = budget.check_budget()
        if exceeded and self._telemetry is not None:
            from .telemetry import EventType
            self._telemetry.emit_budget_event(
                event_type=EventType.BUDGET_EXCEEDED,
                session_id=session_id,
                upstream_id=str(upstream_id) if upstream_id is not None else "",
                budget_tool_calls=budget.tool_calls,
                budget_max_calls=budget.max_tool_calls,
                reason_code="BUDGET_EXCEEDED",
            )
        return exceeded

    def clear_debit(self, upstream_id: Any) -> None:
        """Remove a debit record (e.g., when a request is cancelled).

        Allows the upstream_id to be debited again if re-registered.
        """
        self._debited.discard(upstream_id)
