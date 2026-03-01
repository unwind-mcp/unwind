"""CRIP — Consentful Rhythm Inference Protocol.

Every rhythm event and state update carries consent metadata.
No rhythm data is stored without its consent scope attached.

CRIP v1 fields:
  consent_scope  — where data may be processed (local_only, private_cloud, aggregate_only)
  retention      — how long data is kept (rolling_7d, rolling_30d, session_only, permanent)
  audit          — protocol version for verification (crip_v1)
  deletable      — whether user can selectively remove this entry (true/false)
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ConsentScope(Enum):
    LOCAL_ONLY = "local_only"
    PRIVATE_CLOUD = "private_cloud"
    AGGREGATE_ONLY = "aggregate_only"


class RetentionPolicy(Enum):
    ROLLING_7D = "rolling_7d"
    ROLLING_30D = "rolling_30d"
    SESSION_ONLY = "session_only"
    PERMANENT = "permanent"


CRIP_VERSION = "v1"


@dataclass(frozen=True)
class CRIPHeaders:
    """Consent headers attached to every rhythm data write."""

    consent_scope: ConsentScope = ConsentScope.LOCAL_ONLY
    retention: RetentionPolicy = RetentionPolicy.ROLLING_7D
    audit: str = CRIP_VERSION
    deletable: bool = True

    def to_pulse_dict(self) -> dict:
        """Fields for pulse.jsonl entries."""
        return {
            "consent_scope": self.consent_scope.value,
            "crip_version": self.audit,
        }

    def to_state_dict(self) -> dict:
        """Fields for state.env entries."""
        return {
            "CONSENT": self.consent_scope.value,
            "RETENTION": self.retention.value,
            "AUDIT": self.audit,
        }

    def validate(self) -> Optional[str]:
        """Validate headers. Returns error message or None."""
        if not isinstance(self.consent_scope, ConsentScope):
            return f"Invalid consent_scope: {self.consent_scope}"
        if not isinstance(self.retention, RetentionPolicy):
            return f"Invalid retention: {self.retention}"
        if self.audit != CRIP_VERSION:
            return f"Unknown CRIP version: {self.audit}"
        return None


# --- CRIP event types (emitted to pulse.jsonl on consent changes) ---

CRIP_EVENT_CONSENT_CHANGED = "CONSENT_CHANGED"
CRIP_EVENT_DATA_DELETED = "DATA_DELETED"
CRIP_EVENT_DATA_RESET = "DATA_RESET"
