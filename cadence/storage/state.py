"""State file — atomic write to cadence/state.env.

A tiny auto-updating state file readable by any language, any sidecar,
any framework. Parseable by shell (source state.env), Python, TypeScript.

Write contract: atomic writes only (write to temp, then rename).
No partial reads possible.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..engine.rhythm import StateResult, TemporalState
from ..protocol.crip import CRIPHeaders


class StateFile:
    """Atomic state file writer/reader for cadence/state.env."""

    def __init__(self, path: Path, crip: Optional[CRIPHeaders] = None):
        self.path = path
        self.crip = crip or CRIPHeaders()

    def write(self, state_result: Optional[StateResult], last_direction: str = "in", last_tokens: int = 0) -> None:
        """Atomically write current state to state.env.

        Args:
            state_result: current rhythm inference (None = FLOW default)
            last_direction: "in" or "out"
            last_tokens: token count of last event
        """
        if state_result:
            user_state = state_result.state.value
            anomaly_score = f"{state_result.anomaly_score:.4f}"
            ert_seconds = f"{state_result.ert_seconds:.0f}"
        else:
            user_state = TemporalState.FLOW.value
            anomaly_score = "0.0000"
            ert_seconds = "0"

        crip = self.crip.to_state_dict()

        lines = [
            f"USER_STATE={user_state}",
            f"ANOMALY_SCORE={anomaly_score}",
            f"ERT_SECONDS={ert_seconds}",
            f"LAST_DIRECTION={last_direction}",
            f"LAST_TOKENS={last_tokens}",
            f"CONSENT={crip['CONSENT']}",
            f"RETENTION={crip['RETENTION']}",
            f"AUDIT={crip['AUDIT']}",
        ]

        content = "\n".join(lines) + "\n"

        # Atomic write: temp file then rename
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".env.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(self.path))

    def read(self) -> Optional[dict]:
        """Read current state from state.env.

        Returns dict of key-value pairs, or None if file doesn't exist.
        """
        if not self.path.exists():
            return None

        result = {}
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    result[key.strip()] = value.strip()
        return result

    def read_user_state(self) -> Optional[str]:
        """Quick read of just the USER_STATE value."""
        state = self.read()
        if state is None:
            return None
        return state.get("USER_STATE")

    def clear(self) -> None:
        """Remove the state file."""
        if self.path.exists():
            os.remove(self.path)
