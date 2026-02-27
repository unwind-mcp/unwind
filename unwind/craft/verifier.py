"""CRAFT ingress verifier core (milestone 1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .canonical import mac_input_bytes
from .crypto import DirectionalKeys, b64url_decode, hmac_sha256


class VerifyError(str, Enum):
    ERR_ENVELOPE_INVALID = "ERR_ENVELOPE_INVALID"  # generic pre-auth
    ERR_REPLAY = "ERR_REPLAY"
    ERR_STATE_DIVERGED = "ERR_STATE_DIVERGED"
    ERR_CONTEXT_MISMATCH = "ERR_CONTEXT_MISMATCH"
    ERR_EPOCH_STALE = "ERR_EPOCH_STALE"


@dataclass(frozen=True)
class VerifyResult:
    accepted: bool
    error: VerifyError | None = None


@dataclass
class ReplayWindow:
    width: int = 1024
    seen: set[int] = field(default_factory=set)

    def contains(self, seq: int) -> bool:
        return seq in self.seen

    def mark(self, seq: int) -> None:
        self.seen.add(seq)
        floor = seq - self.width
        if floor > 0 and len(self.seen) > self.width * 2:
            self.seen = {s for s in self.seen if s >= floor}


@dataclass
class CraftSessionState:
    session_id: str
    account_id: str
    channel_id: str
    conversation_id: str
    context_type: str
    current_epoch: int
    keys_c2p: DirectionalKeys
    keys_p2c: DirectionalKeys

    highest_seq: dict[str, int] = field(default_factory=lambda: {"c2p": 0, "p2c": 0})
    last_state_commit: dict[str, bytes] = field(default_factory=dict)
    replay_bitmap: dict[str, ReplayWindow] = field(
        default_factory=lambda: {"c2p": ReplayWindow(), "p2c": ReplayWindow()}
    )

    def keys_for_direction(self, direction: str) -> DirectionalKeys:
        if direction == "c2p":
            return self.keys_c2p
        if direction == "p2c":
            return self.keys_p2c
        raise ValueError(f"Invalid direction: {direction}")


class CraftVerifier:
    """Verifier implementing v4.2 ingress provenance boundary."""

    REQUIRED_FIELDS = {
        "v",
        "epoch",
        "session_id",
        "account_id",
        "channel_id",
        "conversation_id",
        "context_type",
        "seq",
        "ts_ms",
        "state_commit",
        "msg_type",
        "direction",
        "payload",
        "mac",
    }

    @staticmethod
    def _parse_seq(raw: Any) -> int:
        if isinstance(raw, int):
            seq = raw
        elif isinstance(raw, str) and raw.isdigit():
            seq = int(raw)
        else:
            raise ValueError("Invalid seq")
        if seq <= 0:
            raise ValueError("seq must be > 0")
        return seq

    @staticmethod
    def _hmac_eq(a: bytes, b: bytes) -> bool:
        import hmac

        return hmac.compare_digest(a, b)

    def verify_and_admit(self, envelope: dict[str, Any], session: CraftSessionState) -> VerifyResult:
        # --- Pre-auth checks (generic error only) ---
        if not isinstance(envelope, dict):
            return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)
        if not self.REQUIRED_FIELDS.issubset(envelope.keys()):
            return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)

        try:
            direction = str(envelope["direction"])
            if direction not in ("c2p", "p2c"):
                return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)

            epoch = int(envelope["epoch"])
            if epoch != session.current_epoch:
                # pre-auth generic by policy
                return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)

            seq = self._parse_seq(envelope["seq"])

            keyset = session.keys_for_direction(direction)
            raw_mac = b64url_decode(str(envelope["mac"]))

            mac_in = mac_input_bytes(envelope)
            mac_expected = hmac_sha256(keyset.k_msg, mac_in)
            if not self._hmac_eq(raw_mac, mac_expected):
                return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)
        except Exception:
            return VerifyResult(False, VerifyError.ERR_ENVELOPE_INVALID)

        # --- Post-auth checks (typed errors) ---
        if envelope["session_id"] != session.session_id:
            return VerifyResult(False, VerifyError.ERR_CONTEXT_MISMATCH)
        if envelope["account_id"] != session.account_id:
            return VerifyResult(False, VerifyError.ERR_CONTEXT_MISMATCH)
        if envelope["channel_id"] != session.channel_id:
            return VerifyResult(False, VerifyError.ERR_CONTEXT_MISMATCH)
        if envelope["conversation_id"] != session.conversation_id:
            return VerifyResult(False, VerifyError.ERR_CONTEXT_MISMATCH)
        if envelope["context_type"] != session.context_type:
            return VerifyResult(False, VerifyError.ERR_CONTEXT_MISMATCH)

        expected_seq = session.highest_seq[direction] + 1
        if seq != expected_seq:
            return VerifyResult(False, VerifyError.ERR_REPLAY)
        if session.replay_bitmap[direction].contains(seq):
            return VerifyResult(False, VerifyError.ERR_REPLAY)

        try:
            state_commit_wire = b64url_decode(str(envelope["state_commit"]))
        except Exception:
            return VerifyResult(False, VerifyError.ERR_STATE_DIVERGED)

        prior_commit = session.last_state_commit.get(direction)
        if prior_commit is None:
            return VerifyResult(False, VerifyError.ERR_STATE_DIVERGED)

        expected_commit = hmac_sha256(keyset.k_state, prior_commit + raw_mac)
        if not self._hmac_eq(state_commit_wire, expected_commit):
            return VerifyResult(False, VerifyError.ERR_STATE_DIVERGED)

        # Atomic commit (single-threaded milestone implementation)
        session.highest_seq[direction] = seq
        session.last_state_commit[direction] = expected_commit
        session.replay_bitmap[direction].mark(seq)

        return VerifyResult(True, None)
