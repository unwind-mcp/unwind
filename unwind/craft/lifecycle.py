"""CRAFT rekey/resync/session lifecycle manager (milestone 3)."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .canonical import canonicalize_json, mac_input_bytes
from .crypto import (
    b64url_decode,
    b64url_encode,
    derive_keys_from_prk,
    derive_rekey_prk,
    hmac_sha256,
    state_commit_0,
)
from .verifier import CraftSessionState


class ResyncError(str, Enum):
    ERR_RESYNC_RATE_LIMIT = "ERR_RESYNC_RATE_LIMIT"
    ERR_RESYNC_BOUNDS = "ERR_RESYNC_BOUNDS"
    ERR_RESYNC_CHALLENGE_INVALID = "ERR_RESYNC_CHALLENGE_INVALID"
    ERR_RESYNC_PROOF_INVALID = "ERR_RESYNC_PROOF_INVALID"
    ERR_RESYNC_STATE_DIVERGED = "ERR_RESYNC_STATE_DIVERGED"


@dataclass(frozen=True)
class RekeyPrepare:
    session_id: str
    epoch_new: int
    boundary_seq_c2p: int
    boundary_seq_p2c: int
    action: str = "rekey_prepare"


@dataclass(frozen=True)
class ResyncChallenge:
    session_id: str
    direction: str
    epoch: int
    expected_seq: int
    challenge_nonce: str
    expires_at_ms: int
    mac: str


@dataclass(frozen=True)
class ResyncResult:
    ok: bool
    error: ResyncError | None = None
    new_epoch: int | None = None


class CraftLifecycleManager:
    """Implements rekey/resync control flow from CRAFT v4.2."""

    def __init__(
        self,
        *,
        max_resync_attempts_per_minute: int = 5,
        max_missing_envelopes: int = 256,
        max_missing_envelopes_bytes: int = 4 * 1024 * 1024,
        challenge_ttl_ms: int = 60_000,
        session_ttl_ms: int = 24 * 60 * 60 * 1000,
        cap_grace_ms: int = 120_000,
        now_ms_fn: Any = None,
    ):
        self.max_resync_attempts_per_minute = max_resync_attempts_per_minute
        self.max_missing_envelopes = max_missing_envelopes
        self.max_missing_envelopes_bytes = max_missing_envelopes_bytes
        self.challenge_ttl_ms = challenge_ttl_ms
        self.session_ttl_ms = session_ttl_ms
        self.cap_grace_ms = cap_grace_ms
        self._now_ms_fn = now_ms_fn or (lambda: int(time.time() * 1000))

        self._resync_challenges: dict[str, ResyncChallenge] = {}
        self._resync_attempts: dict[str, list[int]] = {}
        self._resync_failures: dict[str, int] = {}
        self._resync_backoff_until_ms: dict[str, int] = {}

    def now_ms(self) -> int:
        return int(self._now_ms_fn())

    def is_session_expired(self, session: CraftSessionState) -> bool:
        return self.now_ms() - session.started_at_ms > self.session_ttl_ms

    def refresh_cap_epoch_grace(self, session: CraftSessionState) -> None:
        """Prune expired grace epochs and keep lifecycle maps consistent."""
        now = self.now_ms()
        keep_epochs = {session.current_epoch}

        for epoch, until_ms in list(session.cap_epoch_grace_until_ms.items()):
            if now <= int(until_ms):
                keep_epochs.add(int(epoch))
            else:
                session.cap_epoch_grace_until_ms.pop(int(epoch), None)

        # prune keys + allowed set to bounded valid epochs
        session.current_or_grace_epochs = set(keep_epochs)
        session.cap_keys_by_epoch = {
            int(e): k for e, k in session.cap_keys_by_epoch.items() if int(e) in keep_epochs
        }

    def initiate_rekey(self, session: CraftSessionState) -> RekeyPrepare:
        """P-initiated rekey with boundary markers."""
        return RekeyPrepare(
            session_id=session.session_id,
            epoch_new=session.current_epoch + 1,
            boundary_seq_c2p=session.highest_seq["c2p"] + 1,
            boundary_seq_p2c=session.highest_seq["p2c"] + 1,
        )

    def apply_rekey_ack(self, session: CraftSessionState, prepare: RekeyPrepare) -> None:
        """Apply rekey transition after authenticated rekey_ack.

        Uses last committed state_commit values (idle direction value unchanged).
        Enforces boundary marker semantics from v4.2.
        """
        if session.prk is None or session.prk_cap_root is None or not session.ctx:
            raise ValueError("Session missing PRK/PRK_cap_root/ctx required for rekey")

        if prepare.session_id != session.session_id:
            raise ValueError("Rekey prepare session mismatch")

        epoch_new = int(prepare.epoch_new)
        if epoch_new != session.current_epoch + 1:
            raise ValueError("Invalid epoch transition")

        expected_boundary_c2p = session.highest_seq["c2p"] + 1
        expected_boundary_p2c = session.highest_seq["p2c"] + 1
        if int(prepare.boundary_seq_c2p) != expected_boundary_c2p:
            raise ValueError("Invalid rekey boundary_seq_c2p")
        if int(prepare.boundary_seq_p2c) != expected_boundary_p2c:
            raise ValueError("Invalid rekey boundary_seq_p2c")

        commit_c2p = session.last_state_commit.get("c2p")
        commit_p2c = session.last_state_commit.get("p2c")
        if commit_c2p is None or commit_p2c is None:
            raise ValueError("Missing directional state commits for rekey")

        prk_new = derive_rekey_prk(
            prk_current=session.prk,
            state_commit_c2p_current=commit_c2p,
            state_commit_p2c_current=commit_p2c,
            epoch_new=epoch_new,
        )

        keys_new = derive_keys_from_prk(
            prk=prk_new,
            prk_cap_root=session.prk_cap_root,
            ctx=session.ctx,
            epoch=epoch_new,
        )

        # Epoch switch
        session.current_epoch = epoch_new
        session.keys_c2p = keys_new.c2p
        session.keys_p2c = keys_new.p2c
        session.prk = keys_new.prk

        session.highest_seq["c2p"] = 0
        session.highest_seq["p2c"] = 0
        session.last_state_commit["c2p"] = state_commit_0(keys_new.c2p.k_state, session.ctx)
        session.last_state_commit["p2c"] = state_commit_0(keys_new.p2c.k_state, session.ctx)
        session.replay_bitmap["c2p"].seen.clear()
        session.replay_bitmap["p2c"].seen.clear()
        session.pending_envelopes["c2p"].clear()
        session.pending_envelopes["p2c"].clear()

        # capability epoch lifecycle: time-bounded grace window for previous epoch only
        now = self.now_ms()
        previous_epoch = epoch_new - 1

        session.cap_keys_by_epoch[epoch_new] = keys_new.k_cap_srv

        # Keep ONLY previous epoch in grace window.
        if previous_epoch in session.cap_keys_by_epoch:
            session.cap_epoch_grace_until_ms[previous_epoch] = now + self.cap_grace_ms

        session.current_or_grace_epochs = {epoch_new}
        if previous_epoch in session.cap_keys_by_epoch:
            session.current_or_grace_epochs.add(previous_epoch)

        # Drop all older epoch material immediately.
        session.cap_keys_by_epoch = {
            e: k for e, k in session.cap_keys_by_epoch.items() if e in session.current_or_grace_epochs
        }
        session.cap_epoch_grace_until_ms = {
            e: t for e, t in session.cap_epoch_grace_until_ms.items() if e in session.current_or_grace_epochs
        }

        self.refresh_cap_epoch_grace(session)

        session.last_rekey_at_ms = now

    def issue_resync_challenge(self, session: CraftSessionState, direction: str) -> ResyncChallenge:
        if direction not in ("c2p", "p2c"):
            raise ValueError("direction must be c2p or p2c")

        nonce = b64url_encode(os.urandom(16))
        challenge_fields = {
            "session_id": session.session_id,
            "direction": direction,
            "epoch": session.current_epoch,
            "expected_seq": session.highest_seq[direction] + 1,
            "challenge_nonce": nonce,
            "expires_at_ms": self.now_ms() + self.challenge_ttl_ms,
        }
        # P->C challenge MAC uses p2c resync key
        mac = b64url_encode(
            hmac_sha256(
                session.keys_for_direction("p2c").k_resync,
                canonicalize_json(challenge_fields).encode("utf-8"),
            )
        )
        ch = ResyncChallenge(mac=mac, **challenge_fields)
        self._resync_challenges[nonce] = ch
        return ch

    def _rate_limit_ok(self, session_id: str) -> bool:
        now = self.now_ms()
        backoff_until = self._resync_backoff_until_ms.get(session_id, 0)
        if now < backoff_until:
            return False

        arr = self._resync_attempts.setdefault(session_id, [])
        arr[:] = [t for t in arr if now - t <= 60_000]
        if len(arr) >= self.max_resync_attempts_per_minute:
            return False
        arr.append(now)
        return True

    def _register_resync_failure(self, session_id: str) -> None:
        now = self.now_ms()
        n = self._resync_failures.get(session_id, 0) + 1
        self._resync_failures[session_id] = n
        # Exponential backoff capped at 60s.
        backoff_ms = min(60_000, 1_000 * (2 ** min(n, 6)))
        self._resync_backoff_until_ms[session_id] = now + backoff_ms

    def _clear_resync_failures(self, session_id: str) -> None:
        self._resync_failures.pop(session_id, None)
        self._resync_backoff_until_ms.pop(session_id, None)

    def _proof_mac_ok(self, session: CraftSessionState, proof: dict[str, Any]) -> bool:
        try:
            got = b64url_decode(str(proof["mac"]))
        except Exception:
            return False
        fields = {k: v for k, v in proof.items() if k != "mac"}
        expected = hmac_sha256(
            session.keys_for_direction("c2p").k_resync,
            canonicalize_json(fields).encode("utf-8"),
        )
        import hmac

        return hmac.compare_digest(got, expected)

    def handle_resync(
        self,
        session: CraftSessionState,
        proof: dict[str, Any],
    ) -> ResyncResult:
        """Validate resync proof, walk missing envelopes, then epoch-bump rekey."""

        def _fail(err: ResyncError, *, terminate: bool = False) -> ResyncResult:
            self._register_resync_failure(session.session_id)
            if terminate:
                self.teardown_session(session)
            return ResyncResult(False, err)

        if not self._rate_limit_ok(session.session_id):
            # B3: rate-limit breach terminates session (fail-closed)
            return _fail(ResyncError.ERR_RESYNC_RATE_LIMIT, terminate=True)

        if not self._proof_mac_ok(session, proof):
            return _fail(ResyncError.ERR_RESYNC_PROOF_INVALID)

        nonce = str(proof.get("challenge_nonce", ""))
        ch = self._resync_challenges.pop(nonce, None)
        if not ch:
            return _fail(ResyncError.ERR_RESYNC_CHALLENGE_INVALID)

        now = self.now_ms()
        if now > ch.expires_at_ms:
            return _fail(ResyncError.ERR_RESYNC_CHALLENGE_INVALID)

        direction = str(proof.get("direction", ""))
        if direction != ch.direction:
            return _fail(ResyncError.ERR_RESYNC_CHALLENGE_INVALID)

        missing_envelopes = list(proof.get("missing_envelopes", []))
        missing_count = len(missing_envelopes)
        missing_bytes = sum(len(canonicalize_json(e).encode("utf-8")) for e in missing_envelopes)
        if missing_count > self.max_missing_envelopes or missing_bytes > self.max_missing_envelopes_bytes:
            # B7: bounds violation terminates session (fail-closed)
            return _fail(ResyncError.ERR_RESYNC_BOUNDS, terminate=True)

        # Check monotonic client claim
        client_highest_seq = int(proof.get("client_highest_seq", 0))
        if client_highest_seq < session.highest_seq[direction]:
            return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

        # Walk chain forward from local state
        keyset = session.keys_for_direction(direction)
        expected_seq = session.highest_seq[direction] + 1
        commit = session.last_state_commit[direction]

        ordered = sorted(missing_envelopes, key=lambda e: int(e.get("seq", 0)))
        for env in ordered:
            # Validate epoch and sequence
            if int(env.get("epoch", -1)) != session.current_epoch:
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)
            if int(env.get("seq", -1)) != expected_seq:
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

            # Validate MAC
            try:
                raw_mac = b64url_decode(str(env["mac"]))
                mac_expected = hmac_sha256(keyset.k_msg, mac_input_bytes(env))
            except Exception:
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)
            import hmac

            if not hmac.compare_digest(raw_mac, mac_expected):
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

            # Validate state chain
            commit_expected = hmac_sha256(keyset.k_state, commit + raw_mac)
            try:
                wire_commit = b64url_decode(str(env["state_commit"]))
            except Exception:
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)
            if not hmac.compare_digest(wire_commit, commit_expected):
                return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

            commit = commit_expected
            expected_seq += 1

        # Validate client target state_commit
        try:
            client_state_commit = b64url_decode(str(proof.get("client_state_commit", "")))
        except Exception:
            return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

        import hmac

        if not hmac.compare_digest(client_state_commit, commit):
            return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

        # Enforce continuity: claimed highest seq must exactly match walked chain
        walked_highest_seq = expected_seq - 1
        if client_highest_seq != walked_highest_seq:
            return _fail(ResyncError.ERR_RESYNC_STATE_DIVERGED)

        # Commit walked state
        session.highest_seq[direction] = walked_highest_seq
        session.last_state_commit[direction] = commit

        # Resync is a rekey event
        prepare = self.initiate_rekey(session)
        self.apply_rekey_ack(session, prepare)

        self._clear_resync_failures(session.session_id)
        return ResyncResult(True, None, new_epoch=session.current_epoch)

    def teardown_session(self, session: CraftSessionState, *, max_network_delay_ms: int = 5000) -> None:
        """Authenticated teardown semantics for session lifecycle.

        Tombstone retention = max(600s, 2x max tolerated network delay).
        """
        retention = max(600_000, 2 * max_network_delay_ms)
        session.tombstoned_until_ms = self.now_ms() + retention

        # Best-effort zeroization by replacing key references
        session.prk = b""
        session.prk_cap_root = b""
        session.keys_c2p = type(session.keys_c2p)(k_msg=b"", k_state=b"", k_resync=b"")
        session.keys_p2c = type(session.keys_p2c)(k_msg=b"", k_state=b"", k_resync=b"")
        session.cap_keys_by_epoch.clear()
        session.current_or_grace_epochs.clear()
        session.cap_epoch_grace_until_ms.clear()
