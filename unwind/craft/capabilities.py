"""CRAFT capability token subsystem (milestone 2).

Implements v4.2 dispatch-only capability enforcement boundary.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonicalize_json
from .crypto import b64url_decode, b64url_encode, hmac_sha256
from .verifier import CraftSessionState


class CapabilityError(str, Enum):
    ERR_CAP_REQUIRED = "ERR_CAP_REQUIRED"
    ERR_CAP_INVALID = "ERR_CAP_INVALID"


class CapabilitySubcode(str, Enum):
    CAP_EXPIRED = "CAP_EXPIRED"
    CAP_REVOKED = "CAP_REVOKED"
    CAP_USE_EXHAUSTED = "CAP_USE_EXHAUSTED"
    CAP_EPOCH_MISMATCH = "CAP_EPOCH_MISMATCH"
    CAP_SCOPE_MISMATCH = "CAP_SCOPE_MISMATCH"
    CAP_LINEAGE_INVALID = "CAP_LINEAGE_INVALID"
    CAP_MAC_INVALID = "CAP_MAC_INVALID"
    CAP_CLAIMS_HASH_MISMATCH = "CAP_CLAIMS_HASH_MISMATCH"


@dataclass(frozen=True)
class CapabilityToken:
    cap_id: str
    claims: dict[str, Any]
    cap_mac: str


@dataclass
class IssuerRecord:
    canonical_claims_hash: str
    cap_epoch: int
    exp: int
    remaining_uses: int
    revoked: bool = False
    issued_at: int = 0
    used_at: int | None = None


@dataclass
class StepUpChallenge:
    challenge_nonce: str
    session_id: str
    conversation_id: str
    bind_seq: int
    cap_epoch: int
    tool_call_digest: str
    display_string: str
    expires_at: int


@dataclass(frozen=True)
class ToolCall:
    session_id: str
    account_id: str
    channel_id: str
    conversation_id: str
    context_type: str
    subject: str
    seq: int
    direction: str
    tool_id: str
    args: dict[str, Any]
    target: str


@dataclass(frozen=True)
class CapabilityDecision:
    allowed: bool
    error: CapabilityError | None = None
    subcode: CapabilitySubcode | None = None


class CapabilityIssuer:
    """Issuer table + token minting + dispatch enforcement."""

    def __init__(
        self,
        *,
        cap_keys_by_epoch: dict[int, bytes],
        transcript_window: int = 32,
        max_ttl_sec: int = 120,
        now_ms_fn: Any = None,
    ):
        self.cap_keys_by_epoch = dict(cap_keys_by_epoch)
        self.transcript_window = transcript_window
        self.max_ttl_sec = max_ttl_sec
        self._now_ms_fn = now_ms_fn or (lambda: int(time.time() * 1000))

        self.issuer_table: dict[str, IssuerRecord] = {}
        self._challenges: dict[str, StepUpChallenge] = {}

    def now_ms(self) -> int:
        return int(self._now_ms_fn())

    @staticmethod
    def _cap_id() -> str:
        return b64url_encode(os.urandom(16))

    @staticmethod
    def canonical_claims_hash(claims: dict[str, Any]) -> str:
        c = canonicalize_json(claims).encode("utf-8")
        return hashlib.sha256(c).hexdigest()

    def _cap_mac(self, claims: dict[str, Any], epoch: int, key_map: dict[int, bytes] | None = None) -> str:
        keys = key_map or self.cap_keys_by_epoch
        key = keys.get(epoch)
        if not key:
            raise ValueError(f"No capability key for epoch {epoch}")
        payload = canonicalize_json(claims).encode("utf-8")
        return b64url_encode(hmac_sha256(key, payload))

    def _verify_cap_mac(self, token: CapabilityToken, epoch: int, key_map: dict[int, bytes] | None = None) -> bool:
        keys = key_map or self.cap_keys_by_epoch
        key = keys.get(epoch)
        if not key:
            return False
        payload = canonicalize_json(token.claims).encode("utf-8")
        expected = hmac_sha256(key, payload)
        try:
            got = b64url_decode(token.cap_mac)
        except Exception:
            return False
        import hmac

        return hmac.compare_digest(expected, got)

    def mint_capability(
        self,
        *,
        session: CraftSessionState,
        subject: str,
        allowed_tools: list[str],
        arg_constraints: dict[str, Any],
        target_constraints: dict[str, Any],
        bind_seq: int,
        state_commit_at_issue: str,
        purpose: str,
        chainable: bool = False,
        max_uses: int = 1,
        ttl_sec: int = 60,
        parent_cap_id: str | None = None,
        tool_call_digest: str | None = None,
    ) -> CapabilityToken:
        if not allowed_tools:
            raise ValueError("allowed_tools cannot be empty")
        if ttl_sec <= 0:
            raise ValueError("ttl_sec must be positive")

        ttl = min(ttl_sec, self.max_ttl_sec)
        now = self.now_ms()
        epoch = session.current_epoch

        if parent_cap_id:
            parent = self.issuer_table.get(parent_cap_id)
            if not parent or parent.revoked or parent.used_at is None:
                raise ValueError("parent capability invalid or unused")

        cap_id = self._cap_id()

        # Prefer epoch keys tracked on session (supports grace window after rekey).
        session_key_map = session.cap_keys_by_epoch or self.cap_keys_by_epoch
        if epoch not in session_key_map:
            raise ValueError(f"No capability key available for epoch {epoch}")
        # keep issuer map in sync for current epoch lookup
        self.cap_keys_by_epoch.setdefault(epoch, session_key_map[epoch])

        claims: dict[str, Any] = {
            "cap_id": cap_id,
            "session_id": session.session_id,
            "account_id": session.account_id,
            "channel_id": session.channel_id,
            "conversation_id": session.conversation_id,
            "context_type": session.context_type,
            "cap_epoch": epoch,
            "subject": subject,
            "allowed_tools": sorted(set(allowed_tools)),
            "arg_constraints": arg_constraints,
            "target_constraints": target_constraints,
            "issued_at": now,
            "exp": now + ttl * 1000,
            "max_uses": max_uses,
            "chainable": bool(chainable),
            "bind_seq": int(bind_seq),
            "state_commit_at_issue": state_commit_at_issue,
            "parent_cap_id": parent_cap_id,
            "purpose": purpose,
            "tool_call_digest": tool_call_digest,
        }
        mac = self._cap_mac(claims, epoch, key_map=session_key_map)
        token = CapabilityToken(cap_id=cap_id, claims=claims, cap_mac=mac)

        self.issuer_table[cap_id] = IssuerRecord(
            canonical_claims_hash=self.canonical_claims_hash(claims),
            cap_epoch=epoch,
            exp=claims["exp"],
            remaining_uses=max_uses,
            revoked=False,
            issued_at=now,
            used_at=None,
        )
        return token

    def revoke(self, cap_id: str) -> None:
        rec = self.issuer_table.get(cap_id)
        if rec:
            rec.revoked = True

    def issue_step_up_challenge(
        self,
        *,
        session: CraftSessionState,
        bind_seq: int,
        tool_call_digest: str,
        display_string: str,
        ttl_sec: int = 60,
    ) -> StepUpChallenge:
        now = self.now_ms()
        nonce = b64url_encode(os.urandom(16))
        ch = StepUpChallenge(
            challenge_nonce=nonce,
            session_id=session.session_id,
            conversation_id=session.conversation_id,
            bind_seq=bind_seq,
            cap_epoch=session.current_epoch,
            tool_call_digest=tool_call_digest,
            display_string=display_string,
            expires_at=now + min(ttl_sec, self.max_ttl_sec) * 1000,
        )
        self._challenges[nonce] = ch
        return ch

    def verify_step_up_proof(
        self,
        *,
        challenge_nonce: str,
        session: CraftSessionState,
        bind_seq: int,
        tool_call_digest: str,
    ) -> bool:
        now = self.now_ms()
        ch = self._challenges.get(challenge_nonce)
        if not ch:
            return False
        if now > ch.expires_at:
            self._challenges.pop(challenge_nonce, None)
            return False

        ok = (
            ch.session_id == session.session_id
            and ch.conversation_id == session.conversation_id
            and ch.bind_seq == bind_seq
            and ch.cap_epoch == session.current_epoch
            and ch.tool_call_digest == tool_call_digest
        )
        # single-use nonce
        self._challenges.pop(challenge_nonce, None)
        return ok

    @staticmethod
    def tool_call_digest(tool_call: ToolCall) -> str:
        body = canonicalize_json(
            {
                "tool_id": tool_call.tool_id,
                "args": tool_call.args,
                "target": tool_call.target,
            }
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def _transcript_consistent(self, state_commit: str, tool_call: ToolCall, session: CraftSessionState) -> bool:
        direction = tool_call.direction
        commits = []
        if direction in session.last_state_commit:
            commits.append(b64url_encode(session.last_state_commit[direction]))
        # Optional richer history if present
        recent = getattr(session, "recent_state_commits", {}).get(direction, [])
        commits.extend(recent[-self.transcript_window :])
        # dedupe while preserving order
        seen = set()
        compact = []
        for c in commits:
            if c not in seen:
                seen.add(c)
                compact.append(c)
        return state_commit in compact

    @staticmethod
    def _normalize_hostname(host: str) -> str:
        # IDNA ToASCII / A-label
        h = host.strip().rstrip(".").lower()
        try:
            return h.encode("idna").decode("ascii")
        except Exception:
            return h

    def _target_satisfies(self, target: str, constraints: dict[str, Any]) -> bool:
        ctype = constraints.get("type")
        if ctype == "exact":
            return target == constraints.get("value")

        if ctype == "network":
            parts = urlsplit(target)
            if parts.scheme not in constraints.get("allowed_schemes", ["https"]):
                return False
            host = self._normalize_hostname(parts.hostname or "")
            allowed_hosts = [self._normalize_hostname(h) for h in constraints.get("allowed_hosts", [])]
            if allowed_hosts and host not in allowed_hosts:
                return False
            if parts.port is not None:
                allowed_ports = constraints.get("allowed_ports", [])
                if allowed_ports and parts.port not in allowed_ports:
                    return False

            if constraints.get("block_private", False):
                try:
                    infos = socket.getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM)
                    for info in infos:
                        ip = info[4][0]
                        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
                            return False
                        if ip.startswith("169.254."):
                            return False
                except Exception:
                    return False
            return True

        if ctype == "filesystem":
            sandbox = constraints.get("sandbox_root")
            if not sandbox:
                return False
            rp = Path(target).resolve()
            root = Path(sandbox).resolve()
            try:
                rp.relative_to(root)
            except Exception:
                return False
            return True

        return False

    @staticmethod
    def _args_satisfy(args: dict[str, Any], constraints: dict[str, Any]) -> bool:
        # schema_digest enforcement is performed by caller against trusted schema registry.
        exact = constraints.get("exact")
        if isinstance(exact, dict):
            for k, v in exact.items():
                if args.get(k) != v:
                    return False

        enums = constraints.get("enum", {})
        for k, allowed in enums.items():
            if k in args and args[k] not in allowed:
                return False

        ranges = constraints.get("ranges", {})
        for k, bounds in ranges.items():
            if k not in args:
                continue
            try:
                val = float(args[k])
            except Exception:
                return False
            if "min" in bounds and val < float(bounds["min"]):
                return False
            if "max" in bounds and val > float(bounds["max"]):
                return False

        patterns = constraints.get("regex", {})
        for k, pattern in patterns.items():
            if k in args and not re.match(pattern, str(args[k])):
                return False
        return True

    def enforce_at_tool_dispatch(
        self,
        *,
        token: CapabilityToken | None,
        tool_call: ToolCall,
        session: CraftSessionState,
        schema_registry: dict[str, dict[str, Any]] | None = None,
    ) -> CapabilityDecision:
        if token is None:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_REQUIRED, None)

        rec = self.issuer_table.get(token.cap_id)
        if not rec or rec.revoked:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_REVOKED)

        claims = token.claims
        cap_epoch = int(claims.get("cap_epoch", -1))

        # Epoch key lookup prefers session map (current + grace), then issuer fallback.
        epoch_keys = session.cap_keys_by_epoch or self.cap_keys_by_epoch
        allowed_epochs = session.current_or_grace_epochs or set(epoch_keys.keys())

        now = self.now_ms()
        # Time-bound grace: old epochs must be within grace deadline.
        if cap_epoch != session.current_epoch:
            grace_until = session.cap_epoch_grace_until_ms.get(cap_epoch)
            if grace_until is None or now > int(grace_until):
                return CapabilityDecision(
                    False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_EPOCH_MISMATCH
                )

        if not self._verify_cap_mac(token, cap_epoch, key_map=epoch_keys):
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_MAC_INVALID)

        if self.canonical_claims_hash(claims) != rec.canonical_claims_hash:
            return CapabilityDecision(
                False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_CLAIMS_HASH_MISMATCH
            )

        if now >= rec.exp:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_EXPIRED)

        if rec.remaining_uses <= 0:
            return CapabilityDecision(
                False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_USE_EXHAUSTED
            )

        if cap_epoch not in epoch_keys:
            return CapabilityDecision(
                False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_EPOCH_MISMATCH
            )

        if cap_epoch not in allowed_epochs:
            return CapabilityDecision(
                False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_EPOCH_MISMATCH
            )

        if rec.cap_epoch != cap_epoch:
            return CapabilityDecision(
                False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_EPOCH_MISMATCH
            )

        if claims.get("session_id") != tool_call.session_id:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)
        if claims.get("account_id") != tool_call.account_id:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)
        if claims.get("channel_id") != tool_call.channel_id:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)
        if claims.get("conversation_id") != tool_call.conversation_id:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)
        if claims.get("context_type") != tool_call.context_type:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)
        if claims.get("subject") != tool_call.subject:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        if int(tool_call.seq) < int(claims.get("bind_seq", 0)):
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        if not self._transcript_consistent(str(claims.get("state_commit_at_issue", "")), tool_call, session):
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        allowed_tools = set(claims.get("allowed_tools", []))
        if tool_call.tool_id not in allowed_tools:
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        arg_constraints = claims.get("arg_constraints", {})
        schema_digest = arg_constraints.get("schema_digest")
        if schema_digest:
            if not schema_registry or schema_digest not in schema_registry:
                return CapabilityDecision(
                    False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH
                )

        if not self._args_satisfy(tool_call.args, arg_constraints):
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        if not self._target_satisfies(tool_call.target, claims.get("target_constraints", {})):
            return CapabilityDecision(False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH)

        parent_cap_id = claims.get("parent_cap_id")
        if parent_cap_id:
            parent = self.issuer_table.get(parent_cap_id)
            if not parent or parent.used_at is None:
                return CapabilityDecision(
                    False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_LINEAGE_INVALID
                )
            if parent.used_at > rec.issued_at:
                return CapabilityDecision(
                    False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_LINEAGE_INVALID
                )

        digest_claim = claims.get("tool_call_digest")
        if digest_claim:
            if digest_claim != self.tool_call_digest(tool_call):
                return CapabilityDecision(
                    False, CapabilityError.ERR_CAP_INVALID, CapabilitySubcode.CAP_SCOPE_MISMATCH
                )

        rec.remaining_uses -= 1
        if rec.remaining_uses == 0:
            rec.used_at = now
        return CapabilityDecision(True, None, None)
