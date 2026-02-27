"""CRAFT state persistence (atomic JSON snapshots).

Milestone scope: crash-safe persistence for replay/state continuity and tombstones.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .crypto import b64url_decode, b64url_encode
from .verifier import CraftSessionState, ReplayWindow


class CraftStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read_obj(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"sessions": {}, "tombstones": {}}
        with self.path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _write_obj(self, obj: dict[str, Any]) -> None:
        fd, tmp_path = tempfile.mkstemp(prefix="craft_state_", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    @staticmethod
    def _serialize_session(session: CraftSessionState) -> dict[str, Any]:
        return {
            "session_id": session.session_id,
            "account_id": session.account_id,
            "channel_id": session.channel_id,
            "conversation_id": session.conversation_id,
            "context_type": session.context_type,
            "current_epoch": session.current_epoch,
            "highest_seq": session.highest_seq,
            "last_state_commit": {
                d: b64url_encode(v) for d, v in session.last_state_commit.items()
            },
            "recent_state_commits": session.recent_state_commits,
            "replay_seen": {d: sorted(list(w.seen)) for d, w in session.replay_bitmap.items()},
            "started_at_ms": session.started_at_ms,
            "last_rekey_at_ms": session.last_rekey_at_ms,
            "tombstoned_until_ms": session.tombstoned_until_ms,
            "ctx": b64url_encode(session.ctx),
            "prk": b64url_encode(session.prk or b""),
            "prk_cap_root": b64url_encode(session.prk_cap_root or b""),
            "cap_keys_by_epoch": {str(k): b64url_encode(v) for k, v in session.cap_keys_by_epoch.items()},
            "current_or_grace_epochs": sorted(list(session.current_or_grace_epochs)),
            "queue_max": session.queue_max,
            "queue_timeout_ms": session.queue_timeout_ms,
        }

    @staticmethod
    def _restore_session(raw: dict[str, Any], session_template: CraftSessionState) -> CraftSessionState:
        """Restore mutable continuity state into an existing session object.

        Transport keys must already be present in the session template.
        """
        s = session_template
        s.current_epoch = int(raw["current_epoch"])
        s.highest_seq = {k: int(v) for k, v in raw.get("highest_seq", {}).items()}
        s.last_state_commit = {
            d: b64url_decode(v) for d, v in raw.get("last_state_commit", {}).items()
        }
        s.recent_state_commits = {
            d: list(v) for d, v in raw.get("recent_state_commits", {}).items()
        }
        seen = raw.get("replay_seen", {})
        s.replay_bitmap = {
            d: ReplayWindow(width=1024, seen=set(int(x) for x in vals))
            for d, vals in seen.items()
        }
        s.started_at_ms = int(raw.get("started_at_ms", s.started_at_ms))
        s.last_rekey_at_ms = int(raw.get("last_rekey_at_ms", s.last_rekey_at_ms))
        s.tombstoned_until_ms = raw.get("tombstoned_until_ms")
        s.ctx = b64url_decode(raw.get("ctx", "")) if raw.get("ctx") else s.ctx
        prk = raw.get("prk")
        if prk:
            s.prk = b64url_decode(prk)
        pcr = raw.get("prk_cap_root")
        if pcr:
            s.prk_cap_root = b64url_decode(pcr)
        s.cap_keys_by_epoch = {
            int(k): b64url_decode(v) for k, v in raw.get("cap_keys_by_epoch", {}).items()
        }
        s.current_or_grace_epochs = set(int(x) for x in raw.get("current_or_grace_epochs", []))
        s.queue_max = int(raw.get("queue_max", s.queue_max))
        s.queue_timeout_ms = int(raw.get("queue_timeout_ms", s.queue_timeout_ms))
        return s

    def save_session(self, session: CraftSessionState) -> None:
        obj = self._read_obj()
        obj.setdefault("sessions", {})[session.session_id] = self._serialize_session(session)
        self._write_obj(obj)

    def restore_session_into(self, session: CraftSessionState) -> bool:
        obj = self._read_obj()
        raw = obj.get("sessions", {}).get(session.session_id)
        if not raw:
            return False
        self._restore_session(raw, session)
        return True

    def save_tombstone(self, session_id: str, expires_at_ms: int) -> None:
        obj = self._read_obj()
        obj.setdefault("tombstones", {})[session_id] = int(expires_at_ms)
        self._write_obj(obj)

    def is_tombstoned(self, session_id: str, now_ms: int) -> bool:
        obj = self._read_obj()
        exp = obj.get("tombstones", {}).get(session_id)
        return bool(exp and int(exp) > now_ms)

    def purge_expired_tombstones(self, now_ms: int) -> int:
        obj = self._read_obj()
        tomb = obj.get("tombstones", {})
        before = len(tomb)
        obj["tombstones"] = {k: v for k, v in tomb.items() if int(v) > now_ms}
        removed = before - len(obj["tombstones"])
        if removed:
            self._write_obj(obj)
        return removed
