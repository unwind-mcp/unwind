from __future__ import annotations

from pathlib import Path

from unwind.craft.crypto import b64url_encode, derive_session_keys, hmac_sha256, state_commit_0
from unwind.craft.persistence import CraftStateStore
from unwind.craft.verifier import CraftSessionState, CraftVerifier
from unwind.craft.canonical import mac_input_bytes


def _ctx_bytes() -> bytes:
    return b"CRAFT/v4.2|sess_abc|acct_main|chan_main|conv_main|dev_fpr"


def _make_session() -> CraftSessionState:
    ctx = _ctx_bytes()
    keys = derive_session_keys(
        ikm=b"i" * 32,
        salt0=b"s" * 32,
        ctx=ctx,
        epoch=0,
        server_secret=b"k" * 32,
    )
    s = CraftSessionState.from_session_keys(
        session_id="sess_abc",
        account_id="acct_main",
        channel_id="chan_main",
        conversation_id="conv_main",
        context_type="dm",
        epoch=0,
        keys=keys,
        ctx=ctx,
    )
    s.last_state_commit["c2p"] = state_commit_0(keys.c2p.k_state, ctx)
    s.last_state_commit["p2c"] = state_commit_0(keys.p2c.k_state, ctx)
    return s


def _signed_env(session: CraftSessionState, seq: int, prior_commit: bytes | None = None) -> tuple[dict, bytes]:
    env = {
        "v": 4,
        "epoch": 0,
        "session_id": session.session_id,
        "account_id": session.account_id,
        "channel_id": session.channel_id,
        "conversation_id": session.conversation_id,
        "context_type": session.context_type,
        "seq": str(seq),
        "ts_ms": 1739999999123,
        "state_commit": "",
        "msg_type": "user_instruction",
        "direction": "c2p",
        "payload": {"text": f"msg-{seq}", "meta": {}},
        "mac": "",
    }
    raw_mac = hmac_sha256(session.keys_c2p.k_msg, mac_input_bytes(env))
    env["mac"] = b64url_encode(raw_mac)
    prev = prior_commit if prior_commit is not None else session.last_state_commit["c2p"]
    commit = hmac_sha256(session.keys_c2p.k_state, prev + raw_mac)
    env["state_commit"] = b64url_encode(commit)
    return env, commit


def test_verify_or_hold_drains_contiguous_queue() -> None:
    s = _make_session()
    v = CraftVerifier()

    env1, commit1 = _signed_env(s, 1)
    env2, _commit2 = _signed_env(s, 2, prior_commit=commit1)

    held = v.verify_or_hold(env2, s, now_ms=1_700_000_000_000)
    assert held.held is True

    res = v.verify_or_hold(env1, s, now_ms=1_700_000_000_100)

    assert res.accepted is True
    assert res.drained == 1
    assert s.highest_seq["c2p"] == 2


def test_state_store_roundtrip_and_tombstones(tmp_path: Path) -> None:
    s = _make_session()
    s.highest_seq["c2p"] = 9
    s.replay_bitmap["c2p"].mark(8)
    s.replay_bitmap["c2p"].mark(9)
    s.cap_epoch_grace_until_ms = {0: 1_700_000_010_000}

    store = CraftStateStore(tmp_path / "craft_state.json")
    store.save_session(s)

    # restore into a fresh template with same identifiers and keys
    s2 = _make_session()
    ok = store.restore_session_into(s2)
    assert ok is True
    assert s2.highest_seq["c2p"] == 9
    assert 9 in s2.replay_bitmap["c2p"].seen
    assert s2.cap_epoch_grace_until_ms.get(0) == 1_700_000_010_000

    now = 1_700_000_000_000
    store.save_tombstone("sess_dead", now + 10_000)
    assert store.is_tombstoned("sess_dead", now) is True
    removed = store.purge_expired_tombstones(now + 20_000)
    assert removed == 1
    assert store.is_tombstoned("sess_dead", now + 20_000) is False
