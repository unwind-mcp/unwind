from __future__ import annotations

from unwind.craft.canonical import canonicalize_json
from unwind.craft.crypto import (
    b64url_encode,
    derive_session_keys,
    hmac_sha256,
    state_commit_0,
)
from unwind.craft.lifecycle import CraftLifecycleManager, ResyncError
from unwind.craft.verifier import CraftSessionState


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
    s.record_state_commit("c2p", s.last_state_commit["c2p"])
    s.record_state_commit("p2c", s.last_state_commit["p2c"])
    return s


def _signed_envelope(session: CraftSessionState, seq: int) -> tuple[dict, bytes]:
    env = {
        "v": 4,
        "epoch": session.current_epoch,
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

    from unwind.craft.canonical import mac_input_bytes

    raw_mac = hmac_sha256(session.keys_c2p.k_msg, mac_input_bytes(env))
    env["mac"] = b64url_encode(raw_mac)
    prev = session.last_state_commit["c2p"]
    commit = hmac_sha256(session.keys_c2p.k_state, prev + raw_mac)
    env["state_commit"] = b64url_encode(commit)
    return env, commit


def test_rekey_prepare_and_ack_resets_epoch_and_seq() -> None:
    session = _make_session()
    session.highest_seq["c2p"] = 7
    session.highest_seq["p2c"] = 3

    lm = CraftLifecycleManager(now_ms_fn=lambda: 1_700_000_001_000)
    prep = lm.initiate_rekey(session)
    assert prep.epoch_new == 1
    assert prep.boundary_seq_c2p == 8
    assert prep.boundary_seq_p2c == 4

    old_cap_key = session.cap_keys_by_epoch[0]
    lm.apply_rekey_ack(session, prep)

    assert session.current_epoch == 1
    assert session.highest_seq["c2p"] == 0
    assert session.highest_seq["p2c"] == 0
    assert 1 in session.cap_keys_by_epoch
    assert session.cap_keys_by_epoch[1] != old_cap_key


def test_resync_enforces_bounds() -> None:
    session = _make_session()
    lm = CraftLifecycleManager(max_missing_envelopes=2, now_ms_fn=lambda: 1_700_000_001_000)

    ch = lm.issue_resync_challenge(session, "c2p")

    proof = {
        "session_id": session.session_id,
        "direction": "c2p",
        "epoch": session.current_epoch,
        "challenge_nonce": ch.challenge_nonce,
        "client_highest_seq": 0,
        "client_state_commit": b64url_encode(session.last_state_commit["c2p"]),
        "missing_envelopes": [{"seq": "1"}, {"seq": "2"}, {"seq": "3"}],
    }
    proof["mac"] = b64url_encode(
        hmac_sha256(
            session.keys_c2p.k_resync,
            canonicalize_json({k: v for k, v in proof.items() if k != "mac"}).encode("utf-8"),
        )
    )

    out = lm.handle_resync(session, proof)
    assert out.ok is False
    assert out.error == ResyncError.ERR_RESYNC_BOUNDS


def test_resync_walks_state_then_rekeys() -> None:
    session = _make_session()
    lm = CraftLifecycleManager(now_ms_fn=lambda: 1_700_000_002_000)

    env1, commit1 = _signed_envelope(session, 1)

    ch = lm.issue_resync_challenge(session, "c2p")
    proof = {
        "session_id": session.session_id,
        "direction": "c2p",
        "epoch": session.current_epoch,
        "challenge_nonce": ch.challenge_nonce,
        "client_highest_seq": 1,
        "client_state_commit": b64url_encode(commit1),
        "missing_envelopes": [env1],
    }
    proof["mac"] = b64url_encode(
        hmac_sha256(
            session.keys_c2p.k_resync,
            canonicalize_json({k: v for k, v in proof.items() if k != "mac"}).encode("utf-8"),
        )
    )

    out = lm.handle_resync(session, proof)
    assert out.ok is True
    assert out.new_epoch == 1
    assert session.current_epoch == 1


def test_resync_rejects_unproven_seq_jump() -> None:
    session = _make_session()
    lm = CraftLifecycleManager(now_ms_fn=lambda: 1_700_000_003_000)

    env1, commit1 = _signed_envelope(session, 1)

    ch = lm.issue_resync_challenge(session, "c2p")
    proof = {
        "session_id": session.session_id,
        "direction": "c2p",
        "epoch": session.current_epoch,
        "challenge_nonce": ch.challenge_nonce,
        # Claims seq jump to 5 but only provides proof for seq 1
        "client_highest_seq": 5,
        "client_state_commit": b64url_encode(commit1),
        "missing_envelopes": [env1],
    }
    proof["mac"] = b64url_encode(
        hmac_sha256(
            session.keys_c2p.k_resync,
            canonicalize_json({k: v for k, v in proof.items() if k != "mac"}).encode("utf-8"),
        )
    )

    out = lm.handle_resync(session, proof)
    assert out.ok is False
    assert out.error == ResyncError.ERR_RESYNC_STATE_DIVERGED


def test_rekey_boundary_mismatch_rejected() -> None:
    session = _make_session()
    session.highest_seq["c2p"] = 2
    session.highest_seq["p2c"] = 4
    lm = CraftLifecycleManager(now_ms_fn=lambda: 1_700_000_004_000)

    prep = lm.initiate_rekey(session)
    bad = type(prep)(
        session_id=prep.session_id,
        epoch_new=prep.epoch_new,
        boundary_seq_c2p=prep.boundary_seq_c2p + 1,
        boundary_seq_p2c=prep.boundary_seq_p2c,
        action=prep.action,
    )

    import pytest

    with pytest.raises(ValueError):
        lm.apply_rekey_ack(session, bad)


def test_session_ttl_and_teardown_tombstone() -> None:
    now = 1_700_000_100_000
    session = _make_session()
    session.started_at_ms = now - (24 * 60 * 60 * 1000 + 1)
    lm = CraftLifecycleManager(now_ms_fn=lambda: now)

    assert lm.is_session_expired(session) is True

    lm.teardown_session(session, max_network_delay_ms=2_000)
    assert session.tombstoned_until_ms is not None
    assert session.tombstoned_until_ms - now >= 600_000
