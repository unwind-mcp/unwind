from __future__ import annotations

import copy

from unwind.craft.canonical import mac_input_bytes
from unwind.craft.crypto import (
    b64url_encode,
    derive_session_keys,
    hmac_sha256,
    state_commit_0,
)
from unwind.craft.verifier import CraftSessionState, CraftVerifier, VerifyError


def _ctx_bytes() -> bytes:
    return b"CRAFT/v4.2|sess_abc|acct_main|chan_main|conv_main|dev_fpr"


def _make_session() -> tuple[CraftSessionState, bytes]:
    ctx = _ctx_bytes()
    keys = derive_session_keys(
        ikm=b"i" * 32,
        salt0=b"s" * 32,
        ctx=ctx,
        epoch=0,
        server_secret=b"k" * 32,
    )
    sess = CraftSessionState(
        session_id="sess_abc",
        account_id="acct_main",
        channel_id="chan_main",
        conversation_id="conv_main",
        context_type="dm",
        current_epoch=0,
        keys_c2p=keys.c2p,
        keys_p2c=keys.p2c,
    )
    sess.last_state_commit["c2p"] = state_commit_0(keys.c2p.k_state, ctx)
    sess.last_state_commit["p2c"] = state_commit_0(keys.p2c.k_state, ctx)
    return sess, ctx


def _signed_c2p_envelope(session: CraftSessionState, seq: int = 1, payload_text: str = "hello") -> dict:
    envelope = {
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
        "payload": {"text": payload_text, "meta": {}},
        "mac": "",
    }

    raw_mac = hmac_sha256(session.keys_c2p.k_msg, mac_input_bytes(envelope))
    envelope["mac"] = b64url_encode(raw_mac)

    prev = session.last_state_commit["c2p"]
    commit = hmac_sha256(session.keys_c2p.k_state, prev + raw_mac)
    envelope["state_commit"] = b64url_encode(commit)
    return envelope


def test_verify_and_admit_accepts_valid_envelope() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=1)
    out = verifier.verify_and_admit(env, session)

    assert out.accepted is True
    assert out.error is None
    assert session.highest_seq["c2p"] == 1


def test_mac_tamper_rejected_with_generic_pre_auth_error() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=1)
    env["payload"]["text"] = "tampered"

    out = verifier.verify_and_admit(env, session)
    assert out.accepted is False
    assert out.error == VerifyError.ERR_ENVELOPE_INVALID


def test_context_mismatch_returns_typed_error_post_auth() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=1)

    # Create a different session binding but same keys/state, so MAC still verifies.
    bad_session = copy.deepcopy(session)
    bad_session.channel_id = "chan_other"

    out = verifier.verify_and_admit(env, bad_session)
    assert out.accepted is False
    assert out.error == VerifyError.ERR_CONTEXT_MISMATCH


def test_sequence_gap_rejected() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=2)
    out = verifier.verify_and_admit(env, session)

    assert out.accepted is False
    assert out.error == VerifyError.ERR_REPLAY


def test_state_commit_not_in_mac_path_option_a_behavior() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=1)

    # Change state_commit only: MAC should still verify (Option A), then state check must fail.
    env["state_commit"] = b64url_encode(b"x" * 32)

    out = verifier.verify_and_admit(env, session)
    assert out.accepted is False
    assert out.error == VerifyError.ERR_STATE_DIVERGED


def test_epoch_stale_returns_generic_pre_auth_error() -> None:
    session, _ = _make_session()
    verifier = CraftVerifier()

    env = _signed_c2p_envelope(session, seq=1)
    env["epoch"] = 1

    out = verifier.verify_and_admit(env, session)
    assert out.accepted is False
    assert out.error == VerifyError.ERR_ENVELOPE_INVALID
