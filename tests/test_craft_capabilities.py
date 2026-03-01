from __future__ import annotations

import copy

import pytest

from unwind.craft.capabilities import (
    CapabilityError,
    CapabilityIssuer,
    CapabilitySubcode,
    ToolCall,
)
from unwind.craft.crypto import b64url_encode, derive_session_keys, state_commit_0
from unwind.craft.verifier import CraftSessionState


def _ctx_bytes() -> bytes:
    return b"CRAFT/v4.2|sess_abc|acct_main|chan_main|conv_main|dev_fpr"


def _make_session_and_issuer() -> tuple[CraftSessionState, CapabilityIssuer]:
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

    issuer = CapabilityIssuer(cap_keys_by_epoch={0: keys.k_cap_srv}, now_ms_fn=lambda: 1_700_000_000_000)
    return sess, issuer


def _tool_call() -> ToolCall:
    return ToolCall(
        session_id="sess_abc",
        account_id="acct_main",
        channel_id="chan_main",
        conversation_id="conv_main",
        context_type="dm",
        subject="user:alice",
        seq=12,
        direction="c2p",
        tool_id="fs_write",
        args={"path": "/tmp/safe.txt", "content": "ok"},
        target="/tmp/safe.txt",
    )


def _mint_basic_token(session: CraftSessionState, issuer: CapabilityIssuer):
    state_commit = b64url_encode(session.last_state_commit["c2p"])
    return issuer.mint_capability(
        session=session,
        subject="user:alice",
        allowed_tools=["fs_write"],
        arg_constraints={"exact": {"path": "/tmp/safe.txt"}},
        target_constraints={"type": "exact", "value": "/tmp/safe.txt"},
        bind_seq=10,
        state_commit_at_issue=state_commit,
        purpose="write approved file",
        max_uses=1,
    )


def test_dispatch_enforcement_happy_path_allows_once() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    decision = issuer.enforce_at_tool_dispatch(token=token, tool_call=_tool_call(), session=session)
    assert decision.allowed is True


def test_dispatch_requires_capability_token() -> None:
    session, issuer = _make_session_and_issuer()
    decision = issuer.enforce_at_tool_dispatch(token=None, tool_call=_tool_call(), session=session)
    assert decision.allowed is False
    assert decision.error == CapabilityError.ERR_CAP_REQUIRED


def test_tampered_claims_fail_mac_validation() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    bad_claims = copy.deepcopy(token.claims)
    bad_claims["subject"] = "user:bob"
    tampered = type(token)(cap_id=token.cap_id, claims=bad_claims, cap_mac=token.cap_mac)

    decision = issuer.enforce_at_tool_dispatch(token=tampered, tool_call=_tool_call(), session=session)
    assert decision.allowed is False
    assert decision.subcode == CapabilitySubcode.CAP_MAC_INVALID


def test_context_scope_mismatch_rejected() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    tc = _tool_call()
    tc_bad = ToolCall(**{**tc.__dict__, "subject": "user:bob"})
    decision = issuer.enforce_at_tool_dispatch(token=token, tool_call=tc_bad, session=session)

    assert decision.allowed is False
    assert decision.subcode == CapabilitySubcode.CAP_SCOPE_MISMATCH


def test_state_commit_mismatch_rejected() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)
    token_bad = type(token)(
        cap_id=token.cap_id,
        claims={**token.claims, "state_commit_at_issue": b64url_encode(b"x" * 32)},
        cap_mac=token.cap_mac,
    )

    decision = issuer.enforce_at_tool_dispatch(token=token_bad, tool_call=_tool_call(), session=session)
    assert decision.allowed is False
    assert decision.subcode == CapabilitySubcode.CAP_MAC_INVALID


def test_use_exhaustion_blocks_second_call() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    first = issuer.enforce_at_tool_dispatch(token=token, tool_call=_tool_call(), session=session)
    second = issuer.enforce_at_tool_dispatch(token=token, tool_call=_tool_call(), session=session)

    assert first.allowed is True
    assert second.allowed is False
    assert second.subcode == CapabilitySubcode.CAP_USE_EXHAUSTED


def test_parent_lineage_requires_parent_used_before_child_mint() -> None:
    session, issuer = _make_session_and_issuer()
    parent = _mint_basic_token(session, issuer)

    with pytest.raises(ValueError):
        issuer.mint_capability(
            session=session,
            subject="user:alice",
            allowed_tools=["fs_write"],
            arg_constraints={"exact": {"path": "/tmp/safe.txt"}},
            target_constraints={"type": "exact", "value": "/tmp/safe.txt"},
            bind_seq=12,
            state_commit_at_issue=b64url_encode(session.last_state_commit["c2p"]),
            purpose="child before parent use",
            parent_cap_id=parent.cap_id,
        )


def test_step_up_challenge_single_use_and_binding() -> None:
    session, issuer = _make_session_and_issuer()
    digest = "abc123"
    ch = issuer.issue_step_up_challenge(
        session=session,
        bind_seq=10,
        tool_call_digest=digest,
        display_string="Approve fs_write /tmp/safe.txt",
    )

    ok = issuer.verify_step_up_proof(
        challenge_nonce=ch.challenge_nonce,
        session=session,
        bind_seq=10,
        tool_call_digest=digest,
    )
    replay = issuer.verify_step_up_proof(
        challenge_nonce=ch.challenge_nonce,
        session=session,
        bind_seq=10,
        tool_call_digest=digest,
    )

    assert ok is True
    assert replay is False


def test_tool_call_digest_bound_capability() -> None:
    session, issuer = _make_session_and_issuer()
    tc = _tool_call()
    digest = issuer.tool_call_digest(tc)

    token = issuer.mint_capability(
        session=session,
        subject="user:alice",
        allowed_tools=["fs_write"],
        arg_constraints={"exact": {"path": "/tmp/safe.txt"}},
        target_constraints={"type": "exact", "value": "/tmp/safe.txt"},
        bind_seq=10,
        state_commit_at_issue=b64url_encode(session.last_state_commit["c2p"]),
        purpose="digest bound",
        tool_call_digest=digest,
    )

    tc_bad = ToolCall(**{**tc.__dict__, "args": {"path": "/tmp/safe.txt", "content": "tampered"}})
    out = issuer.enforce_at_tool_dispatch(token=token, tool_call=tc_bad, session=session)
    assert out.allowed is False
    assert out.subcode == CapabilitySubcode.CAP_SCOPE_MISMATCH


def test_previous_epoch_cap_allowed_within_grace_window() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    # Simulate rekey to epoch 1 while retaining epoch 0 grace verification key.
    keys_epoch1 = derive_session_keys(
        ikm=b"i" * 32,
        salt0=b"s" * 32,
        ctx=_ctx_bytes(),
        epoch=1,
        server_secret=b"k" * 32,
    )
    session.current_epoch = 1
    session.cap_keys_by_epoch = {0: issuer.cap_keys_by_epoch[0], 1: keys_epoch1.k_cap_srv}
    session.current_or_grace_epochs = {0, 1}
    session.cap_epoch_grace_until_ms = {0: issuer.now_ms() + 60_000}
    issuer.cap_keys_by_epoch[1] = keys_epoch1.k_cap_srv

    out = issuer.enforce_at_tool_dispatch(token=token, tool_call=_tool_call(), session=session)
    assert out.allowed is True


def test_previous_epoch_cap_rejected_outside_grace_window() -> None:
    session, issuer = _make_session_and_issuer()
    token = _mint_basic_token(session, issuer)

    keys_epoch1 = derive_session_keys(
        ikm=b"i" * 32,
        salt0=b"s" * 32,
        ctx=_ctx_bytes(),
        epoch=1,
        server_secret=b"k" * 32,
    )
    session.current_epoch = 1
    session.cap_keys_by_epoch = {0: issuer.cap_keys_by_epoch[0], 1: keys_epoch1.k_cap_srv}
    session.current_or_grace_epochs = {1}
    session.cap_epoch_grace_until_ms = {0: issuer.now_ms() - 1}
    issuer.cap_keys_by_epoch[1] = keys_epoch1.k_cap_srv

    out = issuer.enforce_at_tool_dispatch(token=token, tool_call=_tool_call(), session=session)
    assert out.allowed is False
    assert out.subcode == CapabilitySubcode.CAP_EPOCH_MISMATCH
