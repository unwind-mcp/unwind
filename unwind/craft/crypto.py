"""CRAFT cryptographic helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii"))


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand (RFC5869)."""
    if length <= 0:
        raise ValueError("length must be positive")
    hash_len = hashlib.sha256().digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("length too large for HKDF")

    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def u16_be(n: int) -> bytes:
    return int(n).to_bytes(2, "big", signed=False)


def u64_be(n: int) -> bytes:
    return int(n).to_bytes(8, "big", signed=False)


def build_hkdf_info(label: str, ctx: bytes, epoch: int) -> bytes:
    label_b = label.encode("utf-8")
    return label_b + b"\x00" + u16_be(len(ctx)) + ctx + u64_be(epoch)


@dataclass(frozen=True)
class DirectionalKeys:
    k_msg: bytes
    k_state: bytes
    k_resync: bytes


@dataclass(frozen=True)
class SessionKeys:
    c2p: DirectionalKeys
    p2c: DirectionalKeys
    k_cap_srv: bytes
    prk: bytes
    prk_cap_root: bytes


def derive_session_keys(
    *,
    ikm: bytes,
    salt0: bytes,
    ctx: bytes,
    epoch: int,
    server_secret: bytes,
) -> SessionKeys:
    """Derive session key bundle per CRAFT v4.2 format."""
    prk = hkdf_extract(salt=salt0, ikm=ikm)
    prk_cap_root = hkdf_extract(salt=b"CRAFT/v4.2/caproot", ikm=server_secret)

    c2p = DirectionalKeys(
        k_msg=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/msg/c2p", ctx, epoch), 32),
        k_state=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/state/c2p", ctx, epoch), 32),
        k_resync=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/resync/c2p", ctx, epoch), 32),
    )
    p2c = DirectionalKeys(
        k_msg=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/msg/p2c", ctx, epoch), 32),
        k_state=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/state/p2c", ctx, epoch), 32),
        k_resync=hkdf_expand(prk, build_hkdf_info("CRAFT/v4/resync/p2c", ctx, epoch), 32),
    )

    k_cap_srv = hkdf_expand(prk_cap_root, build_hkdf_info("CRAFT/v4/cap", ctx, epoch), 32)
    return SessionKeys(c2p=c2p, p2c=p2c, k_cap_srv=k_cap_srv, prk=prk, prk_cap_root=prk_cap_root)


def state_commit_0(k_state: bytes, ctx: bytes) -> bytes:
    msg = b"CRAFT/v4/state0\x00" + u16_be(len(ctx)) + ctx
    return hmac_sha256(k_state, msg)


def derive_rekey_prk(
    *,
    prk_current: bytes,
    state_commit_c2p_current: bytes,
    state_commit_p2c_current: bytes,
    epoch_new: int,
) -> bytes:
    """Derive next PRK from rekey salt formula in v4.2."""
    rekey_salt = hmac_sha256(
        prk_current,
        b"CRAFT/v4/rekey-salt\x00" + state_commit_c2p_current + state_commit_p2c_current,
    )
    return hkdf_extract(
        salt=rekey_salt,
        ikm=prk_current + b"CRAFT/v4/rekey\x00" + u64_be(epoch_new),
    )
