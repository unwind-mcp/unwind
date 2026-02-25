"""Tests for Ed25519 signature verification (R-SIG-001).

Covers:
- Key generation and key store CRUD
- Canonical JSON serialisation
- Sign + verify round-trip
- Invalid / tampered signatures
- Key not found, key revoked
- Malformed signature blocks
- Unsupported algorithms
- Key store I/O (save/load)
- SignatureVerifier caching
- Integration with SupplyChainVerifier
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from unwind.enforcement.signature_verify import (
    ED25519_PUBLIC_KEY_LENGTH,
    ED25519_SIGNATURE_LENGTH,
    KeyEntry,
    KeyStore,
    SignatureAlgorithm,
    SignatureResult,
    SignatureVerdict,
    SignatureVerifier,
    _key_store_hmac_path,
    canonical_provider_json,
    generate_ed25519_keypair,
    load_key_store,
    parse_key_store,
    save_key_store,
    sign_provider_entry,
    verify_provider_signature,
    _sign_ed25519,
    _verify_ed25519,
)


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_key, public_key = generate_ed25519_keypair()
    return private_key, public_key


@pytest.fixture
def key_store(keypair):
    """Key store with one test key."""
    _, public_key = keypair
    ks = KeyStore()
    ks.add_key("test-key-1", public_key, owner="Test Suite")
    return ks


@pytest.fixture
def sample_provider_data():
    """A sample provider dict (unsigned)."""
    return {
        "name": "MCP Filesystem Server",
        "version": "1.2.3",
        "digest": "sha256:abcdef1234567890",
        "tools": ["fs_read", "fs_write"],
        "origin": "https://github.com/mcp/fs",
        "trusted_at": "2026-02-22T12:00:00+00:00",
    }


@pytest.fixture
def signed_provider_data(keypair, sample_provider_data):
    """A sample provider dict with valid Ed25519 signature."""
    private_key, _ = keypair
    return sign_provider_entry(sample_provider_data, private_key, "test-key-1")


# ─────────────────────────────────────────────────────
# Key Generation
# ─────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_keypair_lengths(self, keypair):
        private_key, public_key = keypair
        assert len(private_key) == 32
        assert len(public_key) == ED25519_PUBLIC_KEY_LENGTH

    def test_keypair_unique(self):
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        assert kp1[0] != kp2[0]
        assert kp1[1] != kp2[1]


# ─────────────────────────────────────────────────────
# Canonical JSON
# ─────────────────────────────────────────────────────

class TestCanonicalJSON:
    def test_sorted_keys(self):
        data = {"z_field": 1, "a_field": 2}
        canonical = canonical_provider_json(data)
        parsed = json.loads(canonical)
        assert list(parsed.keys()) == ["a_field", "z_field"]

    def test_no_whitespace(self):
        data = {"name": "test", "version": "1.0"}
        canonical = canonical_provider_json(data)
        assert b" " not in canonical
        assert b"\n" not in canonical

    def test_signature_excluded(self):
        data = {
            "name": "test",
            "signature": {"alg": "Ed25519", "key_id": "k1", "sig": "abc"},
        }
        canonical = canonical_provider_json(data)
        parsed = json.loads(canonical)
        assert "signature" not in parsed

    def test_deterministic(self, sample_provider_data):
        c1 = canonical_provider_json(sample_provider_data)
        c2 = canonical_provider_json(sample_provider_data)
        assert c1 == c2

    def test_returns_bytes(self, sample_provider_data):
        result = canonical_provider_json(sample_provider_data)
        assert isinstance(result, bytes)


# ─────────────────────────────────────────────────────
# Low-level sign/verify
# ─────────────────────────────────────────────────────

class TestEd25519Primitives:
    def test_sign_verify_roundtrip(self, keypair):
        private_key, public_key = keypair
        message = b"test message"
        sig = _sign_ed25519(private_key, message)
        assert len(sig) == ED25519_SIGNATURE_LENGTH
        assert _verify_ed25519(public_key, sig, message) is True

    def test_wrong_message_fails(self, keypair):
        private_key, public_key = keypair
        sig = _sign_ed25519(private_key, b"original")
        assert _verify_ed25519(public_key, sig, b"tampered") is False

    def test_wrong_key_fails(self, keypair):
        private_key, _ = keypair
        _, other_public = generate_ed25519_keypair()
        sig = _sign_ed25519(private_key, b"message")
        assert _verify_ed25519(other_public, sig, b"message") is False

    def test_corrupted_signature_fails(self, keypair):
        private_key, public_key = keypair
        sig = _sign_ed25519(private_key, b"message")
        corrupted = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert _verify_ed25519(public_key, corrupted, b"message") is False


# ─────────────────────────────────────────────────────
# Key Store
# ─────────────────────────────────────────────────────

class TestKeyStore:
    def test_add_key(self, keypair):
        _, pub = keypair
        ks = KeyStore()
        entry = ks.add_key("k1", pub, owner="Test")
        assert entry.key_id == "k1"
        assert entry.public_key == pub
        assert entry.revoked is False
        assert entry.added_at is not None

    def test_add_key_wrong_length(self):
        ks = KeyStore()
        with pytest.raises(ValueError, match="32 bytes"):
            ks.add_key("k1", b"too-short")

    def test_get_key(self, key_store):
        entry = key_store.get_key("test-key-1")
        assert entry is not None
        assert entry.owner == "Test Suite"

    def test_get_missing_key(self, key_store):
        assert key_store.get_key("nonexistent") is None

    def test_revoke_key(self, key_store):
        assert key_store.revoke_key("test-key-1") is True
        assert key_store.is_revoked("test-key-1") is True

    def test_revoke_missing_key(self, key_store):
        assert key_store.revoke_key("nonexistent") is False

    def test_is_revoked_false_by_default(self, key_store):
        assert key_store.is_revoked("test-key-1") is False


# ─────────────────────────────────────────────────────
# Key Store I/O
# ─────────────────────────────────────────────────────

class TestKeyStoreIO:
    def test_save_load_roundtrip(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        loaded = load_key_store(path)
        assert "test-key-1" in loaded.keys
        assert loaded.keys["test-key-1"].public_key == key_store.keys["test-key-1"].public_key
        assert loaded.keys["test-key-1"].owner == "Test Suite"

    def test_load_missing_file(self, tmp_path):
        ks = load_key_store(tmp_path / "nonexistent.json")
        assert len(ks.keys) == 0

    def test_load_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json!!!")
        ks = load_key_store(path)
        assert len(ks.keys) == 0

    def test_load_skips_bad_keys(self, tmp_path):
        path = tmp_path / "keys.json"
        data = {
            "version": "1.0",
            "keys": {
                "good-key": {
                    "public_key": "aa" * 32,
                    "owner": "Good",
                },
                "bad-key": {
                    "public_key": "tooshort",
                    "owner": "Bad",
                },
                "wrong-length": {
                    "public_key": "bb" * 16,
                    "owner": "Wrong",
                },
            },
        }
        path.write_text(json.dumps(data))
        ks = load_key_store(path)
        assert "good-key" in ks.keys
        assert "bad-key" not in ks.keys
        assert "wrong-length" not in ks.keys

    def test_save_creates_directory(self, key_store, tmp_path):
        path = tmp_path / "deep" / "nested" / "keys.json"
        save_key_store(key_store, path)
        assert path.exists()

    def test_revoked_key_persists(self, key_store, tmp_path):
        key_store.revoke_key("test-key-1")
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        loaded = load_key_store(path)
        assert loaded.keys["test-key-1"].revoked is True


# ─────────────────────────────────────────────────────
# Provider Signature Verification
# ─────────────────────────────────────────────────────

class TestProviderSignatureVerification:
    def test_valid_signature(self, signed_provider_data, key_store):
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.VALID
        assert result.key_id == "test-key-1"

    def test_no_signature(self, sample_provider_data, key_store):
        result = verify_provider_signature(sample_provider_data, key_store)
        assert result.verdict == SignatureVerdict.NO_SIGNATURE

    def test_tampered_name(self, signed_provider_data, key_store):
        signed_provider_data["name"] = "TAMPERED"
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.INVALID

    def test_tampered_version(self, signed_provider_data, key_store):
        signed_provider_data["version"] = "9.9.9"
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.INVALID

    def test_tampered_tools(self, signed_provider_data, key_store):
        signed_provider_data["tools"].append("injected_tool")
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.INVALID

    def test_tampered_digest(self, signed_provider_data, key_store):
        signed_provider_data["digest"] = "sha256:tampered"
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.INVALID

    def test_key_not_found(self, signed_provider_data):
        empty_store = KeyStore()
        result = verify_provider_signature(signed_provider_data, empty_store)
        assert result.verdict == SignatureVerdict.KEY_NOT_FOUND

    def test_key_revoked(self, signed_provider_data, key_store):
        key_store.revoke_key("test-key-1")
        result = verify_provider_signature(signed_provider_data, key_store)
        assert result.verdict == SignatureVerdict.KEY_REVOKED

    def test_unsupported_algorithm(self, sample_provider_data, key_store):
        sample_provider_data["signature"] = {
            "alg": "RSA-2048",
            "key_id": "test-key-1",
            "sig": "aa" * 64,
        }
        result = verify_provider_signature(sample_provider_data, key_store)
        assert result.verdict == SignatureVerdict.UNSUPPORTED_ALG

    def test_malformed_missing_fields(self, sample_provider_data, key_store):
        sample_provider_data["signature"] = {"alg": "Ed25519"}
        result = verify_provider_signature(sample_provider_data, key_store)
        assert result.verdict == SignatureVerdict.MALFORMED

    def test_malformed_bad_hex(self, sample_provider_data, key_store):
        sample_provider_data["signature"] = {
            "alg": "Ed25519",
            "key_id": "test-key-1",
            "sig": "not-valid-hex!!!",
        }
        result = verify_provider_signature(sample_provider_data, key_store)
        assert result.verdict == SignatureVerdict.MALFORMED

    def test_malformed_wrong_sig_length(self, sample_provider_data, key_store):
        sample_provider_data["signature"] = {
            "alg": "Ed25519",
            "key_id": "test-key-1",
            "sig": "aa" * 32,  # 32 bytes, not 64
        }
        result = verify_provider_signature(sample_provider_data, key_store)
        assert result.verdict == SignatureVerdict.MALFORMED

    def test_wrong_key_signature(self, sample_provider_data, key_store):
        """Signed with a different key than what's in the store."""
        other_priv, _ = generate_ed25519_keypair()
        signed = sign_provider_entry(sample_provider_data, other_priv, "test-key-1")
        result = verify_provider_signature(signed, key_store)
        assert result.verdict == SignatureVerdict.INVALID


# ─────────────────────────────────────────────────────
# Sign Provider Entry
# ─────────────────────────────────────────────────────

class TestSignProviderEntry:
    def test_adds_signature_block(self, keypair, sample_provider_data):
        private_key, _ = keypair
        signed = sign_provider_entry(sample_provider_data, private_key, "k1")
        assert "signature" in signed
        assert signed["signature"]["alg"] == "Ed25519"
        assert signed["signature"]["key_id"] == "k1"
        assert len(signed["signature"]["sig"]) == 128  # 64 bytes hex

    def test_preserves_original_data(self, keypair, sample_provider_data):
        private_key, _ = keypair
        signed = sign_provider_entry(sample_provider_data, private_key, "k1")
        assert signed["name"] == sample_provider_data["name"]
        assert signed["version"] == sample_provider_data["version"]

    def test_does_not_mutate_input(self, keypair, sample_provider_data):
        private_key, _ = keypair
        original = dict(sample_provider_data)
        sign_provider_entry(sample_provider_data, private_key, "k1")
        assert sample_provider_data == original  # No mutation


# ─────────────────────────────────────────────────────
# SignatureVerifier (with caching)
# ─────────────────────────────────────────────────────

class TestSignatureVerifier:
    def test_verify_caches_result(self, signed_provider_data, key_store):
        sv = SignatureVerifier(key_store)
        r1 = sv.verify("provider-1", signed_provider_data)
        r2 = sv.verify("provider-1", signed_provider_data)
        assert r1.verdict == SignatureVerdict.VALID
        assert r1 is r2  # Same object from cache

    def test_clear_cache(self, signed_provider_data, key_store):
        sv = SignatureVerifier(key_store)
        sv.verify("provider-1", signed_provider_data)
        assert len(sv._cache) == 1
        sv.clear_cache()
        assert len(sv._cache) == 0

    def test_summary(self, signed_provider_data, sample_provider_data, key_store):
        sv = SignatureVerifier(key_store)
        sv.verify("signed", signed_provider_data)
        sv.verify("unsigned", sample_provider_data)
        summary = sv.summary()
        assert summary["total_keys"] == 1
        assert summary["cached_verifications"] == 2
        assert "valid" in summary["verdicts"]
        assert "no_signature" in summary["verdicts"]


# ─────────────────────────────────────────────────────
# Integration with SupplyChainVerifier
# ─────────────────────────────────────────────────────

class TestSupplyChainSignatureIntegration:
    """Test Ed25519 verification wired into SupplyChainVerifier."""

    def _make_lockfile_with_signed_provider(self, keypair, key_store):
        """Helper: create a lockfile with a signed provider and require_signatures."""
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, TrustPolicy, SupplyChainVerifier,
        )
        private_key, _ = keypair

        # Build provider data and sign it
        provider_data = {
            "name": "Secure Server",
            "version": "2.0.0",
            "digest": "sha256:secure123",
            "tools": ["secure_tool"],
            "origin": "https://secure.example.com",
            "trusted_at": datetime.now(timezone.utc).isoformat(),
        }
        signed = sign_provider_entry(provider_data, private_key, "test-key-1")

        entry = ProviderEntry(
            provider_id="secure-server",
            name=signed["name"],
            version=signed["version"],
            digest=signed["digest"],
            tools=signed["tools"],
            origin=signed["origin"],
            trusted_at=signed["trusted_at"],
            signature=signed["signature"],
        )

        lf = Lockfile(
            providers={"secure-server": entry},
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lf.build_index()

        sv = SignatureVerifier(key_store)
        verifier = SupplyChainVerifier(lf, signature_verifier=sv)
        return verifier

    def test_valid_signature_trusted(self, keypair, key_store):
        from unwind.enforcement.supply_chain import TrustVerdict
        verifier = self._make_lockfile_with_signed_provider(keypair, key_store)
        result = verifier.verify_tool("secure_tool")
        assert result.verdict == TrustVerdict.TRUSTED
        assert result.signature_valid is True

    def test_revoked_key_rejected(self, keypair, key_store):
        from unwind.enforcement.supply_chain import TrustVerdict
        key_store.revoke_key("test-key-1")
        verifier = self._make_lockfile_with_signed_provider(keypair, key_store)
        result = verifier.verify_tool("secure_tool")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID
        assert result.signature_valid is False

    def test_tampered_provider_rejected(self, keypair, key_store):
        from unwind.enforcement.supply_chain import TrustVerdict
        verifier = self._make_lockfile_with_signed_provider(keypair, key_store)
        # Tamper with the provider entry after signing
        verifier.lockfile.providers["secure-server"].version = "9.9.9"
        result = verifier.verify_tool("secure_tool")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID

    def test_no_verifier_rejects_when_signatures_required(self, keypair):
        """Without signature_verifier + require_signatures → SIGNATURE_INVALID.

        SENTINEL finding: presence-only fallback must not be used when
        signatures are required. No verifier = no way to verify = reject.
        """
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, TrustPolicy, SupplyChainVerifier, TrustVerdict,
        )
        private_key, _ = keypair

        entry = ProviderEntry(
            provider_id="p1",
            name="Provider",
            version="1.0",
            digest="sha256:abc",
            tools=["tool_a"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "aa" * 64},
        )

        lf = Lockfile(
            providers={"p1": entry},
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lf.build_index()

        # No signature_verifier — must reject, not fall back to presence check
        verifier = SupplyChainVerifier(lf, signature_verifier=None)
        result = verifier.verify_tool("tool_a")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID
        assert result.signature_valid is False
        assert "SignatureVerifier" in result.reason

    def test_no_verifier_passes_when_signatures_not_required(self, keypair):
        """Without signature_verifier + require_signatures=False → TRUSTED.

        The signature check is only triggered when require_signatures is True,
        so no verifier + no requirement = no problem.
        """
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, TrustPolicy, SupplyChainVerifier, TrustVerdict,
        )

        entry = ProviderEntry(
            provider_id="p1",
            name="Provider",
            version="1.0",
            digest="sha256:abc",
            tools=["tool_a"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "aa" * 64},
        )

        lf = Lockfile(
            providers={"p1": entry},
            trust_policy=TrustPolicy(require_signatures=False),  # Not required
        )
        lf.build_index()

        verifier = SupplyChainVerifier(lf, signature_verifier=None)
        result = verifier.verify_tool("tool_a")
        assert result.verdict == TrustVerdict.TRUSTED

    def test_missing_signature_rejected(self, keypair, key_store):
        """Provider with no signature when require_signatures=True."""
        from unwind.enforcement.supply_chain import (
            Lockfile, ProviderEntry, TrustPolicy, SupplyChainVerifier, TrustVerdict,
        )

        entry = ProviderEntry(
            provider_id="unsigned",
            name="Unsigned Server",
            version="1.0",
            digest="sha256:abc",
            tools=["unsigned_tool"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature=None,  # No signature
        )

        lf = Lockfile(
            providers={"unsigned": entry},
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lf.build_index()

        sv = SignatureVerifier(key_store)
        verifier = SupplyChainVerifier(lf, signature_verifier=sv)
        result = verifier.verify_tool("unsigned_tool")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID

    def test_provider_to_dict_helper(self, keypair):
        """_provider_to_dict produces correct dict for signature verification."""
        from unwind.enforcement.supply_chain import ProviderEntry, SupplyChainVerifier

        entry = ProviderEntry(
            provider_id="p1",
            name="Test",
            version="1.0",
            digest="sha256:abc",
            tools=["t1", "t2"],
            origin="https://example.com",
            trusted_at="2026-01-01T00:00:00+00:00",
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "deadbeef"},
        )

        d = SupplyChainVerifier._provider_to_dict(entry)
        assert d["name"] == "Test"
        assert d["tools"] == ["t1", "t2"]
        assert "signature" in d
        assert "provider_id" not in d  # Not serialised


# ─────────────────────────────────────────────────────
# Key Store HMAC Integrity (SENTINEL finding)
# ─────────────────────────────────────────────────────

class TestKeyStoreIntegrity:
    """HMAC protection for the key store file."""

    def test_save_creates_hmac_sidecar(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        sidecar = _key_store_hmac_path(path)
        assert sidecar.exists()
        assert len(sidecar.read_text()) == 64  # SHA-256 hex

    def test_save_without_signing(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path, sign=False)
        assert not _key_store_hmac_path(path).exists()

    def test_roundtrip_with_hmac(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        loaded = load_key_store(path)
        assert "test-key-1" in loaded.keys

    def test_tampered_key_store_fails_closed(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        # Tamper
        content = path.read_text()
        path.write_text(content + "\n")
        loaded = load_key_store(path)
        assert len(loaded.keys) == 0  # Fail-closed

    def test_missing_sidecar_warns_but_loads(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path, sign=False)
        loaded = load_key_store(path)
        assert "test-key-1" in loaded.keys  # Loads with warning

    def test_skip_verification(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        # Tamper
        content = path.read_text()
        path.write_text(content + "\n")
        # With verification off, tampered file loads
        loaded = load_key_store(path, verify_integrity=False)
        assert "test-key-1" in loaded.keys

    def test_custom_hmac_key(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        key = b"my-keystore-secret-key!!!!!!!!!!"
        save_key_store(key_store, path, hmac_key=key)
        loaded = load_key_store(path, hmac_key=key)
        assert "test-key-1" in loaded.keys

    def test_wrong_hmac_key_fails(self, key_store, tmp_path):
        path = tmp_path / "keys.json"
        save_key_store(key_store, path, hmac_key=b"key-1-secret!!!!!!!!!!!!!!!!!!")
        loaded = load_key_store(path, hmac_key=b"key-2-different!!!!!!!!!!!!!!!!!")
        assert len(loaded.keys) == 0  # Key mismatch → fail-closed

    def test_hmac_sidecar_path(self, tmp_path):
        path = tmp_path / "provider-keyring.json"
        sidecar = _key_store_hmac_path(path)
        assert sidecar.name == "provider-keyring.json.hmac"

    # --- Strict-mode sidecar enforcement (drift fix #2) ---

    def test_strict_missing_sidecar_fails_closed(self, key_store, tmp_path):
        """Strict + no HMAC sidecar → empty key store (fail-closed)."""
        path = tmp_path / "keys.json"
        save_key_store(key_store, path, sign=False)  # No sidecar
        loaded = load_key_store(path, strict=True)
        assert len(loaded.keys) == 0  # Strict rejects unsigned

    def test_strict_with_valid_sidecar_loads(self, key_store, tmp_path):
        """Strict + valid HMAC sidecar → loads normally."""
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)  # Creates sidecar
        loaded = load_key_store(path, strict=True)
        assert "test-key-1" in loaded.keys

    def test_strict_tampered_still_fails_closed(self, key_store, tmp_path):
        """Strict + tampered content → fail-closed (same as permissive)."""
        path = tmp_path / "keys.json"
        save_key_store(key_store, path)
        content = path.read_text()
        path.write_text(content + "\n")
        loaded = load_key_store(path, strict=True)
        assert len(loaded.keys) == 0

    def test_permissive_missing_sidecar_still_loads(self, key_store, tmp_path):
        """Permissive + no sidecar → loads with warning (backwards compatible)."""
        path = tmp_path / "keys.json"
        save_key_store(key_store, path, sign=False)
        loaded = load_key_store(path, strict=False)
        assert "test-key-1" in loaded.keys
