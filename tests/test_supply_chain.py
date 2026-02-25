"""Tests for supply-chain trust system.

Covers:
- Lockfile loading, parsing, saving
- Provider entry mechanics (digest, expiry)
- Tool→provider index lookup
- SupplyChainVerifier: all verdict types
- Blocklist management
- Quarantine workflow
- Provider registration
- Digest computation and verification
- Trust policy enforcement
- Real-world attack scenarios
"""

import json
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from unwind.enforcement.supply_chain import (
    HMACKey,
    HMACVerification,
    Lockfile,
    MIN_KEY_LENGTH,
    ProviderEntry,
    SupplyChainVerifier,
    TrustPolicy,
    TrustVerdict,
    VerificationResult,
    _get_hmac_key,
    _hmac_sidecar_path,
    compute_digest,
    compute_hmac,
    load_lockfile,
    parse_lockfile,
    save_lockfile,
    verify_hmac,
    verify_lockfile_integrity,
)


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def sample_provider():
    return ProviderEntry(
        provider_id="mcp-filesystem",
        name="MCP Filesystem Server",
        version="1.2.3",
        digest="sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        tools=["fs_read", "fs_write", "fs_delete", "fs_mkdir"],
        origin="https://github.com/mcp/filesystem-server",
        trusted_at=datetime.now(timezone.utc).isoformat(),
    )


@pytest.fixture
def sample_lockfile(sample_provider):
    lf = Lockfile(
        version="1.0",
        created=datetime.now(timezone.utc).isoformat(),
        providers={"mcp-filesystem": sample_provider},
        trust_policy=TrustPolicy(
            require_signatures=False,
            quarantine_unknown=True,
            max_age_days=90,
        ),
    )
    lf.build_index()
    return lf


@pytest.fixture
def verifier(sample_lockfile):
    return SupplyChainVerifier(sample_lockfile)


@pytest.fixture
def multi_provider_lockfile():
    """Lockfile with multiple providers."""
    providers = {
        "mcp-filesystem": ProviderEntry(
            provider_id="mcp-filesystem",
            name="MCP Filesystem",
            version="1.2.3",
            digest="sha256:aaaa",
            tools=["fs_read", "fs_write"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        ),
        "mcp-git": ProviderEntry(
            provider_id="mcp-git",
            name="MCP Git",
            version="2.0.1",
            digest="sha256:bbbb",
            tools=["git_clone", "git_push", "git_status"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        ),
        "mcp-email": ProviderEntry(
            provider_id="mcp-email",
            name="MCP Email",
            version="0.9.0",
            digest="sha256:cccc",
            tools=["send_email", "read_email"],
            origin="https://github.com/mcp/email-server",
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "deadbeef"},
        ),
    }
    lf = Lockfile(
        version="1.0",
        created=datetime.now(timezone.utc).isoformat(),
        providers=providers,
        blocklist={"mcp-malicious"},
        trust_policy=TrustPolicy(
            require_signatures=False,
            quarantine_unknown=True,
            max_age_days=90,
        ),
    )
    lf.build_index()
    return lf


# ─────────────────────────────────────────────────────
# Digest computation
# ─────────────────────────────────────────────────────

class TestDigest:
    def test_compute_sha256(self):
        content = b"hello world"
        digest = compute_digest(content)
        assert digest.startswith("sha256:")
        assert len(digest.split(":")[1]) == 64  # SHA256 hex = 64 chars

    def test_same_content_same_digest(self):
        assert compute_digest(b"test") == compute_digest(b"test")

    def test_different_content_different_digest(self):
        assert compute_digest(b"a") != compute_digest(b"b")

    def test_empty_content(self):
        digest = compute_digest(b"")
        assert digest.startswith("sha256:")

    def test_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported"):
            compute_digest(b"test", algorithm="md5")


# ─────────────────────────────────────────────────────
# ProviderEntry
# ─────────────────────────────────────────────────────

class TestProviderEntry:
    def test_digest_algorithm(self, sample_provider):
        assert sample_provider.digest_algorithm() == "sha256"

    def test_digest_value(self, sample_provider):
        val = sample_provider.digest_value()
        assert val == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    def test_no_colon_in_digest(self):
        entry = ProviderEntry(
            provider_id="x", name="x", version="1", digest="noprefix", tools=[]
        )
        assert entry.digest_algorithm() == "unknown"
        assert entry.digest_value() == "noprefix"

    def test_not_expired(self, sample_provider):
        assert not sample_provider.is_expired(90)

    def test_expired(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        entry = ProviderEntry(
            provider_id="x", name="x", version="1", digest="",
            tools=[], trusted_at=old_date
        )
        assert entry.is_expired(90)

    def test_zero_max_age_never_expires(self, sample_provider):
        assert not sample_provider.is_expired(0)

    def test_no_trusted_at_never_expires(self):
        entry = ProviderEntry(
            provider_id="x", name="x", version="1", digest="", tools=[]
        )
        assert not entry.is_expired(90)

    def test_invalid_date_treated_as_expired(self):
        entry = ProviderEntry(
            provider_id="x", name="x", version="1", digest="",
            tools=[], trusted_at="not-a-date"
        )
        assert entry.is_expired(90)


# ─────────────────────────────────────────────────────
# Lockfile
# ─────────────────────────────────────────────────────

class TestLockfile:
    def test_provider_for_tool(self, sample_lockfile):
        assert sample_lockfile.provider_for_tool("fs_read") == "mcp-filesystem"
        assert sample_lockfile.provider_for_tool("fs_write") == "mcp-filesystem"

    def test_unknown_tool(self, sample_lockfile):
        assert sample_lockfile.provider_for_tool("unknown_tool") is None

    def test_is_blocked(self, multi_provider_lockfile):
        assert multi_provider_lockfile.is_blocked("mcp-malicious")
        assert not multi_provider_lockfile.is_blocked("mcp-filesystem")

    def test_get_provider(self, sample_lockfile):
        entry = sample_lockfile.get_provider("mcp-filesystem")
        assert entry is not None
        assert entry.name == "MCP Filesystem Server"

    def test_get_missing_provider(self, sample_lockfile):
        assert sample_lockfile.get_provider("nonexistent") is None

    def test_multi_provider_index(self, multi_provider_lockfile):
        assert multi_provider_lockfile.provider_for_tool("git_push") == "mcp-git"
        assert multi_provider_lockfile.provider_for_tool("send_email") == "mcp-email"
        assert multi_provider_lockfile.provider_for_tool("fs_read") == "mcp-filesystem"


# ─────────────────────────────────────────────────────
# Lockfile load/save
# ─────────────────────────────────────────────────────

class TestLockfileIO:
    def test_load_missing_file(self, tmp_path):
        lf = load_lockfile(tmp_path / "nonexistent.json")
        assert lf.version == "1.0"
        assert len(lf.providers) == 0

    def test_load_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json!!!")
        lf = load_lockfile(bad_file)
        assert len(lf.providers) == 0

    def test_save_and_load_roundtrip(self, sample_lockfile, tmp_path):
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)

        loaded = load_lockfile(path)
        assert loaded.version == "1.0"
        assert "mcp-filesystem" in loaded.providers
        assert loaded.providers["mcp-filesystem"].version == "1.2.3"
        assert loaded.provider_for_tool("fs_read") == "mcp-filesystem"

    def test_save_creates_directory(self, sample_lockfile, tmp_path):
        path = tmp_path / "deep" / "nested" / "lockfile.json"
        save_lockfile(sample_lockfile, path)
        assert path.exists()

    def test_parse_lockfile_minimal(self):
        data = {"providers": {}, "trust_policy": {}}
        lf = parse_lockfile(data)
        assert lf.version == "1.0"
        assert lf.trust_policy.quarantine_unknown is True  # default

    def test_parse_lockfile_with_signature(self):
        data = {
            "providers": {
                "signed-provider": {
                    "name": "Signed",
                    "version": "1.0",
                    "digest": "sha256:1234",
                    "tools": ["tool_a"],
                    "signature": {"alg": "Ed25519", "key_id": "k1", "sig": "abc"},
                }
            },
            "trust_policy": {"require_signatures": True},
        }
        lf = parse_lockfile(data)
        entry = lf.providers["signed-provider"]
        assert entry.signature is not None
        assert entry.signature["alg"] == "Ed25519"
        assert lf.trust_policy.require_signatures is True


# ─────────────────────────────────────────────────────
# SupplyChainVerifier — Verdicts
# ─────────────────────────────────────────────────────

class TestVerifierVerdicts:
    def test_trusted_tool(self, verifier):
        result = verifier.verify_tool("fs_read")
        assert result.verdict == TrustVerdict.TRUSTED
        assert result.provider_id == "mcp-filesystem"

    def test_unknown_tool_quarantined(self, verifier):
        result = verifier.verify_tool("unknown_tool")
        assert result.verdict == TrustVerdict.QUARANTINED

    def test_unknown_tool_untrusted_when_quarantine_off(self, sample_provider):
        lf = Lockfile(
            providers={"mcp-filesystem": sample_provider},
            trust_policy=TrustPolicy(quarantine_unknown=False),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)
        result = v.verify_tool("unknown_tool")
        assert result.verdict == TrustVerdict.UNTRUSTED

    def test_blocked_provider(self, multi_provider_lockfile):
        # Add a tool to the malicious provider to make it findable
        malicious = ProviderEntry(
            provider_id="mcp-malicious", name="Malicious",
            version="1.0", digest="sha256:evil", tools=["evil_tool"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        multi_provider_lockfile.providers["mcp-malicious"] = malicious
        multi_provider_lockfile.build_index()

        v = SupplyChainVerifier(multi_provider_lockfile)
        result = v.verify_tool("evil_tool")
        assert result.verdict == TrustVerdict.BLOCKED

    def test_expired_provider(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        entry = ProviderEntry(
            provider_id="old", name="Old Provider", version="1.0",
            digest="sha256:old", tools=["old_tool"], trusted_at=old_date,
        )
        lf = Lockfile(
            providers={"old": entry},
            trust_policy=TrustPolicy(max_age_days=90),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)
        result = v.verify_tool("old_tool")
        assert result.verdict == TrustVerdict.EXPIRED

    def test_digest_mismatch(self, verifier):
        result = verifier.verify_tool("fs_read", current_digest="sha256:wrong")
        assert result.verdict == TrustVerdict.UNTRUSTED
        assert result.digest_match is False

    def test_digest_match(self, verifier, sample_provider):
        result = verifier.verify_tool("fs_read", current_digest=sample_provider.digest)
        assert result.verdict == TrustVerdict.TRUSTED
        assert result.digest_match is True

    def test_signature_required_but_missing(self):
        entry = ProviderEntry(
            provider_id="unsigned", name="Unsigned", version="1.0",
            digest="sha256:abc", tools=["tool_a"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        lf = Lockfile(
            providers={"unsigned": entry},
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)
        result = v.verify_tool("tool_a")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID

    def test_signature_required_no_verifier_rejects(self):
        """require_signatures + no SignatureVerifier → SIGNATURE_INVALID.

        SENTINEL finding: presence-only fallback not acceptable when
        signatures are required.
        """
        entry = ProviderEntry(
            provider_id="signed", name="Signed", version="1.0",
            digest="sha256:abc", tools=["tool_a"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "valid"},
        )
        lf = Lockfile(
            providers={"signed": entry},
            trust_policy=TrustPolicy(require_signatures=True),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)  # No signature_verifier
        result = v.verify_tool("tool_a")
        assert result.verdict == TrustVerdict.SIGNATURE_INVALID
        assert result.signature_valid is False

    def test_signature_not_required_passes_without_verifier(self):
        """require_signatures=False → signature check skipped entirely."""
        entry = ProviderEntry(
            provider_id="signed", name="Signed", version="1.0",
            digest="sha256:abc", tools=["tool_a"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
            signature={"alg": "Ed25519", "key_id": "k1", "sig": "valid"},
        )
        lf = Lockfile(
            providers={"signed": entry},
            trust_policy=TrustPolicy(require_signatures=False),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)
        result = v.verify_tool("tool_a")
        assert result.verdict == TrustVerdict.TRUSTED


# ─────────────────────────────────────────────────────
# Blocklist management
# ─────────────────────────────────────────────────────

class TestBlocklist:
    def test_add_to_blocklist(self, verifier):
        verifier.add_to_blocklist("mcp-filesystem")
        result = verifier.verify_tool("fs_read")
        assert result.verdict == TrustVerdict.BLOCKED

    def test_remove_from_blocklist(self, multi_provider_lockfile):
        v = SupplyChainVerifier(multi_provider_lockfile)
        v.remove_from_blocklist("mcp-malicious")
        assert not multi_provider_lockfile.is_blocked("mcp-malicious")

    def test_add_removes_from_verified_cache(self, verifier):
        verifier.verify_tool("fs_read")  # Populates cache
        assert verifier.is_provider_verified("mcp-filesystem")
        verifier.add_to_blocklist("mcp-filesystem")
        assert not verifier.is_provider_verified("mcp-filesystem")

    def test_double_add_no_duplicate(self, verifier):
        verifier.add_to_blocklist("test")
        verifier.add_to_blocklist("test")
        assert "test" in verifier.lockfile.blocklist
        assert len([x for x in verifier.lockfile.blocklist if x == "test"]) == 1


# ─────────────────────────────────────────────────────
# Hardening: duplicate tools, version downgrade, empty digest
# ─────────────────────────────────────────────────────

class TestHardening:
    def test_duplicate_tool_claims_first_writer_wins(self):
        """Two providers claiming same tool: first-writer-wins."""
        providers = {
            "legit-server": ProviderEntry(
                provider_id="legit-server", name="Legit", version="1.0",
                digest="sha256:aaaa", tools=["shared_tool", "legit_only"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
            "evil-server": ProviderEntry(
                provider_id="evil-server", name="Evil", version="1.0",
                digest="sha256:bbbb", tools=["shared_tool", "evil_only"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
        }
        lf = Lockfile(providers=providers)
        lf.build_index()
        # First-writer-wins: legit-server owns shared_tool
        assert lf.provider_for_tool("shared_tool") == "legit-server"

    def test_has_duplicate_tool_claims(self):
        """Detect tools claimed by multiple providers."""
        providers = {
            "a": ProviderEntry(provider_id="a", name="A", version="1.0",
                               digest="sha256:aa", tools=["tool_x", "tool_y"]),
            "b": ProviderEntry(provider_id="b", name="B", version="1.0",
                               digest="sha256:bb", tools=["tool_x", "tool_z"]),
        }
        lf = Lockfile(providers=providers)
        lf.build_index()
        dupes = lf.has_duplicate_tool_claims()
        assert "tool_x" in dupes
        assert set(dupes["tool_x"]) == {"a", "b"}
        assert "tool_y" not in dupes
        assert "tool_z" not in dupes

    def test_version_downgrade_rejected(self, verifier):
        """Version downgrade should raise ValueError."""
        verifier.register_provider(
            provider_id="my-server", name="MyServer", version="2.0.0",
            tools=["my_tool"], content=b"v2 content",
        )
        with pytest.raises(ValueError, match="downgrade rejected"):
            verifier.register_provider(
                provider_id="my-server", name="MyServer", version="1.0.0",
                tools=["my_tool"], content=b"v1 content",
            )

    def test_version_downgrade_allowed_with_flag(self, verifier):
        """Version downgrade allowed when explicitly permitted."""
        verifier.register_provider(
            provider_id="my-server", name="MyServer", version="2.0.0",
            tools=["my_tool"], content=b"v2 content",
        )
        entry = verifier.register_provider(
            provider_id="my-server", name="MyServer", version="1.0.0",
            tools=["my_tool"], content=b"v1 content",
            allow_downgrade=True,
        )
        assert entry.version == "1.0.0"

    def test_version_upgrade_always_allowed(self, verifier):
        """Upgrading version always works."""
        verifier.register_provider(
            provider_id="my-server", name="MyServer", version="1.0.0",
            tools=["my_tool"], content=b"v1 content",
        )
        entry = verifier.register_provider(
            provider_id="my-server", name="MyServer", version="2.0.0",
            tools=["my_tool"], content=b"v2 content",
        )
        assert entry.version == "2.0.0"

    def test_empty_digest_in_lockfile_rejects_verification(self):
        """Provider with no stored digest should reject when live digest provided."""
        providers = {
            "no-digest-server": ProviderEntry(
                provider_id="no-digest-server", name="NoDigest", version="1.0",
                digest="",  # No stored digest!
                tools=["fragile_tool"],
                trusted_at=datetime.now(timezone.utc).isoformat(),
            ),
        }
        lf = Lockfile(providers=providers)
        lf.build_index()
        v = SupplyChainVerifier(lf)
        # With no live digest, passes (backwards compat)
        result = v.verify_tool("fragile_tool")
        assert result.verdict == TrustVerdict.TRUSTED
        # With live digest but no stored digest, rejects
        result = v.verify_tool("fragile_tool", current_digest="sha256:abc123")
        assert result.verdict == TrustVerdict.UNTRUSTED
        assert result.digest_match is False

    def test_blocklist_is_set_not_list(self, verifier):
        """Blocklist should be a set for O(1) lookup."""
        assert isinstance(verifier.lockfile.blocklist, set)


# ─────────────────────────────────────────────────────
# Quarantine workflow
# ─────────────────────────────────────────────────────

class TestQuarantine:
    def test_quarantine_provider(self, verifier, sample_provider):
        verifier.quarantine_provider("new-provider", sample_provider)
        q = verifier.get_quarantine()
        assert "new-provider" in q

    def test_release_from_quarantine(self, verifier, sample_provider):
        verifier.quarantine_provider("new-provider", sample_provider)
        released = verifier.release_from_quarantine("new-provider")
        assert released is not None
        assert verifier.get_quarantine() == {}

    def test_release_nonexistent(self, verifier):
        assert verifier.release_from_quarantine("nope") is None

    def test_quarantine_empty_by_default(self, verifier):
        assert verifier.get_quarantine() == {}


# ─────────────────────────────────────────────────────
# Provider registration
# ─────────────────────────────────────────────────────

class TestRegistration:
    def test_register_new_provider(self, verifier):
        entry = verifier.register_provider(
            provider_id="mcp-new",
            name="New Provider",
            version="1.0.0",
            tools=["new_tool"],
            content=b"provider code here",
            origin="https://example.com",
        )
        assert entry.digest.startswith("sha256:")
        assert entry.trusted_at is not None

        # Should now be verifiable
        result = verifier.verify_tool("new_tool")
        assert result.verdict == TrustVerdict.TRUSTED

    def test_register_without_content(self, verifier):
        entry = verifier.register_provider(
            provider_id="mcp-no-content",
            name="No Content",
            version="1.0.0",
            tools=["nc_tool"],
        )
        assert entry.digest == ""

    def test_register_rebuilds_index(self, verifier):
        verifier.register_provider(
            provider_id="mcp-dynamic",
            name="Dynamic",
            version="1.0.0",
            tools=["dynamic_tool"],
        )
        assert verifier.lockfile.provider_for_tool("dynamic_tool") == "mcp-dynamic"


# ─────────────────────────────────────────────────────
# Verification cache
# ─────────────────────────────────────────────────────

class TestVerificationCache:
    def test_verified_provider_cached(self, verifier):
        verifier.verify_tool("fs_read")
        assert verifier.is_provider_verified("mcp-filesystem")

    def test_unverified_not_cached(self, verifier):
        assert not verifier.is_provider_verified("mcp-filesystem")

    def test_failed_verification_not_cached(self, verifier):
        verifier.verify_tool("fs_read", current_digest="sha256:wrong")
        assert not verifier.is_provider_verified("mcp-filesystem")


# ─────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────

class TestSummary:
    def test_summary_structure(self, verifier):
        s = verifier.summary()
        assert "total_providers" in s
        assert "verified_this_session" in s
        assert "quarantined" in s
        assert "blocklisted" in s
        assert "require_signatures" in s
        assert "max_age_days" in s

    def test_summary_values(self, verifier):
        verifier.verify_tool("fs_read")
        s = verifier.summary()
        assert s["total_providers"] == 1
        assert s["verified_this_session"] == 1
        assert s["quarantined"] == 0
        assert s["blocklisted"] == 0


# ─────────────────────────────────────────────────────
# Real-world attack scenarios
# ─────────────────────────────────────────────────────

class TestAttackScenarios:
    def test_malicious_server_update_caught_by_digest(self):
        """Attacker updates MCP server code → digest changes → blocked."""
        entry = ProviderEntry(
            provider_id="mcp-fs", name="FS", version="1.0",
            digest=compute_digest(b"legitimate code"),
            tools=["fs_read"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        lf = Lockfile(providers={"mcp-fs": entry})
        lf.build_index()
        v = SupplyChainVerifier(lf)

        # Attacker modifies server code
        tampered_digest = compute_digest(b"legitimate code + backdoor")
        result = v.verify_tool("fs_read", current_digest=tampered_digest)
        assert result.verdict == TrustVerdict.UNTRUSTED
        assert result.digest_match is False

    def test_supply_chain_injection_new_tool(self):
        """Attacker adds a new tool to a compromised server → quarantined."""
        entry = ProviderEntry(
            provider_id="mcp-fs", name="FS", version="1.0",
            digest="sha256:legit", tools=["fs_read", "fs_write"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        lf = Lockfile(
            providers={"mcp-fs": entry},
            trust_policy=TrustPolicy(quarantine_unknown=True),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)

        # Attacker injects a new tool not in the lockfile
        result = v.verify_tool("fs_exfiltrate")
        assert result.verdict == TrustVerdict.QUARANTINED

    def test_blocklisted_provider_cannot_be_used(self, multi_provider_lockfile):
        """Even if provider has valid tools, blocklist takes priority."""
        malicious = ProviderEntry(
            provider_id="mcp-malicious", name="Malicious",
            version="1.0", digest="sha256:looks-legit",
            tools=["innocent_tool"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        multi_provider_lockfile.providers["mcp-malicious"] = malicious
        multi_provider_lockfile.build_index()
        v = SupplyChainVerifier(multi_provider_lockfile)

        result = v.verify_tool("innocent_tool")
        assert result.verdict == TrustVerdict.BLOCKED

    def test_stale_trust_expired(self):
        """Provider trusted 6 months ago with 90-day policy → expired."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
        entry = ProviderEntry(
            provider_id="old-server", name="Old Server",
            version="0.5.0", digest="sha256:old",
            tools=["legacy_tool"], trusted_at=old_date,
        )
        lf = Lockfile(
            providers={"old-server": entry},
            trust_policy=TrustPolicy(max_age_days=90),
        )
        lf.build_index()
        v = SupplyChainVerifier(lf)
        result = v.verify_tool("legacy_tool")
        assert result.verdict == TrustVerdict.EXPIRED

    def test_version_pinning(self, verifier, sample_provider):
        """Lockfile pins version — useful for audit trail."""
        entry = verifier.lockfile.get_provider("mcp-filesystem")
        assert entry.version == "1.2.3"
        # If upstream claims 1.2.4 but lockfile says 1.2.3 → digest will differ

    def test_full_quarantine_approve_workflow(self, verifier):
        """Complete workflow: unknown → quarantine → human approve → trusted."""
        # 1. Unknown tool arrives
        result = verifier.verify_tool("brand_new_tool")
        assert result.verdict == TrustVerdict.QUARANTINED

        # 2. Admin quarantines the provider for review
        new_entry = ProviderEntry(
            provider_id="mcp-new", name="New Server",
            version="1.0.0", digest=compute_digest(b"new server code"),
            tools=["brand_new_tool"],
            trusted_at=datetime.now(timezone.utc).isoformat(),
        )
        verifier.quarantine_provider("mcp-new", new_entry)

        # 3. Human reviews and approves
        released = verifier.release_from_quarantine("mcp-new")
        assert released is not None

        # 4. Register in lockfile
        verifier.register_provider(
            provider_id="mcp-new",
            name="New Server",
            version="1.0.0",
            tools=["brand_new_tool"],
            content=b"new server code",
        )

        # 5. Now trusted
        result = verifier.verify_tool("brand_new_tool")
        assert result.verdict == TrustVerdict.TRUSTED


# ─────────────────────────────────────────────────────
# HMAC Lockfile Integrity (R-LOCK-003)
# ─────────────────────────────────────────────────────

class TestHMACPrimitives:
    """Test low-level HMAC functions."""

    def test_compute_hmac_deterministic(self):
        key = b"test-key"
        content = b"test-content"
        h1 = compute_hmac(content, key)
        h2 = compute_hmac(content, key)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_hmac_different_keys(self):
        content = b"same-content"
        h1 = compute_hmac(content, b"key-1")
        h2 = compute_hmac(content, b"key-2")
        assert h1 != h2

    def test_compute_hmac_different_content(self):
        key = b"same-key"
        h1 = compute_hmac(b"content-a", key)
        h2 = compute_hmac(b"content-b", key)
        assert h1 != h2

    def test_verify_hmac_valid(self):
        key = b"test-key"
        content = b"test-content"
        mac = compute_hmac(content, key)
        assert verify_hmac(content, mac, key) is True

    def test_verify_hmac_tampered_content(self):
        key = b"test-key"
        mac = compute_hmac(b"original", key)
        assert verify_hmac(b"tampered", mac, key) is False

    def test_verify_hmac_wrong_key(self):
        content = b"test-content"
        mac = compute_hmac(content, b"correct-key")
        assert verify_hmac(content, mac, b"wrong-key") is False

    def test_verify_hmac_timing_safe(self):
        """verify_hmac uses constant-time comparison (hmac.compare_digest)."""
        # We can't easily test timing, but we verify it uses the right function
        # by ensuring it works correctly for near-miss values
        key = b"key"
        content = b"content"
        mac = compute_hmac(content, key)
        # Flip one character
        tampered_mac = mac[:-1] + ("0" if mac[-1] != "0" else "1")
        assert verify_hmac(content, tampered_mac, key) is False


class TestHMACKeyDerivation:
    """Test HMAC key retrieval and derivation."""

    def test_fallback_key_deterministic(self, tmp_path):
        """Same path always produces same fallback key."""
        path = tmp_path / "lockfile.json"
        k1 = _get_hmac_key(path)
        k2 = _get_hmac_key(path)
        assert k1.key == k2.key
        assert len(k1.key) == 32  # SHA-256 output

    def test_fallback_key_not_production(self, tmp_path):
        """Fallback key is tagged as non-production."""
        k = _get_hmac_key(tmp_path / "lockfile.json")
        assert k.is_production is False
        assert k.source == "fallback"

    def test_fallback_key_different_paths(self, tmp_path):
        """Different paths produce different fallback keys."""
        k1 = _get_hmac_key(tmp_path / "lockfile-a.json")
        k2 = _get_hmac_key(tmp_path / "lockfile-b.json")
        assert k1.key != k2.key

    def test_env_key_hex(self, tmp_path, monkeypatch):
        """UNWIND_LOCKFILE_KEY env var (hex) takes priority."""
        hex_key = "aa" * 32  # 32 bytes in hex
        monkeypatch.setenv("UNWIND_LOCKFILE_KEY", hex_key)
        k = _get_hmac_key(tmp_path / "lockfile.json")
        assert k.key == bytes.fromhex(hex_key)
        assert k.is_production is True
        assert k.source == "env"

    def test_env_key_passphrase(self, tmp_path, monkeypatch):
        """Non-hex env var is used as UTF-8 passphrase."""
        monkeypatch.setenv("UNWIND_LOCKFILE_KEY", "my-secret-passphrase")
        k = _get_hmac_key(tmp_path / "lockfile.json")
        assert k.key == b"my-secret-passphrase"
        assert k.is_production is True

    def test_env_key_overrides_fallback(self, tmp_path, monkeypatch):
        """Env var key is different from path-derived fallback."""
        fallback = _get_hmac_key(tmp_path / "lockfile.json")
        monkeypatch.setenv("UNWIND_LOCKFILE_KEY", "override")
        env_key = _get_hmac_key(tmp_path / "lockfile.json")
        assert fallback.key != env_key.key

    def test_short_env_key_still_production(self, tmp_path, monkeypatch):
        """Short env key is tagged production but with warning."""
        monkeypatch.setenv("UNWIND_LOCKFILE_KEY", "ab")  # Only 1 byte hex
        k = _get_hmac_key(tmp_path / "lockfile.json")
        assert k.is_production is True  # Still production, just short
        assert len(k.key) < MIN_KEY_LENGTH


class TestHMACSidecar:
    """Test HMAC sidecar path and file operations."""

    def test_sidecar_path(self, tmp_path):
        lf_path = tmp_path / "lockfile.json"
        sidecar = _hmac_sidecar_path(lf_path)
        assert sidecar == tmp_path / "lockfile.json.hmac"

    def test_sidecar_path_nested(self, tmp_path):
        lf_path = tmp_path / "config" / "unwind.lock.json"
        sidecar = _hmac_sidecar_path(lf_path)
        assert sidecar.name == "unwind.lock.json.hmac"


class TestVerifyLockfileIntegrity:
    """Test the verify_lockfile_integrity function."""

    def test_missing_lockfile(self, tmp_path):
        result = verify_lockfile_integrity(tmp_path / "nonexistent.json")
        assert result.valid is False
        assert result.sidecar_exists is False

    def test_no_sidecar(self, tmp_path):
        """Lockfile exists but no HMAC sidecar → unsigned."""
        lf_path = tmp_path / "lockfile.json"
        lf_path.write_text('{"version": "1.0"}')
        result = verify_lockfile_integrity(lf_path)
        assert result.valid is False
        assert result.sidecar_exists is False
        assert "unsigned" in result.reason.lower() or "No HMAC" in result.reason

    def test_valid_hmac(self, tmp_path):
        """Lockfile + valid sidecar → passes."""
        lf_path = tmp_path / "lockfile.json"
        content = b'{"version": "1.0"}'
        lf_path.write_bytes(content)

        key = _get_hmac_key(lf_path).key
        sidecar = _hmac_sidecar_path(lf_path)
        sidecar.write_text(compute_hmac(content, key))

        result = verify_lockfile_integrity(lf_path)
        assert result.valid is True
        assert result.sidecar_exists is True

    def test_tampered_content(self, tmp_path):
        """Content changed after signing → HMAC mismatch."""
        lf_path = tmp_path / "lockfile.json"
        original = b'{"version": "1.0"}'
        lf_path.write_bytes(original)

        key = _get_hmac_key(lf_path).key
        sidecar = _hmac_sidecar_path(lf_path)
        sidecar.write_text(compute_hmac(original, key))

        # Tamper with the lockfile
        lf_path.write_bytes(b'{"version": "1.0", "blocklist": []}')

        result = verify_lockfile_integrity(lf_path)
        assert result.valid is False
        assert result.sidecar_exists is True
        assert "FAILED" in result.reason or "tampered" in result.reason.lower()

    def test_tampered_sidecar(self, tmp_path):
        """Sidecar modified → HMAC mismatch."""
        lf_path = tmp_path / "lockfile.json"
        content = b'{"version": "1.0"}'
        lf_path.write_bytes(content)

        sidecar = _hmac_sidecar_path(lf_path)
        sidecar.write_text("deadbeef" * 8)  # Fake HMAC

        result = verify_lockfile_integrity(lf_path)
        assert result.valid is False
        assert result.sidecar_exists is True

    def test_custom_key(self, tmp_path):
        """Explicit key overrides env/fallback."""
        lf_path = tmp_path / "lockfile.json"
        content = b'{"version": "1.0"}'
        lf_path.write_bytes(content)

        custom_key = b"custom-secret-key"
        sidecar = _hmac_sidecar_path(lf_path)
        sidecar.write_text(compute_hmac(content, custom_key))

        # With correct key → passes
        result = verify_lockfile_integrity(lf_path, key=custom_key)
        assert result.valid is True

        # With wrong key → fails
        result = verify_lockfile_integrity(lf_path, key=b"wrong-key")
        assert result.valid is False


class TestLockfileHMACIntegration:
    """Integration tests: save_lockfile writes HMAC, load_lockfile verifies it."""

    def test_save_creates_sidecar(self, sample_lockfile, tmp_path):
        """save_lockfile creates an HMAC sidecar file."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)
        sidecar = _hmac_sidecar_path(path)
        assert sidecar.exists()
        assert len(sidecar.read_text()) == 64  # SHA-256 hex

    def test_save_without_signing(self, sample_lockfile, tmp_path):
        """save_lockfile(sign=False) skips HMAC sidecar."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path, sign=False)
        sidecar = _hmac_sidecar_path(path)
        assert not sidecar.exists()

    def test_roundtrip_with_hmac(self, sample_lockfile, tmp_path):
        """Save + load with HMAC verification passes."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)
        loaded = load_lockfile(path)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is True

    def test_tampered_lockfile_fails_closed(self, sample_lockfile, tmp_path):
        """Tampered lockfile → load returns empty lockfile (fail-closed)."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)

        # Tamper with the lockfile content
        content = path.read_text()
        path.write_text(content + "\n")

        loaded = load_lockfile(path)
        assert len(loaded.providers) == 0  # Fail-closed: empty lockfile
        assert loaded._hmac_verified is False

    def test_missing_sidecar_grace_mode(self, sample_lockfile, tmp_path):
        """Missing sidecar in non-strict mode → loads with warning."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path, sign=False)  # No sidecar
        loaded = load_lockfile(path, strict=False)
        assert "mcp-filesystem" in loaded.providers  # Still loads

    def test_missing_sidecar_strict_mode(self, sample_lockfile, tmp_path):
        """Missing sidecar in strict mode → fails closed."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path, sign=False)  # No sidecar
        loaded = load_lockfile(path, strict=True)
        assert len(loaded.providers) == 0  # Rejected

    def test_skip_verification(self, sample_lockfile, tmp_path):
        """verify_integrity=False skips HMAC check entirely."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)

        # Tamper
        content = path.read_text()
        path.write_text(content + "\n")

        # With verification off, tampered file loads fine
        loaded = load_lockfile(path, verify_integrity=False)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is None

    def test_custom_key_roundtrip(self, sample_lockfile, tmp_path):
        """Save and load with explicit custom key."""
        path = tmp_path / "lockfile.json"
        key = b"my-deployment-secret"
        save_lockfile(sample_lockfile, path, hmac_key=key)
        loaded = load_lockfile(path, hmac_key=key)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is True

    def test_wrong_key_fails(self, sample_lockfile, tmp_path):
        """Signed with one key, loaded with different key → fails closed."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path, hmac_key=b"key-1")
        loaded = load_lockfile(path, hmac_key=b"key-2")
        assert len(loaded.providers) == 0  # Key mismatch → fail-closed
        assert loaded._hmac_verified is False

    def test_migration_workflow(self, sample_lockfile, tmp_path):
        """Migration: unsigned lockfile → save signs it → subsequent loads verify."""
        path = tmp_path / "lockfile.json"

        # Step 1: Save without signing (legacy format)
        save_lockfile(sample_lockfile, path, sign=False)
        assert not _hmac_sidecar_path(path).exists()

        # Step 2: Load in grace mode (succeeds)
        loaded = load_lockfile(path, strict=False)
        assert "mcp-filesystem" in loaded.providers

        # Step 3: Re-save with signing (migration)
        save_lockfile(loaded, path, sign=True)
        assert _hmac_sidecar_path(path).exists()

        # Step 4: Subsequent loads verify HMAC
        loaded2 = load_lockfile(path)
        assert loaded2._hmac_verified is True
        assert "mcp-filesystem" in loaded2.providers

    def test_sidecar_deleted_after_signing(self, sample_lockfile, tmp_path):
        """If sidecar is deleted after signing, loads as unsigned."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)

        # Delete sidecar
        _hmac_sidecar_path(path).unlink()

        # Non-strict: loads with warning (unsigned)
        loaded = load_lockfile(path, strict=False)
        assert "mcp-filesystem" in loaded.providers

        # Strict: fails closed
        loaded2 = load_lockfile(path, strict=True)
        assert len(loaded2.providers) == 0


class TestStrictModeKeyEnforcement:
    """P0 fix: strict mode requires a production HMAC key (SENTINEL finding)."""

    def test_strict_with_fallback_key_hard_fails(self, sample_lockfile, tmp_path):
        """Strict mode + no env key (fallback) → hard fail, even if HMAC valid."""
        path = tmp_path / "lockfile.json"
        # Save with fallback key (creates valid HMAC)
        save_lockfile(sample_lockfile, path)
        # Load strict without env key → should fail closed
        loaded = load_lockfile(path, strict=True)
        assert len(loaded.providers) == 0
        assert loaded._hmac_verified is False

    def test_strict_with_production_key_succeeds(self, sample_lockfile, tmp_path, monkeypatch):
        """Strict mode + env key → loads normally."""
        monkeypatch.setenv("UNWIND_LOCKFILE_KEY", "aa" * 32)
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)
        loaded = load_lockfile(path, strict=True)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is True

    def test_strict_with_explicit_key_succeeds(self, sample_lockfile, tmp_path):
        """Strict mode + explicit hmac_key param → loads normally."""
        key = b"explicit-production-secret-key!!"
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path, hmac_key=key)
        loaded = load_lockfile(path, strict=True, hmac_key=key)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is True

    def test_nonstrict_with_fallback_key_still_works(self, sample_lockfile, tmp_path):
        """Non-strict mode + fallback key → loads normally (dev convenience)."""
        path = tmp_path / "lockfile.json"
        save_lockfile(sample_lockfile, path)
        loaded = load_lockfile(path, strict=False)
        assert "mcp-filesystem" in loaded.providers
        assert loaded._hmac_verified is True

    def test_strict_fallback_key_rejects_before_sidecar_check(self, sample_lockfile, tmp_path):
        """Strict + fallback key fails even before checking HMAC sidecar existence."""
        path = tmp_path / "lockfile.json"
        # Save without signing — no sidecar
        save_lockfile(sample_lockfile, path, sign=False)
        # Strict + no env key → fails on key check, not sidecar check
        loaded = load_lockfile(path, strict=True)
        assert len(loaded.providers) == 0
        assert loaded._hmac_verified is False

    def test_hmac_key_dataclass(self):
        """HMACKey dataclass stores provenance correctly."""
        k = HMACKey(key=b"test", is_production=True, source="env")
        assert k.key == b"test"
        assert k.is_production is True
        assert k.source == "env"
