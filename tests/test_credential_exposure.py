"""Tests for Credential Exposure Check — pre-execution parameter scanning.

Source: SENTINEL merged list § ADD NOW #2
Verifies detection of API keys, tokens, env var references, and
correct severity assignment (block for untrusted sinks, amber otherwise).
"""

import tempfile
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.enforcement.credential_exposure import (
    CredentialExposureCheck,
    CREDENTIAL_PATTERNS,
    SENSITIVE_ENV_VARS,
    UNTRUSTED_SINK_TOOLS,
)


def _make_config() -> UnwindConfig:
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


class TestCredentialPatterns(unittest.TestCase):
    """Test individual regex patterns match expected credential formats."""

    def test_aws_access_key(self):
        """AKIA-prefixed keys should match."""
        text = "key is AKIAIOSFODNN7EXAMPLE"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "AWS access key not detected")

    def test_github_pat(self):
        """github_pat_ tokens should match."""
        text = "token=github_pat_abcdefghijklmnopqrstuvwxyz"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "GitHub PAT not detected")

    def test_ghp_token(self):
        """ghp_ fine-grained tokens should match."""
        text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "GitHub ghp_ token not detected")

    def test_openai_key(self):
        """sk- prefixed keys should match."""
        text = "openai_key=sk-abcdefghijklmnopqrstuvwxyz"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "OpenAI key not detected")

    def test_anthropic_key(self):
        """sk-ant- prefixed keys should match."""
        text = "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "Anthropic key not detected")

    def test_jwt_token(self):
        """JWT tokens should match."""
        text = "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "JWT not detected")

    def test_pem_header(self):
        """PEM private key headers should match."""
        text = "-----BEGIN RSA PRIVATE KEY-----"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "PEM key not detected")

    def test_connection_string(self):
        """Database connection strings with credentials should match."""
        text = "postgres://admin:secret123@db.example.com:5432/mydb"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "Connection string not detected")

    def test_openclaw_gateway_token(self):
        """OpenClaw gateway tokens should match."""
        text = "token=gw_tok_abcdefghijklmnopqrstuvwxyz"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertTrue(len(findings) > 0, "OpenClaw gateway token not detected")

    def test_clean_text_no_match(self):
        """Normal text should not trigger false positives."""
        text = "Hello world, this is a normal message with no secrets."
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertEqual(len(findings), 0, f"False positive: {findings}")

    def test_short_api_key_no_match(self):
        """Short strings that look like keys but are too short should not match."""
        text = "api_key=abc"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_value(text)
        self.assertEqual(len(findings), 0, "Short key should not match")


class TestEnvVarDetection(unittest.TestCase):
    """Test environment variable reference detection."""

    def test_dollar_env_ref(self):
        """$AWS_SECRET_ACCESS_KEY should be detected."""
        text = "export $AWS_SECRET_ACCESS_KEY"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_env_references(text)
        self.assertTrue(len(findings) > 0, "Env var reference not detected")

    def test_curly_brace_env_ref(self):
        """${GITHUB_TOKEN} should be detected."""
        text = "use ${GITHUB_TOKEN} here"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_env_references(text)
        self.assertTrue(len(findings) > 0, "Curly brace env ref not detected")

    def test_non_sensitive_env_var(self):
        """Non-sensitive env vars should not trigger."""
        text = "PATH=$HOME/bin"
        check = CredentialExposureCheck(_make_config())
        findings = check._scan_env_references(text)
        self.assertEqual(len(findings), 0, "Non-sensitive var false positive")


class TestSeverityAssignment(unittest.TestCase):
    """Test that severity is correctly assigned based on tool type."""

    def test_untrusted_sink_blocks(self):
        """Credentials sent to untrusted sinks should be BLOCK."""
        check = CredentialExposureCheck(_make_config())
        result = check.check(
            "send_email",
            {"body": "my key is AKIAIOSFODNN7EXAMPLE ok"},
        )
        self.assertIsNotNone(result)
        severity, message = result
        self.assertEqual(severity, "block")
        self.assertIn("BLOCK", message)

    def test_local_tool_ambers(self):
        """Credentials in local tool params should be AMBER."""
        check = CredentialExposureCheck(_make_config())
        result = check.check(
            "fs_write",
            {"content": "key=AKIAIOSFODNN7EXAMPLE stored"},
        )
        self.assertIsNotNone(result)
        severity, message = result
        self.assertEqual(severity, "amber")
        self.assertIn("AMBER", message)

    def test_clean_params_returns_none(self):
        """Clean parameters should return None."""
        check = CredentialExposureCheck(_make_config())
        result = check.check("fs_write", {"content": "hello world"})
        self.assertIsNone(result)

    def test_empty_params_returns_none(self):
        """Empty or None params should return None."""
        check = CredentialExposureCheck(_make_config())
        self.assertIsNone(check.check("fs_write", {}))
        self.assertIsNone(check.check("fs_write", None))


class TestRecursiveScanning(unittest.TestCase):
    """Test nested parameter scanning."""

    def test_nested_dict(self):
        """Credentials in nested dicts should be found."""
        check = CredentialExposureCheck(_make_config())
        params = {
            "config": {
                "auth": {
                    "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
                }
            }
        }
        result = check.check("http_post", params)
        self.assertIsNotNone(result, "Nested credential not detected")

    def test_list_values(self):
        """Credentials in list values should be found."""
        check = CredentialExposureCheck(_make_config())
        params = {
            "headers": [
                "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz"
            ]
        }
        result = check.check("http_post", params)
        self.assertIsNotNone(result, "List credential not detected")

    def test_max_depth_limit(self):
        """Deeply nested params should stop scanning at max_depth."""
        check = CredentialExposureCheck(_make_config())
        # Build a 10-level deep nested dict
        inner = {"key": "AKIAIOSFODNN7EXAMPLE"}
        for _ in range(10):
            inner = {"nested": inner}
        # Default max_depth=5, so the key should NOT be found
        findings = check._scan_params_recursive(inner, depth=0, max_depth=5)
        self.assertEqual(len(findings), 0, "Should stop at max depth")


class TestAllUntrustedSinks(unittest.TestCase):
    """Verify all untrusted sink tools produce block severity."""

    def test_each_sink_tool_blocks(self):
        params = {"body": "sk-ant-abcdefghijklmnopqrstuvwxyz is secret"}
        check = CredentialExposureCheck(_make_config())
        for tool in UNTRUSTED_SINK_TOOLS:
            result = check.check(tool, params)
            self.assertIsNotNone(result, f"{tool} should detect credential")
            severity, _ = result
            self.assertEqual(
                severity, "block",
                f"{tool} should produce 'block' severity, got '{severity}'",
            )


if __name__ == "__main__":
    unittest.main()
