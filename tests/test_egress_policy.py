"""Tests for Egress Policy Pack — domain-level egress controls.

Source: SENTINEL merged list § ADD NOW #4
Verifies cloud metadata blocking, internal service blocking,
domain denylist, and optional allowlist enforcement.
"""

import unittest

from unwind.enforcement.egress_policy import (
    EgressPolicyCheck,
    CLOUD_METADATA_HOSTNAMES,
    DEFAULT_DOMAIN_DENYLIST,
)
from unwind.config import UnwindConfig

import tempfile
from pathlib import Path


def _make_config() -> UnwindConfig:
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


class TestCloudMetadataBlocking(unittest.TestCase):
    """Test that cloud metadata endpoints are blocked."""

    def setUp(self):
        self.check = EgressPolicyCheck(_make_config())

    def test_aws_metadata_ip(self):
        result = self.check.check("http://169.254.169.254/latest/meta-data/")
        self.assertIsNotNone(result)
        self.assertIn("CLOUD_METADATA", result)

    def test_gcp_metadata_hostname(self):
        result = self.check.check("http://metadata.google.internal/computeMetadata/v1/")
        self.assertIsNotNone(result)
        self.assertIn("CLOUD_METADATA", result)

    def test_azure_imds(self):
        """Azure uses the same 169.254.169.254 IP."""
        result = self.check.check("http://169.254.169.254/metadata/instance")
        self.assertIsNotNone(result)

    def test_alibaba_metadata(self):
        result = self.check.check("http://100.100.100.200/latest/meta-data/")
        self.assertIsNotNone(result)

    def test_aws_ecs_metadata(self):
        result = self.check.check("http://169.254.170.2/v2/metadata")
        self.assertIsNotNone(result)

    def test_kubernetes_service_account(self):
        result = self.check.check("https://kubernetes.default.svc/api/v1/namespaces")
        self.assertIsNotNone(result)
        self.assertIn("CLOUD_METADATA", result)

    def test_link_local_pattern(self):
        """Any 169.254.x.y should match the pattern."""
        result = self.check.check("http://169.254.42.42/some/path")
        self.assertIsNotNone(result)

    def test_metadata_prefix_pattern(self):
        """metadata.anything should match."""
        result = self.check.check("http://metadata.custom-cloud.io/v1/")
        self.assertIsNotNone(result)


class TestInternalServiceBlocking(unittest.TestCase):
    """Test that internal service endpoints are blocked."""

    def setUp(self):
        self.check = EgressPolicyCheck(_make_config())

    def test_consul(self):
        result = self.check.check("http://consul.service.dc1/v1/kv/")
        self.assertIsNotNone(result)
        self.assertIn("INTERNAL_SERVICE", result)

    def test_vault(self):
        result = self.check.check("https://vault.example.com/v1/secret/data/myapp")
        self.assertIsNotNone(result)
        self.assertIn("INTERNAL_SERVICE", result)

    def test_etcd(self):
        result = self.check.check("http://etcd.cluster.local:2379/v3/kv/range")
        self.assertIsNotNone(result)

    def test_kubernetes_cluster_local(self):
        result = self.check.check("https://myservice.default.svc.cluster.local/api")
        self.assertIsNotNone(result)

    def test_redis(self):
        result = self.check.check("http://redis.internal:6379/")
        self.assertIsNotNone(result)

    def test_prometheus(self):
        result = self.check.check("http://prometheus.monitoring:9090/api/v1/query")
        self.assertIsNotNone(result)

    def test_docker(self):
        result = self.check.check("http://docker.internal:2375/containers/json")
        self.assertIsNotNone(result)


class TestDomainDenylist(unittest.TestCase):
    """Test domain denylist blocking."""

    def setUp(self):
        self.check = EgressPolicyCheck(_make_config())

    def test_pastebin_blocked(self):
        result = self.check.check("https://pastebin.com/raw/abc123")
        self.assertIsNotNone(result)
        self.assertIn("DOMAIN_DENIED", result)

    def test_webhook_site_blocked(self):
        result = self.check.check("https://webhook.site/abc-def-123")
        self.assertIsNotNone(result)
        self.assertIn("DOMAIN_DENIED", result)

    def test_requestbin_blocked(self):
        result = self.check.check("https://requestbin.com/r/abc123")
        self.assertIsNotNone(result)

    def test_transfer_sh_blocked(self):
        result = self.check.check("https://transfer.sh/abc/file.txt")
        self.assertIsNotNone(result)

    def test_interact_sh_blocked(self):
        result = self.check.check("https://interact.sh/abc123")
        self.assertIsNotNone(result)

    def test_subdomain_of_denied(self):
        """Subdomains of denied domains should also be blocked."""
        result = self.check.check("https://app.pastebin.com/something")
        self.assertIsNotNone(result)
        self.assertIn("DOMAIN_DENIED", result)


class TestDomainAllowlist(unittest.TestCase):
    """Test optional domain allowlist enforcement."""

    def test_no_allowlist_allows_all(self):
        """Without allowlist, non-denied domains should pass."""
        check = EgressPolicyCheck(_make_config())
        result = check.check("https://api.github.com/repos")
        self.assertIsNone(result)

    def test_allowlist_permits_listed(self):
        """Domains on the allowlist should be allowed."""
        check = EgressPolicyCheck(
            _make_config(),
            domain_allowlist=frozenset({"github.com", "api.openai.com"}),
        )
        result = check.check("https://api.github.com/repos")
        # github.com is on allowlist, api.github.com matches *.github.com
        # Wait — the check does suffix matching: hostname.endswith("." + allowed)
        # "api.github.com".endswith(".github.com") → True ✓
        self.assertIsNone(result)

    def test_allowlist_blocks_unlisted(self):
        """Domains NOT on the allowlist should be blocked."""
        check = EgressPolicyCheck(
            _make_config(),
            domain_allowlist=frozenset({"github.com"}),
        )
        result = check.check("https://evil.example.com/steal")
        self.assertIsNotNone(result)
        self.assertIn("DOMAIN_NOT_ALLOWED", result)

    def test_allowlist_still_blocks_metadata(self):
        """Cloud metadata should be blocked even if somehow on allowlist."""
        check = EgressPolicyCheck(
            _make_config(),
            domain_allowlist=frozenset({"169.254.169.254"}),
        )
        # Metadata check runs BEFORE allowlist check
        result = check.check("http://169.254.169.254/latest/")
        self.assertIsNotNone(result)
        self.assertIn("CLOUD_METADATA", result)


class TestRuntimeDenylist(unittest.TestCase):
    """Test runtime denylist modification."""

    def test_add_denied_domain(self):
        check = EgressPolicyCheck(_make_config())
        # Initially allowed
        result = check.check("https://custom-exfil.io/data")
        self.assertIsNone(result)

        # Add to denylist
        check.add_denied_domain("custom-exfil.io")
        result = check.check("https://custom-exfil.io/data")
        self.assertIsNotNone(result)
        self.assertIn("DOMAIN_DENIED", result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        self.check = EgressPolicyCheck(_make_config())

    def test_no_hostname(self):
        """URLs without hostname should be blocked."""
        result = self.check.check("file:///etc/passwd")
        self.assertIsNotNone(result)
        self.assertIn("EGRESS_NO_HOST", result)

    def test_normal_url_allowed(self):
        """Normal external URLs should pass all checks."""
        result = self.check.check("https://www.google.com/search?q=hello")
        self.assertIsNone(result)

    def test_internal_domain_suffix(self):
        """*.internal domains should be caught by metadata pattern."""
        result = self.check.check("https://secret.internal/api/keys")
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
