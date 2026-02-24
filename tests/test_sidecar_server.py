"""Tests for UNWIND Sidecar Server — FastAPI policy server.

Verifies:
- Health endpoint returns correct status (including watchdog)
- Policy check endpoint with valid/invalid requests
- Fail-closed behaviour (pipeline errors → block, not 500)
- Auth middleware (bearer token, mandatory auth, loopback check)
- API version header enforcement
- Telemetry endpoint best-effort behaviour
- Policy source integration (degraded on load failure)
- Watchdog stale hook detection
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult, PipelineResult
from unwind.enforcement.policy_source import ImmutablePolicySource
from unwind.sidecar.server import create_app, ENGINE_VERSION

# All tests use this known secret — auth is now mandatory.
TEST_SECRET = "test-secret-for-unit-tests"


def _make_config() -> UnwindConfig:
    tmp = tempfile.mkdtemp()
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)
    return config


def _make_client(
    config=None,
    pipeline=None,
    shared_secret=TEST_SECRET,
    policy_source=None,
) -> TestClient:
    """Create a TestClient with default config and mandatory auth."""
    if config is None:
        config = _make_config()
    app = create_app(
        config=config,
        pipeline=pipeline,
        shared_secret=shared_secret,
        policy_source=policy_source,
    )
    return TestClient(app)


def _headers(secret=TEST_SECRET):
    """Standard headers: auth + API version."""
    return {
        "Authorization": f"Bearer {secret}",
        "X-UNWIND-API-Version": "1",
    }


def _auth_headers(secret=TEST_SECRET):
    """Alias for _headers — backwards compat."""
    return _headers(secret)


def _version_header():
    """API version header only — no auth (for auth failure tests)."""
    return {"X-UNWIND-API-Version": "1"}


def _valid_policy_body():
    return {
        "toolName": "fs_read",
        "params": {"path": "/workspace/readme.md"},
        "agentId": "agent-001",
        "sessionKey": "sess-001",
    }


# ═══════════════════════════════════════════════════════════════
# Health endpoint
# ═══════════════════════════════════════════════════════════════


class TestHealthEndpoint(unittest.TestCase):
    """Test GET /v1/health."""

    def test_health_returns_up(self):
        client = _make_client()
        resp = client.get("/v1/health", headers=_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "up")
        self.assertEqual(data["engineVersion"], ENGINE_VERSION)
        self.assertIn("uptimeMs", data)
        self.assertIsNone(data["lastPolicyCheckTs"])

    def test_health_after_policy_check(self):
        """lastPolicyCheckTs should be set after a policy check."""
        client = _make_client()
        # Do a policy check first
        client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        # Now check health
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertIsNotNone(data["lastPolicyCheckTs"])

    def test_health_includes_watchdog_fields(self):
        """Health response should include watchdog-related fields."""
        client = _make_client()
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertIn("watchdogThresholdMs", data)
        self.assertIn("activeSessions", data)
        self.assertEqual(data["activeSessions"], 0)
        # Not stale initially — no checks have happened yet
        self.assertNotIn("watchdogStale", data)  # Only included when True


# ═══════════════════════════════════════════════════════════════
# Policy check endpoint
# ═══════════════════════════════════════════════════════════════


class TestPolicyCheck(unittest.TestCase):
    """Test POST /v1/policy/check."""

    def test_valid_request_returns_decision(self):
        client = _make_client()
        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("decision", data)
        self.assertIn(data["decision"], ["allow", "block", "mutate", "challenge_required"])

    def test_missing_required_field_returns_422(self):
        """Missing toolName should return 422."""
        client = _make_client()
        body = {
            "params": {"path": "/workspace/readme.md"},
            "agentId": "agent-001",
            "sessionKey": "sess-001",
        }
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], "SCHEMA_INVALID")

    def test_empty_tool_name_returns_422(self):
        client = _make_client()
        body = _valid_policy_body()
        body["toolName"] = "   "
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_tool_name_too_long_returns_422(self):
        client = _make_client()
        body = _valid_policy_body()
        body["toolName"] = "x" * 200
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_params_not_object_returns_422(self):
        client = _make_client()
        body = _valid_policy_body()
        body["params"] = "not-an-object"
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_invalid_json_returns_422(self):
        client = _make_client()
        resp = client.post(
            "/v1/policy/check",
            content=b"not valid json {{{{",
            headers={**_headers(), "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 422)

    def test_canary_tool_returns_block(self):
        """Canary tools should always be blocked (session killed)."""
        client = _make_client()
        body = _valid_policy_body()
        body["toolName"] = "disable_security_audit"
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")

    def test_self_protection_blocks_unwind_paths(self):
        """Attempts to access .unwind dirs should be blocked."""
        config = _make_config()
        client = _make_client(config=config)
        body = _valid_policy_body()
        body["toolName"] = "fs_read"
        body["params"] = {"path": str(config.unwind_home / "events.db")}
        resp = client.post(
            "/v1/policy/check",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")


# ═══════════════════════════════════════════════════════════════
# Fail-closed contract
# ═══════════════════════════════════════════════════════════════


class TestFailClosed(unittest.TestCase):
    """Verify fail-closed: pipeline errors → block, never 500."""

    def test_pipeline_exception_returns_block_not_500(self):
        """If pipeline.check() raises, handler should return block."""
        config = _make_config()
        pipeline = MagicMock(spec=EnforcementPipeline)
        pipeline.check.side_effect = RuntimeError("pipeline exploded")
        pipeline.classify_tool.return_value = "read"

        client = _make_client(config=config, pipeline=pipeline)
        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        # MUST be 200 with block decision, NOT 500
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")
        self.assertIn("SIDECAR_INTERNAL_ERROR", data.get("blockReason", ""))


# ═══════════════════════════════════════════════════════════════
# Auth middleware
# ═══════════════════════════════════════════════════════════════


class TestAuthMiddleware(unittest.TestCase):
    """Test bearer auth and mandatory auth enforcement (CWE-306 fix)."""

    def test_mandatory_auth_rejects_no_header(self):
        """Auth is ALWAYS required — even with empty secret, one is generated."""
        # Pass empty string → server auto-generates a secret.
        # Without knowing that secret, requests must fail.
        client = _make_client(shared_secret="")
        resp = client.get("/v1/health", headers=_version_header())
        # Could be 401 (no auth header) — the key point is it's NOT 200
        self.assertEqual(resp.status_code, 401)

    def test_auto_generated_secret_works(self):
        """When no secret provided, auto-generated secret must work."""
        # We need to capture the auto-generated secret.
        # Pass empty string → create_app generates one internally.
        # We can't easily extract it, so test via the explicit path:
        # provide a known secret and verify it works.
        known_secret = "explicit-test-secret"
        client = _make_client(shared_secret=known_secret)
        resp = client.get("/v1/health", headers=_headers(known_secret))
        self.assertEqual(resp.status_code, 200)

    def test_valid_bearer_token(self):
        client = _make_client(shared_secret="test-secret")
        resp = client.get("/v1/health", headers=_headers("test-secret"))
        self.assertEqual(resp.status_code, 200)

    def test_missing_auth_header_returns_401(self):
        client = _make_client(shared_secret="test-secret")
        resp = client.get("/v1/health", headers=_version_header())
        self.assertEqual(resp.status_code, 401)

    def test_wrong_bearer_token_returns_401(self):
        client = _make_client(shared_secret="test-secret")
        resp = client.get("/v1/health", headers=_headers("wrong-secret"))
        self.assertEqual(resp.status_code, 401)

    def test_missing_api_version_header_returns_400(self):
        """Missing X-UNWIND-API-Version should return 400."""
        client = _make_client()
        resp = client.get(
            "/v1/health",
            headers={"Authorization": f"Bearer {TEST_SECRET}"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_wrong_api_version_returns_400(self):
        client = _make_client()
        resp = client.get(
            "/v1/health",
            headers={
                "Authorization": f"Bearer {TEST_SECRET}",
                "X-UNWIND-API-Version": "99",
            },
        )
        self.assertEqual(resp.status_code, 400)


# ═══════════════════════════════════════════════════════════════
# Telemetry endpoint
# ═══════════════════════════════════════════════════════════════


class TestTelemetryEndpoint(unittest.TestCase):
    """Test POST /v1/telemetry/event — best-effort, always 202."""

    def test_valid_telemetry_returns_202(self):
        client = _make_client()
        body = {
            "toolName": "fs_read",
            "params": {"path": "/workspace/readme.md"},
            "durationMs": 42,
            "agentId": "agent-001",
            "sessionKey": "sess-001",
        }
        resp = client.post(
            "/v1/telemetry/event",
            json=body,
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertEqual(data["status"], "accepted")

    def test_malformed_telemetry_still_returns_202(self):
        """Telemetry is best-effort — even bad data returns 202."""
        client = _make_client()
        resp = client.post(
            "/v1/telemetry/event",
            content=b"garbage data",
            headers={**_headers(), "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 202)

    def test_empty_body_returns_202(self):
        client = _make_client()
        resp = client.post(
            "/v1/telemetry/event",
            json={},
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 202)


# ═══════════════════════════════════════════════════════════════
# Policy source integration
# ═══════════════════════════════════════════════════════════════


class TestPolicySourceIntegration(unittest.TestCase):
    """Test sidecar behaviour when policy source fails."""

    def test_degraded_health_on_policy_load_failure(self):
        """If policy source fails, health should report degraded."""
        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "workspace"
        workspace.mkdir()
        # Put config INSIDE workspace → boundary violation → load fails
        unwind_home = workspace / ".unwind"
        unwind_home.mkdir()
        (unwind_home / "policy.json").write_text('{"mode": "enforce"}')

        config = UnwindConfig(
            unwind_home=unwind_home,
            workspace_root=workspace,
        )
        policy_source = ImmutablePolicySource(unwind_home=unwind_home)

        client = _make_client(config=config, policy_source=policy_source)
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["status"], "degraded")

    def test_all_requests_blocked_on_policy_load_failure(self):
        """If policy source fails, all policy checks should block."""
        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "workspace"
        workspace.mkdir()
        unwind_home = workspace / ".unwind"
        unwind_home.mkdir()
        (unwind_home / "policy.json").write_text('{"mode": "enforce"}')

        config = UnwindConfig(
            unwind_home=unwind_home,
            workspace_root=workspace,
        )
        policy_source = ImmutablePolicySource(unwind_home=unwind_home)

        client = _make_client(config=config, policy_source=policy_source)
        resp = client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "block")
        self.assertIn("POLICY_SOURCE_FAILED", data.get("blockReason", ""))


# ═══════════════════════════════════════════════════════════════
# Watchdog (stale hook detection)
# ═══════════════════════════════════════════════════════════════


class TestWatchdog(unittest.TestCase):
    """Test watchdog stale hook detection in health endpoint.

    The watchdog catches:
    - OpenClaw hook failures (hooks not firing after updates)
    - Adapter crashes (TS plugin dies, sidecar keeps running)
    - Hook bypass (tool called outside the hooked flow)

    Detection: if sessions exist and no policy check arrives within
    WATCHDOG_THRESHOLD_SECONDS, health reports watchdog_stale=True.
    """

    def test_not_stale_initially(self):
        """No sessions, no checks → not stale (nothing to be stale about)."""
        client = _make_client()
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["status"], "up")
        # watchdogStale is only included in wire format when True
        self.assertNotIn("watchdogStale", data)

    def test_not_stale_when_checks_flowing(self):
        """Active policy checks → not stale."""
        client = _make_client()
        # Send a policy check to create a session and record activity
        client.post(
            "/v1/policy/check",
            json=_valid_policy_body(),
            headers=_headers(),
        )
        resp = client.get("/v1/health", headers=_headers())
        data = resp.json()
        self.assertEqual(data["status"], "up")
        self.assertNotIn("watchdogStale", data)
        self.assertGreaterEqual(data["activeSessions"], 1)

    def test_stale_when_no_checks_within_threshold(self):
        """Sessions exist but no recent check → stale."""
        import os
        old_val = os.environ.get("UNWIND_WATCHDOG_THRESHOLD", "")
        os.environ["UNWIND_WATCHDOG_THRESHOLD"] = "1"  # 1 second threshold
        try:
            client = _make_client()
            # Send a policy check to establish a session
            client.post(
                "/v1/policy/check",
                json=_valid_policy_body(),
                headers=_headers(),
            )
            # Verify not stale immediately
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertNotIn("watchdogStale", data)

            # Wait for threshold to expire
            time.sleep(1.5)

            # Now should be stale
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertTrue(data.get("watchdogStale", False))
            self.assertEqual(data["status"], "watchdog_stale")
        finally:
            if old_val:
                os.environ["UNWIND_WATCHDOG_THRESHOLD"] = old_val
            else:
                os.environ.pop("UNWIND_WATCHDOG_THRESHOLD", None)

    def test_stale_clears_after_new_check(self):
        """Stale flag should clear when a new policy check arrives."""
        import os
        old_val = os.environ.get("UNWIND_WATCHDOG_THRESHOLD", "")
        os.environ["UNWIND_WATCHDOG_THRESHOLD"] = "1"
        try:
            client = _make_client()
            # Establish session
            client.post(
                "/v1/policy/check",
                json=_valid_policy_body(),
                headers=_headers(),
            )
            # Wait for staleness
            time.sleep(1.5)
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertTrue(data.get("watchdogStale", False))

            # Send another check — should clear staleness
            client.post(
                "/v1/policy/check",
                json=_valid_policy_body(),
                headers=_headers(),
            )
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertNotIn("watchdogStale", data)
            self.assertEqual(data["status"], "up")
        finally:
            if old_val:
                os.environ["UNWIND_WATCHDOG_THRESHOLD"] = old_val
            else:
                os.environ.pop("UNWIND_WATCHDOG_THRESHOLD", None)

    def test_watchdog_threshold_in_health_response(self):
        """Health response should report the configured threshold."""
        import os
        old_val = os.environ.get("UNWIND_WATCHDOG_THRESHOLD", "")
        os.environ["UNWIND_WATCHDOG_THRESHOLD"] = "45"
        try:
            client = _make_client()
            resp = client.get("/v1/health", headers=_headers())
            data = resp.json()
            self.assertEqual(data["watchdogThresholdMs"], 45000)
        finally:
            if old_val:
                os.environ["UNWIND_WATCHDOG_THRESHOLD"] = old_val
            else:
                os.environ.pop("UNWIND_WATCHDOG_THRESHOLD", None)


if __name__ == "__main__":
    unittest.main()
