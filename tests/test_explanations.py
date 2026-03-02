"""Dashboard explanation engine tests.

Proves that:
1. All 15 pipeline templates match their expected patterns, stages, and severities
2. Capture-group interpolation fills detail text correctly
3. Missing capture groups produce readable fallback text (no raw placeholders)
4. Unknown / unrecognised reasons hit the fallback path
5. All results carry the required dict keys
6. Matching is case-insensitive
"""

import pytest

from unwind.dashboard.explanations import explain


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

REQUIRED_KEYS = {"headline", "detail", "action", "severity", "stage"}


def _assert_keys(result: dict) -> None:
    """Every explain() result must carry all required keys."""
    assert set(result.keys()) == REQUIRED_KEYS, (
        f"Missing or extra keys: got {set(result.keys())}, expected {REQUIRED_KEYS}"
    )


# ------------------------------------------------------------------ #
# 1. Template matching  (15 templates)
# ------------------------------------------------------------------ #


class TestCanaryTemplate:
    """Template 1 -- CANARY TRIGGERED."""

    def test_canary_with_tool_name(self):
        result = explain("CANARY TRIGGERED on evil_tool")
        _assert_keys(result)
        assert result["stage"] == "Canary"
        assert result["severity"] == "critical"
        assert "evil_tool" in result["detail"]

    def test_canary_without_tool_name(self):
        """When the tool name is absent the {1} placeholder must not leak."""
        result = explain("CANARY TRIGGERED")
        _assert_keys(result)
        assert result["stage"] == "Canary"
        assert result["severity"] == "critical"
        assert "{1}" not in result["detail"]


class TestSessionKillTemplate:
    """Template 2 -- Session Kill."""

    def test_session_killed(self):
        result = explain("Session has been killed")
        _assert_keys(result)
        assert result["stage"] == "Session Kill"
        assert result["severity"] == "critical"


class TestSelfProtectionTemplate:
    """Template 3 -- System Core Protected."""

    def test_self_protection(self):
        result = explain("System Core Protected")
        _assert_keys(result)
        assert result["stage"] == "Self-Protection"
        assert result["severity"] == "critical"


class TestPathJailTemplate:
    """Template 4 -- Path Jail Violation."""

    def test_path_jail_with_path(self):
        result = explain("Path Jail Violation: /etc/passwd")
        _assert_keys(result)
        assert result["stage"] == "Path Jail"
        assert result["severity"] == "warning"
        assert "/etc/passwd" in result["detail"]


class TestSensitivePathTemplate:
    """Template 5 -- Sensitive Path Denied."""

    def test_sensitive_path(self):
        result = explain("Sensitive Path Denied: ~/.ssh/id_rsa")
        _assert_keys(result)
        assert result["stage"] == "Sensitive Path"
        assert result["severity"] == "warning"
        assert "~/.ssh/id_rsa" in result["detail"]


class TestSSRFShieldTemplate:
    """Template 6 -- SSRF Shield."""

    def test_ssrf_shield(self):
        result = explain("SSRF Shield: request to 169.254.169.254")
        _assert_keys(result)
        assert result["stage"] == "SSRF Shield"
        assert result["severity"] == "warning"


class TestDLPLiteTemplate:
    """Template 7 -- DLP-Lite Alert."""

    def test_dlp_lite(self):
        result = explain("DLP-Lite Alert: API key found")
        _assert_keys(result)
        assert result["stage"] == "DLP-Lite"
        assert result["severity"] == "warning"


class TestCircuitBreakerTemplate:
    """Template 8 -- Circuit Breaker."""

    def test_circuit_breaker(self):
        result = explain("Circuit Breaker: 15 writes in 2s")
        _assert_keys(result)
        assert result["stage"] == "Circuit Breaker"
        assert result["severity"] == "warning"


class TestTaintedSessionTemplate:
    """Template 9 -- Tainted session."""

    def test_tainted_session(self):
        result = explain("Tainted session: external content")
        _assert_keys(result)
        assert result["stage"] == "Tainted Session"
        assert result["severity"] == "warning"


class TestCadenceAwayTemplate:
    """Template 10 -- Cadence: Away."""

    def test_user_away(self):
        result = explain("user is AWAY")
        _assert_keys(result)
        assert result["stage"] == "Cadence: Away"
        assert result["severity"] == "warning"


class TestCadenceVarianceTemplate:
    """Template 11 -- Cadence: Variance."""

    def test_suspiciously_regular(self):
        result = explain("suspiciously regular timing")
        _assert_keys(result)
        assert result["stage"] == "Cadence: Variance"
        assert result["severity"] == "warning"


class TestCadenceReadingTemplate:
    """Template 12 -- Cadence: Reading."""

    def test_user_reading(self):
        result = explain("user is READING")
        _assert_keys(result)
        assert result["stage"] == "Cadence: Reading"
        assert result["severity"] == "info"


class TestSupplyChainTemplate:
    """Template 13 -- Supply Chain."""

    def test_supply_chain(self):
        result = explain("Supply-chain: untrusted provider")
        _assert_keys(result)
        assert result["stage"] == "Supply Chain"
        assert result["severity"] == "critical"


class TestCredentialExposureTemplate:
    """Template 14 -- Credential Exposure."""

    def test_credential_exposure(self):
        result = explain("Credential Exposure")
        _assert_keys(result)
        assert result["stage"] == "Credential Exposure"
        assert result["severity"] == "critical"


class TestExecTunnelTemplate:
    """Template 15 -- Exec Tunnel."""

    def test_exec_tunnel(self):
        result = explain("Exec tunnel detected")
        _assert_keys(result)
        assert result["stage"] == "Exec Tunnel"
        assert result["severity"] == "warning"


# ------------------------------------------------------------------ #
# 2. Fallback for unknown reasons
# ------------------------------------------------------------------ #


class TestFallback:
    """Unrecognised raw_reason strings must produce a safe fallback."""

    def test_unknown_reason(self):
        raw = "some completely unknown policy reason XYZ-999"
        result = explain(raw)
        _assert_keys(result)
        assert result["stage"] == "unknown"
        assert result["severity"] == "info"
        assert raw in result["detail"]

    def test_empty_string(self):
        result = explain("")
        _assert_keys(result)
        assert result["stage"] == "unknown"
        assert result["severity"] == "info"


# ------------------------------------------------------------------ #
# 3. All results carry required keys (parametrised sweep)
# ------------------------------------------------------------------ #


_ALL_RAW_REASONS = [
    "CANARY TRIGGERED on evil_tool",
    "CANARY TRIGGERED",
    "Session has been killed",
    "System Core Protected",
    "Path Jail Violation: /etc/passwd",
    "Sensitive Path Denied: ~/.ssh/id_rsa",
    "SSRF Shield: request to 169.254.169.254",
    "DLP-Lite Alert: API key found",
    "Circuit Breaker: 15 writes in 2s",
    "Tainted session: external content",
    "user is AWAY",
    "suspiciously regular timing",
    "user is READING",
    "Supply-chain: untrusted provider",
    "Credential Exposure",
    "Exec tunnel detected",
    "totally unknown reason",
]


@pytest.mark.parametrize("raw_reason", _ALL_RAW_REASONS)
def test_all_results_have_required_keys(raw_reason: str):
    result = explain(raw_reason)
    _assert_keys(result)


# ------------------------------------------------------------------ #
# 4. Case-insensitivity
# ------------------------------------------------------------------ #


class TestCaseInsensitivity:
    """Patterns compile with re.IGNORECASE -- verify mixed-case input matches."""

    def test_session_killed_mixed_case(self):
        result = explain("session HAS BEEN KILLED")
        _assert_keys(result)
        assert result["stage"] == "Session Kill"
        assert result["severity"] == "critical"

    def test_canary_lowercase(self):
        result = explain("canary triggered on sneaky_tool")
        assert result["stage"] == "Canary"
        assert "sneaky_tool" in result["detail"]

    def test_ssrf_uppercase(self):
        result = explain("SSRF SHIELD: request to 10.0.0.1")
        assert result["stage"] == "SSRF Shield"

    def test_exec_tunnel_mixed(self):
        result = explain("EXEC TUNNEL detected")
        assert result["stage"] == "Exec Tunnel"

    def test_user_away_lowercase(self):
        result = explain("user is away")
        assert result["stage"] == "Cadence: Away"
