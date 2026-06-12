"""Regression tests for the extended explanation templates (wording patch).

One test per template family: each previously-unmatched raw reason must now
resolve to a friendly headline (stage != "unknown"), and no raw ALL_CAPS
internal code may leak into the headline.
"""

import pytest

from unwind.dashboard.explanations import explain

EXTENDED_CASES = [
    # (raw reason, expected stage, expected severity)
    ("Exec tunnel blocked: Privilege escalation attempt: sudo", "Exec Tunnel", "critical"),
    ("Exec tunnel blocked: Dangerous git operation: git push --force", "Exec Tunnel", "warning"),
    ("Exec tunnel blocked: System cron modification: crontab", "Exec Tunnel", "critical"),
    ("Exec tunnel blocked: Service management command: systemctl", "Exec Tunnel", "warning"),
    ("Exec tunnel blocked: Script interpreter execution: python3", "Exec Tunnel", "warning"),
    ("Exec tunnel blocked: Tunnelled OpenClaw admin command: openclaw config", "Exec Tunnel", "warning"),
    # the tainted-session variant is correctly handled by the existing
    # Tainted Session template (it is an approval prompt, not a hard block)
    ("Exec tunnel: Tunnelled git command: git status (tainted session)", "Tainted Session", "warning"),
    ("GHOST_EGRESS_SECRET_REGISTRY: known secret detected ", "Ghost Egress", "critical"),
    ("GHOST_EGRESS_SECRET_REGISTRY: registry unavailable — ", "Ghost Egress", "warning"),
    ("GHOST_EGRESS_DLP: secret detected in URL [aws_key]", "Ghost Egress", "warning"),
    ("GHOST_MODE_NETWORK_BLOCKED (policy=isolate): example.com", "Ghost Mode", "info"),
    ("Signature verification FAILED for key 'k1' (R-SIG-001)", "Supply Chain", "critical"),
    ("HMAC verification FAILED — lockfile may be tampered (R-LOCK-003)", "Supply Chain", "critical"),
    ("Tool 'mystery_tool' not found in any known provider. Quarantined.", "Supply Chain", "critical"),
    ("Tool 'mystery_tool' not found in lockfile.", "Supply Chain", "critical"),
    ("Provider 'evil-corp' is on the blocklist.", "Supply Chain", "critical"),
    ("Tool 'send_email' is outside session scope.", "Session Scope", "warning"),
    ("RSS age 12.3s > 10s", "Freshness", "warning"),
    ("Taint age 99.1s > 60s", "Freshness", "warning"),
    ("registry_degraded", "Freshness", "warning"),
    ("Dual-control violation: approver cannot be requester", "Breakglass", "warning"),
    ("Breakglass is disabled by policy (BREAKGLASS_DISABLED)", "Breakglass", "info"),
    ("Key 'old-key' has been revoked", "CRAFT", "critical"),
    ("Key 'ghost-key' not found in key store", "CRAFT", "critical"),
    ("TTL elapsed (non-renewable)", "Approval", "info"),
]


@pytest.mark.parametrize("raw,stage,severity", EXTENDED_CASES)
def test_extended_reason_is_explained(raw, stage, severity):
    result = explain(raw)
    assert result["stage"] == stage, f"fell through or mis-routed: {raw!r}"
    assert result["severity"] == severity
    assert result["headline"]
    assert result["detail"]
    assert result["action"]


@pytest.mark.parametrize("raw,stage,severity", EXTENDED_CASES)
def test_no_raw_codes_in_headline(raw, stage, severity):
    headline = explain(raw)["headline"]
    for code in ("GHOST_EGRESS", "GHOST_MODE", "DLP", "HMAC", "RSS", "TTL", "_"):
        assert code not in headline, f"jargon {code!r} leaked into headline for {raw!r}"


def test_specific_exec_tunnel_beats_generic():
    """Specific exec-tunnel classes must match before the generic template."""
    result = explain("Exec tunnel blocked: Privilege escalation attempt: sudo")
    assert result["headline"] == "Your agent tried to gain elevated privileges"


def test_unknown_reason_still_falls_back():
    result = explain("Some brand new reason nobody has seen")
    assert result["stage"] == "unknown"
    assert result["severity"] == "info"
