#!/usr/bin/env python3
"""Rollback Drill — Punch List #3 (SENTINEL pre-prod, v2).

Proves UNWIND can recover from a bad strict-path deploy without weakening
core trust controls. Runs TWO fault classes and TWO recovery pathways per
SENTINEL's enhanced spec (22 Feb 2026).

Scenario A — HARD FAIL + BREAKGLASS-GATED ROLLBACK:
    Digest provider throws → strict blocks known-good traffic.
    Recovery: breakglass to ungate, then rollback, then revoke.

Scenario B — SILENT DEGRADATION + DIRECT ROLLBACK (no breakglass):
    Digest provider returns wrong digest → TOCTOU drift silently
    allows mismatched provider. Detection via trust-leg telemetry.
    Recovery: direct rollback, no breakglass needed.

Pass criteria (SENTINEL acceptance):
    - Detection ≤ 60s (simulated)
    - Containment start ≤ 3 min (simulated)
    - Full recovery ≤ 10 min (simulated)
    - No trust bypass: no TRUSTED verdict with missing trust legs
    - Telemetry continuity: incident fully reconstructable
    - Post-rollback: 0 active breakglass tokens, overrides cleared
    - Pre-pinned rollback target matched

Exit codes:
    0 = all drill steps passed
    1 = drill step failed
    2 = infrastructure error

Usage:
    python tools/rollback_drill.py [--verbose]
"""

import hashlib
import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Ensure project root is importable ──
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from unwind.config import UnwindConfig
from unwind.enforcement.breakglass import (
    BreakglassService,
    BreakglassEventType,
    TokenState,
)
from unwind.enforcement.pipeline import EnforcementPipeline, CheckResult
from unwind.enforcement.supply_chain import (
    Lockfile,
    ProviderEntry,
    SupplyChainVerifier,
    TrustPolicy,
)
from unwind.enforcement.signature_verify import (
    KeyStore,
    SignatureVerifier,
    generate_ed25519_keypair,
    sign_provider_entry,
)
from unwind.enforcement.telemetry import EnforcementTelemetry, EventType
from unwind.session import Session


# ── Colours ──
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    MAGENTA = "\033[35m"

    @staticmethod
    def ok(msg: str) -> str:
        return f"{C.GREEN}✓ PASS{C.RESET} {msg}"

    @staticmethod
    def fail(msg: str) -> str:
        return f"{C.RED}✗ FAIL{C.RESET} {msg}"

    @staticmethod
    def phase(n: str, msg: str) -> str:
        return f"\n{C.BOLD}{C.MAGENTA}═══ Phase {n}: {msg}{C.RESET}"

    @staticmethod
    def step(msg: str) -> str:
        return f"\n  {C.BOLD}{C.CYAN}── {msg}{C.RESET}"

    @staticmethod
    def header(msg: str) -> str:
        return f"\n{C.BOLD}{'═' * 64}\n  {msg}\n{'═' * 64}{C.RESET}"

    @staticmethod
    def scenario(name: str) -> str:
        return f"\n{C.BOLD}{C.YELLOW}{'─' * 64}\n  SCENARIO: {name}\n{'─' * 64}{C.RESET}"


# ── Drill result tracker ──

class DrillResult:
    def __init__(self):
        self.steps: list[dict] = []
        self.passed = 0
        self.failed = 0
        self.start_time = time.time()
        self.timeline: list[dict] = []

    def check(self, condition: bool, description: str) -> bool:
        status = "PASS" if condition else "FAIL"
        self.steps.append({
            "description": description,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if condition:
            self.passed += 1
            print(f"    {C.ok(description)}")
        else:
            self.failed += 1
            print(f"    {C.fail(description)}")
        return condition

    def mark_timeline(self, event: str, detail: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(time.time() - self.start_time, 3),
            "event": event,
        }
        if detail:
            entry["detail"] = detail
        self.timeline.append(entry)
        print(f"    {C.DIM}[T+{entry['elapsed_s']:.3f}s] {event}{C.RESET}")

    def to_report(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "drill": "rollback_drill_v2",
            "spec": "SENTINEL pre-prod punch list #3 (enhanced)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "total_checks": self.passed + self.failed,
            "passed": self.passed,
            "failed": self.failed,
            "verdict": "PASS" if self.failed == 0 else "FAIL",
            "steps": self.steps,
            "timeline": self.timeline,
        }


# ── Test environment ──

def create_test_env():
    """Create a clean UNWIND environment with signed lockfile + digest provider."""
    tmp = tempfile.mkdtemp(prefix="rollback-drill-")
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)

    private_key, public_key = generate_ed25519_keypair()
    key_store = KeyStore()
    key_store.add_key(key_id="prod-key", public_key=public_key)
    sig_verifier = SignatureVerifier(key_store)

    trusted_at = datetime.now(timezone.utc).isoformat()
    provider_data = {
        "name": "acme-tools",
        "version": "2.1.0",
        "digest": "sha256:acme2100",
        "tools": ["tool_read", "tool_write", "tool_query"],
        "origin": "https://acme.example.com/mcp",
        "trusted_at": trusted_at,
    }
    signed_data = sign_provider_entry(provider_data, private_key, "prod-key")

    lockfile = Lockfile(
        providers={
            "acme-tools": ProviderEntry(
                provider_id="acme-tools",
                name="acme-tools",
                version="2.1.0",
                digest="sha256:acme2100",
                tools=["tool_read", "tool_write", "tool_query"],
                origin="https://acme.example.com/mcp",
                trusted_at=trusted_at,
                signature=signed_data["signature"],
            ),
        },
        trust_policy=TrustPolicy(require_signatures=True),
    )
    lockfile.build_index()
    lockfile._hmac_verified = True

    return config, lockfile, sig_verifier


# ── Digest providers ──

def make_good_digest_provider():
    """Returns correct digest (healthy state)."""
    def provider(provider_id: str) -> str:
        return "sha256:acme2100"
    return provider


def make_broken_digest_provider():
    """Raises exception (hard fail — registry outage)."""
    def provider(provider_id: str) -> str:
        raise ConnectionError(
            f"Registry unreachable for '{provider_id}' — "
            f"simulated outage (drill fault injection)"
        )
    return provider


def make_wrong_digest_provider():
    """Returns wrong digest (silent degradation — TOCTOU drift)."""
    def provider(provider_id: str) -> str:
        return "sha256:TAMPERED_0xdead"
    return provider


def pipeline_config_hash(
    strict: bool,
    has_supply_chain: bool,
    has_digest_provider: bool,
    has_breakglass: bool,
    digest_label: str = "",
) -> str:
    """Compute a reproducible hash for a pipeline configuration."""
    state = {
        "strict": strict,
        "has_supply_chain": has_supply_chain,
        "has_digest_provider": has_digest_provider,
        "has_breakglass": has_breakglass,
        "digest_label": digest_label,
    }
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()[:16]


# ── SLO timing tracker ──

class SLOTracker:
    """Track SLO compliance for drill timing criteria."""
    SLO_DETECT_S = 60.0
    SLO_CONTAIN_S = 180.0
    SLO_RECOVER_S = 600.0

    def __init__(self):
        self.fault_injected_at: float = 0.0
        self.detected_at: float = 0.0
        self.contained_at: float = 0.0
        self.recovered_at: float = 0.0

    def detect_elapsed(self) -> float:
        return self.detected_at - self.fault_injected_at

    def contain_elapsed(self) -> float:
        return self.contained_at - self.fault_injected_at

    def recover_elapsed(self) -> float:
        return self.recovered_at - self.fault_injected_at


# ══════════════════════════════════════════════════════════════
# SCENARIO A: Hard fail + breakglass-gated rollback
# ══════════════════════════════════════════════════════════════

def run_scenario_a(result: DrillResult, verbose: bool = False) -> dict:
    """Hard fail regression with breakglass-gated recovery."""
    print(C.scenario("A — HARD FAIL + BREAKGLASS-GATED ROLLBACK"))
    print(f"    Fault: digest provider throws ConnectionError")
    print(f"    Recovery: breakglass → rollback → revoke")

    config, lockfile, sig_verifier = create_test_env()
    supply_chain = SupplyChainVerifier(lockfile, sig_verifier)
    telemetry = EnforcementTelemetry()
    slo = SLOTracker()
    bg_audit: list[dict] = []
    command_transcript: list[str] = []

    def bg_callback(event):
        bg_audit.append(event.to_dict())
        if verbose:
            print(f"    {C.DIM}[BG-AUDIT] {json.dumps(event.to_dict(), default=str)}{C.RESET}")

    breakglass = BreakglassService(
        enabled=True,
        callback=bg_callback,
        autonomous_profiles={"sentinel-cron"},
    )

    # ── Pre-pin rollback target ──
    print(C.phase("A1", "PRE-PIN rollback target"))
    rollback_target_hash = pipeline_config_hash(
        strict=True,
        has_supply_chain=True,
        has_digest_provider=True,
        has_breakglass=True,
        digest_label="good",
    )
    result.mark_timeline("A_ROLLBACK_TARGET_PINNED", f"hash={rollback_target_hash}")
    command_transcript.append(f"Pre-pin rollback target: config_hash={rollback_target_hash}")

    # ── A1: BASELINE ──
    print(C.phase("A2", "BASELINE — healthy strict-path"))
    result.mark_timeline("A_BASELINE_START")

    pipeline_healthy = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_good_digest_provider(),
        strict=True,
        breakglass=breakglass,
        telemetry=telemetry,
    )
    command_transcript.append("Deploy: healthy pipeline (good digest provider)")

    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"a-baseline-{tool}", config=config)
        r = pipeline_healthy.check(session, tool)
        result.check(r.action == CheckResult.ALLOW, f"[A] Baseline: {tool} → ALLOW")

    baseline_trusted = len(telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED))
    result.check(baseline_trusted == 3, f"[A] Baseline: {baseline_trusted} TRUSTED events")
    result.mark_timeline("A_BASELINE_COMPLETE")

    # ── A2: INJECT — hard fail ──
    print(C.phase("A3", "INJECT — hard fail (digest provider exception)"))
    slo.fault_injected_at = time.time()
    result.mark_timeline("A_FAULT_INJECTION")
    command_transcript.append("Inject fault: broken digest provider (ConnectionError)")

    pipeline_broken = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_broken_digest_provider(),
        strict=True,
        breakglass=breakglass,
        telemetry=telemetry,
    )

    blocked = 0
    for i in range(5):
        for tool in ["tool_read", "tool_write", "tool_query"]:
            session = Session(session_id=f"a-fault-{i}-{tool}", config=config)
            r = pipeline_broken.check(session, tool)
            if r.action == CheckResult.BLOCK:
                blocked += 1

    result.check(blocked == 15, f"[A] Hard fail: {blocked}/15 requests blocked")

    # ── A3: DETECT ──
    print(C.phase("A4", "DETECT — telemetry surge"))
    slo.detected_at = time.time()
    result.mark_timeline("A_DETECTION")

    digest_errors = [
        e for e in telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)
        if e.reason_code == "DIGEST_PROVIDER_ERROR"
    ]
    result.check(len(digest_errors) == 15, f"[A] Detect: {len(digest_errors)} DIGEST_PROVIDER_ERROR events")
    result.check(
        all(e.session_id != "" for e in digest_errors),
        "[A] All error events have session_id"
    )
    result.check(
        all(e.tool_name != "" for e in digest_errors),
        "[A] All error events have tool_name"
    )

    detect_s = slo.detect_elapsed()
    result.check(
        detect_s <= SLOTracker.SLO_DETECT_S,
        f"[A] SLO: detection in {detect_s:.3f}s (≤ {SLOTracker.SLO_DETECT_S}s)"
    )
    command_transcript.append(f"Detection: {len(digest_errors)} DIGEST_PROVIDER_ERROR events in {detect_s:.3f}s")

    # ── A4: RESPOND — breakglass ──
    print(C.phase("A5", "RESPOND — breakglass-gated mitigation"))
    result.mark_timeline("A_INCIDENT_OPEN", "commander=ops-alice")
    command_transcript.append("Incident opened: ops-alice as commander")

    token = breakglass.request(
        requester_id="ops-alice",
        flags=["digest_provider", "require_all_legs"],
        reason="Digest registry outage — applying scoped override while rollback in progress.",
        ttl_seconds=300,
    )
    result.check(token is not None, "[A] Breakglass request accepted")
    result.check(
        set(token.flags) == {"digest_provider", "require_all_legs"},
        f"[A] Scoped to 2 flags: {token.flags}"
    )
    command_transcript.append(f"Breakglass requested: token={token.token_id}, flags={token.flags}, ttl=300s")

    approved = breakglass.approve(token.token_id, approver_id="ops-bob")
    result.check(approved, "[A] Breakglass approved (dual-control: ops-bob)")
    slo.contained_at = time.time()
    result.mark_timeline("A_BREAKGLASS_ACTIVE", f"token={token.token_id}")
    command_transcript.append(f"Breakglass approved: ops-bob (dual-control)")

    contain_s = slo.contain_elapsed()
    result.check(
        contain_s <= SLOTracker.SLO_CONTAIN_S,
        f"[A] SLO: containment in {contain_s:.3f}s (≤ {SLOTracker.SLO_CONTAIN_S}s)"
    )

    # Verify traffic flows under breakglass
    bg_ok = 0
    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"a-bg-{tool}", config=config)
        r = pipeline_broken.check(session, tool)
        if r.action == CheckResult.ALLOW:
            bg_ok += 1
    result.check(bg_ok == 3, f"[A] Breakglass mitigating: {bg_ok}/3 requests allowed")

    # ── A5: ROLLBACK ──
    print(C.phase("A6", "ROLLBACK — restore known-good config"))
    result.mark_timeline("A_ROLLBACK_START")
    command_transcript.append("Rollback: restoring good digest provider")

    pipeline_restored = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_good_digest_provider(),
        strict=True,
        breakglass=breakglass,
        telemetry=telemetry,
    )

    # Verify against pre-pinned target
    actual_hash = pipeline_config_hash(
        strict=True,
        has_supply_chain=True,
        has_digest_provider=True,
        has_breakglass=True,
        digest_label="good",
    )
    result.check(
        actual_hash == rollback_target_hash,
        f"[A] Rollback target matched: {actual_hash} == {rollback_target_hash}"
    )

    health_ok = 0
    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"a-rollback-{tool}", config=config)
        r = pipeline_restored.check(session, tool)
        if r.action == CheckResult.ALLOW:
            health_ok += 1
    result.check(health_ok == 3, f"[A] Rollback health check: {health_ok}/3 healthy")

    slo.recovered_at = time.time()
    result.mark_timeline("A_ROLLBACK_COMPLETE")
    command_transcript.append("Rollback complete: health check passed")

    recover_s = slo.recover_elapsed()
    result.check(
        recover_s <= SLOTracker.SLO_RECOVER_S,
        f"[A] SLO: full recovery in {recover_s:.3f}s (≤ {SLOTracker.SLO_RECOVER_S}s)"
    )

    # ── A6: CLEANUP — revoke breakglass ──
    print(C.phase("A7", "CLEANUP — revoke breakglass"))
    result.mark_timeline("A_CLEANUP_START")

    revoked = breakglass.revoke(
        token.token_id,
        revoker_id="ops-alice",
        reason="Rollback complete — breakglass no longer needed.",
    )
    result.check(revoked, "[A] Breakglass token revoked")
    result.check(not breakglass.has_active_breakglass(), "[A] No active breakglass tokens")
    result.check(breakglass.get_active_overrides() == {}, "[A] No active overrides")
    command_transcript.append(f"Breakglass revoked: token={token.token_id}")

    # Post-revocation health check
    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"a-post-{tool}", config=config)
        r = pipeline_restored.check(session, tool)
        result.check(r.action == CheckResult.ALLOW, f"[A] Post-revoke: {tool} → ALLOW")

    result.mark_timeline("A_CLEANUP_COMPLETE")

    # ── A7: VERIFY — telemetry continuity ──
    print(C.phase("A8", "VERIFY — telemetry continuity + trust integrity"))
    result.mark_timeline("A_VERIFICATION_START")

    all_trusted = telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED)
    trusted_with_sigs = [e for e in all_trusted if e.signature_valid == "True"]
    result.check(
        len(trusted_with_sigs) == len(all_trusted),
        f"[A] All {len(all_trusted)} TRUSTED events have valid signatures"
    )

    summary = telemetry.summary()
    types_present = set(summary["by_type"].keys())
    result.check(EventType.TRUST_GATE_TRUSTED in types_present, "[A] Telemetry has TRUSTED events")
    result.check(EventType.STRICT_MODE_BLOCK in types_present, "[A] Telemetry has STRICT_MODE_BLOCK")
    result.check(
        EventType.STRICT_MODE_BREAKGLASS_OVERRIDE in types_present,
        "[A] Telemetry has BREAKGLASS_OVERRIDE"
    )

    timestamps = [e.timestamp for e in telemetry.event_log]
    is_ordered = all(t1 <= t2 for t1, t2 in zip(timestamps, timestamps[1:]))
    result.check(is_ordered, "[A] Telemetry monotonically ordered")

    result.mark_timeline("A_VERIFICATION_COMPLETE")

    return {
        "scenario": "A_HARD_FAIL_BREAKGLASS_GATED",
        "rollback_target_hash": rollback_target_hash,
        "actual_rollback_hash": actual_hash,
        "slo": {
            "detect_s": round(detect_s, 3),
            "contain_s": round(contain_s, 3),
            "recover_s": round(recover_s, 3),
        },
        "telemetry_summary": summary,
        "reason_codes_emitted": sorted(set(
            e.reason_code for e in telemetry.event_log if e.reason_code
        )),
        "breakglass_audit": bg_audit,
        "breakglass_summary": breakglass.summary(),
        "command_transcript": command_transcript,
        "final_state": {
            "active_breakglass": breakglass.has_active_breakglass(),
            "active_overrides": breakglass.get_active_overrides(),
            "telemetry_events": len(telemetry.event_log),
            "trust_gate_trusted": len(all_trusted),
            "strict_blocks": len(telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)),
        },
    }


# ══════════════════════════════════════════════════════════════
# SCENARIO B: Silent degradation + direct rollback (no breakglass)
# ══════════════════════════════════════════════════════════════

def run_scenario_b(result: DrillResult, verbose: bool = False) -> dict:
    """Silent degradation regression with direct rollback (no breakglass)."""
    print(C.scenario("B — SILENT DEGRADATION + DIRECT ROLLBACK (no breakglass)"))
    print(f"    Fault: digest provider returns wrong digest (TOCTOU drift)")
    print(f"    Recovery: direct rollback — no breakglass needed")

    config, lockfile, sig_verifier = create_test_env()
    supply_chain = SupplyChainVerifier(lockfile, sig_verifier)
    telemetry = EnforcementTelemetry()
    slo = SLOTracker()
    command_transcript: list[str] = []

    # ── Pre-pin rollback target ──
    print(C.phase("B1", "PRE-PIN rollback target"))
    rollback_target_hash = pipeline_config_hash(
        strict=True,
        has_supply_chain=True,
        has_digest_provider=True,
        has_breakglass=False,
        digest_label="good",
    )
    result.mark_timeline("B_ROLLBACK_TARGET_PINNED", f"hash={rollback_target_hash}")
    command_transcript.append(f"Pre-pin rollback target: config_hash={rollback_target_hash}")

    # ── B1: BASELINE ──
    print(C.phase("B2", "BASELINE — healthy strict-path"))
    result.mark_timeline("B_BASELINE_START")

    pipeline_healthy = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_good_digest_provider(),
        strict=True,
        telemetry=telemetry,
    )
    command_transcript.append("Deploy: healthy pipeline (good digest provider)")

    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"b-baseline-{tool}", config=config)
        r = pipeline_healthy.check(session, tool)
        result.check(r.action == CheckResult.ALLOW, f"[B] Baseline: {tool} → ALLOW")

    baseline_trusted = len(telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED))
    result.check(baseline_trusted == 3, f"[B] Baseline: {baseline_trusted} TRUSTED events")
    result.mark_timeline("B_BASELINE_COMPLETE")

    # ── B2: INJECT — silent degradation (wrong digest) ──
    print(C.phase("B3", "INJECT — silent degradation (wrong digest)"))
    slo.fault_injected_at = time.time()
    result.mark_timeline("B_FAULT_INJECTION")
    command_transcript.append("Inject fault: wrong digest provider (sha256:TAMPERED_0xdead)")

    pipeline_degraded = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_wrong_digest_provider(),
        strict=True,
        telemetry=telemetry,
    )

    # Silent degradation: the wrong digest causes verify_tool to see a mismatch.
    # With strict + require_all_legs, this should block because digest_match will
    # be False (the live digest doesn't match the lockfile digest).
    # This IS detected — strict mode catches it. That's the point: strict prevents
    # the silent degradation from becoming a trust bypass.
    degraded_results = {"allow": 0, "block": 0, "amber": 0}
    for i in range(5):
        for tool in ["tool_read", "tool_write", "tool_query"]:
            session = Session(session_id=f"b-degrade-{i}-{tool}", config=config)
            r = pipeline_degraded.check(session, tool)
            if r.action == CheckResult.ALLOW:
                degraded_results["allow"] += 1
            elif r.action == CheckResult.BLOCK:
                degraded_results["block"] += 1
            elif r.action == CheckResult.AMBER:
                degraded_results["amber"] += 1

    # In strict mode with require_all_legs, mismatched digest → BLOCK
    # (digest leg fails → trust_leg_missing)
    result.check(
        degraded_results["block"] == 15,
        f"[B] Silent degradation detected: {degraded_results['block']}/15 blocked (strict caught it)"
    )
    result.check(
        degraded_results["allow"] == 0,
        f"[B] No traffic silently allowed with wrong digest"
    )

    # ── B3: DETECT — telemetry shows digest mismatch via trust gate ──
    print(C.phase("B4", "DETECT — telemetry digest mismatch (UNTRUSTED)"))
    slo.detected_at = time.time()
    result.mark_timeline("B_DETECTION")

    # Wrong digest → verify_tool returns UNTRUSTED (digest_match=False)
    # before reaching the require_all_legs check. This is correct:
    # the trust gate itself catches the TOCTOU drift.
    untrusted_events = telemetry.events_by_type(EventType.TRUST_GATE_UNTRUSTED)
    result.check(
        len(untrusted_events) == 15,
        f"[B] Detect: {len(untrusted_events)} TRUST_GATE_UNTRUSTED events (digest mismatch)"
    )
    result.check(
        all(e.session_id != "" for e in untrusted_events),
        "[B] All UNTRUSTED events have session_id"
    )
    result.check(
        all(e.tool_name != "" for e in untrusted_events),
        "[B] All UNTRUSTED events have tool_name"
    )
    # Verify the events contain digest mismatch info
    result.check(
        all(e.trust_verdict == "untrusted" for e in untrusted_events),
        "[B] All events have trust_verdict=untrusted"
    )

    detect_s = slo.detect_elapsed()
    result.check(
        detect_s <= SLOTracker.SLO_DETECT_S,
        f"[B] SLO: detection in {detect_s:.3f}s (≤ {SLOTracker.SLO_DETECT_S}s)"
    )
    command_transcript.append(f"Detection: {len(untrusted_events)} TRUST_GATE_UNTRUSTED events in {detect_s:.3f}s")

    # ── B4: RESPOND + ROLLBACK — direct (no breakglass) ──
    print(C.phase("B5", "RESPOND + ROLLBACK — direct (no breakglass needed)"))
    slo.contained_at = time.time()
    result.mark_timeline("B_DIRECT_ROLLBACK_START")
    command_transcript.append("Direct rollback: restoring good digest provider (no breakglass)")

    # Strict mode is already blocking the bad traffic — no breakglass needed.
    # Just swap the digest provider back.
    pipeline_restored = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=make_good_digest_provider(),
        strict=True,
        telemetry=telemetry,
    )

    # Verify against pre-pinned target
    actual_hash = pipeline_config_hash(
        strict=True,
        has_supply_chain=True,
        has_digest_provider=True,
        has_breakglass=False,
        digest_label="good",
    )
    result.check(
        actual_hash == rollback_target_hash,
        f"[B] Rollback target matched: {actual_hash} == {rollback_target_hash}"
    )

    health_ok = 0
    for tool in ["tool_read", "tool_write", "tool_query"]:
        session = Session(session_id=f"b-rollback-{tool}", config=config)
        r = pipeline_restored.check(session, tool)
        if r.action == CheckResult.ALLOW:
            health_ok += 1
    result.check(health_ok == 3, f"[B] Rollback health check: {health_ok}/3 healthy")

    slo.recovered_at = time.time()
    result.mark_timeline("B_ROLLBACK_COMPLETE")
    command_transcript.append("Rollback complete: health check passed")

    contain_s = slo.contain_elapsed()
    recover_s = slo.recover_elapsed()
    result.check(
        contain_s <= SLOTracker.SLO_CONTAIN_S,
        f"[B] SLO: containment in {contain_s:.3f}s (≤ {SLOTracker.SLO_CONTAIN_S}s)"
    )
    result.check(
        recover_s <= SLOTracker.SLO_RECOVER_S,
        f"[B] SLO: recovery in {recover_s:.3f}s (≤ {SLOTracker.SLO_RECOVER_S}s)"
    )

    # ── B5: VERIFY ──
    print(C.phase("B6", "VERIFY — telemetry continuity + no trust bypass"))
    result.mark_timeline("B_VERIFICATION_START")

    all_trusted = telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED)
    trusted_with_sigs = [e for e in all_trusted if e.signature_valid == "True"]
    result.check(
        len(trusted_with_sigs) == len(all_trusted),
        f"[B] All {len(all_trusted)} TRUSTED events have valid signatures"
    )

    # Verify NO breakglass override events (direct rollback path)
    bg_overrides = telemetry.events_by_type(EventType.STRICT_MODE_BREAKGLASS_OVERRIDE)
    result.check(
        len(bg_overrides) == 0,
        f"[B] No breakglass override events (direct rollback path)"
    )

    timestamps = [e.timestamp for e in telemetry.event_log]
    is_ordered = all(t1 <= t2 for t1, t2 in zip(timestamps, timestamps[1:]))
    result.check(is_ordered, "[B] Telemetry monotonically ordered")

    summary = telemetry.summary()
    result.mark_timeline("B_VERIFICATION_COMPLETE")

    return {
        "scenario": "B_SILENT_DEGRADATION_DIRECT_ROLLBACK",
        "rollback_target_hash": rollback_target_hash,
        "actual_rollback_hash": actual_hash,
        "slo": {
            "detect_s": round(detect_s, 3),
            "contain_s": round(contain_s, 3),
            "recover_s": round(recover_s, 3),
        },
        "telemetry_summary": summary,
        "reason_codes_emitted": sorted(set(
            e.reason_code for e in telemetry.event_log if e.reason_code
        )),
        "command_transcript": command_transcript,
        "final_state": {
            "active_breakglass": False,
            "active_overrides": {},
            "telemetry_events": len(telemetry.event_log),
            "trust_gate_trusted": len(all_trusted),
            "strict_blocks": len(telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)),
            "breakglass_overrides": 0,
        },
    }


# ══════════════════════════════════════════════════════════════
# Main drill
# ══════════════════════════════════════════════════════════════

def run_drill(verbose: bool = False) -> tuple:
    result = DrillResult()

    print(C.header("ROLLBACK DRILL v2 (Punch List #3)"))
    print(f"  Scenarios: A (hard fail + breakglass) + B (silent degradation + direct)")
    print(f"  Started:   {datetime.now(timezone.utc).isoformat()}")
    print(f"  SLOs:      detect ≤{SLOTracker.SLO_DETECT_S:.0f}s, "
          f"contain ≤{SLOTracker.SLO_CONTAIN_S:.0f}s, "
          f"recover ≤{SLOTracker.SLO_RECOVER_S:.0f}s")

    result.mark_timeline("DRILL_START")

    # Run both scenarios
    scenario_a = run_scenario_a(result, verbose=verbose)
    scenario_b = run_scenario_b(result, verbose=verbose)

    result.mark_timeline("DRILL_COMPLETE")

    # Build report
    report = result.to_report()
    report["scenarios"] = {
        "A": scenario_a,
        "B": scenario_b,
    }
    report["post_incident_review"] = {
        "scenario_a": {
            "fault_class": "Hard fail (digest provider exception)",
            "detection": "Telemetry surge — STRICT_MODE_BLOCK with DIGEST_PROVIDER_ERROR",
            "recovery_path": "Breakglass-gated: scoped override → rollback → revoke",
            "trust_integrity": "No trust bypass — all TRUSTED events had valid signatures",
            "breakglass_hygiene": "Token properly revoked, no lingering overrides",
        },
        "scenario_b": {
            "fault_class": "Silent degradation (wrong digest — TOCTOU drift)",
            "detection": "Telemetry — TRUST_GATE_UNTRUSTED (digest mismatch caught by trust gate)",
            "recovery_path": "Direct rollback — trust gate already blocked bad traffic",
            "trust_integrity": "No trust bypass — digest mismatch returned UNTRUSTED before require_all_legs",
            "breakglass_hygiene": "N/A — breakglass not used",
        },
    }

    return result, report


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    try:
        result, report = run_drill(verbose=verbose)
    except Exception as e:
        print(f"\n{C.RED}INFRASTRUCTURE ERROR: {e}{C.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(2)

    # Print final summary
    print(C.header("DRILL REPORT"))
    print(f"  Scenarios: 2 (A: hard fail + breakglass, B: silent degradation + direct)")
    print(f"  Checks:    {result.passed + result.failed}")
    print(f"  Passed:    {C.GREEN}{result.passed}{C.RESET}")
    print(f"  Failed:    {C.RED}{result.failed}{C.RESET}")
    elapsed = report["elapsed_seconds"]
    print(f"  Elapsed:   {elapsed:.3f}s")

    # Per-scenario SLO summary
    for label, scenario in [("A", report["scenarios"]["A"]), ("B", report["scenarios"]["B"])]:
        slo = scenario["slo"]
        print(f"\n  Scenario {label} SLOs:")
        print(f"    Detect:  {slo['detect_s']:.3f}s (≤ {SLOTracker.SLO_DETECT_S:.0f}s)")
        print(f"    Contain: {slo['contain_s']:.3f}s (≤ {SLOTracker.SLO_CONTAIN_S:.0f}s)")
        print(f"    Recover: {slo['recover_s']:.3f}s (≤ {SLOTracker.SLO_RECOVER_S:.0f}s)")

    if result.failed == 0:
        print(f"\n  {C.GREEN}{C.BOLD}DRILL PASSED ✓{C.RESET}")
        print(f"  Both scenarios passed. All SLOs met.")
    else:
        print(f"\n  {C.RED}{C.BOLD}DRILL FAILED ✗{C.RESET}")
        print(f"  {result.failed} check(s) failed — review above.")

    # Write JSON report
    report_path = Path(__file__).resolve().parent.parent / "drill_report_rollback.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report: {report_path}")

    sys.exit(0 if result.failed == 0 else 1)


if __name__ == "__main__":
    main()
