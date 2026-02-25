#!/usr/bin/env python3
"""Breakglass Operational Drill — Punch List #4 (R-BREAK-001).

Runs a simulated dual-control breakglass lifecycle with full audit output.
Designed to be executed on the Pi as operational proof that breakglass
works end-to-end under realistic conditions.

Drill scenario:
    1. REQUEST:  ops-alice requests override of require_all_legs + digest_provider
    2. APPROVE:  ops-bob approves the token (dual-control)
    3. VERIFY:   confirm overrides are active, pipeline honours them
    4. QUERY:    inspect active overrides, remaining TTL, audit trail
    5. REVOKE:   ops-carol revokes early (incident resolved)
    6. VERIFY:   confirm overrides are gone, pipeline blocks again
    7. REPORT:   structured audit output for post-drill review

Exit codes:
    0 = all drill steps passed
    1 = drill step failed (assertion error)
    2 = infrastructure error

Usage:
    python tools/breakglass_drill.py [--verbose]
    python -m tools.breakglass_drill
"""

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
    OVERRIDABLE_FLAGS,
    NON_OVERRIDABLE_FLAGS,
    MAX_FLAGS_PER_TOKEN,
    MAX_TTL_SECONDS,
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


# ── Colours for terminal output ──
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"

    @staticmethod
    def ok(msg: str) -> str:
        return f"{C.GREEN}✓ PASS{C.RESET} {msg}"

    @staticmethod
    def fail(msg: str) -> str:
        return f"{C.RED}✗ FAIL{C.RESET} {msg}"

    @staticmethod
    def step(n: int, msg: str) -> str:
        return f"\n{C.BOLD}{C.CYAN}── Step {n}: {msg}{C.RESET}"

    @staticmethod
    def header(msg: str) -> str:
        return f"\n{C.BOLD}{'═' * 60}\n  {msg}\n{'═' * 60}{C.RESET}"


# ── Test infrastructure ──

def create_test_env():
    """Create a temporary UNWIND environment with signed lockfile."""
    tmp = tempfile.mkdtemp(prefix="bg-drill-")
    config = UnwindConfig(
        unwind_home=Path(tmp) / ".unwind",
        workspace_root=Path(tmp) / "workspace",
    )
    config.ensure_dirs()
    (Path(tmp) / "workspace").mkdir(exist_ok=True)

    # Generate keys and signed lockfile
    private_key, public_key = generate_ed25519_keypair()
    key_store = KeyStore()
    key_store.add_key(key_id="drill-key", public_key=public_key)
    sig_verifier = SignatureVerifier(key_store)

    trusted_at = datetime.now(timezone.utc).isoformat()
    provider_data = {
        "name": "drill-provider",
        "version": "1.0.0",
        "digest": "sha256:drill123",
        "tools": ["tool_alpha", "tool_beta"],
        "origin": "https://drill.example.com",
        "trusted_at": trusted_at,
    }
    signed_data = sign_provider_entry(provider_data, private_key, "drill-key")

    lockfile = Lockfile(
        providers={
            "drill-provider": ProviderEntry(
                provider_id="drill-provider",
                name="drill-provider",
                version="1.0.0",
                digest="sha256:drill123",
                tools=["tool_alpha", "tool_beta"],
                origin="https://drill.example.com",
                trusted_at=trusted_at,
                signature=signed_data["signature"],
            ),
        },
        trust_policy=TrustPolicy(require_signatures=True),
    )
    lockfile.build_index()
    lockfile._hmac_verified = True

    return config, lockfile, sig_verifier


class DrillResult:
    """Accumulates drill step results."""

    def __init__(self):
        self.steps: list[dict] = []
        self.passed = 0
        self.failed = 0
        self.start_time = time.time()

    def check(self, condition: bool, description: str) -> bool:
        """Record a check result."""
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

    def to_report(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "drill": "breakglass_operational_drill",
            "spec": "R-BREAK-001",
            "punch_list_item": "#4",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "total_checks": self.passed + self.failed,
            "passed": self.passed,
            "failed": self.failed,
            "verdict": "PASS" if self.failed == 0 else "FAIL",
            "steps": self.steps,
        }


# ── Drill steps ──

def run_drill(verbose: bool = False) -> DrillResult:
    """Execute the full breakglass operational drill."""
    result = DrillResult()

    print(C.header("BREAKGLASS OPERATIONAL DRILL (R-BREAK-001)"))
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"  Overridable flags: {sorted(OVERRIDABLE_FLAGS)}")
    print(f"  Non-overridable flags: {sorted(NON_OVERRIDABLE_FLAGS)}")
    print(f"  Max flags/token: {MAX_FLAGS_PER_TOKEN}")
    print(f"  Max TTL: {MAX_TTL_SECONDS}s ({MAX_TTL_SECONDS/3600:.0f}h)")

    # ── Environment setup ──
    config, lockfile, sig_verifier = create_test_env()
    supply_chain = SupplyChainVerifier(lockfile, sig_verifier)
    telemetry = EnforcementTelemetry()
    audit_events: list[dict] = []

    def audit_callback(event):
        d = event.to_dict()
        audit_events.append(d)
        if verbose:
            print(f"    {C.DIM}[AUDIT] {json.dumps(d, default=str)}{C.RESET}")

    bg = BreakglassService(
        enabled=True,
        callback=audit_callback,
        autonomous_profiles={"sentinel-cron"},
    )

    # ────────────────────────────────────────────
    # Step 1: Verify strict mode blocks WITHOUT breakglass
    # ────────────────────────────────────────────
    print(C.step(1, "Verify strict mode blocks without breakglass"))

    pipeline_strict = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=None,  # Missing → strict blocks
        strict=True,
        telemetry=telemetry,
    )
    session = Session(session_id="drill-001", config=config)
    check_result = pipeline_strict.check(session, "tool_alpha")
    result.check(
        check_result.action == CheckResult.BLOCK,
        "Strict mode blocks when digest_provider missing (no breakglass)"
    )

    # ────────────────────────────────────────────
    # Step 2: Autonomous profile default-deny
    # ────────────────────────────────────────────
    print(C.step(2, "Verify autonomous profile default-deny"))

    auto_token = bg.request(
        requester_id="sentinel-cron",
        flags=["digest_provider"],
        reason="Automated attempt",
    )
    result.check(
        auto_token is None,
        "Autonomous profile 'sentinel-cron' denied breakglass request"
    )

    # ────────────────────────────────────────────
    # Step 3: Non-overridable flag rejection
    # ────────────────────────────────────────────
    print(C.step(3, "Verify non-overridable flags rejected"))

    bad_token = bg.request(
        requester_id="ops-alice",
        flags=["supply_chain_verifier"],
        reason="Try to override core control",
    )
    result.check(
        bad_token is None,
        "Non-overridable flag 'supply_chain_verifier' correctly rejected"
    )

    # ────────────────────────────────────────────
    # Step 4: Flag cap enforcement (max 2)
    # ────────────────────────────────────────────
    print(C.step(4, "Verify per-token flag cap"))

    three_flags = bg.request(
        requester_id="ops-alice",
        flags=["require_all_legs", "digest_provider", "lockfile_hmac"],
        reason="Try to override all 3",
    )
    result.check(
        three_flags is None,
        f"3-flag request denied (cap is {MAX_FLAGS_PER_TOKEN})"
    )

    # ────────────────────────────────────────────
    # Step 5: REQUEST — ops-alice requests 2-flag override
    # ────────────────────────────────────────────
    print(C.step(5, "REQUEST: ops-alice requests breakglass"))

    token = bg.request(
        requester_id="ops-alice",
        flags=["require_all_legs", "digest_provider"],
        reason="Emergency provider migration — digest registry down",
        ttl_seconds=1800,
    )
    result.check(token is not None, "Breakglass request accepted")
    result.check(
        token.state == TokenState.PENDING,
        f"Token state is PENDING (got {token.state.value})"
    )
    result.check(
        len(token.flags) == 2,
        f"Token has 2 flags: {token.flags}"
    )
    result.check(
        token.ttl_seconds == 1800.0,
        f"TTL is 1800s (got {token.ttl_seconds})"
    )

    token_id = token.token_id
    print(f"    Token ID: {token_id}")

    # ────────────────────────────────────────────
    # Step 6: Dual-control — self-approve blocked
    # ────────────────────────────────────────────
    print(C.step(6, "Verify dual-control (self-approve blocked)"))

    # Request a separate token for self-approve test
    self_token = bg.request(
        requester_id="ops-dave",
        flags=["digest_provider"],
        reason="Self-approve test",
    )
    self_approve_ok = bg.approve(self_token.token_id, approver_id="ops-dave")
    result.check(
        not self_approve_ok,
        "Self-approval correctly rejected (requester == approver)"
    )
    result.check(
        self_token.state == TokenState.REJECTED,
        f"Self-approved token state is REJECTED (got {self_token.state.value})"
    )

    # ────────────────────────────────────────────
    # Step 7: APPROVE — ops-bob approves the real token
    # ────────────────────────────────────────────
    print(C.step(7, "APPROVE: ops-bob approves the token"))

    approved = bg.approve(token_id, approver_id="ops-bob")
    result.check(approved, "Token approved by ops-bob")

    token = bg.get_token(token_id)
    result.check(
        token.state == TokenState.ACTIVE,
        f"Token state is ACTIVE (got {token.state.value})"
    )
    result.check(
        token.approver_id == "ops-bob",
        f"Approver recorded as ops-bob (got {token.approver_id})"
    )
    result.check(
        token.remaining_seconds > 0,
        f"Token has remaining TTL ({token.remaining_seconds:.0f}s)"
    )

    # ────────────────────────────────────────────
    # Step 8: VERIFY — overrides are active
    # ────────────────────────────────────────────
    print(C.step(8, "VERIFY: overrides active in service"))

    result.check(
        bg.is_flag_overridden("require_all_legs"),
        "require_all_legs is overridden"
    )
    result.check(
        bg.is_flag_overridden("digest_provider"),
        "digest_provider is overridden"
    )
    result.check(
        not bg.is_flag_overridden("lockfile_hmac"),
        "lockfile_hmac is NOT overridden (not in token)"
    )
    result.check(
        not bg.is_flag_overridden("supply_chain_verifier"),
        "supply_chain_verifier is NOT overridden (non-overridable)"
    )
    result.check(
        bg.has_active_breakglass(),
        "Service reports active breakglass"
    )

    overrides = bg.get_active_overrides()
    result.check(
        set(overrides.keys()) == {"require_all_legs", "digest_provider"},
        f"Active overrides: {overrides}"
    )

    # ────────────────────────────────────────────
    # Step 9: PIPELINE — verify breakglass lets traffic through
    # ────────────────────────────────────────────
    print(C.step(9, "PIPELINE: breakglass overrides strict blocks"))

    pipeline_bg = EnforcementPipeline(
        config=config,
        supply_chain_verifier=supply_chain,
        digest_provider=None,  # Still missing — but overridden
        strict=True,
        breakglass=bg,
        telemetry=telemetry,
    )
    session2 = Session(session_id="drill-002", config=config)
    check_result2 = pipeline_bg.check(session2, "tool_alpha")
    result.check(
        check_result2.action == CheckResult.ALLOW,
        "Pipeline ALLOWS tool_alpha with breakglass active"
    )

    # Verify telemetry recorded the override
    override_events = telemetry.events_by_type(EventType.STRICT_MODE_BREAKGLASS_OVERRIDE)
    result.check(
        len(override_events) > 0,
        f"Telemetry recorded {len(override_events)} breakglass override event(s)"
    )

    # ────────────────────────────────────────────
    # Step 10: APPROVAL WINDOW compression
    # ────────────────────────────────────────────
    print(C.step(10, "Verify approval window compression during breakglass"))

    result.check(
        bg.get_window_ttl_multiplier() == 0.5,
        "Window TTL multiplier is 0.5 during breakglass"
    )
    result.check(
        bg.get_window_max_uses_divisor() == 2,
        "Window max_uses divisor is 2 during breakglass"
    )

    # ────────────────────────────────────────────
    # Step 11: REVOKE — ops-carol revokes the token
    # ────────────────────────────────────────────
    print(C.step(11, "REVOKE: ops-carol revokes the token"))

    revoked = bg.revoke(
        token_id,
        revoker_id="ops-carol",
        reason="Incident resolved — digest registry back online",
    )
    result.check(revoked, "Token successfully revoked by ops-carol")

    token = bg.get_token(token_id)
    result.check(
        token.state == TokenState.REVOKED,
        f"Token state is REVOKED (got {token.state.value})"
    )
    result.check(
        token.revoker_id == "ops-carol",
        f"Revoker recorded as ops-carol (got {token.revoker_id})"
    )

    # ────────────────────────────────────────────
    # Step 12: VERIFY — overrides are gone, pipeline blocks again
    # ────────────────────────────────────────────
    print(C.step(12, "VERIFY: overrides gone after revocation"))

    result.check(
        not bg.is_flag_overridden("require_all_legs"),
        "require_all_legs no longer overridden"
    )
    result.check(
        not bg.is_flag_overridden("digest_provider"),
        "digest_provider no longer overridden"
    )
    result.check(
        not bg.has_active_breakglass(),
        "No active breakglass tokens"
    )

    session3 = Session(session_id="drill-003", config=config)
    check_result3 = pipeline_bg.check(session3, "tool_alpha")
    result.check(
        check_result3.action == CheckResult.BLOCK,
        "Pipeline BLOCKS again after revocation"
    )

    # Approval windows back to normal
    result.check(
        bg.get_window_ttl_multiplier() == 1.0,
        "Window TTL multiplier back to 1.0"
    )

    # ────────────────────────────────────────────
    # Step 13: Re-revoke fails (already revoked)
    # ────────────────────────────────────────────
    print(C.step(13, "Verify re-revoke fails (idempotency)"))

    re_revoked = bg.revoke(token_id, revoker_id="ops-carol", reason="Double-tap")
    result.check(
        not re_revoked,
        "Re-revoke correctly rejected (token already revoked)"
    )

    # ────────────────────────────────────────────
    # Step 14: AUDIT TRAIL — verify completeness
    # ────────────────────────────────────────────
    print(C.step(14, "AUDIT: verify audit trail completeness"))

    # Filter audit events for the main token
    main_events = [e for e in audit_events if e.get("token_id") == token_id]
    main_types = [e["event_type"] for e in main_events]

    result.check(
        BreakglassEventType.REQUESTED in main_types,
        "Audit contains REQUESTED event"
    )
    result.check(
        BreakglassEventType.APPROVED in main_types,
        "Audit contains APPROVED event"
    )
    result.check(
        BreakglassEventType.ACTIVATED in main_types,
        "Audit contains ACTIVATED event"
    )
    result.check(
        BreakglassEventType.REVOKED in main_types,
        "Audit contains REVOKED event"
    )

    # Also verify denial events exist somewhere in the log
    all_types = [e["event_type"] for e in audit_events]
    result.check(
        BreakglassEventType.DENIED_DISABLED in all_types
        or BreakglassEventType.DENIED_NON_OVERRIDABLE in all_types,
        "Audit contains at least one DENIED event (non-overridable or cap)"
    )
    result.check(
        BreakglassEventType.DENIED_SELF_APPROVE in all_types,
        "Audit contains DENIED_SELF_APPROVE event"
    )

    # ────────────────────────────────────────────
    # Step 15: TELEMETRY — verify enforcement telemetry
    # ────────────────────────────────────────────
    print(C.step(15, "TELEMETRY: verify enforcement telemetry"))

    summary = telemetry.summary()
    result.check(
        summary["total_events"] > 0,
        f"Telemetry recorded {summary['total_events']} events"
    )

    # Trust gate events
    trusted_events = telemetry.events_by_type(EventType.TRUST_GATE_TRUSTED)
    result.check(
        len(trusted_events) > 0,
        f"Telemetry has {len(trusted_events)} TRUST_GATE_TRUSTED event(s)"
    )

    # Strict block events (from step 1)
    strict_events = telemetry.events_by_type(EventType.STRICT_MODE_BLOCK)
    result.check(
        len(strict_events) > 0,
        f"Telemetry has {len(strict_events)} STRICT_MODE_BLOCK event(s)"
    )

    # Breakglass override events (from step 9)
    bg_override = telemetry.events_by_type(EventType.STRICT_MODE_BREAKGLASS_OVERRIDE)
    result.check(
        len(bg_override) > 0,
        f"Telemetry has {len(bg_override)} BREAKGLASS_OVERRIDE event(s)"
    )

    # ────────────────────────────────────────────
    # Summary / service state
    # ────────────────────────────────────────────
    print(C.step(16, "SUMMARY: breakglass service state"))

    svc_summary = bg.summary()
    result.check(
        svc_summary["active_tokens"] == 0,
        "No active tokens remaining"
    )
    result.check(
        svc_summary["active_overrides"] == {},
        "No active overrides remaining"
    )

    print(f"\n    Service summary: {json.dumps(svc_summary, indent=2, default=str)}")

    # ── Final report ──
    report = result.to_report()
    report["audit_trail"] = audit_events
    report["telemetry_summary"] = summary
    report["service_summary"] = svc_summary

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

    # ── Print report ──
    print(C.header("DRILL REPORT"))
    print(f"  Checks: {result.passed + result.failed}")
    print(f"  Passed: {C.GREEN}{result.passed}{C.RESET}")
    print(f"  Failed: {C.RED}{result.failed}{C.RESET}")
    elapsed = report["elapsed_seconds"]
    print(f"  Elapsed: {elapsed:.2f}s")

    if result.failed == 0:
        print(f"\n  {C.GREEN}{C.BOLD}DRILL PASSED ✓{C.RESET}")
        print(f"  All breakglass lifecycle steps verified.")
    else:
        print(f"\n  {C.RED}{C.BOLD}DRILL FAILED ✗{C.RESET}")
        print(f"  {result.failed} check(s) failed — review above.")

    # Write JSON report
    report_path = Path(__file__).resolve().parent.parent / "drill_report_breakglass.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report: {report_path}")

    sys.exit(0 if result.failed == 0 else 1)


if __name__ == "__main__":
    main()
