"""Enforcement Pipeline — chains all checks in order.

This is the security spine of UNWIND. Every tool call passes through
this pipeline before reaching upstream. All checks are deterministic,
require no LLM calls, and run in-process.

Pipeline order:
0a. Session kill check
0b. Supply-chain verification (pre-RBAC trust gate)
1.  Canary check (honeypot tripwire — instant kill)
2.  Self-protection (block .unwind paths)
2b. Exec tunnel detection
2c. Credential exposure (pre-execution param scan)
3.  Path jail (workspace canonicalization)
3b. Ghost Egress Guard (block network reads in Ghost Mode — BEFORE DNS)
4.  SSRF shield (DNS resolve + IP block)
4b. Egress policy (domain-level: metadata, internal, denylist)
5.  DLP-lite (regex + entropy on egress)
6.  Circuit breaker (rate limiting)
7.  Taint check (sensor/actuator gating)
7a. Cadence Bridge (temporal anomaly — P3-11)
8.  Session scope (allowlist check)
9.  Ghost Mode gate (intercept + shadow VFS)
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from ..config import UnwindConfig
from ..session import Session, TrustState
from .self_protection import SelfProtectionCheck
from .path_jail import PathJailCheck
from .ssrf_shield import SSRFShieldCheck
from .dlp_lite import DLPLiteCheck
from .canary import CanaryCheck
from .credential_exposure import CredentialExposureCheck
from .egress_policy import EgressPolicyCheck
from .ghost_egress import GhostEgressGuard, GhostSessionAllowlist
from .secret_registry import SecretRegistry
from .exec_tunnel import ExecTunnelCheck, EXEC_TOOL_NAMES
from .approval_windows import (
    ApprovalWindowConfig,
    ApprovalWindowService,
    RiskBand,
    ThreatMode,
)
from .response_validator import ResponseValidator, SessionBudget
from .rubber_stamp import RubberStampConfig, RubberStampState, RSSLevel
from .breakglass import BreakglassService
from .supply_chain import SupplyChainVerifier, TrustVerdict
from .cadence_bridge import CadenceBridge, CadenceBridgeConfig
from .taint_decay import TaintLevel
from .telemetry import EnforcementTelemetry, EventType


class CheckResult(Enum):
    ALLOW = "allow"           # Proceed to upstream
    BLOCK = "block"           # Hard deny — return error to agent
    AMBER = "amber"           # Pause for user confirmation
    GHOST = "ghost"           # Ghost Mode — log + return fake success
    KILL = "kill"             # Session killed — canary or critical violation


@dataclass
class ApprovalGate:
    """Result of processing an approval through the rubber-stamp detector."""
    allowed: bool                            # Whether the approval is accepted
    rss_score: int = 0                       # Current rubber-stamp score
    rss_level: RSSLevel = RSSLevel.NONE      # Current RSS severity level
    hold_seconds: float = 0.0                # Mandatory wait before approval enabled
    reason: str = ""                         # Why approval was gated/blocked
    lockout_remaining: float = 0.0           # Seconds until lockout expires


@dataclass
class PipelineResult:
    """Result of running the enforcement pipeline."""
    action: CheckResult
    canonical_target: Optional[str] = None  # Resolved path for logging
    tool_class: str = "unknown"             # sensor, actuator, control_plane, unknown_actuator, canary
    block_reason: Optional[str] = None      # Why it was blocked/flagged
    amber_reason: Optional[str] = None      # Why it needs confirmation


class EnforcementPipeline:
    """Run all enforcement checks against a tool call."""

    # Type alias for digest provider callback
    # Takes provider_id → returns "sha256:<hex>" or None
    DigestProvider = Callable[[str], Optional[str]]

    def __init__(
        self,
        config: UnwindConfig,
        supply_chain_verifier: Optional[SupplyChainVerifier] = None,
        rubber_stamp_config: Optional[RubberStampConfig] = None,
        approval_window_config: Optional[ApprovalWindowConfig] = None,
        digest_provider: Optional["EnforcementPipeline.DigestProvider"] = None,
        strict: bool = False,
        breakglass: Optional[BreakglassService] = None,
        telemetry: Optional[EnforcementTelemetry] = None,
        cadence_bridge: Optional[CadenceBridge] = None,
        secret_registry: Optional[SecretRegistry] = None,
    ):
        self.config = config
        self.strict = strict
        self.breakglass = breakglass
        self.telemetry = telemetry or EnforcementTelemetry()
        self.self_protection = SelfProtectionCheck(config)
        self.path_jail = PathJailCheck(config)
        self.ssrf_shield = SSRFShieldCheck(config)
        self.dlp_lite = DLPLiteCheck(config)
        self.canary = CanaryCheck(config)
        self.exec_tunnel = ExecTunnelCheck(config)
        self.credential_exposure = CredentialExposureCheck(config)
        self.egress_policy = EgressPolicyCheck(config)
        self.ghost_egress = GhostEgressGuard(config, secret_registry=secret_registry)
        # Back-compat alias used by tests/injectors.
        self.ghost_egress_guard = self.ghost_egress
        self._ghost_session_allowlists: dict[str, GhostSessionAllowlist] = {}
        self.supply_chain = supply_chain_verifier  # Optional — stage 0b
        # Digest-at-execution provider: computes live digest of a provider
        # for TOCTOU-safe integrity checking (R-LOCK-002)
        self.digest_provider = digest_provider
        self.rss_config = rubber_stamp_config or RubberStampConfig()
        # Per-operator RSS state (keyed by operator_id)
        self._rss_states: dict[str, RubberStampState] = {}
        # Response principal validator (transport layer, post-response)
        # Wire telemetry into response validator for budget events
        self.response_validator = ResponseValidator(telemetry=self.telemetry)
        # Approval windows (time-limited pre-authorisation)
        self.approval_windows = ApprovalWindowService(
            config=approval_window_config or ApprovalWindowConfig()
        )
        # Cadence Bridge (P3-11): temporal anomaly detection
        if cadence_bridge is not None:
            self.cadence_bridge: Optional[CadenceBridge] = cadence_bridge
        elif config.cadence_bridge_enabled:
            self.cadence_bridge = CadenceBridge(
                state_env_path=config.cadence_state_env_path,
            )
        else:
            self.cadence_bridge = None

    def _is_strict(
        self,
        flag_name: str,
        session_id: str = "",
        tool_name: str = "",
    ) -> bool:
        """Check if a strict-mode flag is effectively enforced.

        Returns True if strict mode is ON *and* the flag is NOT overridden
        by an active breakglass token.

        Non-overridable flags (like supply_chain_verifier) always return
        self.strict — breakglass cannot override them.

        Emits telemetry when a breakglass override is used.
        """
        if not self.strict:
            return False
        if self.breakglass is not None and self.breakglass.is_flag_overridden(flag_name):
            # Emit telemetry: breakglass override used
            overrides = self.breakglass.get_active_overrides()
            token_id = overrides.get(flag_name, "")
            self.telemetry.emit_breakglass_override(
                strict_flag=flag_name,
                breakglass_token_id=token_id,
                session_id=session_id,
                tool_name=tool_name,
            )
            return False
        return True

    def classify_tool(self, tool_name: str, session_id: Optional[str] = None) -> str:
        """Classify a tool into canary/sensor/control-plane/actuator buckets."""
        if self.canary.is_canary(tool_name, session_id=session_id):
            return "canary"
        if tool_name in self.config.sensor_tools:
            return "sensor"
        if tool_name in self.config.control_plane_tools:
            return "control_plane"
        if tool_name in self.config.state_modifying_tools:
            return "actuator"
        return "unknown_actuator"

    def check(
        self,
        session: Session,
        tool_name: str,
        target: Optional[str] = None,
        parameters: Optional[dict] = None,
        payload: Optional[str] = None,
    ) -> PipelineResult:
        """Run the full enforcement pipeline.

        Args:
            session: Current session state
            tool_name: MCP tool being called
            target: File path or URL target
            parameters: Tool call parameters
            payload: Outbound payload for egress tools (DLP scan)

        Returns:
            PipelineResult with action to take
        """
        tool_class = self.classify_tool(tool_name, session_id=session.session_id)
        canonical_target = target

        # --- 0a. Session kill check ---
        if session.killed:
            return PipelineResult(
                action=CheckResult.KILL,
                tool_class=tool_class,
                block_reason="Session has been killed — no further actions permitted",
            )

        # --- 0b. Supply-chain verification (pre-RBAC trust gate) ---
        if self.supply_chain is None and self.strict:
            # R-STRICT-001: supply_chain_verifier is NON-OVERRIDABLE
            # (breakglass cannot bypass this — always use self.strict)
            reason = (
                "Strict mode: no supply-chain verifier configured — "
                "cannot verify provider trust (SUPPLY_CHAIN_VERIFIER_MISSING)"
            )
            self.telemetry.emit_strict_block(
                strict_flag="supply_chain_verifier",
                reason_code="SUPPLY_CHAIN_VERIFIER_MISSING",
                block_reason=reason,
                session_id=session.session_id,
                tool_name=tool_name,
            )
            return PipelineResult(
                action=CheckResult.BLOCK,
                tool_class=tool_class,
                block_reason=reason,
            )
        if self.supply_chain is not None:
            # Digest-at-execution: compute live digest if provider available (R-LOCK-002)
            current_digest = None
            if self.digest_provider is not None:
                provider_id = self.supply_chain.lockfile.provider_for_tool(tool_name)
                if provider_id is not None:
                    try:
                        current_digest = self.digest_provider(provider_id)
                    except Exception as exc:
                        if self._is_strict("digest_provider", session.session_id, tool_name):
                            # R-STRICT-001: digest computation failure → fail-closed
                            reason = (
                                f"Strict mode: digest-provider error for "
                                f"'{provider_id}': {exc}"
                            )
                            self.telemetry.emit_strict_block(
                                strict_flag="digest_provider",
                                reason_code="DIGEST_PROVIDER_ERROR",
                                block_reason=reason,
                                session_id=session.session_id,
                                tool_name=tool_name,
                            )
                            return PipelineResult(
                                action=CheckResult.BLOCK,
                                tool_class=tool_class,
                                block_reason=reason,
                            )
                        # Permissive: treat as no digest
                        # (verify_tool will still check lockfile-level digest)
                    else:
                        if current_digest is None and self._is_strict("digest_provider", session.session_id, tool_name):
                            # R-STRICT-001: provider returned None → fail-closed
                            reason = (
                                f"Strict mode: digest-provider returned None for "
                                f"'{provider_id}' — cannot verify runtime integrity"
                            )
                            self.telemetry.emit_strict_block(
                                strict_flag="digest_provider",
                                reason_code="DIGEST_PROVIDER_NULL",
                                block_reason=reason,
                                session_id=session.session_id,
                                tool_name=tool_name,
                            )
                            return PipelineResult(
                                action=CheckResult.BLOCK,
                                tool_class=tool_class,
                                block_reason=reason,
                            )
            elif self._is_strict("digest_provider", session.session_id, tool_name):
                # R-STRICT-001: no digest_provider configured → fail-closed
                provider_id = self.supply_chain.lockfile.provider_for_tool(tool_name)
                if provider_id is not None:
                    reason = (
                        "Strict mode: no digest-provider configured — "
                        "cannot verify runtime integrity (R-STRICT-001)"
                    )
                    self.telemetry.emit_strict_block(
                        strict_flag="digest_provider",
                        reason_code="DIGEST_PROVIDER_MISSING",
                        block_reason=reason,
                        session_id=session.session_id,
                        tool_name=tool_name,
                    )
                    return PipelineResult(
                        action=CheckResult.BLOCK,
                        tool_class=tool_class,
                        block_reason=reason,
                    )
            sc_result = self.supply_chain.verify_tool(tool_name, current_digest=current_digest)

            # R-STRICT-001: require_all_legs — all three trust legs must
            # be verified for TRUSTED verdict in strict mode
            # (overridable via breakglass)
            if (
                self._is_strict("require_all_legs", session.session_id, tool_name)
                and sc_result.verdict == TrustVerdict.TRUSTED
            ):
                missing_legs = []
                # Leg 1: HMAC lockfile integrity
                hmac_verified = getattr(self.supply_chain.lockfile, "_hmac_verified", None)
                if hmac_verified is not True:
                    missing_legs.append("HMAC lockfile integrity")
                # Leg 2: Ed25519 signature
                if sc_result.signature_valid is not True:
                    missing_legs.append("Ed25519 signature")
                # Leg 3: Digest-at-execution
                if sc_result.digest_match is not True:
                    missing_legs.append("digest-at-execution")
                if missing_legs:
                    reason = (
                        f"Strict mode: trust gate requires all legs — "
                        f"missing: {', '.join(missing_legs)} "
                        f"(TRUST_LEG_MISSING)"
                    )
                    self.telemetry.emit_strict_block(
                        strict_flag="require_all_legs",
                        reason_code="TRUST_LEG_MISSING",
                        block_reason=reason,
                        session_id=session.session_id,
                        tool_name=tool_name,
                    )
                    return PipelineResult(
                        action=CheckResult.BLOCK,
                        tool_class=tool_class,
                        block_reason=reason,
                    )

            if sc_result.verdict == TrustVerdict.BLOCKED:
                self.telemetry.emit_trust_gate(
                    event_type=EventType.TRUST_GATE_BLOCKED,
                    session_id=session.session_id,
                    tool_name=tool_name,
                    provider_id=sc_result.provider_id or "",
                    provider_name=sc_result.provider_name or "",
                    trust_verdict="blocked",
                    reason_code="PROVIDER_BLOCKLISTED",
                    block_reason=sc_result.reason,
                )
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    tool_class=tool_class,
                    block_reason=(
                        f"Supply-chain: provider '{sc_result.provider_name}' "
                        f"is blocklisted. {sc_result.reason}"
                    ),
                )
            if sc_result.verdict == TrustVerdict.QUARANTINED:
                self.telemetry.emit_trust_gate(
                    event_type=EventType.TRUST_GATE_QUARANTINED,
                    session_id=session.session_id,
                    tool_name=tool_name,
                    provider_id=sc_result.provider_id or "",
                    provider_name=sc_result.provider_name or "",
                    trust_verdict="quarantined",
                    reason_code="PROVIDER_QUARANTINED",
                    block_reason=sc_result.reason,
                )
                return PipelineResult(
                    action=CheckResult.AMBER,
                    tool_class=tool_class,
                    amber_reason=(
                        f"Supply-chain: {sc_result.reason} "
                        f"Requires human review before use."
                    ),
                )
            if sc_result.verdict in (
                TrustVerdict.UNTRUSTED,
                TrustVerdict.EXPIRED,
                TrustVerdict.SIGNATURE_INVALID,
            ):
                # Map verdict to specific reason code
                reason_codes = {
                    TrustVerdict.UNTRUSTED: "PROVIDER_UNTRUSTED",
                    TrustVerdict.EXPIRED: "PROVIDER_EXPIRED",
                    TrustVerdict.SIGNATURE_INVALID: "SIGNATURE_INVALID",
                }
                # Map verdict to specific event type
                event_types = {
                    TrustVerdict.UNTRUSTED: EventType.TRUST_GATE_UNTRUSTED,
                    TrustVerdict.EXPIRED: EventType.TRUST_GATE_EXPIRED,
                    TrustVerdict.SIGNATURE_INVALID: EventType.TRUST_GATE_SIGNATURE_INVALID,
                }
                self.telemetry.emit_trust_gate(
                    event_type=event_types.get(
                        sc_result.verdict, EventType.TRUST_GATE_BLOCKED
                    ),
                    session_id=session.session_id,
                    tool_name=tool_name,
                    provider_id=sc_result.provider_id or "",
                    provider_name=sc_result.provider_name or "",
                    trust_verdict=sc_result.verdict.value,
                    reason_code=reason_codes.get(
                        sc_result.verdict, "UNKNOWN"
                    ),
                    block_reason=sc_result.reason,
                    digest_match=str(sc_result.digest_match) if sc_result.digest_match is not None else "",
                    signature_valid=str(sc_result.signature_valid) if sc_result.signature_valid is not None else "",
                )
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    tool_class=tool_class,
                    block_reason=f"Supply-chain: {sc_result.reason}",
                )
            # TRUSTED — emit and continue pipeline
            self.telemetry.emit_trust_gate(
                event_type=EventType.TRUST_GATE_TRUSTED,
                session_id=session.session_id,
                tool_name=tool_name,
                provider_id=sc_result.provider_id or "",
                provider_name=sc_result.provider_name or "",
                trust_verdict="trusted",
                digest_match=str(sc_result.digest_match) if sc_result.digest_match is not None else "",
                signature_valid=str(sc_result.signature_valid) if sc_result.signature_valid is not None else "",
            )

        # --- 1. Canary check (before anything else — instant kill) ---
        canary_result = self.canary.check(tool_name, session_id=session.session_id)
        if canary_result:
            session.kill()
            return PipelineResult(
                action=CheckResult.KILL,
                tool_class="canary",
                block_reason=canary_result,
            )

        # --- 2. Self-protection ---
        if target:
            sp_result = self.self_protection.check(tool_name, target=target)
            if sp_result:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    tool_class=tool_class,
                    block_reason=sp_result,
                )

        if tool_name == "bash_exec" and parameters:
            command = parameters.get("command", "")
            sp_result = self.self_protection.check(tool_name, command=command)
            if sp_result:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    tool_class=tool_class,
                    block_reason=sp_result,
                )

        # --- 2b. Exec Tunnel Detection (SENTINEL finding 2026-02-22) ---
        # Parse exec/bash_exec commands to detect tunnelled tool calls.
        # e.g. "exec git push --force" must hit git policy, not just bash policy.
        if tool_name in EXEC_TOOL_NAMES and parameters:
            tunnel = self.exec_tunnel.check(tool_name, parameters)
            if tunnel:
                # Dangerous patterns → hard block
                if tunnel.is_dangerous:
                    return PipelineResult(
                        action=CheckResult.BLOCK,
                        tool_class="actuator",
                        block_reason=f"Exec tunnel blocked: {tunnel.reason}",
                    )

                # Tunnelled tool detected → reclassify
                if tunnel.virtual_tool:
                    # Re-classify the tunnelled tool
                    tunnelled_class = self.classify_tool(
                        tunnel.virtual_tool,
                        session_id=session.session_id,
                    )

                    # If tunnelled tool is a sensor, taint the session
                    if tunnel.virtual_tool.startswith("git_") and tunnel.virtual_tool.split("_", 1)[1] in (
                        "clone", "fetch", "pull"
                    ):
                        session.taint(source_tool=tunnel.virtual_tool)

                    # If tainted + tunnelled actuator → amber
                    if (
                        session.is_tainted
                        and tunnel.virtual_tool in self.config.high_risk_actuator_tools
                    ):
                        session.trust_state = TrustState.AMBER
                        return PipelineResult(
                            action=CheckResult.AMBER,
                            canonical_target=canonical_target,
                            tool_class=tunnelled_class,
                            amber_reason=f"Exec tunnel: {tunnel.reason} (tainted session)",
                        )

        # --- 2b2. Exec mode risk evaluation ---
        if tool_name in (
            "exec", "exec_process", "bash_exec", "shell_exec", "run_command", "execute_command"
        ) and parameters:
            elevated = bool(parameters.get("elevated", False))
            host = parameters.get("host", "gateway")
            security = parameters.get("security", "full")

            if elevated and session.ghost_mode:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=canonical_target,
                    tool_class="actuator",
                    block_reason=(
                        "Elevated exec blocked in Ghost Mode: host-level execution "
                        "would bypass ghost interception."
                    ),
                )

            if elevated and session.is_tainted:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=canonical_target,
                    tool_class="actuator",
                    block_reason=(
                        "Elevated exec blocked on tainted session: potential "
                        "privilege escalation from untrusted input."
                    ),
                )

            if host == "gateway" and security == "full" and not elevated:
                if session.is_tainted:
                    session.trust_state = TrustState.AMBER
                    return PipelineResult(
                        action=CheckResult.AMBER,
                        canonical_target=canonical_target,
                        tool_class="actuator",
                        amber_reason=(
                            "Unrestricted exec (security=full, host=gateway) on tainted "
                            "session. Review command before proceeding."
                        ),
                    )

        # --- 2c. Credential Exposure (pre-execution param scan) ---
        if parameters:
            cred_result = self.credential_exposure.check(tool_name, parameters)
            if cred_result:
                severity, message = cred_result
                if severity == "block":
                    return PipelineResult(
                        action=CheckResult.BLOCK,
                        canonical_target=canonical_target,
                        tool_class=tool_class,
                        block_reason=message,
                    )
                else:  # amber
                    session.trust_state = TrustState.AMBER
                    return PipelineResult(
                        action=CheckResult.AMBER,
                        canonical_target=canonical_target,
                        tool_class=tool_class,
                        amber_reason=message,
                    )

        # --- 2d. Control-plane tool gate ---
        if tool_class == "control_plane":
            session.trust_state = TrustState.AMBER
            return PipelineResult(
                action=CheckResult.AMBER,
                canonical_target=canonical_target,
                tool_class=tool_class,
                amber_reason=(
                    f"Control-plane tool '{tool_name}' requires explicit approval. "
                    "These tools can modify gateway configuration and scheduling."
                ),
            )

        # --- 2e. Unknown tool gate (fail-closed) ---
        if tool_class == "unknown_actuator":
            session.trust_state = TrustState.AMBER
            return PipelineResult(
                action=CheckResult.AMBER,
                canonical_target=canonical_target,
                tool_class=tool_class,
                amber_reason=(
                    f"Unknown tool '{tool_name}' is not in any classification set. "
                    "Treating as potential actuator (fail-closed). Add to "
                    "config.py tool sets to resolve."
                ),
            )

        # --- 3. Path jail (for filesystem tools) ---
        if target and tool_name in self.config.filesystem_tools:
            jail_error, canonical = self.path_jail.check(target)
            canonical_target = canonical
            if jail_error:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=canonical,
                    tool_class=tool_class,
                    block_reason=jail_error,
                )

        # --- 3b. Path jail for secondary path parameters ---
        # Tools like fs_copy, fs_move, fs_rename have multiple path args.
        # Check ALL of them, not just the primary target.
        if tool_name in self.config.filesystem_tools and parameters:
            _secondary_path_keys = (
                "destination", "new_path", "old_path", "source",
                "output", "dest", "target_path", "to", "from",
            )
            for key in _secondary_path_keys:
                if key in parameters and isinstance(parameters[key], str):
                    secondary = parameters[key]
                    # Skip if it's the same as the primary target
                    if secondary == target:
                        continue
                    jail_error, canonical = self.path_jail.check(secondary)
                    if jail_error:
                        return PipelineResult(
                            action=CheckResult.BLOCK,
                            canonical_target=canonical,
                            tool_class=tool_class,
                            block_reason=f"Secondary path ({key}): {jail_error}",
                        )

        # --- 3a. apply_patch path extraction (paths embedded in patch body) ---
        if tool_name == "apply_patch" and parameters:
            patch_text = parameters.get("patch", parameters.get("input", ""))
            if isinstance(patch_text, str):
                for line in patch_text.splitlines():
                    for marker in ("*** Add File:", "*** Update File:",
                                   "*** Delete File:", "*** Move to:"):
                        if line.strip().startswith(marker):
                            embedded_path = line.strip()[len(marker):].strip()
                            if embedded_path:
                                jail_error, canonical = self.path_jail.check(embedded_path)
                                if jail_error:
                                    return PipelineResult(
                                        action=CheckResult.BLOCK,
                                        canonical_target=canonical,
                                        tool_class=tool_class,
                                        block_reason=f"apply_patch: {jail_error}",
                                    )

        # --- 3b. Ghost Egress Guard (network isolation in Ghost Mode) ---
        # Runs BEFORE SSRF so that secrets in URLs never trigger DNS lookups.
        if session.ghost_mode:
            session_allowlist = self._ghost_session_allowlists.get(session.session_id)
            ghost_result = self.ghost_egress_guard.check(
                tool_name, target=target, parameters=parameters,
                session_allowlist=session_allowlist,
            )
            if ghost_result is not None:
                if ghost_result.blocked:
                    return PipelineResult(
                        action=CheckResult.GHOST,
                        canonical_target=canonical_target,
                        tool_class=tool_class,
                        block_reason=ghost_result.reason,
                    )
                # Not blocked — passed DLP scanning, continue pipeline

        # --- 4. SSRF shield (for network tools) ---
        # NOTE: This validates the initial URL. HTTP redirects must be
        # re-validated via ssrf_shield.check_redirect() by the adapter
        # or HTTP client. Adapters SHOULD set follow_redirects=False and
        # route redirect targets back through the pipeline, or use
        # check_redirect() before following each hop.
        if tool_name in self.config.network_tools and target:
            ssrf_result = self.ssrf_shield.check(target)
            if ssrf_result:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=target,
                    tool_class=tool_class,
                    block_reason=ssrf_result,
                )

        # --- 4b. Egress policy (domain-level controls) ---
        if tool_name in self.config.network_tools and target:
            egress_result = self.egress_policy.check(target)
            if egress_result:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=target,
                    tool_class=tool_class,
                    block_reason=egress_result,
                )

        # --- 5. DLP-lite (for egress tools) ---
        if tool_name in self.config.egress_tools and payload:
            dlp_result = self.dlp_lite.check(payload)
            if dlp_result:
                session.trust_state = TrustState.AMBER
                return PipelineResult(
                    action=CheckResult.AMBER,
                    canonical_target=canonical_target,
                    tool_class=tool_class,
                    amber_reason=dlp_result,
                )

        # --- 6. Circuit breaker (for state-modifying tools) ---
        if tool_name in self.config.state_modifying_tools:
            breaker_tripped = session.record_state_modify()
            if breaker_tripped:
                return PipelineResult(
                    action=CheckResult.BLOCK,
                    canonical_target=canonical_target,
                    tool_class=tool_class,
                    block_reason=(
                        f"Circuit Breaker: exceeded {self.config.circuit_breaker_max_calls} "
                        f"state-modifying calls in {self.config.circuit_breaker_window_seconds}s"
                    ),
                )

        # --- 7. Taint check (graduated decay) ---
        # Capture taint state BEFORE decay for cadence bridge (P3-11)
        _was_tainted_pre_decay = session.is_tainted

        # Apply time-based decay first
        session.check_taint_decay()

        # If this is a sensor, taint the session (with source tracking)
        if tool_class == "sensor":
            session.taint(source_tool=tool_name)
        else:
            # Non-sensor ops contribute to operation-based decay
            session.record_clean_op()

        # Graduated amber: only HIGH/CRITICAL taint triggers amber
        if (
            session.should_amber_for_taint()
            and tool_name in self.config.high_risk_actuator_tools
        ):
            # Check for valid approval window before prompting
            args_shape = self._compute_args_shape(parameters)
            if self.approval_windows.consume_window(
                session.session_id, tool_name, args_shape
            ):
                # Window consumed — skip amber prompt, allow through
                pass
            else:
                # Record the prompt for burst tracking
                self.approval_windows.record_approval_prompt(session.session_id)
                # Record tainted pivot for burst tracking
                self.approval_windows.record_tainted_pivot(session.session_id)

                session.trust_state = TrustState.AMBER
                taint_summary = session.taint_state.summary()
                return PipelineResult(
                    action=CheckResult.AMBER,
                    canonical_target=canonical_target,
                    tool_class=tool_class,
                    amber_reason=(
                        f"Tainted session (level={taint_summary['level']}) attempting high-risk action. "
                        f"Sources: {', '.join(taint_summary['sources'])}."
                    ),
                )

        # --- 7a. Cadence Bridge: temporal anomaly detection (P3-11) ---
        if self.cadence_bridge is not None:
            self.cadence_bridge.check_taint_clear(
                session_id=session.session_id,
                was_tainted=_was_tainted_pre_decay,
                is_tainted=session.is_tainted,
            )
            cadence_signals = self.cadence_bridge.check(
                session_id=session.session_id,
                tool_name=tool_name,
                tool_class=tool_class,
                is_tainted=session.is_tainted,
            )
            for signal in cadence_signals:
                if signal.should_escalate_taint:
                    session.taint(source_tool=signal.taint_escalation_source)
                if signal.should_amber and tool_name in self.config.high_risk_actuator_tools:
                    session.trust_state = TrustState.AMBER
                    return PipelineResult(
                        action=CheckResult.AMBER,
                        canonical_target=canonical_target,
                        tool_class=tool_class,
                        amber_reason=signal.amber_reason,
                    )

        # --- 8. Session scope check ---
        if session.allowed_tools is not None and tool_name not in session.allowed_tools:
            session.trust_state = TrustState.AMBER
            return PipelineResult(
                action=CheckResult.AMBER,
                canonical_target=canonical_target,
                tool_class=tool_class,
                amber_reason=f"Tool '{tool_name}' is outside session scope.",
            )

        # --- 9. Ghost Mode gate ---
        # Uses broader interception than circuit breaker: explicit set + prefix
        # heuristic.  If it looks like a write, Ghost Mode catches it.
        if session.ghost_mode and self.config.is_ghost_intercepted(tool_name):
            # Update shadow VFS to keep agent reads consistent
            if tool_name in ("fs_write", "write_file") and target and payload:
                session.ghost_write(target, payload)
            elif tool_name in ("fs_delete", "delete_file", "remove_file") and target:
                session.ghost_delete(target)
            elif tool_name in ("fs_rename", "rename_file", "fs_move", "move_file") and parameters:
                old = parameters.get("path", parameters.get("source", parameters.get("old_path", "")))
                new = parameters.get("new_path", parameters.get("destination", parameters.get("target", "")))
                if old and new:
                    session.ghost_rename(str(old), str(new))
            elif tool_name in ("fs_copy", "copy_file") and target and parameters:
                dest = parameters.get("destination", parameters.get("new_path", parameters.get("dest", "")))
                if dest and payload:
                    session.ghost_write(str(dest), payload)
                elif dest and target:
                    # Copy: read source from shadow or mark dest as written
                    src_content = session.ghost_read(target)
                    if src_content is not None:
                        session.ghost_write(str(dest), src_content)
            elif tool_name == "apply_patch" and parameters:
                # Parse patch markers to update shadow VFS
                patch_text = parameters.get("patch", parameters.get("input", ""))
                if isinstance(patch_text, str):
                    for line in patch_text.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("*** Delete File:"):
                            del_path = line_s[len("*** Delete File:"):].strip()
                            if del_path:
                                session.ghost_delete(del_path)
                        elif line_s.startswith("*** Add File:"):
                            add_path = line_s[len("*** Add File:"):].strip()
                            if add_path:
                                # Mark as written (content unknown but file exists)
                                session.ghost_write(add_path, "[ghost: patch applied]")
            return PipelineResult(
                action=CheckResult.GHOST,
                canonical_target=canonical_target,
                tool_class=tool_class,
            )

        # Ghost Mode read from shadow VFS
        if session.ghost_mode and target:
            shadow_content = session.ghost_read(target)
            if shadow_content is not None:
                return PipelineResult(
                    action=CheckResult.GHOST,
                    canonical_target=canonical_target,
                    tool_class=tool_class,
                )

        # --- All checks passed ---
        return PipelineResult(
            action=CheckResult.ALLOW,
            canonical_target=canonical_target,
            tool_class=tool_class,
        )

    # --- Approval callback flow (rubber-stamp detection) ---

    def get_rss_state(self, operator_id: str) -> RubberStampState:
        """Get or create RSS state for an operator."""
        if operator_id not in self._rss_states:
            self._rss_states[operator_id] = RubberStampState()
        return self._rss_states[operator_id]

    def process_approval(
        self,
        operator_id: str,
        approved: bool,
        latency_seconds: float,
        pattern_hash: str = "",
        amber_tier: str = "",
    ) -> ApprovalGate:
        """Process an operator's approval decision through rubber-stamp detection.

        Called when the operator responds to an AMBER prompt.
        Returns an ApprovalGate indicating whether the approval should proceed.

        Args:
            operator_id: Who is approving (hash of human identity)
            approved: True if approved, False if rejected
            latency_seconds: Time between prompt shown and decision
            pattern_hash: Hash of the tool+args pattern being approved
            amber_tier: AMBER_LOW, AMBER_HIGH, AMBER_CRITICAL

        Returns:
            ApprovalGate with allowed=True if approval proceeds, or
            allowed=False with hold/lockout details if rubber-stamping detected.
        """
        import time as _time

        state = self.get_rss_state(operator_id)

        # Check lockout first
        if state.lockout_until is not None and _time.time() < state.lockout_until:
            remaining = state.lockout_until - _time.time()
            return ApprovalGate(
                allowed=False,
                rss_score=state.peak_rss,
                rss_level=RSSLevel.VERY_HIGH,
                lockout_remaining=remaining,
                reason=(
                    f"Approval lockout active ({remaining:.0f}s remaining). "
                    f"Rubber-stamp score {state.peak_rss} triggered automatic cooldown."
                ),
            )

        # Record the decision
        state.record_decision(
            approved=approved,
            latency_seconds=latency_seconds,
            pattern_hash=pattern_hash,
            amber_tier=amber_tier,
        )

        # If it's a rejection, always allow it through
        if not approved:
            rss = state.compute_rss(latency_seconds, pattern_hash, self.rss_config)
            return ApprovalGate(
                allowed=True,
                rss_score=rss,
                rss_level=RSSLevel.NONE,
                reason="Rejection recorded.",
            )

        # Compute RSS and apply actions
        rss = state.compute_rss(latency_seconds, pattern_hash, self.rss_config)
        actions = state.apply_rss_actions(rss, self.rss_config)

        level = RSSLevel.NONE
        if rss >= self.rss_config.rss_very_high_min:
            level = RSSLevel.VERY_HIGH
        elif rss >= self.rss_config.rss_high_min:
            level = RSSLevel.HIGH
        elif rss >= self.rss_config.rss_medium_min:
            level = RSSLevel.MEDIUM

        # VERY_HIGH: lockout — reject this approval
        if level == RSSLevel.VERY_HIGH:
            return ApprovalGate(
                allowed=False,
                rss_score=rss,
                rss_level=level,
                lockout_remaining=self.rss_config.very_high_lockout_seconds,
                reason=(
                    f"Rubber-stamp score {rss} (VERY_HIGH). "
                    f"All approvals disabled for {self.rss_config.very_high_lockout_seconds:.0f}s. "
                    f"Actions: {', '.join(actions.get('actions', []))}"
                ),
            )

        # HIGH: inject hold time
        hold = 0.0
        if level == RSSLevel.HIGH:
            hold = self.rss_config.high_hold_seconds

        return ApprovalGate(
            allowed=True,
            rss_score=rss,
            rss_level=level,
            hold_seconds=hold,
            reason=f"RSS={rss} ({level.name}). {', '.join(actions.get('actions', []))}".strip(),
        )

    # --- Transport layer: response principal validation ---

    def register_request(
        self,
        upstream_id,
        agent_id,
        session: Session,
        tool_name: str = "",
        tag: Optional[str] = None,
    ):
        """Register an outbound request for response tracking.

        Called by the transport layer when sending a request upstream.
        Tags the request with the originating session for later validation.
        Also records the tool call against the session's budget.
        """
        req = self.response_validator.register_request(
            upstream_id=upstream_id,
            agent_id=agent_id,
            session_id=session.session_id,
            tool_name=tool_name,
            tag=tag,
        )

        # Budget tracking (R-SEN-003) — idempotent on upstream_id
        budget_error = self.response_validator.record_tool_call(
            session.session_id, upstream_id=upstream_id
        )
        if budget_error:
            session.trust_state = TrustState.RED
            session.kill()

        return req, budget_error

    def validate_response(
        self,
        upstream_id,
        expected_session: Optional[Session] = None,
    ) -> tuple[Optional[object], Optional[str]]:
        """Validate an upstream response before delivering to the agent.

        Called by the transport layer when a response arrives from upstream.
        Ensures the response is delivered only to the correct session.

        Returns:
            (PendingRequest, None) if valid
            (None, error_message) if principal mismatch or unknown response
        """
        expected_sid = expected_session.session_id if expected_session else None
        return self.response_validator.validate_response(upstream_id, expected_sid)

    def set_session_budget(
        self,
        session: Session,
        budget: SessionBudget,
    ) -> None:
        """Set a resource budget for a session (R-SEN-003).

        Used for autonomous sessions like SENTINEL cron jobs.
        """
        self.response_validator.set_budget(session.session_id, budget)

    def check_session_budget(self, session: Session) -> Optional[str]:
        """Check if a session's budget is exceeded."""
        return self.response_validator.check_budget(session.session_id)

    # --- Approval windows integration ---

    @staticmethod
    def _compute_args_shape(parameters: Optional[dict]) -> str:
        """Compute a canonical argument shape string for context hashing.

        Extracts sorted key names and type names from the parameters dict.
        This ensures that different values for the same argument structure
        produce the same context hash (allowing window reuse).
        """
        if not parameters:
            return ""
        parts = []
        for key in sorted(parameters.keys()):
            val = parameters[key]
            parts.append(f"{key}:{type(val).__name__}")
        return ",".join(parts)

    def issue_approval_window(
        self,
        session: Session,
        operator_id: str,
        tool_name: str,
        parameters: Optional[dict] = None,
        risk_band: RiskBand = RiskBand.AMBER_LOW,
    ) -> Optional[object]:
        """Issue an approval window after operator approves an amber prompt.

        Called from the approval callback (after process_approval succeeds).
        Returns the window object if created, None for CRITICAL band.
        """
        args_shape = self._compute_args_shape(parameters)
        return self.approval_windows.create_window(
            session_id=session.session_id,
            operator_id=operator_id,
            tool_name=tool_name,
            args_shape=args_shape,
            risk_band=risk_band,
        )

    def sync_threat_mode(self, session: Session) -> None:
        """Synchronise the approval window threat mode with session taint.

        Maps taint levels to threat modes per SENTINEL SLA spec:
            MEDIUM or below → NORMAL
            HIGH            → ELEVATED
            CRITICAL        → ACTIVE_EXPLOITATION
        """
        taint_level = session.taint_state.level
        if taint_level >= TaintLevel.CRITICAL:
            target = ThreatMode.ACTIVE_EXPLOITATION
        elif taint_level >= TaintLevel.HIGH:
            target = ThreatMode.ELEVATED
        else:
            target = ThreatMode.NORMAL

        if target != self.approval_windows.threat_mode:
            self.approval_windows.set_threat_mode(target)

    def invalidate_windows_for_session(
        self, session: Session, reason: str = ""
    ) -> int:
        """Invalidate all approval windows for a session.

        Called when session is killed, taint spikes, or RSS hits VERY_HIGH.
        """
        return self.approval_windows.invalidate_session_windows(
            session.session_id, reason
        )

    # --- Ghost Egress Guard: session domain allowlist helpers ---

    def ghost_allow_domain(self, session: Session, domain: str) -> None:
        """Add a domain to the session's Ghost Mode allowlist (for 'ask' mode)."""
        sid = session.session_id
        if sid not in self._ghost_session_allowlists:
            self._ghost_session_allowlists[sid] = GhostSessionAllowlist(
                ttl_seconds=self.config.ghost_network_allowlist_ttl_seconds
            )
        self._ghost_session_allowlists[sid].allow(domain)

    def ghost_allowed_domains(self, session: Session) -> list[str]:
        """Return currently allowed domains for a session's Ghost Mode."""
        sid = session.session_id
        al = self._ghost_session_allowlists.get(sid)
        if al is None:
            return []
        return al.allowed_domains()
