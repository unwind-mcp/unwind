"""Amber Mediator Rollout Guard — GO-10 safe-by-default deployment gate.

Config gate: amber.mediator.mode = off | shadow | enforce
  - off (default): mediator fields emitted on wire but not enforced
  - shadow: validation runs but results are logged, not enforced
  - enforce: full approval token validation + blocking

Shadow parity test: compares shadow decisions against baseline to verify
no enforcement outcome drift before promoting to enforce mode.

Thresholds per SENTINEL's GO-10 spec (unwind-amber-go10-rollout-guard-spec.yaml):
  - exact_decision_match_rate >= 99.9%
  - reason_code_match_rate >= 99.5%
  - unsafe_allow_drift_rate == 0%
  - overblock_drift_rate <= 0.1%
  - telemetry_chain_completeness == 100%
  - replay_acceptance_rate == 0%

Framework-agnostic: no OpenClaw-specific logic.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("unwind.enforcement.amber_rollout")


# ---------------------------------------------------------------------------
# Config gate
# ---------------------------------------------------------------------------

class AmberMediatorMode(Enum):
    """Rollout gate modes for amber mediator enforcement."""
    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


# Default: mediator is OFF — safe by default
DEFAULT_MODE = AmberMediatorMode.OFF

# Config key name (for YAML/env config lookup)
CONFIG_KEY = "amber.mediator.mode"


def parse_mode(value: str) -> AmberMediatorMode:
    """Parse a config string into an AmberMediatorMode.

    Fail-closed: unrecognised values default to OFF.
    """
    try:
        return AmberMediatorMode(value.lower().strip())
    except (ValueError, AttributeError):
        logger.warning(
            "Unrecognised amber.mediator.mode '%s', defaulting to OFF (safe)", value
        )
        return AmberMediatorMode.OFF


# ---------------------------------------------------------------------------
# Shadow parity test
# ---------------------------------------------------------------------------

# Acceptance thresholds (per GO-10 spec)
THRESHOLDS = {
    "exact_decision_match_rate": 0.999,       # >= 99.9%
    "reason_code_match_rate": 0.995,          # >= 99.5%
    "unsafe_allow_drift_rate": 0.0,           # == 0%
    "overblock_drift_rate": 0.001,            # <= 0.1%
    "telemetry_chain_completeness": 1.0,      # == 100%
    "replay_acceptance_rate": 0.0,            # == 0%
}

# Minimum sample requirements
MIN_EVENTS_TOTAL = 2000
MIN_EVENTS_PER_TIER = {
    "AMBER_LOW": 200,
    "AMBER_HIGH": 200,
    "AMBER_CRITICAL": 50,
}
MIN_OBSERVATION_HOURS = 24


@dataclass
class ShadowDecision:
    """A single shadow vs baseline comparison record."""
    event_id: str
    risk_tier: str
    # Baseline (existing pipeline) decision
    baseline_decision: str    # allow | amber | deny | kill
    baseline_reason_code: str
    # Shadow (mediator) decision
    shadow_decision: str      # allow | amber | deny | kill
    shadow_reason_code: str
    # Telemetry completeness
    telemetry_fields_present: int
    telemetry_fields_required: int
    # Replay
    replay_accepted: bool = False


@dataclass
class ShadowParityResult:
    """Result of a shadow parity test run."""
    # Sample size
    total_events: int = 0
    events_per_tier: dict = field(default_factory=dict)
    observation_hours: float = 0.0

    # Computed rates
    exact_decision_match_rate: float = 0.0
    reason_code_match_rate: float = 0.0
    unsafe_allow_drift_rate: float = 0.0
    overblock_drift_rate: float = 0.0
    telemetry_chain_completeness: float = 0.0
    replay_acceptance_rate: float = 0.0

    # Verdict
    sample_sufficient: bool = False
    all_thresholds_pass: bool = False
    failures: list = field(default_factory=list)

    @property
    def promote_safe(self) -> bool:
        """Can we safely promote from shadow to enforce?"""
        return self.sample_sufficient and self.all_thresholds_pass


def run_shadow_parity_test(
    decisions: list[ShadowDecision],
    observation_hours: float = 0.0,
) -> ShadowParityResult:
    """Run the shadow parity test against GO-10 thresholds.

    Args:
        decisions: List of shadow vs baseline comparison records.
        observation_hours: Duration of observation window in hours.

    Returns:
        ShadowParityResult with computed rates and pass/fail verdict.
    """
    result = ShadowParityResult()
    n = len(decisions)
    result.total_events = n
    result.observation_hours = observation_hours

    if n == 0:
        result.failures.append("no_events")
        return result

    # Count events per tier
    tier_counts: dict[str, int] = {}
    for d in decisions:
        tier_counts[d.risk_tier] = tier_counts.get(d.risk_tier, 0) + 1
    result.events_per_tier = tier_counts

    # Check sample sufficiency
    result.sample_sufficient = True
    if n < MIN_EVENTS_TOTAL:
        result.sample_sufficient = False
        result.failures.append(f"insufficient_total: {n} < {MIN_EVENTS_TOTAL}")
    for tier, min_count in MIN_EVENTS_PER_TIER.items():
        actual = tier_counts.get(tier, 0)
        if actual < min_count:
            result.sample_sufficient = False
            result.failures.append(f"insufficient_{tier}: {actual} < {min_count}")
    if observation_hours < MIN_OBSERVATION_HOURS:
        result.sample_sufficient = False
        result.failures.append(f"insufficient_hours: {observation_hours} < {MIN_OBSERVATION_HOURS}")

    # Compute rates
    decision_matches = sum(1 for d in decisions if d.baseline_decision == d.shadow_decision)
    reason_matches = sum(1 for d in decisions if d.baseline_reason_code == d.shadow_reason_code)

    # Unsafe allow: shadow says allow where baseline says amber/deny
    unsafe_allows = sum(
        1 for d in decisions
        if d.shadow_decision == "allow"
        and d.baseline_decision in ("amber", "deny", "kill")
    )

    # Overblock: shadow says deny where baseline says allow
    overblocks = sum(
        1 for d in decisions
        if d.shadow_decision == "deny"
        and d.baseline_decision == "allow"
    )

    # Telemetry completeness
    total_fields_present = sum(d.telemetry_fields_present for d in decisions)
    total_fields_required = sum(d.telemetry_fields_required for d in decisions)

    # Replay acceptance
    replay_accepted = sum(1 for d in decisions if d.replay_accepted)

    result.exact_decision_match_rate = decision_matches / n
    result.reason_code_match_rate = reason_matches / n
    result.unsafe_allow_drift_rate = unsafe_allows / n
    result.overblock_drift_rate = overblocks / n
    result.telemetry_chain_completeness = (
        total_fields_present / total_fields_required if total_fields_required > 0 else 1.0
    )
    result.replay_acceptance_rate = replay_accepted / n

    # Check thresholds
    result.all_thresholds_pass = True

    if result.exact_decision_match_rate < THRESHOLDS["exact_decision_match_rate"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"exact_decision_match_rate: {result.exact_decision_match_rate:.4f} < {THRESHOLDS['exact_decision_match_rate']}"
        )

    if result.reason_code_match_rate < THRESHOLDS["reason_code_match_rate"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"reason_code_match_rate: {result.reason_code_match_rate:.4f} < {THRESHOLDS['reason_code_match_rate']}"
        )

    if result.unsafe_allow_drift_rate > THRESHOLDS["unsafe_allow_drift_rate"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"unsafe_allow_drift_rate: {result.unsafe_allow_drift_rate:.4f} > {THRESHOLDS['unsafe_allow_drift_rate']}"
        )

    if result.overblock_drift_rate > THRESHOLDS["overblock_drift_rate"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"overblock_drift_rate: {result.overblock_drift_rate:.4f} > {THRESHOLDS['overblock_drift_rate']}"
        )

    if result.telemetry_chain_completeness < THRESHOLDS["telemetry_chain_completeness"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"telemetry_chain_completeness: {result.telemetry_chain_completeness:.4f} < {THRESHOLDS['telemetry_chain_completeness']}"
        )

    if result.replay_acceptance_rate > THRESHOLDS["replay_acceptance_rate"]:
        result.all_thresholds_pass = False
        result.failures.append(
            f"replay_acceptance_rate: {result.replay_acceptance_rate:.4f} > {THRESHOLDS['replay_acceptance_rate']}"
        )

    return result
