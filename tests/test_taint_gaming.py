"""Adversarial taint gaming tests — stateful sequence attacks.

These tests simulate an attacker who UNDERSTANDS the taint decay system
and deliberately crafts sequences of actions to exploit it.

Attack patterns tested:
    1. Slow drip exfiltration — taint, wait for decay, exfil chunk, repeat
    2. Clean op flooding — spam clean ops to accelerate decay
    3. Cooldown surfing — stay within cooldown to prevent escalation
    4. Below-threshold persistence — hold taint just below amber
    5. Taint washing — fully decay then use data while at NONE
    6. Split-source evasion — use many different tools to avoid pattern detection
    7. Time-boundary exploit — act at exact decay boundary
    8. Interleaved read/write — alternate sensor and actuator calls

These are the attacks the GPT Pro review (finding #9) warned about:
"an attacker can deliberately transform, chunk, encode, or paraphrase
until taint dissipates."
"""

import time

import pytest

from unwind.enforcement.taint_decay import (
    AMBER_TAINT_THRESHOLD,
    TaintDecayConfig,
    TaintLevel,
    TaintState,
)


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def config():
    """Standard config matching pre-P2-8 defaults (dwell=0 for compat)."""
    return TaintDecayConfig(
        decay_interval_seconds=60.0,
        clean_ops_per_decay=10,
        retaint_cooldown_seconds=5.0,
        single_event_max=TaintLevel.HIGH,
        amber_threshold=TaintLevel.HIGH,
        min_dwell_seconds=0.0,
    )


@pytest.fixture
def fast_config():
    """Fast config for tests that need real time.sleep calls."""
    return TaintDecayConfig(
        decay_interval_seconds=0.5,
        clean_ops_per_decay=3,
        retaint_cooldown_seconds=0.1,
        single_event_max=TaintLevel.HIGH,
        amber_threshold=TaintLevel.HIGH,
        min_dwell_seconds=0.0,
    )


@pytest.fixture
def state():
    return TaintState()


# ═══════════════════════════════════════════════════════
# 1. Slow Drip Exfiltration
# ═══════════════════════════════════════════════════════

class TestSlowDripExfiltration:
    """Attacker reads sensitive data, waits for taint to decay,
    then exfiltrates a small chunk. Repeats across multiple cycles.

    The question: can an attacker exfiltrate data one piece at a time
    by always waiting until taint has decayed to NONE?
    """

    def test_taint_wash_then_exfil(self, state, config):
        """Taint from sensor call, wait for full decay, then check state.

        Result: attacker CAN reach NONE after waiting. This is by design —
        the pipeline's DLP-lite and credential scanner still run regardless
        of taint level. Taint adds amber gates, it doesn't replace other checks.
        """
        # Step 1: Read sensitive data (sensor call)
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Step 2: Wait for full decay (simulate 5 minutes)
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)
        assert state.level == TaintLevel.NONE

        # Step 3: Attacker is now at NONE — no amber gate
        assert not state.should_amber(config)

        # IMPORTANT: This is "by design" — taint is defense-in-depth.
        # DLP-lite (stage 10) and credential scanning (stage 6) still fire
        # regardless of taint level. Taint adds an EXTRA amber gate on top.
        # The attacker still can't exfil actual secrets without hitting those.

    def test_repeated_drip_cycles(self, state, config):
        """Multiple taint-decay-exfil cycles should each start fresh.

        After full decay, taint_event_count resets — the system has no memory
        of prior elevated periods. This is a conscious trade-off:
        we accept it because the other pipeline stages don't forget.
        """
        for cycle in range(5):
            # Taint
            state.apply_taint(f"sensor_{cycle}", config)
            assert state.level >= TaintLevel.MEDIUM

            # Full decay
            state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
            state.apply_decay(config)
            assert state.level == TaintLevel.NONE

            # Verify full reset
            assert state.taint_event_count == 0
            assert state.taint_sources == []

    def test_drip_with_insufficient_decay(self, state, config):
        """Attacker tries to act after partial decay — still tainted."""
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Wait only 1 interval (should drop to LOW, not NONE)
        state.last_taint_event = time.time() - config.decay_interval_seconds - 1
        state.apply_decay(config)
        assert state.level == TaintLevel.LOW
        assert state.is_tainted  # Still tainted, just not amber-worthy


# ═══════════════════════════════════════════════════════
# 2. Clean Op Flooding
# ═══════════════════════════════════════════════════════

class TestCleanOpFlooding:
    """Attacker spams clean operations to accelerate decay.

    If an attacker can trigger many low-risk tool calls rapidly
    (e.g. fs_read on safe files), they might decay taint faster than
    the time-based system would allow.
    """

    def test_flood_clean_ops_to_decay_from_medium(self, state, config):
        """Flooding clean ops can decay MEDIUM to NONE.

        With clean_ops_per_decay=10, an attacker needs 20 clean ops
        to go from MEDIUM(2) to NONE(0). That's 20 tool calls.
        """
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        ops_needed = 0
        while state.level > TaintLevel.NONE:
            state.apply_clean_op(config)
            ops_needed += 1

        # MEDIUM needs: 10 ops to LOW, 10 more to NONE = 20
        assert ops_needed == config.clean_ops_per_decay * 2

    def test_flood_clean_ops_to_decay_from_high(self, state, config):
        """Flooding from HIGH requires 30 clean ops."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH

        ops_needed = 0
        while state.level > TaintLevel.NONE:
            state.apply_clean_op(config)
            ops_needed += 1

        # HIGH(3) needs: 10 × 3 = 30 clean ops
        assert ops_needed == config.clean_ops_per_decay * 3

    def test_flood_clean_ops_to_decay_from_critical(self, state, config):
        """Flooding from CRITICAL requires 40 clean ops."""
        # Reach CRITICAL via 3 spaced taint events
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("read_email", config)
        assert state.level == TaintLevel.CRITICAL

        ops_needed = 0
        while state.level > TaintLevel.NONE:
            state.apply_clean_op(config)
            ops_needed += 1

        # CRITICAL(4) needs: 10 × 4 = 40 clean ops
        assert ops_needed == config.clean_ops_per_decay * 4

    def test_flood_is_observable(self, state, config):
        """The flood itself is visible in the session's tool-call count.

        An attacker flooding 40 fs_reads in a row creates an obvious
        anomaly in the circuit breaker / telemetry. This test confirms
        the numbers are non-trivial (can't decay in 2-3 ops).
        """
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH

        # Minimum clean ops to escape amber threshold
        ops_to_below_amber = 0
        while state.should_amber(config):
            state.apply_clean_op(config)
            ops_to_below_amber += 1

        # Need 10 ops to drop from HIGH to MEDIUM (below amber threshold)
        assert ops_to_below_amber == config.clean_ops_per_decay


# ═══════════════════════════════════════════════════════
# 3. Cooldown Surfing
# ═══════════════════════════════════════════════════════

class TestCooldownSurfing:
    """Attacker fires sensor calls rapidly to stay within cooldown,
    preventing escalation above MEDIUM while accumulating data.

    The cooldown is designed to prevent OVER-escalation, but an
    adversary could exploit it to PREVENT escalation.
    """

    def test_rapid_fire_stays_at_medium(self, state, config):
        """10 sensor calls within cooldown = still MEDIUM."""
        state.apply_taint("search_web", config)
        for i in range(9):
            state.apply_taint(f"fetch_url_{i}", config)

        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)

    def test_cooldown_surf_accumulates_sources(self, state, config):
        """Even though level doesn't escalate, source tracking still works.

        This means the session record shows ALL the sensor tools used,
        even if taint level was held at MEDIUM by cooldown.
        """
        state.apply_taint("search_web", config)
        state.apply_taint("fetch_url_1", config)
        state.apply_taint("fetch_url_2", config)
        state.apply_taint("read_email", config)

        # Level stuck at MEDIUM
        assert state.level == TaintLevel.MEDIUM

        # But all sources recorded
        assert "search_web" in state.taint_sources
        assert "fetch_url_1" in state.taint_sources
        assert "fetch_url_2" in state.taint_sources
        assert "read_email" in state.taint_sources

    def test_cooldown_surf_then_space_escalates(self, state, config):
        """If attacker eventually spaces calls, escalation resumes."""
        # Rapid fire within cooldown
        state.apply_taint("search_web", config)
        for i in range(5):
            state.apply_taint(f"fetch_{i}", config)
        assert state.level == TaintLevel.MEDIUM

        # Now space out past cooldown
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_late", config)
        assert state.level == TaintLevel.HIGH
        assert state.should_amber(config)


# ═══════════════════════════════════════════════════════
# 4. Below-Threshold Persistence
# ═══════════════════════════════════════════════════════

class TestBelowThresholdPersistence:
    """Attacker tries to maintain taint at exactly MEDIUM — below the
    amber threshold but still 'tainted' — to avoid amber prompts while
    having recently ingested external data.
    """

    def test_single_sensor_stays_below_amber(self, state, config):
        """A single sensor call reaches MEDIUM, which is below amber.

        This is by design: a single search_web shouldn't require human
        approval for every subsequent write. The risk is that the agent
        has read some external data and could be influenced by it.
        """
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)

        # Agent can now do writes without amber gates
        # This is the "amber fatigue" trade-off working as intended.

    def test_re_taint_within_cooldown_keeps_medium(self, state, config):
        """Attacker keeps refreshing taint within cooldown to stay at MEDIUM.

        By calling sensor tools rapidly, they refresh the timestamp
        (preventing decay) while not escalating above MEDIUM.
        """
        state.apply_taint("search_web", config)
        initial_time = state.last_taint_event

        # Refresh 5 times within cooldown
        for i in range(5):
            state.apply_taint(f"sensor_{i}", config)

        assert state.level == TaintLevel.MEDIUM
        # Timestamp refreshed — decay clock reset
        assert state.last_taint_event >= initial_time

    def test_below_threshold_but_dlp_still_fires(self, state, config):
        """Even at MEDIUM (no amber gate), other pipeline stages still run.

        This test documents the design assumption: taint gates are ADDITIVE.
        DLP-lite, credential scanning, egress policy all fire regardless.
        An attacker at MEDIUM can't exfil an AWS key just because they
        don't have an amber prompt — the key is caught by stage 6.
        """
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)

        # The taint system ALONE doesn't prevent exfiltration at MEDIUM.
        # That's the design contract — taint is one layer in a 14-stage pipeline.
        # This test exists to document that assumption, not to assert a fix.


# ═══════════════════════════════════════════════════════
# 5. Taint Washing
# ═══════════════════════════════════════════════════════

class TestTaintWashing:
    """Attacker reads sensitive data, then 'washes' the taint by waiting
    or doing clean ops, then acts on the data while at NONE.

    This is the fundamental limitation of ANY decay-based system.
    The mitigation is: other pipeline stages don't care about taint.
    """

    def test_time_wash(self, state, config):
        """Wait for time-based decay to reach NONE, then state is clean."""
        state.apply_taint("search_web", config)

        # Wait 5 intervals (5 minutes with defaults)
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)

        assert state.level == TaintLevel.NONE
        assert not state.is_tainted
        assert state.taint_event_count == 0  # Full reset

    def test_op_wash(self, state, config):
        """Use clean ops to wash taint to NONE."""
        state.apply_taint("search_web", config)

        # MEDIUM(2) needs 20 clean ops
        for _ in range(config.clean_ops_per_decay * 2):
            state.apply_clean_op(config)

        assert state.level == TaintLevel.NONE
        assert not state.is_tainted

    def test_combined_wash(self, state, config):
        """Use time + ops together for faster washing."""
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH  # Level 3

        # Time drops one level (HIGH → MEDIUM)
        state.last_taint_event = time.time() - config.decay_interval_seconds - 1
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM

        # Ops drop two more (MEDIUM → LOW → NONE)
        for _ in range(config.clean_ops_per_decay * 2):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.NONE

    def test_wash_then_retaint_starts_fresh(self, state, config):
        """After washing to NONE, a new taint starts from scratch.

        No memory of previous elevated period. This means an attacker
        who washes successfully is back at MEDIUM, not HIGH.
        """
        # First cycle: reach HIGH
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH

        # Wash
        state.last_taint_event = time.time() - (config.decay_interval_seconds * 5)
        state.apply_decay(config)
        assert state.level == TaintLevel.NONE

        # Retaint — starts at MEDIUM, NOT HIGH
        state.apply_taint("new_search", config)
        assert state.level == TaintLevel.MEDIUM
        assert state.taint_event_count == 1  # Fresh count


# ═══════════════════════════════════════════════════════
# 6. Split-Source Evasion
# ═══════════════════════════════════════════════════════

class TestSplitSourceEvasion:
    """Attacker uses many different tool names to spread taint sources,
    hoping the system tracks by tool name and misses the aggregate risk.
    """

    def test_many_unique_sources_still_tracks_all(self, state, config):
        """All unique sources recorded regardless of cooldown."""
        tools = [f"custom_sensor_{i}" for i in range(20)]
        for tool in tools:
            state.apply_taint(tool, config)

        # Level capped at MEDIUM (cooldown), but all 20 sources recorded
        assert state.level == TaintLevel.MEDIUM
        assert len(state.taint_sources) == 20

    def test_many_sources_visible_in_summary(self, state, config):
        """Summary audit trail shows all sources even when level didn't escalate."""
        state.apply_taint("search_web", config)
        state.apply_taint("read_email", config)
        state.apply_taint("fetch_rss", config)

        summary = state.summary()
        assert len(summary["sources"]) == 3
        assert summary["taint_events"] == 1  # Only first increments (others in cooldown)


# ═══════════════════════════════════════════════════════
# 7. Time-Boundary Exploits
# ═══════════════════════════════════════════════════════

class TestTimeBoundaryExploits:
    """Attacker acts at the exact moment taint crosses a threshold boundary."""

    def test_act_at_exact_decay_boundary(self, state, config):
        """At exactly the decay interval boundary, level should drop.

        The decay is floor-based: elapsed / interval rounded down.
        At exactly 60s, that's 60/60 = 1 level drop.
        """
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # Exactly at boundary
        state.last_taint_event = time.time() - config.decay_interval_seconds
        state.apply_decay(config)
        assert state.level == TaintLevel.LOW

    def test_just_before_decay_boundary(self, state, config):
        """Just under the interval: no decay yet."""
        state.apply_taint("search_web", config)

        # 1 second short of boundary
        state.last_taint_event = time.time() - config.decay_interval_seconds + 1
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM  # No change

    def test_act_at_amber_drop_moment(self, state, config):
        """Attacker times action to the exact moment taint drops below amber.

        HIGH → MEDIUM crossing is the critical boundary.
        """
        state.apply_taint("search_web", config)
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("fetch_url", config)
        assert state.level == TaintLevel.HIGH
        assert state.should_amber(config)

        # Wait exactly one interval: HIGH → MEDIUM
        state.last_taint_event = time.time() - config.decay_interval_seconds
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)  # Amber gate just dropped

        # Attacker acts here — at MEDIUM, no amber gate
        # This is the "decay gaming" sweet spot.
        # Defence: DLP-lite and credential scanner are taint-independent.


# ═══════════════════════════════════════════════════════
# 8. Interleaved Sensor/Actuator Sequences
# ═══════════════════════════════════════════════════════

class TestInterleavedSequences:
    """Attacker alternates sensor calls (that taint) with actuator calls
    (that count as clean ops), trying to keep taint unstable.
    """

    def test_alternate_taint_and_clean(self, state, config):
        """Alternating taint/clean: cooldown retaints DON'T reset clean counter.

        This is actually a finding: within cooldown, apply_taint takes the
        early-return path and does NOT reset clean_ops_since_taint. So an
        attacker interleaving sensor calls within cooldown can't prevent
        op-based decay — the clean ops keep accumulating.
        """
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        # 9 clean ops (not enough to decay)
        for _ in range(config.clean_ops_per_decay - 1):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.MEDIUM

        # Retaint within cooldown — clean counter NOT reset (good for security)
        state.apply_taint("sensor_0", config)
        assert state.clean_ops_since_taint == config.clean_ops_per_decay - 1

        # One more clean op pushes over the threshold → decay
        state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW

        # Cooldown retaint from LOW doesn't prevent the decay that happened
        # This means cooldown surfing + clean op interleaving can't hold at MEDIUM

    def test_interleaved_with_enough_clean_ops_decays(self, state, config):
        """If attacker doesn't retaint fast enough, clean ops win."""
        state.apply_taint("search_web", config)

        # 10 clean ops → decay to LOW
        for _ in range(config.clean_ops_per_decay):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW

        # Retaint from LOW → but apply_taint from LOW raises by one = MEDIUM
        state.last_taint_event = time.time() - config.retaint_cooldown_seconds - 1
        state.apply_taint("second_search", config)
        assert state.level == TaintLevel.MEDIUM  # Not HIGH, started from LOW

    def test_real_world_attack_sequence(self, state, fast_config):
        """Simulate a realistic attack: search, read results, wait, exfil.

        Uses fast_config with real time.sleep for realistic timing.
        """
        config = fast_config

        # Phase 1: Read data (2 sensor calls, spaced past cooldown)
        state.apply_taint("search_web", config)
        assert state.level == TaintLevel.MEDIUM

        time.sleep(config.retaint_cooldown_seconds + 0.05)
        state.apply_taint("fetch_result", config)
        assert state.level == TaintLevel.HIGH
        assert state.should_amber(config)

        # Phase 2: Wait for one decay interval
        time.sleep(config.decay_interval_seconds + 0.05)
        state.apply_decay(config)
        assert state.level == TaintLevel.MEDIUM
        assert not state.should_amber(config)

        # Phase 3: Flood clean ops
        for _ in range(config.clean_ops_per_decay):
            state.apply_clean_op(config)
        assert state.level == TaintLevel.LOW

        # Phase 4: Wait for final decay
        time.sleep(config.decay_interval_seconds + 0.05)
        state.apply_decay(config)
        assert state.level == TaintLevel.NONE

        # Total attack time: ~1.2 seconds with fast_config
        # With production config (60s intervals): ~3+ minutes
        # This is detectable via telemetry patterns.


# ═══════════════════════════════════════════════════════
# 9. Config Boundary Testing
# ═══════════════════════════════════════════════════════

class TestConfigBoundaries:
    """Test extreme config values that could create vulnerabilities."""

    def test_zero_decay_interval_no_crash(self):
        """Zero decay interval shouldn't cause division by zero."""
        config = TaintDecayConfig(decay_interval_seconds=0.0)
        state = TaintState()
        state.apply_taint("test", config)
        # With 0 interval, any elapsed time = infinite levels of decay
        state.last_taint_event = time.time() - 1
        # Should not crash — just decay to NONE
        result = state.apply_decay(config)
        # Implementation note: int(elapsed / 0.0) would be ZeroDivisionError
        # if not handled. This test catches that.

    def test_zero_clean_ops_per_decay(self):
        """Zero clean_ops_per_decay shouldn't cause infinite loop."""
        config = TaintDecayConfig(clean_ops_per_decay=0)
        state = TaintState()
        state.apply_taint("test", config)
        # With 0 ops per decay, every clean op would trigger decay?
        # Or should it be ignored? This tests the implementation.
        result = state.apply_clean_op(config)
        # Should not crash or infinite loop

    def test_very_long_cooldown(self):
        """Very long cooldown means escalation is nearly impossible."""
        config = TaintDecayConfig(retaint_cooldown_seconds=3600.0)  # 1 hour
        state = TaintState()
        state.apply_taint("search_web", config)
        state.apply_taint("fetch_url", config)
        # Second call within cooldown — no escalation
        assert state.level == TaintLevel.MEDIUM

    def test_very_short_cooldown_allows_rapid_escalation(self):
        """Very short cooldown allows rapid escalation to CRITICAL."""
        config = TaintDecayConfig(retaint_cooldown_seconds=0.001)
        state = TaintState()

        state.apply_taint("t1", config)
        time.sleep(0.01)
        state.apply_taint("t2", config)
        time.sleep(0.01)
        state.apply_taint("t3", config)

        assert state.level == TaintLevel.CRITICAL
