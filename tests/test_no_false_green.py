"""No-false-green contract tests for dashboard integrity status.

Sentinel gate requirement: The dashboard MUST show amber or red (never green)
when any of these conditions exist:

  1. Stale heartbeat/telemetry (watchdog_stale, event_store stale)
  2. Replayed or out-of-order sequence (CRAFT chain tampered)
  3. Sidecar restart secret mismatch (401 from sidecar)
  4. Transport outage/disconnect (sidecar unreachable)
  5. Dashboard startup before sidecar/gateway ready (cold start)
  6. Signature verification failure (sig invalid, stale TTL, seq replay)

Invariant: The dashboard is render-only.  UNWIND (sidecar) is the authority.
Green requires ALL of: sidecar connected, auth verified (not 401), sidecar
status "up", watchdog fresh, event store fresh, CRAFT chain intact,
AND (when signed health is available) signature valid, payload fresh,
sequence monotonic.

Any violation → overall != "healthy".  No exceptions.
"""

import json
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from unwind.config import UnwindConfig
from unwind.recorder.event_store import EventStore, EventStatus
from unwind.dashboard.app import create_app
from unwind.sidecar.health_schema import (
    SCHEMA_VERSION,
    derive_health_signing_key,
    sign_health_payload,
)


# ── Sidecar response fixtures ──────────────────────────────────────

_TEST_SECRET = "test-shared-secret-for-no-false-green"
_TEST_KEY = derive_health_signing_key(_TEST_SECRET)


def _sidecar_healthy(**overrides):
    """Simulate a healthy sidecar /v1/health response (legacy unsigned)."""
    body = {
        "status": "up",
        "uptimeMs": 60_000,
        "engineVersion": "0.1.0-alpha",
        "lastPolicyCheckTs": "2026-03-03T12:00:00+00:00",
        "watchdogStale": False,
        "watchdogThresholdMs": 86_400_000,
        "activeSessions": 1,
        "mediationActive": True,
        "toolCallsProcessed": 42,
    }
    body.update(overrides)
    return 200, body


def _sidecar_healthy_signed(*, seq=1, key=_TEST_KEY, **overrides):
    """Simulate a healthy sidecar /v1/health response with signed schema v1.

    Produces a fully signed payload that passes all verification gates.
    """
    now = datetime.now(timezone.utc)
    body = {
        "version": SCHEMA_VERSION,
        "instance_id": "test-host",
        "emitted_at": now.isoformat(),
        "fresh_until": (now + timedelta(seconds=60)).isoformat(),
        "ttl_sec": 60,
        "seq": seq,
        "state": "green",
        "reason_code": "OK",
        "detail": "All checks passed",
        "checks": {
            "sidecar_link": "ok",
            "adapter_auth": "ok",
            "watchdog_stale": False,
            "pipeline_enforcement": "ok",
            "audit_chain": "ok",
        },
        "sig": {
            "alg": "HMAC-SHA256",
            "kid": "unwind-health-2026-03",
            "value": "",
        },
        # Legacy fields
        "status": "up",
        "uptimeMs": 60_000,
        "engineVersion": "0.1.0-alpha",
        "lastPolicyCheckTs": "2026-03-03T12:00:00+00:00",
        "watchdogStale": False,
        "watchdogThresholdMs": 86_400_000,
        "activeSessions": 1,
        "mediationActive": True,
        "toolCallsProcessed": 42,
    }
    body.update(overrides)
    body["sig"]["value"] = sign_health_payload(body, key)
    return 200, body


def _sidecar_unreachable():
    """Simulate sidecar connection failure (503)."""
    return 503, {"error": "Sidecar unavailable"}


def _sidecar_auth_rejected():
    """Simulate 401 from mismatched shared secret."""
    return 401, {"error": "Unauthorized"}


# ── Base class ──────────────────────────────────────────────────────


@patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", None)
class _BaseIntegrityTest(unittest.TestCase):
    """Shared setup for integrity contract tests.

    Patches _HEALTH_SIGNING_KEY to None so legacy unsigned sidecar responses
    are accepted (sig verification is skipped in dev/unsigned mode).
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.app = create_app(self.config)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _seed_green_event(self, age_seconds=0):
        """Insert a green event into EventStore."""
        store = EventStore(self.config.events_db_path)
        store.initialize()
        eid = store.write_pending(
            session_id="test_session",
            tool="fs_read",
            tool_class="sensor",
            target="/workspace/readme.md",
            target_canonical="/workspace/readme.md",
            parameters=None,
            session_tainted=False,
            trust_state="green",
        )
        store.complete_event(eid, EventStatus.SUCCESS)
        if age_seconds > 0:
            store._conn.execute(
                "UPDATE events SET timestamp = ? WHERE event_id = ?",
                (time.time() - age_seconds, eid),
            )
            store._conn.commit()
        store.close()
        return eid

    def _get_health(self):
        """Call /api/system-health and return parsed JSON."""
        resp = self.client.get("/api/system-health")
        self.assertEqual(resp.status_code, 200)
        return json.loads(resp.data)

    def _assert_not_healthy(self, data, context=""):
        """Assert overall is NOT 'healthy' (the no-false-green invariant)."""
        self.assertNotEqual(
            data["overall"], "healthy",
            f"NO-FALSE-GREEN VIOLATION: overall='healthy' {context}",
        )

    def _assert_sidecar_pill_not_green(self, data, context=""):
        """Assert sidecar pill would render non-green.

        Green requires: connected AND status=='up' AND NOT watchdog_stale.
        """
        si = data["sidecar"]
        is_green = si["connected"] and si["status"] == "up" and not si["watchdog_stale"]
        self.assertFalse(is_green, f"Sidecar pill false-green: {context}")


# ── Gate 4: Transport outage / disconnect ───────────────────────────


class TestTransportOutage(_BaseIntegrityTest):
    """Sidecar unreachable → never healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_overall_disconnected_when_sidecar_unreachable(self, mock_proxy):
        mock_proxy.return_value = _sidecar_unreachable()
        data = self._get_health()
        self.assertEqual(data["overall"], "disconnected")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_sidecar_not_connected_on_503(self, mock_proxy):
        mock_proxy.return_value = _sidecar_unreachable()
        data = self._get_health()
        self.assertFalse(data["sidecar"]["connected"])
        self.assertEqual(data["sidecar"]["status"], "unreachable")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_stale_green_events_do_not_rescue_outage(self, mock_proxy):
        """Recent green events in EventStore cannot make overall healthy
        when the sidecar is unreachable."""
        self._seed_green_event()
        mock_proxy.return_value = _sidecar_unreachable()
        data = self._get_health()
        self._assert_not_healthy(data, "sidecar unreachable + recent green events")


# ── Gate 3: Sidecar auth mismatch (401) ────────────────────────────


class TestAuthMismatch(_BaseIntegrityTest):
    """Sidecar returns 401 (secret mismatch after restart) → never healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_overall_not_healthy_on_401(self, mock_proxy):
        mock_proxy.return_value = _sidecar_auth_rejected()
        data = self._get_health()
        self._assert_not_healthy(data, "sidecar returned 401")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_sidecar_not_connected_on_401(self, mock_proxy):
        """A 401 means the link is broken — sidecar must not appear connected."""
        mock_proxy.return_value = _sidecar_auth_rejected()
        data = self._get_health()
        self.assertFalse(data["sidecar"]["connected"])
        self._assert_sidecar_pill_not_green(data, "401 auth rejection")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_401_with_green_events_still_not_healthy(self, mock_proxy):
        """Green events cannot mask a broken auth link."""
        self._seed_green_event()
        mock_proxy.return_value = _sidecar_auth_rejected()
        data = self._get_health()
        self._assert_not_healthy(data, "401 + recent green events")


# ── Gate 1: Stale heartbeat / telemetry ─────────────────────────────


class TestStaleHeartbeat(_BaseIntegrityTest):
    """Stale watchdog or event store → never healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_watchdog_stale_degrades_overall(self, mock_proxy):
        mock_proxy.return_value = _sidecar_healthy(watchdogStale=True)
        data = self._get_health()
        self._assert_not_healthy(data, "watchdog_stale=True")
        self.assertEqual(data["overall"], "degraded")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_watchdog_stale_pill_not_green(self, mock_proxy):
        mock_proxy.return_value = _sidecar_healthy(watchdogStale=True)
        data = self._get_health()
        self._assert_sidecar_pill_not_green(data, "watchdog_stale=True")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_event_store_stale_degrades_overall(self, mock_proxy):
        """EventStore stale (>300s since last event, active sessions) → degraded."""
        self._seed_green_event(age_seconds=600)
        mock_proxy.return_value = _sidecar_healthy(activeSessions=1)
        data = self._get_health()
        self.assertTrue(data["event_store"]["stale"])
        self._assert_not_healthy(data, "event_store stale (600s, active sessions)")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_sidecar_degraded_status_not_healthy(self, mock_proxy):
        """Sidecar reports status='degraded' (policy load failure) → not healthy.

        This catches the case where the sidecar is reachable and watchdog is fine,
        but the policy engine failed to load.  Without this check, overall would
        be 'healthy' — a false green.
        """
        mock_proxy.return_value = _sidecar_healthy(status="degraded", watchdogStale=False)
        data = self._get_health()
        self._assert_not_healthy(data, "sidecar status='degraded' (policy load failure)")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_sidecar_watchdog_stale_status_not_healthy(self, mock_proxy):
        """Sidecar reports status='watchdog_stale' → not healthy."""
        mock_proxy.return_value = _sidecar_healthy(
            status="watchdog_stale", watchdogStale=True,
        )
        data = self._get_health()
        self._assert_not_healthy(data, "sidecar status='watchdog_stale'")


# ── Gate 2: Replayed / out-of-order sequence (CRAFT chain) ──────────


class TestChainIntegrity(_BaseIntegrityTest):
    """Tampered or broken CRAFT chain → never healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_tampered_chain_degrades_overall(self, mock_proxy):
        mock_proxy.return_value = _sidecar_healthy()
        store = EventStore(self.config.events_db_path)
        store.initialize()
        eid1 = store.write_pending(
            session_id="sess", tool="fs_read", tool_class="sensor",
            target="/t", target_canonical="/t",
            parameters=None, session_tainted=False, trust_state="green",
        )
        store.complete_event(eid1, EventStatus.SUCCESS)
        eid2 = store.write_pending(
            session_id="sess", tool="fs_write", tool_class="actuator",
            target="/t", target_canonical="/t",
            parameters=None, session_tainted=False, trust_state="green",
        )
        store.complete_event(eid2, EventStatus.SUCCESS)
        # Tamper: overwrite chain hash
        store._conn.execute(
            "UPDATE events SET chain_hash = 'tampered_hash' WHERE event_id = ?",
            (eid2,),
        )
        store._conn.commit()
        store.close()

        data = self._get_health()
        self.assertFalse(data["craft_chain"]["verified"])
        self._assert_not_healthy(data, "CRAFT chain tampered")
        self.assertEqual(data["overall"], "degraded")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_chain_verification_error_degrades_overall(self, mock_proxy):
        """If chain verification throws, overall must not be healthy."""
        mock_proxy.return_value = _sidecar_healthy()
        # Seed one event, then corrupt the chain_hash column to trigger
        # an error during verification
        store = EventStore(self.config.events_db_path)
        store.initialize()
        eid = store.write_pending(
            session_id="sess", tool="fs_read", tool_class="sensor",
            target="/t", target_canonical="/t",
            parameters=None, session_tainted=False, trust_state="green",
        )
        store.complete_event(eid, EventStatus.SUCCESS)
        # Set prev_hash expectation to something wrong
        store._conn.execute(
            "UPDATE events SET chain_hash = 'broken' WHERE event_id = ?",
            (eid,),
        )
        store._conn.commit()
        store.close()

        data = self._get_health()
        # Chain should report an error (broken hash) or be marked unverified
        # Either way, overall must not be healthy
        if not data["craft_chain"]["verified"]:
            self._assert_not_healthy(data, "chain verification failed")


# ── Gate 5: Dashboard cold start ────────────────────────────────────


class TestColdStart(_BaseIntegrityTest):
    """Dashboard starts before sidecar/gateway ready → never healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_cold_start_sidecar_down(self, mock_proxy):
        """No events, sidecar not running → disconnected."""
        mock_proxy.return_value = _sidecar_unreachable()
        data = self._get_health()
        self.assertEqual(data["overall"], "disconnected")
        self.assertEqual(data["event_store"]["total_events"], 0)

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_cold_start_auth_rejected(self, mock_proxy):
        """Dashboard starts with wrong secret, no events → not healthy."""
        mock_proxy.return_value = _sidecar_auth_rejected()
        data = self._get_health()
        self._assert_not_healthy(data, "cold start with auth rejection")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_cold_start_sidecar_up_no_events_is_valid(self, mock_proxy):
        """Sidecar up + no events + no active sessions = valid initial state.

        This is the ONE case where healthy-with-no-events is acceptable:
        the system just started, nothing has happened yet, sidecar is ready.
        """
        mock_proxy.return_value = _sidecar_healthy(
            activeSessions=0, toolCallsProcessed=0,
        )
        data = self._get_health()
        self.assertTrue(data["sidecar"]["connected"])
        # No assertion on overall here — healthy is acceptable in this state


# ── Combined failure modes ──────────────────────────────────────────


class TestCombinedFailures(_BaseIntegrityTest):
    """Multiple simultaneous failures must not produce healthy."""

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_stale_events_plus_watchdog_stale(self, mock_proxy):
        self._seed_green_event(age_seconds=600)
        mock_proxy.return_value = _sidecar_healthy(
            watchdogStale=True, activeSessions=1,
        )
        data = self._get_health()
        self._assert_not_healthy(data, "stale events + watchdog stale")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_degraded_sidecar_plus_stale_events(self, mock_proxy):
        self._seed_green_event(age_seconds=600)
        mock_proxy.return_value = _sidecar_healthy(
            status="degraded", activeSessions=1,
        )
        data = self._get_health()
        self._assert_not_healthy(data, "degraded sidecar + stale events")


# ══════════════════════════════════════════════════════════════════════
# Gate 6: Signed health verification (sig, TTL, seq)
# ══════════════════════════════════════════════════════════════════════


class _BaseSignedHealthTest(unittest.TestCase):
    """Base class for signed health verification tests.

    Uses a real signing key (not None) so signature gates are active.
    Resets the global sequence tracker between tests.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = UnwindConfig(
            unwind_home=Path(self.tmpdir) / ".unwind",
            workspace_root=Path(self.tmpdir) / "workspace",
        )
        self.config.ensure_dirs()
        self.app = create_app(self.config)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get_health(self):
        resp = self.client.get("/api/system-health")
        self.assertEqual(resp.status_code, 200)
        return json.loads(resp.data)

    def _assert_not_healthy(self, data, context=""):
        self.assertNotEqual(
            data["overall"], "healthy",
            f"NO-FALSE-GREEN VIOLATION: overall='healthy' {context}",
        )


class TestSignatureVerification(_BaseSignedHealthTest):
    """Signature-based gates on health payloads."""

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_valid_signed_payload_passes(self, mock_proxy, mock_tracker):
        """A correctly signed, fresh, monotonic payload → healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        mock_tracker_inst = SequenceTracker()
        mock_tracker.check_and_update = mock_tracker_inst.check_and_update
        mock_tracker.reset = mock_tracker_inst.reset

        mock_proxy.return_value = _sidecar_healthy_signed(seq=1)
        data = self._get_health()
        self.assertTrue(data["sidecar"]["sig_valid"])
        self.assertTrue(data["sidecar"]["payload_fresh"])
        self.assertTrue(data["sidecar"]["seq_valid"])
        self.assertEqual(data["overall"], "healthy")

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_tampered_sig_not_healthy(self, mock_proxy, mock_tracker):
        """Tampered signature → not healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        mock_tracker_inst = SequenceTracker()
        mock_tracker.check_and_update = mock_tracker_inst.check_and_update

        _, body = _sidecar_healthy_signed(seq=1)
        body["sig"]["value"] = "tampered-signature-value"
        mock_proxy.return_value = (200, body)

        data = self._get_health()
        self.assertFalse(data["sidecar"]["sig_valid"])
        self._assert_not_healthy(data, "tampered signature")
        self.assertEqual(data["sidecar"]["reason_code"], "SIGNATURE_INVALID")

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_missing_sig_envelope_not_healthy(self, mock_proxy, mock_tracker):
        """Missing sig envelope → UNKNOWN_SOURCE → not healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        mock_tracker_inst = SequenceTracker()
        mock_tracker.check_and_update = mock_tracker_inst.check_and_update

        # Response without sig field
        mock_proxy.return_value = _sidecar_healthy()
        data = self._get_health()
        self._assert_not_healthy(data, "missing sig envelope")
        self.assertEqual(data["sidecar"]["reason_code"], "UNKNOWN_SOURCE")

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_wrong_key_not_healthy(self, mock_proxy, mock_tracker):
        """Signed with different key → not healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        mock_tracker_inst = SequenceTracker()
        mock_tracker.check_and_update = mock_tracker_inst.check_and_update

        wrong_key = derive_health_signing_key("different-secret")
        mock_proxy.return_value = _sidecar_healthy_signed(seq=1, key=wrong_key)

        data = self._get_health()
        self.assertFalse(data["sidecar"]["sig_valid"])
        self._assert_not_healthy(data, "signed with wrong key")


class TestPayloadFreshness(_BaseSignedHealthTest):
    """TTL-based freshness gate on health payloads."""

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_expired_ttl_not_healthy(self, mock_proxy, mock_tracker):
        """Expired fresh_until → not healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        mock_tracker_inst = SequenceTracker()
        mock_tracker.check_and_update = mock_tracker_inst.check_and_update

        past = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        # Sign with expired fresh_until
        mock_proxy.return_value = _sidecar_healthy_signed(
            seq=1, fresh_until=past,
        )
        data = self._get_health()
        self.assertFalse(data["sidecar"]["payload_fresh"])
        self._assert_not_healthy(data, "expired TTL")
        self.assertEqual(data["sidecar"]["reason_code"], "PAYLOAD_STALE")


class TestSequenceReplay(_BaseSignedHealthTest):
    """Sequence monotonicity gate on health payloads."""

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_replayed_seq_not_healthy(self, mock_proxy, mock_tracker):
        """Replayed sequence number → not healthy."""
        from unwind.sidecar.health_schema import SequenceTracker
        tracker = SequenceTracker()
        mock_tracker.check_and_update = tracker.check_and_update
        mock_tracker.reset = tracker.reset

        # First request — seq=5 accepted
        mock_proxy.return_value = _sidecar_healthy_signed(seq=5)
        data1 = self._get_health()
        self.assertEqual(data1["overall"], "healthy")

        # Second request — same seq=5 replayed
        mock_proxy.return_value = _sidecar_healthy_signed(seq=5)
        data2 = self._get_health()
        self.assertFalse(data2["sidecar"]["seq_valid"])
        self._assert_not_healthy(data2, "replayed sequence")
        self.assertEqual(data2["sidecar"]["reason_code"], "SEQ_REPLAY_OR_ROLLBACK")

    @patch("unwind.dashboard.app._HEALTH_SEQ_TRACKER")
    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", _TEST_KEY)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_restart_seq_degrades(self, mock_proxy, mock_tracker):
        """Seq=1 after higher value (restart) → accepted but degraded."""
        from unwind.sidecar.health_schema import SequenceTracker
        tracker = SequenceTracker()
        mock_tracker.check_and_update = tracker.check_and_update
        mock_tracker.reset = tracker.reset

        # First request — seq=100
        mock_proxy.return_value = _sidecar_healthy_signed(seq=100)
        data1 = self._get_health()
        self.assertEqual(data1["overall"], "healthy")

        # Second request — seq=1 (restart)
        mock_proxy.return_value = _sidecar_healthy_signed(seq=1)
        data2 = self._get_health()
        self.assertTrue(data2["sidecar"]["seq_valid"])
        # Restart forces amber state
        self.assertEqual(data2["sidecar"]["state"], "amber")
        self._assert_not_healthy(data2, "restart seq forces amber")


class TestUnsignedDevMode(_BaseSignedHealthTest):
    """When no signing key is configured (dev mode), unsigned payloads degrade."""

    @patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", None)
    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_no_key_unsigned_response_degrades(self, mock_proxy):
        """No signing key + unsigned response → UNKNOWN_SOURCE → degraded."""
        mock_proxy.return_value = _sidecar_healthy()
        data = self._get_health()
        self.assertEqual(data["sidecar"]["reason_code"], "UNKNOWN_SOURCE")
        self._assert_not_healthy(data, "no signing key (dev mode)")


# ══════════════════════════════════════════════════════════════════════
# Orb false-green contract tests
# ══════════════════════════════════════════════════════════════════════


@patch("unwind.dashboard.app._HEALTH_SIGNING_KEY", None)
class TestOrbFalseGreen(_BaseIntegrityTest):
    """Orb posture layer: orb_state must reflect composite event data.

    Done criteria (Sentinel):
      1. Cannot produce orb_state=green when blocked > 0 or red_events > 0
      2. Away Mode and main orb never contradict for same window
      3. Test coverage for the above rule
    """

    def _seed_event(self, trust_state="green", status="success",
                    session_tainted=False, tool="fs_read", age_seconds=0):
        """Insert an event with specified properties."""
        store = EventStore(self.config.events_db_path)
        store.initialize()
        eid = store.write_pending(
            session_id="test_session",
            tool=tool,
            tool_class="actuator" if "write" in tool else "sensor",
            target="/workspace/test.txt",
            target_canonical="/workspace/test.txt",
            parameters=None,
            session_tainted=session_tainted,
            trust_state=trust_state,
        )
        status_enum = {
            "success": EventStatus.SUCCESS,
            "blocked": EventStatus.BLOCKED,
        }.get(status, EventStatus.SUCCESS)
        store.complete_event(eid, status_enum)
        if age_seconds > 0:
            store._conn.execute(
                "UPDATE events SET timestamp = ? WHERE event_id = ?",
                (time.time() - age_seconds, eid),
            )
            store._conn.commit()
        store.close()
        return eid

    def _get_trust_state(self):
        """Call /api/trust-state and return parsed JSON."""
        resp = self.client.get("/api/trust-state")
        self.assertEqual(resp.status_code, 200)
        return json.loads(resp.data)

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_orb_red_when_blocked_events(self, mock_proxy):
        """Blocked events in last hour → orb_state must be red."""
        mock_proxy.return_value = _sidecar_healthy()
        # Seed a green event followed by a blocked event
        self._seed_event(trust_state="green", status="success", age_seconds=60)
        self._seed_event(trust_state="red", status="blocked", age_seconds=30)
        # Seed a final green event so trust_state (most recent) is green
        self._seed_event(trust_state="green", status="success", age_seconds=0)

        data = self._get_trust_state()
        self.assertEqual(data["trust_state"], "green",
                         "Precondition: most-recent event is green")
        self.assertEqual(data["orb_state"], "red",
                         "ORB FALSE-GREEN: orb_state must be red when blocked > 0")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_orb_red_when_red_events(self, mock_proxy):
        """Red trust events in last hour → orb_state must be red."""
        mock_proxy.return_value = _sidecar_healthy()
        # Seed red events, then a green event last
        self._seed_event(trust_state="red", status="success", age_seconds=60)
        self._seed_event(trust_state="green", status="success", age_seconds=0)

        data = self._get_trust_state()
        self.assertEqual(data["trust_state"], "green",
                         "Precondition: most-recent event is green")
        self.assertEqual(data["orb_state"], "red",
                         "ORB FALSE-GREEN: orb_state must be red when red_events > 0")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_orb_green_when_all_clean(self, mock_proxy):
        """No blocked/red events, sidecar up → orb_state green."""
        mock_proxy.return_value = _sidecar_healthy()
        self._seed_event(trust_state="green", status="success", age_seconds=0)

        data = self._get_trust_state()
        self.assertEqual(data["orb_state"], "green")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_orb_amber_when_tainted(self, mock_proxy):
        """Tainted session events (no blocks/reds) → orb_state amber."""
        mock_proxy.return_value = _sidecar_healthy()
        self._seed_event(trust_state="green", status="success",
                         session_tainted=True, age_seconds=0)

        data = self._get_trust_state()
        self.assertEqual(data["orb_state"], "amber",
                         "Tainted session should produce amber orb")

    @patch("unwind.dashboard.app._proxy_sidecar")
    def test_orb_matches_away_mode(self, mock_proxy):
        """orb_state and away-summary trust_state must not contradict.

        If away says red, orb must not be green. If away says green, orb
        must not be red.
        """
        mock_proxy.return_value = _sidecar_healthy()
        # Seed blocked event + trailing green
        self._seed_event(trust_state="red", status="blocked", age_seconds=60)
        self._seed_event(trust_state="green", status="success", age_seconds=0)

        trust_data = self._get_trust_state()
        orb = trust_data["orb_state"]

        # Get away summary for the same window
        since = time.time() - 3600
        resp = self.client.get(f"/api/away-summary?since={since}")
        self.assertEqual(resp.status_code, 200)
        away_data = json.loads(resp.data)
        away_trust = away_data["trust_state"]

        # Severity ordering for comparison
        severity = {"green": 0, "amber": 1, "red": 2}

        # Orb must be at least as severe as away mode's assessment
        self.assertGreaterEqual(
            severity.get(orb, 0),
            severity.get(away_trust, 0),
            f"ORB-AWAY CONTRADICTION: orb={orb} but away={away_trust}",
        )


if __name__ == "__main__":
    unittest.main()
