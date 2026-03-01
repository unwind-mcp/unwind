"""Tests for CRIP — Consentful Rhythm Inference Protocol."""

import unittest

from cadence.protocol.crip import (
    CRIP_VERSION,
    ConsentScope,
    CRIPHeaders,
    RetentionPolicy,
)


class TestCRIPHeaders(unittest.TestCase):
    """Test CRIP header generation and validation."""

    def test_default_headers(self):
        h = CRIPHeaders()
        self.assertEqual(h.consent_scope, ConsentScope.LOCAL_ONLY)
        self.assertEqual(h.retention, RetentionPolicy.ROLLING_7D)
        self.assertEqual(h.audit, "v1")
        self.assertTrue(h.deletable)

    def test_validate_defaults_pass(self):
        h = CRIPHeaders()
        self.assertIsNone(h.validate())

    def test_to_pulse_dict(self):
        h = CRIPHeaders()
        d = h.to_pulse_dict()
        self.assertEqual(d["consent_scope"], "local_only")
        self.assertEqual(d["crip_version"], "v1")
        self.assertNotIn("retention", d)  # not in pulse entries

    def test_to_state_dict(self):
        h = CRIPHeaders()
        d = h.to_state_dict()
        self.assertEqual(d["CONSENT"], "local_only")
        self.assertEqual(d["RETENTION"], "rolling_7d")
        self.assertEqual(d["AUDIT"], "v1")

    def test_custom_consent_scope(self):
        h = CRIPHeaders(consent_scope=ConsentScope.PRIVATE_CLOUD)
        d = h.to_pulse_dict()
        self.assertEqual(d["consent_scope"], "private_cloud")

    def test_custom_retention(self):
        h = CRIPHeaders(retention=RetentionPolicy.SESSION_ONLY)
        d = h.to_state_dict()
        self.assertEqual(d["RETENTION"], "session_only")

    def test_all_consent_scopes(self):
        for scope in ConsentScope:
            h = CRIPHeaders(consent_scope=scope)
            self.assertIsNone(h.validate())

    def test_all_retention_policies(self):
        for policy in RetentionPolicy:
            h = CRIPHeaders(retention=policy)
            self.assertIsNone(h.validate())

    def test_frozen_immutable(self):
        h = CRIPHeaders()
        with self.assertRaises(AttributeError):
            h.consent_scope = ConsentScope.PRIVATE_CLOUD


if __name__ == "__main__":
    unittest.main()
