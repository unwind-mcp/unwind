"""Regression lock-in for URL-vs-path handling in self-protection.

Bug class prevented by this suite:
- URL targets (e.g. https://evil.com) being treated as local filesystem paths
  and resolved under workspace/protected roots, causing false
  "System Core Protected" blocks.

This suite asserts:
1) URL targets with :// never enter SelfProtectionCheck.check_path()
2) Local file paths still use path resolution and remain protected
3) Pipeline handling of URL-like targets does not regress to
   "System Core Protected" path-locker blocks
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from unwind.config import UnwindConfig
from unwind.enforcement.pipeline import CheckResult, EnforcementPipeline
from unwind.enforcement.self_protection import SelfProtectionCheck
from unwind.session import Session


def _make_config() -> UnwindConfig:
    tmp = Path(tempfile.mkdtemp(prefix="unwind-url-reg-"))
    cfg = UnwindConfig(
        unwind_home=tmp / ".unwind",
        workspace_root=tmp / "workspace",
    )
    cfg.ensure_dirs()
    cfg.workspace_root.mkdir(parents=True, exist_ok=True)
    return cfg


class TestSelfProtectionUrlSkipContract(unittest.TestCase):
    """URL targets must skip path canonicalization in self-protection."""

    def setUp(self):
        self.config = _make_config()
        self.check = SelfProtectionCheck(self.config)

    def _assert_url_skips_check_path(self, target: str) -> None:
        with patch.object(self.check, "check_path", wraps=self.check.check_path) as spy:
            result = self.check.check("http_get", target=target)
            self.assertIsNone(
                result,
                msg=f"Expected self-protection to skip URL target, got: {result}",
            )
            spy.assert_not_called()

    def test_standard_schemes_skip_path_resolution(self):
        targets = [
            "https://evil.com",
            "http://evil.com/path",
            "ftp://files.example.com/download.txt",
            "file:///etc/passwd",
        ]
        for target in targets:
            with self.subTest(target=target):
                self._assert_url_skips_check_path(target)

    def test_edge_case_urls_skip_path_resolution(self):
        # Includes local-looking URL paths, encoded colons, and mixed slashes.
        targets = [
            "https://evil.com/home/dandare/.openclaw/events.db",
            "https://evil.com/Users/alice/.openclaw/events.db",
            "https://evil.com/%2Fhome%2Fdandare%2F.openclaw%2Fevents.db",
            "https://evil.com/path%3Awith%3Aencoded%3Acolons",
            "https://evil.com\\mixed\\slashes\\..\\payload",
            "HTTP://EVIL.COM/path",
        ]
        for target in targets:
            with self.subTest(target=target):
                self._assert_url_skips_check_path(target)

    def test_local_paths_still_use_path_resolution(self):
        protected = str(self.config.events_db_path)
        safe = str(self.config.workspace_root / "notes.txt")

        with patch.object(self.check, "check_path", wraps=self.check.check_path) as spy:
            blocked = self.check.check("fs_read", target=protected)
            allowed = self.check.check("fs_read", target=safe)

            self.assertIsNotNone(blocked)
            self.assertIn("System Core Protected", blocked)
            self.assertIsNone(allowed)
            self.assertGreaterEqual(spy.call_count, 2)


class TestPipelinePathUrlRegression(unittest.TestCase):
    """Pipeline should never report URL targets as local protected-path hits."""

    def setUp(self):
        self.config = _make_config()
        self.pipeline = EnforcementPipeline(self.config)
        self.session = Session(session_id="sess-url-reg", config=self.config)

        # Isolate this suite from DNS/network-specific behaviour so we only
        # test URL-vs-path regression mechanics.
        self.pipeline.ssrf_shield.check = lambda target: None  # type: ignore[assignment]
        self.pipeline.egress_policy.check = lambda target: None  # type: ignore[assignment]

    def _check_no_system_core_protected(self, target: str) -> None:
        result = self.pipeline.check(
            session=self.session,
            tool_name="http_get",
            target=target,
            parameters={"url": target},
        )
        self.assertEqual(
            result.action,
            CheckResult.ALLOW,
            msg=f"Expected ALLOW for isolated URL/path regression test. got={result.action} reason={result.block_reason}",
        )
        if result.block_reason:
            self.assertNotIn("System Core Protected", result.block_reason)

    def test_url_targets_do_not_regress_to_system_core_protected(self):
        targets = [
            "https://evil.com",
            "http://evil.com/path",
            "ftp://files.example.com/download.txt",
            "file:///etc/passwd",
            "https://evil.com/home/dandare/.openclaw/events.db",
            "https://evil.com/Users/alice/.openclaw/events.db",
            "https://evil.com/path%3Awith%3Aencoded%3Acolons",
            "https://evil.com\\mixed\\slashes\\..\\payload",
            "http:///etc/passwd",
        ]
        for target in targets:
            with self.subTest(target=target):
                self._check_no_system_core_protected(target)


if __name__ == "__main__":
    unittest.main()
