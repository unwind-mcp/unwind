"""P2-9: Canary randomisation hardening tests.

Ensures canary names are not static/enumerable across sessions while
preserving deterministic canary trip detection.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path

from unwind.config import UnwindConfig
from unwind.enforcement.canary import CanaryCheck
from unwind.enforcement.pipeline import CheckResult
from unwind.proxy import UnwindProxy


def _make_config() -> UnwindConfig:
    tmp = Path(tempfile.mkdtemp(prefix="unwind-canary-rot-"))
    cfg = UnwindConfig(
        unwind_home=tmp / ".unwind",
        workspace_root=tmp / "workspace",
    )
    cfg.ensure_dirs()
    cfg.workspace_root.mkdir(parents=True, exist_ok=True)
    return cfg


class TestCanaryRandomization(unittest.TestCase):
    """Canary visible names should rotate while detection remains reliable."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_names_change_between_sessions(self):
        config = _make_config()
        proxy = UnwindProxy(config)

        names_a = {t["name"] for t in proxy.get_tool_list(session_id="sess-A")}
        names_b = {t["name"] for t in proxy.get_tool_list(session_id="sess-B")}

        self.assertEqual(len(names_a), len(config.canary_tools))
        self.assertEqual(len(names_b), len(config.canary_tools))
        self.assertNotEqual(names_a, names_b)

        # Stable internal marker pattern with random suffix.
        self.assertTrue(all(CanaryCheck.DYNAMIC_MARKER in n for n in names_a))
        self.assertTrue(all(CanaryCheck.DYNAMIC_MARKER in n for n in names_b))

    def test_names_change_between_instances(self):
        config1 = _make_config()
        config2 = _make_config()
        proxy1 = UnwindProxy(config1)
        proxy2 = UnwindProxy(config2)

        names_1 = {t["name"] for t in proxy1.get_tool_list(session_id="sess-shared")}
        names_2 = {t["name"] for t in proxy2.get_tool_list(session_id="sess-shared")}

        self.assertNotEqual(names_1, names_2)

    def test_detection_still_fires_with_randomized_names(self):
        config = _make_config()
        proxy = UnwindProxy(config)
        config.ensure_dirs()
        proxy.event_store.initialize()

        sid = "sess-detect"
        dynamic_name = proxy.get_tool_list(session_id=sid)[0]["name"]

        async def _test():
            result = await proxy.handle_tool_call(
                tool_name=dynamic_name,
                parameters={},
                session_id=sid,
            )
            self.assertIn("error", result)
            self.assertIn("CANARY TRIGGERED", result["error"])
            self.assertTrue(proxy.sessions[sid].killed)

        try:
            self._run(_test())
        finally:
            proxy.event_store.close()

    def test_old_enumeration_list_does_not_help_next_session(self):
        config = _make_config()
        proxy = UnwindProxy(config)

        sid_a = "sess-enum-A"
        sid_b = "sess-enum-B"

        names_a = {t["name"] for t in proxy.get_tool_list(session_id=sid_a)}
        names_b = {t["name"] for t in proxy.get_tool_list(session_id=sid_b)}

        # Find at least one old name absent from the new session list.
        stale_name = next((name for name in names_a if name not in names_b), None)
        self.assertIsNotNone(stale_name)

        session_b = proxy.get_or_create_session(sid_b)

        stale_result = proxy.pipeline.check(session_b, stale_name)
        self.assertNotEqual(
            stale_result.action,
            CheckResult.KILL,
            msg="Old-session canary name should not kill in a new session",
        )

        current_name = next(iter(names_b))
        current_result = proxy.pipeline.check(session_b, current_name)
        self.assertEqual(current_result.action, CheckResult.KILL)


if __name__ == "__main__":
    unittest.main()
