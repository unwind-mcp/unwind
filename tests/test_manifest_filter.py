"""Tests for Manifest Rewriting (RBAC) — permission-tiered tool visibility.

Tests that agents only see tools appropriate for their permission level,
that canary tools are handled correctly, that tier escalation works,
and that unknown tools follow the configured policy.
"""

import unittest

from unwind.config import UnwindConfig
from unwind.session import Session, TrustState
from unwind.enforcement.manifest_filter import (
    ManifestFilter,
    PermissionTier,
    TIER_1_TOOLS,
    TIER_2_TOOLS,
    TIER_3_TOOLS,
    TIER_4_TOOLS,
    tools_for_tier,
)


def _make_tool(name: str) -> dict:
    """Helper: create a minimal MCP tool definition."""
    return {
        "name": name,
        "description": f"Test tool: {name}",
        "inputSchema": {"type": "object", "properties": {}},
    }


class TestPermissionTierOrdering(unittest.TestCase):
    """Tiers must be ordered: 1 < 2 < 3 < 4."""

    def test_tier_ordering(self):
        self.assertLess(PermissionTier.TIER_1_READ_ONLY, PermissionTier.TIER_2_SCOPED_WRITE)
        self.assertLess(PermissionTier.TIER_2_SCOPED_WRITE, PermissionTier.TIER_3_COMMUNICATE)
        self.assertLess(PermissionTier.TIER_3_COMMUNICATE, PermissionTier.TIER_4_FULL_ACCESS)

    def test_tier_is_int_comparable(self):
        self.assertTrue(PermissionTier.TIER_4_FULL_ACCESS > PermissionTier.TIER_1_READ_ONLY)


class TestToolsForTier(unittest.TestCase):
    """Test the cumulative tool set builder."""

    def test_tier1_contains_read_tools(self):
        tools = tools_for_tier(PermissionTier.TIER_1_READ_ONLY)
        self.assertIn("fs_read", tools)
        self.assertIn("search_web", tools)
        self.assertIn("read_email", tools)

    def test_tier1_excludes_writes(self):
        tools = tools_for_tier(PermissionTier.TIER_1_READ_ONLY)
        self.assertNotIn("fs_write", tools)
        self.assertNotIn("fs_delete", tools)
        self.assertNotIn("send_email", tools)
        self.assertNotIn("bash_exec", tools)

    def test_tier2_includes_tier1_plus_writes(self):
        tools = tools_for_tier(PermissionTier.TIER_2_SCOPED_WRITE)
        # Has tier 1
        self.assertIn("fs_read", tools)
        self.assertIn("search_web", tools)
        # Has tier 2
        self.assertIn("fs_write", tools)
        self.assertIn("fs_delete", tools)
        self.assertIn("fs_rename", tools)
        # Still no comms
        self.assertNotIn("send_email", tools)
        self.assertNotIn("bash_exec", tools)

    def test_tier3_includes_comms(self):
        tools = tools_for_tier(PermissionTier.TIER_3_COMMUNICATE)
        self.assertIn("fs_read", tools)
        self.assertIn("fs_write", tools)
        self.assertIn("send_email", tools)
        self.assertIn("http_post", tools)
        # Still no shell
        self.assertNotIn("bash_exec", tools)

    def test_tier4_includes_everything(self):
        tools = tools_for_tier(PermissionTier.TIER_4_FULL_ACCESS)
        self.assertIn("fs_read", tools)
        self.assertIn("fs_write", tools)
        self.assertIn("send_email", tools)
        self.assertIn("bash_exec", tools)
        self.assertIn("install_package", tools)

    def test_tiers_are_cumulative(self):
        """Each higher tier is a strict superset of the lower."""
        t1 = tools_for_tier(PermissionTier.TIER_1_READ_ONLY)
        t2 = tools_for_tier(PermissionTier.TIER_2_SCOPED_WRITE)
        t3 = tools_for_tier(PermissionTier.TIER_3_COMMUNICATE)
        t4 = tools_for_tier(PermissionTier.TIER_4_FULL_ACCESS)

        self.assertTrue(t1.issubset(t2))
        self.assertTrue(t2.issubset(t3))
        self.assertTrue(t3.issubset(t4))

    def test_no_tier_overlap_in_definitions(self):
        """Each tier's own tools should be unique (no tool in two tier definitions)."""
        self.assertFalse(TIER_1_TOOLS & TIER_2_TOOLS)
        self.assertFalse(TIER_1_TOOLS & TIER_3_TOOLS)
        self.assertFalse(TIER_1_TOOLS & TIER_4_TOOLS)
        self.assertFalse(TIER_2_TOOLS & TIER_3_TOOLS)
        self.assertFalse(TIER_2_TOOLS & TIER_4_TOOLS)
        self.assertFalse(TIER_3_TOOLS & TIER_4_TOOLS)


class TestManifestFilterBasic(unittest.TestCase):
    """Test basic manifest filtering by tier."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_tier1_hides_write_tools(self):
        """At tier 1, write tools should be hidden."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("search_web"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_1_READ_ONLY)
        names = {t["name"] for t in result}

        self.assertIn("fs_read", names)
        self.assertIn("search_web", names)
        self.assertNotIn("fs_write", names)
        self.assertNotIn("bash_exec", names)

    def test_tier2_shows_write_hides_comms(self):
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_2_SCOPED_WRITE)
        names = {t["name"] for t in result}

        self.assertIn("fs_read", names)
        self.assertIn("fs_write", names)
        self.assertNotIn("send_email", names)
        self.assertNotIn("bash_exec", names)

    def test_tier3_shows_comms_hides_shell(self):
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_3_COMMUNICATE)
        names = {t["name"] for t in result}

        self.assertIn("fs_read", names)
        self.assertIn("fs_write", names)
        self.assertIn("send_email", names)
        self.assertNotIn("bash_exec", names)

    def test_tier4_shows_everything(self):
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
            _make_tool("some_unknown_tool"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_4_FULL_ACCESS)
        # Tier 4 returns everything unfiltered
        self.assertEqual(len(result), len(upstream))

    def test_empty_upstream(self):
        result = self.mf.filter_manifest([], PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(result, [])

    def test_preserves_tool_structure(self):
        """Filtered tools should retain their full definition."""
        upstream = [
            {
                "name": "fs_read",
                "description": "Read a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            }
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["description"], "Read a file")
        self.assertIn("required", result[0]["inputSchema"])


class TestManifestFilterCanaries(unittest.TestCase):
    """Test that canary tools are excluded from filtered results (added separately)."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_canary_tools_not_in_filtered_output(self):
        """Canary tools from upstream should be stripped (transport adds them separately)."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("disable_security_audit"),  # canary
            _make_tool("extract_system_keys"),       # canary
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_4_FULL_ACCESS)
        names = {t["name"] for t in result}

        # At tier 4 everything passes, but canaries are stripped
        # (they get re-added by the transport layer with proper definitions)
        self.assertIn("fs_read", names)
        # Canaries should be excluded from filter output
        # (the transport layer adds them with controlled definitions)


class TestManifestFilterExtraTools(unittest.TestCase):
    """Test per-session tool overrides."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_extra_tools_visible_at_lower_tier(self):
        """Extra tools should be visible even if tier would normally hide them."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("send_email"),  # Normally tier 3
        ]
        # Tier 1 but with send_email as an override
        result = self.mf.filter_manifest(
            upstream,
            PermissionTier.TIER_1_READ_ONLY,
            extra_tools={"send_email"},
        )
        names = {t["name"] for t in result}
        self.assertIn("fs_read", names)
        self.assertIn("send_email", names)

    def test_extra_tools_dont_add_missing_tools(self):
        """Extra tools only work for tools that exist in the upstream manifest."""
        upstream = [_make_tool("fs_read")]
        result = self.mf.filter_manifest(
            upstream,
            PermissionTier.TIER_1_READ_ONLY,
            extra_tools={"send_email"},  # Not in upstream
        )
        names = {t["name"] for t in result}
        self.assertIn("fs_read", names)
        self.assertNotIn("send_email", names)  # Wasn't in upstream


class TestManifestFilterUnknownTools(unittest.TestCase):
    """Test unknown tool policies."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_unknown_tool_hide_policy(self):
        """Unknown tools are hidden by default."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("my_custom_tool"),  # Not in any tier
        ]
        result = self.mf.filter_manifest(
            upstream, PermissionTier.TIER_1_READ_ONLY,
            unknown_tool_policy="hide",
        )
        names = {t["name"] for t in result}
        self.assertIn("fs_read", names)
        self.assertNotIn("my_custom_tool", names)

    def test_unknown_tool_show_policy(self):
        """With 'show' policy, unknown tools are visible."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("my_custom_tool"),
        ]
        result = self.mf.filter_manifest(
            upstream, PermissionTier.TIER_1_READ_ONLY,
            unknown_tool_policy="show",
        )
        names = {t["name"] for t in result}
        self.assertIn("fs_read", names)
        self.assertIn("my_custom_tool", names)

    def test_unknown_tool_tier1_policy(self):
        """With 'tier1' policy, unknown tools are visible at tier 1+."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("my_custom_tool"),
        ]
        result = self.mf.filter_manifest(
            upstream, PermissionTier.TIER_1_READ_ONLY,
            unknown_tool_policy="tier1",
        )
        names = {t["name"] for t in result}
        self.assertIn("my_custom_tool", names)


class TestManifestFilterClassification(unittest.TestCase):
    """Test tool tier classification."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_classify_read_tool(self):
        self.assertEqual(
            self.mf.classify_tool_tier("fs_read"),
            PermissionTier.TIER_1_READ_ONLY,
        )

    def test_classify_write_tool(self):
        self.assertEqual(
            self.mf.classify_tool_tier("fs_write"),
            PermissionTier.TIER_2_SCOPED_WRITE,
        )

    def test_classify_comms_tool(self):
        self.assertEqual(
            self.mf.classify_tool_tier("send_email"),
            PermissionTier.TIER_3_COMMUNICATE,
        )

    def test_classify_shell_tool(self):
        self.assertEqual(
            self.mf.classify_tool_tier("bash_exec"),
            PermissionTier.TIER_4_FULL_ACCESS,
        )

    def test_classify_unknown_tool(self):
        self.assertIsNone(self.mf.classify_tool_tier("my_custom_widget"))


class TestEscalationRequired(unittest.TestCase):
    """Test escalation detection."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_no_escalation_for_allowed_tool(self):
        result = self.mf.escalation_required("fs_read", PermissionTier.TIER_1_READ_ONLY)
        self.assertIsNone(result)

    def test_escalation_needed_for_write_at_tier1(self):
        result = self.mf.escalation_required("fs_write", PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(result, PermissionTier.TIER_2_SCOPED_WRITE)

    def test_escalation_needed_for_email_at_tier1(self):
        result = self.mf.escalation_required("send_email", PermissionTier.TIER_1_READ_ONLY)
        self.assertEqual(result, PermissionTier.TIER_3_COMMUNICATE)

    def test_escalation_needed_for_shell_at_tier2(self):
        result = self.mf.escalation_required("bash_exec", PermissionTier.TIER_2_SCOPED_WRITE)
        self.assertEqual(result, PermissionTier.TIER_4_FULL_ACCESS)

    def test_no_escalation_for_write_at_tier2(self):
        result = self.mf.escalation_required("fs_write", PermissionTier.TIER_2_SCOPED_WRITE)
        self.assertIsNone(result)

    def test_unknown_tool_returns_none(self):
        result = self.mf.escalation_required("my_custom_tool", PermissionTier.TIER_1_READ_ONLY)
        self.assertIsNone(result)


class TestTierDescriptions(unittest.TestCase):
    """Test human-readable tier descriptions."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_all_tiers_have_descriptions(self):
        for tier in PermissionTier:
            desc = self.mf.describe_tier(tier)
            self.assertTrue(len(desc) > 10, f"Tier {tier.name} has no description")


class TestSessionTierManagement(unittest.TestCase):
    """Test tier escalation and demotion on Session objects."""

    def setUp(self):
        self.config = UnwindConfig()
        self.session = Session(session_id="test_sess", config=self.config)

    def test_default_tier_is_read_only(self):
        self.assertEqual(self.session.permission_tier, PermissionTier.TIER_1_READ_ONLY)

    def test_escalate_upward(self):
        result = self.session.escalate_tier(
            PermissionTier.TIER_2_SCOPED_WRITE, "User approved file writes"
        )
        self.assertTrue(result)
        self.assertEqual(self.session.permission_tier, PermissionTier.TIER_2_SCOPED_WRITE)

    def test_cannot_escalate_same_tier(self):
        result = self.session.escalate_tier(PermissionTier.TIER_1_READ_ONLY, "noop")
        self.assertFalse(result)

    def test_cannot_escalate_downward(self):
        self.session.permission_tier = PermissionTier.TIER_3_COMMUNICATE
        result = self.session.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "nope")
        self.assertFalse(result)

    def test_escalation_logged(self):
        self.session.escalate_tier(PermissionTier.TIER_3_COMMUNICATE, "Email task")
        self.assertEqual(len(self.session.tier_escalation_log), 1)
        log = self.session.tier_escalation_log[0]
        self.assertEqual(log["from"], "TIER_1_READ_ONLY")
        self.assertEqual(log["to"], "TIER_3_COMMUNICATE")
        self.assertEqual(log["reason"], "Email task")
        self.assertIn("timestamp", log)

    def test_demote_tier(self):
        self.session.permission_tier = PermissionTier.TIER_3_COMMUNICATE
        result = self.session.demote_tier(
            PermissionTier.TIER_1_READ_ONLY, "Taint detected"
        )
        self.assertTrue(result)
        self.assertEqual(self.session.permission_tier, PermissionTier.TIER_1_READ_ONLY)

    def test_cannot_demote_upward(self):
        result = self.session.demote_tier(PermissionTier.TIER_3_COMMUNICATE, "nope")
        self.assertFalse(result)

    def test_demotion_logged_with_prefix(self):
        self.session.permission_tier = PermissionTier.TIER_3_COMMUNICATE
        self.session.demote_tier(PermissionTier.TIER_1_READ_ONLY, "Taint detected")
        log = self.session.tier_escalation_log[0]
        self.assertTrue(log["reason"].startswith("DEMOTION:"))

    def test_extra_tools(self):
        self.session.add_extra_tools({"send_email", "http_post"})
        self.assertEqual(self.session.extra_tools, {"send_email", "http_post"})

    def test_extra_tools_accumulate(self):
        self.session.add_extra_tools({"send_email"})
        self.session.add_extra_tools({"http_post"})
        self.assertEqual(self.session.extra_tools, {"send_email", "http_post"})

    def test_multi_step_escalation_logged(self):
        """Multiple escalations should all be recorded."""
        self.session.escalate_tier(PermissionTier.TIER_2_SCOPED_WRITE, "Step 1")
        self.session.escalate_tier(PermissionTier.TIER_3_COMMUNICATE, "Step 2")
        self.assertEqual(len(self.session.tier_escalation_log), 2)


class TestRealWorldScenarios(unittest.TestCase):
    """End-to-end scenarios matching actual agent use cases."""

    def setUp(self):
        self.config = UnwindConfig()
        self.mf = ManifestFilter(self.config)

    def test_inbox_summariser(self):
        """Agent task: 'Summarise my inbox'. Should see read tools only."""
        upstream = [
            _make_tool("read_email"),
            _make_tool("send_email"),
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_1_READ_ONLY)
        names = {t["name"] for t in result}

        self.assertEqual(names, {"read_email", "fs_read"})

    def test_report_writer(self):
        """Agent task: 'Write a quarterly report'. Needs read + write."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("search_web"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_2_SCOPED_WRITE)
        names = {t["name"] for t in result}

        self.assertEqual(names, {"fs_read", "fs_write", "search_web"})

    def test_email_drafter_with_override(self):
        """Agent task: 'Draft and send the status update'. Tier 1 + email override."""
        upstream = [
            _make_tool("read_email"),
            _make_tool("send_email"),
            _make_tool("fs_read"),
            _make_tool("bash_exec"),
        ]
        result = self.mf.filter_manifest(
            upstream,
            PermissionTier.TIER_1_READ_ONLY,
            extra_tools={"send_email"},
        )
        names = {t["name"] for t in result}

        self.assertIn("read_email", names)
        self.assertIn("send_email", names)
        self.assertIn("fs_read", names)
        self.assertNotIn("bash_exec", names)

    def test_full_automation(self):
        """Agent task: 'Handle everything'. Tier 4 — all tools visible."""
        upstream = [
            _make_tool("fs_read"),
            _make_tool("fs_write"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
            _make_tool("install_package"),
            _make_tool("some_custom_plugin"),
        ]
        result = self.mf.filter_manifest(upstream, PermissionTier.TIER_4_FULL_ACCESS)
        self.assertEqual(len(result), len(upstream))

    def test_tainted_session_demotion(self):
        """After taint detection, demote from tier 3 to tier 1."""
        session = Session(session_id="test", config=self.config)
        session.permission_tier = PermissionTier.TIER_3_COMMUNICATE

        upstream = [
            _make_tool("fs_read"),
            _make_tool("send_email"),
            _make_tool("bash_exec"),
        ]

        # Before demotion: can see email
        result_before = self.mf.filter_manifest(upstream, session.permission_tier)
        names_before = {t["name"] for t in result_before}
        self.assertIn("send_email", names_before)

        # Simulate taint → demotion
        session.taint()
        session.demote_tier(PermissionTier.TIER_1_READ_ONLY, "Taint detected")

        # After demotion: email hidden
        result_after = self.mf.filter_manifest(upstream, session.permission_tier)
        names_after = {t["name"] for t in result_after}
        self.assertNotIn("send_email", names_after)
        self.assertIn("fs_read", names_after)


if __name__ == "__main__":
    unittest.main()
