"""Manifest Rewriting — per-session RBAC for MCP tool visibility.

This is UNWIND's answer to the #1 MCP security gap identified by
Jason Haddix (Arcanum Security): agents see ALL tools with no access control.

Instead of blocking tool calls after the agent tries them (reactive),
we hide restricted tools from the manifest entirely (proactive).
An agent can't call what it can't see.

Permission Tiers:
  TIER_1_READ_ONLY   — Read/search tools only (default for new sessions)
  TIER_2_SCOPED_WRITE — Adds file writes within workspace
  TIER_3_COMMUNICATE  — Adds email/messaging/posting
  TIER_4_FULL_ACCESS  — All tools visible (experienced users, explicit opt-in)

Each tier includes all tools from lower tiers.
Canary honeypot tools are ALWAYS injected regardless of tier.
"""

from enum import IntEnum
from typing import Optional

from ..config import UnwindConfig


class PermissionTier(IntEnum):
    """Permission tiers — higher number = more tools visible.

    IntEnum so tiers are naturally comparable: TIER_2 > TIER_1 etc.
    """
    TIER_1_READ_ONLY = 1
    TIER_2_SCOPED_WRITE = 2
    TIER_3_COMMUNICATE = 3
    TIER_4_FULL_ACCESS = 4


# --- Tool classification by tier ---
# These are the ADDITIONAL tools each tier unlocks (cumulative).
# Tool names use the same identifiers as config.py tool sets.

# Tier 1: Read-only tools (always visible)
TIER_1_TOOLS = frozenset({
    # Filesystem reads
    "fs_read", "fs_list", "fs_search", "fs_stat", "fs_tree",
    # Web reads
    "fetch_web", "http_get", "search_web", "browser_navigate",
    # Document parsing
    "read_document", "read_email", "read_calendar",
    "read_slack", "read_rss",
    # General queries
    "query", "search", "get", "list", "describe", "inspect",
})

# Tier 2: Adds scoped filesystem writes
TIER_2_TOOLS = frozenset({
    "fs_write", "fs_delete", "fs_rename", "fs_mkdir",
    "fs_copy", "fs_move",
})

# Tier 3: Adds communication/outbound
TIER_3_TOOLS = frozenset({
    "send_email", "post_message", "http_post",
    "upload_file", "api_call", "webhook",
    "create_calendar_event", "modify_calendar_event",
    "delete_calendar_event",
    "inbound_message",  # Allow reply context
})

# Tier 4: Adds dangerous execution tools
TIER_4_TOOLS = frozenset({
    "bash_exec", "shell_run", "exec", "run_command",
    "install_package", "pip_install", "npm_install",
    "websocket",
})


def tools_for_tier(tier: PermissionTier) -> frozenset:
    """Return all tool names visible at a given tier (cumulative)."""
    tools = set(TIER_1_TOOLS)
    if tier >= PermissionTier.TIER_2_SCOPED_WRITE:
        tools |= TIER_2_TOOLS
    if tier >= PermissionTier.TIER_3_COMMUNICATE:
        tools |= TIER_3_TOOLS
    if tier >= PermissionTier.TIER_4_FULL_ACCESS:
        tools |= TIER_4_TOOLS
    return frozenset(tools)


class ManifestFilter:
    """Filter MCP tool manifests based on session permission tier.

    Usage:
        filter = ManifestFilter(config)
        visible_tools = filter.filter_manifest(upstream_tools, tier)

    The agent only sees tools appropriate for its permission level.
    Unknown tools (not in any tier) are handled by the `unknown_tool_policy`:
      - "hide"  = unknown tools are hidden (default, most secure)
      - "tier1" = unknown tools visible at tier 1+ (permissive)
      - "show"  = unknown tools always visible (legacy compatibility)
    """

    def __init__(self, config: UnwindConfig):
        self.config = config

    def filter_manifest(
        self,
        upstream_tools: list[dict],
        tier: PermissionTier,
        extra_tools: Optional[set] = None,
        unknown_tool_policy: str = "hide",
    ) -> list[dict]:
        """Filter upstream tool list based on permission tier.

        Args:
            upstream_tools: Raw tool definitions from the upstream MCP server
            tier: Current session's permission tier
            extra_tools: Additional tool names to allow (per-session overrides)
            unknown_tool_policy: How to handle tools not in any tier definition
                "hide" — hide unknown tools (most secure, default)
                "tier1" — show unknown tools at tier 1 and above
                "show" — always show unknown tools

        Returns:
            Filtered list of tool definitions the agent is allowed to see.
            Canary tools are NOT included here (added separately by transport).
        """
        if tier == PermissionTier.TIER_4_FULL_ACCESS:
            # Full access = no filtering (but still log what's visible)
            return list(upstream_tools)

        allowed = tools_for_tier(tier)
        if extra_tools:
            allowed = allowed | extra_tools

        filtered = []
        for tool in upstream_tools:
            name = tool.get("name", "")

            # Canary tools are never filtered out (they're added separately)
            if name in self.config.canary_tools:
                continue  # Skip — canaries injected by transport layer

            # Check if tool is in any tier's definition
            all_known = TIER_1_TOOLS | TIER_2_TOOLS | TIER_3_TOOLS | TIER_4_TOOLS
            is_known = name in all_known

            if name in allowed:
                filtered.append(tool)
            elif not is_known:
                # Unknown tool — apply policy
                if unknown_tool_policy == "show":
                    filtered.append(tool)
                elif unknown_tool_policy == "tier1":
                    filtered.append(tool)
                # "hide" = don't include
            # else: known tool not in current tier = hidden

        return filtered

    def classify_tool_tier(self, tool_name: str) -> Optional[PermissionTier]:
        """Return the minimum tier required to see a tool, or None if unknown."""
        if tool_name in TIER_1_TOOLS:
            return PermissionTier.TIER_1_READ_ONLY
        if tool_name in TIER_2_TOOLS:
            return PermissionTier.TIER_2_SCOPED_WRITE
        if tool_name in TIER_3_TOOLS:
            return PermissionTier.TIER_3_COMMUNICATE
        if tool_name in TIER_4_TOOLS:
            return PermissionTier.TIER_4_FULL_ACCESS
        return None

    def describe_tier(self, tier: PermissionTier) -> str:
        """Human-readable description of what a tier allows."""
        descriptions = {
            PermissionTier.TIER_1_READ_ONLY: (
                "Read Only — can search, read files, browse web. Cannot modify anything."
            ),
            PermissionTier.TIER_2_SCOPED_WRITE: (
                "Scoped Write — can read + write/delete files within workspace. "
                "Cannot send emails or make network requests."
            ),
            PermissionTier.TIER_3_COMMUNICATE: (
                "Communicate — can read + write + send emails, post messages, "
                "make API calls. Full task automation."
            ),
            PermissionTier.TIER_4_FULL_ACCESS: (
                "Full Access — all tools visible including shell execution. "
                "Use only when you know what the agent is doing."
            ),
        }
        return descriptions.get(tier, f"Unknown tier: {tier}")

    def escalation_required(
        self, tool_name: str, current_tier: PermissionTier
    ) -> Optional[PermissionTier]:
        """Check if a tool call requires tier escalation.

        Returns the required tier if escalation needed, None if tool is allowed.
        This is used by the pipeline to generate meaningful AMBER messages
        like "Agent wants to send_email — this requires Tier 3 (Communicate)."
        """
        required = self.classify_tool_tier(tool_name)
        if required is None:
            return None  # Unknown tool — handled by policy
        if required > current_tier:
            return required
        return None
