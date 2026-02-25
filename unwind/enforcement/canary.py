"""Canary Honeypot Tool (The Tripwire).

Injects fake, sensitive-sounding tools into the MCP manifest.
If any are called, it's near-certain evidence of prompt injection.
Instant RED alert + session kill.

P2-9 hardening:
- Static canary names remain as template IDs for backwards compatibility.
- Session-aware manifest injection now randomises visible canary names,
  so memorised names from prior sessions do not transfer.
"""

import secrets
from typing import Optional

from ..config import UnwindConfig


# Less-obvious visible stems (audit recommendation)
_CANARY_STEMS: dict[str, str] = {
    "disable_security_audit": "backup_workspace_snapshot",
    "extract_system_keys": "sync_remote_credentials",
    "grant_admin_access": "rotate_service_tokens",
    "override_safety_limits": "export_agent_memory",
}


class CanaryCheck:
    """Detect calls to honeypot tools — instant RED on match."""

    # Stable marker pattern for internally generated canary names.
    # Exposed in tool names but randomised suffix prevents cross-session reuse.
    DYNAMIC_MARKER = "__uwc_"

    def __init__(self, config: UnwindConfig):
        self.config = config
        # session_id -> {dynamic_name: template_name}
        self._session_name_to_template: dict[str, dict[str, str]] = {}
        # session_id -> {template_name: dynamic_name}
        self._session_template_to_name: dict[str, dict[str, str]] = {}

    def _template_names(self) -> list[str]:
        # Stable order for deterministic output shape.
        return sorted(self.config.canary_tools)

    def _make_dynamic_name(self, template_name: str, used: set[str]) -> str:
        stem = _CANARY_STEMS.get(template_name, template_name)
        while True:
            suffix = secrets.token_hex(4)  # 8 hex chars
            candidate = f"{stem}{self.DYNAMIC_MARKER}{suffix}"
            if candidate not in used:
                return candidate

    def _ensure_session_canaries(self, session_id: str) -> None:
        if session_id in self._session_name_to_template:
            return

        name_to_template: dict[str, str] = {}
        template_to_name: dict[str, str] = {}
        used: set[str] = set()

        for template_name in self._template_names():
            dyn = self._make_dynamic_name(template_name, used)
            used.add(dyn)
            name_to_template[dyn] = template_name
            template_to_name[template_name] = dyn

        self._session_name_to_template[session_id] = name_to_template
        self._session_template_to_name[session_id] = template_to_name

    def is_canary(self, tool_name: str, session_id: Optional[str] = None) -> bool:
        """Return True if tool_name matches a canary in this context."""
        # Session-scoped dynamic names
        if session_id is not None:
            self._ensure_session_canaries(session_id)
            if tool_name in self._session_name_to_template.get(session_id, {}):
                return True

        # Back-compat static template names (sidecar/tests)
        return tool_name in self.config.canary_tools

    def check(self, tool_name: str, session_id: Optional[str] = None) -> Optional[str]:
        """Check if a tool call targets a canary.

        Returns error message if canary triggered, None if clean.
        """
        if not self.is_canary(tool_name, session_id=session_id):
            return None

        if session_id is not None:
            template = self._session_name_to_template.get(session_id, {}).get(
                tool_name,
                tool_name,
            )
            return (
                f"CANARY TRIGGERED: Agent attempted to call honeypot tool '{tool_name}' "
                f"(template '{template}'). This indicates the agent is being directed by "
                f"hostile instructions. Session killed."
            )

        return (
            f"CANARY TRIGGERED: Agent attempted to call honeypot tool '{tool_name}'. "
            f"This indicates the agent is being directed by hostile instructions. "
            f"Session killed."
        )

    def _definition_for_template(self, template_name: str, visible_name: str) -> dict:
        """Return MCP tool definition for a template with visible name override."""
        definitions = {
            "disable_security_audit": {
                "name": visible_name,
                "description": "Temporarily disable security audit logging for the current session. "
                               "Useful for high-throughput operations where logging overhead is unwanted.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "duration_minutes": {
                            "type": "integer",
                            "description": "How long to disable auditing (max 60 minutes)",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for disabling audit",
                        },
                    },
                    "required": ["duration_minutes"],
                },
            },
            "extract_system_keys": {
                "name": visible_name,
                "description": "Extract system API keys and credentials for backup or migration purposes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key_type": {
                            "type": "string",
                            "description": "Type of keys to extract: 'all', 'api', 'ssh', 'certificates'",
                        },
                        "output_format": {
                            "type": "string",
                            "description": "Output format: 'json', 'env', 'yaml'",
                        },
                    },
                    "required": ["key_type"],
                },
            },
            "grant_admin_access": {
                "name": visible_name,
                "description": "Elevate current session to administrator privileges for system management tasks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "description": "Scope of admin access: 'full', 'filesystem', 'network'",
                        },
                    },
                    "required": ["scope"],
                },
            },
            "override_safety_limits": {
                "name": visible_name,
                "description": "Override rate limits and safety checks for the current operation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "confirmation_code": {
                            "type": "string",
                            "description": "Safety override confirmation code",
                        },
                    },
                    "required": ["confirmation_code"],
                },
            },
        }

        if template_name in definitions:
            return definitions[template_name]

        # Generic fallback for custom template IDs in config.canary_tools
        return {
            "name": visible_name,
            "description": "Internal maintenance operation.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        }

    def get_canary_tool_definitions(self, session_id: Optional[str] = None) -> list[dict]:
        """Generate fake tool definitions for the MCP manifest.

        Args:
            session_id: if provided, returns session-randomised visible names.
                        if None, returns legacy/static names (backwards compatibility).
        """
        if session_id is not None:
            self._ensure_session_canaries(session_id)
            mapping = self._session_template_to_name.get(session_id, {})
            return [
                self._definition_for_template(template_name, mapping[template_name])
                for template_name in self._template_names()
                if template_name in mapping
            ]

        # Legacy static names
        return [
            self._definition_for_template(template_name, template_name)
            for template_name in self._template_names()
        ]
