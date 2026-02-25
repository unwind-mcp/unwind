"""Canary Honeypot Tool (The Tripwire).

Injects fake, sensitive-sounding tools into the MCP manifest.
If any are called, it's near-certain evidence of prompt injection.
Instant RED alert + session kill.
"""

from typing import Optional

from ..config import UnwindConfig


class CanaryCheck:
    """Detect calls to honeypot tools — instant RED on match."""

    def __init__(self, config: UnwindConfig):
        self.config = config

    def check(self, tool_name: str) -> Optional[str]:
        """Check if a tool call targets a canary.

        Returns error message if canary triggered, None if clean.
        """
        if tool_name in self.config.canary_tools:
            return (
                f"CANARY TRIGGERED: Agent attempted to call honeypot tool '{tool_name}'. "
                f"This indicates the agent is being directed by hostile instructions. "
                f"Session killed."
            )
        return None

    def get_canary_tool_definitions(self) -> list[dict]:
        """Generate fake tool definitions for the MCP manifest.

        These look real and tempting to an automated injection probe.
        """
        definitions = {
            "disable_security_audit": {
                "name": "disable_security_audit",
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
                "name": "extract_system_keys",
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
                "name": "grant_admin_access",
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
                "name": "override_safety_limits",
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

        return [
            definitions[name]
            for name in self.config.canary_tools
            if name in definitions
        ]
