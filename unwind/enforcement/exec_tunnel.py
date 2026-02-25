"""Exec Tunnel Detection — parse shell commands for nested tool calls.

SENTINEL finding (2026-02-22): In OpenClaw, git and cron are often reached
via `exec git ...` or `exec openclaw cron ...`. If UNWIND only gates by
tool name, an attacker bypasses tool-specific policy by tunnelling through exec.

This check parses exec/bash_exec command strings to detect:
1. Dangerous command patterns (rm -rf /, force push, etc.)
2. Tunnelled tool calls (git push = git_push policy, openclaw cron = cron policy)
3. Shell metacharacter abuse (;, &&, ||, $(), backticks, pipes to dangerous sinks)

When a tunnelled tool is detected, the check returns the "virtual" tool name
so the pipeline can reclassify and apply that tool's full policy.
"""

import re
import shlex
import unicodedata
from dataclasses import dataclass
from typing import Optional, FrozenSet

from ..config import UnwindConfig


@dataclass
class ExecTunnelResult:
    """Result of exec tunnel analysis."""
    is_tunnelled: bool = False
    virtual_tool: Optional[str] = None   # e.g. "git_push", "cron_add"
    is_dangerous: bool = False            # Hard-block patterns
    reason: str = ""


# --- Dangerous command patterns: always block ---
DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\b.*(/|~|\.\.)"),
     "Recursive force delete with broad target"),
    (re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\s+/\s*$"),
     "rm -rf / detected"),
    (re.compile(r"\bdd\s+.*\bof=/dev/"),
     "Direct device write via dd"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;"),
     "Fork bomb pattern"),
    (re.compile(r"\bmkfs\b"),
     "Filesystem format command"),
    (re.compile(r"\b(chmod|chown)\s+(-R\s+)?[0-7]*\s+/\s*$"),
     "Recursive permission change on root"),
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"),
     "Pipe from curl to shell (supply chain risk)"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"),
     "Pipe from wget to shell (supply chain risk)"),
]

# --- Git subcommand classification ---
GIT_DANGEROUS_ARGS: dict[str, list[str]] = {
    "push": ["--force", "-f", "--force-with-lease", "--delete"],
    "reset": ["--hard"],
    "checkout": ["."],        # discard all changes
    "clean": ["-f", "-fd"],   # delete untracked files
    "rebase": [],             # always flag in tainted session
    "merge": [],              # always flag in tainted session
}

GIT_ACTUATOR_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "push", "commit", "reset", "checkout", "clean", "rebase",
    "merge", "tag", "branch",
})

GIT_SENSOR_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "clone", "fetch", "pull",  # Ingest external content
})

# --- Exec tool names that trigger this check ---
EXEC_TOOL_NAMES: FrozenSet[str] = frozenset({
    "bash_exec", "shell_exec", "exec", "run_command",
    "execute_command", "shell_run",
})

# --- Shell metacharacters that indicate command chaining ---
CHAIN_METACHAR_PATTERN = re.compile(
    r"[;|&`]"       # semicolons, pipes, ampersands, backticks
    r"|\$\("        # $() subshell
    r"|\$\{"        # ${} variable expansion tricks
    r"|>\s*/dev/"   # redirect to device
)


class ExecTunnelCheck:
    """Detect and reclassify tunnelled tool calls within exec commands."""

    def __init__(self, config: UnwindConfig):
        self.config = config

    def _normalize(self, command: str) -> str:
        """Unicode NFKC normalization to defeat lookalike evasion."""
        return unicodedata.normalize("NFKC", command).strip()

    def _parse_argv(self, command: str) -> list[str]:
        """Parse command into argv, handling parse failures gracefully."""
        try:
            return shlex.split(command)
        except ValueError:
            # Fallback: split on whitespace (lossy but safe)
            return command.split()

    def _check_dangerous_patterns(self, command: str) -> Optional[str]:
        """Check for always-block dangerous patterns."""
        normalized = self._normalize(command)
        for pattern, description in DANGEROUS_PATTERNS:
            if pattern.search(normalized):
                return f"Dangerous exec pattern: {description}"
        return None

    def _check_chain_metacharacters(self, command: str) -> Optional[str]:
        """Detect shell metacharacters used for command chaining.

        If a command chains multiple operations, the second command
        could be doing something the first is a decoy for.
        Returns a warning reason if chaining detected.
        """
        normalized = self._normalize(command)
        if CHAIN_METACHAR_PATTERN.search(normalized):
            return f"Shell command chaining detected (metacharacters in: {command[:80]})"
        return None

    def _classify_git(self, argv: list[str]) -> ExecTunnelResult:
        """Classify a git command."""
        # Find the git subcommand (skip flags like -C, --git-dir)
        subcommand = None
        i = 1  # Skip 'git' itself
        while i < len(argv):
            arg = argv[i]
            if arg.startswith("-"):
                # Skip flags and their values
                if arg in ("-C", "--git-dir", "--work-tree", "-c"):
                    i += 2  # Skip flag + value
                    continue
                i += 1
                continue
            subcommand = arg
            break

        if not subcommand:
            return ExecTunnelResult()

        remaining_args = argv[i + 1:] if i + 1 < len(argv) else []

        # Check for dangerous git arguments
        if subcommand in GIT_DANGEROUS_ARGS:
            dangerous_flags = GIT_DANGEROUS_ARGS[subcommand]
            for flag in dangerous_flags:
                if flag in remaining_args:
                    return ExecTunnelResult(
                        is_tunnelled=True,
                        virtual_tool=f"git_{subcommand}",
                        is_dangerous=True,
                        reason=f"Dangerous git operation: git {subcommand} {flag}",
                    )

        # Classify as sensor or actuator
        if subcommand in GIT_SENSOR_SUBCOMMANDS:
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool=f"git_{subcommand}",
                reason=f"Tunnelled git sensor: git {subcommand}",
            )

        if subcommand in GIT_ACTUATOR_SUBCOMMANDS:
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool=f"git_{subcommand}",
                reason=f"Tunnelled git actuator: git {subcommand}",
            )

        return ExecTunnelResult(
            is_tunnelled=True,
            virtual_tool=f"git_{subcommand}",
            reason=f"Tunnelled git command: git {subcommand}",
        )

    def _classify_openclaw(self, argv: list[str]) -> ExecTunnelResult:
        """Classify an openclaw command."""
        if len(argv) < 2:
            return ExecTunnelResult()

        subcommand = argv[1]

        if subcommand == "cron":
            action = argv[2] if len(argv) > 2 else "unknown"
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool=f"cron_{action}",
                reason=f"Tunnelled cron operation: openclaw cron {action}",
            )

        if subcommand in ("devices", "config", "onboard"):
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool=f"openclaw_{subcommand}",
                is_dangerous=True,
                reason=f"Tunnelled OpenClaw admin command: openclaw {subcommand}",
            )

        return ExecTunnelResult(
            is_tunnelled=True,
            virtual_tool=f"openclaw_{subcommand}",
            reason=f"Tunnelled OpenClaw command: openclaw {subcommand}",
        )

    def _classify_package_manager(self, binary: str, argv: list[str]) -> ExecTunnelResult:
        """Classify npm/pip/apt package manager commands."""
        if len(argv) < 2:
            return ExecTunnelResult()

        subcommand = argv[1]

        if subcommand in ("install", "add", "i"):
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="install_package",
                reason=f"Tunnelled package install: {binary} {subcommand}",
            )

        if subcommand in ("uninstall", "remove", "rm"):
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="uninstall_package",
                reason=f"Tunnelled package removal: {binary} {subcommand}",
            )

        if subcommand in ("publish", "push"):
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="publish_package",
                is_dangerous=True,
                reason=f"Tunnelled package publish: {binary} {subcommand}",
            )

        return ExecTunnelResult()

    def _classify_network(self, binary: str, argv: list[str]) -> ExecTunnelResult:
        """Classify curl/wget/ssh network commands."""
        return ExecTunnelResult(
            is_tunnelled=True,
            virtual_tool=f"exec_{binary}",
            reason=f"Tunnelled network tool: {binary}",
        )

    def check(
        self,
        tool_name: str,
        parameters: Optional[dict] = None,
    ) -> Optional[ExecTunnelResult]:
        """Check if an exec tool is tunnelling another tool.

        Returns ExecTunnelResult if tunnelling detected, None if clean.
        """
        if tool_name not in EXEC_TOOL_NAMES:
            return None

        if not parameters:
            return None

        command = parameters.get("command", "")
        if not command:
            return None

        normalized = self._normalize(command)

        # --- 1. Check for always-block dangerous patterns ---
        danger = self._check_dangerous_patterns(normalized)
        if danger:
            return ExecTunnelResult(
                is_tunnelled=False,
                is_dangerous=True,
                reason=danger,
            )

        # --- 2. Check for command chaining metacharacters ---
        chain_warning = self._check_chain_metacharacters(normalized)

        # --- 3. Parse and classify the primary command ---
        argv = self._parse_argv(normalized)
        if not argv:
            return None

        # Resolve the binary name (strip path prefix)
        binary = argv[0].rsplit("/", 1)[-1].lower()

        # Route to specialised classifiers
        result = ExecTunnelResult()

        if binary == "git":
            result = self._classify_git(argv)
        elif binary == "openclaw":
            result = self._classify_openclaw(argv)
        elif binary in ("npm", "pip", "pip3", "yarn", "pnpm", "apt", "apt-get"):
            result = self._classify_package_manager(binary, argv)
        elif binary in ("curl", "wget", "ssh", "scp", "rsync", "nc", "ncat", "netcat"):
            result = self._classify_network(binary, argv)
        elif binary in ("python", "python3", "node", "ruby", "perl"):
            result = ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool=f"exec_{binary}",
                reason=f"Script interpreter execution: {binary}",
            )
        elif binary in ("sudo", "su", "doas"):
            result = ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="privilege_escalation",
                is_dangerous=True,
                reason=f"Privilege escalation attempt: {binary}",
            )
        elif binary in ("systemctl", "service", "launchctl"):
            result = ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="service_management",
                is_dangerous=True,
                reason=f"Service management command: {binary}",
            )
        elif binary in ("crontab",):
            result = ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="cron_edit",
                is_dangerous=True,
                reason=f"System cron modification: {binary}",
            )

        # Attach chain warning if both tunnelled and chained
        if chain_warning and result.is_tunnelled:
            result.reason += f" + {chain_warning}"

        # If we only found chaining but no specific tool tunnel, still flag it
        if chain_warning and not result.is_tunnelled:
            return ExecTunnelResult(
                is_tunnelled=True,
                virtual_tool="exec_chained",
                reason=chain_warning,
            )

        return result if (result.is_tunnelled or result.is_dangerous) else None
