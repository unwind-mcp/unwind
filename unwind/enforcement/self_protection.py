"""Self-Protection (The Path Locker).

Prevents the agent from accessing or modifying UNWIND's own files.
Canonicalizes paths before matching to defeat evasion via symlinks,
Unicode lookalikes, case changes, and environment variable expansion.
"""

import os
import re
import shlex
import unicodedata
from pathlib import Path
from typing import Optional

from ..config import UnwindConfig


class SelfProtectionCheck:
    """Block any tool call targeting UNWIND-protected paths."""

    def __init__(self, config: UnwindConfig):
        self.config = config
        # Pre-compute canonical protected roots
        self._protected_canonical: list[str] = []
        for root in config.protected_roots:
            try:
                canonical = os.path.realpath(str(root))
                self._protected_canonical.append(canonical)
            except OSError:
                # Root doesn't exist yet — protect the expected path
                self._protected_canonical.append(str(root.expanduser()))

    def _normalize_text(self, text: str) -> str:
        """Normalize Unicode to defeat lookalike characters."""
        # NFKC normalization collapses fullwidth, compatibility chars, etc.
        return unicodedata.normalize("NFKC", text)

    def _canonicalize_path(self, raw_path: str) -> str:
        """Resolve a path to its canonical form.

        For existing paths: resolves symlinks and .. traversal.
        For non-existing paths: resolves parent dir + appends filename,
        because realpath on a non-existing path behaves differently.
        """
        normalized = self._normalize_text(raw_path)
        # Expand ~ and env vars
        expanded = os.path.expandvars(os.path.expanduser(normalized))

        target = Path(expanded)
        if target.exists():
            return os.path.realpath(expanded)
        elif target.parent.exists():
            # Canonicalize parent, append the leaf name
            parent_real = os.path.realpath(str(target.parent))
            return os.path.join(parent_real, target.name)
        else:
            # Best effort — resolve as-is
            return os.path.realpath(expanded)

    def _is_protected(self, canonical_path: str) -> bool:
        """Check if a canonical path falls within any protected root."""
        for protected in self._protected_canonical:
            # Path is protected if it IS the root or starts with root + separator
            if canonical_path == protected or canonical_path.startswith(protected + os.sep):
                return True
        return False

    def check_path(self, raw_path: str) -> Optional[str]:
        """Check a file path. Returns error message if blocked, None if allowed."""
        canonical = self._canonicalize_path(raw_path)
        if self._is_protected(canonical):
            return f"Permission Denied: System Core Protected (resolved: {canonical})"
        return None

    def check_shell_command(self, command: str) -> Optional[str]:
        """Check a shell command for protected path references.

        Parses arguments and resolves each path-like argument.
        Returns error message if blocked, None if allowed.
        """
        normalized = self._normalize_text(command)

        try:
            args = shlex.split(normalized)
        except ValueError:
            # If we can't parse it, check the raw string as fallback
            args = normalized.split()

        for arg in args:
            # Skip flags/options
            if arg.startswith("-"):
                continue
            # Check if this argument looks like a path
            if "/" in arg or "~" in arg or "." in arg:
                canonical = self._canonicalize_path(arg)
                if self._is_protected(canonical):
                    return f"Permission Denied: System Core Protected (shell arg resolved: {canonical})"

        return None

    def check(self, tool: str, target: Optional[str] = None, command: Optional[str] = None) -> Optional[str]:
        """Main entry point. Returns error message if blocked, None if allowed.

        Args:
            tool: The tool name being called
            target: File path target (for fs.* tools)
            command: Shell command string (for bash_exec)
        """
        if target:
            result = self.check_path(target)
            if result:
                return result

        if command or tool == "bash_exec":
            cmd = command or target or ""
            result = self.check_shell_command(cmd)
            if result:
                return result

        return None
