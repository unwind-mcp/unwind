"""Path Jail (The Workspace Jail) + Sensitive Path Deny-List.

Ensures all filesystem operations stay within the configured workspace root.
Canonicalizes paths to defeat traversal via .., symlinks, mixed separators,
and URL-encoded path components.

Additionally enforces a hard deny-list of sensitive paths that must NEVER be
accessed regardless of workspace root setting. Inspired by NanoClaw's mount
allowlist approach but enforced at the tool-call level.

Source: SENTINEL Output 1 (sensitive-path deny-list validation, Pi/OpenClaw)
"""

import os
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Optional

from ..config import UnwindConfig


# ---------------------------------------------------------------------------
# Sensitive-path hard deny-list
# ---------------------------------------------------------------------------
# Checked AFTER canonicalization + symlink resolution.
# Block regardless of workspace allow.
# Source: NanoClaw mount-allowlist + SENTINEL OpenClaw-specific additions.

# Exact directory name patterns (matched against any path component)
SENSITIVE_DIR_PATTERNS: frozenset = frozenset({
    # --- Credentials & Keys ---
    ".ssh",
    ".gnupg",
    ".gpg",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".docker",
    ".netrc",
    ".npmrc",
    # --- OpenClaw-specific (SENTINEL validated on Pi) ---
    ".openclaw",
    # --- Other agent frameworks ---
    ".cursor",
    ".claude",
    # --- Generic sensitive ---
    "credentials",
    ".secret",
    ".secrets",
})

# Filename patterns (matched against the final path component)
SENSITIVE_FILE_PATTERNS: tuple = (
    re.compile(r"^\.env.*$"),                  # .env, .env.local, .env.production
    re.compile(r"^id_rsa$"),
    re.compile(r"^id_ed25519$"),
    re.compile(r"^id_ecdsa$"),
    re.compile(r"^id_dsa$"),
    re.compile(r"^private_key$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^.*\.p12$"),
    re.compile(r"^.*\.pfx$"),
    re.compile(r"^.*\.key$"),
    # OpenClaw-specific files
    re.compile(r"^gateway\.token$"),
    re.compile(r"^exec-approvals\.json$"),
    re.compile(r"^device-auth\.json$"),
    re.compile(r"^paired\.json$"),
    re.compile(r"^pending\.json$"),
    re.compile(r"^auth\.json$"),
    re.compile(r"^auth-profiles\.json$"),
)

# Full path substring patterns (deeply nested OpenClaw paths)
SENSITIVE_PATH_SUBSTRINGS: tuple = (
    "/.openclaw/credentials/",
    "/.openclaw/identity/",
    "/.openclaw/devices/",
    "/.openclaw/agents/",  # Contains per-agent auth + session transcripts
)


class PathJailCheck:
    """Jail filesystem paths to workspace root + sensitive deny-list.

    Two-layer check:
    1. Sensitive deny-list — certain paths blocked regardless of workspace
    2. Workspace jail — path must be within workspace root
    """

    def __init__(self, config: UnwindConfig):
        self.config = config
        # Pre-compute canonical workspace root
        self._workspace_canonical = os.path.realpath(
            str(config.workspace_root.expanduser())
        )

    def _decode_url_components(self, path: str) -> str:
        """Decode URL-encoded path components (%2e%2e = ..)."""
        return urllib.parse.unquote(path)

    def _normalize_separators(self, path: str) -> str:
        """Normalize mixed path separators."""
        return path.replace("\\", "/")

    def canonicalize(self, raw_path: str) -> str:
        """Resolve a raw path to its canonical form.

        Symlinks are resolved to prevent traversal bypasses.
        Returns the canonical path. Does NOT check if it's within jail.
        """
        # Step 1: URL-decode
        decoded = self._decode_url_components(raw_path)
        # Step 2: Normalize Unicode
        normalized = unicodedata.normalize("NFKC", decoded)
        # Step 3: Normalize separators
        normalized = self._normalize_separators(normalized)
        # Step 4: Expand ~ and env vars
        expanded = os.path.expandvars(os.path.expanduser(normalized))
        # Step 5: Resolve to canonical path (resolves symlinks)
        return os.path.realpath(expanded)

    def _check_sensitive_deny_list(self, canonical: str) -> Optional[str]:
        """Check canonical path against sensitive deny-list.

        Returns error message if path is denied, None if allowed.
        Runs AFTER canonicalization + symlink resolution.
        """
        # Split into components for directory pattern matching
        parts = canonical.split(os.sep)

        # Check directory patterns (any component in path)
        for part in parts:
            if part in SENSITIVE_DIR_PATTERNS:
                return (
                    f"Sensitive Path Denied: path contains protected directory "
                    f"'{part}' (SENSITIVE_PATH_DENY_LIST)"
                )

        # Check filename patterns (final component only)
        filename = parts[-1] if parts else ""
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.match(filename):
                return (
                    f"Sensitive Path Denied: filename '{filename}' matches "
                    f"sensitive pattern (SENSITIVE_PATH_DENY_LIST)"
                )

        # Check full path substrings (deeply nested OpenClaw paths)
        for substring in SENSITIVE_PATH_SUBSTRINGS:
            if substring in canonical:
                return (
                    f"Sensitive Path Denied: path contains protected segment "
                    f"'{substring}' (SENSITIVE_PATH_DENY_LIST)"
                )

        return None

    def check(self, raw_path: str) -> tuple[Optional[str], str]:
        """Check if a path passes both deny-list and workspace jail.

        Returns:
            (error_message, canonical_path)
            error_message is None if path is allowed.
            canonical_path is always returned for logging.
        """
        canonical = self.canonicalize(raw_path)

        # --- Layer 1: Sensitive deny-list (FIRST — blocks even within workspace) ---
        deny_error = self._check_sensitive_deny_list(canonical)
        if deny_error:
            return deny_error, canonical

        # --- Layer 2: Workspace jail ---
        if (
            canonical == self._workspace_canonical
            or canonical.startswith(self._workspace_canonical + os.sep)
        ):
            return None, canonical

        return (
            f"Path Jail Violation: {raw_path} resolves to {canonical}, "
            f"outside workspace {self._workspace_canonical}",
            canonical,
        )
