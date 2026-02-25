"""Immutable Policy Source — config outside workspace, hash-checked at startup.

Source: SENTINEL merged list § ADD NOW #3
        ADAPTER_THREAT_MODEL.yaml § TM-ADAPTER-007 (config manipulation)

Purpose:
    Ensure UNWIND's configuration lives OUTSIDE the agent workspace so the
    agent cannot modify its own guardrails. At startup, the config file's
    SHA-256 is recorded. On every reload attempt, the hash is re-verified.
    If the hash doesn't match the recorded value, the reload is rejected
    and the sidecar operates on the last-known-good config (fail-closed).

Design:
    1. Config file MUST live under UNWIND_HOME (~/.unwind/), NOT in the
       agent workspace. The policy_source module enforces this.
    2. At startup, compute SHA-256 of the config file → "birth hash".
    3. On reload, recompute hash. If it matches birth hash, load. If not,
       reject reload and log a CRITICAL alert.
    4. An operator can explicitly rotate the birth hash via CLI
       (unwind policy rotate-hash) after making intentional changes.
    5. If no config file exists, use defaults and log a warning.

NanoClaw compatibility note:
    NanoClaw uses external JSON config (outside container) by design.
    This module provides equivalent protection for UNWIND on OpenClaw
    where the plugin runs in-process with no container boundary.
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("unwind.policy_source")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_FILENAME = "policy.json"
HASH_FILENAME = "policy.sha256"
DEFAULT_UNWIND_HOME = "~/.unwind"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PolicyLoadResult:
    """Result of loading or reloading policy config."""
    success: bool
    config_data: dict = field(default_factory=dict)
    hash_hex: str = ""
    error: Optional[str] = None
    was_default: bool = False


# ---------------------------------------------------------------------------
# Immutable Policy Source
# ---------------------------------------------------------------------------

class ImmutablePolicySource:
    """Manages UNWIND config with integrity verification.

    Config file location: {unwind_home}/policy.json
    Hash file location:   {unwind_home}/policy.sha256

    The hash file is written at first load (or when explicitly rotated).
    All subsequent loads verify against this recorded hash.
    """

    def __init__(self, unwind_home: Optional[Path] = None):
        if unwind_home is None:
            unwind_home = Path(
                os.environ.get("UNWIND_HOME", DEFAULT_UNWIND_HOME)
            ).expanduser()
        self.unwind_home = unwind_home
        self.config_path = unwind_home / CONFIG_FILENAME
        self.hash_path = unwind_home / HASH_FILENAME
        self._birth_hash: Optional[str] = None
        self._current_config: dict = {}
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def birth_hash(self) -> Optional[str]:
        return self._birth_hash

    @property
    def current_config(self) -> dict:
        return self._current_config

    # -------------------------------------------------------------------
    # Workspace boundary enforcement
    # -------------------------------------------------------------------

    def _verify_outside_workspace(self, workspace_root: Optional[Path] = None) -> Optional[str]:
        """Verify config file is NOT inside the agent workspace.

        Returns error message if boundary violated, None if OK.
        """
        if workspace_root is None:
            workspace_root = Path(
                os.environ.get("UNWIND_WORKSPACE", "~/agent-workspace")
            ).expanduser()

        try:
            config_resolved = self.config_path.resolve()
            workspace_resolved = workspace_root.resolve()

            if str(config_resolved).startswith(str(workspace_resolved)):
                return (
                    f"POLICY_SOURCE_BOUNDARY_VIOLATION: config file "
                    f"'{config_resolved}' is inside agent workspace "
                    f"'{workspace_resolved}'. Config MUST live outside "
                    f"the workspace to prevent agent self-modification."
                )
        except (OSError, ValueError) as exc:
            return f"POLICY_SOURCE_PATH_ERROR: {exc}"

        return None

    # -------------------------------------------------------------------
    # Hash computation
    # -------------------------------------------------------------------

    @staticmethod
    def _compute_hash(file_path: Path) -> str:
        """Compute SHA-256 of a file, returning hex digest."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _read_stored_hash(self) -> Optional[str]:
        """Read the stored birth hash from disk."""
        if not self.hash_path.exists():
            return None
        try:
            return self.hash_path.read_text().strip()
        except OSError:
            return None

    def _write_stored_hash(self, hash_hex: str) -> None:
        """Write birth hash to disk."""
        self.hash_path.parent.mkdir(parents=True, exist_ok=True)
        self.hash_path.write_text(hash_hex + "\n")

    # -------------------------------------------------------------------
    # Load / reload
    # -------------------------------------------------------------------

    def initial_load(
        self, workspace_root: Optional[Path] = None
    ) -> PolicyLoadResult:
        """Load config at startup. Records birth hash if first time.

        Call this once during sidecar startup.
        """
        # --- Boundary check ---
        boundary_error = self._verify_outside_workspace(workspace_root)
        if boundary_error:
            logger.critical("[policy_source] %s", boundary_error)
            return PolicyLoadResult(success=False, error=boundary_error)

        # --- Config file existence ---
        if not self.config_path.exists():
            logger.warning(
                "[policy_source] No config file at %s — using defaults",
                self.config_path,
            )
            self._current_config = {}
            self._loaded = True
            return PolicyLoadResult(
                success=True,
                config_data={},
                was_default=True,
            )

        # --- Read and parse ---
        try:
            raw = self.config_path.read_text(encoding="utf-8")
            config_data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            error = f"POLICY_SOURCE_PARSE_ERROR: {exc}"
            logger.error("[policy_source] %s", error)
            return PolicyLoadResult(success=False, error=error)

        if not isinstance(config_data, dict):
            error = "POLICY_SOURCE_INVALID: config must be a JSON object"
            logger.error("[policy_source] %s", error)
            return PolicyLoadResult(success=False, error=error)

        # --- Compute current hash ---
        current_hash = self._compute_hash(self.config_path)

        # --- Check stored hash ---
        stored_hash = self._read_stored_hash()

        if stored_hash is None:
            # First load — record birth hash
            self._write_stored_hash(current_hash)
            self._birth_hash = current_hash
            logger.info(
                "[policy_source] Birth hash recorded: %s...%s",
                current_hash[:8],
                current_hash[-4:],
            )
        else:
            # Subsequent start — verify against stored hash
            if stored_hash != current_hash:
                error = (
                    f"POLICY_SOURCE_HASH_MISMATCH: config file modified "
                    f"without hash rotation. Expected {stored_hash[:12]}..., "
                    f"got {current_hash[:12]}... "
                    f"Use 'unwind policy rotate-hash' to accept changes."
                )
                logger.critical("[policy_source] %s", error)
                return PolicyLoadResult(success=False, error=error)
            self._birth_hash = stored_hash

        self._current_config = config_data
        self._loaded = True

        return PolicyLoadResult(
            success=True,
            config_data=config_data,
            hash_hex=current_hash,
        )

    def reload(self) -> PolicyLoadResult:
        """Attempt to reload config from disk.

        Verifies hash matches birth hash before accepting.
        If hash doesn't match, rejects reload and keeps current config.
        """
        if not self._loaded:
            return PolicyLoadResult(
                success=False,
                error="POLICY_SOURCE_NOT_INITIALIZED: call initial_load() first",
            )

        if not self.config_path.exists():
            return PolicyLoadResult(
                success=False,
                error="POLICY_SOURCE_FILE_MISSING: config file removed",
            )

        # --- Recompute hash ---
        current_hash = self._compute_hash(self.config_path)

        if self._birth_hash and current_hash != self._birth_hash:
            error = (
                f"POLICY_SOURCE_RELOAD_REJECTED: hash mismatch. "
                f"Birth hash {self._birth_hash[:12]}..., "
                f"current {current_hash[:12]}... "
                f"Keeping last-known-good config."
            )
            logger.warning("[policy_source] %s", error)
            return PolicyLoadResult(
                success=False,
                config_data=self._current_config,  # Return current as fallback
                hash_hex=self._birth_hash,
                error=error,
            )

        # --- Parse ---
        try:
            raw = self.config_path.read_text(encoding="utf-8")
            config_data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            error = f"POLICY_SOURCE_RELOAD_PARSE_ERROR: {exc}"
            logger.error("[policy_source] %s", error)
            return PolicyLoadResult(
                success=False,
                config_data=self._current_config,
                error=error,
            )

        self._current_config = config_data
        return PolicyLoadResult(
            success=True,
            config_data=config_data,
            hash_hex=current_hash,
        )

    # -------------------------------------------------------------------
    # Hash rotation (operator-initiated)
    # -------------------------------------------------------------------

    def rotate_hash(self) -> PolicyLoadResult:
        """Rotate the birth hash to accept intentional config changes.

        Called by operator via CLI: `unwind policy rotate-hash`
        This re-reads the config, computes new hash, and stores it.
        """
        if not self.config_path.exists():
            return PolicyLoadResult(
                success=False,
                error="POLICY_SOURCE_FILE_MISSING: nothing to rotate",
            )

        try:
            raw = self.config_path.read_text(encoding="utf-8")
            config_data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            return PolicyLoadResult(
                success=False,
                error=f"POLICY_SOURCE_ROTATE_PARSE_ERROR: {exc}",
            )

        new_hash = self._compute_hash(self.config_path)
        old_hash = self._birth_hash or "(none)"

        self._write_stored_hash(new_hash)
        self._birth_hash = new_hash
        self._current_config = config_data

        logger.info(
            "[policy_source] Hash rotated: %s... → %s...",
            old_hash[:12],
            new_hash[:12],
        )

        return PolicyLoadResult(
            success=True,
            config_data=config_data,
            hash_hex=new_hash,
        )

    # -------------------------------------------------------------------
    # Config access helpers
    # -------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by key."""
        return self._current_config.get(key, default)

    def get_section(self, section: str) -> dict:
        """Get a config section (nested dict)."""
        val = self._current_config.get(section, {})
        return val if isinstance(val, dict) else {}
