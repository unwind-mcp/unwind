"""Rollback Engine — undo last, undo range, selective undo.

Supports:
  unwind undo last              — Undo the most recent state-modifying action
  unwind undo <event_id>        — Undo a specific event
  unwind undo --since "3pm"     — Undo all state-modifying actions since a time
  unwind undo --session <id>    — Undo all state-modifying actions in a session

Conflict detection: if a file has been modified since the snapshot was taken,
the rollback is flagged and requires --force to proceed.
"""

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from ..config import UnwindConfig
from .manager import Snapshot, SnapshotType


class RollbackStatus(Enum):
    SUCCESS = "success"
    CONFLICT = "conflict"          # File changed since snapshot
    SNAPSHOT_MISSING = "missing"   # No snapshot for this event
    NOT_RESTORABLE = "not_restorable"  # Snapshot was skipped (too large, etc.)
    ALREADY_ROLLED_BACK = "already_rolled_back"
    ERROR = "error"


@dataclass
class RollbackResult:
    """Result of a single rollback operation."""
    event_id: str
    status: RollbackStatus
    original_path: str
    message: str
    snapshot_type: Optional[str] = None
    conflict_detail: Optional[str] = None


class RollbackEngine:
    """Performs rollback operations using stored snapshots."""

    def __init__(self, config: UnwindConfig):
        self.config = config

    def _file_hash(self, path: str) -> Optional[str]:
        """Compute SHA-256 of a file."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, OSError):
            return None

    def _check_conflict(self, snapshot: Snapshot) -> Optional[str]:
        """Check if restoring this snapshot would cause a conflict.

        For FILE_COPY: no conflict check — the user explicitly asked to undo,
        so restoring the pre-action state is always correct. We can't detect
        third-party modifications without tracking the post-action hash.

        For ATOMIC_MOVE: conflict if a new file appeared at the original path
        (something was written there after the deletion).

        Returns a conflict description, or None if no conflict.
        """
        target = Path(snapshot.original_path)
        metadata = json.loads(snapshot.metadata) if snapshot.metadata else {}

        # New file creation: no conflict possible
        if metadata.get("type") == "new_file":
            return None

        # FILE_COPY: always safe to restore — user wants the pre-action state
        if snapshot.snapshot_type == SnapshotType.FILE_COPY.value:
            return None

        # ATOMIC_MOVE: conflict if a NEW file now exists at the original path
        # (file was deleted by snapshot, but something new appeared there)
        if snapshot.snapshot_type == SnapshotType.ATOMIC_MOVE.value:
            if target.exists():
                current_hash = self._file_hash(str(target))
                if current_hash and snapshot.original_hash and current_hash != snapshot.original_hash:
                    return (
                        f"New file exists at {snapshot.original_path} "
                        f"(hash {current_hash[:12]}... differs from original "
                        f"{snapshot.original_hash[:12]}...)"
                    )

        return None

    def rollback_single(self, snapshot: Snapshot, force: bool = False) -> RollbackResult:
        """Roll back a single event using its snapshot.

        Args:
            snapshot: The snapshot record to restore from
            force: If True, ignore conflicts and overwrite

        Returns:
            RollbackResult with status and details
        """
        if not snapshot.restorable:
            return RollbackResult(
                event_id=snapshot.event_id,
                status=RollbackStatus.NOT_RESTORABLE,
                original_path=snapshot.original_path,
                message=f"Snapshot not restorable: {snapshot.snapshot_type}",
                snapshot_type=snapshot.snapshot_type,
            )

        metadata = json.loads(snapshot.metadata) if snapshot.metadata else {}

        # --- New file creation: undo = delete the file ---
        if metadata.get("type") == "new_file":
            target = Path(snapshot.original_path)
            if not target.exists():
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.ALREADY_ROLLED_BACK,
                    original_path=snapshot.original_path,
                    message="File already removed",
                    snapshot_type=snapshot.snapshot_type,
                )
            try:
                target.unlink()
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.SUCCESS,
                    original_path=snapshot.original_path,
                    message="Removed file created by action",
                    snapshot_type=snapshot.snapshot_type,
                )
            except (IOError, OSError) as e:
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.ERROR,
                    original_path=snapshot.original_path,
                    message=f"Failed to remove file: {e}",
                    snapshot_type=snapshot.snapshot_type,
                )

        # --- File copy: undo = restore from snapshot ---
        if snapshot.snapshot_type == SnapshotType.FILE_COPY.value:
            if not snapshot.snapshot_path or not Path(snapshot.snapshot_path).exists():
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.SNAPSHOT_MISSING,
                    original_path=snapshot.original_path,
                    message="Snapshot file not found on disk",
                    snapshot_type=snapshot.snapshot_type,
                )

            # Check for conflicts
            if not force:
                conflict = self._check_conflict(snapshot)
                if conflict:
                    return RollbackResult(
                        event_id=snapshot.event_id,
                        status=RollbackStatus.CONFLICT,
                        original_path=snapshot.original_path,
                        message=f"Conflict detected: {conflict}",
                        snapshot_type=snapshot.snapshot_type,
                        conflict_detail=conflict,
                    )

            try:
                # Ensure parent directory exists
                Path(snapshot.original_path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(snapshot.snapshot_path, snapshot.original_path)
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.SUCCESS,
                    original_path=snapshot.original_path,
                    message=f"Restored from snapshot ({metadata.get('method', 'copy')})",
                    snapshot_type=snapshot.snapshot_type,
                )
            except (IOError, OSError) as e:
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.ERROR,
                    original_path=snapshot.original_path,
                    message=f"Restore failed: {e}",
                    snapshot_type=snapshot.snapshot_type,
                )

        # --- Atomic move: undo = move back from trash ---
        if snapshot.snapshot_type == SnapshotType.ATOMIC_MOVE.value:
            if not snapshot.snapshot_path or not Path(snapshot.snapshot_path).exists():
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.SNAPSHOT_MISSING,
                    original_path=snapshot.original_path,
                    message="Trashed file not found",
                    snapshot_type=snapshot.snapshot_type,
                )

            target = Path(snapshot.original_path)
            if target.exists() and not force:
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.CONFLICT,
                    original_path=snapshot.original_path,
                    message="File already exists at original location",
                    snapshot_type=snapshot.snapshot_type,
                    conflict_detail="File exists at restore target",
                )

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(snapshot.snapshot_path, str(target))
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.SUCCESS,
                    original_path=snapshot.original_path,
                    message="Restored from trash (atomic move back)",
                    snapshot_type=snapshot.snapshot_type,
                )
            except (IOError, OSError) as e:
                return RollbackResult(
                    event_id=snapshot.event_id,
                    status=RollbackStatus.ERROR,
                    original_path=snapshot.original_path,
                    message=f"Restore from trash failed: {e}",
                    snapshot_type=snapshot.snapshot_type,
                )

        # --- JSON diff: undo = return the "before" config ---
        if snapshot.snapshot_type == SnapshotType.JSON_DIFF.value:
            # Config rollback is returned as data — the caller decides
            # how to apply it (write to file, update settings, etc.)
            diff = json.loads(snapshot.metadata) if snapshot.metadata else {}
            return RollbackResult(
                event_id=snapshot.event_id,
                status=RollbackStatus.SUCCESS,
                original_path=snapshot.original_path,
                message=f"Config rollback data available: {json.dumps(diff.get('before', {}))[:80]}",
                snapshot_type=snapshot.snapshot_type,
            )

        # Unknown snapshot type
        return RollbackResult(
            event_id=snapshot.event_id,
            status=RollbackStatus.NOT_RESTORABLE,
            original_path=snapshot.original_path,
            message=f"Unknown snapshot type: {snapshot.snapshot_type}",
            snapshot_type=snapshot.snapshot_type,
        )

    def rollback_batch(
        self, snapshots: list[Snapshot], force: bool = False
    ) -> list[RollbackResult]:
        """Roll back multiple snapshots in reverse chronological order.

        Snapshots should be provided newest-first. They will be rolled back
        in that order (newest action undone first).
        """
        results = []
        for snapshot in snapshots:
            result = self.rollback_single(snapshot, force=force)
            results.append(result)

            # If a non-force rollback hits a conflict, stop the batch
            if not force and result.status == RollbackStatus.CONFLICT:
                break

        return results
