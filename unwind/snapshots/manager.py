"""Smart Snapshot Manager.

Captures pre-action state for rollback capability:
1. Try OS-native reflink/copy-on-write first (essentially free)
2. Fall back to normal copy if reflink unavailable
3. Size cap: 25MB — files larger than this are skipped
4. Atomic moves for deletions (instant, no copy)
5. JSON diffs for config changes

Snapshots are stored in ~/.unwind/snapshots/ with metadata in SQLite.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from ..config import UnwindConfig


class SnapshotType(Enum):
    FILE_COPY = "file_copy"          # Full file backup (reflink or copy)
    ATOMIC_MOVE = "atomic_move"      # File moved to trash (for deletions)
    JSON_DIFF = "json_diff"          # JSON before/after diff
    SKIPPED_TOO_LARGE = "skipped"    # File exceeded size cap
    CONTENT_ONLY = "content_only"    # Content stored directly (small files/configs)


@dataclass
class Snapshot:
    """Record of a pre-action state capture."""
    snapshot_id: str
    event_id: str
    timestamp: float
    snapshot_type: str  # SnapshotType value
    original_path: str
    snapshot_path: Optional[str]  # Where the backup lives
    original_size: int
    original_hash: Optional[str]  # SHA-256 of original content
    metadata: Optional[str]  # JSON metadata (e.g., diff content)
    restorable: bool  # Can this be fully reversed?


class SnapshotManager:
    """Manages pre-action snapshots for rollback capability."""

    def __init__(self, config: UnwindConfig):
        self.config = config
        self._system = platform.system()

    def _generate_snapshot_id(self, event_id: str) -> str:
        """Generate a snapshot ID tied to its event."""
        return f"snap_{event_id}"

    def _snapshot_file_path(self, snapshot_id: str, original_path: str) -> Path:
        """Compute the storage path for a snapshot file."""
        # Preserve original extension for easy identification
        ext = Path(original_path).suffix
        return self.config.snapshots_dir / f"{snapshot_id}{ext}"

    def _file_hash(self, path: str) -> Optional[str]:
        """Compute SHA-256 of a file. Returns None if file doesn't exist."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, OSError):
            return None

    def _try_reflink_copy(self, src: str, dst: str) -> bool:
        """Attempt OS-native reflink/copy-on-write. Returns True if successful."""
        try:
            if self._system == "Linux":
                result = subprocess.run(
                    ["cp", "--reflink=auto", src, dst],
                    capture_output=True, timeout=10,
                )
                return result.returncode == 0
            elif self._system == "Darwin":
                # macOS APFS clone
                result = subprocess.run(
                    ["cp", "-c", src, dst],
                    capture_output=True, timeout=10,
                )
                return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return False

    def snapshot_file_write(self, event_id: str, target_path: str) -> Snapshot:
        """Snapshot a file before it's written/modified.

        Strategy: reflink → copy fallback → skip if too large.
        """
        snapshot_id = self._generate_snapshot_id(event_id)
        target = Path(target_path)

        # If the file doesn't exist yet (new file creation), nothing to snapshot
        if not target.exists():
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.CONTENT_ONLY.value,
                original_path=target_path,
                snapshot_path=None,
                original_size=0,
                original_hash=None,
                metadata=json.dumps({"type": "new_file", "existed": False}),
                restorable=True,  # Rollback = delete the new file
            )

        file_size = target.stat().st_size

        # Size cap check
        if file_size > self.config.snapshot_max_file_bytes:
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.SKIPPED_TOO_LARGE.value,
                original_path=target_path,
                snapshot_path=None,
                original_size=file_size,
                original_hash=self._file_hash(target_path),
                metadata=json.dumps({
                    "type": "skipped",
                    "reason": f"File size {file_size} exceeds cap {self.config.snapshot_max_file_bytes}",
                }),
                restorable=False,
            )

        # Compute hash before copying
        original_hash = self._file_hash(target_path)
        snap_path = self._snapshot_file_path(snapshot_id, target_path)

        # Try reflink first (essentially free on supported filesystems)
        if self._try_reflink_copy(target_path, str(snap_path)):
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.FILE_COPY.value,
                original_path=target_path,
                snapshot_path=str(snap_path),
                original_size=file_size,
                original_hash=original_hash,
                metadata=json.dumps({"method": "reflink"}),
                restorable=True,
            )

        # Fallback: regular copy
        try:
            shutil.copy2(target_path, str(snap_path))
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.FILE_COPY.value,
                original_path=target_path,
                snapshot_path=str(snap_path),
                original_size=file_size,
                original_hash=original_hash,
                metadata=json.dumps({"method": "copy"}),
                restorable=True,
            )
        except (IOError, OSError) as e:
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.SKIPPED_TOO_LARGE.value,
                original_path=target_path,
                snapshot_path=None,
                original_size=file_size,
                original_hash=original_hash,
                metadata=json.dumps({"type": "copy_failed", "error": str(e)}),
                restorable=False,
            )

    def snapshot_file_delete(self, event_id: str, target_path: str) -> Snapshot:
        """Snapshot a file before deletion by atomic move to trash.

        Instead of copy-then-delete, we intercept the delete and move
        the file to our trash directory. Moves on the same drive are instant.
        """
        snapshot_id = self._generate_snapshot_id(event_id)
        target = Path(target_path)

        if not target.exists():
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.ATOMIC_MOVE.value,
                original_path=target_path,
                snapshot_path=None,
                original_size=0,
                original_hash=None,
                metadata=json.dumps({"type": "file_not_found"}),
                restorable=False,
            )

        file_size = target.stat().st_size
        original_hash = self._file_hash(target_path)
        trash_path = self.config.trash_dir / f"{snapshot_id}_{target.name}"

        try:
            # Atomic move — instant on same filesystem
            shutil.move(target_path, str(trash_path))
            return Snapshot(
                snapshot_id=snapshot_id,
                event_id=event_id,
                timestamp=time.time(),
                snapshot_type=SnapshotType.ATOMIC_MOVE.value,
                original_path=target_path,
                snapshot_path=str(trash_path),
                original_size=file_size,
                original_hash=original_hash,
                metadata=json.dumps({"method": "atomic_move"}),
                restorable=True,
            )
        except (IOError, OSError) as e:
            # Move failed — try copy as fallback
            try:
                snap_path = self._snapshot_file_path(snapshot_id, target_path)
                shutil.copy2(target_path, str(snap_path))
                return Snapshot(
                    snapshot_id=snapshot_id,
                    event_id=event_id,
                    timestamp=time.time(),
                    snapshot_type=SnapshotType.FILE_COPY.value,
                    original_path=target_path,
                    snapshot_path=str(snap_path),
                    original_size=file_size,
                    original_hash=original_hash,
                    metadata=json.dumps({"method": "copy_fallback", "move_error": str(e)}),
                    restorable=True,
                )
            except (IOError, OSError) as e2:
                return Snapshot(
                    snapshot_id=snapshot_id,
                    event_id=event_id,
                    timestamp=time.time(),
                    snapshot_type=SnapshotType.SKIPPED_TOO_LARGE.value,
                    original_path=target_path,
                    snapshot_path=None,
                    original_size=file_size,
                    original_hash=original_hash,
                    metadata=json.dumps({"type": "snapshot_failed", "error": str(e2)}),
                    restorable=False,
                )

    def snapshot_config_change(self, event_id: str, before: dict, after: dict) -> Snapshot:
        """Snapshot a configuration change as a JSON diff."""
        snapshot_id = self._generate_snapshot_id(event_id)
        diff = {
            "before": before,
            "after": after,
        }
        return Snapshot(
            snapshot_id=snapshot_id,
            event_id=event_id,
            timestamp=time.time(),
            snapshot_type=SnapshotType.JSON_DIFF.value,
            original_path="config",
            snapshot_path=None,
            original_size=len(json.dumps(before)),
            original_hash=hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
            metadata=json.dumps(diff),
            restorable=True,
        )
