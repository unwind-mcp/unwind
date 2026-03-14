from __future__ import annotations

"""Shadow VFS — in-memory filesystem overlay for Ghost Mode.

When Ghost Mode intercepts a write, the content goes here.
When a subsequent read targets the same path, the shadow returns
the "written" content so the agent stays consistent.

The agent thinks it wrote a file and can read it back.
In reality, nothing touched disk.
"""

from typing import Optional


class ShadowVFS:
    """In-memory virtual filesystem overlay.

    Tracks writes that were intercepted and serves them back on reads,
    maintaining agent consistency without touching the real filesystem.
    """

    def __init__(self):
        self._store: dict[str, str | bytes] = {}
        self._deleted: set[str] = set()

    def write(self, path: str, content: str | bytes) -> None:
        """Record a ghost write."""
        self._store[path] = content
        self._deleted.discard(path)

    def read(self, path: str) -> Optional[str | bytes]:
        """Read from shadow. Returns None if path not in shadow."""
        if path in self._deleted:
            return ""  # File was "deleted" in ghost mode
        return self._store.get(path)

    def delete(self, path: str) -> None:
        """Record a ghost delete."""
        self._store.pop(path, None)
        self._deleted.add(path)

    def rename(self, old_path: str, new_path: str) -> None:
        """Record a ghost rename."""
        content = self._store.pop(old_path, None)
        if content is not None:
            self._store[new_path] = content
        self._deleted.add(old_path)
        self._deleted.discard(new_path)

    def has(self, path: str) -> bool:
        """Check if a path has been touched in ghost mode."""
        return path in self._store or path in self._deleted

    @property
    def write_count(self) -> int:
        return len(self._store)

    @property
    def delete_count(self) -> int:
        return len(self._deleted)

    def clear(self) -> None:
        """Reset the shadow filesystem."""
        self._store.clear()
        self._deleted.clear()

    def summary(self) -> dict:
        """Return a summary of ghost activity."""
        return {
            "files_written": list(self._store.keys()),
            "files_deleted": list(self._deleted),
            "write_count": self.write_count,
            "delete_count": self.delete_count,
        }
