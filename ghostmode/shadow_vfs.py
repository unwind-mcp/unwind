from __future__ import annotations

"""Shadow VFS — in-memory filesystem overlay for Ghost Mode.

When Ghost Mode intercepts a write, the content goes here.
When a subsequent read targets the same path, the shadow returns
the "written" content so the agent stays consistent.

The agent thinks it wrote a file and can read it back.
In reality, nothing touched disk.
"""

import fnmatch
import os
import time
from typing import Optional


def normalize(path: str) -> str:
    """Normalise a path so the same file always maps to the same key."""
    return os.path.normpath(os.path.expanduser(str(path)))


class EditNotFound(ValueError):
    """An edit's oldText was not found in the file."""


def apply_edits(content: str, edits: list[dict]) -> str:
    """Apply filesystem-server style edits ({oldText, newText}) to content.

    Mirrors the upstream server: each edit must match, otherwise the
    whole edit fails and nothing changes.
    """
    result = content.replace("\r\n", "\n")
    for edit in edits:
        old = str(edit.get("oldText", "")).replace("\r\n", "\n")
        new = str(edit.get("newText", "")).replace("\r\n", "\n")
        if old and old in result:
            result = result.replace(old, new, 1)
            continue
        # Fall back to whitespace-insensitive line matching, like the server
        old_lines = old.split("\n")
        lines = result.split("\n")
        for i in range(len(lines) - len(old_lines) + 1):
            window = lines[i:i + len(old_lines)]
            if [l.strip() for l in window] == [l.strip() for l in old_lines]:
                # Re-indent the replacement to where the match was found
                indent = window[0][:len(window[0]) - len(window[0].lstrip())]
                old_indent = old_lines[0][:len(old_lines[0]) - len(old_lines[0].lstrip())]
                new_lines = [indent + (l[len(old_indent):] if l.startswith(old_indent) else l.lstrip())
                             for l in new.split("\n")]
                lines[i:i + len(old_lines)] = new_lines
                result = "\n".join(lines)
                break
        else:
            raise EditNotFound(f"Could not find exact match for edit:\n{old}")
    return result


class ShadowVFS:
    """In-memory virtual filesystem overlay.

    Tracks writes that were intercepted and serves them back on reads,
    maintaining agent consistency without touching the real filesystem.
    """

    def __init__(self):
        self._store: dict[str, str | bytes] = {}
        self._mtimes: dict[str, float] = {}
        self._dirs: set[str] = set()
        self._deleted: set[str] = set()

    def write(self, path: str, content: str | bytes) -> None:
        """Record a ghost write."""
        path = normalize(path)
        self._store[path] = content
        self._mtimes[path] = time.time()
        self._deleted.discard(path)

    def mkdir(self, path: str) -> None:
        """Record a ghost directory creation.

        Missing parents need no entry of their own: children() treats any
        directory above a shadow path as existing, like mkdir -p.
        """
        path = normalize(path)
        self._dirs.add(path)
        self._mtimes[path] = time.time()
        self._deleted.discard(path)

    def read(self, path: str) -> Optional[str | bytes]:
        """Read from shadow. Returns None if path not in shadow.

        Returns "" for a path deleted in ghost mode; use is_deleted() to
        tell that apart from an empty file.
        """
        path = normalize(path)
        if path in self._deleted:
            return ""  # File was "deleted" in ghost mode
        return self._store.get(path)

    def delete(self, path: str) -> None:
        """Record a ghost delete."""
        path = normalize(path)
        self._store.pop(path, None)
        self._dirs.discard(path)
        self._deleted.add(path)

    def rename(self, old_path: str, new_path: str) -> None:
        """Record a ghost rename of a file or directory already in the shadow."""
        old_path, new_path = normalize(old_path), normalize(new_path)
        content = self._store.pop(old_path, None)
        if content is not None:
            self._store[new_path] = content
            self._mtimes[new_path] = time.time()
        if old_path in self._dirs:
            self.mkdir(new_path)
            self._dirs.discard(old_path)
            prefix = old_path + os.sep
            for p in [p for p in self._store if p.startswith(prefix)]:
                self._store[new_path + p[len(old_path):]] = self._store.pop(p)
            for d in [d for d in self._dirs if d.startswith(prefix)]:
                self._dirs.discard(d)
                self._dirs.add(new_path + d[len(old_path):])
        self._deleted.add(old_path)
        self._deleted.discard(new_path)

    def has(self, path: str) -> bool:
        """Check if a path has been touched in ghost mode."""
        path = normalize(path)
        return path in self._store or path in self._deleted or path in self._dirs

    def is_file(self, path: str) -> bool:
        return normalize(path) in self._store

    def is_dir(self, path: str) -> bool:
        return normalize(path) in self._dirs

    def is_deleted(self, path: str) -> bool:
        """True if the path, or a directory above it, was deleted in ghost mode."""
        path = normalize(path)
        if path in self._store or path in self._dirs:
            return False
        while True:
            if path in self._deleted:
                return True
            parent = os.path.dirname(path)
            if parent == path or parent in self._store or parent in self._dirs:
                return False
            path = parent

    def mtime(self, path: str) -> float:
        return self._mtimes.get(normalize(path), time.time())

    # ── Listing overlay ──

    def children(self, directory: str) -> tuple[dict[str, str], set[str]]:
        """Shadow changes directly inside a directory.

        Returns ({name: "file"|"dir"} added in the shadow, {names deleted}).
        """
        directory = normalize(directory)
        prefix = directory.rstrip(os.sep) + os.sep
        added: dict[str, str] = {}
        for p in (*self._store, *self._dirs):
            if not p.startswith(prefix):
                continue
            first, sep, _ = p[len(prefix):].partition(os.sep)
            if sep or p in self._dirs:
                added[first] = "dir"
            else:
                added.setdefault(first, "file")
        deleted = {os.path.basename(p) for p in self._deleted
                   if os.path.dirname(p) == directory
                   and os.path.basename(p) not in added}
        return added, deleted

    def touches_tree(self, directory: str) -> bool:
        """True if the shadow has any change at or below this directory."""
        directory = normalize(directory)
        prefix = directory.rstrip(os.sep) + os.sep
        return any(p == directory or p.startswith(prefix)
                   for p in (*self._store, *self._dirs, *self._deleted))

    def search(self, root: str, pattern: str) -> list[str]:
        """Shadow files/dirs under root whose name or relative path matches."""
        root = normalize(root)
        prefix = root.rstrip(os.sep) + os.sep
        matches = []
        for p in sorted({*self._store, *self._dirs}):
            if not p.startswith(prefix):
                continue
            rel, name = p[len(prefix):], os.path.basename(p)
            if (fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern)
                    or pattern.lower() in name.lower()):
                matches.append(p)
        return matches

    @property
    def write_count(self) -> int:
        return len(self._store)

    @property
    def delete_count(self) -> int:
        return len(self._deleted)

    def clear(self) -> None:
        """Reset the shadow filesystem."""
        self._store.clear()
        self._mtimes.clear()
        self._dirs.clear()
        self._deleted.clear()

    def summary(self) -> dict:
        """Return a summary of ghost activity."""
        return {
            "files_written": list(self._store.keys()),
            "files_deleted": list(self._deleted),
            "dirs_created": sorted(self._dirs),
            "write_count": self.write_count,
            "delete_count": self.delete_count,
        }
