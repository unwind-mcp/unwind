"""Profile — human-readable rhythm summary.

Auto-updated plain English summary of the current rhythm.
The agent reads profile.md for broader context. Includes archived
thread breadcrumbs with configurable TTL.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..engine.rhythm import RhythmEngine, TimeBin


class ProfileWriter:
    """Auto-update cadence/profile.md with rhythm summary."""

    def __init__(self, path: Path, utc_offset_hours: float = 0.0):
        self.path = path
        self.utc_offset_hours = utc_offset_hours

    def update(self, engine: RhythmEngine) -> None:
        """Rewrite profile.md with current rhythm data."""
        lines = ["## Current Rhythm Profile\n"]

        bin_labels = {
            TimeBin.MORNING: "Morning (6am-12pm)",
            TimeBin.AFTERNOON: "Afternoon (12pm-6pm)",
            TimeBin.EVENING: "Evening (6pm-11pm)",
            TimeBin.NIGHT: "Night (11pm-6am)",
        }

        for bin_type in TimeBin:
            state = engine.bins[bin_type]
            label = bin_labels[bin_type]
            if state.observation_count == 0:
                lines.append(f"- {label}: no data yet\n")
            else:
                minutes = state.ema_seconds / 60
                if minutes < 1:
                    timing = f"{state.ema_seconds:.0f} seconds"
                else:
                    timing = f"{minutes:.0f} minutes"
                confidence = "confident" if state.is_confident else "learning"
                lines.append(
                    f"- {label}: typical response ~{timing} "
                    f"({state.observation_count} observations, {confidence})\n"
                )

        now = datetime.now(timezone.utc)
        lines.append(f"- Last updated: {now.isoformat()}\n")
        if self.utc_offset_hours != 0:
            sign = "+" if self.utc_offset_hours >= 0 else ""
            lines.append(f"- Timezone offset: {sign}{self.utc_offset_hours:.1f}h\n")

        # Preserve archived threads section if it exists
        archived = self._read_archived_section()
        if archived:
            lines.append("\n")
            lines.extend(archived)

        content = "".join(lines)

        # Atomic write
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".md.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(self.path))

    def add_archived_thread(self, date: str, summary: str) -> None:
        """Add an archived thread breadcrumb to profile.md."""
        archived = self._read_archived_section()
        if not archived:
            archived = ["## Archived Threads (TTL expired)\n"]
        archived.append(f"- [{date}] {summary}\n")

        # Read full file and replace/append archived section
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                content = f.read()
            # Remove old archived section
            marker = "## Archived Threads"
            idx = content.find(marker)
            if idx >= 0:
                content = content[:idx]
            content = content.rstrip() + "\n\n" + "".join(archived)
        else:
            content = "".join(archived)

        tmp = self.path.with_suffix(".md.tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp), str(self.path))

    def _read_archived_section(self) -> list[str]:
        """Extract the archived threads section from profile.md."""
        if not self.path.exists():
            return []
        lines = []
        in_section = False
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("## Archived Threads"):
                    in_section = True
                elif line.startswith("## ") and in_section:
                    break
                if in_section:
                    lines.append(line)
        return lines
