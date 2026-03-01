#!/usr/bin/env python3
"""Build a cold-start recovery packet from workspace memory files.

Goal: produce a high-signal briefing that can be read in <2 minutes after
context reset/compaction.
"""

from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return path.read_text(errors="ignore").splitlines()


def extract_sections(md_lines: list[str]) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = "__root__"
    sections[current] = []
    for line in md_lines:
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
            continue
        sections.setdefault(current, []).append(line)
    return sections


def pick_bullets(lines: list[str], limit: int) -> list[str]:
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if line.startswith("- "):
            out.append(line)
        if len(out) >= limit:
            break
    return out


def tail_bullets(lines: list[str], limit: int) -> list[str]:
    bullets = [ln.strip() for ln in lines if ln.strip().startswith("- ")]
    return bullets[-limit:]


def date_file(day: dt.date) -> Path:
    return ROOT / "memory" / f"{day.isoformat()}.md"


def build_packet(now: dt.datetime) -> str:
    identity = read_lines(ROOT / "IDENTITY.md")
    user = read_lines(ROOT / "USER.md")
    memory_md = read_lines(ROOT / "MEMORY.md")
    critical_ip = read_lines(ROOT / "memory" / "CRITICAL_IP.md")

    today = now.date()
    yesterday = today - dt.timedelta(days=1)
    today_lines = read_lines(date_file(today))
    yday_lines = read_lines(date_file(yesterday))
    decision_lines = read_lines(ROOT / "memory" / "decision-log.md")

    memory_sections = extract_sections(memory_md)

    durable = []
    for heading in [
        "1) Project identity and boundaries",
        "2) Core architecture (durable)",
        "5) Infrastructure anchors",
        "6) Key strategic decisions (durable)",
    ]:
        durable.extend(pick_bullets(memory_sections.get(heading, []), 4))

    if not durable:
        durable = pick_bullets(memory_md, 12)

    critical_todos = [
        ln.strip()
        for ln in critical_ip
        if ln.strip().startswith("- Status: TODO") or ln.strip().startswith("- Missing:")
    ]

    id_anchor = pick_bullets(identity, 4)
    user_anchor = pick_bullets(user, 6)
    today_tail = tail_bullets(today_lines, 10)
    yday_tail = tail_bullets(yday_lines, 6)
    decision_candidates = [ln.strip() for ln in decision_lines if ln.strip().startswith("-")]
    decisions = [
        ln for ln in decision_candidates
        if ln.startswith("- 20") or ln.startswith("- decision:") or ln.startswith("- rationale:") or ln.startswith("- alternatives:")
    ][-8:]

    ts = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    out: list[str] = []
    out.append("# SENTINEL Recovery Packet")
    out.append("")
    out.append(f"Generated: {ts}")
    out.append(f"Workspace: {ROOT}")
    out.append("")

    out.append("## 0) Fast recovery order (<2 min target)")
    out.append("")
    out.append("1. Read this packet end-to-end.")
    out.append("2. Read `memory/CRITICAL_IP.md` for unresolved continuity-critical gaps.")
    out.append("3. Read today/yesterday memory logs for latest operational deltas.")
    out.append("4. Run `openclaw status` and `openclaw memory status --json`.")
    out.append("5. Continue work; avoid relying on pre-reset transcript context.")
    out.append("")

    out.append("## 1) Identity + human anchor")
    out.append("")
    for item in id_anchor + user_anchor:
        out.append(item)
    out.append("")

    out.append("## 2) Durable project facts (from MEMORY.md)")
    out.append("")
    for item in durable[:16]:
        out.append(item)
    out.append("")

    out.append("## 3) Active continuity snapshot")
    out.append("")
    out.append(f"### Today ({today.isoformat()})")
    for item in today_tail or ["- No daily log found for today."]:
        out.append(item)
    out.append("")
    out.append(f"### Yesterday ({yesterday.isoformat()})")
    for item in yday_tail or ["- No daily log found for yesterday."]:
        out.append(item)
    out.append("")

    out.append("## 4) Open continuity gaps")
    out.append("")
    for item in critical_todos or ["- No TODO gaps detected in CRITICAL_IP.md"]:
        out.append(item)
    out.append("")

    out.append("## 5) Recent architecture decisions")
    out.append("")
    for item in decisions or ["- No recent decision bullets found."]:
        out.append(item)
    out.append("")

    out.append("## 6) Verification commands")
    out.append("")
    out.append("```bash")
    out.append("openclaw status")
    out.append("openclaw memory status --json")
    out.append("openclaw hooks info session-memory")
    out.append("```")
    out.append("")

    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SENTINEL cold-start recovery packet")
    parser.add_argument(
        "--out",
        default=str(ROOT / "memory" / "RECOVERY_PACKET.md"),
        help="Output markdown path",
    )
    args = parser.parse_args()

    start = time.perf_counter()
    now = dt.datetime.now().astimezone()
    packet = build_packet(now)

    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(packet, encoding="utf-8")

    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"Wrote recovery packet: {out_path}")
    print(f"Elapsed: {elapsed_ms:.1f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
