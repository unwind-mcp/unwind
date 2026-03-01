"""Cadence CLI — reset, forget, status.

Usage:
    cadence status                  Show current rhythm state
    cadence reset                   Clear all rhythm data (CRIP: DATA_RESET)
    cadence forget --before DATE    Remove events before DATE (CRIP: DATA_DELETED)
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine.rhythm import RhythmEngine
from .protocol.crip import CRIPHeaders
from .storage.pulse import PulseLog
from .storage.state import StateFile
from .storage.profile import ProfileWriter


DEFAULT_CADENCE_DIR = Path("cadence")


def _get_paths(base: Path) -> tuple[Path, Path, Path]:
    return (
        base / "pulse.jsonl",
        base / "state.env",
        base / "profile.md",
    )


def cmd_status(args: argparse.Namespace) -> int:
    """Show current rhythm state."""
    base = Path(args.dir)
    pulse_path, state_path, profile_path = _get_paths(base)

    state_file = StateFile(state_path)
    state = state_file.read()

    if state is None:
        print("Cadence: not initialised (no state.env found)")
        return 1

    print("Cadence Status")
    print("-" * 40)
    for key, value in state.items():
        print(f"  {key}: {value}")

    pulse = PulseLog(pulse_path)
    count = pulse.event_count()
    print(f"\n  Events logged: {count}")

    if profile_path.exists():
        print(f"  Profile: {profile_path}")
    else:
        print("  Profile: not yet generated")

    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    """Clear all rhythm data."""
    base = Path(args.dir)
    pulse_path, state_path, profile_path = _get_paths(base)

    pulse = PulseLog(pulse_path)
    count = pulse.reset()
    print(f"Cadence: reset complete. {count} events removed.")

    state_file = StateFile(state_path)
    state_file.clear()
    print("Cadence: state.env cleared.")

    if profile_path.exists():
        profile_path.unlink()
        print("Cadence: profile.md removed.")

    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    """Remove events before a given date."""
    try:
        before = datetime.fromisoformat(args.before)
        if before.tzinfo is None:
            before = before.replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"Error: invalid date format: {args.before}")
        print("Use ISO 8601 format, e.g. 2026-02-28 or 2026-02-28T14:00:00Z")
        return 1

    base = Path(args.dir)
    pulse_path, _, _ = _get_paths(base)

    pulse = PulseLog(pulse_path)
    removed = pulse.forget_before(before)
    print(f"Cadence: {removed} events removed before {before.isoformat()}")

    return 0


def main(argv: list[str] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cadence",
        description="Cadence — temporal-awareness rhythm layer",
    )
    parser.add_argument(
        "--dir", default=str(DEFAULT_CADENCE_DIR),
        help="Cadence data directory (default: cadence/)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show current rhythm state")
    sub.add_parser("reset", help="Clear all rhythm data")

    forget_parser = sub.add_parser("forget", help="Remove events before a date")
    forget_parser.add_argument(
        "--before", required=True,
        help="ISO 8601 date/datetime cutoff",
    )

    args = parser.parse_args(argv)

    if args.command == "status":
        return cmd_status(args)
    elif args.command == "reset":
        return cmd_reset(args)
    elif args.command == "forget":
        return cmd_forget(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
