#!/usr/bin/env python3
"""Evidence Pack Generator for SENTINEL verification.

Produces a structured text bundle containing actual code, diffs, test
results, and config snapshots that can be pasted directly to SENTINEL
for code-level verification.

Closes the visibility gap: SENTINEL reviews code truth, not summaries.

Usage:
    python tools/evidence_pack.py                    # Full pack
    python tools/evidence_pack.py --since HEAD~3     # Last 3 commits
    python tools/evidence_pack.py --since abc123     # Since specific commit
    python tools/evidence_pack.py --files-only       # Just changed file contents
    python tools/evidence_pack.py --section tests    # Only test results section

Output goes to stdout (for piping/pasting) or to a file with --output.
"""

import argparse
import json
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

# Repo root (relative to this script)
REPO_ROOT = Path(__file__).resolve().parent.parent
ENFORCEMENT_DIR = REPO_ROOT / "unwind" / "enforcement"
TESTS_DIR = REPO_ROOT / "tests"

# Max lines per file before truncation
MAX_FILE_LINES = 500

# Enforcement modules — the security-critical code SENTINEL needs to verify
CRITICAL_MODULES = [
    "pipeline.py",
    "supply_chain.py",
    "signature_verify.py",
    "approval_windows.py",
    "rubber_stamp.py",
    "taint_decay.py",
]


def run(cmd, cwd=None, timeout=30):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=cwd or REPO_ROOT, timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def section_header(title):
    """Format a section header."""
    bar = "=" * 72
    return f"\n{bar}\n  {title}\n{bar}\n"


def git_log_section(since):
    """Git log since reference point."""
    out, _, _ = run(f"git log --oneline --no-decorate {since}..HEAD")
    if not out:
        out, _, _ = run("git log --oneline --no-decorate -10")
    return section_header("GIT LOG") + out


def git_diff_stat_section(since):
    """Git diff --stat showing changed files."""
    out, _, _ = run(f"git diff --stat {since}..HEAD")
    if not out:
        out, _, _ = run("git diff --stat HEAD~5..HEAD")
    return section_header("DIFF STAT") + out


def changed_files_section(since):
    """List of changed files with their full paths."""
    out, _, _ = run(f"git diff --name-only {since}..HEAD")
    if not out:
        out, _, _ = run("git diff --name-only HEAD~5..HEAD")
    return section_header("CHANGED FILES") + out


def file_contents_section(since=None, files_list=None):
    """Full contents of changed enforcement files.

    This is the core of the evidence pack — actual code SENTINEL can verify.
    """
    if files_list is None:
        # Get changed files from git
        out, _, _ = run(f"git diff --name-only {since}..HEAD" if since else "git diff --name-only HEAD~5..HEAD")
        files_list = [f.strip() for f in out.split("\n") if f.strip()]

    # Filter to enforcement + test files (security-critical)
    critical_files = []
    for f in files_list:
        if any(f.endswith(m) for m in CRITICAL_MODULES):
            critical_files.append(f)
        elif f.startswith("tests/"):
            critical_files.append(f)
        elif f.startswith("unwind/enforcement/"):
            critical_files.append(f)

    # Also always include current versions of critical modules
    for mod in CRITICAL_MODULES:
        mod_path = f"unwind/enforcement/{mod}"
        if mod_path not in critical_files:
            full_path = REPO_ROOT / mod_path
            if full_path.exists():
                critical_files.append(mod_path)

    output = section_header("FILE CONTENTS (security-critical modules)")

    for rel_path in sorted(set(critical_files)):
        full_path = REPO_ROOT / rel_path
        if not full_path.exists():
            output += f"\n--- {rel_path} (DELETED) ---\n"
            continue

        try:
            content = full_path.read_text(encoding="utf-8")
            lines = content.split("\n")
            truncated = ""
            if len(lines) > MAX_FILE_LINES:
                lines = lines[:MAX_FILE_LINES]
                truncated = f"\n... TRUNCATED at {MAX_FILE_LINES} lines (full file: {len(content.split(chr(10)))} lines) ..."

            output += f"\n--- {rel_path} ({len(lines)} lines) ---\n"
            output += "\n".join(f"{i+1:4d}| {line}" for i, line in enumerate(lines))
            output += truncated + "\n"
        except Exception as e:
            output += f"\n--- {rel_path} (READ ERROR: {e}) ---\n"

    return output


def git_diff_content_section(since):
    """Actual diff content for changed enforcement files."""
    out, _, _ = run(
        f"git diff {since}..HEAD -- unwind/enforcement/ tests/",
    )
    if not out:
        out, _, _ = run("git diff HEAD~5..HEAD -- unwind/enforcement/ tests/")

    if len(out) > 50000:
        out = out[:50000] + "\n\n... DIFF TRUNCATED AT 50000 chars ..."

    return section_header("DIFF CONTENT (enforcement + tests)") + out


def test_results_section():
    """Run pytest and capture results."""
    output = section_header("TEST RESULTS")

    # Run full suite
    stdout, stderr, rc = run(
        "python -m pytest tests/ -v --tb=short 2>&1",
        timeout=120,
    )

    # Summary line
    for line in (stdout + stderr).split("\n"):
        if "passed" in line or "failed" in line or "error" in line.lower():
            output += f"SUMMARY: {line}\n"
            break

    output += f"EXIT CODE: {rc}\n\n"

    # Full output
    output += stdout
    if stderr:
        output += f"\n\nSTDERR:\n{stderr}"

    return output


def strict_mode_config_section():
    """Extract the effective strict-mode configuration from code."""
    output = section_header("STRICT-MODE CONFIG SNAPSHOT")

    # Extract the strict parameter from pipeline.py
    pipeline_path = ENFORCEMENT_DIR / "pipeline.py"
    if pipeline_path.exists():
        content = pipeline_path.read_text()

        # Find __init__ signature
        output += "Pipeline.__init__ strict parameter:\n"
        for i, line in enumerate(content.split("\n")):
            if "strict" in line.lower() and ("def __init__" in content.split("\n")[max(0,i-5):i+1][-1] if i > 0 else False or "self.strict" in line):
                output += f"  {line.strip()}\n"

        # Find all strict-mode branch points
        output += "\nStrict-mode branch points in pipeline.py:\n"
        for i, line in enumerate(content.split("\n"), 1):
            if "self.strict" in line:
                output += f"  L{i}: {line.strip()}\n"

    # Extract strict-mode branches from supply_chain.py
    sc_path = ENFORCEMENT_DIR / "supply_chain.py"
    if sc_path.exists():
        content = sc_path.read_text()
        output += "\nStrict-mode branch points in supply_chain.py:\n"
        for i, line in enumerate(content.split("\n"), 1):
            if "strict" in line.lower() and ("if" in line or "strict" in line):
                output += f"  L{i}: {line.strip()}\n"

    return output


def reason_code_section():
    """Extract all reason codes from enforcement modules."""
    output = section_header("REASON CODES")

    reason_codes = set()
    for mod in CRITICAL_MODULES:
        mod_path = ENFORCEMENT_DIR / mod
        if not mod_path.exists():
            continue
        content = mod_path.read_text()
        for i, line in enumerate(content.split("\n"), 1):
            # Look for reason code patterns
            for pattern in [
                "TRUST_LEG_MISSING",
                "DIGEST_PROVIDER_MISSING",
                "DIGEST_PROVIDER_ERROR",
                "SIGNATURE_VERIFIER_ERROR",
                "R-STRICT-001",
                "R-LOCK-003",
                "R-SIG-001",
                "R-LOCK-002",
                "LOCK_HMAC_MISSING",
                "KEYSTORE_HMAC_INVALID",
                "TOFU_FORBIDDEN_IN_STRICT",
                "BREAKGLASS_DISABLED",
            ]:
                if pattern in line:
                    reason_codes.add((pattern, mod, i, line.strip()))

    for code, mod, lineno, line in sorted(reason_codes):
        output += f"  {code} @ {mod}:L{lineno}\n    {line}\n"

    return output


def metadata_section():
    """Pack metadata: timestamp, commit, test count."""
    output = section_header("EVIDENCE PACK METADATA")

    timestamp = datetime.now(timezone.utc).isoformat()
    commit_hash, _, _ = run("git rev-parse --short HEAD")
    commit_msg, _, _ = run("git log -1 --format=%s")
    branch, _, _ = run("git rev-parse --abbrev-ref HEAD")

    # Count tests
    test_count_out, _, _ = run(
        "python -m pytest tests/ --collect-only -q 2>&1 | tail -1",
        timeout=30,
    )

    output += f"Timestamp (UTC): {timestamp}\n"
    output += f"Branch: {branch}\n"
    output += f"HEAD: {commit_hash} — {commit_msg}\n"
    output += f"Test collection: {test_count_out}\n"
    output += f"Generator: tools/evidence_pack.py v1.0\n"
    output += f"Purpose: SENTINEL code-level verification (R-STRICT-001)\n"

    return output


def build_pack(args):
    """Build the full evidence pack."""
    since = args.since or "HEAD~5"
    sections = []

    # Always include metadata
    sections.append(metadata_section())

    if args.section:
        # Single section mode
        section_map = {
            "log": lambda: git_log_section(since),
            "stat": lambda: git_diff_stat_section(since),
            "files": lambda: changed_files_section(since),
            "contents": lambda: file_contents_section(since),
            "diff": lambda: git_diff_content_section(since),
            "tests": test_results_section,
            "config": strict_mode_config_section,
            "reasons": reason_code_section,
        }
        fn = section_map.get(args.section)
        if fn:
            sections.append(fn())
        else:
            print(f"Unknown section: {args.section}", file=sys.stderr)
            print(f"Available: {', '.join(section_map.keys())}", file=sys.stderr)
            sys.exit(1)
    elif args.files_only:
        sections.append(file_contents_section(since))
    else:
        # Full pack
        sections.append(git_log_section(since))
        sections.append(git_diff_stat_section(since))
        sections.append(changed_files_section(since))
        sections.append(strict_mode_config_section())
        sections.append(reason_code_section())
        sections.append(test_results_section())
        # Diff content last (largest)
        sections.append(git_diff_content_section(since))

    pack = "\n".join(sections)

    # Add sentinel-readable header
    header = textwrap.dedent(f"""\
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  UNWIND EVIDENCE PACK — for SENTINEL code-level verification          ║
    ║  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'):54s} ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """)

    return header + pack


def main():
    parser = argparse.ArgumentParser(
        description="Generate evidence pack for SENTINEL verification",
    )
    parser.add_argument(
        "--since",
        help="Git reference point (default: HEAD~5)",
        default=None,
    )
    parser.add_argument(
        "--files-only",
        action="store_true",
        help="Only output file contents section",
    )
    parser.add_argument(
        "--section",
        choices=["log", "stat", "files", "contents", "diff", "tests", "config", "reasons"],
        help="Output only a specific section",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write to file instead of stdout",
    )

    args = parser.parse_args()
    pack = build_pack(args)

    if args.output:
        Path(args.output).write_text(pack, encoding="utf-8")
        print(f"Evidence pack written to {args.output}", file=sys.stderr)
        print(f"Size: {len(pack):,} chars", file=sys.stderr)
    else:
        print(pack)


if __name__ == "__main__":
    main()
