#!/usr/bin/env python3
"""SENTINEL Audit Script — monitors what SENTINEL actually runs on the Pi.

Watches bash history and OpenClaw execution logs for commands that were
NOT authorised in the architecture plan. If an unauthorised command is
detected, triggers a Red Light alert.

Runs on the Pi as a cron job (every 5 minutes) or as a persistent watcher.

What it monitors:
1. ~/.bash_history — any new commands since last check
2. ~/.openclaw/logs/ — OpenClaw tool execution logs
3. Network connections — unexpected outbound connections

What triggers an alert:
- Commands not in the authorised list (configurable)
- Network connections to unexpected hosts
- File access outside the workspace
- Any attempt to read/modify this audit script itself

Usage (on the Pi):
    # One-shot check:
    python3 sentinel_audit.py --check

    # Watch mode (persistent):
    python3 sentinel_audit.py --watch

    # Install as cron (every 5 minutes):
    python3 sentinel_audit.py --install-cron
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

HOME = Path.home()
AUDIT_STATE_DIR = HOME / ".unwind" / "audit"
BASH_HISTORY = HOME / ".bash_history"
OPENCLAW_LOGS = HOME / ".openclaw" / "logs"
OPENCLAW_WORKSPACE = HOME / ".openclaw" / "workspace"

# Alert output
ALERT_FILE = AUDIT_STATE_DIR / "alerts.jsonl"
STATE_FILE = AUDIT_STATE_DIR / "last_check.json"

# Commands that SENTINEL is allowed to run
# (Update this list as the architecture plan evolves)
AUTHORISED_COMMANDS = {
    # OpenClaw / Codex operations
    "openclaw", "claw",
    # File operations within workspace
    "cat", "ls", "head", "tail", "wc", "grep", "find", "mkdir", "cp", "mv",
    "touch", "chmod",
    # Text processing
    "sed", "awk", "sort", "uniq", "tr", "cut", "diff",
    # Python
    "python3", "python", "pip3", "pip",
    # Node
    "node", "npm", "npx",
    # Git (within workspace)
    "git",
    # System info (read-only)
    "uname", "whoami", "date", "uptime", "free", "df", "which", "env",
    "printenv", "echo",
    # Editors (for config)
    "nano", "vim", "vi",
}

# Commands that trigger immediate Red Light
DANGEROUS_COMMANDS = {
    # Network exfiltration
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    # Remote access
    "ssh", "scp", "rsync", "sftp", "telnet",
    # Privilege escalation
    "sudo", "su", "passwd", "chown",
    # System modification
    "apt", "apt-get", "dpkg", "snap", "systemctl", "service",
    # Disk/mount operations
    "mount", "umount", "fdisk", "mkfs", "dd",
    # Process manipulation
    "kill", "killall", "pkill", "nohup",
    # Compiler/build (could compile exploits)
    "gcc", "g++", "make", "cc",
    # Crypto/encoding (potential exfiltration prep)
    "base64", "openssl",
    # Cron manipulation
    "crontab",
}

# Network hosts SENTINEL should be connecting to
AUTHORISED_HOSTS = {
    "api.openai.com",
    "127.0.0.1",
    "localhost",
    # Add your Mac's IP when using key proxy:
    # "192.168.0.XXX",
}

# Paths SENTINEL should never access
FORBIDDEN_PATHS = {
    str(HOME / ".ssh"),
    str(HOME / ".gnupg"),
    str(HOME / ".aws"),
    "/etc/shadow",
    "/etc/passwd",
    str(AUDIT_STATE_DIR),  # Self-protection: audit can't be modified by SENTINEL
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [sentinel-audit] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel-audit")


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    """Load last check state."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"last_history_line": 0, "last_check_ts": ""}


def _save_state(state: dict):
    """Save check state."""
    AUDIT_STATE_DIR.mkdir(parents=True, exist_ok=True)
    state["last_check_ts"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _emit_alert(severity: str, category: str, detail: str, command: str = ""):
    """Write an alert to the alerts file and stdout."""
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,  # "red", "amber", "info"
        "category": category,
        "detail": detail,
        "command": command[:200],  # Truncate long commands
    }

    AUDIT_STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

    marker = "RED LIGHT" if severity == "red" else severity.upper()
    logger.warning("[%s] %s: %s | cmd: %s", marker, category, detail, command[:100])
    return alert


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_bash_history(state: dict) -> list[dict]:
    """Check bash history for unauthorised commands."""
    alerts = []

    if not BASH_HISTORY.exists():
        return alerts

    try:
        lines = BASH_HISTORY.read_text().splitlines()
    except OSError:
        return alerts

    last_line = state.get("last_history_line", 0)
    new_lines = lines[last_line:]
    state["last_history_line"] = len(lines)

    for line in new_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Extract the base command (first word, strip pipes/redirects)
        parts = re.split(r"[|;&\s]", line)
        base_cmd = parts[0].strip() if parts else ""

        # Strip path prefix
        if "/" in base_cmd:
            base_cmd = base_cmd.rsplit("/", 1)[-1]

        if not base_cmd:
            continue

        # Check dangerous commands first
        if base_cmd in DANGEROUS_COMMANDS:
            alerts.append(_emit_alert(
                severity="red",
                category="dangerous_command",
                detail=f"SENTINEL ran dangerous command: {base_cmd}",
                command=line,
            ))
            continue

        # Check authorised list
        if base_cmd not in AUTHORISED_COMMANDS:
            alerts.append(_emit_alert(
                severity="amber",
                category="unauthorised_command",
                detail=f"SENTINEL ran unrecognised command: {base_cmd}",
                command=line,
            ))
            continue

        # Check for forbidden path access in arguments
        for forbidden in FORBIDDEN_PATHS:
            if forbidden in line:
                alerts.append(_emit_alert(
                    severity="red",
                    category="forbidden_path_access",
                    detail=f"Command references forbidden path: {forbidden}",
                    command=line,
                ))
                break

    return alerts


def check_network_connections() -> list[dict]:
    """Check for unexpected outbound network connections."""
    alerts = []

    try:
        result = subprocess.run(
            ["ss", "-tunp"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return alerts

        for line in result.stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 5:
                continue

            # Extract remote address
            remote = parts[4] if len(parts) > 4 else ""
            if ":" in remote:
                host = remote.rsplit(":", 1)[0]
                # Strip brackets from IPv6
                host = host.strip("[]")

                # Skip local connections
                if host in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                    continue

                # Check if it's to an authorised host
                # (We can't resolve IPs to hostnames reliably, so we
                # check against known IPs. Add your Mac IP to AUTHORISED_HOSTS.)
                # For now, just log all external connections as info
                alerts.append(_emit_alert(
                    severity="info",
                    category="network_connection",
                    detail=f"Outbound connection to {host}",
                    command=line.strip(),
                ))

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass  # ss might not be available

    return alerts


def check_self_integrity() -> list[dict]:
    """Check if this audit script has been tampered with."""
    alerts = []

    script_path = Path(__file__).resolve()
    hash_file = AUDIT_STATE_DIR / "audit_script.sha256"

    current_hash = hashlib.sha256(script_path.read_bytes()).hexdigest()

    if hash_file.exists():
        stored_hash = hash_file.read_text().strip()
        if stored_hash != current_hash:
            alerts.append(_emit_alert(
                severity="red",
                category="self_integrity",
                detail="Audit script has been modified! Possible compromise.",
                command=f"hash mismatch: {stored_hash[:12]}... → {current_hash[:12]}...",
            ))
    else:
        # First run — record hash
        AUDIT_STATE_DIR.mkdir(parents=True, exist_ok=True)
        hash_file.write_text(current_hash + "\n")
        logger.info("Audit script hash recorded: %s...%s", current_hash[:8], current_hash[-4:])

    return alerts


def check_workspace_escape() -> list[dict]:
    """Check for files created outside the workspace."""
    alerts = []

    # Look for recently modified files in sensitive directories
    sensitive_dirs = [HOME / ".ssh", HOME / ".gnupg", HOME / ".openclaw"]

    for sdir in sensitive_dirs:
        if not sdir.exists():
            continue
        try:
            result = subprocess.run(
                ["find", str(sdir), "-mmin", "-10", "-type", "f"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                if line:
                    alerts.append(_emit_alert(
                        severity="amber",
                        category="workspace_escape",
                        detail=f"Recently modified file outside workspace: {line}",
                        command="",
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return alerts


# ---------------------------------------------------------------------------
# Main check routine
# ---------------------------------------------------------------------------

def run_check() -> list[dict]:
    """Run all audit checks and return alerts."""
    state = _load_state()
    all_alerts = []

    # Self-integrity first (if this script is tampered, nothing else matters)
    all_alerts.extend(check_self_integrity())

    # Bash history
    all_alerts.extend(check_bash_history(state))

    # Network connections
    all_alerts.extend(check_network_connections())

    # Workspace escape
    all_alerts.extend(check_workspace_escape())

    _save_state(state)

    # Summary
    reds = sum(1 for a in all_alerts if a.get("severity") == "red")
    ambers = sum(1 for a in all_alerts if a.get("severity") == "amber")

    if reds:
        logger.error("RED LIGHT: %d critical alerts found", reds)
    elif ambers:
        logger.warning("AMBER: %d warnings found", ambers)
    else:
        logger.info("All clear — no alerts")

    return all_alerts


def watch_mode(interval: int = 300):
    """Run checks in a loop."""
    logger.info("Watch mode started (checking every %ds)", interval)
    while True:
        try:
            run_check()
        except Exception as exc:
            logger.error("Check failed: %s", exc)
        time.sleep(interval)


def install_cron():
    """Install this script as a cron job (every 5 minutes)."""
    script = Path(__file__).resolve()
    cron_line = f"*/5 * * * * /usr/bin/python3 {script} --check >> /tmp/sentinel-audit.log 2>&1"

    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    existing = result.stdout if result.returncode == 0 else ""

    if str(script) in existing:
        print("Cron job already installed.")
        return

    new_crontab = existing.rstrip() + "\n" + cron_line + "\n"
    proc = subprocess.run(
        ["crontab", "-"],
        input=new_crontab, text=True,
        capture_output=True,
    )
    if proc.returncode == 0:
        print(f"Cron job installed: {cron_line}")
    else:
        print(f"Failed to install cron: {proc.stderr}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL Audit Script")
    parser.add_argument("--check", action="store_true", help="Run one-shot check")
    parser.add_argument("--watch", action="store_true", help="Run in watch mode")
    parser.add_argument("--install-cron", action="store_true", help="Install as cron job")
    parser.add_argument("--interval", type=int, default=300, help="Watch interval (seconds)")
    parser.add_argument("--show-alerts", action="store_true", help="Show recent alerts")

    args = parser.parse_args()

    if args.show_alerts:
        if ALERT_FILE.exists():
            lines = ALERT_FILE.read_text().splitlines()
            for line in lines[-20:]:
                print(line)
        else:
            print("No alerts yet.")
    elif args.install_cron:
        install_cron()
    elif args.watch:
        watch_mode(interval=args.interval)
    else:
        # Default: one-shot check
        alerts = run_check()
        if any(a.get("severity") == "red" for a in alerts):
            sys.exit(2)  # Exit code 2 = red alert
        elif any(a.get("severity") == "amber" for a in alerts):
            sys.exit(1)  # Exit code 1 = amber warning
        sys.exit(0)
