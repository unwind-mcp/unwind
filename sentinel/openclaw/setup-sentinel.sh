#!/bin/bash
# SENTINEL OpenClaw Setup Script
# Run this on the Pi to deploy SENTINEL as an OpenClaw agent personality

set -e

WORKSPACE="$HOME/.openclaw/workspace"
REPORTS="$HOME/sentinel-reports"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== SENTINEL OpenClaw Setup ==="
echo ""

# Create reports directory
echo "[1/4] Creating reports directory..."
mkdir -p "$REPORTS"
echo "  Created: $REPORTS"

# Copy personality files to OpenClaw workspace
echo "[2/4] Deploying personality files..."
cp "$SCRIPT_DIR/SOUL.md" "$WORKSPACE/SOUL.md"
cp "$SCRIPT_DIR/AGENTS.md" "$WORKSPACE/AGENTS.md"
cp "$SCRIPT_DIR/IDENTITY.md" "$WORKSPACE/IDENTITY.md"
cp "$SCRIPT_DIR/USER.md" "$WORKSPACE/USER.md"
echo "  Deployed: SOUL.md, AGENTS.md, IDENTITY.md, USER.md"

# Set up cron jobs
echo "[3/4] Setting up scheduled tasks..."
echo "  The following cron jobs will be created via OpenClaw CLI:"
echo ""
echo "  1. CVE Watch        — every 6 hours"
echo "  2. MCP Spec Tracker — daily at 08:00 UTC"
echo "  3. AI Safety News   — daily at 09:00 UTC"
echo "  4. Arcanum Feed     — daily at 10:00 UTC"
echo "  5. UNWIND Self-Test — daily at 06:00 UTC"
echo ""
echo "  Run these commands to activate:"
echo ""

cat << 'CRON_COMMANDS'
# CVE Watch — every 6 hours
openclaw cron add \
  --name "sentinel-cve-watch" \
  --every "6h" \
  --session isolated \
  --message "Run CVE Watch task. Search NVD and GitHub Security Advisories for new CVEs matching UNWIND's threat surface keywords. Save structured report to ~/sentinel-reports/cve-watch-$(date +%Y-%m-%d).md"

# MCP Spec Tracker — daily at 08:00 UTC
openclaw cron add \
  --name "sentinel-mcp-spec" \
  --cron "0 8 * * *" \
  --tz "UTC" \
  --session isolated \
  --message "Run MCP Spec Tracker task. Check modelcontextprotocol/specification and SDK repos for new commits, version bumps, and security-relevant changes since last check. Save structured report to ~/sentinel-reports/mcp-spec-$(date +%Y-%m-%d).md"

# AI Safety News — daily at 09:00 UTC
openclaw cron add \
  --name "sentinel-safety-news" \
  --cron "0 9 * * *" \
  --tz "UTC" \
  --session isolated \
  --message "Run AI Safety News Digest task. Monitor GitHub repos (Invariant, PurpleLlama, Garak, NeMo Guardrails, Rebuff), arXiv papers, and Hacker News for AI agent security developments. Save structured report to ~/sentinel-reports/safety-news-$(date +%Y-%m-%d).md"

# Arcanum Feed — daily at 10:00 UTC
openclaw cron add \
  --name "sentinel-arcanum" \
  --cron "0 10 * * *" \
  --tz "UTC" \
  --session isolated \
  --message "Run Arcanum Feed task. Check Arcanum-Sec GitHub org for updates to Prompt Injection Taxonomy, sec-context anti-patterns, and Agent Breaker lab. Cross-reference new attack patterns against UNWIND's enforcement stages. Save structured report to ~/sentinel-reports/arcanum-$(date +%Y-%m-%d).md"

# UNWIND Self-Test — daily at 06:00 UTC
openclaw cron add \
  --name "sentinel-self-test" \
  --cron "0 6 * * *" \
  --tz "UTC" \
  --session isolated \
  --message "Run UNWIND Self-Test task. Execute the full UNWIND test suite with pytest. Report total tests, pass/fail count, any new failures compared to previous run, and test count trend. Save structured report to ~/sentinel-reports/self-test-$(date +%Y-%m-%d).md"
CRON_COMMANDS

echo ""
echo "[4/4] Setup complete!"
echo ""
echo "  SOUL.md and personality files are live in: $WORKSPACE"
echo "  Reports will be saved to: $REPORTS"
echo "  Copy and run the cron commands above to activate scheduled monitoring."
echo ""
echo "  To test SENTINEL now, open the TUI and ask it a question:"
echo "    openclaw tui"
echo ""
echo "  === SENTINEL is ready. ==="
