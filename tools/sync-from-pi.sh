#!/usr/bin/env bash
# Sync UNWIND from Pi → Mac (pull SENTINEL's changes)
#
# Usage:  ./tools/sync-from-pi.sh
#
# Run from Mac terminal. Pulls the Pi's OpenClaw workspace to ~/Downloads/UNWIND/.
# You'll be prompted for the Pi user's password.
#
# IMPORTANT: This uses --delete which will overwrite local Mac changes.
# Always commit/push to GitHub before running if you have local work.

PI_IP="${UNWIND_PI_HOST:?Set UNWIND_PI_HOST}"
PI_USER="${UNWIND_PI_USER:-pi}"
PI_PATH="${UNWIND_PI_PATH:-/home/${PI_USER}/.openclaw/workspace/UNWIND/}"
MAC_PATH="$HOME/Downloads/UNWIND/"

echo "Syncing UNWIND: Pi ($PI_IP) → Mac"
echo "  From: $PI_USER@$PI_IP:$PI_PATH"
echo "  To:   $MAC_PATH"
echo ""

rsync -avz --delete --exclude='.git' "$PI_USER@$PI_IP:$PI_PATH" "$MAC_PATH"

echo ""
echo "Done. Review changes:  cd $MAC_PATH && git diff"
