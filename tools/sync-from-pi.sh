#!/usr/bin/env bash
# Sync UNWIND from Pi → Mac (pull SENTINEL's changes)
#
# Usage:  ./tools/sync-from-pi.sh
#
# Run from Mac terminal. Pulls the Pi's OpenClaw workspace to ~/Downloads/UNWIND/.
# You'll be prompted for dandare's password.
#
# IMPORTANT: This uses --delete which will overwrite local Mac changes.
# Always commit/push to GitHub before running if you have local work.

PI_IP="192.168.0.171"
PI_USER="dandare"
PI_PATH="/home/dandare/.openclaw/workspace/UNWIND/"
MAC_PATH="$HOME/Downloads/UNWIND/"

echo "Syncing UNWIND: Pi ($PI_IP) → Mac"
echo "  From: $PI_USER@$PI_IP:$PI_PATH"
echo "  To:   $MAC_PATH"
echo ""

rsync -avz --delete --exclude='.git' "$PI_USER@$PI_IP:$PI_PATH" "$MAC_PATH"

echo ""
echo "Done. Review changes:  cd $MAC_PATH && git diff"
