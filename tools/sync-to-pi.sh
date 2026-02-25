#!/usr/bin/env bash
# Sync UNWIND from Mac → Pi (Raspberry Pi 5 / SENTINEL)
#
# Usage:  ./tools/sync-to-pi.sh
#
# Run from Mac terminal. Pushes ~/Downloads/UNWIND/ to the Pi's
# OpenClaw workspace. You'll be prompted for dandare's password.

PI_IP="192.168.0.171"
PI_USER="dandare"
PI_PATH="/home/dandare/.openclaw/workspace/UNWIND/"
MAC_PATH="$HOME/Downloads/UNWIND/"

echo "Syncing UNWIND: Mac → Pi ($PI_IP)"
echo "  From: $MAC_PATH"
echo "  To:   $PI_USER@$PI_IP:$PI_PATH"
echo ""

rsync -avz --delete "$MAC_PATH" "$PI_USER@$PI_IP:$PI_PATH"

echo ""
echo "Done. Run tests on Pi:  ssh $PI_USER@$PI_IP 'cd $PI_PATH && python -m pytest -q'"
