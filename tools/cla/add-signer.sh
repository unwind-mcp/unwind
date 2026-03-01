#!/usr/bin/env bash
set -euo pipefail

# Add a GitHub username to .github/cla-signers.txt if not present.
# Usage:
#   tools/cla/add-signer.sh <github-username>

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <github-username>" >&2
  exit 1
fi

USERNAME="$1"
FILE=".github/cla-signers.txt"

if [[ ! -f "$FILE" ]]; then
  echo "Missing $FILE (run from repo root)." >&2
  exit 1
fi

if [[ ! "$USERNAME" =~ ^[A-Za-z0-9-]+$ ]]; then
  echo "Invalid GitHub username: $USERNAME" >&2
  exit 1
fi

if grep -Eiq "^${USERNAME}$" "$FILE"; then
  echo "Already present: $USERNAME"
  exit 0
fi

echo "$USERNAME" >> "$FILE"

echo "Added signer: $USERNAME"
echo
echo "Next steps:"
echo "  git add $FILE"
echo "  git commit -m \"cla: add signer ${USERNAME}\""
