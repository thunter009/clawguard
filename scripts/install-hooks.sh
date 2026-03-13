#!/usr/bin/env bash
# Install git hooks by symlinking from scripts/ into .git/hooks/
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

ln -sf "$REPO_ROOT/scripts/commit-msg" "$HOOKS_DIR/commit-msg"
echo "Installed commit-msg hook"
