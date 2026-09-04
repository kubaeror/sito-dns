#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Configuring git hooks directory..."
git config core.hooksPath "$SCRIPT_DIR/git-hooks"
chmod +x "$SCRIPT_DIR/git-hooks/"*
echo "Git hooks configured successfully to use $SCRIPT_DIR/git-hooks"
