#!/usr/bin/env bash
set -euo pipefail

# Conventional commit message validator
commit_msg_file="$1"
commit_msg=$(head -n 1 "$commit_msg_file")

# Allow merge commits and initial commits without conventional syntax
if [[ "$commit_msg" =~ ^Merge.* ]] || [[ "$commit_msg" =~ ^Revert.* ]]; then
    exit 0
fi

# Regex for Conventional Commits
# type(scope?): description
pattern="^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-zA-Z0-9_\.\-]+\))?!?: .+$"

if [[ ! "$commit_msg" =~ $pattern ]]; then
    echo "ERROR: Invalid commit message format." >&2
    echo "Message was: '$commit_msg'" >&2
    echo "Format must follow Conventional Commits: <type>(<scope>): <subject>" >&2
    echo "Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert" >&2
    echo "Example: chore(workspace): scaffold 13-crate workspace" >&2
    exit 1
fi
