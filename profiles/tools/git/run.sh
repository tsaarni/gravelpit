#!/bin/bash
# Profile: Git version control.
[ "$1" = "--check" ] && { command -v git >/dev/null; exit; }
export GIT_AUTHOR_NAME="Test"
export GIT_AUTHOR_EMAIL="test@example.com"
export GIT_COMMITTER_NAME="Test"
export GIT_COMMITTER_EMAIL="test@example.com"
git init
git add .
git commit -m "initial"
git log --oneline
