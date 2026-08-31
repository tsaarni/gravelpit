#!/bin/bash
# Profile: GitHub CLI.
[ "$1" = "--check" ] && { command -v gh >/dev/null; exit; }
gh --version
gh auth status || true
