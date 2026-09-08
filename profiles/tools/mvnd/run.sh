#!/bin/bash
# Profile: Maven Daemon (mvnd).
[ "$1" = "--check" ] && { command -v mvnd >/dev/null; exit; }
mvnd compile -q -B
