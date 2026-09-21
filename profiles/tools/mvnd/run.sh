#!/bin/bash
# Profile: Maven Daemon (mvnd).
[ "$1" = "--check" ] && { command -v mvnd >/dev/null; exit; }

# Stop any running daemon so mvnd starts fresh and exercises all startup paths
# including lock file creation in .m2/repository/.locks/.
mvnd --stop 2>/dev/null || true

mvnd compile -q -B
