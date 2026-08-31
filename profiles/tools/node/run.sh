#!/bin/bash
# Profile: Node.js.
[ "$1" = "--check" ] && { command -v node >/dev/null; exit; }
node hello.js
