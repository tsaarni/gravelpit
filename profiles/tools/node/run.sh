#!/bin/bash
# Profile: Node.js, npm, and pnpm.
[ "$1" = "--check" ] && { command -v node >/dev/null && command -v npm >/dev/null && command -v pnpm >/dev/null; exit; }
node hello.js

npm install --no-audit --no-fund
npm run hello

rm -rf node_modules package-lock.json

# Clear pnpm metadata cache so pnpm exercises write and delete paths that a
# warm cache would skip. pnpm only refreshes metadata when cached versions
# are stale enough, making recordings non-deterministic without this.
pnpm cache delete is-odd is-number 2>/dev/null || true

pnpm install
pnpm run hello
