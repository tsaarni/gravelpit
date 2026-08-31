#!/bin/bash
# Profile: Node.js, npm, and pnpm.
[ "$1" = "--check" ] && { command -v node >/dev/null && command -v npm >/dev/null && command -v pnpm >/dev/null; exit; }
node hello.js

npm install --no-audit --no-fund
npm run hello

rm -rf node_modules package-lock.json

pnpm install
pnpm run hello
