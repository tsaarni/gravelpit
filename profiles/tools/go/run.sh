#!/bin/bash
# Profile: Go toolchain.
[ "$1" = "--check" ] && { command -v go >/dev/null; exit; }
go build -o output .
go vet ./...
