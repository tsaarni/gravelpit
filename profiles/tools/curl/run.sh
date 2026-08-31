#!/bin/bash
# Profile: curl HTTP client.
[ "$1" = "--check" ] && { command -v curl >/dev/null; exit; }
curl -s -o output.txt https://example.com
