#!/bin/bash
# Profile: Apache Maven.
[ "$1" = "--check" ] && { command -v mvn >/dev/null; exit; }
mvn compile -q -B
