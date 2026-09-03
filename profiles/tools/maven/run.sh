#!/bin/bash
# Profile: Apache Maven (system mvn and maven wrapper).
[ "$1" = "--check" ] && { command -v mvn >/dev/null; exit; }
mvn compile -q -B
./mvnw compile -q -B
