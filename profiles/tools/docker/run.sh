#!/bin/bash
# Profile: Docker build and compose.
[ "$1" = "--check" ] && { docker info >/dev/null 2>&1; exit; }
docker build -t gravelpit-test:latest .
docker compose config
docker rmi gravelpit-test:latest 2>/dev/null || true
