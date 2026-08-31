#!/bin/bash
# Profile: Kubernetes kubectl.
[ "$1" = "--check" ] && { command -v kubectl >/dev/null; exit; }
kubectl version --client
kubectl api-resources --cached 2>/dev/null || true
