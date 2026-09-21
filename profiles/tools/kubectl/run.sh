#!/bin/bash
# Profile: Kubernetes kubectl.
[ "$1" = "--check" ] && { command -v kubectl >/dev/null; exit; }
kubectl version --client
# Without --cached kubectl tries to reach the server, caches the response (or
# error), and exercises write and delete paths in .kube/cache that --cached
# would skip.
kubectl api-resources 2>/dev/null || true
