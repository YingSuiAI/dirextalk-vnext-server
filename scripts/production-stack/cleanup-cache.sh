#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: cleanup-cache.sh' >&2
    exit 2
fi
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
# This is intentionally the complete cleanup allowlist: no volumes, logs,
# active images, containers, or secret/config paths are ever removed.
docker image prune --force --filter dangling=true >/dev/null
docker builder prune --force >/dev/null
