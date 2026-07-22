#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: cleanup-cache.sh' >&2
    exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo 'cleanup requires root' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
evidence=/var/lib/dirextalk/vnext/last-successful-operation
[[ -f "$evidence" && ! -L "$evidence" && $(stat -c '%a:%u:%g' "$evidence") == 600:0:0 ]] || { echo 'retained success evidence is required before cleanup' >&2; exit 1; }
grep -qx 'status=ready' "$evidence" || { echo 'success evidence is incomplete' >&2; exit 1; }
# This is intentionally the complete cleanup allowlist: no volumes, logs,
# active images, containers, or secret/config paths are ever removed.
docker image prune --force --filter dangling=true >/dev/null
docker builder prune --force >/dev/null
