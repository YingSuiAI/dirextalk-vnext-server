#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: down.sh' >&2
    exit 2
fi
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
docker compose --project-name dirextalk-vnext-production \
    --env-file /etc/dirextalk/vnext/config/production.env \
    -f /etc/dirextalk/vnext/config/production-compose.yml down --remove-orphans
