#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: bootstrap.sh' >&2
    exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo 'bootstrap requires root' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
env_file=/etc/dirextalk/vnext/config/production.env
compose_file=/etc/dirextalk/vnext/config/production-compose.yml
[[ -f "$env_file" && ! -L "$env_file" && $(stat -c '%a' "$env_file") == 644 ]] || { echo 'invalid production env file' >&2; exit 1; }
[[ -f "$compose_file" && ! -L "$compose_file" ]] || { echo 'missing installed compose file' >&2; exit 1; }
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" config >/dev/null
scripts/production-stack/validate-files.sh
scripts/production-stack/validate-images.sh
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" up -d
scripts/production-stack/verify.sh
