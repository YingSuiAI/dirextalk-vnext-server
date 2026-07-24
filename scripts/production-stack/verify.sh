#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: verify.sh' >&2
    exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo 'verification requires root' >&2; exit 1; }
env_file=/etc/dirextalk/vnext/config/production.env
compose_file=/etc/dirextalk/vnext/config/production-compose.yml
[[ -f "$env_file" && ! -L "$env_file" ]] || { echo 'missing production env file' >&2; exit 1; }
[[ -f "$compose_file" && ! -L "$compose_file" ]] || { echo 'missing installed compose file' >&2; exit 1; }
grep -Eq '^DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:[0-9a-f]{64}$' "$env_file" || { echo 'server image is not an immutable vnet-server digest' >&2; exit 1; }
grep -Eq '^DTX_(POSTGRES|CADDY|MIGRATOR)_IMAGE=[^@[:space:]]+@sha256:[0-9a-f]{64}$' "$env_file" || { echo 'dependency image is not an immutable digest' >&2; exit 1; }
grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)_FILE' "$compose_file" || { echo 'URL file contract missing' >&2; exit 1; }
! grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)=' "$compose_file" || { echo 'raw database URL env is forbidden' >&2; exit 1; }
scripts/production-stack/validate-files.sh
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" config >/dev/null
scripts/production-stack/validate-images.sh
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" up --force-recreate --no-deps --abort-on-container-failure node-ready realtime-ready
