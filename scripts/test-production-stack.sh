#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compose="$root/docker/production/docker-compose.yml"
[[ -f "$compose" ]] || { echo 'production compose missing' >&2; exit 1; }
grep -q 'dirextalk/vnet-server@sha256:<64 lowercase hex>' "$root/docker/production/README.md"
grep -q 'condition: service_completed_successfully' "$compose"
grep -q 'postgres-data:' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-agent-control"\]' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-realtime-sync-gateway"\]' "$compose"
grep -q 'profiles: \["opaque-push"\]' "$compose"
grep -q 'DTX_.*DATABASE_URL_FILE' "$compose"
grep -q 'reverse_proxy @realtime https://realtime-gateway:9444' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @node https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q 'tls_trust_pool file /data/caddy/private-ca.pem' "$root/docker/production/Caddyfile"
! grep -q 'agent-control:944' "$root/docker/production/Caddyfile"
! grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)=' "$compose"
! grep -Eq 'image:[[:space:]]+[^$[:space:]]+:(latest|dev)(@|[[:space:]]|$)' "$compose"
! grep -Eq 'docker compose.*(exec|run)[[:space:]]' "$root/scripts/production-stack"/*.sh
for script in "$root"/scripts/production-stack/{install,bootstrap,update,verify,down,cleanup-cache}.sh; do
    test -x "$script" || { echo "not executable: $script" >&2; exit 1; }
done
echo 'production stack structural/negative checks passed'
