#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: verify.sh' >&2
    exit 2
fi
env_file=/etc/dirextalk/vnext/config/production.env
compose_file=/etc/dirextalk/vnext/config/production-compose.yml
[[ -f "$env_file" && ! -L "$env_file" ]] || { echo 'missing production env file' >&2; exit 1; }
[[ -f "$compose_file" && ! -L "$compose_file" ]] || { echo 'missing installed compose file' >&2; exit 1; }
grep -Eq '^DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:[0-9a-f]{64}$' "$env_file" || { echo 'server image is not an immutable vnet-server digest' >&2; exit 1; }
grep -Eq '^DTX_(POSTGRES|CADDY|MIGRATOR)_IMAGE=[^@[:space:]]+@sha256:[0-9a-f]{64}$' "$env_file" || { echo 'dependency image is not an immutable digest' >&2; exit 1; }
grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)_FILE' "$compose_file" || { echo 'URL file contract missing' >&2; exit 1; }
! grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)=' "$compose_file" || { echo 'raw database URL env is forbidden' >&2; exit 1; }
check_secret() {
    local path=$1 mode
    [[ -f "$path" && ! -L "$path" ]] || { echo "missing secret: $path" >&2; exit 1; }
    mode=$(stat -c '%a' "$path")
    [[ "$mode" == 400 && $(stat -c '%u:%g' "$path") == 0:0 ]] || { echo "secret ownership/mode invalid: $path" >&2; exit 1; }
}
check_config() {
    local path=$1
    [[ -f "$path" && ! -L "$path" && $(stat -c '%a' "$path") == 644 && $(stat -c '%u:%g' "$path") == 0:0 ]] || { echo "config ownership/mode invalid: $path" >&2; exit 1; }
}
check_config /etc/dirextalk/vnext/config/Caddyfile
check_config /etc/dirextalk/vnext/config/agent-control.json
for name in postgres-admin-password admin-database-url identity-database-url group-database-url mailbox-database-url public-feed-database-url indexer-database-url realtime-database-url; do
    check_secret "/etc/dirextalk/vnext/secrets/$name"
done
for name in dtx_identity_node dtx_group_node dtx_mailbox_node dtx_push_registration dtx_push_identity_auth dtx_realtime_sync_gateway dtx_push_broker dtx_public_feed_node dtx_indexer_node; do
    check_secret "/etc/dirextalk/vnext/secrets/role-passwords/$name"
done
for name in database-url enrollment-key.pem control-key.pem legacy-gateway-server-key.pem connector-issuer-key.pem; do
    check_secret "/etc/dirextalk/vnext/secrets/agent-control/$name"
done
for name in node-cert.pem node-key.pem gateway-cert.pem gateway-key.pem private-ca.pem mls-sequencer-key.pem server-cert.pem server-key.pem; do
    check_secret "/etc/dirextalk/vnext/tls/$name"
done
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" config >/dev/null
