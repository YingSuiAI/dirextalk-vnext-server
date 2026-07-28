#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compose="$root/docker/production/docker-compose.yml"
example="$root/docker/production/examples/production.env.example"
[[ -f "$compose" && -f "$example" ]] || { echo 'production compose/example missing' >&2; exit 1; }
grep -q '"docker/production/examples/production.env.example"' "$root/tools/production-stack-bundle.py"
grep -q "example='docker/production/examples/production.env.example'" "$root/scripts/production-stack/host/provision-vnext"
! grep -q 'examples/{v\\[\"target\"\\]}.env.example' "$root/scripts/production-stack/host/provision-vnext"

grep -q 'dirextalk/vnet-server@sha256:<64 lowercase hex>' "$root/docker/production/README.md"
grep -q 'condition: service_completed_successfully' "$compose"
grep -q 'postgres-data:/var/lib/postgresql$' "$compose"
! grep -q 'postgres-data:/var/lib/postgresql/data$' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-agent-control"\]' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-realtime-sync-gateway"\]' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-opaque-push-broker"\]' "$compose"
grep -q 'network_mode: service:opaque-push' "$compose"
grep -q 'command: \["verify-roles"\]' "$compose"
! grep -Eq 'dtx_(agent_control|agent_peer_admin|public_feed_node|indexer_node)' "$root/bins/dtx-production-migrate/src/main.rs"
! grep -Eq 'dtx_(agent_control|agent_peer_admin|public_feed_node|indexer_node)' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'dtx_push_registration_runtime' "$root/docker/production/postgres/product-core-grants.sql"
grep -q 'dtx_push_broker_runtime' "$root/docker/production/postgres/product-core-grants.sql"
grep -q 'DTX_.*DATABASE_URL_FILE' "$compose"
grep -q 'push-identity-database-url' "$compose"
grep -q 'push-registration-database-url' "$compose"
grep -q 'push-broker-database-url' "$compose"
grep -q 'push-root-key' "$compose"
grep -q 'push-fcm-service-account.json' "$compose"
grep -q 'push-certificate.pem' "$compose"
grep -q 'push-private-key.pem' "$compose"
grep -q 'DTX_AGENT_CONTROL_BIND.*:9443:9443' "$compose"
grep -q 'network_mode: service:agent-control' "$compose"
grep -q 'https://.*:8443/local/ready' "$compose"
grep -q 'https://.*:9444/local/ready' "$compose"
grep -q 'http://127.0.0.1:9488/local/ready' "$compose"
grep -qF '@opaque_push path /v1/devices/push-registrations/fcm' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @realtime https://realtime-gateway:9444' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @opaque_push https://opaque-push:9448' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @node https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q '@node path_regexp versioned_api \^/v\[1-9\]\[0-9\]\*/\.\*\$' "$root/docker/production/Caddyfile"
! grep -q 'public_feed\|indexer' "$root/docker/production/Caddyfile"
push_line=$(grep -n '^    @opaque_push ' "$root/docker/production/Caddyfile" | cut -d: -f1)
node_line=$(grep -n '^    @node ' "$root/docker/production/Caddyfile" | cut -d: -f1)
(( push_line < node_line ))
grep -q 'path_regexp mcp \^/mcp\$' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @mcp https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q 'tls_trust_pool file /data/caddy/private-ca.pem' "$root/docker/production/Caddyfile"
! grep -q 'agent-control:944' "$root/docker/production/Caddyfile"
! grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)=' "$compose"
! grep -Eq 'image:[[:space:]]+[^$[:space:]]+:(latest|dev)(@|[[:space:]]|$)' "$compose"
! grep -q 'kill -0 1' "$compose"
! grep -Eq 'docker compose.*(exec|run)[[:space:]]' "$root/scripts/production-stack"/*.sh
grep -q 'O_NOFOLLOW' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'validate_root_ancestor_chain' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'preload_role_passwords' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q '\.commit()' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'force-recreate --no-deps --abort-on-container-failure' "$root/scripts/production-stack/verify.sh"
grep -q 'Opaque push is a required Product Core service' "$root/docker/production/README.md"
# Agent Control remains opt-in: default config excludes it, while the profile
# includes both service and readiness checks. Its shared database grants stay
# covered by the assertions above.
fixture=$(mktemp -d)
trap 'find "$fixture" -xdev -type f -delete; find "$fixture" -xdev -type l -delete; find "$fixture" -xdev -depth -type d -empty -delete' EXIT
docker compose --env-file "$example" -f "$compose" config --services >"$fixture/default-services"
! grep -qx 'agent-control' "$fixture/default-services"
! grep -qx 'agent-control-ready' "$fixture/default-services"
for service in postgres bootstrap-roles migrate grant-roles verify-roles dtx-node node-ready realtime-gateway realtime-ready opaque-push opaque-push-ready caddy; do
    grep -qx "$service" "$fixture/default-services"
done
! grep -Eq '^(agent-control|agent-control-ready|public-feed|indexer)' "$fixture/default-services"
docker compose --profile agent-control --env-file "$example" -f "$compose" config --services >"$fixture/agent-control-services"
grep -qx 'agent-control' "$fixture/agent-control-services"
grep -qx 'agent-control-ready' "$fixture/agent-control-services"
! grep -q 'agent-control.json' "$root/scripts/production-stack/install.sh"
! grep -q 'secrets/agent-control' "$root/scripts/production-stack/install.sh"
! grep -q 'agent-control.json' "$root/scripts/production-stack/validate-files.sh"
! grep -q 'secrets/agent-control' "$root/scripts/production-stack/validate-files.sh"
! grep -q 'agent-control-ready' "$root/scripts/production-stack/verify.sh"

python3 "$root/tools/validate-production-images.py" --self-test
python3 "$root/tools/validate-production-images.py" "$example"
for script in "$root"/scripts/production-stack/{install,bootstrap,verify,down,validate-images,validate-files}.sh; do
    test -x "$script" || { echo "not executable: $script" >&2; exit 1; }
done
for helper in "$root"/scripts/production-stack/host/{install-vnext,provision-vnext,read-vnext-receipt,client-binding-issue,client-binding-expire,client-binding-revoke,client-binding-export-cleanup,deployment-binding-ticket-issue,deployment-binding-ticket-cleanup}; do
    test -x "$helper" || { echo "not executable: $helper" >&2; exit 1; }
done
python3 "$root/tools/test-client-binding-release-artifacts.py"
bash "$root/scripts/check-release-image.sh"
echo 'Product Core production stack gates passed'
