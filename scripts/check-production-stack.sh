#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compose="$root/docker/production/docker-compose.yml"
example="$root/docker/production/examples/production.env.example"
[[ -f "$compose" && -f "$example" ]] || { echo 'production compose/example missing' >&2; exit 1; }

grep -q 'dirextalk/vnet-server@sha256:<64 lowercase hex>' "$root/docker/production/README.md"
grep -q 'condition: service_completed_successfully' "$compose"
grep -q 'postgres-data:/var/lib/postgresql$' "$compose"
! grep -q 'postgres-data:/var/lib/postgresql/data$' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-agent-control"\]' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-realtime-sync-gateway"\]' "$compose"
! grep -q '^  opaque-push:' "$compose"
grep -q 'command: \["verify-roles"\]' "$compose"
grep -q 'dtx_agent_control' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'dtx_agent_peer_admin' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'register_mcp_credential_digest' "$root/docker/production/postgres/agent-control-grants.sql"
grep -q 'agent.connector_bootstrap_issuances' "$root/docker/production/postgres/agent-control-grants.sql"
grep -q 'agent.connector_bootstrap_issuances' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'directory.index_registrations.*UPDATE' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'directory.index_cache_generations' "$root/docker/local/postgres/20-local-runtime-grants.sql"
grep -q "directory.index_cache_generations', 'UPDATE'" "$root/docker/production/postgres/verify-roles.sql"
grep -q 'DTX_.*DATABASE_URL_FILE' "$compose"
grep -q 'DTX_AGENT_CONTROL_BIND.*:9443:9443' "$compose"
grep -q 'network_mode: service:agent-control' "$compose"
grep -q 'https://.*:8443/local/ready' "$compose"
grep -q 'https://.*:9444/local/ready' "$compose"
grep -q 'reverse_proxy @realtime https://realtime-gateway:9444' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @node https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q '@node path_regexp versioned_api \^/v\[1-9\]\[0-9\]\*/\.\*\$' "$root/docker/production/Caddyfile"
grep -qF '@public_feed path_regexp public_feed ^/\.well-known/dirextalk/public/v1/[^/]+(/.*)?$' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @public_feed https://dtx-node:8443' "$root/docker/production/Caddyfile"
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
grep -q 'opaque push is fail-closed disabled\|Opaque push is fail-closed disabled' "$root/docker/production/README.md"
# Agent Control remains opt-in: default config excludes it, while the profile
# includes both service and readiness checks. Its shared database grants stay
# covered by the assertions above.
fixture=$(mktemp -d)
trap 'find "$fixture" -xdev -type f -delete; find "$fixture" -xdev -type l -delete; find "$fixture" -xdev -depth -type d -empty -delete' EXIT
docker compose --env-file "$example" -f "$compose" config --services >"$fixture/default-services"
! grep -qx 'agent-control' "$fixture/default-services"
! grep -qx 'agent-control-ready' "$fixture/default-services"
for service in postgres bootstrap-roles migrate grant-roles verify-roles dtx-node node-ready realtime-gateway realtime-ready caddy; do
    grep -qx "$service" "$fixture/default-services"
done
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
for helper in "$root"/scripts/production-stack/host/{client-binding-issue,client-binding-expire,client-binding-revoke,client-binding-export-cleanup}; do
    test -x "$helper" || { echo "not executable: $helper" >&2; exit 1; }
done
python3 "$root/tools/test-client-binding-release-artifacts.py"
bash "$root/scripts/check-release-image.sh"
echo 'Product Core production stack gates passed'
