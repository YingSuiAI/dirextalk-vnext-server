#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: validate-files.sh' >&2
    exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo 'file validation requires root' >&2; exit 1; }
check_material() {
    local path=$1 expected=$2
    [[ -f "$path" && ! -L "$path" ]] || { echo "missing material: $path" >&2; exit 1; }
    [[ $(stat -c '%a:%u:%g' "$path") == "$expected" ]] || { echo "material ownership/mode invalid: $path" >&2; exit 1; }
}
for name in Caddyfile agent-control.json production.env production-compose.yml; do
    check_material "/etc/dirextalk/vnext/config/$name" 644:0:0
done
for name in postgres-admin-password admin-database-url; do
    check_material "/etc/dirextalk/vnext/secrets/$name" 400:0:0
done
for name in identity-database-url group-database-url mailbox-database-url public-feed-database-url indexer-database-url realtime-database-url; do
    check_material "/etc/dirextalk/vnext/secrets/$name" 440:0:10001
done
for name in dtx_identity_node dtx_group_node dtx_mailbox_node dtx_push_registration dtx_push_identity_auth dtx_realtime_sync_gateway dtx_push_broker dtx_public_feed_node dtx_indexer_node dtx_agent_control; do
    check_material "/etc/dirextalk/vnext/secrets/role-passwords/$name" 400:0:0
done
for name in database-url enrollment-key.pem control-key.pem legacy-gateway-server-key.pem connector-issuer-key.pem; do
    check_material "/etc/dirextalk/vnext/secrets/agent-control/$name" 440:0:10001
done
for name in node-key.pem gateway-key.pem server-key.pem; do
    check_material "/etc/dirextalk/vnext/tls/$name" 440:0:10001
done
check_material /etc/dirextalk/vnext/tls/mls-sequencer-key.pem 400:10001:10001
for name in node-cert.pem gateway-cert.pem private-ca.pem server-cert.pem enrollment-chain.pem control-chain.pem connector-client-roots.pem legacy-gateway-server-chain.pem internal-service-client-roots.pem connector-issuer.pem connector-response-intermediates.pem; do
    check_material "/etc/dirextalk/vnext/tls/$name" 444:0:0
done
