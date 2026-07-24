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
for name in Caddyfile production.env production-compose.yml; do
    check_material "/etc/dirextalk/vnext/config/$name" 644:0:0
done
for name in postgres-admin-password admin-database-url; do
    check_material "/etc/dirextalk/vnext/secrets/$name" 400:0:0
done
for name in identity-database-url group-database-url mailbox-database-url realtime-database-url; do
    check_material "/etc/dirextalk/vnext/secrets/$name" 440:0:10001
done
for name in push-identity-database-url push-registration-database-url push-broker-database-url push-root-key push-fcm-service-account.json; do
    check_material "/etc/dirextalk/vnext/secrets/$name" 400:0:0
done
for name in dtx_identity_node dtx_group_node dtx_mailbox_node dtx_push_registration dtx_push_identity_auth dtx_realtime_sync_gateway dtx_push_broker; do
    check_material "/etc/dirextalk/vnext/secrets/role-passwords/$name" 400:0:0
done
for name in node-key.pem gateway-key.pem server-key.pem; do
    check_material "/etc/dirextalk/vnext/tls/$name" 440:0:10001
done
check_material /etc/dirextalk/vnext/tls/mls-sequencer-key.pem 400:10001:10001
for name in node-cert.pem gateway-cert.pem private-ca.pem server-cert.pem; do
    check_material "/etc/dirextalk/vnext/tls/$name" 444:0:0
done
for name in push-certificate.pem push-private-key.pem; do
    check_material "/etc/dirextalk/vnext/tls/$name" 400:0:0
done
