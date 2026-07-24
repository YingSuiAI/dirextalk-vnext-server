#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'Usage: bash scripts/test-production-postgres.sh' >&2
    exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
suffix=$$
network="dtx-production-role-test-$suffix"
database="dtx-production-role-db-$suffix"
secrets="dtx-production-role-secrets-$suffix"
runtime=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
postgres=postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
cleanup() {
    docker rm -f "$database" >/dev/null 2>&1 || true
    docker volume rm "$secrets" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cargo build -p dtx-production-migrate --locked >/dev/null
docker network create "$network" >/dev/null
docker volume create "$secrets" >/dev/null
docker run -d --name "$database" --network "$network" --network-alias postgres \
    -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=dtx_node "$postgres" >/dev/null
for attempt in $(seq 1 30); do
    docker exec "$database" pg_isready -U postgres -d dtx_node >/dev/null 2>&1 && break
    [[ $attempt -lt 30 ]] || { echo 'ephemeral PostgreSQL did not become ready' >&2; exit 1; }
    sleep 1
done

# Synthetic values only. The first pass omits the broker password and proves
# complete preloading prevents every role mutation.
docker run --rm -v "$secrets:/run/dtx-production" "$runtime" /bin/sh -ec '
  install -d -o root -g root -m 0700 /run/dtx-production/role-passwords
  printf "%s\n" "postgres://postgres@postgres:5432/dtx_node?sslmode=disable" >/run/dtx-production/admin-url
  chmod 0400 /run/dtx-production/admin-url
  for role in dtx_identity_node dtx_group_node dtx_mailbox_node dtx_push_registration dtx_push_identity_auth dtx_realtime_sync_gateway; do
    printf "%s\n" "synthetic-$role-password" >"/run/dtx-production/role-passwords/$role"
    chmod 0400 "/run/dtx-production/role-passwords/$role"
  done'
run_migrator() {
    docker run --rm --network "$network" -v "$secrets:/run/dtx-production:ro" \
        -v "$root/target/debug/dtx-production-migrate:/usr/local/bin/dtx-production-migrate:ro" \
        -e DTX_ADMIN_DATABASE_URL_FILE=/run/dtx-production/admin-url \
        -e DTX_DATABASE_URL_FILE=/run/dtx-production/admin-url \
        "$runtime" /usr/local/bin/dtx-production-migrate "$1"
}
run_migrator migrate >/dev/null
run_migrator migrate >/dev/null
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT (SELECT count(*) FROM public._sqlx_migrations WHERE success) = 21
               AND (SELECT epoch = 'product-core-alpha-20260724'
                          AND octet_length(baseline_digest) = 32
                      FROM system.schema_epoch WHERE singleton);" | grep -qx t

if docker run --rm --network "$network" \
    -v "$root/target/debug/dtx-production-migrate:/usr/local/bin/dtx-production-migrate:ro" \
    "$runtime" /bin/sh -ec '
      printf "%s\n" "postgres://postgres@postgres:5432/dtx_node?sslmode=disable" >/tmp/admin-url
      chmod 0400 /tmp/admin-url
      DTX_ADMIN_DATABASE_URL_FILE=/tmp/admin-url /usr/local/bin/dtx-production-migrate bootstrap-roles' \
    >/dev/null 2>&1; then
    echo 'unsafe writable ancestor chain unexpectedly accepted' >&2
    exit 1
fi
if run_migrator bootstrap-roles >/dev/null 2>&1; then
    echo 'incomplete password set unexpectedly mutated roles' >&2
    exit 1
fi
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT to_regrole('dtx_identity_node') IS NULL" | grep -qx t

docker run --rm -v "$secrets:/run/dtx-production" "$runtime" /bin/sh -ec '
  printf "%s\n" synthetic-push-broker-password >/run/dtx-production/role-passwords/broker-target
  chmod 0400 /run/dtx-production/role-passwords/broker-target
  ln -s broker-target /run/dtx-production/role-passwords/dtx_push_broker'
if run_migrator bootstrap-roles >/dev/null 2>&1; then
    echo 'symlinked password unexpectedly passed O_NOFOLLOW' >&2
    exit 1
fi
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT to_regrole('dtx_identity_node') IS NULL" | grep -qx t
docker run --rm -v "$secrets:/run/dtx-production" "$runtime" /bin/sh -ec '
  rm /run/dtx-production/role-passwords/dtx_push_broker
  mv /run/dtx-production/role-passwords/broker-target /run/dtx-production/role-passwords/dtx_push_broker'
run_migrator bootstrap-roles >/dev/null
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null
run_migrator bootstrap-roles >/dev/null
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null

# Existing dangerous attributes and memberships are stripped on reconciliation.
docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "CREATE ROLE dtx_unapproved; ALTER ROLE dtx_identity_node SUPERUSER BYPASSRLS CREATEROLE; GRANT dtx_unapproved TO dtx_identity_node;" >/dev/null
run_migrator bootstrap-roles >/dev/null
run_migrator verify-roles >/dev/null
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND rolinherit AND (SELECT count(*) FROM pg_auth_members edges JOIN pg_roles member ON member.oid = edges.member WHERE member.rolname = 'dtx_identity_node') = 1 FROM pg_roles WHERE rolname = 'dtx_identity_node';" | grep -qx t
echo 'production PostgreSQL Product Core role/readiness/rollback checks passed'
