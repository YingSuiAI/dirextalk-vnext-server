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

# Synthetic values only. The first pass intentionally omits the final password
# and proves complete preloading prevents every role mutation.
docker run --rm -v "$secrets:/run/dtx-production" "$runtime" /bin/sh -ec '
  install -d -o root -g root -m 0700 /run/dtx-production/role-passwords
  printf "%s\n" "postgres://postgres@postgres:5432/dtx_node?sslmode=disable" >/run/dtx-production/admin-url
  chmod 0400 /run/dtx-production/admin-url
  for role in dtx_identity_node dtx_group_node dtx_mailbox_node dtx_push_registration dtx_push_identity_auth dtx_realtime_sync_gateway dtx_push_broker dtx_public_feed_node dtx_indexer_node; do
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
# Model an already-migrated installation from before peer administration was
# bootstrapped. Migration 38's conditional grant must leave no optional role or
# ACL behind when the role did not yet exist.
run_migrator migrate >/dev/null
run_migrator migrate >/dev/null
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT (SELECT count(*) FROM public._sqlx_migrations WHERE success) = 21
               AND (SELECT epoch = 'product-core-alpha-20260724'
                          AND octet_length(baseline_digest) = 32
                      FROM system.schema_epoch WHERE singleton);" | grep -qx t
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT to_regrole('dtx_agent_peer_admin') IS NULL AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE coalesce(array_to_string(nspacl, ','), '') LIKE '%dtx_agent_peer_admin%') AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE coalesce(array_to_string(proacl, ','), '') LIKE '%dtx_agent_peer_admin%') AND NOT EXISTS (SELECT 1 FROM pg_class WHERE coalesce(array_to_string(relacl, ','), '') LIKE '%dtx_agent_peer_admin%')" | grep -qx t
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
  printf "%s\n" synthetic-agent-control-password >/run/dtx-production/role-passwords/agent-control-target
  chmod 0400 /run/dtx-production/role-passwords/agent-control-target
  ln -s agent-control-target /run/dtx-production/role-passwords/dtx_agent_control'
if run_migrator bootstrap-roles >/dev/null 2>&1; then
    echo 'symlinked password unexpectedly passed O_NOFOLLOW' >&2
    exit 1
fi
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT to_regrole('dtx_identity_node') IS NULL" | grep -qx t
docker run --rm -v "$secrets:/run/dtx-production" "$runtime" /bin/sh -ec '
  rm /run/dtx-production/role-passwords/dtx_agent_control
  mv /run/dtx-production/role-passwords/agent-control-target /run/dtx-production/role-passwords/dtx_agent_control'
run_migrator bootstrap-roles >/dev/null
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname = 'dtx_agent_peer_admin'" | grep -qx t
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = 'dtx_agent_peer_admin'" | grep -qx t
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null
run_migrator bootstrap-roles >/dev/null
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null

docker exec "$database" psql -Atq -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "SET ROLE dtx_agent_peer_admin; SELECT has_function_privilege(current_user, 'agent.register_mcp_credential_digest(uuid,uuid,bytea,uuid,uuid,uuid,text,uuid,text,bigint,bigint)', 'EXECUTE') AND has_function_privilege(current_user, 'agent.revoke_mcp_credential_digest(uuid,uuid,bytea,bigint)', 'EXECUTE');" | grep -qx t
docker exec "$database" psql -Atq -U postgres -d dtx_node \
    -c "SELECT (SELECT count(*) FROM pg_namespace WHERE nspname IN ('system', 'agent', 'identity', 'groups', 'directory') AND has_schema_privilege('dtx_agent_peer_admin', oid, 'USAGE')) = 1 AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('system', 'agent', 'identity', 'groups', 'directory') AND has_schema_privilege('dtx_agent_peer_admin', oid, 'CREATE')) AND (SELECT count(*) FROM pg_proc JOIN pg_namespace ON pg_namespace.oid = pg_proc.pronamespace WHERE nspname IN ('system', 'agent', 'identity', 'groups', 'directory') AND has_function_privilege('dtx_agent_peer_admin', pg_proc.oid, 'EXECUTE')) = 2 AND NOT EXISTS (SELECT 1 FROM pg_class JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace WHERE nspname IN ('system', 'agent', 'identity', 'groups', 'directory') AND relkind IN ('r', 'p', 'v', 'm', 'f') AND (has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'SELECT') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'INSERT') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'UPDATE') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'DELETE') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'TRUNCATE') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'REFERENCES') OR has_table_privilege('dtx_agent_peer_admin', pg_class.oid, 'TRIGGER')))" | grep -qx t
if docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "SET ROLE dtx_agent_peer_admin; SELECT count(*) FROM agent.mcp_credentials;" >/dev/null 2>&1; then
    echo 'Agent peer admin acquired forbidden table privilege' >&2
    exit 1
fi
docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "REVOKE EXECUTE ON FUNCTION agent.revoke_mcp_credential_digest(uuid, uuid, bytea, bigint) FROM dtx_agent_peer_admin;" >/dev/null
if run_migrator verify-roles >/dev/null 2>&1; then
    echo 'Agent peer admin readiness unexpectedly accepted a missing digest-revoke grant' >&2
    exit 1
fi
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null

for role in dtx_indexer_node dtx_public_feed_node; do
    docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
        -c "REVOKE EXECUTE ON FUNCTION system.is_uuid_v7(uuid) FROM $role;" >/dev/null
    if run_migrator verify-roles >/dev/null 2>&1; then
        echo "$role readiness unexpectedly accepted a missing UUIDv7 validator grant" >&2
        exit 1
    fi
    run_migrator grant-roles >/dev/null
    run_migrator verify-roles >/dev/null
done

docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "REVOKE UPDATE ON directory.index_cache_generations FROM dtx_indexer_node;" >/dev/null
if run_migrator verify-roles >/dev/null 2>&1; then
    echo 'Indexer readiness unexpectedly accepted a missing cache-generation grant' >&2
    exit 1
fi
run_migrator grant-roles >/dev/null
run_migrator verify-roles >/dev/null

docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "SET ROLE dtx_agent_control; SELECT count(*) FROM system.schema_versions; SELECT epoch, baseline_digest FROM system.schema_epoch;" >/dev/null
if docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "SET ROLE dtx_agent_control; TRUNCATE agent.connector_control_operations;" >/dev/null 2>&1; then
    echo 'Agent Control acquired forbidden TRUNCATE privilege' >&2
    exit 1
fi

# Existing dangerous attributes and memberships are stripped on reconciliation.
docker exec "$database" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_node \
    -c "CREATE ROLE dtx_unapproved; ALTER ROLE dtx_agent_control SUPERUSER BYPASSRLS CREATEROLE; GRANT dtx_unapproved TO dtx_agent_control; ALTER ROLE dtx_agent_peer_admin LOGIN INHERIT SUPERUSER BYPASSRLS CREATEROLE PASSWORD 'synthetic-peer-admin-password'; GRANT dtx_unapproved TO dtx_agent_peer_admin;" >/dev/null
run_migrator bootstrap-roles >/dev/null
run_migrator verify-roles >/dev/null
echo 'production PostgreSQL role/readiness/rollback checks passed'
