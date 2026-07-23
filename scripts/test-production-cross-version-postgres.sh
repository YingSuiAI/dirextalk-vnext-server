#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: test-production-cross-version-postgres.sh' >&2
    exit 2
fi
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'docker daemon is required' >&2; exit 1; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
prior_commit=72de883
candidate_commit=b5c24a1
postgres_image=postgres:18.4-alpine3.24
retained_image=dirextalk/vnet-server@sha256:c972284fe1019c20f11e396be3c801a90991d1950e658b6a00c0a76d1676f17a
fixture=$(mktemp -d)
container="dtx-cross-version-$PPID-$$"
retained_container="$container-retained"
network="$container-network"

cleanup() {
    docker stop "$retained_container" >/dev/null 2>&1 || true
    docker stop "$container" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    find "$fixture" -type f -delete
    find "$fixture" -depth -type d -empty -delete
}
trap cleanup EXIT

git -C "$root" archive "$prior_commit" migrations docker/local/postgres/20-local-runtime-grants.sql \
    docker/production/postgres/agent-control-grants.sql | tar -x -C "$fixture"
[[ $(git -C "$root" show "$prior_commit:Cargo.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1) == 0.1.1 ]]
[[ $(git -C "$root" show "$candidate_commit:Cargo.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1) == 0.1.4 ]]
[[ $(find "$fixture/migrations" -name '*.up.sql' | wc -l) == 54 ]]
[[ $(git -C "$root" diff --name-only "$prior_commit" "$candidate_commit" -- migrations | grep -c '\.up\.sql$') == 1 ]]

docker network create "$network" >/dev/null
docker run -d --rm --name "$container" --network "$network" --network-alias postgres \
    -e POSTGRES_PASSWORD=cross-version-test-only \
    -e POSTGRES_DB=dtx_cross_version \
    "$postgres_image" >/dev/null
for _attempt in $(seq 1 30); do
    if docker exec "$container" pg_isready -U postgres -d dtx_cross_version >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$container" pg_isready -U postgres -d dtx_cross_version >/dev/null

psql_admin() {
    docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d dtx_cross_version "$@"
}

psql_admin >/dev/null <<'SQL'
CREATE TABLE public._sqlx_migrations(
    version bigint PRIMARY KEY,
    description text NOT NULL,
    installed_on timestamptz NOT NULL DEFAULT now(),
    success boolean NOT NULL,
    checksum bytea NOT NULL,
    execution_time bigint NOT NULL
);
DO $roles$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'dtx_identity_runtime', 'dtx_group_runtime', 'dtx_mailbox_runtime',
        'dtx_push_registration_runtime', 'dtx_push_identity_auth_runtime',
        'dtx_realtime_sync_runtime', 'dtx_push_broker_runtime',
        'dtx_public_feed_runtime', 'dtx_agent_runtime', 'dtx_agent_peer_admin',
        'dtx_public_feed_node', 'dtx_indexer_node'
    ] LOOP
        EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
    END LOOP;
    CREATE ROLE dtx_agent_control LOGIN PASSWORD 'retained-code-test-only'
        IN ROLE dtx_agent_runtime;
END
$roles$;
SQL

for migration in "$fixture"/migrations/*.up.sql; do
    base=$(basename "$migration" .up.sql)
    version=${base%%_*}
    description=${base#*_}
    checksum=$(sha384sum "$migration" | awk '{print $1}')
    psql_admin --single-transaction >/dev/null <"$migration"
    psql_admin >/dev/null <<SQL
INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time)
VALUES ($version,'$description',true,decode('$checksum','hex'),0);
SQL
done

# Establish the exact live 0.1.1 grants before the version transition.
psql_admin >/dev/null <"$fixture/docker/local/postgres/20-local-runtime-grants.sql"
psql_admin >/dev/null <"$fixture/docker/production/postgres/agent-control-grants.sql"

# The only 0.1.4 schema delta is applied in the same forward-only manner as the
# production migrator. No down file is read or executed.
candidate_migration="$fixture/candidate.up.sql"
git -C "$root" show \
    "$candidate_commit:migrations/202607230055_agent_identity_reader_rls_fix.up.sql" \
    >"$candidate_migration"
psql_admin --single-transaction >/dev/null <"$candidate_migration"
candidate_checksum=$(sha384sum "$candidate_migration" | awk '{print $1}')
psql_admin >/dev/null <<SQL
INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time)
VALUES (202607230055,'agent_identity_reader_rls_fix',true,decode('$candidate_checksum','hex'),0);
SQL

# Candidate grant reconciliation runs after migrations in production. Exercise
# the retained 0.1.1 Agent Control identity/query contract against that exact
# resulting 0.1.4 database surface.
git -C "$root" show "$candidate_commit:docker/local/postgres/20-local-runtime-grants.sql" \
    | psql_admin >/dev/null
git -C "$root" show "$candidate_commit:docker/production/postgres/agent-control-grants.sql" \
    | psql_admin >/dev/null
docker exec -e PGPASSWORD=retained-code-test-only "$container" \
    psql -v ON_ERROR_STOP=1 -At -U dtx_agent_control -d dtx_cross_version \
    -c "SELECT count(*) >= 0 FROM identity.log_heads" | grep -qx t
psql_admin -At -c \
    "SELECT count(*) FROM public._sqlx_migrations WHERE success" | grep -qx 55

if docker image inspect "$retained_image" >/dev/null 2>&1; then
    runtime="$fixture/retained-runtime"
    mkdir -p "$runtime"
    openssl req -x509 -newkey ed25519 -nodes -days 1 \
        -subj '/CN=retained-code.test' -keyout "$runtime/server-key.pem" \
        -out "$runtime/server-cert.pem" >/dev/null 2>&1
    cp "$runtime/server-cert.pem" "$runtime/client-roots.pem"
    cp "$runtime/server-cert.pem" "$runtime/issuer.pem"
    cp "$runtime/server-key.pem" "$runtime/issuer-key.pem"
    printf '%s\n' \
        'postgresql://dtx_agent_control:retained-code-test-only@postgres/dtx_cross_version' \
        >"$runtime/database-url"
    chmod 0644 "$runtime"/*
    cat >"$runtime/config.json" <<'JSON'
{
  "database_url_file": "/run/dtx-test/database-url",
  "max_database_connections": 4,
  "health": {"listen": "0.0.0.0:9080"},
  "owner_api": {"listen": "127.0.0.1:9081", "tenant_id": "0190f2a5-7b1c-7abc-8def-0123456789a0"},
  "enrollment": {"listen": "0.0.0.0:9443", "certificate_chain_pem": "/run/dtx-test/server-cert.pem", "private_key_pkcs8_pem": "/run/dtx-test/server-key.pem"},
  "control": {"listen": "0.0.0.0:9444", "certificate_chain_pem": "/run/dtx-test/server-cert.pem", "private_key_pkcs8_pem": "/run/dtx-test/server-key.pem", "client_ca_bundle_pem": "/run/dtx-test/client-roots.pem"},
  "legacy_gateway": {"listen": "0.0.0.0:9445", "certificate_chain_pem": "/run/dtx-test/server-cert.pem", "private_key_pkcs8_pem": "/run/dtx-test/server-key.pem", "client_ca_bundle_pem": "/run/dtx-test/client-roots.pem"},
  "connector_issuer": {"certificate_pem": "/run/dtx-test/issuer.pem", "private_key_pkcs8_pem": "/run/dtx-test/issuer-key.pem"}
}
JSON
    chmod 0644 "$runtime/config.json"
    docker run -d --rm --name "$retained_container" --network "$network" \
        -v "$runtime:/run/dtx-test:ro" \
        --entrypoint /usr/local/bin/dtx-agent-control "$retained_image" \
        --config /run/dtx-test/config.json >/dev/null
    retained_ready=0
    for _attempt in $(seq 1 30); do
        if docker exec "$container" wget -qO- \
            "http://$retained_container:9080/ready" 2>/dev/null | grep -qx ready; then
            retained_ready=1
            break
        fi
        [[ $(docker inspect "$retained_container" --format '{{.State.Running}}' 2>/dev/null) == true ]] || break
        sleep 1
    done
    if (( retained_ready != 1 )); then
        docker logs "$retained_container" >&2 || true
        echo 'retained immutable 0.1.1 Agent Control did not become ready on the 0.1.4 schema' >&2
        exit 1
    fi
    echo 'PostgreSQL 0.1.1 -> 0.1.4 migration and immutable retained 0.1.1 Agent Control readiness passed'
else
    echo "immutable retained binary fixture unavailable locally: $retained_image" >&2
    echo 'PostgreSQL 0.1.1 -> 0.1.4 migration and retained grant/query compatibility passed'
fi
