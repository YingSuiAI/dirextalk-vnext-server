#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
cargo_script="$script_dir/cargo.sh"
postgres_image="postgres:18.4-alpine3.24"
container_name="dtx-sqlx-${BASHPID}-${RANDOM}"
container_started=0
previous_database_url_is_set=0
previous_database_url=""

usage() {
    printf 'Usage: bash scripts/sqlx-prepare.sh\n'
}

if (( $# > 0 )); then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
fi
if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker is required for the SQLx migration/metadata gate.\n' >&2
    exit 1
fi

user_data_root="${XDG_DATA_HOME:-${HOME:?HOME is required when XDG_DATA_HOME is unset}/.local/share}"
sqlx_tool_root="${DTX_SQLX_TOOL_ROOT:-$user_data_root/dirextalk/tools/sqlx-cli-0.9.0}"
if [[ -d "$sqlx_tool_root/bin" ]]; then
    export PATH="$sqlx_tool_root/bin:$PATH"
fi

if ! sqlx_version="$("$cargo_script" sqlx --version 2>&1)"; then
    printf '%s\n' "$sqlx_version" >&2
    printf 'sqlx-cli 0.9.0 is required; install it with the command in COMMANDS.md.\n' >&2
    exit 1
fi
if [[ ! "$sqlx_version" =~ (^|[[:space:]])0\.9\.0($|[[:space:]]) ]]; then
    printf 'sqlx-cli 0.9.0 is required, but found: %s\n' "$sqlx_version" >&2
    exit 1
fi

if [[ -v DATABASE_URL ]]; then
    previous_database_url_is_set=1
    previous_database_url="$DATABASE_URL"
fi

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( container_started == 1 )); then
        docker rm --force "$container_name" >/dev/null 2>&1 || true
    fi
    if (( previous_database_url_is_set == 1 )); then
        export DATABASE_URL="$previous_database_url"
    else
        unset DATABASE_URL
    fi
    exit "$exit_code"
}
trap cleanup EXIT

cd -- "$repository_root"
docker run --detach --name "$container_name" \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    --env POSTGRES_USER=dtx_sqlx \
    --env POSTGRES_DB=dtx_sqlx \
    --publish '127.0.0.1::5432' \
    --tmpfs /var/lib/postgresql \
    "$postgres_image" >/dev/null
container_started=1

ready=0
for (( attempt = 1; attempt <= 60; attempt++ )); do
    running="$(docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null || true)"
    if [[ "$running" != "true" ]]; then
        break
    fi
    if docker exec "$container_name" \
        pg_isready --username dtx_sqlx --dbname dtx_sqlx >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if (( ready == 0 )); then
    running="$(docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null || true)"
    if [[ "$running" != "true" ]]; then
        printf 'Ephemeral PostgreSQL exited before it became ready.\n' >&2
    else
        printf 'Ephemeral PostgreSQL did not become ready within 60 seconds.\n' >&2
    fi
    exit 1
fi

published="$(docker port "$container_name" '5432/tcp')"
host_port="${published##*:}"
if [[ ! "$host_port" =~ ^[0-9]+$ ]]; then
    printf 'Docker returned an invalid PostgreSQL host port.\n' >&2
    exit 1
fi
export DATABASE_URL="postgres://dtx_sqlx@127.0.0.1:${host_port}/dtx_sqlx?sslmode=disable"

"$cargo_script" sqlx migrate run --source migrations
"$cargo_script" sqlx prepare --workspace --check
