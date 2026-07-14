#!/bin/sh
set -eu

: "${DTX_DEV_DATABASE_URL:?DTX_DEV_DATABASE_URL is required}"

umask 077
database_url_file="${TMPDIR:-/tmp}/dtx-identity-database-url"
printf '%s\n' "$DTX_DEV_DATABASE_URL" > "$database_url_file"
unset DTX_DEV_DATABASE_URL
export DTX_IDENTITY_DATABASE_URL_FILE="$database_url_file"

dtx-identity-node &
node_pid=$!
socat TCP-LISTEN:8080,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:9080 &
proxy_pid=$!

cleanup() {
    kill "$proxy_pid" "$node_pid" 2>/dev/null || true
    wait "$proxy_pid" "$node_pid" 2>/dev/null || true
    rm -f "$database_url_file"
}

trap cleanup EXIT INT TERM
wait "$node_pid"
