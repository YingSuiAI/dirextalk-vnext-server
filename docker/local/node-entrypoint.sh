#!/bin/sh
set -eu

: "${DTX_DEV_IDENTITY_DATABASE_URL:?DTX_DEV_IDENTITY_DATABASE_URL is required}"
: "${DTX_DEV_GROUP_DATABASE_URL:?DTX_DEV_GROUP_DATABASE_URL is required}"
: "${DTX_DEV_MAILBOX_DATABASE_URL:?DTX_DEV_MAILBOX_DATABASE_URL is required}"
: "${DTX_DEV_PUBLIC_FEED_DATABASE_URL:?DTX_DEV_PUBLIC_FEED_DATABASE_URL is required}"
: "${DTX_DEV_INDEXER_DATABASE_URL:?DTX_DEV_INDEXER_DATABASE_URL is required}"

umask 077
secret_dir="${TMPDIR:-/tmp}/dtx-node-database-urls"
mkdir -p "$secret_dir"
printf '%s\n' "$DTX_DEV_IDENTITY_DATABASE_URL" > "$secret_dir/identity"
printf '%s\n' "$DTX_DEV_GROUP_DATABASE_URL" > "$secret_dir/group"
printf '%s\n' "$DTX_DEV_MAILBOX_DATABASE_URL" > "$secret_dir/mailbox"
printf '%s\n' "$DTX_DEV_PUBLIC_FEED_DATABASE_URL" > "$secret_dir/public-feed"
printf '%s\n' "$DTX_DEV_INDEXER_DATABASE_URL" > "$secret_dir/indexer"
unset DTX_DEV_IDENTITY_DATABASE_URL DTX_DEV_GROUP_DATABASE_URL \
    DTX_DEV_MAILBOX_DATABASE_URL DTX_DEV_PUBLIC_FEED_DATABASE_URL \
    DTX_DEV_INDEXER_DATABASE_URL
export DTX_IDENTITY_DATABASE_URL_FILE="$secret_dir/identity"
export DTX_GROUP_DATABASE_URL_FILE="$secret_dir/group"
export DTX_MAILBOX_DATABASE_URL_FILE="$secret_dir/mailbox"
export DTX_PUBLIC_FEED_DATABASE_URL_FILE="$secret_dir/public-feed"
export DTX_INDEXER_DATABASE_URL_FILE="$secret_dir/indexer"

dtx-node &
node_pid=$!
socat TCP-LISTEN:8080,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:9080 &
proxy_pid=$!

cleanup() {
    kill "$proxy_pid" "$node_pid" 2>/dev/null || true
    wait "$proxy_pid" "$node_pid" 2>/dev/null || true
    rm -rf "$secret_dir"
}

trap cleanup EXIT INT TERM
wait "$node_pid"
