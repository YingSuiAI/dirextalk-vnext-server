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

# The disposable local node still needs a stable per-container Sequencer key so
# the unified Group Service descriptor is usable. Production supplies this file
# out of band; this development key lives only in the container writable layer.
sequencer_key_dir="${HOME:?HOME is required}/.local/state/dirextalk"
sequencer_key="$sequencer_key_dir/mls-sequencer.key"
mkdir -p "$sequencer_key_dir"
chmod 0700 "$sequencer_key_dir"
if [ ! -e "$sequencer_key" ]; then
    temporary_key="$sequencer_key.$$"
    dd if=/dev/urandom of="$temporary_key" bs=32 count=1 status=none
    chmod 0600 "$temporary_key"
    mv "$temporary_key" "$sequencer_key"
fi
export DTX_GROUP_MLS_SEQUENCER_KEY_FILE="$sequencer_key"

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
