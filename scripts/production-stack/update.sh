#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: update.sh' >&2
    exit 2
fi
[[ ${EUID} -eq 0 ]] || { echo 'update requires root' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
env_file=/etc/dirextalk/vnext/config/production.env
compose_file=/etc/dirextalk/vnext/config/production-compose.yml
[[ -f "$env_file" && ! -L "$env_file" && $(stat -c '%a' "$env_file") == 644 ]] || { echo 'invalid production env file' >&2; exit 1; }
scripts/production-stack/validate-files.sh
scripts/production-stack/validate-images.sh
previous=/var/lib/dirextalk/vnext/current.env
[[ -f "$previous" && ! -L "$previous" && $(stat -c '%a:%u:%g' "$previous") == 600:0:0 ]] || { echo 'retained prior release is required' >&2; exit 1; }
python3 /usr/local/lib/dirextalk/validate-production-images.py "$previous"
grep -qx 'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' "$previous" || { echo 'prior release has no compatible rollback contract' >&2; exit 1; }
grep -qx 'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' "$env_file" || { echo 'candidate has no compatible rollback contract' >&2; exit 1; }
previous_version=$(sed -n 's/^DTX_RELEASE_VERSION=//p' "$previous")
candidate_version=$(sed -n 's/^DTX_RELEASE_VERSION=//p' "$env_file")
[[ "$previous_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$candidate_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo 'production release versions must be canonical SemVer' >&2
    exit 1
}
if [[ "$candidate_version" != "$previous_version" ]]; then
    IFS=. read -r previous_major previous_minor previous_patch <<<"$previous_version"
    IFS=. read -r candidate_major candidate_minor candidate_patch <<<"$candidate_version"
    if [[ "$previous_version" != "0.1.1" || "$candidate_version" != "0.1.4" ]]; then
        echo 'production cross-version admission is limited to 0.1.1 -> 0.1.4' >&2
        exit 1
    fi
    if (( candidate_major < previous_major ||
        (candidate_major == previous_major && candidate_minor < previous_minor) ||
        (candidate_major == previous_major && candidate_minor == previous_minor && candidate_patch <= previous_patch) )); then
        echo 'production update must move strictly forward across schema history' >&2
        exit 1
    fi
fi
# A completed update is a safe replay. The retained receipt is deliberately
# checked before any pull/up so a crash after the final compose succeeds cannot
# repeat external work.
last_success=/var/lib/dirextalk/vnext/last-successful-operation
if cmp -s "$env_file" "$previous" && [[ -f "$last_success" ]] && grep -qx 'status=ready' "$last_success"; then
    echo 'production update already applied; replay is a no-op'
    exit 0
fi
record=$(mktemp -d /var/lib/dirextalk/vnext/releases/update.XXXXXXXX)
install -o root -g root -m 0600 "$previous" "$record/prior.env"
install -o root -g root -m 0600 "$env_file" "$record/candidate.env"
sha256sum "$compose_file" >"$record/compose.sha256"
chmod 0600 "$record/compose.sha256"
scripts/production-stack/validate-images.sh
docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" pull --quiet
scripts/production-stack/validate-images.sh
if ! docker compose --project-name dirextalk-vnext-production --env-file "$env_file" -f "$compose_file" up -d --remove-orphans \
    || ! scripts/production-stack/verify.sh; then
    sha256sum --check --status "$record/compose.sha256" || { echo 'compose changed; automatic rollback refused' >&2; exit 1; }
    python3 /usr/local/lib/dirextalk/validate-production-images.py "$record/prior.env"
    # Code-only rollback: forward migrations are never reversed. Reconcile the
    # retained binaries and images without dependencies, preserving named
    # volumes, operator config/secrets, and TLS material.
    docker compose --project-name dirextalk-vnext-production --env-file "$record/prior.env" -f "$compose_file" \
        up -d --no-deps dtx-node realtime-gateway agent-control caddy
    python3 /usr/local/lib/dirextalk/validate-production-images.py "$record/prior.env"
    docker compose --project-name dirextalk-vnext-production --env-file "$record/prior.env" -f "$compose_file" \
        up --force-recreate --no-deps --abort-on-container-failure node-ready realtime-ready agent-control-ready
    printf 'status=rolled_back\n' >"$record/receipt.tmp"
    chmod 0600 "$record/receipt.tmp"
    mv "$record/receipt.tmp" "$record/receipt"
    echo 'candidate readiness failed; compatible prior release restored' >&2
    exit 1
fi
printf 'status=ready\nkind=update\n' >"$record/receipt.tmp"
chmod 0600 "$record/receipt.tmp"
mv "$record/receipt.tmp" "$record/receipt"
install -o root -g root -m 0600 "$env_file" /var/lib/dirextalk/vnext/current.env.tmp
mv /var/lib/dirextalk/vnext/current.env.tmp /var/lib/dirextalk/vnext/current.env
printf 'status=ready\n' >/var/lib/dirextalk/vnext/last-successful-operation.tmp
chmod 0600 /var/lib/dirextalk/vnext/last-successful-operation.tmp
mv /var/lib/dirextalk/vnext/last-successful-operation.tmp /var/lib/dirextalk/vnext/last-successful-operation
scripts/production-stack/cleanup-cache.sh
