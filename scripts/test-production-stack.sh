#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compose="$root/docker/production/docker-compose.yml"
[[ -f "$compose" ]] || { echo 'production compose missing' >&2; exit 1; }
grep -q 'dirextalk/vnet-server@sha256:<64 lowercase hex>' "$root/docker/production/README.md"
grep -q 'condition: service_completed_successfully' "$compose"
grep -q 'postgres-data:' "$compose"
grep -q 'postgres-data:/var/lib/postgresql$' "$compose"
! grep -q 'postgres-data:/var/lib/postgresql/data$' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-agent-control"\]' "$compose"
grep -q 'entrypoint: \["/usr/local/bin/dtx-realtime-sync-gateway"\]' "$compose"
! grep -q '^  opaque-push:' "$compose"
grep -q 'command: \["verify-roles"\]' "$compose"
grep -q 'dtx_agent_control' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'dtx_agent_peer_admin' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'register_mcp_credential_digest' "$root/docker/production/postgres/agent-control-grants.sql"
grep -q 'agent.connector_bootstrap_issuances' "$root/docker/production/postgres/agent-control-grants.sql"
grep -q 'agent.connector_bootstrap_issuances' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'directory.index_registrations.*UPDATE' "$root/docker/production/postgres/verify-roles.sql"
grep -q 'directory.index_cache_generations' "$root/docker/local/postgres/20-local-runtime-grants.sql"
grep -q "directory.index_cache_generations', 'UPDATE'" "$root/docker/production/postgres/verify-roles.sql"
grep -q 'DTX_.*DATABASE_URL_FILE' "$compose"
grep -q 'DTX_AGENT_CONTROL_BIND.*:9443:9443' "$compose"
grep -q 'network_mode: service:agent-control' "$compose"
grep -q 'https://.*:8443/local-health' "$compose"
grep -q 'https://.*:9444/local/ready' "$compose"
grep -q 'reverse_proxy @realtime https://realtime-gateway:9444' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @node https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q '@node path_regexp versioned_api \^/v\[1-9\]\[0-9\]\*/\.\*\$' "$root/docker/production/Caddyfile"
grep -qF '@public_feed path_regexp public_feed ^/\.well-known/dirextalk/public/v1/[^/]+(/.*)?$' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @public_feed https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q 'path_regexp mcp \^/mcp\$' "$root/docker/production/Caddyfile"
grep -q 'reverse_proxy @mcp https://dtx-node:8443' "$root/docker/production/Caddyfile"
grep -q 'tls_trust_pool file /data/caddy/private-ca.pem' "$root/docker/production/Caddyfile"
! grep -q 'agent-control:944' "$root/docker/production/Caddyfile"
! grep -Eq 'DTX_(DATABASE_URL|ADMIN_DATABASE_URL)=' "$compose"
! grep -Eq 'image:[[:space:]]+[^$[:space:]]+:(latest|dev)(@|[[:space:]]|$)' "$compose"
! grep -q 'kill -0 1' "$compose"
! grep -Eq 'docker compose.*(exec|run)[[:space:]]' "$root/scripts/production-stack"/*.sh
grep -q 'O_NOFOLLOW' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'validate_root_ancestor_chain' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'preload_role_passwords' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q '\.commit()' "$root/bins/dtx-production-migrate/src/main.rs"
grep -q 'prior.env' "$root/scripts/production-stack/update.sh"
grep -q 'compose.sha256' "$root/scripts/production-stack/update.sh"
grep -Eq 'status=rolled_back|write_record_receipt rolled_back' "$root/scripts/production-stack/update.sh"
! grep -Eq 'docker compose.*down.*(--volumes|-v)' "$root/scripts/production-stack/update.sh"
grep -q 'bundle is missing the exact forward migration compatibility marker' "$root/scripts/production-stack/host/install-vnext"
grep -q 'invokes a down migration' "$root/docker/production/README.md"
grep -q 'force-recreate --no-deps --abort-on-container-failure' "$root/scripts/production-stack/verify.sh"
grep -q 'last-successful-operation' "$root/scripts/production-stack/cleanup-cache.sh"
grep -q 'legacy_build=/opt/dirextalk-vnext/build' \
    "$root/scripts/production-stack/cleanup-cache.sh"
grep -q -- 'find -P "$legacy_build" -xdev' \
    "$root/scripts/production-stack/cleanup-cache.sh"
grep -q 'mountpoint -q -- "$legacy_build"' \
    "$root/scripts/production-stack/cleanup-cache.sh"
grep -q -- '--filter until=24h' "$root/scripts/production-stack/cleanup-cache.sh"
grep -q -- '--max-used-space 1073741824' "$root/scripts/production-stack/cleanup-cache.sh"
grep -q 'cleanup_timeout_seconds=120' "$root/scripts/production-stack/cleanup-cache.sh"
grep -q -- '--kill-after=10s "$cleanup_timeout_seconds"' \
    "$root/scripts/production-stack/cleanup-cache.sh"
! grep -Eq 'docker (volume|system|container) (rm|prune)' \
    "$root/scripts/production-stack/cleanup-cache.sh"
grep -q '440:0:10001' "$root/scripts/production-stack/validate-files.sh"
grep -q '400:0:0' "$root/scripts/production-stack/validate-files.sh"
grep -q '444:0:0' "$root/scripts/production-stack/validate-files.sh"
grep -q 'opaque push is fail-closed disabled\|Opaque push is fail-closed disabled' "$root/docker/production/README.md"
grep -q 'dirextalk.vnext-stack-bundle' "$root/tools/vnext-stack-bundle.py"
grep -q 'dirextalk.vnext-install-request' "$root/scripts/production-stack/host/install-vnext"
grep -q 'dirextalk.vnext-installed-release' "$root/scripts/production-stack/host/read-vnext-receipt"
grep -q 'BUNDLE_UPLOAD = Path("/home/ubuntu/dirextalk-vnext.bundle")' "$root/scripts/production-stack/host/install-vnext"
grep -q 'REQUEST_UPLOAD = Path("/home/ubuntu/dirextalk-vnext.request")' "$root/scripts/production-stack/host/install-vnext"
grep -q 'dirextalk/vnet-server@sha256:' "$root/scripts/production-stack/host/install-vnext"
! grep -q 'dirextalk/vnet-server:latest' "$root/scripts/production-stack/host/install-vnext"
python3 "$root/tools/validate-production-images.py" --self-test
python3 "$root/tools/vnext-stack-bundle.py" self-test --source-root "$root"
python3 "$root/scripts/test-production-stack-cross-version.py"
bash "$root/scripts/test-production-stack-update-recovery.sh"

cleanup_test_root=$(mktemp -d)
trap 'find "$cleanup_test_root" -xdev -type f -delete; find "$cleanup_test_root" -xdev -type l -delete; find "$cleanup_test_root" -xdev -depth -type d -empty -delete' EXIT
cleanup_fixture="$cleanup_test_root/opt/dirextalk-vnext"
mkdir -p "$cleanup_fixture"/{build/nested,releases,config,tls,secrets,volumes,logs}
chmod 0755 "$cleanup_fixture"
chmod 0700 "$cleanup_fixture/build" "$cleanup_fixture/build/nested"
printf 'retired compiler output\n' >"$cleanup_fixture/build/nested/artifact"
printf 'preserve\n' >"$cleanup_fixture/releases/current"
printf 'preserve\n' >"$cleanup_fixture/secrets/operator"
(
    # shellcheck source=scripts/production-stack/cleanup-cache.sh
    source "$root/scripts/production-stack/cleanup-cache.sh"
    legacy_parent="$cleanup_fixture"
    legacy_build="$cleanup_fixture/build"
    cleanup_owner_uid=$(id -u)
    cleanup_owner_gid=$(id -g)
    cleanup_timeout_seconds=5
    cleanup_legacy_build
)
[[ ! -e "$cleanup_fixture/build" && ! -L "$cleanup_fixture/build" ]]
grep -qx preserve "$cleanup_fixture/releases/current"
grep -qx preserve "$cleanup_fixture/secrets/operator"
for sibling in releases config tls secrets volumes logs; do
    [[ -d "$cleanup_fixture/$sibling" ]]
done

mkdir -m 0700 "$cleanup_fixture/build"
ln -s "$cleanup_fixture/releases/current" "$cleanup_fixture/build/outside"
if (
    # shellcheck source=scripts/production-stack/cleanup-cache.sh
    source "$root/scripts/production-stack/cleanup-cache.sh"
    legacy_parent="$cleanup_fixture"
    legacy_build="$cleanup_fixture/build"
    cleanup_owner_uid=$(id -u)
    cleanup_owner_gid=$(id -g)
    cleanup_timeout_seconds=5
    cleanup_legacy_build
) 2>/dev/null; then
    echo 'legacy build cleanup unexpectedly accepted a symlink' >&2
    exit 1
fi
[[ -L "$cleanup_fixture/build/outside" ]]
grep -qx preserve "$cleanup_fixture/releases/current"
unlink "$cleanup_fixture/build/outside"
rmdir "$cleanup_fixture/build"
ln -s "$cleanup_fixture/releases" "$cleanup_fixture/build"
if (
    # shellcheck source=scripts/production-stack/cleanup-cache.sh
    source "$root/scripts/production-stack/cleanup-cache.sh"
    legacy_parent="$cleanup_fixture"
    legacy_build="$cleanup_fixture/build"
    cleanup_owner_uid=$(id -u)
    cleanup_owner_gid=$(id -g)
    cleanup_timeout_seconds=5
    cleanup_legacy_build
) 2>/dev/null; then
    echo 'legacy build cleanup unexpectedly followed a root symlink' >&2
    exit 1
fi
[[ -L "$cleanup_fixture/build" ]]
grep -qx preserve "$cleanup_fixture/releases/current"

for example in "$root"/docker/production/examples/x{6,7,8}.env.example; do
    python3 "$root/tools/validate-production-images.py" "$example"
done
for script in "$root"/scripts/production-stack/{install,bootstrap,update,verify,down,cleanup-cache,validate-images,validate-files}.sh; do
    test -x "$script" || { echo "not executable: $script" >&2; exit 1; }
done
for helper in "$root"/scripts/production-stack/host/{install-vnext,read-vnext-receipt,client-binding-issue,client-binding-expire,client-binding-revoke,client-binding-export-cleanup}; do
    test -x "$helper" || { echo "not executable: $helper" >&2; exit 1; }
done
grep -q 'client-binding-issue' "$root/tools/vnext-stack-bundle.py"
grep -q 'client-binding-expire' "$root/tools/vnext-stack-bundle.py"
grep -q 'client-binding-revoke' "$root/tools/vnext-stack-bundle.py"
grep -q 'client-binding-export-cleanup' "$root/tools/vnext-stack-bundle.py"
! grep -q 'private-ca.pem:/run/dtx-client-binding/private-ca.pem:ro' "$root/docker/production/docker-compose.yml"
! grep -q 'private-key.pem:/run/dtx-client-binding' "$root/docker/production/docker-compose.yml"
grep -q '/etc/dirextalk/vnext/client-binding' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q 'shred --remove=unlink' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q '/home/ubuntu/dirextalk-client-binding.request' "$root/scripts/production-stack/host/client-binding-issue"
grep -q '/home/ubuntu/dirextalk-client-binding.import.json' "$root/scripts/production-stack/host/client-binding-issue"
grep -q '/run/dtx-client-binding/private-ca.pem' "$root/scripts/production-stack/host/client-binding-issue"
grep -q '/etc/dirextalk/vnext/tls/private-ca.pem' "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'private-ca.pem.tmp' "$root/scripts/production-stack/host/client-binding-issue"
grep -q "0:0:444:1" "$root/scripts/production-stack/host/client-binding-issue"
grep -q "stat -c '%d' /home/ubuntu" "$root/scripts/production-stack/host/client-binding-issue"
grep -q "1000:1000:400" "$root/scripts/production-stack/host/client-binding-issue"
grep -q "0:0:600" "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'mv -T.*dirextalk-client-binding.request\|mv -T -- "\$staged"' "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'mv -fT.*"\$export"' "$root/scripts/production-stack/host/client-binding-issue"
grep -q ':%h' "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'client-binding-issuer >/dev/null' "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'normalize_request_tmp' "$root/scripts/production-stack/host/client-binding-issue"
grep -q 'binding export staging diverges' "$root/scripts/production-stack/host/client-binding-issue"
grep -q '1000:1000:400:1\|0:0:600:1' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q '0:0:400:1' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q '1000:1000:600:1' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q '/home/ubuntu/dirextalk-client-binding.request' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q '/home/ubuntu/dirextalk-client-binding.import.json' "$root/scripts/production-stack/host/client-binding-export-cleanup"
grep -q "1000:1000:400" "$root/scripts/production-stack/host/client-binding-export-cleanup"
! grep -Eq 'client-binding-(issue|expire|revoke|export-cleanup).*\$[A-Za-z_]+|client-binding-(issue|expire|revoke|export-cleanup).*\$\{[A-Za-z_]+' "$root/scripts/production-stack/host"/*
grep -q -- '--runtime-image dirextalk/vnet-server@sha256:<64-hex> --migrator-image' "$root/scripts/check-release-image.sh"
grep -q 'docker export --output' "$root/scripts/check-release-image.sh"
grep -q 'scripts/check-release-image.sh' "$root/scripts/publish-production-release.sh"
grep -q 'bash scripts/test-production-cross-version-postgres.sh' "$root/scripts/publish-production-release.sh"
grep -q 'DTX_PUBLICATION_SOURCE_COMMIT="\$source_commit"' \
    "$root/scripts/publish-production-release.sh"
grep -q "candidate_commit=.*rev-parse --verify 'HEAD" \
    "$root/scripts/test-production-cross-version-postgres.sh"
! grep -q 'candidate_commit=b5c24a1277ee5b65268c601f43b634cd2943c004' \
    "$root/scripts/test-production-cross-version-postgres.sh"
! grep -q '202607230055_agent_identity_reader_rls_fix' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'diff --name-status --no-renames' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'candidate-migrations.expected' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'prior-migrations.expected' \
    "$root/scripts/test-production-cross-version-postgres.sh"
[[ $(grep -Fc 'description=${description_slug//_/ }' \
    "$root/scripts/test-production-cross-version-postgres.sh") -eq 2 ]]
! grep -Fq 'description=${base#*_}' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'candidate_migration_count=.*candidate_migrations' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'secrets.token_hex(8)' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'retained_container_id=.*docker run -d' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q 'docker logs "\$retained_container_id"' \
    "$root/scripts/test-production-cross-version-postgres.sh"
! grep -q 'docker run -d --rm --name "\$retained_container"' \
    "$root/scripts/test-production-cross-version-postgres.sh"
grep -q -- '--runtime-image "\$repository@\$runtime_digest"' "$root/scripts/publish-production-release.sh"
grep -q -- '--migrator-image "\$repository@\$migrator_digest"' "$root/scripts/publish-production-release.sh"
grep -q 'snapshot_tool=.*production-source-snapshot.py' \
    "$root/scripts/publish-production-release.sh"
grep -q 'validate-source' \
    "$root/scripts/publish-production-release.sh"
grep -q -- '--file "\$build_context/docker/release/Dockerfile"' \
    "$root/scripts/publish-production-release.sh"
grep -q -- '--file "\$build_context/docker/production/Dockerfile.migrate"' \
    "$root/scripts/publish-production-release.sh"
[[ $(grep -Fc '    "$build_context"' "$root/scripts/publish-production-release.sh") -eq 2 ]]
test -x "$root/tools/production-source-snapshot.py"
test -x "$root/tools/test-client-binding-release-artifacts.py"
for test_script in "$root"/scripts/{test-production-stack-update-recovery,test-production-cross-version-postgres}.sh; do
    test -x "$test_script" || { echo "not executable: $test_script" >&2; exit 1; }
done
echo 'production stack structural/negative checks passed'
