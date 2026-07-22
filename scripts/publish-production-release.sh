#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: publish-production-release.sh' >&2
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
command -v docker >/dev/null 2>&1 || { echo 'docker is required for production publication' >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo 'git is required for production publication' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required for production publication' >&2; exit 1; }
docker info >/dev/null
docker buildx version >/dev/null

input=docker/release/production-release.json
state=target/production-release
lock="$state/release.lock"
active="$state/active-builder"
umask 077
install -d -m 0700 "$state"
[[ -d "$state" && ! -L "$state" ]] || { echo 'release state directory is unsafe' >&2; exit 1; }
if ! mkdir "$lock"; then
    echo 'another production release is active' >&2
    exit 1
fi
owns_builder=0
finish() {
    status=$?
    trap - EXIT
    if (( owns_builder == 1 )) && ! scripts/cleanup-production-release.sh; then
        status=1
    fi
    if ! rmdir "$lock"; then
        status=1
    fi
    exit "$status"
}
trap finish EXIT

if [[ -e "$active" || -L "$active" ]]; then
    echo 'stale release builder state exists; run scripts/cleanup-production-release.sh first' >&2
    exit 1
fi
git diff --quiet
git diff --cached --quiet
[[ -z $(git ls-files --others --exclude-standard) ]] || { echo 'production publication requires a clean worktree' >&2; exit 1; }
source_commit=$(git rev-parse --verify 'HEAD^{commit}')
[[ $source_commit =~ ^[0-9a-f]{40}$ ]] || { echo 'source commit is not a full Git object ID' >&2; exit 1; }
version=$(python3 tools/production-release.py show-version --input "$input" --repository-root "$root")
repository=dirextalk/vnet-server
runtime_version_tag="$repository:$version"
runtime_commit_tag="$repository:git-$source_commit"
migrator_version_tag="$repository:migrate-$version"
migrator_commit_tag="$repository:migrate-git-$source_commit"
latest_tag="$repository:latest"

for evidence in \
    release-facts.json \
    runtime-metadata.json runtime-version-manifest.json runtime-commit-manifest.json \
    migrator-metadata.json migrator-version-manifest.json migrator-commit-manifest.json \
    latest-manifest.json; do
    path="$state/$evidence"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || { echo "unsafe stale release evidence: $path" >&2; exit 1; }
        /usr/bin/unlink "$path"
    fi
done

tag_must_be_absent() {
    tag=$1
    label=$2
    error_file="$state/$label-preflight.stderr"
    if docker buildx imagetools inspect "$tag" --format '{{json .Manifest}}' >/dev/null 2>"$error_file"; then
        echo "immutable release tag already exists: $tag" >&2
        return 1
    fi
    if ! grep -Eiq 'not found|manifest unknown|manifest_unknown' "$error_file"; then
        echo "registry preflight failed without proving tag absence: $tag" >&2
        return 1
    fi
    /usr/bin/unlink "$error_file"
}

tag_must_be_absent "$runtime_version_tag" runtime-version
tag_must_be_absent "$runtime_commit_tag" runtime-commit
tag_must_be_absent "$migrator_version_tag" migrator-version
tag_must_be_absent "$migrator_commit_tag" migrator-commit

builder="dtx-vnet-release-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
printf '%s\n' "$builder" >"$active"
chmod 0600 "$active"
owns_builder=1
docker buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null

docker buildx build \
    --builder "$builder" \
    --platform linux/amd64 \
    --pull \
    --push \
    --file docker/release/Dockerfile \
    --tag "$runtime_version_tag" \
    --tag "$runtime_commit_tag" \
    --label "org.opencontainers.image.version=$version" \
    --label "org.opencontainers.image.revision=$source_commit" \
    --metadata-file "$state/runtime-metadata.json" \
    .
docker buildx imagetools inspect "$runtime_version_tag" --format '{{json .Manifest}}' >"$state/runtime-version-manifest.json"
docker buildx imagetools inspect "$runtime_commit_tag" --format '{{json .Manifest}}' >"$state/runtime-commit-manifest.json"
runtime_digest=$(python3 tools/production-release.py verified-digest \
    --metadata "$state/runtime-metadata.json" \
    --version-manifest "$state/runtime-version-manifest.json" \
    --commit-manifest "$state/runtime-commit-manifest.json")

docker buildx build \
    --builder "$builder" \
    --platform linux/amd64 \
    --pull \
    --push \
    --file docker/production/Dockerfile.migrate \
    --tag "$migrator_version_tag" \
    --tag "$migrator_commit_tag" \
    --label "org.opencontainers.image.version=$version" \
    --label "org.opencontainers.image.revision=$source_commit" \
    --metadata-file "$state/migrator-metadata.json" \
    .
docker buildx imagetools inspect "$migrator_version_tag" --format '{{json .Manifest}}' >"$state/migrator-version-manifest.json"
docker buildx imagetools inspect "$migrator_commit_tag" --format '{{json .Manifest}}' >"$state/migrator-commit-manifest.json"
python3 tools/production-release.py verified-digest \
    --metadata "$state/migrator-metadata.json" \
    --version-manifest "$state/migrator-version-manifest.json" \
    --commit-manifest "$state/migrator-commit-manifest.json" >/dev/null

# latest is a runtime discovery pointer only. Both immutable products have
# already been pushed and independently read back before this line can run.
docker buildx imagetools create \
    --builder "$builder" \
    --prefer-index=false \
    --tag "$latest_tag" \
    "$repository@$runtime_digest"
docker buildx imagetools inspect "$latest_tag" --format '{{json .Manifest}}' >"$state/latest-manifest.json"

python3 tools/production-release.py emit-facts \
    --input "$input" \
    --repository-root "$root" \
    --source-commit "$source_commit" \
    --runtime-metadata "$state/runtime-metadata.json" \
    --runtime-version-manifest "$state/runtime-version-manifest.json" \
    --runtime-commit-manifest "$state/runtime-commit-manifest.json" \
    --migrator-metadata "$state/migrator-metadata.json" \
    --migrator-version-manifest "$state/migrator-version-manifest.json" \
    --migrator-commit-manifest "$state/migrator-commit-manifest.json" \
    --latest-manifest "$state/latest-manifest.json" \
    --output "$state/release-facts.json"
echo "production release facts: $root/$state/release-facts.json"
