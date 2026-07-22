#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: cleanup-production-release.sh' >&2
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
state="$root/target/production-release/active-builder"
if [[ ! -e "$state" && ! -L "$state" ]]; then
    exit 0
fi
[[ -f "$state" && ! -L "$state" ]] || { echo 'release builder state is not a regular file' >&2; exit 1; }
[[ $(stat -c '%a:%u' "$state") == "600:$(id -u)" ]] || { echo 'release builder state owner or mode is invalid' >&2; exit 1; }
[[ $(wc -l <"$state") -eq 1 ]] || { echo 'release builder state must contain exactly one line' >&2; exit 1; }
IFS= read -r builder <"$state"
[[ $builder =~ ^dtx-vnet-release-[0-9a-f]{12}$ ]] || { echo 'release builder name is invalid' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'docker is required for release cleanup' >&2; exit 1; }
docker info >/dev/null
docker buildx version >/dev/null
if docker buildx ls --format '{{.Name}}' | grep -Fxq -- "$builder"; then
    docker buildx rm --force "$builder"
fi
/usr/bin/unlink "$state"
