#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
cargo_script="$script_dir/cargo.sh"

usage() {
    printf 'Usage: bash scripts/check-testkit-boundary.sh\n'
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
if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 is required to inspect Cargo metadata.\n' >&2
    exit 1
fi

cd -- "$repository_root"
"$cargo_script" metadata --format-version 1 --no-deps |
    python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
violations = []
for package in metadata["packages"]:
    if package["name"] == "dtx-testkit":
        continue
    for dependency in package["dependencies"]:
        if dependency["name"] == "dtx-testkit" and dependency.get("kind") != "dev":
            violations.append(
                "{}:{}".format(
                    package["name"], dependency.get("kind") or "normal"
                )
            )

if violations:
    print(
        "dtx-testkit must be dev-only; invalid dependencies: "
        + ", ".join(violations),
        file=sys.stderr,
    )
    raise SystemExit(1)
'
