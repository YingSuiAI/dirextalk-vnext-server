#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
cargo_script="$script_dir/cargo.sh"
temporary_directory=""

usage() {
    printf 'Usage: bash scripts/verify.sh\n'
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
for required_command in cp dart diff git mkdir mktemp node rm; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf '%s is required for the repository verification gate.\n' \
            "$required_command" >&2
        exit 1
    fi
done

cleanup() {
    local exit_code=$?
    trap - EXIT
    if [[ -n "$temporary_directory" && -d "$temporary_directory" ]]; then
        rm -rf -- "$temporary_directory" || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT

cd -- "$repository_root"
"$cargo_script" run -p dtx-protocol --locked -- check-generated .
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/dtx-verify.XXXXXX")"
mkdir -p "$temporary_directory/generated-rust" "$temporary_directory/generated-dart"
cp -a crates/dtx-wire/src/generated/. "$temporary_directory/generated-rust/"
cp -a protocol/generated/dart/lib/src/. "$temporary_directory/generated-dart/"
"$cargo_script" run -p dtx-protocol --locked -- generate .
"$cargo_script" run -p dtx-protocol --locked -- check-generated .
if ! diff -qr "$temporary_directory/generated-rust" crates/dtx-wire/src/generated ||
    ! diff -qr "$temporary_directory/generated-dart" protocol/generated/dart/lib/src; then
    printf 'Protocol regeneration changed generated sources.\n' >&2
    exit 1
fi

"$cargo_script" run -p dtx-protocol --locked -- validate .
"$cargo_script" run -p dtx-protocol --locked -- check-breaking .

(
    cd -- "$repository_root/protocol/generated/dart"
    dart pub get --enforce-lockfile
    dart format --output=none --set-exit-if-changed .
    dart analyze --fatal-infos
    dart test
    dart compile js tool/web_smoke.dart -O2 \
        -o "$temporary_directory/dtx-protocol-web-smoke.js"
    node "$temporary_directory/dtx-protocol-web-smoke.js"
)

"$cargo_script" fmt --all -- --check
"$script_dir/check-testkit-boundary.sh"
"$cargo_script" clippy --workspace --locked --all-targets --all-features -- -D warnings
"$cargo_script" test --workspace --locked
"$script_dir/sqlx-prepare.sh"
"$cargo_script" deny check
"$cargo_script" audit
git diff --check
