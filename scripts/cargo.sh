#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
toolchain_file="$repository_root/rust-toolchain.toml"

usage() {
    printf 'Usage: bash scripts/cargo.sh <cargo-command> [arguments...]\n'
}

if (( $# == 0 )); then
    usage >&2
    exit 2
fi
if [[ ! -r "$toolchain_file" ]]; then
    printf 'Pinned Rust toolchain file is not readable: %s\n' "$toolchain_file" >&2
    exit 1
fi
if ! command -v rustup >/dev/null 2>&1; then
    printf 'rustup is required to run the pinned repository toolchain.\n' >&2
    exit 1
fi

pinned_toolchain="$(
    sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$toolchain_file"
)"
if [[ -z "$pinned_toolchain" || "$pinned_toolchain" == *$'\n'* ]]; then
    printf 'Unable to resolve one pinned Rust channel from %s\n' "$toolchain_file" >&2
    exit 1
fi

installed_toolchains="$(rustup toolchain list)"
escaped_toolchain="${pinned_toolchain//./\\.}"
if ! grep -Eq "^${escaped_toolchain}(-|[[:space:]])" <<<"$installed_toolchains"; then
    printf 'Rust toolchain %s is not installed.\n' "$pinned_toolchain" >&2
    exit 1
fi

exec rustup run "$pinned_toolchain" cargo "$@"
