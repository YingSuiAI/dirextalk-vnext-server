#!/usr/bin/env bash
set -euo pipefail

evidence=/var/lib/dirextalk/vnext/last-successful-operation
legacy_parent=/opt/dirextalk-vnext
legacy_build=/opt/dirextalk-vnext/build
cleanup_owner_uid=0
cleanup_owner_gid=0
cleanup_timeout_seconds=120

cleanup_legacy_build() {
    local parent_mode parent_uid parent_gid parent_device
    local build_mode build_uid build_gid build_device mounted unsafe
    if [[ ! -e "$legacy_build" && ! -L "$legacy_build" ]]; then
        return 0
    fi
    [[ -d "$legacy_parent" && ! -L "$legacy_parent" && \
        $(readlink -f -- "$legacy_parent") == "$legacy_parent" ]] || {
        echo 'legacy build parent is unsafe' >&2
        return 1
    }
    IFS=: read -r parent_mode parent_uid parent_gid parent_device < <(
        stat -c '%a:%u:%g:%d' "$legacy_parent"
    )
    [[ "$parent_uid" == "$cleanup_owner_uid" && "$parent_gid" == "$cleanup_owner_gid" ]] || {
        echo 'legacy build parent ownership is unsafe' >&2
        return 1
    }
    (( (8#$parent_mode & 8#022) == 0 )) || {
        echo 'legacy build parent permissions are unsafe' >&2
        return 1
    }
    [[ -d "$legacy_build" && ! -L "$legacy_build" && \
        $(readlink -f -- "$legacy_build") == "$legacy_build" ]] || {
        echo 'legacy build root is unsafe' >&2
        return 1
    }
    IFS=: read -r build_mode build_uid build_gid build_device < <(
        stat -c '%a:%u:%g:%d' "$legacy_build"
    )
    [[ "$build_uid" == "$cleanup_owner_uid" && "$build_gid" == "$cleanup_owner_gid" \
        && "$build_device" == "$parent_device" ]] || {
        echo 'legacy build ownership or device is unsafe' >&2
        return 1
    }
    (( (8#$build_mode & 8#022) == 0 )) || {
        echo 'legacy build root permissions are unsafe' >&2
        return 1
    }
    ! mountpoint -q -- "$legacy_build" || {
        echo 'legacy build root is a mount point' >&2
        return 1
    }
    if ! mounted=$(timeout --signal=TERM --kill-after=10s "$cleanup_timeout_seconds" \
        find -P "$legacy_build" -xdev -type d \
            -exec mountpoint -q -- '{}' \; -printf x -quit); then
        echo 'legacy build mount-boundary validation failed' >&2
        return 1
    fi
    [[ -z "$mounted" ]] || {
        echo 'legacy build contains a mount point' >&2
        return 1
    }
    if ! unsafe=$(timeout --signal=TERM --kill-after=10s "$cleanup_timeout_seconds" \
        find -P "$legacy_build" -xdev \
            \( ! -uid "$cleanup_owner_uid" -o ! -gid "$cleanup_owner_gid" \
                -o \( ! -type f -a ! -type d \) \
                -o \( -type d -perm /022 \) \
                -o \( -type f -links +1 \) \) \
            -printf x -quit); then
        echo 'legacy build ownership/type validation failed' >&2
        return 1
    fi
    [[ -z "$unsafe" ]] || {
        echo 'legacy build tree is unsafe' >&2
        return 1
    }
    timeout --signal=TERM --kill-after=10s "$cleanup_timeout_seconds" \
        find -P "$legacy_build" -xdev -depth -delete
    [[ ! -e "$legacy_build" && ! -L "$legacy_build" ]] || {
        echo 'legacy build cleanup was incomplete' >&2
        return 1
    }
    sync -f "$legacy_parent"
}

main() {
    if (( $# != 0 )); then
        echo 'usage: cleanup-cache.sh' >&2
        return 2
    fi
    [[ ${EUID} -eq 0 ]] || { echo 'cleanup requires root' >&2; return 1; }
    command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; return 1; }
    command -v find >/dev/null 2>&1 || { echo 'find is required' >&2; return 1; }
    command -v mountpoint >/dev/null 2>&1 || { echo 'mountpoint is required' >&2; return 1; }
    command -v readlink >/dev/null 2>&1 || { echo 'readlink is required' >&2; return 1; }
    command -v timeout >/dev/null 2>&1 || { echo 'timeout is required' >&2; return 1; }
    [[ -f "$evidence" && ! -L "$evidence" && \
        $(stat -c '%a:%u:%g' "$evidence") == 600:0:0 ]] || {
        echo 'retained success evidence is required before cleanup' >&2
        return 1
    }
    grep -qx 'status=ready' "$evidence" || {
        echo 'success evidence is incomplete' >&2
        return 1
    }
    # /opt/dirextalk-vnext/build is a retired pre-bundle compiler surface.
    # Current and recovery artifacts live only under releases/, so this exact
    # root-owned, same-device tree is safe to remove after mount/type checks.
    cleanup_legacy_build || return $?
    # Current production binaries are built inside BuildKit. This remaining
    # fixed allowlist is time- and storage-bounded and never names volumes,
    # containers, logs, active images, configuration, TLS, or secret paths.
    timeout --signal=TERM --kill-after=10s "$cleanup_timeout_seconds" \
        docker image prune --force --filter dangling=true --filter until=24h >/dev/null
    timeout --signal=TERM --kill-after=10s "$cleanup_timeout_seconds" \
        docker builder prune --force \
            --reserved-space 536870912 --max-used-space 1073741824 >/dev/null
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
