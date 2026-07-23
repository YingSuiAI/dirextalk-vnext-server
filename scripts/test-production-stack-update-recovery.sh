#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

make_fixture() {
    local fixture=$1
    mkdir -p "$fixture"/{releases,state}
    printf '%s\n' \
        'DTX_RELEASE_VERSION=0.1.1' \
        'DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
        'DTX_MIGRATOR_IMAGE=dirextalk/vnet-server@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
        'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' >"$fixture/prior.env"
    printf '%s\n' \
        'DTX_RELEASE_VERSION=0.1.4' \
        'DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
        'DTX_MIGRATOR_IMAGE=dirextalk/vnet-server@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
        'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' >"$fixture/candidate.env"
    cp "$fixture/prior.env" "$fixture/current.env"
    cp "$fixture/candidate.env" "$fixture/production.env"
    printf 'services: {}\n' >"$fixture/compose.yml"
}

worker() {
    local fixture=$1
    # shellcheck source=scripts/production-stack/update.sh
    source "$root/scripts/production-stack/update.sh"
    state_root="$fixture/state"
    release_root="$fixture/releases"
    env_file="$fixture/production.env"
    compose_file="$fixture/compose.yml"
    current_env="$fixture/current.env"
    last_success="$fixture/last-success"
    image_validator="$fixture/validator"
    state_owner_uid=$(id -u)
    state_owner_gid=$(id -g)

    sync_path() { :; }
    ensure_state_root() { mkdir -p "$state_root"; chmod 0700 "$state_root"; }
    atomic_copy() {
        cp "$1" "$2.tmp"
        chmod "$3" "$2.tmp"
        mv "$2.tmp" "$2"
    }
    atomic_text() {
        printf '%s' "$3" >"$1.tmp"
        chmod "$2" "$1.tmp"
        mv "$1.tmp" "$1"
    }
    validate_images_for() {
        printf 'validate:%s\n' "$(basename -- "$1")" >>"$fixture/events"
    }
    compose_with() {
        local selected=$1
        shift
        validate_intent
        printf 'compose:%s:%s\n' "$(basename -- "$selected")" "$*" >>"$fixture/events"
        if [[ "$*" == 'up -d --remove-orphans' ]]; then
            touch "$fixture/candidate-started"
        elif [[ "$*" == 'up -d --no-deps dtx-node realtime-gateway agent-control caddy' ]]; then
            touch "$fixture/prior-started"
        fi
    }
    readiness_with() {
        local selected=$1
        printf 'ready:%s\n' "$(basename -- "$selected")" >>"$fixture/events"
        if [[ "$selected" == "$state_root/candidate.env" ]]; then
            [[ -f "$fixture/candidate-started" && ${DTX_TEST_CANDIDATE_FAIL:-0} == 0 ]]
        else
            [[ -f "$fixture/prior-started" && ${DTX_TEST_PRIOR_FAIL:-0} == 0 ]]
        fi
    }
    fault_point() {
        if [[ ${DTX_TEST_FAULT:-} == "$1" && ! -f "$fixture/fault-fired" ]]; then
            touch "$fixture/fault-fired"
            return 91
        fi
    }

    if [[ ! -f "$state_root/intent" ]]; then
        write_intent 0.1.1 0.1.4 || return $?
    fi
    run_update_state_machine
}

run_worker() {
    local fixture=$1
    shift
    (
        export DTX_TEST_FAULT= DTX_TEST_CANDIDATE_FAIL=0 DTX_TEST_PRIOR_FAIL=0
        for setting in "$@"; do
            export "$setting"
        done
        worker "$fixture"
    )
}

assert_count() {
    local expected=$1 pattern=$2 file=$3 actual
    actual=$(grep -cF "$pattern" "$file" || true)
    [[ "$actual" == "$expected" ]] || {
        echo "expected $expected occurrences of '$pattern', got $actual" >&2
        exit 1
    }
}

test_root=$(mktemp -d)
trap 'find "$test_root" -type f -delete; find "$test_root" -depth -type d -empty -delete' EXIT

# Crash after candidate migration/start but before readiness: replay probes the
# existing candidate and never reruns compose up/migrations.
compose_crash="$test_root/compose-crash"
make_fixture "$compose_crash"
if run_worker "$compose_crash" DTX_TEST_FAULT=after-candidate-compose; then
    echo 'compose crash injection unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$compose_crash/state/phase") == candidate_started ]]
run_worker "$compose_crash"
[[ $(cat "$compose_crash/state/phase") == ready ]]
cmp "$compose_crash/production.env" "$compose_crash/candidate.env"
cmp "$compose_crash/current.env" "$compose_crash/candidate.env"
assert_count 1 'compose:candidate.env:up -d --remove-orphans' "$compose_crash/events"

# Root-state tampering is detected by the authenticated intent before any
# Docker command is issued.
tampered="$test_root/tampered"
make_fixture "$tampered"
if run_worker "$tampered" DTX_TEST_FAULT=after-phase-intent; then
    echo 'intent crash injection unexpectedly succeeded' >&2
    exit 1
fi
printf '# tampered\n' >>"$tampered/state/candidate.env"
if run_worker "$tampered"; then
    echo 'tampered candidate intent unexpectedly succeeded' >&2
    exit 1
fi
[[ ! -f "$tampered/events" ]]

# Crash after readiness has durably reached candidate_ready: replay performs
# only the two desired-active promotions, with no compose or probe repetition.
ready_crash="$test_root/ready-crash"
make_fixture "$ready_crash"
if run_worker "$ready_crash" DTX_TEST_FAULT=after-phase-candidate_ready; then
    echo 'candidate_ready crash injection unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$ready_crash/state/phase") == candidate_ready ]]
cmp "$ready_crash/production.env" "$ready_crash/prior.env"
cmp "$ready_crash/current.env" "$ready_crash/prior.env"
before=$(wc -l <"$ready_crash/events")
run_worker "$ready_crash"
after=$(wc -l <"$ready_crash/events")
[[ "$before" == "$after" ]]
[[ $(cat "$ready_crash/state/phase") == ready ]]

# Each promotion boundary converges independently after a crash.
for boundary in production_env_promoted active_promoted; do
    fixture="$test_root/$boundary"
    make_fixture "$fixture"
    if run_worker "$fixture" "DTX_TEST_FAULT=after-phase-$boundary"; then
        echo "$boundary crash injection unexpectedly succeeded" >&2
        exit 1
    fi
    side_effects=$(wc -l <"$fixture/events")
    run_worker "$fixture"
    [[ $(wc -l <"$fixture/events") == "$side_effects" ]]
    [[ $(cat "$fixture/state/phase") == ready ]]
    cmp "$fixture/production.env" "$fixture/candidate.env"
    cmp "$fixture/current.env" "$fixture/candidate.env"
done

# Candidate failure restores canonical desired-active state first, then proves
# retained prior service readiness before emitting rolled_back.
rollback="$test_root/rollback"
make_fixture "$rollback"
if run_worker "$rollback" DTX_TEST_CANDIDATE_FAIL=1 2>"$rollback/error"; then
    echo 'candidate failure unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$rollback/state/phase") == rolled_back ]]
cmp "$rollback/production.env" "$rollback/prior.env"
cmp "$rollback/current.env" "$rollback/prior.env"
grep -qx 'status=rolled_back' "$rollback/state/receipt"
assert_count 1 'compose:prior.env:up -d --no-deps dtx-node realtime-gateway agent-control caddy' "$rollback/events"
assert_count 1 'ready:prior.env' "$rollback/events"
grep -q 'compatible prior release restored on the forward schema' "$rollback/error"

# Failed prior readiness is explicitly nonterminal and cannot publish success.
failed_recovery="$test_root/failed-recovery"
make_fixture "$failed_recovery"
if run_worker "$failed_recovery" DTX_TEST_CANDIDATE_FAIL=1 DTX_TEST_PRIOR_FAIL=1 \
    2>"$failed_recovery/error"; then
    echo 'failed prior recovery unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$failed_recovery/state/phase") == recovery_failed ]]
grep -qx 'status=recovery_failed' "$failed_recovery/state/receipt"
! grep -qx 'status=rolled_back' "$failed_recovery/state/receipt"
grep -q 'retained prior services did not become ready' "$failed_recovery/error"

echo 'production update executable crash/replay/recovery checks passed'
