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

# Crash immediately after the pre-call phase: no candidate Compose command has
# run, and replay must execute the exact authenticated candidate once.
started_crash="$test_root/started-crash"
make_fixture "$started_crash"
if run_worker "$started_crash" DTX_TEST_FAULT=after-phase-candidate_started; then
    echo 'candidate_started crash injection unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$started_crash/state/phase") == candidate_started ]]
assert_count 0 'compose:candidate.env:up -d --remove-orphans' "$started_crash/events"
run_worker "$started_crash"
[[ $(cat "$started_crash/state/phase") == ready ]]
assert_count 1 'compose:candidate.env:up -d --remove-orphans' "$started_crash/events"

# A crash after Compose returns but before candidate_applied is durable leaves
# only pre-call evidence. Replay reconciles the exact candidate Compose again.
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
assert_count 2 'compose:candidate.env:up -d --remove-orphans' "$compose_crash/events"

# candidate_applied is the first durable proof that Compose returned success.
# Replay from it skips Compose and performs only readiness and promotion.
applied_crash="$test_root/applied-crash"
make_fixture "$applied_crash"
if run_worker "$applied_crash" DTX_TEST_FAULT=after-phase-candidate_applied; then
    echo 'candidate_applied crash injection unexpectedly succeeded' >&2
    exit 1
fi
[[ $(cat "$applied_crash/state/phase") == candidate_applied ]]
assert_count 1 'compose:candidate.env:up -d --remove-orphans' "$applied_crash/events"
run_worker "$applied_crash"
[[ $(cat "$applied_crash/state/phase") == ready ]]
assert_count 1 'compose:candidate.env:up -d --remove-orphans' "$applied_crash/events"

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

# An unrepaired retry performs one readiness attempt, remains nonterminal, and
# does not re-enter either candidate or prior long-service Compose.
if run_worker "$failed_recovery" DTX_TEST_PRIOR_FAIL=1 \
    2>"$failed_recovery/retry-error"; then
    echo 'unrepaired recovery retry unexpectedly succeeded' >&2
    exit 1
else
    retry_status=$?
fi
[[ "$retry_status" == 2 ]]
[[ $(cat "$failed_recovery/state/phase") == recovery_failed ]]
grep -qx 'status=recovery_failed' "$failed_recovery/state/receipt"
grep -q 'bounded recovery recheck' "$failed_recovery/retry-error"

# The same authenticated intent has one bounded readiness recheck per
# invocation after operator repair. It never re-enters candidate or prior
# long-service Compose, and publishes rolled_back only after readiness.
if run_worker "$failed_recovery" 2>"$failed_recovery/resume-error"; then
    echo 'repaired recovery unexpectedly reported update success' >&2
    exit 1
else
    resume_status=$?
fi
[[ "$resume_status" == 1 ]]
[[ $(cat "$failed_recovery/state/phase") == rolled_back ]]
grep -qx 'status=rolled_back' "$failed_recovery/state/receipt"
assert_count 1 'compose:candidate.env:up -d --remove-orphans' "$failed_recovery/events"
assert_count 1 'compose:prior.env:up -d --no-deps dtx-node realtime-gateway agent-control caddy' \
    "$failed_recovery/events"
assert_count 3 'ready:prior.env' "$failed_recovery/events"
grep -q 'repaired prior release is ready on the forward schema' "$failed_recovery/resume-error"

# Lock admission rejects unsafe files and serializes concurrent update critical
# sections under one root-owned, non-symlink flock.
unsafe_lock="$test_root/unsafe-lock"
mkdir -p "$unsafe_lock"
chmod 0700 "$unsafe_lock"
touch "$unsafe_lock/target"
ln -s "$unsafe_lock/target" "$unsafe_lock/update.lock"
if (
    # shellcheck source=scripts/production-stack/update.sh
    source "$root/scripts/production-stack/update.sh"
    update_lock="$unsafe_lock/update.lock"
    state_owner_uid=$(id -u)
    state_owner_gid=$(id -g)
    sync_path() { :; }
    acquire_update_lock
) 2>/dev/null; then
    echo 'symlink production update lock unexpectedly accepted' >&2
    exit 1
fi

unsafe_mode_lock="$test_root/unsafe-mode-lock"
mkdir -p "$unsafe_mode_lock"
chmod 0700 "$unsafe_mode_lock"
touch "$unsafe_mode_lock/update.lock"
chmod 0644 "$unsafe_mode_lock/update.lock"
if (
    # shellcheck source=scripts/production-stack/update.sh
    source "$root/scripts/production-stack/update.sh"
    update_lock="$unsafe_mode_lock/update.lock"
    state_owner_uid=$(id -u)
    state_owner_gid=$(id -g)
    sync_path() { :; }
    acquire_update_lock
) 2>/dev/null; then
    echo 'world-readable production update lock unexpectedly accepted' >&2
    exit 1
fi

lock_worker() (
    local fixture=$1 worker_id=$2
    # shellcheck source=scripts/production-stack/update.sh
    source "$root/scripts/production-stack/update.sh"
    update_lock="$fixture/update.lock"
    state_owner_uid=$(id -u)
    state_owner_gid=$(id -g)
    sync_path() { :; }
    run_locked_update() {
        printf 'enter:%s\n' "$worker_id" >>"$fixture/events"
        touch "$fixture/entered-$worker_id"
        if [[ "$worker_id" == first ]]; then
            while [[ ! -f "$fixture/release-first" ]]; do
                sleep 0.01
            done
        fi
        printf 'exit:%s\n' "$worker_id" >>"$fixture/events"
    }
    run_serialized_update
)

concurrent_lock="$test_root/concurrent-lock"
mkdir -p "$concurrent_lock"
chmod 0700 "$concurrent_lock"
lock_worker "$concurrent_lock" first &
first_pid=$!
for _attempt in $(seq 1 100); do
    [[ -f "$concurrent_lock/entered-first" ]] && break
    sleep 0.01
done
[[ -f "$concurrent_lock/entered-first" ]]
lock_worker "$concurrent_lock" second &
second_pid=$!
sleep 0.2
[[ ! -f "$concurrent_lock/entered-second" ]]
touch "$concurrent_lock/release-first"
wait "$first_pid"
wait "$second_pid"
diff -u <(printf '%s\n' enter:first exit:first enter:second exit:second) \
    "$concurrent_lock/events"

echo 'production update executable crash/replay/recovery checks passed'
