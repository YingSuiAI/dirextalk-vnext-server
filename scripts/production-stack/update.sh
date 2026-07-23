#!/usr/bin/env bash
set -euo pipefail

project=dirextalk-vnext-production
env_file=/etc/dirextalk/vnext/config/production.env
compose_file=/etc/dirextalk/vnext/config/production-compose.yml
state_root=/var/lib/dirextalk/vnext/update-intent
release_root=/var/lib/dirextalk/vnext/releases
current_env=/var/lib/dirextalk/vnext/current.env
last_success=/var/lib/dirextalk/vnext/last-successful-operation
image_validator=/usr/local/lib/dirextalk/validate-production-images.py
state_owner_uid=0
state_owner_gid=0

sync_path() {
    sync -f "$1"
}

atomic_copy() {
    local source=$1 destination=$2 mode=$3 temporary
    temporary="${destination}.tmp.$$"
    install -o root -g root -m "$mode" "$source" "$temporary"
    sync_path "$temporary"
    mv -f "$temporary" "$destination"
    sync_path "$(dirname -- "$destination")"
}

atomic_text() {
    local destination=$1 mode=$2 value=$3 temporary
    temporary="${destination}.tmp.$$"
    printf '%s' "$value" >"$temporary"
    chown root:root "$temporary"
    chmod "$mode" "$temporary"
    sync_path "$temporary"
    mv -f "$temporary" "$destination"
    sync_path "$(dirname -- "$destination")"
}

phase() {
    secure_state_file "$state_root/phase" || return 1
    cat "$state_root/phase"
}

write_phase() {
    atomic_text "$state_root/phase" 0600 "$1"$'\n'
    fault_point "after-phase-$1" || return $?
}

intent_value() {
    local key=$1
    sed -n "s/^${key}=//p" "$state_root/intent"
}

secure_state_file() {
    local path=$1
    [[ -f "$path" && ! -L "$path" && $(stat -c '%a:%u:%g:%h' "$path") == \
        "600:$state_owner_uid:$state_owner_gid:1" ]]
}

validate_intent() {
    local body expected actual lines
    [[ -d "$state_root" && ! -L "$state_root" && $(stat -c '%a:%u:%g' "$state_root") == \
        "700:$state_owner_uid:$state_owner_gid" ]] || {
        echo 'durable update state root is unsafe' >&2
        return 1
    }
    secure_state_file "$state_root/intent" || {
        echo 'durable update intent is missing' >&2
        return 1
    }
    lines=$(wc -l <"$state_root/intent")
    [[ "$lines" == 9 ]] || { echo 'durable update intent shape is invalid' >&2; return 1; }
    for key in schema prior_sha256 candidate_sha256 compose_sha256 previous_version candidate_version compatibility material_sha256 intent_sha256; do
        [[ $(grep -c "^${key}=" "$state_root/intent") == 1 ]] || {
            echo "durable update intent field is invalid: $key" >&2
            return 1
        }
    done
    [[ $(intent_value schema) == dirextalk.vnext-production-update-intent.v1 ]] || return 1
    [[ $(intent_value compatibility) == forward-schema-compatible-v1 ]] || return 1
    body=$(sed '$d' "$state_root/intent")
    expected=$(intent_value intent_sha256)
    actual=$(printf '%s\n' "$body" | sha256sum | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || { echo 'durable update intent authentication failed' >&2; return 1; }
    for retained in prior.env candidate.env compose.yml; do
        secure_state_file "$state_root/$retained" || return 1
    done
    [[ $(sha256sum "$state_root/prior.env" | awk '{print $1}') == "$(intent_value prior_sha256)" ]] || return 1
    [[ $(sha256sum "$state_root/candidate.env" | awk '{print $1}') == "$(intent_value candidate_sha256)" ]] || return 1
    [[ $(sha256sum "$state_root/compose.yml" | awk '{print $1}') == "$(intent_value compose_sha256)" ]] || return 1
}

write_intent() {
    local previous_version=$1 candidate_version=$2 body hash material
    ensure_state_root
    atomic_copy "$current_env" "$state_root/prior.env" 0600
    atomic_copy "$env_file" "$state_root/candidate.env" 0600
    atomic_copy "$compose_file" "$state_root/compose.yml" 0600
    material=$(sha256sum "$state_root/prior.env" "$state_root/candidate.env" "$state_root/compose.yml" | sha256sum | awk '{print $1}')
    body=$(
        printf '%s\n' \
            'schema=dirextalk.vnext-production-update-intent.v1' \
            "prior_sha256=$(sha256sum "$state_root/prior.env" | awk '{print $1}')" \
            "candidate_sha256=$(sha256sum "$state_root/candidate.env" | awk '{print $1}')" \
            "compose_sha256=$(sha256sum "$state_root/compose.yml" | awk '{print $1}')" \
            "previous_version=$previous_version" \
            "candidate_version=$candidate_version" \
            'compatibility=forward-schema-compatible-v1' \
            "material_sha256=$material"
    )
    hash=$(printf '%s\n' "$body" | sha256sum | awk '{print $1}')
    atomic_text "$state_root/intent" 0600 "$body"$'\n'"intent_sha256=$hash"$'\n'
    write_phase intent || return $?
}

ensure_state_root() {
    install -d -o root -g root -m 0700 "$state_root"
    sync_path "$(dirname -- "$state_root")"
}

validate_images_for() {
    python3 "$image_validator" "$1"
}

compose_with() {
    local selected_env=$1
    shift
    docker compose --project-name "$project" --env-file "$selected_env" -f "$state_root/compose.yml" "$@"
}

readiness_with() {
    local selected_env=$1
    validate_images_for "$selected_env"
    compose_with "$selected_env" config >/dev/null
    compose_with "$selected_env" up --force-recreate --no-deps --abort-on-container-failure \
        node-ready realtime-ready agent-control-ready
}

fault_point() {
    :
}

write_record_receipt() {
    local status=$1
    atomic_text "$state_root/receipt" 0600 "status=$status"$'\n'
}

promote_candidate() {
    case "$(phase)" in
        candidate_ready)
            atomic_copy "$state_root/compose.yml" "$compose_file" 0644
            write_phase candidate_config_promoted || return $?
            ;&
        candidate_config_promoted)
            atomic_copy "$state_root/candidate.env" "$env_file" 0644
            write_phase production_env_promoted || return $?
            ;&
        production_env_promoted)
            atomic_copy "$state_root/candidate.env" "$current_env" 0600
            write_phase active_promoted || return $?
            ;&
        active_promoted)
            write_record_receipt ready
            atomic_text "$last_success" 0600 'status=ready'$'\n'
            write_phase ready || return $?
            ;&
        ready)
            return 0
            ;;
        *)
            echo 'candidate promotion requested from an invalid phase' >&2
            return 1
            ;;
    esac
}

finish_rollback() {
    atomic_copy "$state_root/prior.env" "$current_env" 0600
    write_record_receipt rolled_back
    write_phase rolled_back || return $?
}

recover_prior_code() {
    write_phase rollback_started || return $?
    # Desired-active configuration is durably restored before prior containers
    # are reconciled. Schema remains forward-only and named volumes are untouched.
    atomic_copy "$state_root/prior.env" "$env_file" 0644
    atomic_copy "$state_root/prior.env" "$current_env" 0600
    if ! validate_images_for "$state_root/prior.env" \
        || ! compose_with "$state_root/prior.env" up -d --no-deps \
            dtx-node realtime-gateway agent-control caddy \
        || ! readiness_with "$state_root/prior.env"; then
        write_record_receipt recovery_failed
        write_phase recovery_failed || return $?
        echo 'candidate failed and retained prior services did not become ready' >&2
        return 2
    fi
    write_phase rollback_ready || return $?
    finish_rollback
    echo 'candidate readiness failed; compatible prior release restored on the forward schema' >&2
    return 1
}

run_update_state_machine() {
    local current_phase
    validate_intent || return $?
    current_phase=$(phase)
    case "$current_phase" in
        ready)
            return 0
            ;;
        rolled_back)
            return 1
            ;;
        recovery_failed)
            echo 'prior-service recovery is nonterminal and requires operator repair' >&2
            return 2
            ;;
        candidate_ready|candidate_config_promoted|production_env_promoted|active_promoted)
            promote_candidate || return $?
            return 0
            ;;
        rollback_ready)
            finish_rollback || return $?
            return 1
            ;;
        rollback_started)
            # Reconciliation is idempotent; after an interrupted rollback it is
            # safer to reconverge the fixed prior services than claim readiness.
            recover_prior_code
            return $?
            ;;
        intent)
            # Keep canonical desired-active state on the prior release until the
            # candidate has passed every readiness probe.
            atomic_copy "$state_root/prior.env" "$env_file" 0644
            validate_images_for "$state_root/candidate.env"
            compose_with "$state_root/candidate.env" pull --quiet
            write_phase pulled || return $?
            ;&
        pulled)
            write_phase candidate_started || return $?
            if ! compose_with "$state_root/candidate.env" up -d --remove-orphans; then
                recover_prior_code
                return $?
            fi
            fault_point after-candidate-compose || return $?
            ;&
        candidate_started)
            # A replay never reruns compose up/migrations. It only probes the
            # already-started candidate and converges to promotion or rollback.
            if ! readiness_with "$state_root/candidate.env"; then
                recover_prior_code
                return $?
            fi
            fault_point after-candidate-readiness || return $?
            write_phase candidate_ready || return $?
            promote_candidate || return $?
            return 0
            ;;
        *)
            echo "unknown durable update phase: $current_phase" >&2
            return 2
            ;;
    esac
}

archive_terminal_intent_for_new_candidate() {
    local current_phase active_digest candidate_digest prior_digest archive
    current_phase=$(phase || true)
    case "$current_phase" in
        ready)
            active_digest=$(sha256sum "$env_file" | awk '{print $1}')
            candidate_digest=$(intent_value candidate_sha256)
            [[ "$active_digest" != "$candidate_digest" ]] || return 0
            ;;&
        rolled_back)
            active_digest=$(sha256sum "$env_file" | awk '{print $1}')
            prior_digest=$(intent_value prior_sha256)
            [[ "$active_digest" != "$prior_digest" ]] || return 0
            ;;&
        ready|rolled_back)
            archive="$release_root/update.$(intent_value intent_sha256)"
            [[ ! -e "$archive" ]] || { echo 'completed update archive already exists' >&2; return 1; }
            mv "$state_root" "$archive"
            sync_path "$release_root"
            ;;
    esac
}

main() {
    if (( $# != 0 )); then
        echo 'usage: update.sh' >&2
        return 2
    fi
    [[ ${EUID} -eq 0 ]] || { echo 'update requires root' >&2; return 1; }
    command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; return 1; }
    [[ -f "$env_file" && ! -L "$env_file" && $(stat -c '%a' "$env_file") == 644 ]] || {
        echo 'invalid production env file' >&2
        return 1
    }
    scripts/production-stack/validate-files.sh
    scripts/production-stack/validate-images.sh
    [[ -f "$current_env" && ! -L "$current_env" && $(stat -c '%a:%u:%g' "$current_env") == 600:0:0 ]] || {
        echo 'retained prior release is required' >&2
        return 1
    }
    if [[ -d "$state_root" ]]; then
        validate_intent || return $?
    fi
    archive_terminal_intent_for_new_candidate
    if [[ ! -d "$state_root" ]]; then
        local previous_version candidate_version
        validate_images_for "$current_env"
        grep -qx 'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' "$current_env" || {
            echo 'prior release has no compatible rollback contract' >&2
            return 1
        }
        grep -qx 'DTX_ROLLBACK_COMPATIBILITY=forward-schema-compatible-v1' "$env_file" || {
            echo 'candidate has no compatible rollback contract' >&2
            return 1
        }
        previous_version=$(sed -n 's/^DTX_RELEASE_VERSION=//p' "$current_env")
        candidate_version=$(sed -n 's/^DTX_RELEASE_VERSION=//p' "$env_file")
        [[ "$previous_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$candidate_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
            echo 'production release versions must be canonical SemVer' >&2
            return 1
        }
        if [[ "$candidate_version" != "$previous_version" ]] && \
            [[ "$previous_version" != 0.1.1 || "$candidate_version" != 0.1.4 ]]; then
            echo 'production cross-version admission is limited to 0.1.1 -> 0.1.4' >&2
            return 1
        fi
        write_intent "$previous_version" "$candidate_version" || return $?
    fi
    local result
    if run_update_state_machine; then
        result=0
    else
        result=$?
    fi
    if (( result == 0 )); then
        scripts/production-stack/cleanup-cache.sh
    fi
    return "$result"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
