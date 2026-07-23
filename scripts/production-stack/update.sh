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
update_lock=/var/lib/dirextalk/vnext/update.lock
update_lock_fd=
state_owner_uid=0
state_owner_gid=0
max_update_archives=16
retained_update_archives=8
max_update_archive_bytes=$((1024 * 1024))
max_update_archive_total_bytes=$((32 * 1024 * 1024))
min_update_free_bytes=$((64 * 1024 * 1024))

sync_path() {
    sync -f "$1"
}

atomic_copy() {
    local source=$1 destination=$2 mode=$3 temporary
    temporary="${destination}.tmp.$$"
    install -o root -g root -m "$mode" "$source" "$temporary" || return $?
    sync_path "$temporary" || return $?
    mv -f "$temporary" "$destination" || return $?
    sync_path "$(dirname -- "$destination")" || return $?
}

atomic_text() {
    local destination=$1 mode=$2 value=$3 temporary
    temporary="${destination}.tmp.$$"
    printf '%s' "$value" >"$temporary" || return $?
    chown root:root "$temporary" || return $?
    chmod "$mode" "$temporary" || return $?
    sync_path "$temporary" || return $?
    mv -f "$temporary" "$destination" || return $?
    sync_path "$(dirname -- "$destination")" || return $?
}

phase() {
    secure_state_file "$state_root/phase" || return 1
    cat "$state_root/phase"
}

write_phase() {
    atomic_text "$state_root/phase" 0600 "$1"$'\n' || return $?
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

secure_update_lock_parent() {
    local parent canonical mode owner_uid owner_gid
    parent=$(dirname -- "$update_lock")
    [[ -d "$parent" && ! -L "$parent" ]] || return 1
    canonical=$(readlink -f -- "$parent") || return 1
    [[ "$canonical" == "$parent" ]] || return 1
    IFS=: read -r mode owner_uid owner_gid < <(stat -c '%a:%u:%g' "$parent")
    [[ "$owner_uid" == "$state_owner_uid" && "$owner_gid" == "$state_owner_gid" ]] || return 1
    (( (8#$mode & 0022) == 0 ))
}

secure_update_lock_file() {
    [[ -f "$update_lock" && ! -L "$update_lock" && \
        $(stat -c '%a:%u:%g:%h' "$update_lock") == \
        "600:$state_owner_uid:$state_owner_gid:1" ]]
}

close_update_lock_fd() {
    if [[ -n ${update_lock_fd:-} ]]; then
        exec {update_lock_fd}>&- || return $?
        update_lock_fd=
    fi
}

acquire_update_lock() {
    local parent path_identity descriptor_identity descriptor_metadata
    parent=$(dirname -- "$update_lock")
    secure_update_lock_parent || {
        echo 'production update lock parent is unsafe' >&2
        return 1
    }
    if [[ ! -e "$update_lock" && ! -L "$update_lock" ]]; then
        if (umask 077; set -o noclobber; : >"$update_lock") 2>/dev/null; then
            chown "$state_owner_uid:$state_owner_gid" "$update_lock" || return $?
            chmod 0600 "$update_lock" || return $?
            sync_path "$update_lock" || return $?
            sync_path "$parent" || return $?
        elif [[ ! -e "$update_lock" && ! -L "$update_lock" ]]; then
            echo 'production update lock could not be created' >&2
            return 1
        fi
    fi
    secure_update_lock_file || {
        echo 'production update lock is unsafe' >&2
        return 1
    }
    exec {update_lock_fd}<>"$update_lock" || return $?
    path_identity=$(stat -c '%d:%i' "$update_lock") || {
        close_update_lock_fd
        return 1
    }
    descriptor_identity=$(stat -Lc '%d:%i' "/proc/self/fd/$update_lock_fd") || {
        close_update_lock_fd
        return 1
    }
    descriptor_metadata=$(stat -Lc '%a:%u:%g:%h' "/proc/self/fd/$update_lock_fd") || {
        close_update_lock_fd
        return 1
    }
    if [[ "$path_identity" != "$descriptor_identity" || \
        "$descriptor_metadata" != "600:$state_owner_uid:$state_owner_gid:1" ]]; then
        close_update_lock_fd
        echo 'production update lock changed while opening' >&2
        return 1
    fi
    flock -x "$update_lock_fd" || {
        close_update_lock_fd
        return 1
    }
    if ! secure_update_lock_file \
        || [[ $(stat -c '%d:%i' "$update_lock") != "$descriptor_identity" ]]; then
        close_update_lock_fd
        echo 'production update lock changed while waiting' >&2
        return 1
    fi
}

validate_intent() {
    local body expected actual lines schema
    local -a keys
    [[ -d "$state_root" && ! -L "$state_root" && $(stat -c '%a:%u:%g' "$state_root") == \
        "700:$state_owner_uid:$state_owner_gid" ]] || {
        echo 'durable update state root is unsafe' >&2
        return 1
    }
    secure_state_file "$state_root/intent" || {
        echo 'durable update intent is missing' >&2
        return 1
    }
    schema=$(intent_value schema)
    case "$schema" in
        dirextalk.vnext-production-update-intent.v1)
            lines=9
            keys=(schema prior_sha256 candidate_sha256 compose_sha256 previous_version
                candidate_version compatibility material_sha256 intent_sha256)
            ;;
        dirextalk.vnext-production-update-intent.v2)
            lines=10
            keys=(schema attempt_id prior_sha256 candidate_sha256 compose_sha256 previous_version
                candidate_version compatibility material_sha256 intent_sha256)
            [[ $(intent_value attempt_id) =~ ^[0-9a-f]{32}$ ]] || {
                echo 'durable update attempt identity is invalid' >&2
                return 1
            }
            ;;
        *)
            echo 'durable update intent schema is invalid' >&2
            return 1
            ;;
    esac
    [[ $(wc -l <"$state_root/intent") == "$lines" ]] || {
        echo 'durable update intent shape is invalid' >&2
        return 1
    }
    for key in "${keys[@]}"; do
        [[ $(grep -c "^${key}=" "$state_root/intent") == 1 ]] || {
            echo "durable update intent field is invalid: $key" >&2
            return 1
        }
    done
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

new_attempt_id() {
    local attempt
    IFS= read -r attempt </proc/sys/kernel/random/uuid || return $?
    attempt=${attempt//-/}
    [[ "$attempt" =~ ^[0-9a-f]{32}$ ]] || {
        echo 'kernel did not provide a valid update attempt identity' >&2
        return 1
    }
    printf '%s\n' "$attempt"
}

archive_attempt_id() {
    local body expected actual
    secure_state_file "$state_root/archive-attempt" || return 1
    [[ $(wc -l <"$state_root/archive-attempt") == 4 ]] || return 1
    for key in schema attempt_id intent_sha256 archive_identity_sha256; do
        [[ $(grep -c "^${key}=" "$state_root/archive-attempt") == 1 ]] || return 1
    done
    [[ $(sed -n 's/^schema=//p' "$state_root/archive-attempt") == \
        dirextalk.vnext-production-update-archive-identity.v1 ]] || return 1
    [[ $(sed -n 's/^attempt_id=//p' "$state_root/archive-attempt") =~ ^[0-9a-f]{32}$ ]] || return 1
    [[ $(sed -n 's/^intent_sha256=//p' "$state_root/archive-attempt") == \
        "$(intent_value intent_sha256)" ]] || return 1
    body=$(sed '$d' "$state_root/archive-attempt")
    expected=$(sed -n 's/^archive_identity_sha256=//p' "$state_root/archive-attempt")
    actual=$(printf '%s\n' "$body" | sha256sum | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || return 1
    sed -n 's/^attempt_id=//p' "$state_root/archive-attempt"
}

ensure_archive_attempt_identity() {
    local attempt_id body hash
    if [[ -e "$state_root/archive-attempt" || -L "$state_root/archive-attempt" ]]; then
        archive_attempt_id >/dev/null
        return $?
    fi
    attempt_id=$(new_attempt_id) || return $?
    body=$(
        printf '%s\n' \
            'schema=dirextalk.vnext-production-update-archive-identity.v1' \
            "attempt_id=$attempt_id" \
            "intent_sha256=$(intent_value intent_sha256)"
    ) || return $?
    hash=$(printf '%s\n' "$body" | sha256sum | awk '{print $1}') || return $?
    atomic_text "$state_root/archive-attempt" 0600 \
        "$body"$'\n'"archive_identity_sha256=$hash"$'\n' || return $?
    archive_attempt_id >/dev/null
}

write_intent() {
    local previous_version=$1 candidate_version=$2 body hash material attempt_id
    attempt_id=$(new_attempt_id) || return $?
    ensure_state_root || return $?
    atomic_copy "$current_env" "$state_root/prior.env" 0600 || return $?
    atomic_copy "$env_file" "$state_root/candidate.env" 0600 || return $?
    atomic_copy "$compose_file" "$state_root/compose.yml" 0600 || return $?
    material=$(sha256sum "$state_root/prior.env" "$state_root/candidate.env" "$state_root/compose.yml" | sha256sum | awk '{print $1}') || return $?
    body=$(
        printf '%s\n' \
            'schema=dirextalk.vnext-production-update-intent.v2' \
            "attempt_id=$attempt_id" \
            "prior_sha256=$(sha256sum "$state_root/prior.env" | awk '{print $1}')" \
            "candidate_sha256=$(sha256sum "$state_root/candidate.env" | awk '{print $1}')" \
            "compose_sha256=$(sha256sum "$state_root/compose.yml" | awk '{print $1}')" \
            "previous_version=$previous_version" \
            "candidate_version=$candidate_version" \
            'compatibility=forward-schema-compatible-v1' \
            "material_sha256=$material"
    ) || return $?
    hash=$(printf '%s\n' "$body" | sha256sum | awk '{print $1}') || return $?
    atomic_text "$state_root/intent" 0600 "$body"$'\n'"intent_sha256=$hash"$'\n' || return $?
    write_phase intent || return $?
}

ensure_state_root() {
    install -d -o root -g root -m 0700 "$state_root" || return $?
    sync_path "$(dirname -- "$state_root")" || return $?
}

intent_archive_basename() {
    local schema intent_hash attempt_id
    schema=$(intent_value schema) || return $?
    intent_hash=$(intent_value intent_sha256) || return $?
    [[ "$intent_hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    case "$schema" in
        dirextalk.vnext-production-update-intent.v1)
            if [[ -e "$state_root/archive-attempt" || -L "$state_root/archive-attempt" ]]; then
                attempt_id=$(archive_attempt_id) || return $?
                printf 'update.%s.%s\n' "$attempt_id" "$intent_hash"
            else
                # Read-only compatibility for archives written before attempt
                # identity was added. New v1 archival always writes the
                # authenticated wrapper first.
                printf 'update.%s\n' "$intent_hash"
            fi
            ;;
        dirextalk.vnext-production-update-intent.v2)
            attempt_id=$(intent_value attempt_id) || return $?
            [[ "$attempt_id" =~ ^[0-9a-f]{32}$ ]] || return 1
            printf 'update.%s.%s\n' "$attempt_id" "$intent_hash"
            ;;
        *)
            return 1
            ;;
    esac
}

directory_size_bytes() {
    local size
    size=$(du -sb -- "$1" | awk '{print $1}') || return $?
    [[ "$size" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$size"
}

validate_update_archive() {
    local archive=$1 saved_root archive_phase expected_name entry name count=0 size result=0
    local -A seen=()
    [[ -d "$archive" && ! -L "$archive" && \
        $(stat -c '%a:%u:%g' "$archive") == \
        "700:$state_owner_uid:$state_owner_gid" ]] || return 1
    [[ $(stat -c '%d' "$archive") == "$(stat -c '%d' "$release_root")" ]] || return 1
    ! mountpoint -q -- "$archive" || return 1
    saved_root=$state_root
    state_root=$archive
    if ! validate_intent; then
        result=1
    else
        archive_phase=$(phase || true)
        [[ "$archive_phase" == ready || "$archive_phase" == rolled_back ]] || result=1
        expected_name=$(intent_archive_basename || true)
        [[ -n "$expected_name" && $(basename -- "$archive") == "$expected_name" ]] || result=1
    fi
    state_root=$saved_root
    (( result == 0 )) || return "$result"
    while IFS= read -r -d '' entry; do
        (( count += 1 ))
        name=$(basename -- "$entry")
        case "$name" in
            intent|prior.env|candidate.env|compose.yml|phase|receipt|archive-attempt)
                [[ -z ${seen[$name]:-} ]] || return 1
                secure_state_file "$entry" || return 1
                seen[$name]=1
                ;;
            *)
                return 1
                ;;
        esac
    done < <(/usr/bin/find "$archive" -mindepth 1 -maxdepth 1 -print0)
    [[ "$count" == 6 || "$count" == 7 ]] || return 1
    for name in intent prior.env candidate.env compose.yml phase receipt; do
        [[ ${seen[$name]:-} == 1 ]] || return 1
    done
    if [[ ${seen[archive-attempt]:-} == 1 ]]; then
        saved_root=$state_root
        state_root=$archive
        archive_attempt_id >/dev/null || result=$?
        state_root=$saved_root
        (( result == 0 )) || return "$result"
    fi
    size=$(directory_size_bytes "$archive") || return $?
    (( size <= max_update_archive_bytes ))
}

archive_intent_value() {
    local archive=$1 key=$2 saved_root result
    saved_root=$state_root
    state_root=$archive
    if ! result=$(intent_value "$key"); then
        state_root=$saved_root
        return 1
    fi
    state_root=$saved_root
    printf '%s\n' "$result"
}

delete_update_archive() {
    local archive=$1 name
    validate_update_archive "$archive" || {
        echo "refusing to remove unsafe update archive: $archive" >&2
        return 1
    }
    for name in intent prior.env candidate.env compose.yml phase receipt; do
        /usr/bin/unlink "$archive/$name" || return $?
    done
    if [[ -f "$archive/archive-attempt" ]]; then
        /usr/bin/unlink "$archive/archive-attempt" || return $?
    fi
    rmdir "$archive" || return $?
    sync_path "$release_root" || return $?
}

available_update_bytes() {
    local blocks
    blocks=$(df -Pk -- "$release_root" | awk 'END {print $4}') || return $?
    [[ "$blocks" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$((blocks * 1024))"
}

maintain_update_storage() {
    local archive size mtime prior_digest candidate_digest record path free_bytes
    local protected_count=0 protected_bytes=0 kept_extra=0
    local count_limit=$((max_update_archives - 1))
    local bytes_limit=$((max_update_archive_total_bytes - max_update_archive_bytes))
    local -a records=() sorted=() references=()
    local -A protected=() satisfied=()
    (( count_limit >= 1 && bytes_limit >= max_update_archive_bytes )) || return 1
    [[ -d "$release_root" && ! -L "$release_root" && \
        $(stat -c '%a:%u:%g' "$release_root") == \
        "700:$state_owner_uid:$state_owner_gid" ]] || {
        echo 'production update archive root is unsafe' >&2
        return 1
    }
    if [[ -f "$current_env" && ! -L "$current_env" ]]; then
        references+=("$(sha256sum "$current_env" | awk '{print $1}')")
    fi
    if [[ -f "$state_root/intent" ]]; then
        validate_intent || return $?
        references+=("$(intent_value prior_sha256)" "$(intent_value candidate_sha256)")
    fi
    for archive in "$release_root"/update.*; do
        [[ -e "$archive" || -L "$archive" ]] || continue
        validate_update_archive "$archive" || {
            echo "production update archive is unsafe: $archive" >&2
            return 1
        }
        size=$(directory_size_bytes "$archive") || return $?
        mtime=$(/usr/bin/find "$archive" -maxdepth 0 -printf '%T@') || return $?
        [[ "$mtime" =~ ^[0-9]+\.[0-9]+$ ]] || return 1
        prior_digest=$(archive_intent_value "$archive" prior_sha256) || return $?
        candidate_digest=$(archive_intent_value "$archive" candidate_sha256) || return $?
        records+=("$mtime"$'\t'"$size"$'\t'"$prior_digest"$'\t'"$candidate_digest"$'\t'"$archive")
    done
    if (( ${#records[@]} > 0 )); then
        mapfile -t sorted < <(printf '%s\n' "${records[@]}" | sort -t $'\t' -k1,1nr -k5,5)
    fi
    for record in "${sorted[@]}"; do
        IFS=$'\t' read -r mtime size prior_digest candidate_digest path <<<"$record"
        for reference in "${references[@]}"; do
            [[ -n "$reference" && -z ${satisfied[$reference]:-} ]] || continue
            if [[ "$prior_digest" == "$reference" || "$candidate_digest" == "$reference" ]]; then
                protected[$path]=1
                satisfied[$reference]=1
            fi
        done
    done
    for record in "${sorted[@]}"; do
        IFS=$'\t' read -r mtime size prior_digest candidate_digest path <<<"$record"
        if [[ ${protected[$path]:-} == 1 ]]; then
            (( protected_count += 1 ))
            (( protected_bytes += size ))
        fi
    done
    if (( protected_count > count_limit || protected_bytes > bytes_limit )); then
        echo 'recovery-referenced update archives exceed the bounded storage quota' >&2
        return 1
    fi
    for record in "${sorted[@]}"; do
        IFS=$'\t' read -r mtime size prior_digest candidate_digest path <<<"$record"
        [[ ${protected[$path]:-} == 1 ]] && continue
        if (( kept_extra < retained_update_archives \
            && protected_count + kept_extra + 1 <= count_limit \
            && protected_bytes + size <= bytes_limit )); then
            (( kept_extra += 1 ))
            (( protected_bytes += size ))
        else
            delete_update_archive "$path" || return $?
        fi
    done
    free_bytes=$(available_update_bytes) || return $?
    if (( free_bytes < min_update_free_bytes + max_update_archive_bytes )); then
        echo 'insufficient free space for a bounded production update attempt' >&2
        return 1
    fi
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
    validate_images_for "$selected_env" || return $?
    compose_with "$selected_env" config >/dev/null || return $?
    compose_with "$selected_env" up --force-recreate --no-deps --abort-on-container-failure \
        node-ready realtime-ready agent-control-ready
}

fault_point() {
    :
}

write_record_receipt() {
    local status=$1
    atomic_text "$state_root/receipt" 0600 "status=$status"$'\n' || return $?
}

promote_candidate() {
    case "$(phase)" in
        candidate_ready)
            atomic_copy "$state_root/compose.yml" "$compose_file" 0644 || return $?
            write_phase candidate_config_promoted || return $?
            ;&
        candidate_config_promoted)
            atomic_copy "$state_root/candidate.env" "$env_file" 0644 || return $?
            write_phase production_env_promoted || return $?
            ;&
        production_env_promoted)
            atomic_copy "$state_root/candidate.env" "$current_env" 0600 || return $?
            write_phase active_promoted || return $?
            ;&
        active_promoted)
            write_record_receipt ready || return $?
            atomic_text "$last_success" 0600 'status=ready'$'\n' || return $?
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
    atomic_copy "$state_root/prior.env" "$current_env" 0600 || return $?
    write_record_receipt rolled_back || return $?
    write_phase rolled_back || return $?
}

mark_recovery_failed() {
    write_record_receipt recovery_failed || return $?
    write_phase recovery_failed || return $?
}

recover_prior_code() {
    write_phase rollback_started || return $?
    # Desired-active configuration is durably restored before prior containers
    # are reconciled. Schema remains forward-only and named volumes are untouched.
    atomic_copy "$state_root/prior.env" "$env_file" 0644 || return $?
    atomic_copy "$state_root/prior.env" "$current_env" 0600 || return $?
    if ! validate_images_for "$state_root/prior.env" \
        || ! compose_with "$state_root/prior.env" up -d --no-deps \
            dtx-node realtime-gateway agent-control caddy \
        || ! readiness_with "$state_root/prior.env"; then
        mark_recovery_failed || return $?
        echo 'candidate failed and retained prior services did not become ready' >&2
        return 2
    fi
    write_phase rollback_ready || return $?
    finish_rollback || return $?
    echo 'candidate readiness failed; compatible prior release restored on the forward schema' >&2
    return 1
}

resume_failed_recovery() {
    # Operator repair may fix a host/runtime dependency without changing the
    # authenticated update intent. Reconcile the exact retained long-running
    # services before probing once per invocation; never re-enter candidate
    # Compose or migrations from here.
    atomic_copy "$state_root/prior.env" "$env_file" 0644 || return $?
    atomic_copy "$state_root/prior.env" "$current_env" 0600 || return $?
    if ! validate_images_for "$state_root/prior.env" \
        || ! compose_with "$state_root/prior.env" up -d --no-deps \
            dtx-node realtime-gateway agent-control caddy \
        || ! readiness_with "$state_root/prior.env"; then
        echo 'retained prior services remain unready after bounded recovery reconciliation' >&2
        return 2
    fi
    write_phase rollback_ready || return $?
    finish_rollback || return $?
    echo 'repaired prior release is ready on the forward schema; rollback completed' >&2
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
            resume_failed_recovery
            return $?
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
            atomic_copy "$state_root/prior.env" "$env_file" 0644 || return $?
            validate_images_for "$state_root/candidate.env" || return $?
            compose_with "$state_root/candidate.env" pull --quiet || return $?
            write_phase pulled || return $?
            ;&
        pulled)
            write_phase candidate_started || return $?
            ;&
        candidate_started)
            # candidate_started is pre-call evidence only. Replaying it must
            # reconcile this exact authenticated candidate Compose invocation.
            if ! compose_with "$state_root/candidate.env" up -d --remove-orphans; then
                recover_prior_code
                return $?
            fi
            fault_point after-candidate-compose || return $?
            write_phase candidate_applied || return $?
            ;&
        candidate_applied)
            # candidate_applied is durable proof that Compose returned success;
            # replay from this point only probes and promotes the candidate.
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

run_locked_update() {
    local previous_version candidate_version result
    fault_point after-update-lock || return $?
    [[ -f "$env_file" && ! -L "$env_file" && $(stat -c '%a' "$env_file") == 644 ]] || {
        echo 'invalid production env file' >&2
        return 1
    }
    scripts/production-stack/validate-files.sh || return $?
    scripts/production-stack/validate-images.sh || return $?
    [[ -f "$current_env" && ! -L "$current_env" && $(stat -c '%a:%u:%g' "$current_env") == 600:0:0 ]] || {
        echo 'retained prior release is required' >&2
        return 1
    }
    if [[ -d "$state_root" ]]; then
        validate_intent || return $?
    fi
    archive_terminal_intent_for_new_candidate || return $?
    if [[ ! -d "$state_root" ]]; then
        validate_images_for "$current_env" || return $?
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
        maintain_update_storage || return $?
        write_intent "$previous_version" "$candidate_version" || return $?
    fi
    if run_update_state_machine; then
        result=0
    else
        result=$?
    fi
    if (( result == 0 )); then
        scripts/production-stack/cleanup-cache.sh || return $?
    fi
    return "$result"
}

archive_terminal_intent_for_new_candidate() {
    local current_phase active_digest candidate_digest prior_digest archive archive_name size
    current_phase=$(phase || true)
    case "$current_phase" in
        ready)
            active_digest=$(sha256sum "$env_file" | awk '{print $1}') || return $?
            candidate_digest=$(intent_value candidate_sha256) || return $?
            [[ "$active_digest" != "$candidate_digest" ]] || return 0
            ;;&
        rolled_back)
            active_digest=$(sha256sum "$env_file" | awk '{print $1}') || return $?
            prior_digest=$(intent_value prior_sha256) || return $?
            [[ "$active_digest" != "$prior_digest" ]] || return 0
            ;;&
        ready|rolled_back)
            if [[ $(intent_value schema) == dirextalk.vnext-production-update-intent.v1 ]]; then
                ensure_archive_attempt_identity || return $?
            fi
            archive_name=$(intent_archive_basename) || return $?
            archive="$release_root/$archive_name"
            [[ ! -e "$archive" && ! -L "$archive" ]] || {
                echo 'authenticated update attempt archive already exists' >&2
                return 1
            }
            size=$(directory_size_bytes "$state_root") || return $?
            (( size <= max_update_archive_bytes )) || {
                echo 'completed update intent exceeds its archive size bound' >&2
                return 1
            }
            [[ -d "$release_root" && ! -L "$release_root" && \
                $(stat -c '%a:%u:%g' "$release_root") == \
                "700:$state_owner_uid:$state_owner_gid" \
                && $(stat -c '%d' "$state_root") == "$(stat -c '%d' "$release_root")" ]] || {
                echo 'completed update archive root or device is unsafe' >&2
                return 1
            }
            ! mountpoint -q -- "$state_root" || {
                echo 'completed update intent is a mount point' >&2
                return 1
            }
            mv -T --no-clobber "$state_root" "$archive" || return $?
            [[ ! -e "$state_root" && ! -L "$state_root" && -d "$archive" ]] || {
                echo 'authenticated update attempt archive was not appended' >&2
                return 1
            }
            sync_path "$release_root" || return $?
            ;;
    esac
}

run_serialized_update() {
    local result
    acquire_update_lock || return $?
    if run_locked_update; then
        result=0
    else
        result=$?
    fi
    if ! close_update_lock_fd; then
        result=1
    fi
    return "$result"
}

main() {
    if (( $# != 0 )); then
        echo 'usage: update.sh' >&2
        return 2
    fi
    [[ ${EUID} -eq 0 ]] || { echo 'update requires root' >&2; return 1; }
    command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; return 1; }
    command -v flock >/dev/null 2>&1 || { echo 'flock is required' >&2; return 1; }
    command -v mountpoint >/dev/null 2>&1 || { echo 'mountpoint is required' >&2; return 1; }
    run_serialized_update
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
