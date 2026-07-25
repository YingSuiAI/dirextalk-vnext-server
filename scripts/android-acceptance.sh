#!/usr/bin/env bash
# Disposable Android acceptance harness; no Product Core scenario semantics live here.
set -euo pipefail
IFS=$'\n\t'

MODE=run
case "${1:---run}" in --dry-run) MODE=dry-run;; --run) MODE=run;; --self-test) MODE=self-test;; *) printf '%s\n' 'android-acceptance: usage: --run|--dry-run|--self-test' >&2; exit 2;; esac
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly RUN_ID="${DTX_ANDROID_ACCEPTANCE_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$$}"
readonly RUN_PREFIX="dirextalk-accept-${RUN_ID}"
readonly AVD_A="${RUN_PREFIX}-a" AVD_B="${RUN_PREFIX}-b"
readonly COMPOSE_PROJECT="dtx-android-accept-${RUN_ID}"
readonly STATE_ROOT="$REPOSITORY_ROOT/.android-acceptance" RUN_ROOT="$REPOSITORY_ROOT/.android-acceptance/$RUN_ID"
readonly EVIDENCE_ROOT="$REPOSITORY_ROOT/artifacts/android-acceptance/$RUN_ID"
readonly ANDROID_SYSTEM_IMAGE="${DTX_ANDROID_SYSTEM_IMAGE:-system-images;android-35;aosp_atd;x86_64}"
readonly ANDROID_ACCELERATION="${DTX_ANDROID_ACCELERATION:-off}"
readonly ANDROID_GPU="${DTX_ANDROID_GPU:-swiftshader_indirect}"
readonly ANDROID_CORES="${DTX_ANDROID_CORES:-2}"
readonly ANDROID_MEMORY_MIB="${DTX_ANDROID_MEMORY_MIB:-2048}"
readonly ANDROID_BOOT_TIMEOUT_SECONDS="${DTX_ANDROID_BOOT_TIMEOUT_SECONDS:-180}"
readonly ANDROID_AVD_RSS_MIB="${DTX_ANDROID_AVD_RSS_MIB:-4300}"
readonly ANDROID_SDK_ROOT_VALUE="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
readonly ANDROID_AVD_COUNT=2
CLAIMED=0 COMPOSE_OWNED=0 AVD_A_CREATED=0 AVD_B_CREATED=0 REVERSE_A=0 REVERSE_B=0
CA_A_INSTALLED=0 CA_B_INSTALLED=0 CA_A_TOUCHED=0 CA_B_TOUCHED=0
TRUST_PROBE_A_TOUCHED=0 TRUST_PROBE_B_TOUCHED=0
TRUST_PROBE_DEX='' TRUST_PROBE_HASH='' TRUST_RESULT_A_PATH='' TRUST_RESULT_B_PATH=''
TRUST_PROBE_A_NONCE='' TRUST_PROBE_B_NONCE=''
PID_A='' PID_B='' PROXY_A_PID='' PROXY_B_PID=''
GUARDIAN_A_PID='' GUARDIAN_B_PID='' PROXY_A_GUARDIAN_PID='' PROXY_B_GUARDIAN_PID=''
GUARDIAN_A_START='' GUARDIAN_B_START='' PROXY_A_GUARDIAN_START='' PROXY_B_GUARDIAN_START=''
PID_A_START='' PID_B_START='' PROXY_A_PID_START='' PROXY_B_PID_START=''
OWNED_GUARDIAN_PID='' OWNED_GUARDIAN_START='' OWNED_CHILD_PID='' OWNED_CHILD_START='' OWNED_PROCESS_INDEX=0
SERIAL_A='' SERIAL_B='' PROXY_A_PORT='' CONTROL_A_PORT='' PROXY_B_PORT='' CONTROL_B_PORT='' NODE_A_PORT='' NODE_B_PORT='' EMULATOR_A_PORT='' EMULATOR_B_PORT='' ALLOCATOR_LOCK_FD='' CA_HASH=''
readonly PROCESS_KILL_GRACE_SECONDS=5

die() { printf '%s\n' "android-acceptance: $*" >&2; exit 1; }
bounded_seconds() {
  local seconds=$ANDROID_BOOT_TIMEOUT_SECONDS
  if [[ "${DTX_ANDROID_TEST_MODE:-}" == 1 && "${DTX_TEST_COMMAND_TIMEOUT_SECONDS:-}" =~ ^[1-9][0-9]*$ ]]; then
    seconds=$DTX_TEST_COMMAND_TIMEOUT_SECONDS
  fi
  printf '%s' "$seconds"
}
run_bounded() {
  local label=$1
  shift
  local status
  if timeout --signal=TERM --kill-after="$PROCESS_KILL_GRACE_SECONDS" "$(bounded_seconds)" "$@"; then
    return 0
  else
    status=$?
  fi
  if [[ "$status" == 124 || "$status" == 137 ]]; then
    printf '%s\n' "android-acceptance: $label timed out" >&2
  elif (( status != 0 )); then
    printf '%s\n' "android-acceptance: $label failed" >&2
  fi
  return "$status"
}
adb_bounded() { local label=$1; shift; run_bounded "adb $label" adb "$@"; }
compose_bounded() { local label=$1; shift; run_bounded "docker compose $label" docker compose "$@"; }
avd_bounded() { local label=$1; shift; run_bounded "avdmanager $label" avdmanager "$@"; }
ps_bounded() { run_bounded 'ps' ps "$@"; }
ss_bounded() { run_bounded 'ss' ss "$@"; }
stat_bounded() { run_bounded 'stat' stat "$@"; }
sha256_bounded() { run_bounded 'sha256sum' sha256sum "$@"; }
start_owned_process() {
  local label=$1 child_file deadline
  shift
  ((OWNED_PROCESS_INDEX += 1))
  child_file="$RUN_ROOT/.guardian-child-$OWNED_PROCESS_INDEX"
  # The guardian is the stable, harness-owned group leader.  It ignores TERM
  # while its child receives the group signal, and survives until verified KILL.
  setsid bash -c 'child_file=$1; shift; trap ":" TERM; "$@" & child=$!; printf "%s" "$child" >"$child_file"; while :; do wait "$child" || :; sleep 2147483647 & wait "$!" || :; done' bash "$child_file" "$@" >/dev/null 2>&1 &
  OWNED_GUARDIAN_PID=$!
  deadline=$((SECONDS + PROCESS_KILL_GRACE_SECONDS))
  while [[ ! -s "$child_file" && SECONDS -lt deadline ]]; do :; done
  [[ -s "$child_file" ]] || return 1
  OWNED_CHILD_PID="$(<"$child_file")"; rm -f -- "$child_file"
  valid_pid "$OWNED_CHILD_PID" || return 1
  OWNED_GUARDIAN_START="$(proc_start_identity "$OWNED_GUARDIAN_PID")" || return 1
  OWNED_CHILD_START="$(proc_start_identity "$OWNED_CHILD_PID")" || return 1
}
proc_start_identity() {
  local pid=$1 stat rest; local -a fields=()
  [[ -r "/proc/$pid/stat" ]] || return 1
  stat="$(<"/proc/$pid/stat")"; rest=${stat#*) }
  IFS=' ' read -r -a fields <<<"$rest"
  [[ "${fields[0]:-}" != Z && "${fields[19]:-}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s' "${fields[19]}"
}
valid_run_id_value() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,47}$ ]]; }
valid_run_id() { valid_run_id_value "$RUN_ID"; }
safe_run_root() { [[ "$RUN_ROOT" == "$STATE_ROOT/$RUN_ID" && "$RUN_ID" != *'/'* ]]; }
safe_avd() { [[ "$1" == "$RUN_PREFIX"-* && "$1" != "$RUN_PREFIX" ]]; }
safe_project() { [[ "$COMPOSE_PROJECT" == "dtx-android-accept-$RUN_ID" ]]; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_emulator_port() { valid_port "$1" && (( 10#$1 >= 5554 && 10#$1 <= 5682 && 10#$1 % 2 == 0 )); }
valid_pid() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
valid_uint() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
valid_config() {
  [[ "$ANDROID_ACCELERATION" == off || "$ANDROID_ACCELERATION" == on ]] || return 1
  [[ "$ANDROID_GPU" == swiftshader_indirect || "$ANDROID_GPU" == software || "$ANDROID_GPU" == host ]] || return 1
  valid_uint "$ANDROID_CORES" && (( ANDROID_CORES >= 1 && ANDROID_CORES <= 8 )) || return 1
  valid_uint "$ANDROID_MEMORY_MIB" && (( ANDROID_MEMORY_MIB >= 1536 && ANDROID_MEMORY_MIB <= 8192 )) || return 1
  valid_uint "$ANDROID_BOOT_TIMEOUT_SECONDS" && (( ANDROID_BOOT_TIMEOUT_SECONDS >= 30 && ANDROID_BOOT_TIMEOUT_SECONDS <= 900 )) || return 1
  valid_uint "$ANDROID_AVD_RSS_MIB" && (( ANDROID_AVD_RSS_MIB >= 3000 && ANDROID_AVD_RSS_MIB <= 12000 )) || return 1
  [[ "$ANDROID_SYSTEM_IMAGE" == 'system-images;android-35;aosp_atd;x86_64' ]] || return 1
}
record() { printf '%s=%s\n' "$1" "$2" >>"$RUN_ROOT/resources"; }

safe_state_tree() {
  local current="$REPOSITORY_ROOT" part relative
  [[ "$STATE_ROOT" == "$REPOSITORY_ROOT/.android-acceptance" ]] || return 1
  relative="${STATE_ROOT#"$REPOSITORY_ROOT"/}"
  IFS=/ read -r -a parts <<<"$relative"
  for part in "${parts[@]}"; do current="$current/$part"; [[ ! -L "$current" ]] || return 1; done
  [[ ! -e "$STATE_ROOT" || -d "$STATE_ROOT" ]]
}

claim_allocator() {
  safe_state_tree || die 'state root or parent is a symlink or outside repository'
  mkdir -- "$STATE_ROOT" 2>/dev/null || [[ -d "$STATE_ROOT" ]] || die 'cannot create state root'
  safe_state_tree || die 'unsafe state root after creation'
  exec {ALLOCATOR_LOCK_FD}>"$STATE_ROOT/.allocator.lock"
  flock -n "$ALLOCATOR_LOCK_FD" || die 'another Android acceptance run owns the allocator'
}

release_allocator() {
  [[ -z "$ALLOCATOR_LOCK_FD" ]] || eval "exec ${ALLOCATOR_LOCK_FD}>&-"
  ALLOCATOR_LOCK_FD=''
}

claim() {
  claim_allocator
  valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'
  (umask 077; mkdir -- "$RUN_ROOT") 2>/dev/null || die 'run id already claimed or unsafe state exists'
  CLAIMED=1
  : >"$RUN_ROOT/resources"
  record run_id "$RUN_ID"; record compose_project "$COMPOSE_PROJECT"
  record android_system_image "$ANDROID_SYSTEM_IMAGE"; record android_acceleration "$ANDROID_ACCELERATION"
  record android_gpu "$ANDROID_GPU"; record android_cores "$ANDROID_CORES"; record android_memory_mib "$ANDROID_MEMORY_MIB"
  record android_boot_timeout_seconds "$ANDROID_BOOT_TIMEOUT_SECONDS"; record android_avd_count "$ANDROID_AVD_COUNT"
  record android_avd_rss_mib "$ANDROID_AVD_RSS_MIB"; record android_rss_reservation_mib "$((ANDROID_AVD_COUNT * ANDROID_AVD_RSS_MIB))"
  allocate_ports
  # Allocation is serialized with every live run's durable reservation, but the
  # lock is not held while Android work executes: independent RUN_IDs can run
  # concurrently without selecting the same ports or serials.
  release_allocator
}

allocate_ports() {
  local seed candidate offset resources='' resource_file resource_line conflict
  command -v cksum >/dev/null || die 'reservation allocator tool is unavailable'
  seed="$(run_bounded 'allocator seed' cksum <<<"$RUN_ID")" || die 'unable to seed reservation allocator'
  seed=${seed%% *}
  [[ "$seed" =~ ^[0-9]+$ ]] || die 'invalid reservation allocator seed'
  shopt -s nullglob
  for resource_file in "$STATE_ROOT"/*/resources; do
    [[ "$resource_file" == "$RUN_ROOT/resources" ]] && continue
    [[ -f "$resource_file" && ! -L "$resource_file" && ! -L "${resource_file%/resources}" ]] || die 'unreadable or unsafe reservation file'
    validate_reservation_file "$resource_file" || die 'corrupt reservation file'
    resources+="$(<"$resource_file")"$'\n'
  done
  shopt -u nullglob
  for ((offset=0; offset<1000; offset++)); do
    candidate=$((20000 + ((seed % 10000 + offset * 3) % 10000)))
    # Emulator console ports are restricted to the documented even 5554-5682
    # range.  A/B consume adjacent even slots; the durable reservation scan
    # below makes the finite range fail closed instead of reusing a serial.
    EMULATOR_A_PORT=$((5554 + ((seed % 64 + offset) % 64) * 2)); EMULATOR_B_PORT=$((EMULATOR_A_PORT + 2))
    conflict=0
    while IFS= read -r resource_line; do
      if [[ "$resource_line" =~ ^(node_a_port|node_b_port|proxy_a_port|control_a_port|proxy_b_port|control_b_port)=(${candidate}|$((candidate+1))|$((candidate+2))|$((candidate+3))|$((candidate+4))|$((candidate+5)))$ || "$resource_line" =~ ^(emulator_a_port|emulator_b_port)=(${EMULATOR_A_PORT}|${EMULATOR_B_PORT})$ ]]; then
        conflict=1
        break
      fi
    done <<<"$resources"
    if (( conflict )); then
      continue
    fi
    break
  done
  (( offset < 999 )) || die 'no exclusive Android acceptance port reservation available'
  NODE_A_PORT=$candidate; NODE_B_PORT=$((candidate+1)); PROXY_A_PORT=$((candidate+2)); CONTROL_A_PORT=$((candidate+3)); PROXY_B_PORT=$((candidate+4)); CONTROL_B_PORT=$((candidate+5))
  SERIAL_A="emulator-$EMULATOR_A_PORT"; SERIAL_B="emulator-$EMULATOR_B_PORT"
  record node_a_port "$NODE_A_PORT"; record node_b_port "$NODE_B_PORT"
  record proxy_a_port "$PROXY_A_PORT"; record control_a_port "$CONTROL_A_PORT"; record proxy_b_port "$PROXY_B_PORT"; record control_b_port "$CONTROL_B_PORT"
  record emulator_a_port "$EMULATOR_A_PORT"; record emulator_b_port "$EMULATOR_B_PORT"; record emulator_a_serial "$SERIAL_A"; record emulator_b_serial "$SERIAL_B"
}

validate_reservation_file() {
  local file=$1 line key value run_id='' compose_project='' node_a_port='' node_b_port='' proxy_a_port='' control_a_port='' proxy_b_port='' control_b_port='' emulator_a_port='' emulator_b_port='' emulator_a_serial='' emulator_b_serial='' compose_owned='' proxy_a_pid='' proxy_b_pid='' emulator_a_pid='' emulator_b_pid='' android_system_image='' android_acceleration='' android_gpu='' android_cores='' android_memory_mib='' android_boot_timeout_seconds='' android_avd_count='' android_avd_rss_mib='' android_rss_reservation_mib=''
  local -A seen=() ports=()
  [[ -r "$file" && -s "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *=* ]] || return 1
    key=${line%%=*}; value=${line#*=}
    [[ -z "${seen[$key]+x}" ]] || return 1
    seen[$key]=1
    case "$key" in
      run_id) valid_run_id_value "$value" || return 1; run_id=$value ;;
      compose_project) compose_project=$value ;;
      compose_owned) [[ "$value" == 1 ]] || return 1; compose_owned=$value ;;
      node_a_port|node_b_port|proxy_a_port|control_a_port|proxy_b_port|control_b_port)
        valid_port "$value" || return 1; [[ -z "${ports[$value]+x}" ]] || return 1; ports[$value]=1
        printf -v "$key" '%s' "$value" ;;
      emulator_a_port|emulator_b_port) valid_emulator_port "$value" || return 1; printf -v "$key" '%s' "$value" ;;
      emulator_a_serial|emulator_b_serial) [[ "$value" =~ ^emulator-[1-9][0-9]{0,4}$ ]] || return 1; printf -v "$key" '%s' "$value" ;;
      android_system_image) [[ "$value" == 'system-images;android-35;aosp_atd;x86_64' ]] || return 1; android_system_image=$value ;;
      android_acceleration) [[ "$value" == off || "$value" == on ]] || return 1; android_acceleration=$value ;;
      android_gpu) [[ "$value" == swiftshader_indirect || "$value" == software || "$value" == host ]] || return 1; android_gpu=$value ;;
      android_cores|android_memory_mib|android_boot_timeout_seconds|android_avd_count|android_avd_rss_mib|android_rss_reservation_mib) valid_uint "$value" || return 1; printf -v "$key" '%s' "$value" ;;
      PROXY_A_PID|PROXY_B_PID|emulator_a_pid|emulator_b_pid|PROXY_A_GUARDIAN_PID|PROXY_B_GUARDIAN_PID|emulator_a_guardian_pid|emulator_b_guardian_pid) valid_pid "$value" || return 1; printf -v "${key,,}" '%s' "$value" ;;
      PROXY_A_PID_START|PROXY_B_PID_START|PROXY_A_GUARDIAN_START|PROXY_B_GUARDIAN_START|emulator_a_pid_start|emulator_b_pid_start|emulator_a_guardian_start|emulator_b_guardian_start) valid_uint "$value" || return 1 ;;
      *) return 1 ;;
    esac
  done <"$file"
  [[ -n "$run_id" && "$compose_project" == "dtx-android-accept-$run_id" ]] || return 1
  [[ -n "$node_a_port" && -n "$node_b_port" && -n "$proxy_a_port" && -n "$control_a_port" && -n "$proxy_b_port" && -n "$control_b_port" ]] || return 1
  (( 10#$node_a_port >= 20000 && 10#$node_a_port <= 29999 )) || return 1
  (( 10#$node_b_port == 10#$node_a_port + 1 && 10#$proxy_a_port == 10#$node_a_port + 2 && 10#$control_a_port == 10#$node_a_port + 3 && 10#$proxy_b_port == 10#$node_a_port + 4 && 10#$control_b_port == 10#$node_a_port + 5 )) || return 1
  [[ -n "$emulator_a_port" && -n "$emulator_b_port" ]] || return 1
  (( 10#$emulator_b_port == 10#$emulator_a_port + 2 )) || return 1
  [[ "$emulator_a_serial" == "emulator-$emulator_a_port" && "$emulator_b_serial" == "emulator-$emulator_b_port" ]] || return 1
  [[ "$android_system_image" == 'system-images;android-35;aosp_atd;x86_64' ]] || return 1
  [[ "$android_acceleration" == off || "$android_acceleration" == on ]] || return 1
  [[ "$android_gpu" == swiftshader_indirect || "$android_gpu" == software || "$android_gpu" == host ]] || return 1
  (( android_avd_count == 2 && android_rss_reservation_mib == android_avd_count * android_avd_rss_mib )) || return 1
}

pid_cmdline_matches() {
  local pid=$1 kind=$2 first=$3 second=$4 third=$5
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  local -a argv=() arg
  while IFS= read -r -d '' arg; do argv+=("$arg"); done <"/proc/$pid/cmdline"
  (( ${#argv[@]} > 0 )) || return 1
  if [[ "$kind" == emulator ]]; then
    local avd_index=-1 port_index=-1 avd_count=0 port_count=0 index
    for index in "${!argv[@]}"; do
      if [[ "${argv[$index]}" == -avd ]]; then avd_index=$index; ((avd_count += 1)); fi
      if [[ "${argv[$index]}" == -port ]]; then port_index=$index; ((port_count += 1)); fi
    done
    (( avd_count == 1 && port_count == 1 && avd_index + 1 < ${#argv[@]} && port_index + 1 < ${#argv[@]} )) || return 1
    [[ "${argv[$((avd_index + 1))]}" == "$first" && "${argv[$((port_index + 1))]}" == "$second" ]] || return 1
  else
    local found=0 arg_value
    for arg_value in "${argv[@]}"; do
      [[ "$arg_value" == "$first" || "$arg_value" == "$second" || "$arg_value" == "$third" ]] && ((found += 1))
    done
    (( found == 3 )) || return 1
  fi
}
process_group_pgid() {
  local pid=$1 pgid
  pgid="$(ps_bounded -o pgid= -p "$pid")"
  pgid=${pgid//[[:space:]]/}
  [[ "$pgid" =~ ^[1-9][0-9]*$ && "$pgid" == "$pid" ]] || return 1
  printf '%s' "$pgid"
}
group_live_member_pids() {
  local pgid=$1 pid member_pgid state listing
  listing="$(ps_bounded -e -o pid=,pgid=,stat=)" || return 2
  while IFS=' ' read -r pid member_pgid state; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$member_pgid" == "$pgid" && "$state" != Z* ]] || continue
    kill -0 "$pid" 2>/dev/null || continue
    printf '%s\n' "$pid"
  done <<<"$listing"
}
group_has_live_members() {
  local members status
  members="$(group_live_member_pids "$1")"; status=$?
  (( status == 0 )) || return "$status"
  [[ -n "$members" ]]
}
wait_for_group_exit() {
  local pgid=$1 deadline=$2 status
  while group_has_live_members "$pgid"; do
    (( SECONDS < deadline )) || return 1
  done
  status=$?
  [[ "$status" == 1 ]] && return 0
  return "$status"
}
guardian_matches() {
  local pid=$1 start=$2 pgid
  valid_pid "$pid" && valid_uint "$start" || return 1
  [[ "$(proc_start_identity "$pid")" == "$start" ]] || return 1
  pgid="$(process_group_pgid "$pid")" || return 1
  [[ "$pgid" == "$pid" ]]
}
guardian_is_gone() {
  local pid=$1 start=$2 current
  valid_pid "$pid" && valid_uint "$start" || return 1
  current="$(proc_start_identity "$pid" 2>/dev/null || true)"
  [[ "$current" != "$start" ]]
}
stop_pid() {
  local pid=$1 child_start=$2 guardian=$3 guardian_start=$4 port=$5 kind=${6:-proxy} first=${7:-} second=${8:-} third=${9:-} serial=${10:-} pgid
  [[ -n "$pid" ]] || return 0
  [[ "$(proc_start_identity "$pid")" == "$child_start" ]] || return 1
  pid_cmdline_matches "$pid" "$kind" "$first" "$second" "$third" || return 1
  if [[ "$kind" == emulator ]]; then
    [[ -n "$serial" ]] || return 1
    (verify_emulator_identity "$serial" "$pid" "$first" "$second") || return 1
  fi
  guardian_matches "$guardian" "$guardian_start" || return 1
  pgid=$guardian
  kill -TERM -- "-$pgid" 2>/dev/null || return 1
  local deadline=$((SECONDS + PROCESS_KILL_GRACE_SECONDS))
  wait_for_group_exit "$pgid" "$deadline"; local group_status=$?
  # A leader may have exited or become a zombie after TERM.  The previously
  # validated, unreusable process group is the ownership boundary now.
  [[ "$group_status" == 0 || "$group_status" == 1 ]] || return 1
  guardian_matches "$guardian" "$guardian_start" || return 1
  kill -KILL -- "-$pgid" 2>/dev/null || return 1
  deadline=$((SECONDS + PROCESS_KILL_GRACE_SECONDS))
  wait_for_group_exit "$pgid" "$deadline" || return 1
  ! group_has_live_members "$pgid" || return 1
  guardian_is_gone "$guardian" "$guardian_start" || return 1
  wait "$pid" 2>/dev/null || true
  ! ss_bounded -ltnH "sport = :$port" | grep -q . || return 1
}
cleanup_probe_remote() {
  local serial=$1 pid=$2 avd=$3 port=$4 result_path=$5
  [[ -n "$result_path" ]] || return 0
  (verify_emulator "$serial" "$pid" "$avd" "$port") || return 1
  adb_bounded 'trust-result cleanup' -s "$serial" shell "rm -f '$result_path' /data/local/tmp/dtx-platform-trust-probe.dex && test ! -e '$result_path' && test ! -e /data/local/tmp/dtx-platform-trust-probe.dex" >/dev/null 2>&1 || return 1
}
cleanup_remote_serial() {
  local serial=$1 pid=$2 avd=$3 port=$4 result_path=$5 ca_touched=$6 probe_touched=$7 reverse=$8
  if ! (verify_emulator "$serial" "$pid" "$avd" "$port"); then
    return 1
  fi
  if [[ "$ca_touched" == 1 ]]; then
    remove_ca_system_store "$serial" || return 1
  fi
  if [[ "$probe_touched" == 1 ]]; then
    cleanup_probe_remote "$serial" "$pid" "$avd" "$port" "$result_path" || return 1
  fi
  if [[ "$reverse" == 1 ]]; then
    adb_bounded 'reverse cleanup' -s "$serial" reverse --remove tcp:8443 >/dev/null 2>&1 || return 1
  fi
}
cleanup() {
  local status=$? cleanup_failed=0
  set +e
  [[ "$MODE" == run ]] || exit "$status"
  if [[ "$CA_A_TOUCHED" == 1 || "$TRUST_PROBE_A_TOUCHED" == 1 || "$REVERSE_A" == 1 ]]; then
    cleanup_remote_serial "$SERIAL_A" "$PID_A" "$AVD_A" "$EMULATOR_A_PORT" "$TRUST_RESULT_A_PATH" "$CA_A_TOUCHED" "$TRUST_PROBE_A_TOUCHED" "$REVERSE_A" || cleanup_failed=1
  fi
  if [[ "$CA_B_TOUCHED" == 1 || "$TRUST_PROBE_B_TOUCHED" == 1 || "$REVERSE_B" == 1 ]]; then
    cleanup_remote_serial "$SERIAL_B" "$PID_B" "$AVD_B" "$EMULATOR_B_PORT" "$TRUST_RESULT_B_PATH" "$CA_B_TOUCHED" "$TRUST_PROBE_B_TOUCHED" "$REVERSE_B" || cleanup_failed=1
  fi
  stop_pid "$PROXY_A_PID" "$PROXY_A_PID_START" "$PROXY_A_GUARDIAN_PID" "$PROXY_A_GUARDIAN_START" "$PROXY_A_PORT" proxy "127.0.0.1:$PROXY_A_PORT" "127.0.0.1:$NODE_A_PORT" "127.0.0.1:$CONTROL_A_PORT" || cleanup_failed=1
  stop_pid "$PROXY_B_PID" "$PROXY_B_PID_START" "$PROXY_B_GUARDIAN_PID" "$PROXY_B_GUARDIAN_START" "$PROXY_B_PORT" proxy "127.0.0.1:$PROXY_B_PORT" "127.0.0.1:$NODE_B_PORT" "127.0.0.1:$CONTROL_B_PORT" || cleanup_failed=1
  stop_pid "$PID_A" "$PID_A_START" "$GUARDIAN_A_PID" "$GUARDIAN_A_START" "$EMULATOR_A_PORT" emulator "$AVD_A" "$EMULATOR_A_PORT" '' "$SERIAL_A" || cleanup_failed=1
  stop_pid "$PID_B" "$PID_B_START" "$GUARDIAN_B_PID" "$GUARDIAN_B_START" "$EMULATOR_B_PORT" emulator "$AVD_B" "$EMULATOR_B_PORT" '' "$SERIAL_B" || cleanup_failed=1
  [[ "$AVD_A_CREATED" != 1 ]] || { safe_avd "$AVD_A" && avd_bounded 'delete AVD A' delete avd --name "$AVD_A" >/dev/null 2>&1 && ! avd_bounded 'list AVDs' list avd | grep -Fqx "    Name: $AVD_A"; } || cleanup_failed=1
  [[ "$AVD_B_CREATED" != 1 ]] || { safe_avd "$AVD_B" && avd_bounded 'delete AVD B' delete avd --name "$AVD_B" >/dev/null 2>&1 && ! avd_bounded 'list AVDs' list avd | grep -Fqx "    Name: $AVD_B"; } || cleanup_failed=1
  if [[ "$COMPOSE_OWNED" == 1 ]]; then
    if ! safe_project; then
      cleanup_failed=1
    else
      compose_bounded 'ps' --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" ps --all >/dev/null 2>&1 || cleanup_failed=1
      compose_bounded 'down' --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" down --volumes --remove-orphans >/dev/null 2>&1 || cleanup_failed=1
    fi
  fi
  if [[ "$cleanup_failed" == 1 ]]; then
    [[ "$CLAIMED" != 1 ]] || printf '%s\n' 'cleanup=failed' >"$RUN_ROOT/cleanup-status"
    [[ "$status" != 0 ]] || status=1
    exit "$status"
  fi
  [[ "$CLAIMED" != 1 ]] || { safe_state_tree && safe_run_root && rm -rf -- "$RUN_ROOT"; } || exit 1
  exit "$status"
}
on_signal() { exit "$1"; }
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

preflight() {
  valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'
  valid_config || die 'invalid Android acceptance configuration'
  command -v docker >/dev/null || die 'docker is required'; command -v adb >/dev/null || die 'adb is required'; command -v timeout >/dev/null || die 'timeout is required'; command -v setsid >/dev/null || die 'setsid is required'
  command -v emulator >/dev/null || die 'emulator is required'; command -v avdmanager >/dev/null || die 'avdmanager is required'; command -v ss >/dev/null || die 'ss is required'
  ! avd_bounded 'list AVDs' list avd | grep -Fqx "    Name: $AVD_A" || die 'AVD A already exists'
  ! avd_bounded 'list AVDs' list avd | grep -Fqx "    Name: $AVD_B" || die 'AVD B already exists'
  ! adb_bounded 'devices' devices | grep -Eq "^(${SERIAL_A}|${SERIAL_B})[[:space:]]" || die 'reserved emulator serial is already active'
}
prepare_trust_probe() {
  local source="$SCRIPT_DIR/android-platform-trust-probe.java" android_jar d8 javac_version probe_dir classes_dir dex_output dex_size source_copy
  if [[ "${DTX_ANDROID_TEST_MODE:-}" == 1 && "${DTX_TEST_NATIVE_TRUST_PROBE:-}" != 1 ]]; then
    probe_dir="$(mktemp -d "$RUN_ROOT/trust-probe.XXXXXX")" || die 'unable to create private trust probe directory'
    TRUST_PROBE_DEX="$probe_dir/classes.dex"; printf test-dex >"$TRUST_PROBE_DEX"
    TRUST_PROBE_HASH="$(sha256_bounded "$TRUST_PROBE_DEX" | awk '{print $1}')"
    return 0
  fi
  [[ -f "$source" && ! -L "$source" ]] || die 'fixed trust probe source is missing or symlinked'
  [[ -n "$ANDROID_SDK_ROOT_VALUE" && -d "$ANDROID_SDK_ROOT_VALUE" && ! -L "$ANDROID_SDK_ROOT_VALUE" ]] || die 'Android SDK root is unavailable'
  android_jar="$ANDROID_SDK_ROOT_VALUE/platforms/android-35/android.jar"
  [[ -f "$android_jar" && ! -L "$android_jar" ]] || die 'API35 android.jar is unavailable'
  javac_version="$(run_bounded 'javac version' javac -version 2>&1)" || die 'JDK javac is unavailable'
  [[ "$javac_version" == 'javac 17.'* ]] || die 'pinned JDK 17 javac is required'
  d8="$(run_bounded 'build-tools discovery' bash -c '
    shopt -s nullglob
    candidates=("$1"/build-tools/*/d8)
    ((${#candidates[@]})) || exit 1
    printf "%s\\n" "${candidates[@]}" | sort -V | tail -n 1
  ' bash "$ANDROID_SDK_ROOT_VALUE")" || die 'Android SDK d8 is unavailable'
  [[ -n "$d8" && -f "$d8" && -x "$d8" && ! -L "$d8" && ! -L "${d8%/d8}" ]] || die 'Android SDK d8 is unavailable'
  probe_dir="$(mktemp -d "$RUN_ROOT/trust-probe.XXXXXX")" || die 'unable to create private trust probe directory'
  classes_dir="$probe_dir/classes"; dex_output="$probe_dir/dex"; mkdir -- "$classes_dir" "$dex_output"
  source_copy="$probe_dir/PlatformTrustProbe.java"
  cp -- "$source" "$source_copy"
  [[ -f "$source_copy" && ! -L "$source_copy" ]] || die 'private trust probe source copy is unsafe'
  run_bounded 'javac trust probe' javac -source 8 -target 8 -cp "$android_jar" -d "$classes_dir" "$source_copy" || die 'trust probe compilation failed'
  run_bounded 'd8 trust probe' "$d8" --lib "$android_jar" --output "$dex_output" "$classes_dir" || die 'trust probe dex compilation failed'
  TRUST_PROBE_DEX="$dex_output/classes.dex"
  [[ -f "$TRUST_PROBE_DEX" && ! -L "$TRUST_PROBE_DEX" ]] || die 'trust probe dex output is missing or symlinked'
  dex_size="$(stat_bounded -c '%s' "$TRUST_PROBE_DEX")"
  [[ "$dex_size" =~ ^[0-9]+$ && dex_size -le 4194304 ]] || die 'trust probe dex output exceeds bound'
  TRUST_PROBE_HASH="$(sha256_bounded "$TRUST_PROBE_DEX" | awk '{print $1}')"
  [[ "$TRUST_PROBE_HASH" =~ ^[0-9a-f]{64}$ ]] || die 'trust probe dex hash is invalid'
}
verify_emulator() {
  local serial=$1 pid=$2 avd=$3 port=$4
  verify_emulator_identity "$serial" "$pid" "$avd" "$port"
  adb_bounded 'root' -s "$serial" root >/dev/null || die 'adb root failed'
  verify_emulator_identity "$serial" "$pid" "$avd" "$port"
  [[ "$(adb_bounded 'getprop' -s "$serial" shell 'getprop ro.kernel.qemu' | tr -d '\r')" == 1 ]] || die 'image is not rooted emulator'
  [[ "$(adb_bounded 'id' -s "$serial" shell 'id -u' | tr -d '\r')" == 0 ]] || die 'emulator root uid is not zero'
}
verify_emulator_identity() {
  local serial=$1 pid=$2 avd=$3 port=$4
  valid_pid "$pid" || die 'emulator PID ownership is required'
  valid_emulator_port "$port" || die 'emulator console port ownership is required'
  adb_bounded 'wait-for-device' -s "$serial" wait-for-device >/dev/null || die 'emulator boot timed out'
  kill -0 "$pid" || die 'emulator PID exited'
  [[ -r "/proc/$pid/cmdline" ]] || die 'emulator process command line is unavailable'
  local -a argv=() arg
  while IFS= read -r -d '' arg; do argv+=("$arg"); done <"/proc/$pid/cmdline"
  local avd_index=-1 port_index=-1 avd_count=0 port_count=0 index
  for index in "${!argv[@]}"; do
    if [[ "${argv[$index]}" == -avd ]]; then avd_index=$index; ((avd_count += 1)); fi
    if [[ "${argv[$index]}" == -port ]]; then port_index=$index; ((port_count += 1)); fi
  done
  (( avd_count == 1 && avd_index >= 0 && avd_index + 1 < ${#argv[@]} )) || die 'emulator PID has an invalid -avd argument set'
  [[ "${argv[$((avd_index + 1))]}" == "$avd" ]] || die 'emulator PID has a mismatched -avd argument'
  (( port_count == 1 && port_index >= 0 && port_index + 1 < ${#argv[@]} )) || die 'emulator PID has an invalid -port argument set'
  [[ "${argv[$((port_index + 1))]}" == "$port" ]] || die 'emulator PID has a mismatched -port argument'
  local avd_reply line
  avd_reply="$(adb_bounded 'avd name' -s "$serial" emu avd name)" || die 'unable to read emulator AVD name'
  local -a console_lines=()
  while IFS= read -r line; do
    line=${line//$'\r'/}
    [[ -n "$line" ]] && console_lines+=("$line")
  done <<<"$avd_reply"
  (( ${#console_lines[@]} == 2 )) || die 'serial does not map to this AVD'
  [[ "${console_lines[0]}" == "$avd" && "${console_lines[1]}" == OK ]] || die 'serial does not map to this AVD'
  [[ "$(adb_bounded 'getprop' -s "$serial" shell 'getprop ro.kernel.qemu' | tr -d '\r')" == 1 ]] || die 'image is not rooted emulator'
}
assert_emulator_ports_free() {
  local console_port=$1 adb_port
  adb_port=$((console_port + 1))
  valid_emulator_port "$console_port" || die 'invalid emulator console port'
  valid_port "$adb_port" || die 'invalid emulator adb port'
  ! ss_bounded -ltnH "sport = :$console_port" | grep -q . || die "emulator console port $console_port is already listening"
  ! ss_bounded -ltnH "sport = :$adb_port" | grep -q . || die "emulator adb port $adb_port is already listening"
  ! adb_bounded 'devices' devices | grep -Eq "^emulator-($console_port|$adb_port)[[:space:]]" || die "emulator port $console_port is already owned by adb"
}
adb_shell_ok() { local serial=$1 command=$2; adb_bounded "shell $command" -s "$serial" shell "$command" >/dev/null; }
new_nonce() {
  local nonce
  nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || return 1
  printf '%s' "$nonce"
}
platform_trust_probe() {
  local serial=$1 pid=$2 avd=$3 port=$4 endpoint=$5 expected=$6 nonce result_path app_status result
  nonce="$(new_nonce)" || return 1
  result_path="/data/local/tmp/dtx-platform-trust-result-$nonce"
  if [[ "$serial" == "$SERIAL_A" ]]; then TRUST_PROBE_A_TOUCHED=1; TRUST_PROBE_A_NONCE="$nonce"; TRUST_RESULT_A_PATH="$result_path"; else TRUST_PROBE_B_TOUCHED=1; TRUST_PROBE_B_NONCE="$nonce"; TRUST_RESULT_B_PATH="$result_path"; fi
  (verify_emulator "$serial" "$pid" "$avd" "$port") || return 1
  adb_bounded 'trust-result reset' -s "$serial" shell "rm -f '$result_path' && test ! -e '$result_path'" >/dev/null 2>&1 || return 1
  app_status=0
  if adb_bounded 'trust-probe push' -s "$serial" push "$TRUST_PROBE_DEX" /data/local/tmp/dtx-platform-trust-probe.dex >/dev/null; then :; else app_status=$?; fi
  if [[ "$app_status" == 0 ]]; then
    if adb_bounded 'trust-probe app_process' -s "$serial" shell "app_process -Djava.class.path=/data/local/tmp/dtx-platform-trust-probe.dex /system/bin com.dirextalk.android.PlatformTrustProbe '$endpoint' '$nonce' '$result_path'" >/dev/null 2>&1; then :; else app_status=$?; fi
  fi
  (verify_emulator "$serial" "$pid" "$avd" "$port") || return 1
  result="$(adb_bounded 'trust-result read' -s "$serial" shell "cat '$result_path'" 2>/dev/null | tr -d '\r')" || result=''
  [[ "$result" == "$expected $nonce" ]] || return 1
  [[ "$app_status" == 0 ]] || return 1
}
verify_system_rw() {
  local serial=$1 probe="/system/etc/security/cacerts/.dtx-writable-$RUN_ID"
  adb_shell_ok "$serial" "test -w /system/etc/security/cacerts" || die 'system CA directory is not writable'
  adb_shell_ok "$serial" "printf dtx > '$probe' && test \"\$(cat '$probe')\" = dtx && rm -f '$probe' && test ! -e '$probe'" || die 'system CA directory write probe failed'
}
verify_ca_file() {
  local serial=$1 ca_file=$2 target=$3 local_digest remote_digest stat mode uid gid context
  adb_shell_ok "$serial" "test -f '$target' && test -r '$target'" || die 'installed CA is absent or unreadable'
  local_digest="$(sha256_bounded "$ca_file" | awk '{print $1}')" || die 'unable to hash CA file'
  remote_digest="$(adb_bounded 'CA digest' -s "$serial" shell "sha256sum '$target'" | awk '{print $1}' | tr -d '\r')" || die 'unable to hash installed CA'
  [[ "$remote_digest" == "$local_digest" ]] || die 'installed CA content mismatch'
  IFS=' ' read -r mode uid gid <<<"$(adb_bounded 'CA stat' -s "$serial" shell "stat -c '%a %u %g' '$target'" | tr -d '\r')"
  [[ "$mode" == 644 && "$uid" == 0 && "$gid" == 0 ]] || die "installed CA mode or owner mismatch: mode=$mode uid=$uid gid=$gid"
  context="$(adb_bounded 'CA context' -s "$serial" shell "ls -Z '$target'" | awk '{print $1}' | tr -d '\r')"
  [[ "$context" == u:object_r:system_file:s0 ]] || die 'installed CA SELinux context mismatch'
}
remount_system() {
  local serial=$1 pid=$2 avd=$3 port=$4 output
  output="$(adb_bounded 'remount' -s "$serial" remount 2>&1)" || die 'adb remount failed'
  if [[ "$output" == *'Successfully disabled verity'* ]]; then
    adb_bounded 'reboot' -s "$serial" reboot >/dev/null || die 'emulator reboot after verity disable failed'
    verify_emulator "$serial" "$pid" "$avd" "$port"
    output="$(adb_bounded 'remount after reboot' -s "$serial" remount 2>&1)" || die 'adb remount after reboot failed'
  fi
  [[ "$output" == *'remount succeeded'* || "$output" == *'Successfully remounted'* ]] || die 'adb remount did not report success'
  verify_system_rw "$serial"
}
install_ca_system_store() {
  local serial=$1 ca_file=$2 pid=$3 avd=$4 port=$5 hash target
  hash="$(run_bounded 'openssl CA hash' openssl x509 -hash -noout -in "$ca_file" | tr -d '\r\n')"
  [[ "$hash" =~ ^[0-9a-fA-F]{8}$ ]] || die 'unexpected CA subject hash'
  CA_HASH="$hash"; target="/system/etc/security/cacerts/$hash.0"
  if [[ "$serial" == "$SERIAL_A" ]]; then CA_A_TOUCHED=1; else CA_B_TOUCHED=1; fi
  adb_bounded 'CA push' -s "$serial" push "$ca_file" "/data/local/tmp/$hash.0" >/dev/null || die 'CA push failed'
  remount_system "$serial" "$pid" "$avd" "$port"
  adb_shell_ok "$serial" "cp '/data/local/tmp/$hash.0' '$target' && chmod 0644 '$target' && chown 0:0 '$target' && restorecon '$target' && rm -f '/data/local/tmp/$hash.0'" || die 'CA installation failed'
  if [[ "$serial" == "$SERIAL_A" ]]; then CA_A_INSTALLED=1; else CA_B_INSTALLED=1; fi
  verify_ca_file "$serial" "$ca_file" "$target"
  adb_bounded 'reboot after CA install' -s "$serial" reboot >/dev/null || die 'emulator reboot after CA install failed'
  verify_emulator "$serial" "$pid" "$avd" "$port"
  verify_ca_file "$serial" "$ca_file" "$target"
}
remove_ca_system_store() {
  local serial=$1 target
  [[ -n "$CA_HASH" ]] || return 0
  target="/system/etc/security/cacerts/$CA_HASH.0"
  (verify_emulator "$serial" "$( [[ "$serial" == "$SERIAL_A" ]] && printf '%s' "$PID_A" || printf '%s' "$PID_B" )" "$( [[ "$serial" == "$SERIAL_A" ]] && printf '%s' "$AVD_A" || printf '%s' "$AVD_B" )" "$( [[ "$serial" == "$SERIAL_A" ]] && printf '%s' "$EMULATOR_A_PORT" || printf '%s' "$EMULATOR_B_PORT" )") || return 1
  adb_bounded 'cleanup remount' -s "$serial" remount >/dev/null 2>&1 || return 1
  adb_shell_ok "$serial" "rm -f '$target' /data/local/tmp/$CA_HASH.0 && test ! -e '$target' && test ! -e '/data/local/tmp/$CA_HASH.0'" || return 1
  adb_shell_ok "$serial" "mount -o ro,remount /system" || return 1
  adb_shell_ok "$serial" "test ! -w /system/etc/security/cacerts" || return 1
}
start_proxy() {
  local listen=$1 upstream=$2 control=$3 variable=$4
  start_owned_process 'proxy' "$REPOSITORY_ROOT/target/debug/dtx-android-response-loss-proxy" "127.0.0.1:$listen" "127.0.0.1:$upstream" "127.0.0.1:$control"
  local pid=$OWNED_CHILD_PID guardian=$OWNED_GUARDIAN_PID
  # Record ownership before the first readiness probe: startup can fail after
  # fork but before either listener exists.
  printf -v "$variable" '%s' "$pid"
  record "$variable" "$pid"
  local guardian_variable="${variable%_PID}_GUARDIAN_PID" child_start_variable="${variable}_START" guardian_start_variable="${variable%_PID}_GUARDIAN_START"
  printf -v "$guardian_variable" '%s' "$guardian"; printf -v "$child_start_variable" '%s' "$OWNED_CHILD_START"; printf -v "$guardian_start_variable" '%s' "$OWNED_GUARDIAN_START"
  record "$guardian_variable" "$guardian"; record "$child_start_variable" "$OWNED_CHILD_START"; record "$guardian_start_variable" "$OWNED_GUARDIAN_START"
  local deadline=$((SECONDS + ANDROID_BOOT_TIMEOUT_SECONDS))
  while :; do
    kill -0 "$pid" 2>/dev/null || die 'proxy exited during startup'
    if ss_bounded -ltnH "sport = :$listen" | grep -q . && ss_bounded -ltnH "sport = :$control" | grep -q .; then
      return 0
    fi
    (( SECONDS < deadline )) || die 'proxy listeners not ready'
  done
}
real_run() {
  claim; preflight
  prepare_trust_probe
  run_bounded 'cargo build response-loss proxy' cargo build --locked -p dtx-android-response-loss-proxy
  COMPOSE_OWNED=1; record compose_owned 1
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" compose_bounded 'up' --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" up --detach --wait
  mkdir -p -- "$RUN_ROOT/tls"
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" compose_bounded 'copy bootstrap CA' --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" cp tls-bootstrap:/run/dtx-local-tls/ca.pem "$RUN_ROOT/tls/ca.pem"
  AVD_A_CREATED=1; avd_bounded 'create AVD A' create avd --name "$AVD_A" --package "$ANDROID_SYSTEM_IMAGE" >/dev/null
  AVD_B_CREATED=1; avd_bounded 'create AVD B' create avd --name "$AVD_B" --package "$ANDROID_SYSTEM_IMAGE" >/dev/null
  assert_emulator_ports_free "$EMULATOR_A_PORT"; assert_emulator_ports_free "$EMULATOR_B_PORT"
  start_owned_process 'emulator A' emulator -avd "$AVD_A" -port "$EMULATOR_A_PORT" -accel "$ANDROID_ACCELERATION" -cores "$ANDROID_CORES" -memory "$ANDROID_MEMORY_MIB" -gpu "$ANDROID_GPU" -writable-system -no-snapshot -wipe-data -no-window || die 'emulator A guardian failed'; PID_A=$OWNED_CHILD_PID; PID_A_START=$OWNED_CHILD_START; GUARDIAN_A_PID=$OWNED_GUARDIAN_PID; GUARDIAN_A_START=$OWNED_GUARDIAN_START; record emulator_a_pid "$PID_A"; record emulator_a_pid_start "$PID_A_START"; record emulator_a_guardian_pid "$GUARDIAN_A_PID"; record emulator_a_guardian_start "$GUARDIAN_A_START"
  assert_emulator_ports_free "$EMULATOR_B_PORT"
  start_owned_process 'emulator B' emulator -avd "$AVD_B" -port "$EMULATOR_B_PORT" -accel "$ANDROID_ACCELERATION" -cores "$ANDROID_CORES" -memory "$ANDROID_MEMORY_MIB" -gpu "$ANDROID_GPU" -writable-system -no-snapshot -wipe-data -no-window || die 'emulator B guardian failed'; PID_B=$OWNED_CHILD_PID; PID_B_START=$OWNED_CHILD_START; GUARDIAN_B_PID=$OWNED_GUARDIAN_PID; GUARDIAN_B_START=$OWNED_GUARDIAN_START; record emulator_b_pid "$PID_B"; record emulator_b_pid_start "$PID_B_START"; record emulator_b_guardian_pid "$GUARDIAN_B_PID"; record emulator_b_guardian_start "$GUARDIAN_B_START"
  verify_emulator "$SERIAL_A" "$PID_A" "$AVD_A" "$EMULATOR_A_PORT"; verify_emulator "$SERIAL_B" "$PID_B" "$AVD_B" "$EMULATOR_B_PORT"
  REVERSE_A=1; adb_bounded 'reverse A' -s "$SERIAL_A" reverse tcp:8443 "tcp:$NODE_A_PORT"
  REVERSE_B=1; adb_bounded 'reverse B' -s "$SERIAL_B" reverse tcp:8443 "tcp:$NODE_B_PORT"
  platform_trust_probe "$SERIAL_A" "$PID_A" "$AVD_A" "$EMULATOR_A_PORT" 'https://localhost:8443/local/ready' UNTRUSTED || die 'platform trust preinstall classification was not certificate-chain rejection'
  platform_trust_probe "$SERIAL_B" "$PID_B" "$AVD_B" "$EMULATOR_B_PORT" 'https://localhost:8443/local/ready' UNTRUSTED || die 'platform trust preinstall classification was not certificate-chain rejection'
  install_ca_system_store "$SERIAL_A" "$RUN_ROOT/tls/ca.pem" "$PID_A" "$AVD_A" "$EMULATOR_A_PORT"
  platform_trust_probe "$SERIAL_A" "$PID_A" "$AVD_A" "$EMULATOR_A_PORT" 'https://localhost:8443/local/ready' TRUSTED || die 'platform trust did not accept installed CA'
  install_ca_system_store "$SERIAL_B" "$RUN_ROOT/tls/ca.pem" "$PID_B" "$AVD_B" "$EMULATOR_B_PORT"
  platform_trust_probe "$SERIAL_B" "$PID_B" "$AVD_B" "$EMULATOR_B_PORT" 'https://localhost:8443/local/ready' TRUSTED || die 'platform trust did not accept installed CA'
  start_proxy "$PROXY_A_PORT" "$NODE_A_PORT" "$CONTROL_A_PORT" PROXY_A_PID; start_proxy "$PROXY_B_PORT" "$NODE_B_PORT" "$CONTROL_B_PORT" PROXY_B_PID
  REVERSE_A=1; adb_bounded 'reverse proxy A' -s "$SERIAL_A" reverse tcp:8443 "tcp:$PROXY_A_PORT"
  REVERSE_B=1; adb_bounded 'reverse proxy B' -s "$SERIAL_B" reverse tcp:8443 "tcp:$PROXY_B_PORT"
  die 'Direct/Group Android scenario runner is not available; no acceptance result was claimed'
}
case "$MODE" in dry-run) valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'; printf '%s\n' 'android-acceptance: dry-run passed (no external commands)';; self-test) valid_run_id && safe_avd "$AVD_A" && safe_avd "$AVD_B" && safe_project && safe_run_root || die 'safety self-test failed'; printf '%s\n' 'android-acceptance: safety self-test passed';; run) real_run;; esac
