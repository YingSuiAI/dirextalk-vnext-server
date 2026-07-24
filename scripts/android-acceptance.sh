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
CLAIMED=0 COMPOSE_OWNED=0 AVD_A_CREATED=0 AVD_B_CREATED=0 REVERSE_A=0 REVERSE_B=0
PID_A='' PID_B='' PROXY_A_PID='' PROXY_B_PID=''
SERIAL_A='' SERIAL_B='' PROXY_A_PORT='' CONTROL_A_PORT='' PROXY_B_PORT='' CONTROL_B_PORT='' NODE_A_PORT='' NODE_B_PORT='' EMULATOR_A_PORT='' EMULATOR_B_PORT='' ALLOCATOR_LOCK_FD=''

die() { printf '%s\n' "android-acceptance: $*" >&2; exit 1; }
valid_run_id_value() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,47}$ ]]; }
valid_run_id() { valid_run_id_value "$RUN_ID"; }
safe_run_root() { [[ "$RUN_ROOT" == "$STATE_ROOT/$RUN_ID" && "$RUN_ID" != *'/'* ]]; }
safe_avd() { [[ "$1" == "$RUN_PREFIX"-* && "$1" != "$RUN_PREFIX" ]]; }
safe_project() { [[ "$COMPOSE_PROJECT" == "dtx-android-accept-$RUN_ID" ]]; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_emulator_port() { valid_port "$1" && (( 10#$1 >= 5554 && 10#$1 <= 5682 && 10#$1 % 2 == 0 )); }
valid_pid() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
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
  allocate_ports
  # Allocation is serialized with every live run's durable reservation, but the
  # lock is not held while Android work executes: independent RUN_IDs can run
  # concurrently without selecting the same ports or serials.
  release_allocator
}

allocate_ports() {
  local seed candidate offset resources='' resource_file
  command -v cksum >/dev/null && command -v awk >/dev/null && command -v seq >/dev/null && command -v grep >/dev/null || die 'reservation allocator tools are unavailable'
  seed=$(printf '%s' "$RUN_ID" | cksum | awk '{print $1}')
  shopt -s nullglob
  for resource_file in "$STATE_ROOT"/*/resources; do
    [[ "$resource_file" == "$RUN_ROOT/resources" ]] && continue
    [[ -f "$resource_file" && ! -L "$resource_file" && ! -L "${resource_file%/resources}" ]] || die 'unreadable or unsafe reservation file'
    validate_reservation_file "$resource_file" || die 'corrupt reservation file'
    resources+="$(<"$resource_file")"$'\n'
  done
  shopt -u nullglob
  for offset in $(seq 0 999); do
    candidate=$((20000 + ((seed % 10000 + offset * 3) % 10000)))
    # Emulator console ports are restricted to the documented even 5554-5682
    # range.  A/B consume adjacent even slots; the durable reservation scan
    # below makes the finite range fail closed instead of reusing a serial.
    EMULATOR_A_PORT=$((5554 + ((seed % 64 + offset) % 64) * 2)); EMULATOR_B_PORT=$((EMULATOR_A_PORT + 2))
    if printf '%s\n' "$resources" | grep -Eq "^(node_a_port|node_b_port|proxy_a_port|control_a_port|proxy_b_port|control_b_port)=(${candidate}|$((candidate+1))|$((candidate+2))|$((candidate+3))|$((candidate+4))|$((candidate+5)))$|^(emulator_a_port|emulator_b_port)=(${EMULATOR_A_PORT}|${EMULATOR_B_PORT})$"; then
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
  local file=$1 line key value run_id='' compose_project='' node_a_port='' node_b_port='' proxy_a_port='' control_a_port='' proxy_b_port='' control_b_port='' emulator_a_port='' emulator_b_port='' emulator_a_serial='' emulator_b_serial='' compose_owned='' proxy_a_pid='' proxy_b_pid='' emulator_a_pid='' emulator_b_pid=''
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
      PROXY_A_PID|PROXY_B_PID|emulator_a_pid|emulator_b_pid) valid_pid "$value" || return 1; printf -v "${key,,}" '%s' "$value" ;;
      *) return 1 ;;
    esac
  done <"$file"
  [[ -n "$run_id" && "$compose_project" == "dtx-android-accept-$run_id" ]] || return 1
  [[ -n "$node_a_port" && -n "$node_b_port" && -n "$proxy_a_port" && -n "$control_a_port" && -n "$proxy_b_port" && -n "$control_b_port" ]] || return 1
  (( 10#$node_a_port >= 20000 && 10#$node_a_port <= 29999 )) || return 1
  (( 10#$node_b_port == 10#$node_a_port + 1 && 10#$proxy_a_port == 10#$node_a_port + 2 && 10#$control_a_port == 10#$node_a_port + 3 && 10#$proxy_b_port == 10#$node_a_port + 4 && 10#$control_b_port == 10#$node_a_port + 5 )) || return 1
  [[ -n "$emulator_a_port" && -n "$emulator_b_port" ]] || return 1
  (( 10#$emulator_b_port == 10#$emulator_a_port + 2 )) || return 1
  [[ "$emulator_a_serial" == "emulator-$emulator_a_port" && "$emulator_b_serial" == "emulator-$emulator_b_port" ]]
}

stop_pid() {
  local pid=$1 port=$2
  [[ -n "$pid" ]] || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  ! kill -0 "$pid" 2>/dev/null || return 1
  ! ss -ltnH "sport = :$port" | grep -q . || return 1
}
cleanup() {
  local status=$? cleanup_failed=0
  set +e
  [[ "$MODE" == run ]] || exit "$status"
  [[ "$REVERSE_A" != 1 ]] || adb -s "$SERIAL_A" reverse --remove tcp:8443 >/dev/null 2>&1 || cleanup_failed=1
  [[ "$REVERSE_B" != 1 ]] || adb -s "$SERIAL_B" reverse --remove tcp:8443 >/dev/null 2>&1 || cleanup_failed=1
  stop_pid "$PROXY_A_PID" "$PROXY_A_PORT" || cleanup_failed=1; stop_pid "$PROXY_B_PID" "$PROXY_B_PORT" || cleanup_failed=1
  [[ -z "$PID_A" ]] || kill "$PID_A" 2>/dev/null || cleanup_failed=1; [[ -z "$PID_B" ]] || kill "$PID_B" 2>/dev/null || cleanup_failed=1
  [[ -z "$PID_A" ]] || wait "$PID_A" 2>/dev/null || true; [[ -z "$PID_B" ]] || wait "$PID_B" 2>/dev/null || true
  [[ "$AVD_A_CREATED" != 1 ]] || { safe_avd "$AVD_A" && avdmanager delete avd --name "$AVD_A" >/dev/null 2>&1 && ! avdmanager list avd | grep -Fqx "    Name: $AVD_A"; } || cleanup_failed=1
  [[ "$AVD_B_CREATED" != 1 ]] || { safe_avd "$AVD_B" && avdmanager delete avd --name "$AVD_B" >/dev/null 2>&1 && ! avdmanager list avd | grep -Fqx "    Name: $AVD_B"; } || cleanup_failed=1
  [[ "$COMPOSE_OWNED" != 1 ]] || { safe_project && docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" down --volumes --remove-orphans >/dev/null 2>&1; } || cleanup_failed=1
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
  command -v docker >/dev/null || die 'docker is required'; command -v adb >/dev/null || die 'adb is required'
  command -v emulator >/dev/null || die 'emulator is required'; command -v avdmanager >/dev/null || die 'avdmanager is required'
  [[ -n "${DTX_ANDROID_SYSTEM_IMAGE:-}" ]] || die 'DTX_ANDROID_SYSTEM_IMAGE is required'
  ! avdmanager list avd | grep -Fqx "    Name: $AVD_A" || die 'AVD A already exists'
  ! avdmanager list avd | grep -Fqx "    Name: $AVD_B" || die 'AVD B already exists'
  ! adb devices | grep -Eq "^(${SERIAL_A}|${SERIAL_B})[[:space:]]" || die 'reserved emulator serial is already active'
}
verify_emulator() {
  local serial=$1 pid=$2 avd=$3
  adb -s "$serial" wait-for-device
  kill -0 "$pid" || die 'emulator PID exited'
  ps -p "$pid" -o args= | grep -F -- "-avd $avd" >/dev/null || die 'serial does not map to recorded emulator PID'
  adb -s "$serial" emu avd name | grep -Fx "$avd" >/dev/null || die 'serial does not map to this AVD'
  adb -s "$serial" root >/dev/null; adb -s "$serial" shell 'test "$(getprop ro.kernel.qemu)" = 1' >/dev/null || die 'image is not rooted emulator'
}
install_ca_system_store() {
  local serial=$1 ca_file=$2 hash
  hash="$(openssl x509 -hash -noout -in "$ca_file")"
  adb -s "$serial" push "$ca_file" "/data/local/tmp/$hash.0" >/dev/null
  adb -s "$serial" shell "mount -o rw,remount /system && cp /data/local/tmp/$hash.0 /system/etc/security/cacerts/$hash.0 && chmod 644 /system/etc/security/cacerts/$hash.0 && rm /data/local/tmp/$hash.0 && mount -o ro,remount /system" >/dev/null
}
start_proxy() {
  local listen=$1 upstream=$2 control=$3 variable=$4
  "$REPOSITORY_ROOT/target/debug/dtx-android-response-loss-proxy" "127.0.0.1:$listen" "127.0.0.1:$upstream" "127.0.0.1:$control" >/dev/null 2>&1 &
  local pid=$!
  # Record ownership before the first readiness probe: startup can fail after
  # fork but before either listener exists.
  printf -v "$variable" '%s' "$pid"
  record "$variable" "$pid"
  sleep 0.1; kill -0 "$pid" || die 'proxy exited during startup'
  ss -ltnH "sport = :$listen" | grep -q . && ss -ltnH "sport = :$control" | grep -q . || die 'proxy listeners not ready'
}
real_run() {
  claim; preflight
  cargo build --locked -p dtx-android-response-loss-proxy
  COMPOSE_OWNED=1; record compose_owned 1
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" up --detach --wait
  mkdir -p -- "$RUN_ROOT/tls"
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" cp tls-bootstrap:/run/dtx-local-tls/ca.pem "$RUN_ROOT/tls/ca.pem"
  AVD_A_CREATED=1; avdmanager create avd --name "$AVD_A" --package "$DTX_ANDROID_SYSTEM_IMAGE" >/dev/null
  AVD_B_CREATED=1; avdmanager create avd --name "$AVD_B" --package "$DTX_ANDROID_SYSTEM_IMAGE" >/dev/null
  emulator -avd "$AVD_A" -port "$EMULATOR_A_PORT" -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_A=$!; record emulator_a_pid "$PID_A"
  emulator -avd "$AVD_B" -port "$EMULATOR_B_PORT" -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_B=$!; record emulator_b_pid "$PID_B"
  verify_emulator "$SERIAL_A" "$PID_A" "$AVD_A"; verify_emulator "$SERIAL_B" "$PID_B" "$AVD_B"
  install_ca_system_store "$SERIAL_A" "$RUN_ROOT/tls/ca.pem"; install_ca_system_store "$SERIAL_B" "$RUN_ROOT/tls/ca.pem"
  start_proxy "$PROXY_A_PORT" "$NODE_A_PORT" "$CONTROL_A_PORT" PROXY_A_PID; start_proxy "$PROXY_B_PORT" "$NODE_B_PORT" "$CONTROL_B_PORT" PROXY_B_PID
  REVERSE_A=1; adb -s "$SERIAL_A" reverse tcp:8443 "tcp:$PROXY_A_PORT"
  REVERSE_B=1; adb -s "$SERIAL_B" reverse tcp:8443 "tcp:$PROXY_B_PORT"
  die 'Direct/Group Android scenario runner is not available; no acceptance result was claimed'
}
case "$MODE" in dry-run) valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'; printf '%s\n' 'android-acceptance: dry-run passed (no external commands)';; self-test) valid_run_id && safe_avd "$AVD_A" && safe_avd "$AVD_B" && safe_project && safe_run_root || die 'safety self-test failed'; printf '%s\n' 'android-acceptance: safety self-test passed';; run) real_run;; esac
