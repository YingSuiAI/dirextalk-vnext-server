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
CLAIMED=0 COMPOSE_UP=0 AVD_A_CREATED=0 AVD_B_CREATED=0 REVERSE_A=0 REVERSE_B=0
PID_A='' PID_B='' PROXY_A_PID='' PROXY_B_PID=''
SERIAL_A='' SERIAL_B='' PROXY_A_PORT='' CONTROL_A_PORT='' PROXY_B_PORT='' CONTROL_B_PORT='' NODE_A_PORT='' NODE_B_PORT=''

die() { printf '%s\n' "android-acceptance: $*" >&2; exit 1; }
valid_run_id() { [[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,47}$ ]]; }
safe_run_root() { [[ "$RUN_ROOT" == "$STATE_ROOT/$RUN_ID" && "$RUN_ID" != *'/'* ]]; }
safe_avd() { [[ "$1" == "$RUN_PREFIX"-* && "$1" != "$RUN_PREFIX" ]]; }
safe_project() { [[ "$COMPOSE_PROJECT" == "dtx-android-accept-$RUN_ID" ]]; }
port_free() { ! ss -ltnH "sport = :$1" | grep -q .; }
record() { printf '%s=%s\n' "$1" "$2" >>"$RUN_ROOT/resources"; }

claim() {
  mkdir -p -- "$STATE_ROOT"
  valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'
  (umask 077; mkdir -- "$RUN_ROOT") 2>/dev/null || die 'run id already claimed or unsafe state exists'
  CLAIMED=1
  : >"$RUN_ROOT/resources"
  record run_id "$RUN_ID"; record compose_project "$COMPOSE_PROJECT"
}

allocate_ports() {
  local seed candidate offset
  seed=$(printf '%s' "$RUN_ID" | cksum | awk '{print $1}')
  candidate=$((20000 + seed % 20000))
  for offset in $(seq 0 999); do
    candidate=$((20000 + (candidate - 20000 + offset * 8) % 20000))
    if port_free "$candidate" && port_free "$((candidate+1))" && port_free "$((candidate+2))" && port_free "$((candidate+3))" && port_free "$((candidate+4))" && port_free "$((candidate+5))"; then
      NODE_A_PORT=$candidate; NODE_B_PORT=$((candidate+1)); PROXY_A_PORT=$((candidate+2)); CONTROL_A_PORT=$((candidate+3)); PROXY_B_PORT=$((candidate+4)); CONTROL_B_PORT=$((candidate+5))
      record node_a_port "$NODE_A_PORT"; record node_b_port "$NODE_B_PORT"
      record proxy_a_port "$PROXY_A_PORT"; record control_a_port "$CONTROL_A_PORT"; record proxy_b_port "$PROXY_B_PORT"; record control_b_port "$CONTROL_B_PORT"
      return
    fi
  done
  die 'no exclusive loopback proxy ports available'
}

stop_pid() {
  local pid=$1 port=$2
  [[ -n "$pid" ]] || return
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  ! kill -0 "$pid" 2>/dev/null || die 'child process survived teardown'
  port_free "$port" || die 'proxy port remained allocated'
}
cleanup() {
  local status=$?
  set +e
  [[ "$MODE" == run ]] || exit "$status"
  [[ "$REVERSE_A" == 1 ]] && adb -s "$SERIAL_A" reverse --remove tcp:8443 >/dev/null 2>&1
  [[ "$REVERSE_B" == 1 ]] && adb -s "$SERIAL_B" reverse --remove tcp:8443 >/dev/null 2>&1
  stop_pid "$PROXY_A_PID" "$PROXY_A_PORT"; stop_pid "$PROXY_B_PID" "$PROXY_B_PORT"
  [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null; [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
  [[ -n "$PID_A" ]] && wait "$PID_A" 2>/dev/null; [[ -n "$PID_B" ]] && wait "$PID_B" 2>/dev/null
  [[ "$AVD_A_CREATED" == 1 ]] && safe_avd "$AVD_A" && avdmanager delete avd --name "$AVD_A" >/dev/null 2>&1
  [[ "$AVD_B_CREATED" == 1 ]] && safe_avd "$AVD_B" && avdmanager delete avd --name "$AVD_B" >/dev/null 2>&1
  [[ "$COMPOSE_UP" == 1 ]] && safe_project && docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" down --volumes --remove-orphans >/dev/null 2>&1
  [[ "$CLAIMED" == 1 ]] && safe_run_root && rm -rf -- "$RUN_ROOT"
  exit "$status"
}
trap cleanup EXIT INT TERM

preflight() {
  valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'
  command -v docker >/dev/null || die 'docker is required'; command -v adb >/dev/null || die 'adb is required'
  command -v emulator >/dev/null || die 'emulator is required'; command -v avdmanager >/dev/null || die 'avdmanager is required'
  [[ -n "${DTX_ANDROID_SYSTEM_IMAGE:-}" ]] || die 'DTX_ANDROID_SYSTEM_IMAGE is required'
  ! avdmanager list avd | grep -Fqx "    Name: $AVD_A" || die 'AVD A already exists'
  ! avdmanager list avd | grep -Fqx "    Name: $AVD_B" || die 'AVD B already exists'
  ! adb devices | grep -Eq '^emulator-[0-9]+\s' || die 'existing emulator serials are not accepted'
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
  sleep 0.1; kill -0 "$pid" || die 'proxy exited during startup'
  ss -ltnH "sport = :$listen" | grep -q . && ss -ltnH "sport = :$control" | grep -q . || die 'proxy listeners not ready'
  printf -v "$variable" '%s' "$pid"
  record "$variable" "$pid"
}
real_run() {
  claim; allocate_ports; preflight
  cargo build --locked -p dtx-android-response-loss-proxy
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" up --detach --wait; COMPOSE_UP=1
  mkdir -p -- "$RUN_ROOT/tls"
  DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" cp tls-bootstrap:/run/dtx-local-tls/ca.pem "$RUN_ROOT/tls/ca.pem"
  avdmanager create avd --name "$AVD_A" --package "$DTX_ANDROID_SYSTEM_IMAGE" >/dev/null; AVD_A_CREATED=1
  avdmanager create avd --name "$AVD_B" --package "$DTX_ANDROID_SYSTEM_IMAGE" >/dev/null; AVD_B_CREATED=1
  emulator -avd "$AVD_A" -port 5554 -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_A=$!; SERIAL_A=emulator-5554; record emulator_a_pid "$PID_A"; record emulator_a_serial "$SERIAL_A"
  emulator -avd "$AVD_B" -port 5556 -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_B=$!; SERIAL_B=emulator-5556; record emulator_b_pid "$PID_B"; record emulator_b_serial "$SERIAL_B"
  verify_emulator "$SERIAL_A" "$PID_A" "$AVD_A"; verify_emulator "$SERIAL_B" "$PID_B" "$AVD_B"
  install_ca_system_store "$SERIAL_A" "$RUN_ROOT/tls/ca.pem"; install_ca_system_store "$SERIAL_B" "$RUN_ROOT/tls/ca.pem"
  start_proxy "$PROXY_A_PORT" "$NODE_A_PORT" "$CONTROL_A_PORT" PROXY_A_PID; start_proxy "$PROXY_B_PORT" "$NODE_B_PORT" "$CONTROL_B_PORT" PROXY_B_PID
  adb -s "$SERIAL_A" reverse tcp:8443 "tcp:$PROXY_A_PORT"; REVERSE_A=1
  adb -s "$SERIAL_B" reverse tcp:8443 "tcp:$PROXY_B_PORT"; REVERSE_B=1
  die 'Direct/Group Android scenario runner is not available; no acceptance result was claimed'
}
case "$MODE" in dry-run) valid_run_id && safe_run_root && safe_project || die 'unsafe run identity'; printf '%s\n' 'android-acceptance: dry-run passed (no external commands)';; self-test) valid_run_id && safe_avd "$AVD_A" && safe_avd "$AVD_B" && safe_project && safe_run_root || die 'safety self-test failed'; printf '%s\n' 'android-acceptance: safety self-test passed';; run) real_run;; esac
