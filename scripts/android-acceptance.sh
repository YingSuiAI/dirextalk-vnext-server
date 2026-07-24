#!/usr/bin/env bash
# Disposable Android acceptance harness. It deliberately has no product scenario logic.
set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly RUN_ID="${DTX_ANDROID_ACCEPTANCE_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$$}"
readonly RUN_PREFIX="dirextalk-accept-${RUN_ID}"
readonly AVD_A="${RUN_PREFIX}-a"
readonly AVD_B="${RUN_PREFIX}-b"
readonly COMPOSE_PROJECT="dtx-android-accept-${RUN_ID}"
readonly STATE_ROOT="$REPOSITORY_ROOT/.android-acceptance"
readonly RUN_ROOT="$STATE_ROOT/$RUN_ID"
readonly EVIDENCE_ROOT="$REPOSITORY_ROOT/artifacts/android-acceptance/$RUN_ID"
readonly DRY_RUN="${DTX_ANDROID_ACCEPTANCE_DRY_RUN:-0}"

PID_A=''
PID_B=''
PROXY_A_PID=''
PROXY_B_PID=''
AVD_A_CREATED=0
AVD_B_CREATED=0
REVERSE_A=0
REVERSE_B=0

die() { printf '%s\n' "android-acceptance: $*" >&2; exit 1; }
require_run_id() { [[ "$RUN_ID" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,47}$ ]] || die 'invalid run id'; }
safe_run_root() { [[ "$RUN_ROOT" == "$STATE_ROOT/$RUN_ID" && "$RUN_ROOT" != "$STATE_ROOT" && "$RUN_ID" != *'/'* ]]; }
safe_avd() { [[ "$1" == "$RUN_PREFIX"-* && "$1" != "$RUN_PREFIX" ]]; }
safe_project() { [[ "$COMPOSE_PROJECT" == "dtx-android-accept-$RUN_ID" ]]; }

cleanup() {
  local status=$?
  set +e
  [[ -n "$PROXY_A_PID" ]] && kill "$PROXY_A_PID" 2>/dev/null
  [[ -n "$PROXY_B_PID" ]] && kill "$PROXY_B_PID" 2>/dev/null
  if [[ "$DRY_RUN" != 1 ]]; then
    [[ "$REVERSE_A" == 1 ]] && adb -s emulator-5554 reverse --remove tcp:8443 2>/dev/null
    [[ "$REVERSE_B" == 1 ]] && adb -s emulator-5556 reverse --remove tcp:8443 2>/dev/null
    [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
    [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
    [[ "$AVD_A_CREATED" == 1 ]] && safe_avd "$AVD_A" && avdmanager delete avd --name "$AVD_A" 2>/dev/null
    [[ "$AVD_B_CREATED" == 1 ]] && safe_avd "$AVD_B" && avdmanager delete avd --name "$AVD_B" 2>/dev/null
    safe_project && docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" down --volumes --remove-orphans 2>/dev/null
  fi
  # TLS material is run-private and is never retained. Evidence has no TLS, logcat, DB, token, or payload output.
  safe_run_root && rm -rf -- "$RUN_ROOT"
  exit "$status"
}
trap cleanup EXIT INT TERM

preflight() {
  require_run_id; safe_project || die 'unsafe compose project'; safe_run_root || die 'unsafe state root'
  if [[ "$DRY_RUN" == 1 ]]; then return; fi
  command -v docker >/dev/null || die 'docker is required'
  command -v adb >/dev/null || die 'adb is required'
  command -v emulator >/dev/null || die 'emulator is required'
  command -v avdmanager >/dev/null || die 'avdmanager is required'
  [[ -n "${DTX_ANDROID_SYSTEM_IMAGE:-}" ]] || die 'DTX_ANDROID_SYSTEM_IMAGE is required'
}

write_evidence() {
  mkdir -p -- "$EVIDENCE_ROOT"
  printf 'run_id=%s\navd_a=%s\navd_b=%s\ncompose_project=%s\nresult=%s\n' "$RUN_ID" "$AVD_A" "$AVD_B" "$COMPOSE_PROJECT" "$1" >"$EVIDENCE_ROOT/summary.txt"
}

install_ca_system_store() {
  local serial=$1 ca_file=$2 hash
  adb -s "$serial" root >/dev/null
  adb -s "$serial" wait-for-device
  adb -s "$serial" shell 'test "$(getprop ro.kernel.qemu)" = 1' >/dev/null || die 'AVD image is not an emulator'
  hash="$(openssl x509 -hash -noout -in "$ca_file")"
  adb -s "$serial" push "$ca_file" "/data/local/tmp/$hash.0" >/dev/null
  adb -s "$serial" shell "mount -o rw,remount /system && cp /data/local/tmp/$hash.0 /system/etc/security/cacerts/$hash.0 && chmod 644 /system/etc/security/cacerts/$hash.0 && rm /data/local/tmp/$hash.0 && mount -o ro,remount /system" >/dev/null
}

real_run() {
  mkdir -p -- "$RUN_ROOT/tls"
  docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" up --detach --wait
  docker compose --project-directory "$REPOSITORY_ROOT" -f "$REPOSITORY_ROOT/docker-compose.local.yml" --project-name "$COMPOSE_PROJECT" cp tls-bootstrap:/run/dtx-local-tls/ca.pem "$RUN_ROOT/tls/ca.pem"
  avdmanager create avd --name "$AVD_A" --package "$DTX_ANDROID_SYSTEM_IMAGE" --force >/dev/null
  AVD_A_CREATED=1
  avdmanager create avd --name "$AVD_B" --package "$DTX_ANDROID_SYSTEM_IMAGE" --force >/dev/null
  AVD_B_CREATED=1
  emulator -avd "$AVD_A" -port 5554 -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_A=$!
  emulator -avd "$AVD_B" -port 5556 -no-snapshot -wipe-data -no-window >/dev/null 2>&1 & PID_B=$!
  adb -s emulator-5554 wait-for-device; adb -s emulator-5556 wait-for-device
  install_ca_system_store emulator-5554 "$RUN_ROOT/tls/ca.pem"
  install_ca_system_store emulator-5556 "$RUN_ROOT/tls/ca.pem"
  cargo run --locked -p dtx-android-response-loss-proxy -- 127.0.0.1:28543 127.0.0.1:18443 127.0.0.1:28544 >/dev/null 2>&1 & PROXY_A_PID=$!
  cargo run --locked -p dtx-android-response-loss-proxy -- 127.0.0.1:28553 127.0.0.1:18444 127.0.0.1:28554 >/dev/null 2>&1 & PROXY_B_PID=$!
  adb -s emulator-5554 reverse tcp:8443 tcp:28543
  REVERSE_A=1
  adb -s emulator-5556 reverse tcp:8443 tcp:28553
  REVERSE_B=1
  die 'Direct/Group Android scenario runner is not available; no acceptance result was claimed'
}

case "${1:---run}" in
  --dry-run) DTX_ANDROID_ACCEPTANCE_DRY_RUN=1; preflight; write_evidence dry-run; printf '%s\n' 'android-acceptance: dry-run passed';;
  --self-test) require_run_id; safe_avd "$AVD_A"; safe_avd "$AVD_B"; safe_project; safe_run_root; [[ "$RUN_PREFIX" == dirextalk-accept-* ]]; printf '%s\n' 'android-acceptance: safety self-test passed';;
  --run) preflight; [[ "$DRY_RUN" == 1 ]] && { write_evidence dry-run; printf '%s\n' 'android-acceptance: dry-run passed'; } || real_run;;
  *) die 'usage: android-acceptance.sh [--run|--dry-run|--self-test]';;
esac
