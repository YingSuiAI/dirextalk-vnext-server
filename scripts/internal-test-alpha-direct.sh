#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SERVER_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly CLIENT_ROOT="${DTX_ALPHA_CLIENT_ROOT:-"$SERVER_ROOT/../dirextalk-vnext-client"}"
readonly FLUTTER_ROOT="$CLIENT_ROOT/app/flutter"
readonly TEST_TARGET="integration_test/internal_test_alpha_direct_harness_test.dart"
readonly PACKAGE="com.dirextalk.dirextalk_vnext_client"
readonly RUN_ID="${DTX_ALPHA_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$$}"
readonly TARGET_MODE="${DTX_ALPHA_TARGET_MODE:-local}"
readonly COMPOSE_PROJECT="dtx-alpha-direct-$RUN_ID"
readonly EVIDENCE_ROOT="$SERVER_ROOT/artifacts/internal-test-alpha/$RUN_ID"
readonly SERIAL_A="${DTX_ALPHA_DEVICE_A:-192.168.1.100:5555}"
readonly SERIAL_B="${DTX_ALPHA_DEVICE_B:-192.168.1.101:5555}"
readonly SERIAL_C="${DTX_ALPHA_DEVICE_C:-192.168.1.102:5555}"
readonly NODE_A_PORT="${DTX_ALPHA_NODE_A_PORT:-28443}"
readonly NODE_B_PORT="${DTX_ALPHA_NODE_B_PORT:-28444}"
readonly NODE_C_PORT="${DTX_ALPHA_NODE_C_PORT:-28445}"
readonly POSTGRES_PORT="${DTX_ALPHA_POSTGRES_PORT:-25432}"
readonly REALTIME_A_PORT="${DTX_ALPHA_REALTIME_A_PORT:-29443}"
readonly REALTIME_B_PORT="${DTX_ALPHA_REALTIME_B_PORT:-29444}"
readonly REALTIME_C_PORT="${DTX_ALPHA_REALTIME_C_PORT:-29445}"
if [[ "$TARGET_MODE" == remote ]]; then
  readonly ORIGIN_A="${DTX_ALPHA_ORIGIN_A:-https://x3.dirextalk.ai}"
  readonly ORIGIN_B="${DTX_ALPHA_ORIGIN_B:-https://x4.dirextalk.ai}"
  readonly ORIGIN_C="${DTX_ALPHA_ORIGIN_C:-https://x5.dirextalk.ai}"
elif [[ "$TARGET_MODE" == local ]]; then
  readonly ORIGIN_A="https://localhost:8443"
  readonly ORIGIN_B="https://localhost:8444"
  readonly ORIGIN_C="https://localhost:8445"
else
  printf '%s\n' "internal-test-alpha-direct: unsupported target mode: $TARGET_MODE" >&2
  exit 1
fi
readonly CA_LOCAL="$EVIDENCE_ROOT/local-ca.pem"
readonly APP_APK="$FLUTTER_ROOT/build/app/outputs/flutter-apk/app-debug.apk"

COMPOSE_STARTED=0
ACTION_INDEX=0
CA_HASH=''
RUN_ACTION_OUTPUT=''
PREPARE_DIRECT_OUTPUT=''
declare -a REVERSE_OWNERS=()
declare -a CA_OWNERS=()

die() {
  printf '%s\n' "internal-test-alpha-direct: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null || die "$1 is required"
}

valid_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

assert_device() {
  local serial=$1 state
  state="$(adb -s "$serial" get-state 2>/dev/null || true)"
  [[ "$state" == device ]] || die "authorized device is unavailable: $serial"
}

assert_port_free() {
  local port=$1
  ! ss -ltnH "sport = :$port" | grep -q . ||
    die "required local port is already listening: $port"
}

compose() {
  DTX_LOCAL_POSTGRES_PORT="$POSTGRES_PORT" \
    DTX_ANDROID_NODE_A_PORT="$NODE_A_PORT" \
    DTX_ANDROID_NODE_B_PORT="$NODE_B_PORT" \
    DTX_ANDROID_NODE_C_PORT="$NODE_C_PORT" \
    DTX_ANDROID_REALTIME_A_PORT="$REALTIME_A_PORT" \
    DTX_ANDROID_REALTIME_B_PORT="$REALTIME_B_PORT" \
    DTX_ANDROID_REALTIME_C_PORT="$REALTIME_C_PORT" \
    DTX_ANDROID_NODE_A_ORIGIN="$ORIGIN_A" \
    DTX_ANDROID_NODE_B_ORIGIN="$ORIGIN_B" \
    DTX_ANDROID_NODE_C_ORIGIN="$ORIGIN_C" \
    docker compose \
      --project-directory "$SERVER_ROOT" \
      -f "$SERVER_ROOT/docker-compose.local.yml" \
      --project-name "$COMPOSE_PROJECT" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  local owner serial port target expected_digest remote_digest
  for owner in "${REVERSE_OWNERS[@]}"; do
    serial=${owner%%|*}
    port=${owner#*|}
    adb -s "$serial" reverse --remove "tcp:$port" >/dev/null 2>&1 || true
  done
  for owner in "${CA_OWNERS[@]}"; do
    serial=${owner%%|*}
    target=${owner#*|}
    expected_digest=${target#*|}
    target=${target%%|*}
    remote_digest="$(adb -s "$serial" shell \
      "test -f '$target' && sha256sum '$target'" 2>/dev/null |
      tr -d '\r' | awk '{print $1}' || true)"
    if [[ "$remote_digest" == "$expected_digest" ]]; then
      adb -s "$serial" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || status=1
      adb -s "$serial" shell "rm -f '$target'" >/dev/null 2>&1 || status=1
    elif [[ -n "$remote_digest" ]]; then
      status=1
    fi
  done
  if ((COMPOSE_STARTED)); then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || status=1
  fi
  exit "$status"
}

install_ca_if_needed() {
  local serial=$1 target="/system/etc/security/cacerts/$CA_HASH.0"
  local existing='' local_digest remote_digest
  local_digest="$(sha256sum "$CA_LOCAL" | awk '{print $1}')"
  adb -s "$serial" root >/dev/null
  adb -s "$serial" wait-for-device
  existing="$(adb -s "$serial" shell "test -f '$target' && sha256sum '$target'" 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then
    [[ "${existing%% *}" == "$local_digest" ]] ||
      die "device has a conflicting certificate at $target: $serial"
    return 0
  fi
  if ! adb -s "$serial" shell \
    "test -w /system/etc/security/cacerts" >/dev/null 2>&1; then
    adb -s "$serial" shell \
      "command -v remount >/dev/null && remount" >/dev/null
  fi
  adb -s "$serial" push "$CA_LOCAL" "/data/local/tmp/$CA_HASH.0" >/dev/null
  adb -s "$serial" shell \
    "cp '/data/local/tmp/$CA_HASH.0' '$target' && chmod 0644 '$target' && chown 0:0 '$target' && restorecon '$target' && rm -f '/data/local/tmp/$CA_HASH.0'"
  CA_OWNERS+=("$serial|$target|$local_digest")
  remote_digest="$(adb -s "$serial" shell "sha256sum '$target'" | tr -d '\r' | awk '{print $1}')"
  [[ "$remote_digest" == "$local_digest" ]] ||
    die "installed CA verification failed: $serial"
}

claim_reverse() {
  local serial=$1 device_port=$2 host_port=$3 existing
  existing="$(adb -s "$serial" reverse --list | awk -v port="tcp:$device_port" '$2 == port {print}')"
  [[ -z "$existing" ]] || die "device reverse already owns tcp:$device_port on $serial"
  adb -s "$serial" reverse "tcp:$device_port" "tcp:$host_port"
  REVERSE_OWNERS+=("$serial|$device_port")
}

write_control() {
  local serial=$1 control=$2
  printf '%s' "$control" |
    adb -s "$serial" shell \
      "run-as '$PACKAGE' sh -c 'umask 077; mkdir -p files; rm -f files/.dtx-alpha-result.json; cat > files/.dtx-alpha-control.json'"
}

run_action() {
  local label=$1 serial=$2 control=$3 output
  ((ACTION_INDEX += 1))
  output="$EVIDENCE_ROOT/$(printf '%03d' "$ACTION_INDEX")-$label.json"
  write_control "$serial" "$control"
  if ! (
    cd -- "$FLUTTER_ROOT"
    flutter test "$TEST_TARGET" -d "$serial" --no-pub --no-uninstall \
      --reporter failures-only
  ) >"$output.log" 2>&1; then
    adb -s "$serial" logcat -d -s rustls-platform-verifier-android \
      >"$output.android.log" 2>&1 || true
    die "Flutter device action failed: $label (see $output.log)"
  fi
  adb -s "$serial" exec-out run-as "$PACKAGE" \
    cat files/.dtx-alpha-result.json >"$output"
  jq -e '.ok == true' "$output" >/dev/null ||
    die "device action failed: $label"
  RUN_ACTION_OUTPUT=$output
}

transfer_secret() {
  local source_serial=$1 destination_serial=$2
  adb -s "$source_serial" exec-out run-as "$PACKAGE" \
    cat files/.dtx-alpha-secret-out |
    adb -s "$destination_serial" shell \
      "run-as '$PACKAGE' sh -c 'umask 077; mkdir -p files; cat > files/.dtx-alpha-secret-in'"
  adb -s "$source_serial" shell run-as "$PACKAGE" \
    rm -f files/.dtx-alpha-secret-out
}

establish_contact() {
  local edge=$1 inviter=$2 importer=$3 inviter_variable=$4 importer_variable=$5
  local inviter_existing=$6 importer_existing=$7
  local invite_result import_result review_result
  local importer_reconcile_result inviter_reconcile_result
  local inviter_contact importer_contact
  run_action "$edge-invite" "$inviter" \
    '{"action":"create_contact_invite"}'
  invite_result=$RUN_ACTION_OUTPUT
  transfer_secret "$inviter" "$importer"
  run_action "$edge-import" "$importer" \
    '{"action":"import_contact_invite"}'
  import_result=$RUN_ACTION_OUTPUT
  run_action "$edge-review" "$inviter" \
    '{"action":"review_contact_requests"}'
  review_result=$RUN_ACTION_OUTPUT
  run_action "$edge-importer-reconcile" "$importer" \
    '{"action":"reconcile_contacts"}'
  importer_reconcile_result=$RUN_ACTION_OUTPUT
  run_action "$edge-inviter-reconcile" "$inviter" \
    '{"action":"reconcile_contacts"}'
  inviter_reconcile_result=$RUN_ACTION_OUTPUT
  importer_contact="$(jq -er --arg existing "$importer_existing" \
    '[.contacts[].contact_id | select(. != $existing)] |
     if length == 1 then .[0] else error("ambiguous importer contact") end' \
    "$importer_reconcile_result")"
  inviter_contact="$(jq -er \
    --arg existing "$inviter_existing" \
    '[.contacts[].contact_id | select(. != $existing)] |
     if length == 1 then .[0] else error("ambiguous inviter contact") end' \
    "$inviter_reconcile_result")"
  [[ -n "$inviter_contact" && -n "$importer_contact" ]] ||
    die "contact edge did not expose exact opaque IDs: $edge"
  printf -v "$inviter_variable" '%s' "$inviter_contact"
  printf -v "$importer_variable" '%s' "$importer_contact"
}

prepare_direct() {
  local edge=$1 sender=$2 receiver=$3 sender_contact=$4 result=''
  local control
  control="$(jq -nc --arg contact "$sender_contact" \
    '{action:"prepare_direct",contact_id:$contact}')"
  for attempt in 1 2 3 4 5 6; do
    run_action "$edge-prepare-$attempt" "$sender" "$control"
    result=$RUN_ACTION_OUTPUT
    if jq -e '.ready == true' "$result" >/dev/null; then
      PREPARE_DIRECT_OUTPUT=$result
      return 0
    fi
    run_action "$edge-receiver-sync-$attempt" "$receiver" \
      '{"action":"sync_direct"}'
  done
  die "Direct conversation did not become ready: $edge"
}

send_direct() {
  local edge=$1 sender=$2 receiver=$3 sender_contact=$4 message=$5
  local prepare_result send_result receive_result='' control
  prepare_direct "$edge" "$sender" "$receiver" "$sender_contact"
  prepare_result=$PREPARE_DIRECT_OUTPUT
  jq -e '.ready == true and (.conversation_id | type == "string")' \
    "$prepare_result" >/dev/null ||
    die "Direct preparation result invalid: $edge"
  control="$(jq -nc --arg contact "$sender_contact" --arg message "$message" \
    '{action:"send_direct",contact_id:$contact,message:$message}')"
  run_action "$edge-send" "$sender" "$control"
  send_result=$RUN_ACTION_OUTPUT
  jq -e '.delivery == "delivered" or .delivery == "pending"' \
    "$send_result" >/dev/null ||
    die "Direct send was not durably queued: $edge"
  control="$(jq -nc --arg message "$message" \
    '{action:"sync_direct",expected_message:$message}')"
  for attempt in 1 2 3 4 5 6; do
    run_action "$edge-receive-$attempt" "$receiver" "$control"
    receive_result=$RUN_ACTION_OUTPUT
    if jq -e '.expected_incoming == true' "$receive_result" >/dev/null; then
      return 0
    fi
  done
  die "Direct receiver did not Pull and ACK exact message: $edge"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in adb flutter jq openssl sha256sum; do
  require_command "$command"
done
if [[ "$TARGET_MODE" == local ]]; then
  for command in docker ss; do
    require_command "$command"
  done
fi
[[ -d "$CLIENT_ROOT/.git" && -f "$FLUTTER_ROOT/pubspec.yaml" ]] ||
  die 'client repository is unavailable'
if [[ "$TARGET_MODE" == local ]]; then
  for port in \
    "$POSTGRES_PORT" \
    "$NODE_A_PORT" "$NODE_B_PORT" "$NODE_C_PORT" \
    "$REALTIME_A_PORT" "$REALTIME_B_PORT" "$REALTIME_C_PORT"; do
    valid_port "$port" || die "invalid port: $port"
    assert_port_free "$port"
  done
fi
for serial in "$SERIAL_A" "$SERIAL_B" "$SERIAL_C"; do
  assert_device "$serial"
done

mkdir -p -- "$EVIDENCE_ROOT"
printf '%s\n' \
  "server_commit=$(git -C "$SERVER_ROOT" rev-parse HEAD)" \
  "client_commit=$(git -C "$CLIENT_ROOT" rev-parse HEAD)" \
  "device_a=$SERIAL_A" \
  "device_b=$SERIAL_B" \
  "device_c=$SERIAL_C" \
  "target_mode=$TARGET_MODE" \
  "origin_a=$ORIGIN_A" \
  "origin_b=$ORIGIN_B" \
  "origin_c=$ORIGIN_C" \
  >"$EVIDENCE_ROOT/run.properties"

if [[ "$TARGET_MODE" == local ]]; then
  COMPOSE_STARTED=1
  compose up --detach --wait
  compose cp tls-bootstrap:/run/dtx-local-tls/ca.pem "$CA_LOCAL"
  CA_HASH="$(openssl x509 -hash -noout -in "$CA_LOCAL" | tr -d '\r\n')"
  [[ "$CA_HASH" =~ ^[0-9a-fA-F]{8}$ ]] || die 'local CA hash invalid'

  for serial in "$SERIAL_A" "$SERIAL_B" "$SERIAL_C"; do
    install_ca_if_needed "$serial"
    claim_reverse "$serial" 8443 "$NODE_A_PORT"
    claim_reverse "$serial" 8444 "$NODE_B_PORT"
    claim_reverse "$serial" 8445 "$NODE_C_PORT"
  done
fi

(
  cd -- "$FLUTTER_ROOT"
  flutter build apk --debug --no-pub
)
[[ -f "$APP_APK" ]] || die 'debug APK was not produced'
sha256sum "$APP_APK" >"$EVIDENCE_ROOT/app-debug.apk.sha256"

for serial in "$SERIAL_A" "$SERIAL_B" "$SERIAL_C"; do
  adb -s "$serial" uninstall "$PACKAGE" >/dev/null 2>&1 || true
  adb -s "$serial" install -t "$APP_APK" >/dev/null
done

run_action provision-a "$SERIAL_A" \
  "$(jq -nc --arg origin "$ORIGIN_A" '{action:"provision",origin:$origin}')" \
  >/dev/null
run_action provision-b "$SERIAL_B" \
  "$(jq -nc --arg origin "$ORIGIN_B" '{action:"provision",origin:$origin}')" \
  >/dev/null
run_action provision-c "$SERIAL_C" \
  "$(jq -nc --arg origin "$ORIGIN_C" '{action:"provision",origin:$origin}')" \
  >/dev/null

CONTACT_A_B='' CONTACT_B_A=''
CONTACT_B_C='' CONTACT_C_B=''
CONTACT_C_A='' CONTACT_A_C=''
establish_contact ab "$SERIAL_A" "$SERIAL_B" CONTACT_A_B CONTACT_B_A '' ''
establish_contact bc "$SERIAL_B" "$SERIAL_C" CONTACT_B_C CONTACT_C_B "$CONTACT_B_A" ''
establish_contact ca "$SERIAL_C" "$SERIAL_A" CONTACT_C_A CONTACT_A_C \
  "$CONTACT_C_B" "$CONTACT_A_B"

MESSAGE_AB="$(openssl rand -hex 24)"
MESSAGE_BC="$(openssl rand -hex 24)"
MESSAGE_CA="$(openssl rand -hex 24)"
send_direct ab "$SERIAL_A" "$SERIAL_B" "$CONTACT_A_B" "$MESSAGE_AB"
send_direct bc "$SERIAL_B" "$SERIAL_C" "$CONTACT_B_C" "$MESSAGE_BC"
send_direct ca "$SERIAL_C" "$SERIAL_A" "$CONTACT_C_A" "$MESSAGE_CA"

printf '%s\n' \
  'direct_ring=passed' \
  "actions=$ACTION_INDEX" \
  "apk_sha256=$(sha256sum "$APP_APK" | awk '{print $1}')" \
  >>"$EVIDENCE_ROOT/run.properties"
printf '%s\n' "internal-test-alpha-direct: PASS evidence=$EVIDENCE_ROOT"
