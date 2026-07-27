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
readonly EVIDENCE_ROOT="$SERVER_ROOT/artifacts/internal-test-alpha/$RUN_ID"
readonly SOURCE_RUN="${DTX_ALPHA_SOURCE_RUN:-"$SERVER_ROOT/artifacts/internal-test-alpha/remote-x345-20260728-0020"}"
readonly SERIAL_A="${DTX_ALPHA_DEVICE_A:-192.168.1.100:5555}"
readonly SERIAL_B="${DTX_ALPHA_DEVICE_B:-192.168.1.101:5555}"
readonly SERIAL_C="${DTX_ALPHA_DEVICE_C:-192.168.1.102:5555}"
readonly ORIGIN_A="${DTX_ALPHA_ORIGIN_A:-https://x3.dirextalk.ai/}"
readonly IDENTITY_ORIGIN_A="${ORIGIN_A%/}"
readonly IDENTITY_ORIGIN_B="${DTX_ALPHA_IDENTITY_ORIGIN_B:-https://x4.dirextalk.ai}"
readonly IDENTITY_ORIGIN_C="${DTX_ALPHA_IDENTITY_ORIGIN_C:-https://x5.dirextalk.ai}"

ACTION_INDEX=0
RUN_ACTION_OUTPUT=''
DISCOVERY_OUTPUT=''

die() {
  printf '%s\n' "internal-test-alpha-group: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null || die "$1 is required"
}

assert_device() {
  local serial=$1 state package_path
  state="$(adb -s "$serial" get-state 2>/dev/null || true)"
  [[ "$state" == device ]] || die "authorized device is unavailable: $serial"
  package_path="$(adb -s "$serial" shell pm path "$PACKAGE" 2>/dev/null | tr -d '\r')"
  [[ "$package_path" == package:* ]] || die "Direct-stage package is absent: $serial"
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

require_applied() {
  local label=$1 result=$2
  jq -e \
    '.requires_resolution == 0 and
     (.outcome == "applied" or .outcome == "retryPending")' \
    "$result" >/dev/null ||
    die "group action was not accepted: $label"
}

discover_until() {
  local label=$1 minimum=$2 control result
  control="$(jq -nc --arg origin "$ORIGIN_A" --arg scope "$SCOPE_ID" \
    '{action:"discover_group_joins",origin:$origin,scope_id:$scope}')"
  for attempt in 1 2 3 4 5 6; do
    run_action "$label-$attempt" "$SERIAL_A" "$control"
    result=$RUN_ACTION_OUTPUT
    if jq -e --argjson minimum "$minimum" \
      '.outcome == "ready" and
       (.policy_revision | type == "string") and
       (.sequencer_head | type == "string") and
       (.items | length) >= $minimum' \
      "$result" >/dev/null; then
      DISCOVERY_OUTPUT=$result
      return 0
    fi
  done
  die "owner did not discover pending joins: $label"
}

join_group() {
  local label=$1 serial=$2 invite=$3 discovery=$4 control result
  control="$(jq -nc \
    --arg origin "$ORIGIN_A" \
    --arg scope "$SCOPE_ID" \
    --arg invite "$invite" \
    --arg revision "$(jq -er '.policy_revision' "$discovery")" \
    --arg head "$(jq -er '.sequencer_head' "$discovery")" \
    '{action:"join_group",origin:$origin,scope_id:$scope,
      invite_id:$invite,policy_revision:$revision,sequencer_head:$head}')"
  run_action "$label" "$serial" "$control"
  result=$RUN_ACTION_OUTPUT
  require_applied "$label" "$result"
}

approve_join() {
  local label=$1 invite=$2 discovery=$3 item control result
  item="$(jq -cer --arg invite "$invite" \
    '[.items[] | select(.invite_id == $invite)] |
     if length == 1 then .[0] else error("exact pending join missing") end' \
    "$discovery")"
  control="$(jq -nc \
    --arg origin "$ORIGIN_A" \
    --arg scope "$SCOPE_ID" \
    --arg revision "$(jq -er '.policy_revision' "$discovery")" \
    --arg head "$(jq -er '.sequencer_head' "$discovery")" \
    --argjson item "$item" \
    '{action:"approve_group_join",origin:$origin,scope_id:$scope,
      policy_revision:$revision,sequencer_head:$head,
      join_request_id:$item.join_request_id,
      candidate_identity_id:$item.candidate_identity_id,
      candidate_device_id:$item.candidate_device_id,
      invite_id:$item.invite_id}')"
  run_action "$label" "$SERIAL_A" "$control"
  result=$RUN_ACTION_OUTPUT
  require_applied "$label" "$result"
}

reconcile_member() {
  local label=$1 serial=$2 result control
  control="$(jq -nc --arg scope "$SCOPE_ID" \
    '{action:"reconcile_group",scope_id:$scope}')"
  for attempt in 1 2 3 4 5 6; do
    run_action "$label-$attempt" "$serial" "$control"
    result=$RUN_ACTION_OUTPUT
    if jq -e \
      '.requires_resolution == 0 and
       .timeline_availability == "ready" and
       (.membership_committed >= 1 or .member_count >= 2)' \
      "$result" >/dev/null; then
      return 0
    fi
  done
  die "group member did not commit and become timeline-ready: $label"
}

receive_group() {
  local label=$1 serial=$2 control result
  control="$(jq -nc --arg scope "$SCOPE_ID" --arg message "$MESSAGE" \
    '{action:"sync_group",scope_id:$scope,expected_message:$message}')"
  for attempt in 1 2 3 4 5 6; do
    run_action "$label-$attempt" "$serial" "$control"
    result=$RUN_ACTION_OUTPUT
    if jq -e \
      '.availability == "ready" and .expected_incoming == true' \
      "$result" >/dev/null; then
      return 0
    fi
  done
  die "group member did not Pull and ACK exact message: $label"
}

for command in adb find flutter jq openssl rg sha256sum sort xargs; do
  require_command "$command"
done
[[ -d "$CLIENT_ROOT/.git" && -f "$FLUTTER_ROOT/pubspec.yaml" ]] ||
  die 'client repository is unavailable'
[[ -f "$SOURCE_RUN/run.properties" ]] ||
  die 'Direct-stage evidence is unavailable'
rg -N -x 'direct_ring=passed' "$SOURCE_RUN/run.properties" >/dev/null ||
  die 'Direct-stage evidence is not passed'
CONTACT_A_B="$(jq -er \
  'if (.contacts | length) == 1
   then .contacts[0].contact_id
   else error("A-B contact evidence is ambiguous")
   end' "$SOURCE_RUN/008-ab-inviter-reconcile.json")"
CONTACT_A_C="$(jq -er --arg existing "$CONTACT_A_B" \
  '[.contacts[].contact_id | select(. != $existing)] |
   if length == 1
   then .[0]
   else error("A-C contact evidence is ambiguous")
   end' "$SOURCE_RUN/017-ca-importer-reconcile.json")"
for serial in "$SERIAL_A" "$SERIAL_B" "$SERIAL_C"; do
  assert_device "$serial"
done

mkdir -p -- "$EVIDENCE_ROOT"
printf '%s\n' \
  "server_commit=$(git -C "$SERVER_ROOT" rev-parse HEAD)" \
  "client_commit=$(git -C "$CLIENT_ROOT" rev-parse HEAD)" \
  "source_direct_evidence=$SOURCE_RUN" \
  "device_a=$SERIAL_A" \
  "device_b=$SERIAL_B" \
  "device_c=$SERIAL_C" \
  "origin_a=$ORIGIN_A" \
  >"$EVIDENCE_ROOT/run.properties"

run_action refresh-identity-a "$SERIAL_A" \
  "$(jq -nc --arg origin "$IDENTITY_ORIGIN_A" \
    '{action:"provision",origin:$origin}')"
run_action refresh-identity-b "$SERIAL_B" \
  "$(jq -nc --arg origin "$IDENTITY_ORIGIN_B" \
    '{action:"provision",origin:$origin}')"
run_action refresh-identity-c "$SERIAL_C" \
  "$(jq -nc --arg origin "$IDENTITY_ORIGIN_C" \
    '{action:"provision",origin:$origin}')"

run_action create-group "$SERIAL_A" \
  "$(jq -nc --arg origin "$ORIGIN_A" \
    '{action:"create_group",origin:$origin}')"
CREATE_RESULT=$RUN_ACTION_OUTPUT
require_applied create-group "$CREATE_RESULT"
SCOPE_ID="$(jq -er '.scope_id' "$CREATE_RESULT")"

run_action issue-invite-b "$SERIAL_A" \
  "$(jq -nc --arg origin "$ORIGIN_A" --arg scope "$SCOPE_ID" \
    --arg contact "$CONTACT_A_B" \
    '{action:"issue_group_invite",origin:$origin,scope_id:$scope,
      contact_id:$contact}')"
INVITE_B_RESULT=$RUN_ACTION_OUTPUT
require_applied issue-invite-b "$INVITE_B_RESULT"
INVITE_B="$(jq -er '.invite_id' "$INVITE_B_RESULT")"

run_action issue-invite-c "$SERIAL_A" \
  "$(jq -nc --arg origin "$ORIGIN_A" --arg scope "$SCOPE_ID" \
    --arg contact "$CONTACT_A_C" \
    '{action:"issue_group_invite",origin:$origin,scope_id:$scope,
      contact_id:$contact}')"
INVITE_C_RESULT=$RUN_ACTION_OUTPUT
require_applied issue-invite-c "$INVITE_C_RESULT"
INVITE_C="$(jq -er '.invite_id' "$INVITE_C_RESULT")"
[[ "$INVITE_B" != "$INVITE_C" ]] || die 'group invites are not distinct'

discover_until owner-head 0
JOIN_HEAD=$DISCOVERY_OUTPUT
join_group join-b "$SERIAL_B" "$INVITE_B" "$JOIN_HEAD"

discover_until pending-b 1
PENDING_B=$DISCOVERY_OUTPUT
join_group join-c "$SERIAL_C" "$INVITE_C" "$PENDING_B"

discover_until pending-bc 2
PENDING_BC=$DISCOVERY_OUTPUT
approve_join approve-b "$INVITE_B" "$PENDING_BC"
discover_until pending-c 1
PENDING_C=$DISCOVERY_OUTPUT
approve_join approve-c "$INVITE_C" "$PENDING_C"

reconcile_member reconcile-b "$SERIAL_B"
reconcile_member reconcile-c "$SERIAL_C"
run_action reconcile-owner "$SERIAL_A" \
  "$(jq -nc --arg scope "$SCOPE_ID" \
    '{action:"reconcile_group",scope_id:$scope}')"
jq -e \
  '.requires_resolution == 0 and
   .timeline_availability == "ready" and .member_count >= 2' \
  "$RUN_ACTION_OUTPUT" >/dev/null ||
  die 'owner did not observe both committed group members'

MESSAGE="$(openssl rand -hex 24)"
run_action send-group "$SERIAL_A" \
  "$(jq -nc --arg scope "$SCOPE_ID" --arg message "$MESSAGE" \
    '{action:"send_group",scope_id:$scope,message:$message}')"
jq -e '.delivery == "delivered" or .delivery == "pending"' \
  "$RUN_ACTION_OUTPUT" >/dev/null ||
  die 'group message was not durably queued'
receive_group receive-b "$SERIAL_B"
receive_group receive-c "$SERIAL_C"

find "$FLUTTER_ROOT/build" -type f -name '*.apk' -print0 |
  sort -z |
  xargs -0 -r sha256sum >"$EVIDENCE_ROOT/apk-sha256.txt"
printf '%s\n' \
  "scope_id=$SCOPE_ID" \
  'group_membership=passed' \
  'group_delivery_b=passed' \
  'group_delivery_c=passed' \
  "actions=$ACTION_INDEX" \
  >>"$EVIDENCE_ROOT/run.properties"
printf '%s\n' "internal-test-alpha-group: PASS evidence=$EVIDENCE_ROOT"
