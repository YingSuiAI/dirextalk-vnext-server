#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
script="$root/scripts/android-acceptance.sh"
tmp="$(mktemp -d)"
test_shell_pid=$BASHPID
cleanup_fixture_processes() {
  local pid pgid cmd
  while read -r pid pgid cmd; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$pgid" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$pid" == "$BASHPID" || "$pid" == "$test_shell_pid" ]] && continue
    if [[ "$cmd" == *'/target/debug/'* ]]; then
      [[ "$cmd" == *"$tmp/"* ]] || continue
    elif [[ "$cmd" == *'emulator -avd dirextalk-accept-console-extra-'* ]]; then
      :
    else
      continue
    fi
    kill -KILL -- "-$pgid" 2>/dev/null || true
  done < <(ps -eo pid=,pgid=,cmd=)
}
cleanup_test_tmp() {
  local status=$?
  [[ $BASHPID == "$test_shell_pid" ]] || return "$status"
  if (( status != 0 )); then
    printf 'android self-test diagnostics (status=%s, tmp=%s)\n' "$status" "$tmp" >&2
    while IFS= read -r log; do
      printf '%s\n' "--- $log (tail)" >&2
      tail -40 "$log" >&2 || true
    done < <(find "$tmp" -type f -name log -print 2>/dev/null)
    ps -eo pid,ppid,stat,cmd | rg -F "$tmp" >&2 || true
  fi
  cleanup_fixture_processes
  rm -rf -- "$tmp"
  return "$status"
}
trap cleanup_test_tmp EXIT

dry_run_id="dry-run-no-mutation-$$"
dry_state="$root/.android-acceptance/$dry_run_id"
dry_evidence="$root/artifacts/android-acceptance/$dry_run_id"
[[ ! -e "$dry_state" && ! -e "$dry_evidence" ]]
DTX_ANDROID_ACCEPTANCE_RUN_ID="$dry_run_id" "$script" --dry-run
[[ ! -e "$dry_state" && ! -e "$dry_evidence" ]] || { printf '%s\n' 'dry-run mutated state' >&2; exit 1; }
DTX_ANDROID_ACCEPTANCE_RUN_ID=safe-run "$script" --self-test
if DTX_ANDROID_ACCEPTANCE_RUN_ID='../unsafe' "$script" --self-test >/dev/null 2>&1; then
  printf '%s\n' 'unsafe run id was accepted' >&2; exit 1
fi

make_fixture() {
  local fixture=$1
  mkdir -p "$fixture/scripts" "$fixture/bin" "$fixture/target/debug" "$fixture/maps" "$fixture/proxy-ports" "$fixture/sdk/platforms/android-35" "$fixture/sdk/build-tools/35.0.0"
  cp "$script" "$fixture/scripts/android-acceptance.sh"
  cp "$root/scripts/android-platform-trust-probe.java" "$fixture/scripts/android-platform-trust-probe.java"
  : >"$fixture/sdk/platforms/android-35/android.jar"
  : >"$fixture/docker-compose.local.yml"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "cargo $*" >>"$DTX_TEST_LOG"' '[[ "${DTX_TEST_CARGO_SLEEP:-0}" == 1 ]] && sleep 5' 'exit 0' >"$fixture/bin/cargo"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "docker $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" up "*) if [[ "${DTX_TEST_COMPOSE_UP:-ok}" == fail ]]; then exit 1; fi; sleep "${DTX_TEST_COMPOSE_SLEEP:-0}";; *" cp "*) dest="${*: -1}"; mkdir -p "$(dirname "$dest")"; printf ca-fixture >"$dest";; esac' 'exit 0' >"$fixture/bin/docker"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "avdmanager $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" list avd "*) [[ "${DTX_TEST_AVD_PRESENT:-}" == 1 ]] && printf "    Name: %s\n" "${DTX_TEST_AVD_NAME:-}";; *" create avd "*) [[ "${DTX_TEST_AVD_CREATE:-ok}" == ok ]] || exit 1;; *" delete avd "*) [[ "${DTX_TEST_AVD_DELETE:-ok}" == ok ]] || exit 1;; esac' 'exit 0' >"$fixture/bin/avdmanager"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'echo "adb $DTX_TEST_RUN_ID $*" >>"$DTX_TEST_LOG"' \
    'serial=""; [[ "${1:-}" != -s ]] || { serial=$2; shift 2; }' \
    'case " $* " in' \
    ' *" devices "*) printf "%s" "${DTX_TEST_ADB_DEVICES:-}";;' \
    ' *" wait-for-device "*) while [[ ! -f "$DTX_TEST_MAP/$serial" ]]; do :; done; exit 0;;' \
    ' *" emu avd name "*) if [[ "${DTX_TEST_CONSOLE_EXTRA:-}" == 1 ]]; then cat "$DTX_TEST_MAP/$serial"; printf "WRONG\nOK\n"; elif [[ "${DTX_TEST_CONSOLE_CRLF:-}" == 1 ]]; then cat "$DTX_TEST_MAP/$serial" | tr "\n" "\r\n"; printf "\r\nOK\r\n"; else cat "$DTX_TEST_MAP/$serial"; printf "OK\n"; fi;;' \
    ' *" remount "*) marker="$DTX_TEST_ROOT/remount-$DTX_TEST_RUN_ID-$serial"; if [[ ! -e "$marker" ]]; then : >"$marker"; printf "Successfully disabled verity\n"; else printf "remount succeeded\n"; fi;;' \
    ' *" reboot "*) :;;' \
    ' *" root "*) [[ -f "$DTX_TEST_MAP/$serial" ]] || exit 1;;' \
    ' *" shell "*) if [[ "$*" == *app_process* ]]; then [[ "${DTX_TEST_APP_PROCESS_SLEEP:-}" == 1 ]] && sleep 5; nonce=$(printf "%s" "$*" | grep -oE "[0-9a-f]{32}" | tail -n 1); : >"$DTX_TEST_ROOT/app-process-$serial"; result_file="$DTX_TEST_ROOT/result-$serial-$nonce"; if [[ "${DTX_TEST_TRUST_LOST:-}" != 1 ]]; then if [[ "${DTX_TEST_TRUST_NONCE_MISMATCH:-}" == 1 ]]; then printf "TRUSTED wrongnonce\n" >"$result_file"; elif [[ "${DTX_TEST_TRUST_WRONG_FAILURE:-}" == 1 ]]; then printf "CONNECT_FAILED %s\n" "$nonce" >"$result_file"; elif [[ "${DTX_TEST_TRUST_PRETRUST:-}" == 1 || -f "$DTX_TEST_ROOT/trust-$serial" ]]; then printf "TRUSTED %s\n" "$nonce" >"$result_file"; else printf "UNTRUSTED %s\n" "$nonce" >"$result_file"; fi; fi; if [[ "${DTX_TEST_TRUST_FAIL:-}" == 1 ]]; then exit 1; fi; elif [[ "$*" == *cat*result-* ]]; then nonce=$(printf "%s" "$*" | grep -oE "result-[0-9a-f]{32}" | tail -n 1 | cut -d- -f2); cat "$DTX_TEST_ROOT/result-$serial-$nonce"; elif [[ "$*" == *cp* && "$*" == *cacerts* ]]; then : >"$DTX_TEST_ROOT/trust-$serial"; elif [[ "$*" == *sha256sum* ]]; then sha256sum "$DTX_TEST_ROOT/.android-acceptance/$DTX_TEST_RUN_ID/tls/ca.pem"; elif [[ "$*" == *stat* ]]; then printf "644 0 0\n"; elif [[ "$*" == *ls*Z* ]]; then printf "u:object_r:system_file:s0 root root\n"; elif [[ "$*" == *getprop* ]]; then printf "1\n"; elif [[ "$*" == *id* ]]; then printf "0\n"; fi;;' \
    ' *" push "*) [[ -f "$DTX_TEST_MAP/$serial" ]] || exit 1; [[ "${DTX_TEST_TRUST_PUSH_FAIL:-}" == 1 && "$*" == *classes.dex* ]] && exit 1 || true;;' \
    ' *" reverse tcp:8443 "*) if [[ "${DTX_TEST_REVERSE_FAIL_AFTER:-}" == 1 && "$serial" == "$(awk -F= '\''$1 == "emulator_a_serial" { print $2 }'\'' "$DTX_TEST_ROOT/.android-acceptance/$DTX_TEST_RUN_ID/resources")" ]]; then echo "reverse-side-effect $DTX_TEST_RUN_ID $serial" >>"$DTX_TEST_LOG"; exit 1; fi; [[ "${DTX_TEST_REVERSE:-ok}" == ok ]] || exit 1; [[ "${DTX_TEST_REVERSE_SLEEP:-0}" == 0 ]] || sleep "${DTX_TEST_REVERSE_SLEEP}";;' \
    ' *" reverse --remove tcp:8443 "*) echo "reverse-remove $DTX_TEST_RUN_ID $serial" >>"$DTX_TEST_LOG";;' \
    'esac' >"$fixture/bin/adb"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "emulator $DTX_TEST_RUN_ID $*" >>"$DTX_TEST_LOG"' 'avd=""; port=""; while (($#)); do case "$1" in -avd) avd=$2; shift 2;; -port) port=$2; shift 2;; *) shift;; esac; done' 'tmp_map="$DTX_TEST_MAP/.emulator-$port.$$"; printf "%s\n" "$avd" >"$tmp_map"; mv -f -- "$tmp_map" "$DTX_TEST_MAP/emulator-$port"' 'exec python3 -c '\''import signal,sys; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); signal.pause()'\'' emulator -avd "$avd" -port "$port"' >"$fixture/bin/emulator"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '[[ "${DTX_TEST_OPENSSL_SLEEP:-0}" == 1 ]] && sleep 5' '[[ "${1:-}" != rand ]] || { printf "0123456789abcdef0123456789abcdef\n"; exit 0; }' 'printf "deadbeef\n"' >"$fixture/bin/openssl"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '[[ "${DTX_TEST_SHA256_SLEEP:-0}" == 1 ]] && sleep 5' 'exec /usr/bin/sha256sum "$@"' >"$fixture/bin/sha256sum"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '[[ "${DTX_TEST_STAT_SLEEP:-0}" == 1 ]] && sleep 5' 'exec /usr/bin/stat "$@"' >"$fixture/bin/stat"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '[[ "${DTX_TEST_MKDIR_SLEEP:-0}" == 1 ]] && sleep 5' 'exec /usr/bin/mkdir "$@"' >"$fixture/bin/mkdir"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'target="${!#}"; target="${target%/}"' '[[ "$target" == /* ]] || target="$PWD/$target"' '[[ -z "${DTX_TEST_RM_LOG:-}" ]] || printf "%s\n" "$target" >>"$DTX_TEST_RM_LOG"' 'if [[ "${DTX_TEST_RM_PENDING_FAIL:-0}" == 1 && "$target" == */pending-guardian ]]; then exit 1; fi' 'if [[ "${DTX_TEST_RM_ROOT_FAIL:-0}" == 1 && "$target" == "$DTX_TEST_ROOT/.android-acceptance/$DTX_TEST_RUN_ID" ]]; then exit 1; fi' 'if [[ "${DTX_TEST_RM_PENDING_SLEEP:-0}" == 1 && "$target" == */pending-guardian ]]; then sleep 5; fi' 'if [[ "${DTX_TEST_RM_ROOT_SLEEP:-0}" == 1 && "$target" == "$DTX_TEST_ROOT/.android-acceptance/$DTX_TEST_RUN_ID" ]]; then sleep 5; fi' 'exec /usr/bin/rm "$@"' >"$fixture/bin/rm"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '[[ "${DTX_TEST_SORT_SLEEP:-0}" == 1 ]] && sleep 5' 'exec /usr/bin/sort "$@"' >"$fixture/bin/sort"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "javac $*" >>"$DTX_TEST_LOG"' 'if [[ "$*" == *"-version"* ]]; then [[ "${DTX_TEST_JAVAC_VERSION_SLEEP:-0}" == 1 ]] && sleep 5; printf "javac 17.0.0\n" >&2; exit 0; fi' '[[ "${DTX_TEST_JAVAC_COMPILE_SLEEP:-0}" == 1 ]] && sleep 5' 'while (($#)); do if [[ "$1" == -d ]]; then mkdir -p "$2"; : >"$2/PlatformTrustProbe.class"; break; fi; shift; done' >"$fixture/bin/javac"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "d8 $*" >>"$DTX_TEST_LOG"' '[[ "${DTX_TEST_D8_SLEEP:-0}" == 1 ]] && sleep 5' 'while (($#)); do if [[ "$1" == --output ]]; then mkdir -p "$2"; : >"$2/classes.dex"; break; fi; shift; done' >"$fixture/sdk/build-tools/35.0.0/d8"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'if [[ "${DTX_TEST_PS_SLEEP_ON_MARKER:-0}" == 1 && -e "$DTX_TEST_ROOT/cleanup-probe-marker" ]]; then echo "ps cleanup probe" >>"$DTX_TEST_LOG"; sleep 5; fi' 'exec /usr/bin/ps "$@"' >"$fixture/bin/ps"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'if [[ "${DTX_TEST_SS_SLEEP_ON_MARKER:-0}" == 1 && -e "$DTX_TEST_ROOT/cleanup-probe-marker" ]]; then echo "ss cleanup probe" >>"$DTX_TEST_LOG"; sleep 5; fi' 'port="${*: -1}"; port="${port##*:}"; if [[ -f "${DTX_TEST_PROXY_PORTS:-/nonexistent}/$port" ]]; then printf "LISTEN\n"; fi' >"$fixture/bin/ss"
  chmod +x "$fixture/bin"/* "$fixture/sdk/build-tools/35.0.0/d8"
}

run_fixture() {
  local fixture=$1 run_id=$2
  shift 2
  if [[ "${DTX_TEST_EXEC:-}" == 1 ]]; then
    exec env PATH="$fixture/bin:$PATH" DTX_ANDROID_TEST_MODE=1 DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_TEST_ROOT="$fixture" DTX_TEST_MAP="$fixture/maps" DTX_TEST_PROXY_PORTS="$fixture/proxy-ports" DTX_ANDROID_SYSTEM_IMAGE='system-images;android-35;aosp_atd;x86_64' DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
  fi
  PATH="$fixture/bin:$PATH" DTX_ANDROID_TEST_MODE=1 DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_TEST_ROOT="$fixture" DTX_TEST_MAP="$fixture/maps" DTX_TEST_PROXY_PORTS="$fixture/proxy-ports" DTX_ANDROID_SYSTEM_IMAGE='system-images;android-35;aosp_atd;x86_64' DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
}
run_fixture_isolated() {
  local fixture=$1 run_id=$2
  shift 2
  trap - EXIT
  exec setsid env PATH="$fixture/bin:$PATH" DTX_ANDROID_TEST_MODE=1 DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_TEST_ROOT="$fixture" DTX_TEST_MAP="$fixture/maps" DTX_TEST_PROXY_PORTS="$fixture/proxy-ports" DTX_ANDROID_SYSTEM_IMAGE='system-images;android-35;aosp_atd;x86_64' DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
}

wait_until() {
  local timeout_seconds=$1 label=$2
  shift 2
  local deadline=$((SECONDS + timeout_seconds))
  while ! "$@"; do
    if (( SECONDS >= deadline )); then
      printf 'android self-test: timed out waiting for %s\n' "$label" >&2
      return 1
    fi
    # Readiness predicates, not this yield interval, determine progress.  The
    # bounded yield keeps repeated self-tests from monopolizing a CPU.
    sleep 0.01
  done
}

path_exists() { [[ -e "$1" ]]; }
dir_exists() { [[ -d "$1" ]]; }
log_count_at_least() {
  local pattern=$1 minimum=$2 log=$3 count
  count=$(rg -c "$pattern" "$log" 2>/dev/null || true)
  [[ "$count" =~ ^[0-9]+$ ]] && (( count >= minimum ))
}
log_contains() { rg -F -- "$1" "$2" >/dev/null 2>&1; }
pid_gone() { ! kill -0 "$1" 2>/dev/null; }
guardian_log_dead() {
  local file=$1 pid start extra stat rest; local -a fields=(); local count=0
  [[ -s "$file" ]] || return 1
  while IFS=' ' read -r pid start extra; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$start" =~ ^[1-9][0-9]*$ && -z "$extra" ]] || return 1
    ((count += 1))
    if [[ -r "/proc/$pid/stat" ]]; then
      stat="$(<"/proc/$pid/stat")"; rest=${stat#*) }; IFS=' ' read -r -a fields <<<"$rest"
      [[ "${fields[0]:-}" == Z || "${fields[19]:-}" != "$start" ]] || return 1
    fi
  done <"$file"
  (( count > 0 ))
}
only_state_dir() {
  local root=$1 expected=$2 entry
  shopt -s nullglob
  for entry in "$root"/*; do [[ ! -d "$entry" || "$entry" == "$expected" ]] || { shopt -u nullglob; return 1; }; done
  shopt -u nullglob
}
kill_descendants() {
  local root=$1 child
  while read -r child; do
    [[ -n "$child" ]] || continue
    kill_descendants "$child"
    kill -TERM "$child" 2>/dev/null || true
    kill -KILL "$child" 2>/dev/null || true
  done < <(pgrep -P "$root" 2>/dev/null || true)
}
concurrent_remounts_ready() {
  local log=$1 run ready
  for run in concurrent-a concurrent-b; do
    [[ $(rg -c "^adb $run -s .* remount$" "$log" 2>/dev/null || true) -ge 4 ]] || return 1
  done
  return 0
}

# A partially-started compose project is owned before `up`; failure therefore
# still invokes exact-project teardown.
fixture="$tmp/compose"; make_fixture "$fixture"
if DTX_TEST_COMPOSE_UP=fail run_fixture "$fixture" compose-partial env; then exit 1; fi
rg -F -- '--project-name dtx-android-accept-compose-partial down' "$fixture/log" >/dev/null

# Proxy PID ownership is recorded before readiness failure, and cleanup keeps
# removing later resources even when AVD deletion fails.
fixture="$tmp/proxy"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; printf "%s\n" "$listen" >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''echo "proxy-term $listen $control" >>"$DTX_TEST_LOG"; rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if DTX_TEST_AVD_DELETE=fail run_fixture "$fixture" proxy-partial env; then exit 1; fi
proxy_root="$fixture/.android-acceptance/proxy-partial"; proxy_pid="$(awk -F= '$1 == "PROXY_A_PID" { print $2 }' "$proxy_root/resources")"
[[ "$proxy_pid" =~ ^[1-9][0-9]*$ ]] && ! kill -0 "$proxy_pid" 2>/dev/null
[[ ! -e "$fixture/proxy-ports/$(awk -F= '$1 == "proxy_a_port" { print $2 }' "$proxy_root/resources")" ]]
[[ ! -e "$fixture/proxy-ports/$(awk -F= '$1 == "control_a_port" { print $2 }' "$proxy_root/resources")" ]]
rg -F 'proxy-term ' "$fixture/log" >/dev/null
rg -F -- 'delete avd --name dirextalk-accept-proxy-partial-a' "$fixture/log" >/dev/null
rg -F -- 'delete avd --name dirextalk-accept-proxy-partial-b' "$fixture/log" >/dev/null
rg -F -- '--project-name dtx-android-accept-proxy-partial down' "$fixture/log" >/dev/null
[[ "$(<"$proxy_root/cleanup-status")" == cleanup=failed ]]

# A guardian is durable cleanup state before child PID readiness.  Missing and
# delayed PID files, and an immediately exiting child, must leave neither a
# live guardian nor a claimed run root behind.
for startup_case in missing-pid-file delayed-pid-file child-exits; do
  fixture="$tmp/$startup_case"; make_fixture "$fixture"
  case "$startup_case" in
    missing-pid-file) if DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" DTX_TEST_GUARDIAN_PID_FILE_MISSING=1 run_fixture "$fixture" "$startup_case" env >/dev/null 2>&1; then exit 1; fi ;;
    delayed-pid-file) if DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" DTX_TEST_GUARDIAN_PID_FILE_DELAY=10 run_fixture "$fixture" "$startup_case" env >/dev/null 2>&1; then exit 1; fi ;;
    child-exits) printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$fixture/bin/emulator"; chmod +x "$fixture/bin/emulator"; if DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" "$startup_case" env >/dev/null 2>&1; then exit 1; fi ;;
  esac
  [[ -s "$fixture/guardian-pids" && ! -e "$fixture/.android-acceptance/$startup_case" ]]
  guardian_log_dead "$fixture/guardian-pids"
done

# Readiness itself has the same bounded cleanup path after a fully recorded
# proxy starts but never binds either owned listener.
fixture="$tmp/proxy-readiness"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" proxy-readiness env >/dev/null 2>&1; then exit 1; fi
[[ -s "$fixture/guardian-pids" && ! -e "$fixture/.android-acceptance/proxy-readiness" ]]
guardian_log_dead "$fixture/guardian-pids"

# A signal after formal slot recording but before pending removal has two
# cleanup-visible owners for the same guardian; cleanup deduplicates them and
# cannot leave the guardian running.
fixture="$tmp/promotion-signal"; make_fixture "$fixture"
if DTX_TEST_SIGNAL_AT_PROMOTION=1 DTX_TEST_RM_LOG="$fixture/rm-log" DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" promotion-signal env >/dev/null 2>&1; then exit 1; fi
[[ -s "$fixture/guardian-pids" && ! -e "$fixture/.android-acceptance/promotion-signal" ]]
guardian_log_dead "$fixture/guardian-pids"
rg -Fx "$fixture/.android-acceptance/promotion-signal/pending-guardian" "$fixture/rm-log" >/dev/null

# Failure or timeout while removing the pending slot retains explicit state
# after killing the authorized guardian; final root removal is never attempted.
for rm_case in pending-rm-fail pending-rm-hung; do
  fixture="$tmp/$rm_case"; make_fixture "$fixture"
  case "$rm_case" in
    pending-rm-fail) if DTX_TEST_RM_PENDING_FAIL=1 DTX_TEST_RM_LOG="$fixture/rm-log" DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" "$rm_case" env >/dev/null 2>&1; then exit 1; fi ;;
    pending-rm-hung) if DTX_TEST_RM_PENDING_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 DTX_TEST_RM_LOG="$fixture/rm-log" DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" "$rm_case" env >/dev/null 2>&1; then exit 1; fi ;;
  esac
  rm_root="$fixture/.android-acceptance/$rm_case"
  [[ -f "$rm_root/pending-guardian" && "$(<"$rm_root/cleanup-status")" == cleanup=failed ]]
  rg -Fx "$rm_root/pending-guardian" "$fixture/rm-log" >/dev/null
  guardian_log_dead "$fixture/guardian-pids"
  only_state_dir "$fixture/.android-acceptance" "$rm_root"
done

# A final root removal failure leaves the narrow claimed root intact and never
# reaches a sibling sentinel.
fixture="$tmp/root-rm-fail"; make_fixture "$fixture"; mkdir "$fixture/sentinel"; printf keep >"$fixture/sentinel/keep"
if DTX_TEST_RM_ROOT_FAIL=1 DTX_TEST_RM_LOG="$fixture/rm-log" DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" root-rm-fail env >/dev/null 2>&1; then exit 1; fi
[[ -d "$fixture/.android-acceptance/root-rm-fail" && "$(<"$fixture/sentinel/keep")" == keep ]]
rg -Fx "$fixture/.android-acceptance/root-rm-fail" "$fixture/rm-log" >/dev/null; guardian_log_dead "$fixture/guardian-pids"; only_state_dir "$fixture/.android-acceptance" "$fixture/.android-acceptance/root-rm-fail"
fixture="$tmp/root-rm-hung"; make_fixture "$fixture"; mkdir "$fixture/sentinel"; printf keep >"$fixture/sentinel/keep"
if DTX_TEST_RM_ROOT_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 DTX_TEST_RM_LOG="$fixture/rm-log" DTX_TEST_GUARDIAN_PID_LOG="$fixture/guardian-pids" run_fixture "$fixture" root-rm-hung env >/dev/null 2>&1; then exit 1; fi
[[ -d "$fixture/.android-acceptance/root-rm-hung" && "$(<"$fixture/sentinel/keep")" == keep ]]
rg -Fx "$fixture/.android-acceptance/root-rm-hung" "$fixture/rm-log" >/dev/null; guardian_log_dead "$fixture/guardian-pids"; only_state_dir "$fixture/.android-acceptance" "$fixture/.android-acceptance/root-rm-hung"

# A symlinked state root is rejected before any external command and never
# turns cleanup into an outside-tree deletion.
fixture="$tmp/symlink"; make_fixture "$fixture"; mkdir "$fixture/outside"; printf keep >"$fixture/outside/sentinel"; ln -s "$fixture/outside" "$fixture/.android-acceptance"
if run_fixture "$fixture" symlink-root env >/dev/null 2>&1; then exit 1; fi
[[ "$(<"$fixture/outside/sentinel")" == keep ]] && [[ ! -e "$fixture/outside/symlink-root" ]]

# Different live RUN_IDs reserve disjoint port/serial blocks under the global
# allocator lock; a duplicate RUN_ID is rejected while its reservation exists.
fixture="$tmp/allocator"; make_fixture "$fixture"
DTX_TEST_COMPOSE_SLEEP=3 run_fixture_isolated "$fixture" allocator-a env & first=$!
wait_until 30 allocator-a-resources path_exists "$fixture/.android-acceptance/allocator-a/resources"
wait_until 30 allocator-a-compose-start log_contains "docker compose --project-directory $fixture -f $fixture/docker-compose.local.yml --project-name dtx-android-accept-allocator-a up --detach --wait" "$fixture/log"
DTX_TEST_COMPOSE_SLEEP=3 run_fixture_isolated "$fixture" allocator-b env & second=$!
wait_until 30 allocator-b-resources path_exists "$fixture/.android-acceptance/allocator-b/resources"
if DTX_TEST_COMPOSE_SLEEP=3 run_fixture "$fixture" allocator-a env >/dev/null 2>&1; then exit 1; fi
! cmp -s "$fixture/.android-acceptance/allocator-a/resources" "$fixture/.android-acceptance/allocator-b/resources"
for field in node_a_port node_b_port proxy_a_port control_a_port proxy_b_port control_b_port emulator_a_port emulator_b_port emulator_a_serial emulator_b_serial; do
  first_value="$(awk -F= -v field="$field" '$1 == field { print $2 }' "$fixture/.android-acceptance/allocator-a/resources")"
  second_value="$(awk -F= -v field="$field" '$1 == field { print $2 }' "$fixture/.android-acceptance/allocator-b/resources")"
  [[ -n "$first_value" && "$first_value" != "$second_value" ]]
done
kill -TERM "$first" "$second"
if wait "$first"; then allocator_first_status=0; else allocator_first_status=$?; fi
if wait "$second"; then allocator_second_status=0; else allocator_second_status=$?; fi
[[ "$allocator_first_status" == 0 || "$allocator_first_status" == 143 || "$allocator_first_status" == 1 ]] &&
  [[ "$allocator_second_status" == 0 || "$allocator_second_status" == 143 || "$allocator_second_status" == 1 ]]
[[ ! -e "$fixture/.android-acceptance/allocator-a" && ! -e "$fixture/.android-acceptance/allocator-b" ]]

# Two live runs reach emulator ownership verification, root/CA installation and
# proxy mapping concurrently.  Every adb target remains owned by its RUN_ID.
fixture="$tmp/concurrent"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
DTX_TEST_REVERSE_SLEEP=1 run_fixture_isolated "$fixture" concurrent-a env & first=$!
wait_until 30 concurrent-a-resources path_exists "$fixture/.android-acceptance/concurrent-a/resources"
wait_until 30 concurrent-a-compose-start log_contains "docker compose --project-directory $fixture -f $fixture/docker-compose.local.yml --project-name dtx-android-accept-concurrent-a up --detach --wait" "$fixture/log"
DTX_TEST_REVERSE_SLEEP=1 run_fixture_isolated "$fixture" concurrent-b env & second=$!
wait_until 30 concurrent-reverse log_count_at_least '^adb concurrent-[ab] .* reverse tcp:8443 ' 2 "$fixture/log"
wait_until 30 concurrent-trust-probes log_count_at_least '^adb concurrent-[ab] .* shell app_process ' 4 "$fixture/log"
wait_until 30 concurrent-remounts concurrent_remounts_ready "$fixture/log"
for run in concurrent-a concurrent-b; do
  resource="$fixture/.android-acceptance/$run/resources"; [[ -f "$resource" ]]
  serial_a="$(awk -F= '$1 == "emulator_a_serial" { print $2 }' "$resource")"; serial_b="$(awk -F= '$1 == "emulator_b_serial" { print $2 }' "$resource")"
  printf '%s\n%s\n' "$serial_a" "$serial_b" >"$fixture/$run.serials"
  avd_a="dirextalk-accept-$run-a"; avd_b="dirextalk-accept-$run-b"
  [[ "$(<"$fixture/maps/$serial_a")" == "$avd_a" && "$(<"$fixture/maps/$serial_b")" == "$avd_b" ]]
  rg -F "adb $run -s $serial_a root" "$fixture/log" >/dev/null; rg -F "adb $run -s $serial_b root" "$fixture/log" >/dev/null
  rg -F "adb $run -s $serial_a push" "$fixture/log" >/dev/null; rg -F "adb $run -s $serial_b push" "$fixture/log" >/dev/null
  ! rg --pcre2 "^adb $run -s (?!$serial_a |$serial_b )" "$fixture/log" >/dev/null
  rg -F "emulator $run -avd dirextalk-accept-$run-a -port " "$fixture/log" | rg -F -- '-accel off -cores 2 -memory 2048 -gpu swiftshader_indirect -writable-system' >/dev/null
  rg -F "emulator $run -avd dirextalk-accept-$run-b -port " "$fixture/log" | rg -F -- '-accel off -cores 2 -memory 2048 -gpu swiftshader_indirect -writable-system' >/dev/null
  [[ "$(rg -c "^adb $run -s .* remount$" "$fixture/log")" -ge 4 ]]
  [[ "$(rg -c "^adb $run -s $serial_a emu avd name$" "$fixture/log")" -ge 3 ]]
  [[ "$(rg -c "^adb $run -s $serial_a shell id -u$" "$fixture/log")" -ge 3 ]]
done
serials="$(awk -F= '/^emulator_[ab]_serial=/ { print $2 }' "$fixture/.android-acceptance/concurrent-a/resources" "$fixture/.android-acceptance/concurrent-b/resources")"
[[ "$(printf '%s\n' "$serials" | sort -u | wc -l)" == 4 ]]
for job in "$first" "$second"; do
  wait_until 60 "job-$job-exit" pid_gone "$job" || true
  if kill -0 "$job" 2>/dev/null; then
    kill -TERM "$job" 2>/dev/null || true
    wait_until 10 "job-$job-final-exit" pid_gone "$job" || true
  fi
  kill_descendants "$job"
done
if wait "$first"; then first_status=0; else first_status=$?; fi
if wait "$second"; then second_status=0; else second_status=$?; fi
[[ "$first_status" == 0 || "$first_status" == 143 || "$first_status" == 1 ]] && [[ "$second_status" == 0 || "$second_status" == 143 || "$second_status" == 1 ]]
for run in concurrent-a concurrent-b; do
  read -r serial <"$fixture/$run.serials"; rg -F "reverse-remove $run $serial" "$fixture/log" >/dev/null
  ! rg -F "reverse-remove $run " "$fixture/log" | rg -Fv -f "$fixture/$run.serials" >/dev/null
  [[ ! -e "$fixture/.android-acceptance/$run" ]]
  rg -F -- "--project-name dtx-android-accept-$run down" "$fixture/log" >/dev/null
done

# Cleanup must refuse a reused/mismatched PID without signalling the unrelated
# process.  The fixture deliberately replaces its argv after binding ports.
fixture="$tmp/pid-mismatch"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'exec -a unrelated-proxy python3 -c '\''import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)'\''' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if run_fixture "$fixture" pid-mismatch env; then exit 1; fi
mismatch_pid="$(awk -F= '$1 == "PROXY_A_PID" { print $2 }' "$fixture/.android-acceptance/pid-mismatch/resources")"
valid_pid_re='^[1-9][0-9]*$'; [[ "$mismatch_pid" =~ $valid_pid_re ]] && kill -0 "$mismatch_pid" 2>/dev/null
! tr '\0' ' ' <"/proc/$mismatch_pid/cmdline" | rg -F '127.0.0.1:' >/dev/null
[[ "$(<"$fixture/.android-acceptance/pid-mismatch/cleanup-status")" == cleanup=failed ]]
kill -KILL "$mismatch_pid" 2>/dev/null || true
wait "$mismatch_pid" 2>/dev/null || true

# If a guardian dies after the group TERM, its numeric PGID must be treated as
# reusable/ambiguous: no group KILL may follow.  BASH_ENV records all kill
# builtins and, after the guardian has died, deterministically maps that
# numeric group to an unrelated sentinel.  A mistaken post-TERM group signal
# would therefore reach the sentinel rather than an actual reused PGID.
fixture="$tmp/guardian-mismatch"; make_fixture "$fixture"
printf '%s\n' 'kill() {' '  printf "kill" >>"$DTX_TEST_KILL_LOG"' '  for arg in "$@"; do printf " <%s>" "$arg" >>"$DTX_TEST_KILL_LOG"; done' '  printf "\n" >>"$DTX_TEST_KILL_LOG"' '  if [[ -n "${DTX_TEST_REUSED_PGID_FILE:-}" && -s "$DTX_TEST_REUSED_PGID_FILE" && -n "${DTX_TEST_UNRELATED_PID:-}" && "${!#}" == "-$(<"$DTX_TEST_REUSED_PGID_FILE")" ]]; then' '    builtin kill "$1" "$DTX_TEST_UNRELATED_PID"' '    return' '  fi' '  builtin kill "$@"' '}' >"$fixture/kill-spy.bash"
setsid bash -c 'trap "exit 0" TERM; while :; do sleep 1; done' & unrelated_pid=$!
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''printf "%s" "$PPID" >"$DTX_TEST_REUSED_PGID_FILE"; kill -KILL "$PPID"; trap "" TERM; while :; do sleep 1; done'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if BASH_ENV="$fixture/kill-spy.bash" DTX_TEST_KILL_LOG="$fixture/kill-log" DTX_TEST_REUSED_PGID_FILE="$fixture/reused-pgid" DTX_TEST_UNRELATED_PID="$unrelated_pid" run_fixture "$fixture" guardian-mismatch env; then exit 1; fi
guardian_root="$fixture/.android-acceptance/guardian-mismatch"
guardian_pid="$(awk -F= '$1 == "PROXY_A_GUARDIAN_PID" { print $2 }' "$guardian_root/resources")"
guardian_child="$(awk -F= '$1 == "PROXY_A_PID" { print $2 }' "$guardian_root/resources")"
[[ "$guardian_pid" =~ $valid_pid_re && "$guardian_child" =~ $valid_pid_re ]]
[[ "$(<"$guardian_root/cleanup-status")" == cleanup=failed ]]
rg -F "kill <-TERM> <--> <-$guardian_pid>" "$fixture/kill-log" >/dev/null
! rg -F "<-$guardian_pid>" "$fixture/kill-log" | rg -F -- '-KILL' >/dev/null
kill -0 "$unrelated_pid" 2>/dev/null
kill -KILL "$guardian_child" 2>/dev/null || true
wait "$guardian_child" 2>/dev/null || true
kill -TERM "$unrelated_pid" 2>/dev/null || true
wait "$unrelated_pid" 2>/dev/null || true

# A stubborn descendant is removed by the owned process-group KILL fallback.
fixture="$tmp/child-cleanup"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' '(trap '\'''\'' TERM; while :; do sleep 1; done) & child=$!; printf "%s" "$child" >"$DTX_TEST_ROOT/proxy-child"' 'trap '\''rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if run_fixture "$fixture" child-cleanup env; then exit 1; fi
child_pid="$(<"$fixture/proxy-child")"
! kill -0 "$child_pid" 2>/dev/null
[[ ! -e "$fixture/.android-acceptance/child-cleanup" ]]

# If the group leader exits on TERM, the independently revalidated group still
# contains and removes its stubborn child.
fixture="$tmp/leader-exit"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' '(trap "" TERM; while :; do sleep 1; done) & child=$!; printf "%s" "$child" >"$DTX_TEST_ROOT/leader-child"' 'trap "rm -f \"$DTX_TEST_PROXY_PORTS/$listen\" \"$DTX_TEST_PROXY_PORTS/$control\"; exit 0" TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if run_fixture "$fixture" leader-exit env; then exit 1; fi
leader_child_pid="$(<"$fixture/leader-child")"
! kill -0 "$leader_child_pid" 2>/dev/null
[[ ! -e "$fixture/.android-acceptance/leader-exit" ]]

# Foreground compose and app_process calls have independent bounded deadlines;
# timeout diagnostics are redacted and owned teardown still runs.
fixture="$tmp/hung-compose"; make_fixture "$fixture"
if DTX_TEST_COMPOSE_SLEEP=5 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-compose env >/dev/null 2>&1; then exit 1; fi
rg -F -- '--project-name dtx-android-accept-hung-compose ps --all' "$fixture/log" >/dev/null
rg -F -- '--project-name dtx-android-accept-hung-compose down' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-compose" ]]
fixture="$tmp/hung-app-process"; make_fixture "$fixture"
if DTX_TEST_APP_PROCESS_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-app-process env >/dev/null 2>&1; then exit 1; fi
rg -F 'shell app_process' "$fixture/log" >/dev/null
rg -F -- '--project-name dtx-android-accept-hung-app-process down' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-app-process" ]]
fixture="$tmp/hung-cargo"; make_fixture "$fixture"
if DTX_TEST_CARGO_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-cargo env >/dev/null 2>&1; then exit 1; fi
rg -F 'cargo build --locked -p dtx-android-response-loss-proxy' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-cargo" ]]
fixture="$tmp/hung-sha256"; make_fixture "$fixture"
if DTX_TEST_SHA256_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-sha256 env >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$fixture/.android-acceptance/hung-sha256" ]]
fixture="$tmp/hung-openssl"; make_fixture "$fixture"
if DTX_TEST_OPENSSL_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-openssl env >/dev/null 2>&1; then exit 1; fi
rg -F 'shell app_process' "$fixture/log" >/dev/null
! rg -F ' remount' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-openssl" ]]

# Native trust-probe toolchain calls use the same deadline as foreground
# commands, including javac version/compilation and d8.
fixture="$tmp/hung-javac-version"; make_fixture "$fixture"
if DTX_TEST_NATIVE_TRUST_PROBE=1 DTX_TEST_JAVAC_VERSION_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 ANDROID_SDK_ROOT="$fixture/sdk" run_fixture "$fixture" hung-javac-version env >/dev/null 2>&1; then exit 1; fi
rg -F 'javac -version' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-javac-version" ]]
fixture="$tmp/hung-javac-compile"; make_fixture "$fixture"
if DTX_TEST_NATIVE_TRUST_PROBE=1 DTX_TEST_JAVAC_COMPILE_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 ANDROID_SDK_ROOT="$fixture/sdk" run_fixture "$fixture" hung-javac-compile env >/dev/null 2>&1; then exit 1; fi
rg -F -- '-source 8 -target 8' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-javac-compile" ]]
fixture="$tmp/hung-d8"; make_fixture "$fixture"
if DTX_TEST_NATIVE_TRUST_PROBE=1 DTX_TEST_D8_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 ANDROID_SDK_ROOT="$fixture/sdk" run_fixture "$fixture" hung-d8 env >/dev/null 2>&1; then exit 1; fi
rg -F 'd8 --lib ' "$fixture/log" >/dev/null
[[ ! -e "$fixture/.android-acceptance/hung-d8" ]]
fixture="$tmp/hung-filter"; make_fixture "$fixture"
if DTX_TEST_NATIVE_TRUST_PROBE=1 DTX_TEST_SORT_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 ANDROID_SDK_ROOT="$fixture/sdk" run_fixture "$fixture" hung-filter env >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$fixture/.android-acceptance/hung-filter" ]]
fixture="$tmp/hung-mkdir"; make_fixture "$fixture"
if DTX_TEST_MKDIR_SLEEP=1 DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 run_fixture "$fixture" hung-mkdir env >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$fixture/.android-acceptance/hung-mkdir" ]]

# Cleanup inspection commands cannot make owned teardown wait forever.  ps is
# checked before signalling, while ss is checked after the process has exited.
for cleanup_probe in ps ss; do
  fixture="$tmp/hung-cleanup-$cleanup_probe"; make_fixture "$fixture"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'if [[ "${DTX_TEST_PS_SLEEP_ON_MARKER:-0}" == 1 ]]; then : >"$DTX_TEST_ROOT/cleanup-probe-marker"; fi' 'trap '\''if [[ "${DTX_TEST_SS_SLEEP_ON_MARKER:-0}" == 1 ]]; then : >"$DTX_TEST_ROOT/cleanup-probe-marker"; fi; rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
  case "$cleanup_probe" in
    ps) if DTX_TEST_REVERSE=fail DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 DTX_TEST_PS_SLEEP_ON_MARKER=1 run_fixture "$fixture" "hung-cleanup-$cleanup_probe" env >/dev/null 2>&1; then exit 1; fi ;;
    ss) if DTX_TEST_REVERSE=fail DTX_TEST_COMMAND_TIMEOUT_SECONDS=1 DTX_TEST_SS_SLEEP_ON_MARKER=1 run_fixture "$fixture" "hung-cleanup-$cleanup_probe" env >/dev/null 2>&1; then exit 1; fi ;;
  esac
  rg -F -- "--project-name dtx-android-accept-hung-cleanup-$cleanup_probe down" "$fixture/log" >/dev/null
  cleanup_fixture_processes
done

# Invalid closed configuration is rejected before any Android side effect.
fixture="$tmp/config"; make_fixture "$fixture"
if DTX_ANDROID_ACCELERATION=turbo run_fixture "$fixture" config-invalid env >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$fixture/log" ]]

# Console parsing ignores CR/empty lines but rejects divergent extra payload.
fixture="$tmp/console-extra"; make_fixture "$fixture"
if DTX_TEST_CONSOLE_EXTRA=1 run_fixture "$fixture" console-extra env >/dev/null 2>&1; then exit 1; fi
rg -F 'emu avd name' "$fixture/log" >/dev/null
fixture="$tmp/console-crlf"; make_fixture "$fixture"
if DTX_TEST_CONSOLE_CRLF=1 run_fixture "$fixture" console-crlf env >/dev/null 2>&1; then exit 1; fi
rg -F 'shell app_process' "$fixture/log" >/dev/null
fixture="$tmp/trust-failure"; make_fixture "$fixture"
if DTX_TEST_TRUST_FAIL=1 run_fixture "$fixture" trust-failure env >/dev/null 2>&1; then exit 1; fi
rg -F 'shell app_process' "$fixture/log" >/dev/null
! rg -F ' remount' "$fixture/log" >/dev/null
for trust_mode in TRUST_NONCE_MISMATCH TRUST_LOST TRUST_WRONG_FAILURE TRUST_PRETRUST TRUST_PUSH_FAIL; do
  trust_id="trust-${trust_mode,,}"; trust_id="${trust_id//_/-}"; fixture="$tmp/$trust_id"; make_fixture "$fixture"
  case "$trust_mode" in
    TRUST_NONCE_MISMATCH) if DTX_TEST_TRUST_NONCE_MISMATCH=1 run_fixture "$fixture" "$trust_id" env >/dev/null 2>&1; then exit 1; fi ;;
    TRUST_LOST) if DTX_TEST_TRUST_LOST=1 run_fixture "$fixture" "$trust_id" env >/dev/null 2>&1; then exit 1; fi ;;
    TRUST_WRONG_FAILURE) if DTX_TEST_TRUST_WRONG_FAILURE=1 run_fixture "$fixture" "$trust_id" env >/dev/null 2>&1; then exit 1; fi ;;
    TRUST_PRETRUST) if DTX_TEST_TRUST_PRETRUST=1 run_fixture "$fixture" "$trust_id" env >/dev/null 2>&1; then exit 1; fi ;;
    TRUST_PUSH_FAIL) if DTX_TEST_TRUST_PUSH_FAIL=1 run_fixture "$fixture" "$trust_id" env >/dev/null 2>&1; then exit 1; fi ;;
  esac
  if [[ "$trust_mode" != TRUST_PUSH_FAIL ]]; then rg -F 'shell app_process' "$fixture/log" >/dev/null; fi
done

# A malformed durable reservation rejects allocation instead of being skipped.
fixture="$tmp/corrupt"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"; printf 'node_a_port=not-a-port\n' >"$fixture/.android-acceptance/stale/resources"
if run_fixture "$fixture" corrupt-scan env >/dev/null 2>&1; then exit 1; fi
for malformed in '20000-corrupt' '1x' 'emulator-5556' 'pid'; do
  fixture="$tmp/corrupt-${malformed//[^A-Za-z0-9]/-}"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"
  printf 'run_id=stale\ncompose_project=dtx-android-accept-stale\nandroid_system_image=system-images;android-35;aosp_atd;x86_64\nandroid_acceleration=off\nandroid_gpu=swiftshader_indirect\nandroid_cores=2\nandroid_memory_mib=2048\nandroid_boot_timeout_seconds=180\nandroid_avd_count=2\nandroid_avd_rss_mib=4300\nandroid_rss_reservation_mib=8600\nnode_a_port=20000\nnode_b_port=20001\nproxy_a_port=20002\ncontrol_a_port=20003\nproxy_b_port=20004\ncontrol_b_port=20005\nemulator_a_port=5554\nemulator_b_port=5556\nemulator_a_serial=emulator-5554\nemulator_b_serial=emulator-5556\n' >"$fixture/.android-acceptance/stale/resources"
  case "$malformed" in 20000-corrupt) sed -i 's/node_a_port=20000/node_a_port=20000-corrupt/' "$fixture/.android-acceptance/stale/resources";; 1x) sed -i 's/PROXY_A_PID=/PROXY_A_PID=1x/' "$fixture/.android-acceptance/stale/resources"; printf 'PROXY_A_PID=1x\n' >>"$fixture/.android-acceptance/stale/resources";; emulator-5556) sed -i 's/emulator_a_serial=emulator-5554/emulator_a_serial=emulator-5556/' "$fixture/.android-acceptance/stale/resources";; pid) printf 'emulator_a_pid=not-a-pid\nemulator_b_pid=321\n' >>"$fixture/.android-acceptance/stale/resources";; esac
  if run_fixture "$fixture" "corrupt-${malformed//[^A-Za-z0-9]/-}" env >/dev/null 2>&1; then exit 1; fi
  [[ ! -e "$fixture/log" ]]
done
for topology in service-gap emulator-gap; do
  fixture="$tmp/topology-$topology"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"
  printf 'run_id=stale\ncompose_project=dtx-android-accept-stale\nandroid_system_image=system-images;android-35;aosp_atd;x86_64\nandroid_acceleration=off\nandroid_gpu=swiftshader_indirect\nandroid_cores=2\nandroid_memory_mib=2048\nandroid_boot_timeout_seconds=180\nandroid_avd_count=2\nandroid_avd_rss_mib=4300\nandroid_rss_reservation_mib=8600\nnode_a_port=20000\nnode_b_port=20001\nproxy_a_port=20002\ncontrol_a_port=20003\nproxy_b_port=20004\ncontrol_b_port=20005\nemulator_a_port=5554\nemulator_b_port=5556\nemulator_a_serial=emulator-5554\nemulator_b_serial=emulator-5556\n' >"$fixture/.android-acceptance/stale/resources"
  case "$topology" in service-gap) sed -i 's/control_b_port=20005/control_b_port=20006/' "$fixture/.android-acceptance/stale/resources";; emulator-gap) sed -i 's/emulator_b_port=5556/emulator_b_port=5558/; s/emulator_b_serial=emulator-5556/emulator_b_serial=emulator-5558/' "$fixture/.android-acceptance/stale/resources";; esac
  if run_fixture "$fixture" "topology-$topology" env >/dev/null 2>&1; then exit 1; fi
  [[ ! -e "$fixture/log" ]]
done

# If A's reverse command applies its mapping but reports failure, cleanup
# removes only A.  Cleanup success drops the root; cleanup failure retains it.
fixture="$tmp/reverse"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if DTX_TEST_REVERSE_FAIL_AFTER=1 run_fixture "$fixture" reverse-ok env; then exit 1; fi
rg -F 'reverse-side-effect reverse-ok ' "$fixture/log" >/dev/null
[[ "$(rg -c '^reverse-remove reverse-ok ' "$fixture/log")" == 1 ]]
[[ ! -e "$fixture/.android-acceptance/reverse-ok" ]]
if DTX_TEST_REVERSE_FAIL_AFTER=1 DTX_TEST_AVD_DELETE=fail run_fixture "$fixture" reverse-retained env; then exit 1; fi
[[ "$(<"$fixture/.android-acceptance/reverse-retained/cleanup-status")" == cleanup=failed ]]
[[ "$(rg -c '^reverse-remove reverse-retained ' "$fixture/log")" == 1 ]]
rg -F -- 'delete avd --name dirextalk-accept-reverse-retained-a' "$fixture/log" >/dev/null
rg -F -- 'delete avd --name dirextalk-accept-reverse-retained-b' "$fixture/log" >/dev/null
rg -F -- '--project-name dtx-android-accept-reverse-retained down' "$fixture/log" >/dev/null

# Signals preserve conventional status while running all owned cleanup.
fixture="$tmp/signals"; make_fixture "$fixture"
DTX_TEST_COMPOSE_SLEEP=1 run_fixture_isolated "$fixture" signal-int env & child=$!
wait_until 30 signal-int-resources dir_exists "$fixture/.android-acceptance/signal-int"
wait_until 30 signal-int-cargo-start log_contains 'cargo build --locked -p dtx-android-response-loss-proxy' "$fixture/log"
kill -INT "$child"
wait_until 10 signal-int-exit pid_gone "$child" || true
if kill -0 "$child" 2>/dev/null; then kill -TERM "$child"; fi
if wait "$child"; then child_status=0; else child_status=$?; fi
[[ "$child_status" == 0 || "$child_status" == 130 || "$child_status" == 143 || "$child_status" == 1 ]]
rg -F -- '--project-name dtx-android-accept-signal-int down' "$fixture/log" >/dev/null

if rg -n 'logcat|pull .*\.db|ca-key|tokens?|payload' "$script" | rg -v 'never retained|no TLS, logcat, DB, token, or payload|no product scenario logic' >/dev/null; then
  printf '%s\n' 'forbidden artifact collection found' >&2; exit 1
fi
printf '%s\n' 'android acceptance shell safety tests passed'
