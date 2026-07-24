#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
script="$root/scripts/android-acceptance.sh"
tmp="$(mktemp -d)"
test_shell_pid=$BASHPID
cleanup_test_tmp() { [[ $BASHPID != "$test_shell_pid" ]] || rm -rf -- "$tmp"; }
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
  mkdir -p "$fixture/scripts" "$fixture/bin" "$fixture/target/debug" "$fixture/maps" "$fixture/proxy-ports"
  cp "$script" "$fixture/scripts/android-acceptance.sh"
  : >"$fixture/docker-compose.local.yml"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "cargo $*" >>"$DTX_TEST_LOG"' 'exit 0' >"$fixture/bin/cargo"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "docker $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" up "*) if [[ "${DTX_TEST_COMPOSE_UP:-ok}" == fail ]]; then exit 1; fi; sleep "${DTX_TEST_COMPOSE_SLEEP:-0}";; esac' 'exit 0' >"$fixture/bin/docker"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "avdmanager $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" list avd "*) [[ "${DTX_TEST_AVD_PRESENT:-}" == 1 ]] && printf "    Name: %s\n" "${DTX_TEST_AVD_NAME:-}";; *" create avd "*) [[ "${DTX_TEST_AVD_CREATE:-ok}" == ok ]] || exit 1;; *" delete avd "*) [[ "${DTX_TEST_AVD_DELETE:-ok}" == ok ]] || exit 1;; esac' 'exit 0' >"$fixture/bin/avdmanager"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "adb $DTX_TEST_RUN_ID $*" >>"$DTX_TEST_LOG"' 'serial=""; [[ "${1:-}" != -s ]] || { serial=$2; shift 2; }' 'case " $* " in *" devices "*) printf "%s" "${DTX_TEST_ADB_DEVICES:-}";; *" wait-for-device "*) for _ in $(seq 1 50); do [[ -f "$DTX_TEST_MAP/$serial" ]] && exit 0; sleep 0.02; done; exit 1;; *" emu avd name "*) cat "$DTX_TEST_MAP/$serial";; *" root "*|*" shell "*|*" push "*) [[ -f "$DTX_TEST_MAP/$serial" ]] || exit 1;; *" reverse tcp:8443 "*) if [[ "${DTX_TEST_REVERSE_FAIL_AFTER:-}" == 1 && "$serial" == "$(awk -F= '\''$1 == "emulator_a_serial" { print $2 }'\'' "$DTX_TEST_ROOT/.android-acceptance/$DTX_TEST_RUN_ID/resources")" ]]; then echo "reverse-side-effect $DTX_TEST_RUN_ID $serial" >>"$DTX_TEST_LOG"; exit 1; fi; [[ "${DTX_TEST_REVERSE:-ok}" == ok ]] || exit 1; [[ "${DTX_TEST_REVERSE_SLEEP:-0}" == 0 ]] || sleep "$DTX_TEST_REVERSE_SLEEP";; *" reverse --remove tcp:8443 "*) echo "reverse-remove $DTX_TEST_RUN_ID $serial" >>"$DTX_TEST_LOG";; esac' >"$fixture/bin/adb"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "emulator $DTX_TEST_RUN_ID $*" >>"$DTX_TEST_LOG"' 'avd=""; port=""; while (($#)); do case "$1" in -avd) avd=$2; shift 2;; -port) port=$2; shift 2;; *) shift;; esac; done' 'printf "%s\n" "$avd" >"$DTX_TEST_MAP/emulator-$port"' 'trap '\''echo "emulator-term $DTX_TEST_RUN_ID $avd" >>"$DTX_TEST_LOG"; rm -f "$DTX_TEST_MAP/emulator-$port"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/bin/emulator"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "deadbeef\n"' >"$fixture/bin/openssl"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'port="${*: -1}"; port="${port##*:}"; [[ -f "${DTX_TEST_PROXY_PORTS:-/nonexistent}/$port" ]] && printf "LISTEN\n"' >"$fixture/bin/ss"
  chmod +x "$fixture/bin"/*
}

run_fixture() {
  local fixture=$1 run_id=$2
  shift 2
  if [[ "${DTX_TEST_EXEC:-}" == 1 ]]; then
    exec env PATH="$fixture/bin:$PATH" DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_TEST_ROOT="$fixture" DTX_TEST_MAP="$fixture/maps" DTX_TEST_PROXY_PORTS="$fixture/proxy-ports" DTX_ANDROID_SYSTEM_IMAGE=fake DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
  fi
  PATH="$fixture/bin:$PATH" DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_TEST_ROOT="$fixture" DTX_TEST_MAP="$fixture/maps" DTX_TEST_PROXY_PORTS="$fixture/proxy-ports" DTX_ANDROID_SYSTEM_IMAGE=fake DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
}

# A partially-started compose project is owned before `up`; failure therefore
# still invokes exact-project teardown.
fixture="$tmp/compose"; make_fixture "$fixture"
if DTX_TEST_COMPOSE_UP=fail run_fixture "$fixture" compose-partial env; then exit 1; fi
rg -F -- '--project-name dtx-android-accept-compose-partial down' "$fixture/log" >/dev/null

# Proxy PID ownership is recorded before readiness failure, and cleanup keeps
# removing later resources even when AVD deletion fails.
fixture="$tmp/proxy"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; printf "%s\n" "$listen" >"$DTX_TEST_PROXY_PORTS/$listen"; printf "%s\n" "$control" >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''echo "proxy-term $listen $control" >>"$DTX_TEST_LOG"; rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
if DTX_TEST_AVD_DELETE=fail run_fixture "$fixture" proxy-partial env; then exit 1; fi
proxy_root="$fixture/.android-acceptance/proxy-partial"; proxy_pid="$(awk -F= '$1 == "PROXY_A_PID" { print $2 }' "$proxy_root/resources")"
[[ "$proxy_pid" =~ ^[1-9][0-9]*$ ]] && ! kill -0 "$proxy_pid" 2>/dev/null
[[ ! -e "$fixture/proxy-ports/$(awk -F= '$1 == "proxy_a_port" { print $2 }' "$proxy_root/resources")" ]]
rg -F 'proxy-term ' "$fixture/log" >/dev/null
rg -F -- 'delete avd --name dirextalk-accept-proxy-partial-a' "$fixture/log" >/dev/null
rg -F -- 'delete avd --name dirextalk-accept-proxy-partial-b' "$fixture/log" >/dev/null
rg -F -- '--project-name dtx-android-accept-proxy-partial down' "$fixture/log" >/dev/null
[[ "$(<"$proxy_root/cleanup-status")" == cleanup=failed ]]

# A symlinked state root is rejected before any external command and never
# turns cleanup into an outside-tree deletion.
fixture="$tmp/symlink"; make_fixture "$fixture"; mkdir "$fixture/outside"; printf keep >"$fixture/outside/sentinel"; ln -s "$fixture/outside" "$fixture/.android-acceptance"
if run_fixture "$fixture" symlink-root env >/dev/null 2>&1; then exit 1; fi
[[ "$(<"$fixture/outside/sentinel")" == keep ]] && [[ ! -e "$fixture/outside/symlink-root" ]]

# Different live RUN_IDs reserve disjoint port/serial blocks under the global
# allocator lock; a duplicate RUN_ID is rejected while its reservation exists.
fixture="$tmp/allocator"; make_fixture "$fixture"
(trap - EXIT; DTX_TEST_EXEC=1 DTX_TEST_COMPOSE_SLEEP=3 run_fixture "$fixture" allocator-a env) & first=$!
for _ in $(seq 1 30); do [[ -f "$fixture/.android-acceptance/allocator-a/resources" ]] && break; sleep 0.1; done
(trap - EXIT; DTX_TEST_EXEC=1 DTX_TEST_COMPOSE_SLEEP=3 run_fixture "$fixture" allocator-b env) & second=$!
for _ in $(seq 1 30); do [[ -f "$fixture/.android-acceptance/allocator-b/resources" ]] && break; sleep 0.1; done
if DTX_TEST_COMPOSE_SLEEP=3 run_fixture "$fixture" allocator-a env >/dev/null 2>&1; then exit 1; fi
! cmp -s "$fixture/.android-acceptance/allocator-a/resources" "$fixture/.android-acceptance/allocator-b/resources"
for field in node_a_port node_b_port proxy_a_port control_a_port proxy_b_port control_b_port emulator_a_port emulator_b_port emulator_a_serial emulator_b_serial; do
  first_value="$(awk -F= -v field="$field" '$1 == field { print $2 }' "$fixture/.android-acceptance/allocator-a/resources")"
  second_value="$(awk -F= -v field="$field" '$1 == field { print $2 }' "$fixture/.android-acceptance/allocator-b/resources")"
  [[ -n "$first_value" && "$first_value" != "$second_value" ]]
done
kill -TERM "$first" "$second"; wait "$first" || [[ $? == 143 ]]; wait "$second" || [[ $? == 143 ]]
[[ ! -e "$fixture/.android-acceptance/allocator-a" && ! -e "$fixture/.android-acceptance/allocator-b" ]]

# Two live runs reach emulator ownership verification, root/CA installation and
# proxy mapping concurrently.  Every adb target remains owned by its RUN_ID.
fixture="$tmp/concurrent"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'listen=${1##*:}; control=${3##*:}; : >"$DTX_TEST_PROXY_PORTS/$listen"; : >"$DTX_TEST_PROXY_PORTS/$control"' 'trap '\''rm -f "$DTX_TEST_PROXY_PORTS/$listen" "$DTX_TEST_PROXY_PORTS/$control"; exit 0'\'' TERM' 'while :; do sleep 1; done' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
(trap - EXIT; DTX_TEST_EXEC=1 DTX_TEST_REVERSE_SLEEP=30 run_fixture "$fixture" concurrent-a env) & first=$!
for _ in $(seq 1 30); do [[ -f "$fixture/.android-acceptance/concurrent-a/resources" ]] && break; sleep 0.1; done
(trap - EXIT; DTX_TEST_EXEC=1 DTX_TEST_REVERSE_SLEEP=30 run_fixture "$fixture" concurrent-b env) & second=$!
for _ in $(seq 1 100); do [[ $(rg -c '^adb concurrent-[ab] .* reverse tcp:8443 ' "$fixture/log" 2>/dev/null || true) -ge 2 ]] && break; sleep 0.1; done
for run in concurrent-a concurrent-b; do
  resource="$fixture/.android-acceptance/$run/resources"; [[ -f "$resource" ]]
  serial_a="$(awk -F= '$1 == "emulator_a_serial" { print $2 }' "$resource")"; serial_b="$(awk -F= '$1 == "emulator_b_serial" { print $2 }' "$resource")"
  printf '%s\n%s\n' "$serial_a" "$serial_b" >"$fixture/$run.serials"
  avd_a="dirextalk-accept-$run-a"; avd_b="dirextalk-accept-$run-b"
  [[ "$(<"$fixture/maps/$serial_a")" == "$avd_a" && "$(<"$fixture/maps/$serial_b")" == "$avd_b" ]]
  rg -F "adb $run -s $serial_a root" "$fixture/log" >/dev/null; rg -F "adb $run -s $serial_b root" "$fixture/log" >/dev/null
  rg -F "adb $run -s $serial_a push" "$fixture/log" >/dev/null; rg -F "adb $run -s $serial_b push" "$fixture/log" >/dev/null
  ! rg --pcre2 "^adb $run -s (?!$serial_a |$serial_b )" "$fixture/log" >/dev/null
done
serials="$(awk -F= '/^emulator_[ab]_serial=/ { print $2 }' "$fixture/.android-acceptance/concurrent-a/resources" "$fixture/.android-acceptance/concurrent-b/resources")"
[[ "$(printf '%s\n' "$serials" | sort -u | wc -l)" == 4 ]]
kill -TERM "$first" "$second"; wait "$first" || [[ $? == 143 ]]; wait "$second" || [[ $? == 143 ]]
for run in concurrent-a concurrent-b; do
  read -r serial <"$fixture/$run.serials"; rg -F "reverse-remove $run $serial" "$fixture/log" >/dev/null
  ! rg -F "reverse-remove $run " "$fixture/log" | rg -Fv -f "$fixture/$run.serials" >/dev/null
  [[ ! -e "$fixture/.android-acceptance/$run" ]]
  rg -F -- "--project-name dtx-android-accept-$run down" "$fixture/log" >/dev/null
done

# A malformed durable reservation rejects allocation instead of being skipped.
fixture="$tmp/corrupt"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"; printf 'node_a_port=not-a-port\n' >"$fixture/.android-acceptance/stale/resources"
if run_fixture "$fixture" corrupt-scan env >/dev/null 2>&1; then exit 1; fi
for malformed in '20000-corrupt' '1x' 'emulator-5556'; do
  fixture="$tmp/corrupt-${malformed//[^A-Za-z0-9]/-}"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"
  printf 'run_id=stale\ncompose_project=dtx-android-accept-stale\nnode_a_port=20000\nnode_b_port=20001\nproxy_a_port=20002\ncontrol_a_port=20003\nproxy_b_port=20004\ncontrol_b_port=20005\nemulator_a_port=5554\nemulator_b_port=5556\nemulator_a_serial=emulator-5554\nemulator_b_serial=emulator-5556\n' >"$fixture/.android-acceptance/stale/resources"
  case "$malformed" in 20000-corrupt) sed -i 's/node_a_port=20000/node_a_port=20000-corrupt/' "$fixture/.android-acceptance/stale/resources";; 1x) sed -i 's/PROXY_A_PID=/PROXY_A_PID=1x/' "$fixture/.android-acceptance/stale/resources"; printf 'PROXY_A_PID=1x\n' >>"$fixture/.android-acceptance/stale/resources";; emulator-5556) sed -i 's/emulator_a_serial=emulator-5554/emulator_a_serial=emulator-5556/' "$fixture/.android-acceptance/stale/resources";; esac
  if run_fixture "$fixture" "corrupt-${malformed//[^A-Za-z0-9]/-}" env >/dev/null 2>&1; then exit 1; fi
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
(trap - EXIT; DTX_TEST_EXEC=1 DTX_TEST_COMPOSE_SLEEP=30 run_fixture "$fixture" signal-int env) & child=$!
for _ in $(seq 1 30); do [[ -d "$fixture/.android-acceptance/signal-int" ]] && break; sleep 0.1; done
kill -INT "$child"; wait "$child" || [[ $? == 130 ]]
rg -F -- '--project-name dtx-android-accept-signal-int down' "$fixture/log" >/dev/null

if rg -n 'logcat|pull .*\.db|ca-key|tokens?|payload' "$script" | rg -v 'never retained|no TLS, logcat, DB, token, or payload|no product scenario logic' >/dev/null; then
  printf '%s\n' 'forbidden artifact collection found' >&2; exit 1
fi
printf '%s\n' 'android acceptance shell safety tests passed'
