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
  mkdir -p "$fixture/scripts" "$fixture/bin" "$fixture/target/debug"
  cp "$script" "$fixture/scripts/android-acceptance.sh"
  : >"$fixture/docker-compose.local.yml"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "cargo $*" >>"$DTX_TEST_LOG"' 'exit 0' >"$fixture/bin/cargo"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "docker $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" up "*) if [[ "${DTX_TEST_COMPOSE_UP:-ok}" == fail ]]; then exit 1; fi; sleep "${DTX_TEST_COMPOSE_SLEEP:-0}";; esac' 'exit 0' >"$fixture/bin/docker"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "avdmanager $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" list avd "*) [[ "${DTX_TEST_AVD_PRESENT:-}" == 1 ]] && printf "    Name: %s\n" "${DTX_TEST_AVD_NAME:-}";; *" create avd "*) [[ "${DTX_TEST_AVD_CREATE:-ok}" == ok ]] || exit 1;; *" delete avd "*) [[ "${DTX_TEST_AVD_DELETE:-ok}" == ok ]] || exit 1;; esac' 'exit 0' >"$fixture/bin/avdmanager"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "adb $*" >>"$DTX_TEST_LOG"' 'case " $* " in *" devices "*) printf "%s" "${DTX_TEST_ADB_DEVICES:-}";; *" emu avd name "*) count_file="$DTX_TEST_LOG.$DTX_TEST_RUN_ID.avd-count"; count=0; [[ ! -f "$count_file" ]] || count=$(<"$count_file"); count=$((count + 1)); printf "%s" "$count" >"$count_file"; suffix=a; (( count == 1 )) || suffix=b; printf "dirextalk-accept-%s-%s\n" "$DTX_TEST_RUN_ID" "$suffix";; *" reverse tcp:8443 "*) [[ "${DTX_TEST_REVERSE:-ok}" == ok ]] || exit 1;; esac' 'exit 0' >"$fixture/bin/adb"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'echo "emulator $*" >>"$DTX_TEST_LOG"' 'sleep 30' >"$fixture/bin/emulator"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "deadbeef\n"' >"$fixture/bin/openssl"
  printf '%s\n' '#!/usr/bin/env bash' '[[ "${DTX_TEST_SS:-fail}" == ok ]] && exit 0; exit 1' >"$fixture/bin/ss"
  chmod +x "$fixture/bin"/*
}

run_fixture() {
  local fixture=$1 run_id=$2
  shift 2
  if [[ "${DTX_TEST_EXEC:-}" == 1 ]]; then
    exec env PATH="$fixture/bin:$PATH" DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_ANDROID_SYSTEM_IMAGE=fake DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
  fi
  PATH="$fixture/bin:$PATH" DTX_TEST_LOG="$fixture/log" DTX_TEST_RUN_ID="$run_id" DTX_ANDROID_SYSTEM_IMAGE=fake DTX_ANDROID_ACCEPTANCE_RUN_ID="$run_id" "$@" "$fixture/scripts/android-acceptance.sh" --run
}

# A partially-started compose project is owned before `up`; failure therefore
# still invokes exact-project teardown.
fixture="$tmp/compose"; make_fixture "$fixture"
if DTX_TEST_COMPOSE_UP=fail run_fixture "$fixture" compose-partial env; then exit 1; fi
rg -F -- '--project-name dtx-android-accept-compose-partial down' "$fixture/log" >/dev/null

# Proxy PID ownership is recorded before readiness failure, and cleanup keeps
# removing later resources even when AVD deletion fails.
fixture="$tmp/proxy"; make_fixture "$fixture"
printf '%s\n' '#!/usr/bin/env bash' 'sleep 30' >"$fixture/target/debug/dtx-android-response-loss-proxy"; chmod +x "$fixture/target/debug/dtx-android-response-loss-proxy"
run_fixture "$fixture" proxy-partial env || true

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

# A malformed durable reservation rejects allocation instead of being skipped.
fixture="$tmp/corrupt"; make_fixture "$fixture"; mkdir -p "$fixture/.android-acceptance/stale"; printf 'node_a_port=not-a-port\n' >"$fixture/.android-acceptance/stale/resources"
if run_fixture "$fixture" corrupt-scan env >/dev/null 2>&1; then exit 1; fi

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
