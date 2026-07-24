#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
script="$root/scripts/android-acceptance.sh"
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
if rg -n 'logcat|pull .*\.db|ca-key|tokens?|payload' "$script" | rg -v 'never retained|no TLS, logcat, DB, token, or payload|no product scenario logic' >/dev/null; then
  printf '%s\n' 'forbidden artifact collection found' >&2; exit 1
fi
printf '%s\n' 'android acceptance shell safety tests passed'
