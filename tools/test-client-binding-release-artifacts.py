#!/usr/bin/env python3
"""Behavioral checks for fixed client-binding host helpers and image cleanup."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
ISSUE = REPOSITORY / "scripts/production-stack/host/client-binding-issue"
CLEANUP = REPOSITORY / "scripts/production-stack/host/client-binding-export-cleanup"
IMAGE_GATE = REPOSITORY / "scripts/check-release-image.sh"
AUTHORIZATION = "A" * 43
REQUEST = (
    '{"identity_tls_root_ca_file":"/run/dtx-client-binding/private-ca.pem",'
    '"schema":"dirextalk.client-binding-issue"}'
)
OUTPUT = (
    f'{{"authorization":"{AUTHORIZATION}",'
    '"schema":"dirextalk.client-binding"}'
)


def quote(path: Path | str) -> str:
    return shlex.quote(str(path))


def rewritten(source: Path, destination: Path, root: Path, home: Path) -> None:
    text = source.read_text()
    replacements = {
        "/etc/dirextalk/vnext/client-binding": str(root / "binding"),
        "/etc/dirextalk/vnext/tls/private-ca.pem": str(root / "tls/private-ca.pem"),
        "/etc/dirextalk/vnext/config/production-compose.yml": str(root / "config/compose.yml"),
        "/etc/dirextalk/vnext/config/production.env": str(root / "config/production.env"),
        "/home/ubuntu": str(home),
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    destination.write_text(text)
    destination.chmod(0o755)


def run_fakeroot(script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    if shutil.which("fakeroot") is None:
        raise RuntimeError("fakeroot is required for client-binding behavioral checks")
    return subprocess.run(
        ["fakeroot", "bash", "-eu", "-o", "pipefail", "-c", script],
        cwd=REPOSITORY,
        env={**os.environ, **(env or {})},
        text=True,
        capture_output=True,
        check=False,
    )


def setup_commands(root: Path, home: Path) -> str:
    binding = root / "binding"
    tls = root / "tls"
    config = root / "config"
    return f"""
mkdir -p {quote(binding)} {quote(tls)} {quote(config)} {quote(home)}
chown 0:0 {quote(root)} {quote(binding)} {quote(tls)} {quote(config)}
chmod 0700 {quote(binding)}
printf '%s' 'synthetic-public-ca' > {quote(tls / "private-ca.pem")}
chown 0:0 {quote(tls / "private-ca.pem")}
chmod 0444 {quote(tls / "private-ca.pem")}
: > {quote(config / "compose.yml")}
: > {quote(config / "production.env")}
"""


def fake_issuer(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == compose ]] || exit 2
count=0
[[ ! -f "$DTX_TEST_DOCKER_COUNT" ]] || count=$(<"$DTX_TEST_DOCKER_COUNT")
printf '%s\n' "$((count + 1))" >"$DTX_TEST_DOCKER_COUNT"
printf '%s' 'synthetic-secret-must-not-reach-stdout'
printf '%s' "$DTX_TEST_OUTPUT_JSON" >"$DTX_TEST_OUTPUT_PATH"
chown 0:0 "$DTX_TEST_OUTPUT_PATH"
chmod 0600 "$DTX_TEST_OUTPUT_PATH"
"""
    )
    path.chmod(0o755)


def assert_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        raise AssertionError(f"{label} failed: {result.stderr}")


def test_issue_normal_and_replay(base: Path) -> None:
    root = base / "normal-root"
    home = base / "normal-home"
    helper = base / "issue-normal"
    fake_bin = base / "normal-bin"
    fake_bin.mkdir()
    rewritten(ISSUE, helper, root, home)
    fake_issuer(fake_bin / "docker")
    binding = root / "binding"
    staged = home / "dirextalk-client-binding.request"
    export = home / "dirextalk-client-binding.import.json"
    output = binding / "import.json"
    count = base / "normal-docker-count"
    stdout = base / "normal.stdout"
    script = (
        setup_commands(root, home)
        + f"""
printf '%s' {quote(REQUEST)} > {quote(staged)}
chown 1000:1000 {quote(staged)}
chmod 0400 {quote(staged)}
PATH={quote(fake_bin)}:$PATH \
DTX_TEST_OUTPUT_PATH={quote(output)} \
DTX_TEST_OUTPUT_JSON={quote(OUTPUT)} \
DTX_TEST_DOCKER_COUNT={quote(count)} \
{quote(helper)} >{quote(stdout)}
[[ ! -s {quote(stdout)} ]]
[[ ! -e {quote(staged)} ]]
[[ $(stat -c '%u:%g:%a:%h' {quote(binding / "request.json")}) == 0:0:600:1 ]]
[[ $(stat -c '%u:%g:%a:%h' {quote(binding / "private-ca.pem")}) == 0:0:600:1 ]]
[[ $(stat -c '%u:%g:%a:%h' {quote(output)}) == 0:0:600:1 ]]
[[ $(stat -c '%u:%g:%a:%h' {quote(export)}) == 1000:1000:400:1 ]]
[[ $(<{quote(count)}) == 1 ]]
PATH={quote(fake_bin)}:$PATH \
DTX_TEST_OUTPUT_PATH={quote(output)} \
DTX_TEST_OUTPUT_JSON={quote(OUTPUT)} \
DTX_TEST_DOCKER_COUNT={quote(count)} \
{quote(helper)} >{quote(stdout)}
[[ ! -s {quote(stdout)} ]]
[[ $(<{quote(count)}) == 1 ]]
cmp -s {quote(output)} {quote(export)}
"""
    )
    assert_success(run_fakeroot(script), "normal issuance/replay")


def test_crash_modes(base: Path) -> None:
    for phase in ("request-root-0400", "export-ubuntu-0600"):
        root = base / f"{phase}-root"
        home = base / f"{phase}-home"
        helper = base / f"issue-{phase}"
        fake_bin = base / f"{phase}-bin"
        fake_bin.mkdir()
        rewritten(ISSUE, helper, root, home)
        fake_issuer(fake_bin / "docker")
        binding = root / "binding"
        output = binding / "import.json"
        export = home / "dirextalk-client-binding.import.json"
        count = base / f"{phase}-count"
        script = setup_commands(root, home)
        if phase == "request-root-0400":
            script += f"""
printf '%s' {quote(REQUEST)} > {quote(binding / "request.json.tmp")}
chown 0:0 {quote(binding / "request.json.tmp")}
chmod 0400 {quote(binding / "request.json.tmp")}
"""
        else:
            script += f"""
printf '%s' {quote(REQUEST)} > {quote(binding / "request.json")}
chown 0:0 {quote(binding / "request.json")}
chmod 0600 {quote(binding / "request.json")}
printf '%s' {quote(OUTPUT)} > {quote(output)}
chown 0:0 {quote(output)}
chmod 0600 {quote(output)}
printf '%s' {quote(OUTPUT)} > {quote(binding / "import.json.export.tmp")}
chown 1000:1000 {quote(binding / "import.json.export.tmp")}
chmod 0600 {quote(binding / "import.json.export.tmp")}
"""
        script += f"""
PATH={quote(fake_bin)}:$PATH \
DTX_TEST_OUTPUT_PATH={quote(output)} \
DTX_TEST_OUTPUT_JSON={quote(OUTPUT)} \
DTX_TEST_DOCKER_COUNT={quote(count)} \
{quote(helper)} >/dev/null
[[ $(stat -c '%u:%g:%a:%h' {quote(binding / "request.json")}) == 0:0:600:1 ]]
[[ $(stat -c '%u:%g:%a:%h' {quote(export)}) == 1000:1000:400:1 ]]
"""
        if phase == "export-ubuntu-0600":
            script += f"[[ ! -e {quote(count)} ]]\n"
        assert_success(run_fakeroot(script), phase)


def test_link_and_device_rejection(base: Path) -> None:
    for kind in ("symlink", "hardlink"):
        root = base / f"{kind}-root"
        home = base / f"{kind}-home"
        helper = base / f"issue-{kind}"
        rewritten(ISSUE, helper, root, home)
        staged = home / "dirextalk-client-binding.request"
        script = setup_commands(root, home)
        if kind == "symlink":
            script += f"""
printf '%s' {quote(REQUEST)} > {quote(home / "target")}
ln -s {quote(home / "target")} {quote(staged)}
"""
        else:
            script += f"""
printf '%s' {quote(REQUEST)} > {quote(staged)}
chown 1000:1000 {quote(staged)}
chmod 0400 {quote(staged)}
ln {quote(staged)} {quote(home / "second-link")}
"""
        script += f"""
if {quote(helper)} >/dev/null 2>&1; then exit 1; fi
[[ -e {quote(staged)} || -L {quote(staged)} ]]
"""
        assert_success(run_fakeroot(script), f"{kind} rejection")

    with tempfile.TemporaryDirectory(dir="/dev/shm") as cross_home_text:
        cross_home = Path(cross_home_text)
        root = base / "cross-root"
        helper = base / "issue-cross-device"
        rewritten(ISSUE, helper, root, cross_home)
        staged = cross_home / "dirextalk-client-binding.request"
        script = setup_commands(root, cross_home) + f"""
printf '%s' {quote(REQUEST)} > {quote(staged)}
chown 1000:1000 {quote(staged)}
chmod 0400 {quote(staged)}
[[ $(stat -c '%d' {quote(cross_home)}) != $(stat -c '%d' {quote(root / "binding")}) ]]
if {quote(helper)} >/dev/null 2>&1; then exit 1; fi
[[ -e {quote(staged)} ]]
[[ ! -e {quote(root / "binding/private-ca.pem")} ]]
[[ ! -e {quote(root / "binding/request.json.tmp")} ]]
"""
        assert_success(run_fakeroot(script), "cross-device rejection")


def test_cleanup_states(base: Path) -> None:
    root = base / "cleanup-root"
    home = base / "cleanup-home"
    helper = base / "cleanup-helper"
    rewritten(CLEANUP, helper, root, home)
    binding = root / "binding"
    root_files = [
        binding / "import.json",
        binding / "request.json",
        binding / "revoke-binding-id",
        binding / "private-ca.pem",
        binding / "private-ca.pem.tmp",
    ]
    script = setup_commands(root, home)
    for path in root_files:
        script += f"printf x > {quote(path)}; chown 0:0 {quote(path)}; chmod 0600 {quote(path)}\n"
    script += f"""
printf x > {quote(binding / "request.json.tmp")}
chown 0:0 {quote(binding / "request.json.tmp")}
chmod 0400 {quote(binding / "request.json.tmp")}
printf x > {quote(binding / "import.json.export.tmp")}
chown 1000:1000 {quote(binding / "import.json.export.tmp")}
chmod 0600 {quote(binding / "import.json.export.tmp")}
printf x > {quote(home / "dirextalk-client-binding.request")}
chown 1000:1000 {quote(home / "dirextalk-client-binding.request")}
chmod 0400 {quote(home / "dirextalk-client-binding.request")}
printf x > {quote(home / "dirextalk-client-binding.import.json")}
chown 1000:1000 {quote(home / "dirextalk-client-binding.import.json")}
chmod 0400 {quote(home / "dirextalk-client-binding.import.json")}
{quote(helper)}
[[ -z $(find {quote(binding)} {quote(home)} -type f -print -quit) ]]
"""
    assert_success(run_fakeroot(script), "cleanup crash states")

    invalid_root = base / "cleanup-invalid-root"
    invalid_home = base / "cleanup-invalid-home"
    invalid_helper = base / "cleanup-invalid-helper"
    rewritten(CLEANUP, invalid_helper, invalid_root, invalid_home)
    invalid_tmp = invalid_root / "binding/import.json.export.tmp"
    invalid_script = setup_commands(invalid_root, invalid_home) + f"""
printf x > {quote(invalid_tmp)}
chown 0:0 {quote(invalid_tmp)}
chmod 0400 {quote(invalid_tmp)}
if {quote(invalid_helper)} >/dev/null 2>&1; then exit 1; fi
[[ -e {quote(invalid_tmp)} ]]
"""
    assert_success(run_fakeroot(invalid_script), "cleanup invalid-state rejection")


def fake_image_docker(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DTX_TEST_DOCKER_LOG"
case "$1" in
  pull) exit 0 ;;
  create) printf '%s\n' "$2" ;;
  export)
    shift
    [[ "$1" == --output ]]
    if [[ "$3" == debian:* ]]; then
      tar -cf "$2" -C "$DTX_TEST_BASE_ROOTFS" .
    else
      tar -cf "$2" -C "$DTX_TEST_ROOTFS" .
    fi
    ;;
  rm)
    [[ ${DTX_TEST_DOCKER_RM_FAIL:-0} != 1 ]]
    ;;
  *) exit 2 ;;
esac
"""
    )
    path.chmod(0o755)


def test_image_gate_cleanup(base: Path) -> None:
    fake_bin = base / "image-bin"
    fake_bin.mkdir()
    fake_image_docker(fake_bin / "docker")
    rootfs = base / "rootfs"
    base_rootfs = base / "base-rootfs"
    (rootfs / "usr/bin").mkdir(parents=True)
    (base_rootfs / "usr/lib").mkdir(parents=True)
    (rootfs / "usr/bin/runtime").write_bytes(b"runtime")
    inherited = b'-----BEGIN PRIVATE KEY-----\nsynthetic\n'
    (base_rootfs / "usr/lib/base-material").write_bytes(inherited)
    (rootfs / "usr/lib").mkdir()
    (rootfs / "usr/lib/base-material").write_bytes(inherited)
    log = base / "image-docker.log"
    digest_a = "dirextalk/vnet-server@sha256:" + "1" * 64
    digest_b = "dirextalk/vnet-server@sha256:" + "2" * 64
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "DTX_TEST_DOCKER_LOG": str(log),
        "DTX_TEST_ROOTFS": str(rootfs),
        "DTX_TEST_BASE_ROOTFS": str(base_rootfs),
    }
    success = subprocess.run(
        [
            "bash",
            str(IMAGE_GATE),
            "--runtime-image",
            digest_a,
            "--migrator-image",
            digest_b,
        ],
        cwd=REPOSITORY,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert_success(success, "runtime and migrator image scans")
    log_text = log.read_text()
    if log_text.count("pull ") != 3 or log_text.count("export ") != 3 or log_text.count("rm ") != 3:
        raise AssertionError("both immutable images were not exported and cleaned")

    def reject_changed_artifact(label: str) -> None:
        rejected = subprocess.run(
            ["bash", str(IMAGE_GATE), "--runtime-image", digest_a],
            cwd=REPOSITORY,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if rejected.returncode == 0 or "sensitive-content" not in rejected.stdout:
            raise AssertionError(f"{label} secret artifact did not fail the image gate")

    (rootfs / "usr/bin/runtime").write_bytes(inherited)
    reject_changed_artifact("added")
    (rootfs / "usr/bin/runtime").write_bytes(b"runtime")
    (rootfs / "usr/lib/base-material").write_bytes(inherited + b"changed")
    reject_changed_artifact("changed")
    (rootfs / "usr/lib/base-material").write_bytes(inherited)

    failure_env = {**env, "DTX_TEST_DOCKER_RM_FAIL": "1"}
    failure = subprocess.run(
        ["bash", str(IMAGE_GATE), "--runtime-image", digest_a],
        cwd=REPOSITORY,
        env=failure_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if failure.returncode == 0 or "cleanup failed" not in failure.stderr:
        raise AssertionError("normal-path container cleanup failure did not fail the image gate")


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        test_issue_normal_and_replay(base)
        test_crash_modes(base)
        test_link_and_device_rejection(base)
        test_cleanup_states(base)
        test_image_gate_cleanup(base)
    print("client-binding release artifact behavioral checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
