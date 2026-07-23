#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"

usage() {
    printf 'Usage: bash scripts/check-release-image.sh [--runtime-image dirextalk/vnet-server@sha256:<64-hex> --migrator-image dirextalk/vnet-server@sha256:<64-hex>]\n'
}

runtime_image=
migrator_image=
while (( $# > 0 )); do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --runtime-image)
            (( $# >= 2 )) && [[ -z "$runtime_image" ]] || { usage >&2; exit 2; }
            runtime_image=$2
            shift 2
            ;;
        --migrator-image)
            (( $# >= 2 )) && [[ -z "$migrator_image" ]] || { usage >&2; exit 2; }
            migrator_image=$2
            shift 2
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done
for image in "$runtime_image" "$migrator_image"; do
    if [[ -n "$image" ]]; then
        [[ "$image" =~ ^dirextalk/vnet-server@sha256:[0-9a-f]{64}$ ]] || {
            echo 'release image must be an immutable repository digest' >&2
            exit 2
        }
    fi
done
if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 is required to inspect the release image contract.\n' >&2
    exit 1
fi

cd -- "$repository_root"
if [[ -n "$runtime_image" || -n "$migrator_image" ]]; then
    command -v docker >/dev/null 2>&1 || { echo 'docker is required for release image export scanning' >&2; exit 1; }
    export_tar=
    container=
    cleanup_export() {
        local failed=0
        if [[ -n "$container" ]]; then
            if docker rm "$container" >/dev/null 2>&1; then
                container=
            else
                failed=1
            fi
        fi
        if [[ -n "$export_tar" && ( -e "$export_tar" || -L "$export_tar" ) ]]; then
            if rm -f -- "$export_tar"; then
                export_tar=
            else
                failed=1
            fi
        fi
        return "$failed"
    }
    finish_export() {
        local status=$?
        trap - EXIT
        if ! cleanup_export; then
            status=1
        fi
        exit "$status"
    }
    scan_image() {
        local image=$1
        export_tar=$(mktemp)
        docker pull "$image" >/dev/null
        container=$(docker create "$image")
        [[ -n "$container" ]] || { echo 'release image container creation returned no id' >&2; return 1; }
        docker export --output "$export_tar" "$container"
        python3 tools/check-runtime-secret-artifacts.py --tar "$export_tar"
        if ! cleanup_export; then
            echo 'release image export cleanup failed' >&2
            return 1
        fi
    }
    trap finish_export EXIT
    [[ -z "$runtime_image" ]] || scan_image "$runtime_image"
    [[ -z "$migrator_image" ]] || scan_image "$migrator_image"
    trap - EXIT
else
    python3 tools/check-runtime-secret-artifacts.py --self-test
fi
python3 - <<'PY'
import json
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Instruction:
    keyword: str
    argument: str
    line: int


def dockerfile_instructions(text: str) -> list[Instruction]:
    """Read Dockerfile instructions after folding continuation lines."""
    instructions: list[Instruction] = []
    pending = ""
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip()
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not pending:
            start_line = line_number
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        pending += line
        content = pending.strip()
        pending = ""
        if not content or content.startswith("#"):
            continue
        parts = content.split(None, 1)
        if len(parts) != 2:
            raise SystemExit(f"Dockerfile line {start_line} has no instruction argument")
        instructions.append(Instruction(parts[0].upper(), parts[1].strip(), start_line))
    if pending:
        raise SystemExit(f"Dockerfile line {start_line} ends with a continuation")
    return instructions


def tokens(instruction: Instruction) -> list[str]:
    try:
        return shlex.split(instruction.argument, comments=False, posix=True)
    except ValueError as error:
        raise SystemExit(f"Dockerfile line {instruction.line} has invalid quoting: {error}") from error


def fail(message: str) -> None:
    raise SystemExit(message)


root = Path.cwd()
manifest_path = root / "docker/release/manifest.json"
dockerfile_path = root / "docker/release/Dockerfile"
readme_path = root / "docker/release/README.md"
try:
    manifest = json.loads(manifest_path.read_text())
except (OSError, json.JSONDecodeError) as error:
    fail(f"release manifest is not valid JSON: {error}")
dockerfile = dockerfile_path.read_text()
readme = readme_path.read_text()

expected = [
    ("dtx-node", "dtx-node", "/usr/local/bin/dtx-node"),
    ("dtx-opaque-push-broker", "dtx-opaque-push-broker", "/usr/local/bin/dtx-opaque-push-broker"),
    ("dtx-realtime-sync-gateway", "dtx-realtime-sync-gateway", "/usr/local/bin/dtx-realtime-sync-gateway"),
    ("dtx-agent-control", "dtx-agent-control-bin", "/usr/local/bin/dtx-agent-control"),
    ("dtx-identity-provision", "dtx-identity-node", "/usr/local/bin/dtx-identity-provision"),
]
actual = [
    (artifact.get("binary"), artifact.get("package"), artifact.get("path"))
    for artifact in manifest.get("artifacts", [])
]
if manifest.get("schema_version") != 1 or actual != expected:
    fail(f"release artifact manifest mismatch: {actual!r}")
if manifest.get("source") != {
    "dockerfile": "docker/release/Dockerfile",
    "lockfile": "Cargo.lock",
}:
    fail("release source inputs are not pinned to the Dockerfile and Cargo.lock")
if manifest.get("runtime") != {
    "file_owner": "root:root",
    "file_mode": "0555",
    "process_uid": 10001,
    "process_gid": 10001,
    "default_entrypoint": "/usr/local/bin/dtx-node",
}:
    fail("release runtime ownership/mode contract changed")

instructions = dockerfile_instructions(dockerfile)
from_instructions = [instruction for instruction in instructions if instruction.keyword == "FROM"]
if len(from_instructions) != 2:
    fail(f"release Dockerfile must have exactly two stages, found {len(from_instructions)}")

build_from, runtime_from = from_instructions
if tokens(build_from) != [
    "rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073",
    "AS",
    "build",
]:
    fail("release build base or stage alias is not the pinned build image")
if tokens(runtime_from) != [
    "debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818",
    "AS",
    "runtime",
]:
    fail("release runtime base or stage alias is not the pinned runtime image")

runtime_start = instructions.index(runtime_from)
build_stage = instructions[:runtime_start]
runtime_stage = instructions[runtime_start:]
if [instruction.keyword for instruction in build_stage] != ["FROM", "WORKDIR", "COPY", "RUN"]:
    fail("build stage instruction structure changed")
if [instruction.keyword for instruction in runtime_stage] != [
    "FROM", "COPY", "RUN", "COPY", "COPY", "COPY", "COPY", "COPY",
    "ENV", "EXPOSE", "STOPSIGNAL", "USER", "ENTRYPOINT",
]:
    fail("runtime stage instruction structure changed")
if any(instruction.keyword == "CMD" for instruction in runtime_stage):
    fail("release image must not declare CMD")
if any(instruction.keyword == "ARG" for instruction in runtime_stage):
    fail("release runtime stage must not expose ARG interfaces")
if tokens(build_stage[1]) != ["/workspace"]:
    fail("release build WORKDIR changed")
if tokens(build_stage[2]) != [".", "."]:
    fail("release build context COPY changed")

def command_tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError as error:
        fail(f"invalid shell quoting in release build RUN: {error}")

run_segments: list[list[str]] = []
for segment in build_stage[-1].argument.split("&&"):
    segment_tokens = command_tokens(segment.strip())
    if segment_tokens:
        run_segments.append(segment_tokens)

def command_after_mounts(segment_tokens: list[str], command: str) -> list[str] | None:
    try:
        index = segment_tokens.index(command)
    except ValueError:
        return None
    if any(not token.startswith("--mount=") for token in segment_tokens[:index]):
        fail(f"unexpected tokens before {command} in build RUN")
    return segment_tokens[index:]

cargo_commands = []
install_commands = []
remove_commands = []
for segment_tokens in run_segments:
    for command in ("cargo", "install", "rm"):
        found = command_after_mounts(segment_tokens, command)
        if found is not None:
            if command == "cargo":
                cargo_commands.append(found)
            elif command == "install":
                install_commands.append(found)
            else:
                remove_commands.append(found)
            break
    else:
        fail(f"unexpected command in release build RUN: {segment_tokens!r}")

if cargo_commands != [
    [
        "cargo", "build", "--release", "--locked",
        "--package", "dtx-node",
        "--package", "dtx-opaque-push-broker",
        "--package", "dtx-realtime-sync-gateway",
        "--package", "dtx-identity-node", "--bin", "dtx-identity-provision",
    ],
    [
        "cargo", "build", "--release", "--locked",
        "--package", "dtx-agent-control-bin", "--bin", "dtx-agent-control",
    ],
]:
    fail(f"release build targets changed: {cargo_commands!r}")
if remove_commands != [
    [
        "rm", "-f",
        "/workspace/target/release/dtx-node",
        "/workspace/target/release/dtx-opaque-push-broker",
        "/workspace/target/release/dtx-realtime-sync-gateway",
        "/workspace/target/release/dtx-identity-provision",
        "/workspace/target/release/dtx-agent-control",
    ],
    ["rm", "-f", "/workspace/target/release/dtx-agent-control"],
]:
    fail("release build must clear cached outputs before each target selection")

expected_installs = [
    ["install", "-D", "-m", "0555", f"/workspace/target/release/{binary}", f"/artifacts/{binary}"]
    for binary, _, _ in expected
]
if install_commands != expected_installs:
    fail(f"release install targets changed: {install_commands!r}")

expected_copy = {(f"/artifacts/{binary}", path) for binary, _, path in expected}
artifact_copies: list[tuple[str, str]] = []
for instruction in runtime_stage:
    if instruction.keyword != "COPY":
        continue
    copy_tokens = tokens(instruction)
    if copy_tokens[:1] == ["--from=build"] and len(copy_tokens) == 3:
        source, destination = copy_tokens[1:]
        if source.startswith("/artifacts/"):
            artifact_copies.append((source, destination))
if set(artifact_copies) != expected_copy or len(artifact_copies) != len(expected_copy):
    fail(f"release artifact COPY allowlist changed: {artifact_copies!r}")

cert_copy = [
    tokens(instruction)
    for instruction in runtime_stage
    if instruction.keyword == "COPY"
    and tokens(instruction) == [
        "--from=build",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-certificates.crt",
    ]
]
if len(cert_copy) != 1:
    fail("release image must copy the pinned CA bundle exactly once")
if any(
    instruction.keyword == "COPY"
    and tokens(instruction)[:1] == ["--from=build"]
    and len(tokens(instruction)) == 3
    and tokens(instruction)[1].startswith("/artifacts/")
    and tuple(tokens(instruction)[1:]) not in expected_copy
    for instruction in runtime_stage
):
    fail("release image contains an unlisted executable artifact")

runtime_runs = [instruction for instruction in runtime_stage if instruction.keyword == "RUN"]
if len(runtime_runs) != 1 or tokens(runtime_runs[0]) != [
    "useradd", "--system", "--uid", "10001", "--create-home",
    "--home-dir", "/var/lib/dirextalk", "dtx",
]:
    fail("runtime stage may only create the fixed non-root user")

env_instructions = [instruction for instruction in runtime_stage if instruction.keyword == "ENV"]
if len(env_instructions) != 1:
    fail("runtime stage ENV cardinality changed")
env_pairs = tokens(env_instructions[0])
if env_pairs != ["DTX_NODE_LISTEN=0.0.0.0:8443"]:
    fail(f"runtime ENV interface changed: {env_pairs!r}")
if any(
    instruction.keyword in {"ENV", "ARG"}
    and "DTX_AGENT_CONTROL" in instruction.argument
    for instruction in instructions
):
    fail("Agent Control must not gain a Dockerfile ENV or ARG interface")

expose_instructions = [instruction for instruction in runtime_stage if instruction.keyword == "EXPOSE"]
if len(expose_instructions) != 1 or tokens(expose_instructions[0]) != ["8443", "9444", "9448"]:
    fail("runtime EXPOSE contract changed")
stopsignal = [instruction for instruction in runtime_stage if instruction.keyword == "STOPSIGNAL"]
if len(stopsignal) != 1 or tokens(stopsignal[0]) != ["SIGTERM"]:
    fail("runtime STOPSIGNAL contract changed")

users = [instruction for instruction in runtime_stage if instruction.keyword == "USER"]
if len(users) != 1 or tokens(users[0]) != ["10001:10001"]:
    fail("runtime USER contract changed")
entrypoints = [instruction for instruction in runtime_stage if instruction.keyword == "ENTRYPOINT"]
if len(entrypoints) != 1:
    fail("release image must have exactly one ENTRYPOINT")
try:
    entrypoint = json.loads(entrypoints[0].argument)
except json.JSONDecodeError as error:
    fail(f"runtime ENTRYPOINT is not valid JSON: {error}")
if entrypoint != ["/usr/local/bin/dtx-node"]:
    fail(f"runtime ENTRYPOINT changed: {entrypoint!r}")
if runtime_stage[-1] is not entrypoints[0] or runtime_stage.index(users[0]) > runtime_stage.index(entrypoints[0]):
    fail("runtime USER/ENTRYPOINT must be effective final-stage settings")
if any(instruction.keyword == "CMD" for instruction in instructions):
    fail("release image must not declare CMD")

for required in (
    "manifest.json",
    "/usr/local/bin/dtx-agent-control",
    "--config /etc/dirextalk/agent-control.json",
    "UID/GID " + chr(96) + "10001:10001" + chr(96),
    "dirextalk/vnet-server@sha256:<64>",
):
    if required not in readme:
        fail(f"release README contract missing: {required}")
PY
python3 tools/production-release.py self-test --repository-root .
bash -n scripts/publish-production-release.sh scripts/cleanup-production-release.sh
for script in scripts/publish-production-release.sh scripts/cleanup-production-release.sh tools/production-release.py; do
    test -x "$script" || { echo "release helper is not executable: $script" >&2; exit 1; }
done
grep -q 'dirextalk.vnet-server-release-input' docker/release/production-release.json
grep -q -- '--platform linux/amd64' scripts/publish-production-release.sh
grep -q -- '--file docker/release/Dockerfile' scripts/publish-production-release.sh
grep -q -- '--file docker/production/Dockerfile.migrate' scripts/publish-production-release.sh
grep -q 'runtime_version_tag=.*repository.*version' scripts/publish-production-release.sh
grep -q 'migrator_version_tag=.*repository:migrate-.*version' scripts/publish-production-release.sh
grep -q 'verified-digest' scripts/publish-production-release.sh
grep -q 'latest is a runtime discovery pointer only' scripts/publish-production-release.sh
grep -q 'buildx imagetools create' scripts/publish-production-release.sh
grep -q 'buildx rm --force' scripts/cleanup-production-release.sh
! grep -Eq 'docker (image|volume|system) (rm|prune)' scripts/{publish,cleanup}-production-release.sh
python3 - <<'PY'
from pathlib import Path

script = Path("scripts/publish-production-release.sh").read_text()
migrator_readback = script.index('    --metadata "$state/migrator-metadata.json"')
latest_move = script.index("# latest is a runtime discovery pointer only")
facts = script.index("python3 tools/production-release.py emit-facts")
if not migrator_readback < latest_move < facts:
    raise SystemExit("latest discovery pointer is not ordered after both immutable read-backs")
PY
