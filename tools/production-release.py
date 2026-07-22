#!/usr/bin/env python3
"""Validate production release inputs and registry read-back evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from pathlib import Path

INPUT_SCHEMA = "dirextalk.vnet-server-release-input"
FACTS_SCHEMA = "dirextalk.vnet-server-release-facts"
REPOSITORY = "dirextalk/vnet-server"
PLATFORM = "linux/amd64"
TARGET = "linux-amd64"
RUNTIME_DOCKERFILE = "docker/release/Dockerfile"
MIGRATOR_DOCKERFILE = "docker/production/Dockerfile.migrate"
MAX_JSON_BYTES = 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RELEASE_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
INPUT_KEYS = {
    "schema",
    "schema_version",
    "version",
    "repository",
    "platform",
    "runtime_dockerfile",
    "migrator_dockerfile",
    "latest_discovery",
}
FACT_KEYS = {
    "schema",
    "schema_version",
    "version",
    "source_commit",
    "target",
    "repository",
    "release_input_sha256",
    "runtime_version_tag",
    "runtime_commit_tag",
    "migrator_version_tag",
    "migrator_commit_tag",
    "server_image",
    "migrator_image",
    "latest_discovery_tag",
    "latest_discovery_digest",
}


class ReleaseError(RuntimeError):
    """Release input or evidence violates the frozen publication contract."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("JSON contains a duplicate key")
        result[key] = value
    return result


def read_regular(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_JSON_BYTES:
        raise ReleaseError(f"release evidence is not a bounded regular file: {path}")
    return path.read_bytes()


def decode(path: Path) -> tuple[object, bytes]:
    raw = read_regular(path)
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"release JSON is invalid: {path}") from error


def load_input(path: Path, repository_root: Path) -> tuple[dict[str, object], bytes]:
    value, raw = decode(path)
    if not isinstance(value, dict) or set(value) != INPUT_KEYS:
        raise ReleaseError("production release input keys are not exact")
    if value.get("schema") != INPUT_SCHEMA or value.get("schema_version") != 1:
        raise ReleaseError("production release input schema is invalid")
    if value.get("repository") != REPOSITORY or value.get("platform") != PLATFORM:
        raise ReleaseError("production release repository or platform is not authorized")
    if value.get("runtime_dockerfile") != RUNTIME_DOCKERFILE:
        raise ReleaseError("production runtime Dockerfile is not fixed")
    if value.get("migrator_dockerfile") != MIGRATOR_DOCKERFILE:
        raise ReleaseError("production migrator Dockerfile is not fixed")
    if value.get("latest_discovery") is not True:
        raise ReleaseError("runtime latest discovery publication must be explicit")
    version = value.get("version")
    if not isinstance(version, str) or RELEASE_SEMVER.fullmatch(version) is None:
        raise ReleaseError("production release version is not tag-safe SemVer")
    cargo = tomllib.loads((repository_root / "Cargo.toml").read_text())
    if cargo.get("workspace", {}).get("package", {}).get("version") != version:
        raise ReleaseError("production release version differs from workspace.package.version")
    if raw != canonical(value):
        raise ReleaseError("production release input is not canonical JSON")
    return value, raw


def tags(version: str, source_commit: str) -> dict[str, str]:
    if RELEASE_SEMVER.fullmatch(version) is None or HEX40.fullmatch(source_commit) is None:
        raise ReleaseError("release version or source commit is invalid")
    return {
        "runtime_version_tag": f"{REPOSITORY}:{version}",
        "runtime_commit_tag": f"{REPOSITORY}:git-{source_commit}",
        "migrator_version_tag": f"{REPOSITORY}:migrate-{version}",
        "migrator_commit_tag": f"{REPOSITORY}:migrate-git-{source_commit}",
        "latest_discovery_tag": f"{REPOSITORY}:latest",
    }


def metadata_digest(path: Path) -> str:
    value, _ = decode(path)
    if not isinstance(value, dict) or not isinstance(value.get("containerimage.digest"), str):
        raise ReleaseError("Buildx metadata has no container image digest")
    result = value["containerimage.digest"]
    if DIGEST.fullmatch(result) is None:
        raise ReleaseError("Buildx metadata image digest is invalid")
    return result


def manifest_digest(path: Path) -> str:
    value, _ = decode(path)
    if not isinstance(value, dict) or not isinstance(value.get("digest"), str):
        raise ReleaseError("registry manifest evidence has no digest")
    result = value["digest"]
    if DIGEST.fullmatch(result) is None:
        raise ReleaseError("registry manifest digest is invalid")
    return result


def verified_digest(metadata: Path, version_manifest: Path, commit_manifest: Path) -> str:
    values = (
        metadata_digest(metadata),
        manifest_digest(version_manifest),
        manifest_digest(commit_manifest),
    )
    if len(set(values)) != 1:
        raise ReleaseError("immutable tag registry read-back differs from the pushed digest")
    return values[0]


def make_facts(
    release_input: dict[str, object],
    release_input_raw: bytes,
    source_commit: str,
    runtime_digest: str,
    migrator_digest: str,
    latest_digest: str,
) -> dict[str, object]:
    version = str(release_input["version"])
    tag_values = tags(version, source_commit)
    for value in (runtime_digest, migrator_digest, latest_digest):
        if DIGEST.fullmatch(value) is None:
            raise ReleaseError("release fact digest is invalid")
    if latest_digest != runtime_digest:
        raise ReleaseError("latest discovery pointer does not resolve to the runtime digest")
    return {
        "schema": FACTS_SCHEMA,
        "schema_version": 1,
        "version": version,
        "source_commit": source_commit,
        "target": TARGET,
        "repository": REPOSITORY,
        "release_input_sha256": sha256(release_input_raw),
        **tag_values,
        "server_image": f"{REPOSITORY}@{runtime_digest}",
        "migrator_image": f"{REPOSITORY}@{migrator_digest}",
        "latest_discovery_digest": latest_digest,
    }


def validate_facts(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != FACT_KEYS:
        raise ReleaseError("production release fact keys are not exact")
    if value.get("schema") != FACTS_SCHEMA or value.get("schema_version") != 1:
        raise ReleaseError("production release fact schema is invalid")
    if value.get("target") != TARGET or value.get("repository") != REPOSITORY:
        raise ReleaseError("production release fact target or repository is invalid")
    version = value.get("version")
    source_commit = value.get("source_commit")
    if not isinstance(version, str) or not isinstance(source_commit, str):
        raise ReleaseError("production release fact version or commit is invalid")
    expected_tags = tags(version, source_commit)
    if any(value.get(key) != expected for key, expected in expected_tags.items()):
        raise ReleaseError("production release fact tags are invalid")
    if not isinstance(value.get("release_input_sha256"), str) or re.fullmatch(
        r"[0-9a-f]{64}", value["release_input_sha256"]
    ) is None:
        raise ReleaseError("production release input digest is invalid")
    image = re.compile(rf"{re.escape(REPOSITORY)}@(sha256:[0-9a-f]{{64}})")
    server = value.get("server_image")
    migrator = value.get("migrator_image")
    if not isinstance(server, str) or image.fullmatch(server) is None:
        raise ReleaseError("production server image fact is invalid")
    if not isinstance(migrator, str) or image.fullmatch(migrator) is None:
        raise ReleaseError("production migrator image fact is invalid")
    latest = value.get("latest_discovery_digest")
    if not isinstance(latest, str) or latest != server.removeprefix(f"{REPOSITORY}@"):
        raise ReleaseError("latest discovery digest is not the server digest")
    return value


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def emit_facts(arguments: argparse.Namespace) -> None:
    repository_root = Path(arguments.repository_root).resolve()
    release_input, input_raw = load_input(Path(arguments.input), repository_root)
    runtime = verified_digest(
        Path(arguments.runtime_metadata),
        Path(arguments.runtime_version_manifest),
        Path(arguments.runtime_commit_manifest),
    )
    migrator = verified_digest(
        Path(arguments.migrator_metadata),
        Path(arguments.migrator_version_manifest),
        Path(arguments.migrator_commit_manifest),
    )
    latest = manifest_digest(Path(arguments.latest_manifest))
    facts = validate_facts(
        make_facts(release_input, input_raw, arguments.source_commit, runtime, migrator, latest)
    )
    atomic_write(Path(arguments.output), canonical(facts))


def self_test(repository_root: Path) -> None:
    input_path = repository_root / "docker/release/production-release.json"
    release_input, input_raw = load_input(input_path, repository_root)
    runtime = "sha256:" + "1" * 64
    migrator = "sha256:" + "2" * 64
    facts = make_facts(release_input, input_raw, "a" * 40, runtime, migrator, runtime)
    validate_facts(facts)
    try:
        make_facts(release_input, input_raw, "a" * 40, runtime, migrator, migrator)
    except ReleaseError:
        pass
    else:
        raise AssertionError("mismatched latest discovery digest was accepted")
    with tempfile.TemporaryDirectory() as temporary:
        metadata = Path(temporary) / "metadata.json"
        version_manifest = Path(temporary) / "version.json"
        commit_manifest = Path(temporary) / "commit.json"
        metadata.write_bytes(canonical({"containerimage.digest": runtime}))
        version_manifest.write_bytes(canonical({"digest": runtime}))
        commit_manifest.write_bytes(canonical({"digest": runtime}))
        if verified_digest(metadata, version_manifest, commit_manifest) != runtime:
            raise AssertionError("registry digest read-back failed")
        commit_manifest.write_bytes(canonical({"digest": migrator}))
        try:
            verified_digest(metadata, version_manifest, commit_manifest)
        except ReleaseError:
            pass
        else:
            raise AssertionError("incomplete release evidence was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    show = subparsers.add_parser("show-version")
    show.add_argument("--input", type=Path, required=True)
    show.add_argument("--repository-root", type=Path, default=Path.cwd())

    verify = subparsers.add_parser("verified-digest")
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--version-manifest", type=Path, required=True)
    verify.add_argument("--commit-manifest", type=Path, required=True)

    emit = subparsers.add_parser("emit-facts")
    emit.add_argument("--input", type=Path, required=True)
    emit.add_argument("--repository-root", type=Path, default=Path.cwd())
    emit.add_argument("--source-commit", required=True)
    emit.add_argument("--runtime-metadata", type=Path, required=True)
    emit.add_argument("--runtime-version-manifest", type=Path, required=True)
    emit.add_argument("--runtime-commit-manifest", type=Path, required=True)
    emit.add_argument("--migrator-metadata", type=Path, required=True)
    emit.add_argument("--migrator-version-manifest", type=Path, required=True)
    emit.add_argument("--migrator-commit-manifest", type=Path, required=True)
    emit.add_argument("--latest-manifest", type=Path, required=True)
    emit.add_argument("--output", type=Path, required=True)

    test = subparsers.add_parser("self-test")
    test.add_argument("--repository-root", type=Path, default=Path.cwd())

    arguments = parser.parse_args()
    try:
        if arguments.command == "show-version":
            value, _ = load_input(arguments.input, arguments.repository_root.resolve())
            print(value["version"])
        elif arguments.command == "verified-digest":
            print(verified_digest(arguments.metadata, arguments.version_manifest, arguments.commit_manifest))
        elif arguments.command == "emit-facts":
            emit_facts(arguments)
        else:
            self_test(arguments.repository_root.resolve())
    except (OSError, ReleaseError, tomllib.TOMLDecodeError) as error:
        parser.exit(1, f"production-release: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
