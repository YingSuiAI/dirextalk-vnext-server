#!/usr/bin/env python3
"""Build and verify the canonical Dirextalk vNext stack tar bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = "dirextalk-vnext-stack"
SCHEMA = "dirextalk.vnext-stack-bundle"
RELEASE_FACT_SCHEMA = "dirextalk.vnet-server-release-facts"
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"dirextalk/vnet-server@sha256:[0-9a-f]{64}")
FILES = (
    "docker/production/Caddyfile",
    "docker/production/README.md",
    "docker/production/config/agent-control.json.example",
    "docker/production/docker-compose.yml",
    "docker/production/examples/x6.env.example",
    "docker/production/examples/x7.env.example",
    "docker/production/examples/x8.env.example",
    "docker/production/migration-compatibility",
    "scripts/production-stack/bootstrap.sh",
    "scripts/production-stack/cleanup-cache.sh",
    "scripts/production-stack/down.sh",
    "scripts/production-stack/host/client-binding-expire",
    "scripts/production-stack/host/client-binding-export-cleanup",
    "scripts/production-stack/host/client-binding-issue",
    "scripts/production-stack/host/client-binding-revoke",
    "scripts/production-stack/install.sh",
    "scripts/production-stack/update.sh",
    "scripts/production-stack/validate-files.sh",
    "scripts/production-stack/validate-images.sh",
    "scripts/production-stack/verify.sh",
    "tools/validate-production-images.py",
)
EXECUTABLES = frozenset(
    path for path in FILES if path.endswith((".sh", ".py")) or path.startswith("scripts/production-stack/host/")
)
MANIFEST_KEYS = {
    "schema", "schema_version", "version", "source_commit", "target",
    "server_image", "migrator_image", "installer_sha256", "files",
}
FILE_KEYS = {"path", "sha256", "mode"}
RELEASE_FACT_KEYS = {
    "schema", "schema_version", "version", "source_commit", "target",
    "repository", "release_input_sha256", "runtime_version_tag",
    "runtime_commit_tag", "migrator_version_tag", "migrator_commit_tag",
    "server_image", "migrator_image", "latest_discovery_tag",
    "latest_discovery_digest",
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and str(path) == value


def validate_manifest(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise ValueError("manifest keys are not exact")
    if manifest["schema"] != SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("manifest schema is invalid")
    if not isinstance(manifest["version"], str) or SEMVER.fullmatch(manifest["version"]) is None:
        raise ValueError("manifest version is not SemVer")
    if not isinstance(manifest["source_commit"], str) or HEX40.fullmatch(manifest["source_commit"]) is None:
        raise ValueError("manifest source_commit is invalid")
    if manifest["target"] != "linux-amd64":
        raise ValueError("manifest target is invalid")
    for key in ("server_image", "migrator_image"):
        if not isinstance(manifest[key], str) or IMAGE.fullmatch(manifest[key]) is None:
            raise ValueError(f"manifest {key} is invalid")
    if not isinstance(manifest["installer_sha256"], str) or HEX64.fullmatch(manifest["installer_sha256"]) is None:
        raise ValueError("manifest installer digest is invalid")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ValueError("manifest files are invalid")
    paths: list[str] = []
    for record in files:
        if not isinstance(record, dict) or set(record) != FILE_KEYS:
            raise ValueError("manifest file record keys are not exact")
        path = record["path"]
        if not isinstance(path, str) or not safe_path(path):
            raise ValueError("manifest file path is unsafe")
        if not isinstance(record["sha256"], str) or HEX64.fullmatch(record["sha256"]) is None:
            raise ValueError("manifest file digest is invalid")
        if record["mode"] not in ("0444", "0555"):
            raise ValueError("manifest file mode is invalid")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ValueError("manifest files are not a sorted unique allowlist")
    if manifest["installer_sha256"] != next(
        (record["sha256"] for record in files if record["path"] == "scripts/production-stack/install.sh"),
        None,
    ):
        raise ValueError("installer digest is not bound to the fixed installer")
    return manifest


def load_release_facts(path: Path) -> tuple[str, str, str, str]:
    raw = path.read_bytes()
    facts = json.loads(raw)
    if not isinstance(facts, dict) or set(facts) != RELEASE_FACT_KEYS:
        raise ValueError("release fact keys are not exact")
    if facts["schema"] != RELEASE_FACT_SCHEMA or facts["schema_version"] != 1:
        raise ValueError("release fact schema is invalid")
    version = facts["version"]
    source_commit = facts["source_commit"]
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise ValueError("release fact version is invalid")
    if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
        raise ValueError("release fact source commit is invalid")
    if facts["target"] != "linux-amd64" or facts["repository"] != "dirextalk/vnet-server":
        raise ValueError("release fact target or repository is invalid")
    if not isinstance(facts["release_input_sha256"], str) or HEX64.fullmatch(facts["release_input_sha256"]) is None:
        raise ValueError("release input digest is invalid")
    expected_tags = {
        "runtime_version_tag": f"dirextalk/vnet-server:{version}",
        "runtime_commit_tag": f"dirextalk/vnet-server:git-{source_commit}",
        "migrator_version_tag": f"dirextalk/vnet-server:migrate-{version}",
        "migrator_commit_tag": f"dirextalk/vnet-server:migrate-git-{source_commit}",
        "latest_discovery_tag": "dirextalk/vnet-server:latest",
    }
    if any(facts[key] != expected for key, expected in expected_tags.items()):
        raise ValueError("release fact immutable or discovery tags are invalid")
    for key in ("server_image", "migrator_image"):
        if not isinstance(facts[key], str) or IMAGE.fullmatch(facts[key]) is None:
            raise ValueError(f"release fact {key} is invalid")
    latest = facts["latest_discovery_digest"]
    if not isinstance(latest, str) or latest != facts["server_image"].removeprefix("dirextalk/vnet-server@"):
        raise ValueError("latest discovery fact does not match the runtime digest")
    if raw != canonical(facts):
        raise ValueError("release facts are not canonical JSON")
    return version, source_commit, facts["server_image"], facts["migrator_image"]


def source_files(source_root: Path) -> list[tuple[str, bytes, str]]:
    result: list[tuple[str, bytes, str]] = []
    for relative in FILES:
        path = source_root / relative
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ValueError(f"bundle source is not a regular file: {relative}")
        result.append((relative, path.read_bytes(), "0555" if relative in EXECUTABLES else "0444"))
    return result


def build(source_root: Path, output: Path, version: str, source_commit: str, server_image: str, migrator_image: str) -> None:
    files = source_files(source_root)
    records = [{"path": path, "sha256": digest(data), "mode": mode} for path, data, mode in files]
    manifest = validate_manifest({
        "schema": SCHEMA,
        "schema_version": 1,
        "version": version,
        "source_commit": source_commit,
        "target": "linux-amd64",
        "server_image": server_image,
        "migrator_image": migrator_image,
        "installer_sha256": next(record["sha256"] for record in records if record["path"] == "scripts/production-stack/install.sh"),
        "files": records,
    })
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with tarfile.open(temporary, "w", format=tarfile.USTAR_FORMAT) as archive:
        directories = {ROOT}
        for relative, _, _ in files:
            current = PurePosixPath(ROOT, relative).parent
            while str(current) != ".":
                directories.add(str(current))
                if str(current) == ROOT:
                    break
                current = current.parent
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o555
            info.uid = info.gid = 0
            info.mtime = 0
            archive.addfile(info)
        entries = [("manifest.json", canonical(manifest), "0444"), *files]
        for relative, data, mode in sorted(entries):
            info = tarfile.TarInfo(f"{ROOT}/{relative}")
            info.size = len(data)
            info.mode = int(mode, 8)
            info.uid = info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    os.replace(temporary, output)


def verify(bundle: Path) -> dict[str, object]:
    seen: set[str] = set()
    directories: set[str] = set()
    payloads: dict[str, bytes] = {}
    modes: dict[str, str] = {}
    with tarfile.open(bundle, "r:") as archive:
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            if name in seen or not safe_path(name) or not (name == ROOT or name.startswith(ROOT + "/")):
                raise ValueError("archive member path is unsafe or duplicated")
            seen.add(name)
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError("archive contains a link or special member")
            if member.uid != 0 or member.gid != 0:
                raise ValueError("archive member owner is not root")
            if member.isdir():
                if member.mode != 0o555:
                    raise ValueError("archive directory mode is invalid")
                directories.add(name)
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("archive file could not be read")
            payloads[name] = stream.read()
            modes[name] = f"{member.mode:04o}"
    manifest_name = f"{ROOT}/manifest.json"
    raw_manifest = payloads.pop(manifest_name, None)
    manifest_mode = modes.pop(manifest_name, None)
    if raw_manifest is None or manifest_mode != "0444":
        raise ValueError("archive manifest is missing")
    manifest = validate_manifest(json.loads(raw_manifest))
    if raw_manifest != canonical(manifest):
        raise ValueError("archive manifest is not canonical JSON")
    expected = {f"{ROOT}/{record['path']}": record for record in manifest["files"]}
    if set(payloads) != set(expected):
        raise ValueError("archive file set differs from manifest allowlist")
    expected_directories = {ROOT}
    for name in expected:
        current = PurePosixPath(name).parent
        while str(current) != ".":
            expected_directories.add(str(current))
            if str(current) == ROOT:
                break
            current = current.parent
    if directories != expected_directories:
        raise ValueError("archive directory set differs from manifest allowlist")
    for name, record in expected.items():
        if digest(payloads[name]) != record["sha256"] or modes[name] != record["mode"]:
            raise ValueError(f"archive file contract mismatch: {name}")
    return manifest


def self_test(source_root: Path) -> None:
    image = "dirextalk/vnet-server@sha256:" + "1" * 64
    with tempfile.TemporaryDirectory() as directory:
        bundle = Path(directory) / "stack.bundle"
        build(source_root, bundle, "1.2.3", "a" * 40, image, image)
        verify(bundle)
        malicious = Path(directory) / "link.bundle"
        with tarfile.open(malicious, "w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(f"{ROOT}/escape")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            archive.addfile(info)
        try:
            verify(malicious)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink archive was accepted")
        invalid = dict(verify(bundle))
        invalid["server_image"] = "dirextalk/vnet-server:latest"
        try:
            validate_manifest(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("mutable server image was accepted")
        invalid = dict(verify(bundle))
        invalid["version"] = "1.2.3-01"
        try:
            validate_manifest(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("non-SemVer version was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "verify", "self-test"))
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--source-commit")
    parser.add_argument("--server-image")
    parser.add_argument("--migrator-image")
    parser.add_argument("--release-facts", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "self-test":
        self_test(arguments.source_root)
    elif arguments.command == "verify":
        if arguments.output is None:
            parser.error("verify requires --output")
        verify(arguments.output)
    else:
        if arguments.output is None:
            parser.error("build requires --output")
        direct = (arguments.version, arguments.source_commit, arguments.server_image, arguments.migrator_image)
        if arguments.release_facts is not None:
            if any(value is not None for value in direct):
                parser.error("build accepts release facts or direct release fields, not both")
            version, source_commit, server_image, migrator_image = load_release_facts(arguments.release_facts)
        else:
            if any(value is None for value in direct):
                parser.error("build requires --release-facts or all direct release fields")
            version, source_commit, server_image, migrator_image = direct
        build(arguments.source_root, arguments.output, version, source_commit, server_image, migrator_image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
