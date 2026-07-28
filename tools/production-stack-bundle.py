#!/usr/bin/env python3
"""Build the deterministic, digest-bound production stack USTAR bundle."""

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
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
MAX_FILE_BYTES = 4 * 1024 * 1024

FILES: tuple[tuple[str, int], ...] = (
    ("docker/production/Caddyfile", 0o444),
    ("docker/production/README.md", 0o444),
    ("docker/production/docker-compose.yml", 0o444),
    ("docker/production/migration-compatibility", 0o444),
    ("scripts/production-stack/bootstrap.sh", 0o555),
    ("scripts/production-stack/down.sh", 0o555),
    ("scripts/production-stack/install.sh", 0o555),
    ("scripts/production-stack/validate-files.sh", 0o555),
    ("scripts/production-stack/validate-images.sh", 0o555),
    ("scripts/production-stack/verify.sh", 0o555),
    ("scripts/production-stack/host/client-binding-expire", 0o555),
    ("scripts/production-stack/host/client-binding-export-cleanup", 0o555),
    ("scripts/production-stack/host/client-binding-issue", 0o555),
    ("scripts/production-stack/host/client-binding-revoke", 0o555),
    ("scripts/production-stack/host/deployment-binding-ticket-cleanup", 0o555),
    ("scripts/production-stack/host/deployment-binding-ticket-issue", 0o555),
    ("tools/validate-production-images.py", 0o555),
)


class BundleError(RuntimeError):
    """A production stack input violates the release contract."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(root: Path, relative: str) -> bytes:
    path = root / relative
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size == 0
        or metadata.st_size > MAX_FILE_BYTES
    ):
        raise BundleError(f"unsafe production stack input: {relative}")
    return path.read_bytes()


def directories(files: list[str]) -> list[str]:
    result = {ROOT}
    for relative in files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            result.add(f"{ROOT}/{parent.as_posix()}")
            parent = parent.parent
    return sorted(result, key=lambda value: (value.count("/"), value))


def header(name: str, mode: int, size: int, directory: bool) -> tarfile.TarInfo:
    item = tarfile.TarInfo(f"{name}/" if directory else name)
    item.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    item.mode = mode
    item.uid = 0
    item.gid = 0
    item.uname = ""
    item.gname = ""
    item.mtime = 0
    item.size = size
    return item


def load_facts(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    required = {"version", "source_commit", "target", "server_image", "migrator_image"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise BundleError("release facts are incomplete")
    if value["target"] != "linux-amd64" or not HEX40.fullmatch(str(value["source_commit"])):
        raise BundleError("release facts target or commit is invalid")
    for key in ("server_image", "migrator_image"):
        image = str(value[key])
        prefix = "dirextalk/vnet-server@"
        if not image.startswith(prefix) or not SHA256.fullmatch(image.removeprefix(prefix)):
            raise BundleError(f"release facts {key} is not digest-pinned")
    return value


def build(repository: Path, release_facts: Path, output: Path) -> dict[str, str]:
    facts = load_facts(release_facts)
    files: list[tuple[str, int, bytes]] = []
    for relative, mode in FILES:
        files.append((relative, mode, regular_bytes(repository, relative)))
    files.sort(key=lambda item: item[0])
    installer = next(raw for path, _, raw in files if path == "scripts/production-stack/install.sh")
    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "version": facts["version"],
        "source_commit": facts["source_commit"],
        "target": facts["target"],
        "server_image": facts["server_image"],
        "migrator_image": facts["migrator_image"],
        "installer_sha256": digest(installer),
        "files": [
            {"path": path, "sha256": digest(raw), "mode": f"{mode:04o}"}
            for path, mode, raw in files
        ],
    }
    manifest_bytes = canonical(manifest)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".stack-bundle.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                paths = [path for path, _, _ in files]
                for directory in directories(paths):
                    archive.addfile(header(directory, 0o555, 0, True))
                archive.addfile(
                    header(f"{ROOT}/manifest.json", 0o444, len(manifest_bytes), False),
                    io.BytesIO(manifest_bytes),
                )
                for path, mode, raw in files:
                    archive.addfile(
                        header(f"{ROOT}/{path}", mode, len(raw), False),
                        io.BytesIO(raw),
                    )
            stream.flush()
            os.fsync(stream.fileno())
        if output.exists() or output.is_symlink():
            raise BundleError("bundle output already exists")
        os.replace(temporary, output)
        os.chmod(output, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()
    raw = output.read_bytes()
    return {
        "bundle": str(output),
        "bundle_sha256": digest(raw),
        "manifest_sha256": digest(manifest_bytes),
        "installer_sha256": digest(installer),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--release-facts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(
            args.repository_root.resolve(strict=True),
            args.release_facts.resolve(strict=True),
            args.output.absolute(),
        )
    except (BundleError, OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
