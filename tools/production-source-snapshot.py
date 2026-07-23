#!/usr/bin/env python3
"""Create and verify a commit-bound production release build context."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True

CONTEXT_NAME = "source-context"
MANIFEST_NAME = "source-context.manifest.json"
MANIFEST_SCHEMA = "dirextalk.production-source-snapshot"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_FILE_COUNT = 20_000
HEX40 = re.compile(r"[0-9a-f]{40}")


class SnapshotError(RuntimeError):
    """The requested release snapshot violates the publication contract."""


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(repository_root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=True,
        capture_output=True,
        env=environment,
    )
    return completed.stdout if binary else completed.stdout.decode("utf-8", "strict")


def absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def require_repository(repository_root: Path) -> Path:
    repository_root = absolute_path(repository_root)
    metadata = repository_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or repository_root.is_symlink():
        raise SnapshotError("repository root is not a real directory")
    if repository_root.resolve(strict=True) != repository_root:
        raise SnapshotError("repository root contains a symbolic-link component")
    return repository_root


def require_state_root(state_root: Path) -> tuple[Path, os.stat_result]:
    state_root = absolute_path(state_root)
    metadata = state_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or state_root.is_symlink():
        raise SnapshotError("release state root is not a real directory")
    if state_root.resolve(strict=True) != state_root:
        raise SnapshotError("release state root contains a symbolic-link component")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SnapshotError("release state root must be current-user-owned mode 0700")
    return state_root, metadata


def snapshot_paths(state_root: Path) -> tuple[Path, Path]:
    return state_root / CONTEXT_NAME, state_root / MANIFEST_NAME


def validate_relative_path(raw_path: str) -> str:
    if not raw_path or "\x00" in raw_path or raw_path.startswith("/"):
        raise SnapshotError("archive contains an invalid path")
    path = PurePosixPath(raw_path)
    if any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != raw_path:
        raise SnapshotError(f"archive path is not canonical: {raw_path!r}")
    return raw_path


def source_tree(repository_root: Path, source_commit: str) -> dict[str, int]:
    raw = run_git(
        repository_root,
        "ls-tree",
        "-rz",
        "--full-tree",
        source_commit,
        binary=True,
    )
    assert isinstance(raw, bytes)
    files: dict[str, int] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata_raw, path_raw = record.split(b"\t", 1)
            mode_raw, object_type_raw, _object_id = metadata_raw.split(b" ", 2)
            path = path_raw.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise SnapshotError("Git tree contains an invalid record") from error
        validate_relative_path(path)
        if object_type_raw != b"blob" or mode_raw not in {b"100644", b"100755"}:
            raise SnapshotError(f"release source contains a link or special entry: {path}")
        if path in files:
            raise SnapshotError(f"Git tree contains a duplicate path: {path}")
        files[path] = 0o500 if mode_raw == b"100755" else 0o400
    if not files or len(files) > MAX_FILE_COUNT:
        raise SnapshotError("release source file count is invalid")
    return files


def expected_directories(files: dict[str, int]) -> set[str]:
    directories: set[str] = set()
    for raw_path in files:
        parent = PurePosixPath(raw_path).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def exact_commit(repository_root: Path, source_commit: str) -> None:
    if HEX40.fullmatch(source_commit) is None:
        raise SnapshotError("source commit must be a full lowercase Git object ID")
    resolved = run_git(
        repository_root,
        "rev-parse",
        "--verify",
        f"{source_commit}^{{commit}}",
    ).strip()
    if resolved != source_commit:
        raise SnapshotError("source commit does not resolve exactly")


def validate_source(repository_root: Path, source_commit: str) -> None:
    repository_root = require_repository(repository_root)
    exact_commit(repository_root, source_commit)
    before = run_git(repository_root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    status = run_git(
        repository_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        binary=True,
    )
    after = run_git(repository_root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    if before != source_commit or after != source_commit:
        raise SnapshotError("publication HEAD differs from the selected source commit")
    if status:
        raise SnapshotError("production publication requires an exactly clean worktree")


def make_archive(repository_root: Path, source_commit: str, state_root: Path) -> Path:
    descriptor, archive_name = tempfile.mkstemp(prefix=".source-archive.", dir=state_root)
    archive_path = Path(archive_name)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "archive",
                "--format=tar",
                f"--output={archive_path}",
                source_commit,
            ],
            check=True,
        )
        metadata = archive_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_ARCHIVE_BYTES
        ):
            raise SnapshotError("Git archive is not a bounded private regular file")
        return archive_path
    except BaseException:
        archive_path.unlink(missing_ok=True)
        raise


def validate_archive(
    archive_path: Path,
    files: dict[str, int],
) -> tuple[dict[str, tarfile.TarInfo], set[str]]:
    expected_dirs = expected_directories(files)
    archive_files: dict[str, tarfile.TarInfo] = {}
    archive_dirs: set[str] = set()
    total_size = 0
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            raw_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
            name = validate_relative_path(raw_name)
            if member.isfile():
                if name in archive_files or name in archive_dirs:
                    raise SnapshotError(f"archive path is duplicated: {name}")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise SnapshotError(f"archive file is not bounded: {name}")
                total_size += member.size
                if total_size > MAX_ARCHIVE_BYTES:
                    raise SnapshotError("archive expands beyond the release size limit")
                archive_files[name] = member
            elif member.isdir():
                if name in archive_dirs or name in archive_files:
                    raise SnapshotError(f"archive path is duplicated: {name}")
                archive_dirs.add(name)
            else:
                raise SnapshotError(f"archive contains a link or special entry: {name}")
    if set(archive_files) != set(files) or archive_dirs != expected_dirs:
        raise SnapshotError("Git archive entries differ from the selected commit tree")
    return archive_files, archive_dirs


def safe_remove_context(state_root: Path, context: Path) -> None:
    if not context.exists() and not context.is_symlink():
        return
    state_metadata = state_root.lstat()

    def remove_entry(path: Path) -> None:
        metadata = path.lstat()
        if metadata.st_uid != os.getuid():
            raise SnapshotError(f"snapshot cleanup refuses a foreign-owned entry: {path}")
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            if metadata.st_dev != state_metadata.st_dev or os.path.ismount(path):
                raise SnapshotError(f"snapshot cleanup refuses a mounted directory: {path}")
            os.chmod(path, 0o700, follow_symlinks=False)
            with os.scandir(path) as entries:
                children = [Path(entry.path) for entry in entries]
            for child in children:
                remove_entry(child)
            path.rmdir()
        else:
            path.unlink()

    remove_entry(context)


def remove_snapshot(state_root: Path) -> None:
    state_root, _ = require_state_root(state_root)
    context, manifest = snapshot_paths(state_root)
    safe_remove_context(state_root, context)
    if manifest.exists() or manifest.is_symlink():
        metadata = manifest.lstat()
        if metadata.st_uid != os.getuid() or stat.S_ISDIR(metadata.st_mode):
            raise SnapshotError("snapshot cleanup refuses an unsafe manifest")
        manifest.unlink()


def write_manifest(path: Path, value: dict[str, object]) -> None:
    raw = canonical_json(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SnapshotError("snapshot manifest write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)


def prepare_snapshot(repository_root: Path, source_commit: str, state_root: Path) -> Path:
    repository_root = require_repository(repository_root)
    state_root, state_metadata = require_state_root(state_root)
    context, manifest_path = snapshot_paths(state_root)
    if context.exists() or context.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise SnapshotError("stale production source snapshot exists")
    exact_commit(repository_root, source_commit)
    files = source_tree(repository_root, source_commit)
    archive_path = make_archive(repository_root, source_commit, state_root)
    try:
        archive_sha256 = sha256_path(archive_path)
        archive_files, directories = validate_archive(archive_path, files)
        os.mkdir(context, 0o700)
        extracted: list[dict[str, object]] = []
        try:
            for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
                destination = context.joinpath(*PurePosixPath(directory).parts)
                os.mkdir(destination, 0o700)
            with tarfile.open(archive_path, mode="r:") as archive:
                members = {member.name.rstrip("/"): member for member in archive.getmembers()}
                for relative_path in sorted(files):
                    member = archive_files[relative_path]
                    archive_member = members.get(member.name.rstrip("/"))
                    if archive_member is None:
                        raise SnapshotError(f"validated archive member disappeared: {relative_path}")
                    source = archive.extractfile(archive_member)
                    if source is None:
                        raise SnapshotError(f"archive file has no readable body: {relative_path}")
                    destination = context.joinpath(*PurePosixPath(relative_path).parts)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(destination, flags, 0o600)
                    digest = hashlib.sha256()
                    size = 0
                    try:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > member.size:
                                raise SnapshotError(f"archive member grew during extraction: {relative_path}")
                            digest.update(chunk)
                            view = memoryview(chunk)
                            while view:
                                written = os.write(descriptor, view)
                                if written <= 0:
                                    raise SnapshotError("snapshot file write made no progress")
                                view = view[written:]
                        if size != member.size:
                            raise SnapshotError(f"archive member was truncated: {relative_path}")
                        os.fsync(descriptor)
                        os.fchmod(descriptor, files[relative_path])
                    finally:
                        os.close(descriptor)
                        source.close()
                    extracted.append(
                        {
                            "mode": f"{files[relative_path]:04o}",
                            "path": relative_path,
                            "sha256": digest.hexdigest(),
                            "size": size,
                        }
                    )
            for directory in sorted(directories, key=lambda item: (-item.count("/"), item)):
                os.chmod(context.joinpath(*PurePosixPath(directory).parts), 0o500)
            os.chmod(context, 0o700)
            write_manifest(
                manifest_path,
                {
                    "directories": sorted(directories),
                    "files": extracted,
                    "git_archive_sha256": archive_sha256,
                    "schema": MANIFEST_SCHEMA,
                    "schema_version": 1,
                    "source_commit": source_commit,
                },
            )
        except BaseException:
            safe_remove_context(state_root, context)
            manifest_path.unlink(missing_ok=True)
            raise
    finally:
        archive_path.unlink(missing_ok=True)
    if context.lstat().st_dev != state_metadata.st_dev:
        remove_snapshot(state_root)
        raise SnapshotError("snapshot context is not on the protected release-state filesystem")
    verify_snapshot(repository_root, source_commit, state_root)
    return context


def read_manifest(path: Path) -> tuple[dict[str, object], bytes]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_size > 16 * 1024 * 1024
    ):
        raise SnapshotError("snapshot manifest is not a private immutable regular file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SnapshotError("snapshot manifest is invalid JSON") from error
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise SnapshotError("snapshot manifest is not canonical JSON")
    return value, raw


def verify_snapshot(repository_root: Path, source_commit: str, state_root: Path) -> Path:
    repository_root = require_repository(repository_root)
    state_root, state_metadata = require_state_root(state_root)
    context, manifest_path = snapshot_paths(state_root)
    exact_commit(repository_root, source_commit)
    value, _ = read_manifest(manifest_path)
    if (
        set(value) != {
            "directories",
            "files",
            "git_archive_sha256",
            "schema",
            "schema_version",
            "source_commit",
        }
        or value.get("schema") != MANIFEST_SCHEMA
        or value.get("schema_version") != 1
        or value.get("source_commit") != source_commit
        or not isinstance(value.get("git_archive_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(value["git_archive_sha256"])) is None
    ):
        raise SnapshotError("snapshot manifest contract is invalid")
    context_metadata = context.lstat()
    if (
        not stat.S_ISDIR(context_metadata.st_mode)
        or context.is_symlink()
        or context_metadata.st_uid != os.getuid()
        or context_metadata.st_dev != state_metadata.st_dev
        or stat.S_IMODE(context_metadata.st_mode) != 0o700
        or os.path.ismount(context)
    ):
        raise SnapshotError("snapshot context is not a private mode-0700 directory")
    directories = value.get("directories")
    file_records = value.get("files")
    if (
        not isinstance(directories, list)
        or not all(isinstance(item, str) for item in directories)
        or directories != sorted(set(directories))
        or not isinstance(file_records, list)
        or len(file_records) > MAX_FILE_COUNT
    ):
        raise SnapshotError("snapshot manifest entry collections are invalid")
    expected_files: dict[str, dict[str, object]] = {}
    for record in file_records:
        if (
            not isinstance(record, dict)
            or set(record) != {"mode", "path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not isinstance(record.get("mode"), str)
            or record.get("mode") not in {"0400", "0500"}
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])) is None
            or not isinstance(record.get("size"), int)
            or not 0 <= int(record["size"]) <= MAX_FILE_BYTES
        ):
            raise SnapshotError("snapshot file record is invalid")
        relative_path = validate_relative_path(str(record["path"]))
        if relative_path in expected_files:
            raise SnapshotError("snapshot manifest contains duplicate files")
        expected_files[relative_path] = record
    if set(directories) != expected_directories({path: 0 for path in expected_files}):
        raise SnapshotError("snapshot manifest directory set is invalid")

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current_root, directory_names, file_names in os.walk(context, topdown=True, followlinks=False):
        current = Path(current_root)
        relative_root = current.relative_to(context)
        for name in list(directory_names):
            path = current / name
            metadata = path.lstat()
            relative = (relative_root / name).as_posix()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_dev != state_metadata.st_dev
                or stat.S_IMODE(metadata.st_mode) != 0o500
                or os.path.ismount(path)
            ):
                raise SnapshotError(f"snapshot directory is unsafe: {relative}")
            actual_directories.add(relative)
        for name in file_names:
            path = current / name
            metadata = path.lstat()
            relative = (relative_root / name).as_posix()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_dev != state_metadata.st_dev
                or metadata.st_nlink != 1
            ):
                raise SnapshotError(f"snapshot file is unsafe: {relative}")
            record = expected_files.get(relative)
            if record is None:
                raise SnapshotError(f"snapshot contains an unexpected file: {relative}")
            if (
                stat.S_IMODE(metadata.st_mode) != int(str(record["mode"]), 8)
                or metadata.st_size != record["size"]
                or sha256_path(path) != record["sha256"]
            ):
                raise SnapshotError(f"snapshot file differs from its manifest: {relative}")
            actual_files.add(relative)
    if actual_files != set(expected_files) or actual_directories != set(directories):
        raise SnapshotError("snapshot filesystem entries differ from its manifest")

    archive_path = make_archive(repository_root, source_commit, state_root)
    try:
        if sha256_path(archive_path) != value["git_archive_sha256"]:
            raise SnapshotError("snapshot archive digest differs from the selected commit")
        validate_archive(archive_path, source_tree(repository_root, source_commit))
    finally:
        archive_path.unlink(missing_ok=True)
    return context


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="dtx-source-snapshot-") as temporary:
        temporary_root = Path(temporary)
        repository = temporary_root / "repository"
        state_root = repository / "target" / "production-release"
        outside = temporary_root / "outside"
        repository.mkdir(mode=0o700)
        outside.write_text("outside\n")
        subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.email", "snapshot-test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.name", "Snapshot Test"],
            check=True,
        )
        (repository / ".gitignore").write_text("/target/\n")
        (repository / "docker/release").mkdir(parents=True)
        (repository / "docker/production").mkdir(parents=True)
        (repository / "docker/release/Dockerfile").write_text("FROM scratch\n# runtime-a\n")
        (repository / "docker/production/Dockerfile.migrate").write_text(
            "FROM scratch\n# migrator-a\n"
        )
        (repository / "payload").write_text("archived-a\n")
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "snapshot a"], check=True)
        source_commit = str(run_git(repository, "rev-parse", "HEAD")).strip()
        state_root.mkdir(parents=True, mode=0o700)
        os.chmod(state_root, 0o700)

        validate_source(repository, source_commit)
        context = prepare_snapshot(repository, source_commit, state_root)
        archived_build_inputs = {
            path: (context / path).read_bytes()
            for path in (
                "docker/release/Dockerfile",
                "docker/production/Dockerfile.migrate",
                "payload",
            )
        }
        expected_build_inputs = {
            path: run_git(repository, "show", f"{source_commit}:{path}", binary=True)
            for path in archived_build_inputs
        }
        if archived_build_inputs != expected_build_inputs:
            raise SnapshotError("snapshot build inputs differ from the archived commit")
        (repository / "docker/release/Dockerfile").write_text("FROM scratch\n# runtime-b\n")
        (repository / "docker/production/Dockerfile.migrate").write_text(
            "FROM scratch\n# migrator-b\n"
        )
        (repository / "payload").write_text("worktree-b\n")
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "snapshot b"], check=True)
        try:
            validate_source(repository, source_commit)
        except SnapshotError:
            pass
        else:
            raise SnapshotError("advanced HEAD was not rejected before publication")
        verify_snapshot(repository, source_commit, state_root)
        if archived_build_inputs != {
            path: (context / path).read_bytes() for path in archived_build_inputs
        }:
            raise SnapshotError("planned build bytes changed after the source repository advanced")
        remove_snapshot(state_root)

        os.symlink(outside, repository / "escape")
        subprocess.run(["git", "-C", str(repository), "add", "escape"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "unsafe link"], check=True)
        linked_commit = str(run_git(repository, "rev-parse", "HEAD")).strip()
        try:
            prepare_snapshot(repository, linked_commit, state_root)
        except SnapshotError:
            pass
        else:
            raise SnapshotError("committed symbolic link was not rejected")
        if outside.read_text() != "outside\n":
            raise SnapshotError("link rejection changed an outside file")
        if snapshot_paths(state_root)[0].exists() or snapshot_paths(state_root)[1].exists():
            raise SnapshotError("failed snapshot preparation left release state behind")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-source")
    prepare = subparsers.add_parser("prepare")
    verify = subparsers.add_parser("verify")
    remove = subparsers.add_parser("remove")
    subparsers.add_parser("self-test")
    for command in (validate, prepare, verify):
        command.add_argument("--repository-root", required=True)
        command.add_argument("--source-commit", required=True)
    for command in (prepare, verify, remove):
        command.add_argument("--state-root", required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "validate-source":
        validate_source(Path(arguments.repository_root), arguments.source_commit)
    elif arguments.command == "prepare":
        context = prepare_snapshot(
            Path(arguments.repository_root),
            arguments.source_commit,
            Path(arguments.state_root),
        )
        print(context)
    elif arguments.command == "verify":
        context = verify_snapshot(
            Path(arguments.repository_root),
            arguments.source_commit,
            Path(arguments.state_root),
        )
        print(context)
    elif arguments.command == "remove":
        remove_snapshot(Path(arguments.state_root))
    elif arguments.command == "self-test":
        self_test()
        print("production source snapshot self-test passed")
    else:
        raise AssertionError(arguments.command)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, tarfile.TarError, SnapshotError) as error:
        raise SystemExit(f"production source snapshot failed: {error}") from error
