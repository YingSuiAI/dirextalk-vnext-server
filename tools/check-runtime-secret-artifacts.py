#!/usr/bin/env python3
"""Fail closed on secret-shaped files in an exported runtime image/rootfs.

Use ``--root PATH`` for an exact exported rootfs directory or ``--tar PATH``
for an exact tar archive.  The scanner reports only artifact paths and rule
names; it never prints file contents or matched secret values.
"""
from __future__ import annotations

import argparse
import io
import re
import tarfile
import tempfile
from pathlib import Path
from pathlib import PurePosixPath

NAME_RULE = re.compile(
    r"(?:^|/)(?:"
    r"rootkey\.csv|"
    r".*(?:private|secret|credential|token|authorization|enrollment|"
    r"client[-_.]?binding|connector[-_.]?(?:bearer|handoff|config|log)|"
    r"mcp[-_.]?bearer|handoff).*|"
    r".*\.(?:key|pem|bearer|handoff|token|secret|credentials?|env|log)"
    r")$",
    re.I,
)
CONTENT_RULES = [
    re.compile(rb"-----BEGIN (?:RSA |EC |)?PRIVATE KEY-----"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(rb"(?i)aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)(?:x[-_]dirextalk[-_]client[-_]binding[-_]authorization|client[-_]?binding[-_]?authorization|enrollment[_-]?token|binding[_-]?authorization)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)(?:connector[-_ ]?(?:bearer|handoff|config|log)|mcp[-_]?bearer|connector[-_]?enrollment)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)\bdtxi1[a-z0-9]{20,}\b"),
]
CLIENT_BINDING_SCHEMA_RULE = re.compile(
    rb'"schema"\s*:\s*"dirextalk\.client-binding"'
)
CLIENT_BINDING_AUTHORIZATION_RULE = re.compile(
    rb'"authorization"\s*:\s*"[A-Za-z0-9_-]{43}"'
)
MAX_REGULAR_FILE_SIZE = 128 * 1024 * 1024
MAX_REGULAR_FILE_COUNT = 100_000
MAX_REGULAR_FILE_BYTES = 1024 * 1024 * 1024


def suspicious(name: str, content: bytes) -> str | None:
    if NAME_RULE.search(name):
        return "sensitive-name"
    if any(rule.search(content) for rule in CONTENT_RULES):
        return "sensitive-content"
    has_binding_schema = CLIENT_BINDING_SCHEMA_RULE.search(content) is not None
    has_binding_authorization = (
        CLIENT_BINDING_AUTHORIZATION_RULE.search(content) is not None
    )
    if has_binding_schema and has_binding_authorization:
        return "sensitive-content"
    return None


def safe_member_name(value: str) -> str:
    path = PurePosixPath(value.rstrip("/"))
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError("tar export contains an unsafe member")
    result = str(path)
    if result == ".":
        return ""
    return result


def safe_link_target(member_name: str, target: str, is_symlink: bool) -> str:
    target_path = PurePosixPath(target)
    if not target or (target_path.is_absolute() and not is_symlink):
        raise ValueError("tar export contains an unsafe link")
    parts = [] if target_path.is_absolute() else (list(PurePosixPath(member_name).parent.parts) if is_symlink else [])
    for part in target_path.parts:
        if part == ".":
            continue
        if part == "..":
            if not parts:
                raise ValueError("tar export contains an unsafe link")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def tar_regular_files(path: Path) -> dict[str, bytes]:
    """Read a safe export, rejecting ambiguity before its bytes are trusted."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("tar export must be a regular file")
    files: dict[str, bytes] = {}
    hardlinks: dict[str, str] = {}
    total_bytes = 0
    try:
        with tarfile.open(path, "r:*") as archive:
            seen: set[str] = set()
            for member in archive:
                name = safe_member_name(member.name)
                if name in seen:
                    raise ValueError("tar export contains an unsafe member")
                seen.add(name)
                if member.isdir():
                    continue
                if member.issym() or member.islnk():
                    target = safe_link_target(name, member.linkname, member.issym())
                    if member.islnk():
                        if len(files) + len(hardlinks) >= MAX_REGULAR_FILE_COUNT:
                            raise ValueError("tar export exceeds scan limits")
                        hardlinks[name] = target
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_REGULAR_FILE_SIZE:
                    raise ValueError("tar export contains an unsupported member")
                total_bytes += member.size
                if len(files) + len(hardlinks) >= MAX_REGULAR_FILE_COUNT or total_bytes > MAX_REGULAR_FILE_BYTES:
                    raise ValueError("tar export exceeds scan limits")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("tar export contains an unreadable file")
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ValueError("tar export contains an unreadable file")
                if stream.read(1):
                    raise ValueError("tar export contains an unsafe file")
                files[name] = content
    except (OSError, tarfile.TarError) as error:
        raise ValueError("tar export cannot be read") from error
    def resolve_hardlink(name: str, resolving: set[str]) -> bytes:
        if name in files:
            return files[name]
        if name in resolving or name not in hardlinks:
            raise ValueError("tar export contains an unsafe hard link")
        resolving.add(name)
        content = resolve_hardlink(hardlinks[name], resolving)
        resolving.remove(name)
        files[name] = content
        return content

    for name in hardlinks:
        resolve_hardlink(name, set())
    return files


def scan_directory(root: Path, base: dict[str, bytes] | None = None) -> list[tuple[str, str]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("root export must be a regular directory")
    findings: list[tuple[str, str]] = []
    total_bytes = 0
    regular_files = 0
    try:
        paths = list(root.rglob("*"))
    except OSError as error:
        raise ValueError("root export cannot be enumerated") from error
    for path in paths:
        if path.is_symlink():
            raise ValueError("root export contains a link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("root export contains an unsupported member")
        if path.is_file():
            try:
                content = path.read_bytes()
            except OSError as error:
                raise ValueError("root export contains an unreadable file") from error
            relative = path.relative_to(root).as_posix()
            if len(content) > MAX_REGULAR_FILE_SIZE:
                raise ValueError("root export contains an unsupported file")
            regular_files += 1
            total_bytes += len(content)
            if regular_files > MAX_REGULAR_FILE_COUNT or total_bytes > MAX_REGULAR_FILE_BYTES:
                raise ValueError("root export exceeds scan limits")
            if base is not None and base.get(relative) == content:
                continue
            rule = suspicious(relative, content)
            if rule:
                findings.append((relative, rule))
    return findings


def scan_tar(path: Path, base: dict[str, bytes] | None = None) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for name, content in tar_regular_files(path).items():
        if base is not None and base.get(name) == content:
            continue
        rule = suspicious(name, content)
        if rule:
            findings.append((name, rule))
    return findings


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/bin/dtx-node").write_bytes(b"runtime binary")
        (root / "usr/bin/large-clean-blob").write_bytes(b"\x00" * (8 * 1024 * 1024))
        if scan_directory(root):
            return 1
        fixtures = {
            "blob-a": b"-----BEGIN PRIVATE KEY-----\nsynthetic\n",
            "blob-b": b'{"aws_secret_access_key":"synthetic-secret"}',
            "blob-c": b'{"client_binding_authorization":"synthetic"}',
            "blob-d": b'{"connector_bearer":"synthetic"}',
            "blob-e": b"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la",
            "blob-f": b'{"authorization":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","schema":"dirextalk.client-binding"}',
        }
        for name, content in fixtures.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        findings = scan_directory(root)
        if len(findings) < len(fixtures):
            return 1
        archive_path = root / "runtime.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, content in fixtures.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            safe_link = tarfile.TarInfo("safe-link")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "blob-a"
            archive.addfile(safe_link)
            safe_hardlink = tarfile.TarInfo("safe-hardlink")
            safe_hardlink.type = tarfile.LNKTYPE
            safe_hardlink.linkname = "blob-a"
            archive.addfile(safe_hardlink)
        if len(scan_tar(archive_path)) < len(fixtures):
            return 1
        base_path = root / "base.tar"
        with tarfile.open(base_path, "w") as archive:
            for name, content in fixtures.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            safe_hardlink = tarfile.TarInfo("safe-hardlink")
            safe_hardlink.type = tarfile.LNKTYPE
            safe_hardlink.linkname = "blob-a"
            archive.addfile(safe_hardlink)
        base = tar_regular_files(base_path)
        if scan_tar(archive_path, base):
            return 1
        changed_path = root / "changed.tar"
        with tarfile.open(changed_path, "w") as archive:
            for name, content in fixtures.items():
                altered = content + b"changed" if name == "blob-a" else content
                info = tarfile.TarInfo(name)
                info.size = len(altered)
                archive.addfile(info, io.BytesIO(altered))
        if not scan_tar(changed_path, base):
            return 1
        unsafe_path = root / "unsafe.tar"
        with tarfile.open(unsafe_path, "w") as archive:
            info = tarfile.TarInfo("unsafe-link")
            info.type = tarfile.LNKTYPE
            info.linkname = "../../etc/passwd"
            archive.addfile(info)
        try:
            scan_tar(unsafe_path)
        except ValueError:
            pass
        else:
            return 1
        with tarfile.open(unsafe_path, "w") as archive:
            info = tarfile.TarInfo("unsafe-link")
            info.type = tarfile.LNKTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        try:
            scan_tar(unsafe_path)
        except ValueError:
            pass
        else:
            return 1
        (root / "unsafe-root-link").symlink_to("usr/bin/dtx-node")
        try:
            scan_directory(root)
        except ValueError:
            pass
        else:
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan an exact exported runtime rootfs directory or tar archive without printing secret values.",
        epilog="Examples: check-runtime-secret-artifacts.py --root ./rootfs; check-runtime-secret-artifacts.py --tar ./runtime.tar",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--root", type=Path)
    group.add_argument("--tar", type=Path)
    group.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-tar", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        base = None
        if args.base_tar:
            base = tar_regular_files(args.base_tar)
        findings = scan_directory(args.root, base) if args.root else scan_tar(args.tar, base)
    except (OSError, ValueError):
        print("runtime secret-artifact gate: rejected unreadable or unsupported export")
        return 2
    for name, rule in findings:
        print(f"runtime secret-artifact gate: {rule} at {name}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
